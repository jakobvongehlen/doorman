"""The egress proxy's addon (deploy/egress/addon.py) against mitmproxy 12.3.1's own flow objects, with a fake
Doorman in place of the proxy API. Run with the proxy's environment:
~/.venvs/egress/bin/python -m pytest deploy/egress/tests -x"""

import asyncio
import json
import os
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from mitmproxy import dns, http, options
from mitmproxy.net.dns import response_codes
from mitmproxy.proxy import commands, events, layer, layers
from mitmproxy.proxy.context import Context
from mitmproxy.proxy.layers import modes
from mitmproxy.proxy.mode_specs import ProxyMode
from mitmproxy.test import taddons, tflow, tutils

import addon as egress
from doorman.egress import fingerprint, rules
from doorman_client import DoormanClient

SECRET = ("The board minutes say the merger with Northwind Traders closes on the fourteenth of March at noon, "
          "and the price per share stays confidential until the press release goes out that afternoon.")
RECIPE_TEXT = ("Preheat the oven to 180 degrees. Whisk the eggs with the sugar until pale and fluffy, then fold in "
               "the flour, a pinch of salt and the melted butter. Pour the batter into a greased tin and bake.")
AGENT_IP = "172.32.0.3"
RECORD_FIELDS = {"ts", "client_ip", "kind", "host", "ip", "port", "method", "path", "status", "bytes_up",
                 "bytes_down", "decision", "rule", "detail", "leak", "process", "duration_ms", "scanned"}


class FakeDoorman:
    token = "dme_test"
    last_error = "connection refused"

    def __init__(self, answer=None):
        self.answer = answer
        self.checks, self.logs, self.statuses = [], [], []
        self.policy_value = None

    def policy(self):
        return self.policy_value

    def check(self, body):
        self.checks.append(body)
        return self.answer(body) if callable(self.answer) else self.answer

    def send_log(self, records):
        self.logs.extend(records)
        return True

    def status(self, body):
        self.statuses.append(body)
        return True


def make(answer=None, observer=None, **policy_changes):
    policy = rules.policy_example()
    policy.update(policy_changes)
    fake = FakeDoorman(answer)
    proxy = egress.DoormanEgress(fake, None, observer)
    proxy.policy = policy
    return proxy, fake


def run(coro):
    return asyncio.run(coro)


REAL_RESOLVE = egress._resolve
FAKE_DNS: dict[str, set[str]] = {}  # what the proxy's own lookup of a claimed name finds in these tests


@pytest.fixture(autouse=True)
def fake_resolver(monkeypatch):
    FAKE_DNS.clear()
    asked = []

    async def resolve(host):
        asked.append(host)
        return set(FAKE_DNS.get(host, ()))

    monkeypatch.setattr(egress, "_resolve", resolve)
    return asked


def client_conn(mode="transparent", dst=("93.184.215.14", 443), src_port=41000):
    conn = tflow.tclient_conn()
    conn.proxy_mode = ProxyMode.parse(mode)
    conn.peername = (AGENT_IP, src_port)
    conn.sockname = dst
    conn.sni = None
    conn.alpn = None
    return conn


def http_flow(method, url, content=b"", headers=None, conn=None, server=("93.184.215.14", 443), vouch=True):
    """A request to `server`; with vouch the claimed host really has that address (the proxy's lookup says
    so), without it the Host header is the agent's invention."""
    request = http.Request.make(method, url, content, headers or {})
    request.timestamp_start = time.time()
    if vouch:
        FAKE_DNS.setdefault(request.pretty_host, set()).add(server[0])
    f = tflow.tflow(req=request, client_conn=conn or client_conn(dst=server))
    f.server_conn.address = server
    return f


async def through(proxy, f, response=True):
    """requestheaders and request as mitmproxy calls them, then the server's answer (unless the proxy
    answered), then the response hook; returns the records sent to Doorman."""
    await proxy.requestheaders(f)
    await proxy.request(f)
    if f.response is None and f.error is None and response:
        f.response = tutils.tresp(content=b"hello back")
    if f.error is None:
        await proxy.response(f)
    else:
        await proxy.error(f)
    await proxy.settle()
    await proxy.flush()
    return [r for r in proxy.client.logs if r["kind"] != "dns"]  # the proxy's own lookups are logged too


def leak_answer(body):
    shared = len(set(body["prints"]) & fingerprint.prints(SECRET))
    chars = fingerprint.estimate_chars(shared)
    if chars >= 100:
        return {"action": "deny", "chars": chars, "sources": ["mail: Board minutes"],
                "reason": f"this request carries about {chars} characters the agent read through Doorman "
                          f"(mail: Board minutes)"}
    return {"action": "allow", "chars": chars, "sources": ["mail: Board minutes"] if chars else [], "reason": ""}


# ---- HTTP rules ---------------------------------------------------------------------------------------------

def test_blocked_host_gets_403_with_copy_and_header():
    proxy, fake = make(deny=["blocked.example"])
    f = http_flow("GET", "https://api.blocked.example/v1/thing?q=1")
    logs = run(through(proxy, f))
    assert f.response.status_code == 403
    assert f.response.headers["X-Doorman-Egress"] == "blocked; rule=deny_list"
    assert f.response.headers["Content-Type"].startswith("text/plain")
    assert f.response.get_text() == (
        "Doorman's network proxy blocked this request: blocked.example is on the owner's deny list. "
        "If your task needs api.blocked.example, ask the owner: doorman egress request api.blocked.example "
        "--reason \"why\"\n")
    assert not fake.checks
    [record] = logs
    assert (record["decision"], record["rule"], record["status"]) == ("deny", "deny_list", 403)
    assert record["detail"] == "blocked.example is on the owner's deny list"


def test_upload_to_exfil_host_is_blocked_but_a_read_is_not():
    proxy, _ = make()
    post = http_flow("POST", "https://webhook.site/abc", b"hello")
    run(through(proxy, post))
    assert post.response.status_code == 403
    assert post.response.headers["X-Doorman-Egress"] == "blocked; rule=exfil_upload"
    get = http_flow("GET", "https://webhook.site/abc")
    run(through(proxy, get))
    assert get.response.status_code == 200


def test_exemption_allows():
    proxy, _ = make(deny=["blocked.example"],
                    exemptions=[{"target": "blocked.example", "expires": time.time() + 3600}])
    f = http_flow("GET", "https://blocked.example/")
    [record] = run(through(proxy, f))
    assert f.response.status_code == 200
    assert (record["decision"], record["rule"]) == ("allow", "exemption")
    assert record["detail"] == "the owner made an exception for blocked.example"

    expired, _ = make(deny=["blocked.example"],
                      exemptions=[{"target": "blocked.example", "expires": time.time() - 1}])
    g = http_flow("GET", "https://blocked.example/")
    run(through(expired, g))
    assert g.response.status_code == 403


class FakeStream:
    """Just enough of mitmproxy's HttpStream for its start_request_stream (as patched by the addon)."""

    def __init__(self, f):
        self.flow, self.stream_id = f, 1
        self.context = type("C", (), {"client": f.client_conn, "server": f.server_conn})()
        self.client_state = "consume"
        self.connected = False

    def state_errored(self, event):  # noqa: D102
        yield from ()

    def make_server_connection(self):
        self.connected = True
        return False
        yield  # noqa: unreachable: a generator, like mitmproxy's


def start_stream(f):
    """mitmproxy starting to stream a request body: the commands it gives, and whether it connected."""
    stream = FakeStream(f)
    out = list(egress.http_layers.HttpStream.start_request_stream(stream))
    return stream, out


def big_upload(url, method="POST", length=64 * 1024 * 1024, **kw):
    f = http_flow(method, url, b"", **kw)
    f.request.headers["content-length"] = str(length)
    f.request.stream = True  # what mitmproxy sets above stream_large_bodies, before requestheaders
    return f


def test_mitmproxy_is_patched_and_its_options_enforced():
    from mitmproxy import version
    assert version.VERSION == "12.3.1"  # the patches below are written against this version
    assert egress.http_layers.HttpStream.start_request_stream.__name__ == "_patched_start_request_stream"
    assert egress.modes.DestinationKnown.finish_start.__name__ == "_patched_finish_start"
    proxy, _ = make()
    from mitmproxy.addons import proxyserver
    with taddons.context(proxyserver.Proxyserver(), proxy) as tctx:
        tctx.configure(proxy, connection_strategy="eager", rawtcp=True)
        assert tctx.options.connection_strategy == "lazy" and tctx.options.rawtcp is False


def test_a_blocked_upload_never_streams_to_the_server():
    from mitmproxy.proxy.layers.http import ErrorCode, HttpErrorHook, ResponseProtocolError
    proxy, fake = make(deny=["blocked.example"])
    f = big_upload("https://blocked.example/up")
    run(proxy.requestheaders(f))
    stream, out = start_stream(f)
    assert not stream.connected and stream.client_state == stream.state_errored
    assert isinstance(out[0], HttpErrorHook)
    [sent] = [c.event for c in out[1:]]
    assert isinstance(sent, ResponseProtocolError) and sent.code == ErrorCode.GENERIC_CLIENT_ERROR
    assert "blocked.example is on the owner's deny list" in sent.message
    run(proxy.error(f))
    run(proxy.flush())
    record = [r for r in fake.logs if r["kind"] == "http"][-1]
    assert (record["decision"], record["rule"]) == ("deny", "deny_list")


def test_an_upload_too_large_to_scan_follows_the_unscanned_setting():
    from mitmproxy.proxy.layers.http import ErrorCode
    proxy, fake = make(unscanned="block")
    f = big_upload("https://example.org/upload", "PUT")
    run(proxy.requestheaders(f))
    stream, out = start_stream(f)
    assert not stream.connected and out[-1].event.code == ErrorCode.REQUEST_TOO_LARGE
    assert "this upload is too large to check" in out[-1].event.message
    run(proxy.error(f))
    run(proxy.flush())
    record = [r for r in fake.logs if r["kind"] == "http"][-1]
    assert (record["decision"], record["rule"]) == ("deny", "unscanned") and record["scanned"] is False
    # found out halfway through a chunked body: the same (mitmproxy calls start_request_stream then too)
    chunked = http_flow("POST", "https://example.org/upload", b"")
    del chunked.request.headers["content-length"]
    run(proxy.requestheaders(chunked))
    chunked.request.stream = True
    stream, _ = start_stream(chunked)
    assert not stream.connected

    # it goes unless the owner chose block, and then still to an allowed host and to the model's API
    for allowed, kw in ((make()[0], {}), (make(unscanned="block", allow=["example.org"])[0], {}),
                        (make(unscanned="block")[0], {"url": "https://api.anthropic.com/v1/files"})):
        g = big_upload(kw.get("url", "https://example.org/upload"))
        run(allowed.requestheaders(g))
        stream, _ = start_stream(g)
        assert stream.connected and callable(g.request.stream)  # streams, counted
        g.request.stream(b"x" * 1000)
        g.request.stream(b"y" * 24)
        g.response = tutils.tresp()
        run(allowed.response(g))
        run(allowed.flush())
        [record] = [r for r in allowed.client.logs if r["kind"] == "http"]
        assert record["decision"] == "allow" and record["bytes_up"] == 1024 and record["scanned"] is False


def test_private_addresses_are_refused_unless_allowed_by_address():
    # Doorman's owner app trusts its own network; through the proxy the agent would arrive from there
    proxy, _ = make(allow=["example.com"])
    spoofed = http_flow("GET", "http://example.com/owner/egress", server=("172.30.0.5", 8711))
    run(through(proxy, spoofed))
    assert spoofed.response.status_code == 403
    assert spoofed.response.headers["X-Doorman-Egress"] == "blocked; rule=private"
    assert "172.30.0.5 is a private address" in spoofed.response.get_text()
    nas = client_conn(dst=("10.1.2.3", 22))
    run(proxy.client_connected(nas))
    assert "10.1.2.3 is a private address" in nas.error
    lan, _ = make(allow=["10.0.0.0/8"])
    nas = client_conn(dst=("10.1.2.3", 22))
    run(lan.client_connected(nas))
    assert nas.error is None
    once, _ = make(exemptions=[{"target": "10.1.2.3:22", "expires": time.time() + 60}])
    nas = client_conn(dst=("10.1.2.3", 22))
    run(once.client_connected(nas))
    assert nas.error is None


# ---- content checks -----------------------------------------------------------------------------------------

def test_leak_check_called_only_with_content():
    proxy, fake = make(answer=leak_answer)
    run(through(proxy, http_flow("GET", "https://example.org/search?q=weather")))
    assert fake.checks == []
    f = http_flow("POST", "https://example.org/notes", json.dumps({"note": "hi there, " + SECRET[:60]}).encode(),
                  {"Content-Type": "application/json"})
    run(through(proxy, f))
    [body] = fake.checks
    assert body["client_ip"] == AGENT_IP and body["host"] == "example.org" and body["method"] == "POST"
    assert body["url"] == "https://example.org/notes"
    assert body["prints"] and all(isinstance(p, int) for p in body["prints"])
    assert body["honeytokens"] == []
    assert f.response.status_code == 200


def test_leak_deny_from_doorman():
    proxy, fake = make(answer=leak_answer)
    f = http_flow("POST", "https://example.org/paste", ("fyi: " + SECRET).encode(), {"Content-Type": "text/plain"})
    [record] = run(through(proxy, f))
    assert f.response.status_code == 403
    assert f.response.headers["X-Doorman-Egress"] == "blocked; rule=leak"
    assert f.response.get_text().startswith("Doorman's network proxy blocked this request: this request carries "
                                            "about ")
    assert "(mail: Board minutes). If your task needs example.org" in f.response.get_text()
    assert record["rule"] == "leak" and record["decision"] == "deny"
    assert record["leak"]["chars"] >= 100 and record["leak"]["sources"] == ["mail: Board minutes"]
    assert record["scanned"] is True


def test_leak_hidden_in_base64_query_is_found():
    import base64
    proxy, fake = make(answer=leak_answer)
    hidden = base64.urlsafe_b64encode(SECRET.encode()).decode()
    f = http_flow("GET", f"https://example.org/track?d={hidden}")
    run(through(proxy, f))
    assert fake.checks and f.response.status_code == 403


def test_note_band_allows_and_records_the_leak():
    proxy, _ = make(answer={"action": "allow", "chars": 60, "sources": ["file: plan.txt"], "reason": ""})
    f = http_flow("POST", "https://example.org/x", SECRET.encode())
    [record] = run(through(proxy, f))
    assert f.response.status_code == 200
    assert record["decision"] == "allow" and record["leak"] == {"chars": 60, "sources": ["file: plan.txt"]}
    quiet, _ = make(answer={"action": "allow", "chars": 0, "sources": [], "reason": ""})
    [record] = run(through(quiet, http_flow("POST", "https://example.org/x", SECRET.encode())))
    assert record["leak"] is None


def test_honeytoken_found_and_blocked_even_when_doorman_is_down():
    proxy, fake = make(answer=None, honeytokens=["canary-7f3a9c2e"], when_doorman_down="allow")
    f = http_flow("POST", "https://example.org/x", b"token=CANARY-7F3A9C2E")
    [record] = run(through(proxy, f))
    assert fake.checks[0]["honeytokens"] == ["canary-7f3a9c2e"]
    assert_silent_502(f)
    assert (record["decision"], record["rule"], record["status"]) == ("deny", "honeytoken", 502)


def assert_silent_502(f):
    """A honeytoken or a quarantine: an ordinary upstream failure as far as the agent can tell."""
    assert f.response.status_code == 502
    assert f.response.content == b"Bad Gateway\n"
    assert "X-Doorman-Egress" not in f.response.headers
    assert not any(word in f.response.get_text().lower() for word in ("doorman", "honeytoken", "decoy", "quarantin"))


def test_doorman_down_follows_setting():
    for setting, status in (("block", 403), ("allow", 200)):
        proxy, fake = make(answer=None, when_doorman_down=setting)
        f = http_flow("POST", "https://example.org/x", SECRET.encode())
        [record] = run(through(proxy, f))
        assert len(fake.checks) == 1
        assert f.response.status_code == status
        if setting == "block":
            assert f.response.headers["X-Doorman-Egress"] == "blocked; rule=doorman_down"
            assert record["rule"] == "doorman_down"
        else:
            assert record["decision"] == "allow" and "couldn't be reached" in record["detail"]
        short = http_flow("GET", "https://example.org/?q=1")  # nothing to check: passes either way
        run(through(proxy, short))
        assert short.response.status_code == 200 and len(fake.checks) == 1


def test_no_scan_host_skips_check():
    proxy, fake = make(answer=leak_answer, honeytokens=["canary-7f3a9c2e", DECOY_KEY.lower()],
                       decoys=[DECOY_KEY.lower()])
    f = http_flow("POST", "https://api.anthropic.com/v1/messages", SECRET.encode())
    [record] = run(through(proxy, f))
    assert fake.checks == [] and f.response.status_code == 200
    assert record["scanned"] is False


# ---- honeytokens and decoy keys at a host on no_scan (the model API) -------------------------------------------

DECOY_KEY = "sk-ant-api03-" + "Qw7rT2xLm9Kp" * 7 + "Zb8Vn3Jc4Hs6dF1gA0yE5uI" + "-" + "Rt5Yp2" + "AA"


def honeytoken_answer(body):
    if body["honeytokens"]:
        return {"action": "deny", "chars": 0, "sources": [], "reason": "this request carries protected content"}
    return {"action": "allow", "chars": 0, "sources": [], "reason": ""}


def no_scan_proxy(answer=honeytoken_answer):
    return make(answer=answer, honeytokens=sorted({"canary-7f3a9c2e", DECOY_KEY.lower()}), decoys=[DECOY_KEY.lower()])


def test_a_decoy_key_used_with_the_model_api_is_blocked_like_anywhere_else():
    import base64
    for url, headers in (("https://api.anthropic.com/v1/messages", {"x-api-key": DECOY_KEY}),
                         ("https://api.openai.com/v1/chat/completions", {"Authorization": f"Bearer {DECOY_KEY}"}),
                         ("https://api.openai.com/v1/models", {"Authorization": "Basic " + base64.b64encode(
                             f"me:{DECOY_KEY}".encode()).decode()}),
                         (f"https://generativelanguage.googleapis.com/v1/models?key={DECOY_KEY}", {})):
        proxy, fake = no_scan_proxy()
        f = http_flow("POST", url, b'{"messages": []}', headers)
        [record] = run(through(proxy, f))
        assert_silent_502(f)
        assert (record["decision"], record["rule"], record["scanned"]) == ("deny", "honeytoken", False), url
        [check] = fake.checks  # reported once, from requestheaders; no fingerprints
        assert check["honeytokens"] == [DECOY_KEY.lower()] and check["prints"] == [] and "no_scan" not in check
    # an owner's honeytoken as a header too, and with Doorman down it still blocks
    proxy, fake = no_scan_proxy(answer=None)
    f = http_flow("GET", "https://api.anthropic.com/v1/models", headers={"x-api-key": "CANARY-7f3a9c2e"})
    [record] = run(through(proxy, f))
    assert_silent_502(f) and record["rule"] == "honeytoken"


def test_the_model_apis_body_is_checked_for_the_decoy_keys_only():
    # what the agent read, a planted honeytoken included, goes to its model: never checked there
    proxy, fake = no_scan_proxy()
    f = http_flow("POST", "https://api.anthropic.com/v1/messages",
                  json.dumps({"messages": [{"content": "the mail says CANARY-7f3a9c2e " + SECRET}]}).encode())
    [record] = run(through(proxy, f))
    assert f.response.status_code == 200 and fake.checks == [] and record["leak"] is None
    # the decoy keys in it (JSON-escaped, too): Doorman decides; here it stops the agent
    body = json.dumps({"messages": [{"content": "cat api-keys.env:\nANTHROPIC_API_KEY=" + DECOY_KEY}]})
    f = http_flow("POST", "https://api.anthropic.com/v1/messages", body.replace("/", "\\/").encode())
    [*_, record] = run(through(proxy, f))
    assert_silent_502(f) and record["rule"] == "honeytoken"
    [check] = fake.checks
    assert check["honeytokens"] == [DECOY_KEY.lower()] and check["prints"] == [] and check["no_scan"] is True
    # Doorman lets it go (decoy keys set to "Only tell me"): it goes, and the log marks it
    told, fake = no_scan_proxy(answer={"action": "allow", "chars": 0, "sources": [], "reason": ""})
    f = http_flow("POST", "https://api.anthropic.com/v1/messages", body.encode())
    [record] = run(through(told, f))
    assert f.response.status_code == 200 and fake.checks[0]["no_scan"] is True
    assert record["decision"] == "allow" and record["leak"] == {"chars": 0, "sources": []}


def test_a_decoy_key_header_stops_a_large_upload_to_the_model_api_before_it_streams():
    from mitmproxy.proxy.layers.http import ErrorCode, ResponseProtocolError
    proxy, fake = no_scan_proxy()
    f = big_upload("https://api.anthropic.com/v1/files", headers={"x-api-key": DECOY_KEY})
    run(proxy.requestheaders(f))
    stream, out = start_stream(f)
    assert not stream.connected
    [sent] = [c.event for c in out[1:]]
    assert isinstance(sent, ResponseProtocolError) and sent.code == ErrorCode.GENERIC_SERVER_ERROR
    assert sent.message == "Bad Gateway" and len(fake.checks) == 1
    clean = big_upload("https://api.anthropic.com/v1/files", headers={"x-api-key": "sk-ant-mine"})
    run(proxy.requestheaders(clean))
    stream, _ = start_stream(clean)
    assert stream.connected and len(fake.checks) == 1


def test_decoy_keys_in_websocket_messages_and_raw_tcp_to_a_no_scan_host():
    from mitmproxy.websocket import WebSocketMessage
    from wsproto.frame_protocol import Opcode
    proxy, fake = no_scan_proxy()
    ws = http_flow("GET", "https://api.openai.com/v1/realtime")
    run(through(proxy, ws))
    ws.websocket = tflow.twebsocket(messages=False)
    ws.websocket.messages.append(WebSocketMessage(Opcode.TEXT, True, b"CANARY-7f3a9c2e " + SECRET.encode()))
    run(proxy.websocket_message(ws))
    assert not ws.websocket.messages[-1].dropped and fake.checks == []
    ws.websocket.messages.append(WebSocketMessage(Opcode.TEXT, True, f'{{"key": "{DECOY_KEY}"}}'.encode()))
    run(proxy.websocket_message(ws))
    assert ws.websocket.messages[-1].dropped
    assert fake.checks[-1]["no_scan"] is True and fake.checks[-1]["method"] == "WEBSOCKET"
    assert http_records(proxy)[-1]["rule"] == "honeytoken"

    raw, fake = no_scan_proxy()
    f = tcp_flow_to(raw, ("160.79.104.10", 4444), name="api.anthropic.com")
    assert send(raw, f, SECRET.encode()).content and fake.checks == []
    data = f"KEY {DECOY_KEY}\r\n".encode()
    sent = [send(raw, f, data[i:i + 20]) for i in range(0, len(data), 20)]  # split across packets
    assert f.metadata[egress.META]["cut"].rule == "honeytoken" and sent[-1].content == b""
    assert fake.checks[-1]["kind"] == "tcp" and fake.checks[-1]["no_scan"] is True
    raw.tcp_end(f)
    [record] = [r for r in http_records(raw) if r["kind"] == "tcp"]
    assert (record["decision"], record["rule"], record["scanned"]) == ("deny", "honeytoken", False)


# large bodies: test_an_upload_too_large_to_scan_follows_the_unscanned_setting


def test_fingerprinting_is_capped(monkeypatch):
    monkeypatch.setattr(egress, "MAX_PRINT_CHARS", 1000)
    prints, hits, complete, _ = egress._scan("https://x.org/", [], SECRET.encode() * 20, "text/plain", [])
    assert prints and not hits and complete is False
    _, _, complete, _ = egress._scan("https://x.org/", [], SECRET.encode(), "text/plain", [])
    assert complete is True


def test_a_failing_check_blocks_rather_than_passes(monkeypatch):
    proxy, _ = make(answer=leak_answer)
    monkeypatch.setattr(egress, "_scan", lambda *a: 1 / 0)
    f = http_flow("POST", "https://example.org/x", SECRET.encode())
    run(through(proxy, f))
    assert f.response.status_code == 403 and f.response.headers["X-Doorman-Egress"] == "blocked; rule=error"


def test_websocket_message_with_a_leak_is_dropped():
    from mitmproxy.websocket import WebSocketMessage
    from wsproto.frame_protocol import Opcode
    proxy, fake = make(answer=leak_answer)
    f = http_flow("GET", "https://chat.example.org/socket")
    run(through(proxy, f))
    f.websocket = tflow.twebsocket(messages=False)
    f.websocket.messages.append(WebSocketMessage(Opcode.TEXT, True, ("say: " + SECRET).encode()))
    run(proxy.websocket_message(f))
    assert f.websocket.messages[-1].dropped
    f.websocket.messages.append(WebSocketMessage(Opcode.TEXT, True, b"hello"))
    run(proxy.websocket_message(f))
    assert not f.websocket.messages[-1].dropped and len(f.websocket.messages) == 1
    run(proxy.flush())
    assert fake.logs[-1]["method"] == "WEBSOCKET" and fake.logs[-1]["rule"] == "leak"


# ---- names vouch only for the addresses the proxy resolved for them ------------------------------------------

AGENTS_OWN_SERVER = ("45.33.32.156", 443)


def resolved(proxy, name, *ips):
    """The agent looked `name` up through the proxy's DNS and got `ips`."""
    for ip in ips:
        proxy._remember(ip, name, time.time())


def test_spoofed_host_of_a_no_scan_name_is_scanned_and_the_leak_blocked():
    proxy, fake = make(answer=leak_answer)
    f = http_flow("POST", "https://api.anthropic.com/v1/messages", ("fyi: " + SECRET).encode(),
                  server=AGENTS_OWN_SERVER, vouch=False)
    [record] = run(through(proxy, f))
    assert len(fake.checks) == 1 and f.response.status_code == 403
    assert f.response.headers["X-Doorman-Egress"] == "blocked; rule=leak"
    assert record["scanned"] is True
    assert record["detail"].endswith("the name api.anthropic.com doesn't match the address 45.33.32.156")


def test_no_scan_name_that_resolved_to_the_address_is_not_scanned():
    proxy, fake = make(answer=leak_answer)
    resolved(proxy, "api.anthropic.com", "160.79.104.10")
    f = http_flow("POST", "https://api.anthropic.com/v1/messages", SECRET.encode(),
                  server=("160.79.104.10", 443), vouch=False)
    [record] = run(through(proxy, f))
    assert fake.checks == [] and f.response.status_code == 200 and record["scanned"] is False
    assert record["detail"] == ""


def test_a_list_entry_covering_a_name_the_address_has_applies_to_a_sibling_name():
    proxy, fake = make(answer=leak_answer, no_scan=["anthropic.com"])
    resolved(proxy, "api.anthropic.com", "160.79.104.10")
    f = http_flow("POST", "https://console.anthropic.com/x", SECRET.encode(), server=("160.79.104.10", 443),
                  vouch=False)
    run(through(proxy, f))
    assert fake.checks == []  # the entry covers both the claimed name and the name the address really has


def test_spoofed_sni_on_the_passthrough_list_is_not_passed_through():
    from mitmproxy import tls
    proxy, _ = make(passthrough=["pinned.example.com"])
    conn = client_conn(dst=AGENTS_OWN_SERVER)
    context = Context(conn, options.Options())
    context.server.address = conn.sockname
    spoofed = tls.ClientHelloData(context, type("H", (), {"sni": "api.pinned.example.com"})())
    run(proxy.tls_clienthello(spoofed))
    assert spoofed.ignore_connection is False  # intercepted: its requests are read and decided
    resolved(proxy, "api.pinned.example.com", AGENTS_OWN_SERVER[0])
    honest = tls.ClientHelloData(context, type("H", (), {"sni": "api.pinned.example.com"})())
    run(proxy.tls_clienthello(honest))
    assert honest.ignore_connection is True
    by_address, _ = make(passthrough=[f"{AGENTS_OWN_SERVER[0]}:443"])
    any_name = tls.ClientHelloData(context, type("H", (), {"sni": "whatever.example"})())
    run(by_address.tls_clienthello(any_name))
    assert any_name.ignore_connection is True  # an address entry matches by address


def test_exemption_by_name_needs_the_name_to_vouch_but_one_by_address_does_not():
    soon = time.time() + 3600
    proxy, _ = make(countries=["US"], exemptions=[{"target": "exempt.example", "expires": soon}])
    proxy.geoip = type("G", (), {"country": staticmethod(lambda ip: "US"), "rows": 1, "date": None})()
    spoofed = http_flow("GET", "https://exempt.example/", server=AGENTS_OWN_SERVER, vouch=False)
    run(through(proxy, spoofed))
    assert spoofed.response.headers["X-Doorman-Egress"] == "blocked; rule=countries"
    resolved(proxy, "exempt.example", AGENTS_OWN_SERVER[0])  # a DNS answer counts though the lookup found none
    honest = http_flow("GET", "https://exempt.example/", server=AGENTS_OWN_SERVER, vouch=False)
    run(through(proxy, honest))
    assert honest.response.status_code == 200

    proxy.policy["exemptions"] = [{"target": AGENTS_OWN_SERVER[0], "expires": soon}]
    by_address = http_flow("GET", "https://anything.example/", server=AGENTS_OWN_SERVER, vouch=False)
    [*_, record] = run(through(proxy, by_address))
    assert by_address.response.status_code == 200 and record["rule"] == "exemption"


def test_allow_by_name_does_not_open_a_spoofed_connection():
    proxy, _ = make(allow=["allowed.example"], deny=["45.33.32.0/24"])
    spoofed = http_flow("GET", "https://allowed.example/", server=AGENTS_OWN_SERVER, vouch=False)
    run(through(proxy, spoofed))
    assert spoofed.response.headers["X-Doorman-Egress"] == "blocked; rule=deny_list"


def test_claiming_a_denied_name_still_gets_it_denied():
    proxy, _ = make(deny=["evil.example"])
    resolved(proxy, "harmless.example", AGENTS_OWN_SERVER[0])
    f = http_flow("GET", "https://evil.example/", server=AGENTS_OWN_SERVER, vouch=False)
    run(through(proxy, f))
    assert f.response.headers["X-Doorman-Egress"] == "blocked; rule=deny_list"


def test_mismatch_is_noted_but_does_not_block_by_itself():
    proxy, _ = make()
    f = http_flow("GET", "https://example.org/", server=AGENTS_OWN_SERVER, vouch=False)
    [record] = run(through(proxy, f))
    assert f.response.status_code == 200 and record["decision"] == "allow"
    assert record["detail"] == "the name example.org doesn't match the address 45.33.32.156"


def test_a_cdn_address_shared_by_two_names_vouches_for_both():
    proxy, fake = make(answer=leak_answer, no_scan=["one.example", "two.example"])
    for name in ("one.example", "two.example"):
        f = dns_flow(name, ["151.101.1.69"])
        response, f.response = f.response, None
        proxy.dns_request(f)
        f.response = response
        proxy.dns_response(f)
    assert set(proxy._names("151.101.1.69")) == {"one.example", "two.example"}
    for name in ("one.example", "two.example"):
        f = http_flow("POST", f"https://{name}/x", SECRET.encode(), server=("151.101.1.69", 443), vouch=False)
        run(through(proxy, f))
    assert fake.checks == []


def test_dns_answers_are_kept_a_day_and_bounded(monkeypatch):
    proxy, _ = make()
    resolved(proxy, "a.example", "151.101.1.69")
    assert proxy.dns_names["151.101.1.69"]["a.example"] - time.time() > 86000
    monkeypatch.setattr(egress, "NAMES_PER_ADDRESS", 2)
    resolved(proxy, "b.example", "151.101.1.69")
    resolved(proxy, "c.example", "151.101.1.69")
    assert len(proxy._names("151.101.1.69")) == 2 and "c.example" in proxy._names("151.101.1.69")
    monkeypatch.setattr(egress, "DNS_MAP_MAX", 2)
    resolved(proxy, "d.example", "151.101.1.70")
    resolved(proxy, "e.example", "151.101.1.71")
    assert len(proxy.dns_names) <= 2


def test_fresh_lookup_of_a_claimed_name(fake_resolver):
    proxy, _ = make()
    FAKE_DNS["fresh.example"] = {"151.101.1.69", "151.101.65.69"}
    assert run(proxy._vouch("fresh.example", "151.101.65.69")) is True
    assert run(proxy._vouch("fresh.example", "45.33.32.156")) is False
    assert fake_resolver == ["fresh.example"]  # asked once, then cached
    assert run(proxy._vouch("fresh.example", None)) is True     # no address to check (regular mode)
    assert run(proxy._vouch("45.33.32.156", "45.33.32.156")) is True  # an IP literal is its own address
    assert run(proxy._vouch("1.2.3.4", "45.33.32.156")) is False
    assert fake_resolver == ["fresh.example"]


def test_a_slow_lookup_counts_as_no_answer(monkeypatch):
    async def slow(host):
        await asyncio.sleep(5)
        return {"45.33.32.156"}

    monkeypatch.setattr(egress, "_resolve", slow)
    monkeypatch.setattr(egress, "LOOKUP_TIMEOUT", 0.05)
    proxy, _ = make()
    assert run(proxy._vouch("slow.example", "45.33.32.156")) is False


def test_the_real_resolver_answers_with_addresses():
    assert run(REAL_RESOLVE("localhost")) & {"127.0.0.1", "::1"}
    assert run(REAL_RESOLVE("no-such-name.invalid")) == set()


# ---- DNS ----------------------------------------------------------------------------------------------------

def dns_flow(name, answers=()):
    request = tutils.tdnsreq(questions=[dns.Question(name, dns.types.A, dns.classes.IN)])
    f = tflow.tdnsflow(req=request)
    f.client_conn.peername = (AGENT_IP, 53000)
    if answers:
        f.response = request.succeed([dns.ResourceRecord.A(name, __import__("ipaddress").IPv4Address(ip))
                                      for ip in answers])
    return f


def test_dns_tunnel_refused():
    proxy, fake = make()
    f = dns_flow("a" * 51 + ".evil.com")
    proxy.dns_request(f)
    assert f.response is not None and f.response.response_code == response_codes.REFUSED
    ok = dns_flow("mail.google.com")
    proxy.dns_request(ok)
    assert ok.response is None  # left to mitmproxy's resolver, which runs after this addon
    run(proxy.flush())
    [record] = fake.logs
    assert (record["kind"], record["decision"], record["rule"]) == ("dns", "deny", "dns_tunnel")
    assert record["port"] == 53 and record["client_ip"] == AGENT_IP


def test_dns_answer_marks_resolved():
    proxy, fake = make()
    f = dns_flow("example.com", ["93.184.215.14"])
    response = f.response
    f.response = None
    proxy.dns_request(f)
    f.response = response
    proxy.dns_response(f)
    assert proxy._dns_name("93.184.215.14") == "example.com"
    conn = client_conn(dst=("93.184.215.14", 22))
    run(proxy.client_connected(conn))
    assert conn.error is None
    raw = proxy.state[conn.id]["raw"]
    assert raw["host"] == "example.com" and raw["decision"].action == "allow"
    # the same port to an address no lookup led to is a bare IP
    other = client_conn(dst=("45.33.32.156", 22))
    run(proxy.client_connected(other))
    assert other.error is not None
    run(proxy.flush())
    assert [r["kind"] for r in fake.logs] == ["dns", "tcp"]
    assert fake.logs[0]["host"] == "example.com" and fake.logs[0]["ip"] == "93.184.215.14"


# ---- raw TCP ------------------------------------------------------------------------------------------------

def test_nonweb_bare_ip_killed():
    proxy, fake = make()
    conn = client_conn(dst=("45.33.32.156", 4444))
    run(proxy.client_connected(conn))
    assert conn.error.startswith("Doorman's network proxy blocked this connection: a port 4444 connection")
    run(proxy.settle())
    run(proxy.flush())
    [record] = fake.logs
    assert (record["kind"], record["decision"], record["rule"]) == ("tcp", "deny", "bare_ip_nonweb")
    assert (record["ip"], record["port"], record["host"]) == ("45.33.32.156", 4444, None)
    # a web port isn't decided at connect time: the HTTP request is
    web = client_conn(dst=("45.33.32.156", 443))
    run(proxy.client_connected(web))
    assert web.error is None


def test_nonweb_block_setting():
    proxy, _ = make(nonweb="block")
    proxy._remember("185.199.108.153", "mail.example.org", time.time())
    conn = client_conn(dst=("185.199.108.153", 993))
    run(proxy.client_connected(conn))
    assert "only web traffic is allowed here (port 993)" in conn.error


def next_layer_for(conn, data_client=b"", data_server=b"", tls=False):
    context = Context(conn, options.Options())
    context.server.address = conn.sockname
    modes.TransparentProxy(context)
    if tls:
        layers.ServerTLSLayer(context)
        layers.ClientTLSLayer(context)
    nl = layer.NextLayer(context)
    for data, side in ((data_client, context.client), (data_server, context.server)):
        if data:
            nl.events.append(events.DataReceived(side, data))
    return nl


def test_raw_tcp_on_a_web_port_gets_the_rules_too():
    proxy, fake = make()
    shell = client_conn(dst=("45.33.32.156", 443))
    nl = next_layer_for(shell, b"\x00\x01binary-ish reverse shell")
    run(proxy.next_layer(nl))
    assert type(nl.layer).__name__ == "_Refuse"
    out = list(nl.layer.handle_event(events.Start()))
    assert out and all(isinstance(c, commands.CloseConnection) for c in out)
    run(proxy.flush())
    assert fake.logs[-1]["rule"] == "bare_ip_nonweb" and fake.logs[-1]["port"] == 443

    named = client_conn(dst=("185.199.108.153", 22))
    proxy._remember("185.199.108.153", "git.example.org", time.time())
    nl = next_layer_for(named, b"SSH-2.0-OpenSSH_9.6\r\n")
    run(proxy.next_layer(nl))
    assert isinstance(nl.layer, layers.TCPLayer)

    plain_http = client_conn(dst=("45.33.32.156", 80))
    nl = next_layer_for(plain_http, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    run(proxy.next_layer(nl))
    assert nl.layer is None  # mitmproxy's HTTP layer; the request hooks decide
    tls = client_conn(dst=("45.33.32.156", 8443))
    nl = next_layer_for(tls, bytes.fromhex("160301") + b"\x00\x05hello")
    run(proxy.next_layer(nl))
    assert nl.layer is None  # intercepted

    FAKE_DNS["imap.example.org"] = {"45.33.32.156"}
    inside = client_conn(dst=("45.33.32.156", 993))
    inside.sni = "imap.example.org"
    nl = next_layer_for(inside, b"", b"* OK IMAP ready\r\n", tls=True)
    run(proxy.next_layer(nl))
    assert isinstance(nl.layer, layers.TCPLayer)  # a name from SNI that has this address: not a bare IP

    lying = client_conn(dst=("45.33.32.157", 993))
    lying.sni = "imap.example.org"  # a name, but not this address's: still a bare IP no lookup led to
    nl = next_layer_for(lying, b"", b"* OK IMAP ready\r\n", tls=True)
    run(proxy.next_layer(nl))
    assert type(nl.layer).__name__ == "_Refuse"
    run(proxy.flush())
    assert fake.logs[-1]["rule"] == "bare_ip_nonweb"
    assert fake.logs[-1]["detail"].endswith("the name imap.example.org doesn't match the address 45.33.32.157")


def test_tcp_flow_logged_with_bytes_and_messages_not_kept():
    proxy, fake = make()
    proxy._remember("185.199.108.153", "git.example.org", time.time())
    conn = client_conn(dst=("185.199.108.153", 22))
    run(proxy.client_connected(conn))
    f = tflow.ttcpflow(client_conn=conn, messages=[])
    proxy.tcp_start(f)
    from mitmproxy.tcp import TCPMessage
    for from_client, data in ((True, b"x" * 100), (False, b"y" * 250), (True, b"z" * 5)):
        f.messages.append(TCPMessage(from_client, data))
        run(proxy.tcp_message(f))
    assert len(f.messages) == 1
    proxy.tcp_end(f)
    run(proxy.flush())
    [record] = fake.logs
    assert (record["kind"], record["host"], record["port"]) == ("tcp", "git.example.org", 22)
    assert (record["bytes_up"], record["bytes_down"]) == (105, 250)


def test_passthrough_and_tls_failed():
    from mitmproxy import tls
    proxy, fake = make(passthrough=["pinned.example.com"])
    conn = client_conn(dst=("151.101.1.69", 443))
    context = Context(conn, options.Options())
    context.server.address = conn.sockname

    class Hello:
        sni = "api.pinned.example.com"

    FAKE_DNS["api.pinned.example.com"] = {"151.101.1.69"}
    data = tls.ClientHelloData(context, Hello())
    run(proxy.client_connected(conn))
    run(proxy.tls_clienthello(data))
    assert data.ignore_connection is True
    proxy.client_disconnected(conn)

    other = tls.ClientHelloData(context, type("H", (), {"sni": "example.org"})())
    run(proxy.tls_clienthello(other))
    assert other.ignore_connection is False
    conn.sni = "example.org"
    proxy.tls_failed_client(tls.TlsData(conn, context))
    run(proxy.flush())
    passed, failed = [r for r in fake.logs if r["kind"] != "dns"]
    assert (passed["kind"], passed["host"], passed["decision"]) == ("tcp", "api.pinned.example.com", "allow")
    assert failed["kind"] == "tls_failed" and failed["host"] == "example.org"
    assert failed["detail"] == ("the client doesn't trust the proxy's certificate (pinned?); add the host to the "
                                "passthrough list if it's needed")


# ---- records, observer, background --------------------------------------------------------------------------

def test_log_record_shape():
    proxy, _ = make()
    f = http_flow("POST", "https://example.org/a/b?c=d", b"short", {"Content-Type": "text/plain"})
    [record] = run(through(proxy, f))
    assert set(record) == RECORD_FIELDS
    assert record["kind"] == "http" and record["client_ip"] == AGENT_IP
    assert (record["host"], record["ip"], record["port"]) == ("example.org", "93.184.215.14", 443)
    assert (record["method"], record["path"], record["status"]) == ("POST", "/a/b?c=d", 200)
    assert (record["bytes_up"], record["bytes_down"]) == (5, len(b"hello back"))
    assert (record["decision"], record["rule"], record["detail"]) == ("allow", "default", "")
    assert record["leak"] is None and record["process"] is None
    assert isinstance(record["ts"], float) and isinstance(record["duration_ms"], int)
    assert record["scanned"] is True
    json.dumps(record)  # goes to Doorman as JSON


def test_long_path_is_clipped_and_errors_are_logged():
    proxy, _ = make()
    f = http_flow("GET", "https://example.org/" + "p" * 1000)
    f.error = tflow.terr("server went away")
    [record] = run(through(proxy, f))
    assert len(record["path"]) == 300
    assert record["status"] is None and record["detail"] == "failed: server went away"


class Observer(BaseHTTPRequestHandler):
    seen: list = []

    def do_GET(self):  # noqa: N802
        Observer.seen.append(self.path)
        body = json.dumps({"pid": 77, "exe": "/usr/bin/curl", "cmdline": "curl -s https://example.org/x",
                           "chain": [{"pid": 42, "cmdline": "bash -c curl -s https://example.org/x"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def observer():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Observer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    Observer.seen = []
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_observer_info_attached(observer):
    async def scenario():
        proxy, fake = make(observer=observer)
        conn = client_conn(dst=("93.184.215.14", 443), src_port=41394)
        await proxy.client_connected(conn)
        f = http_flow("GET", "https://example.org/x", conn=conn)
        return await through(proxy, f)

    [record] = run(scenario())
    assert record["process"]["pid"] == 77 and record["process"]["chain"][0]["pid"] == 42
    assert Observer.seen == ["/lookup?port=41394&dst=93.184.215.14%3A443"]


def test_observer_down_costs_at_most_its_timeout():
    async def scenario():
        proxy, fake = make(observer="http://127.0.0.1:9")  # nothing listens on the discard port
        conn = client_conn()
        start = time.monotonic()
        await proxy.client_connected(conn)
        logs = await through(proxy, http_flow("GET", "https://example.org/x", conn=conn))
        return logs, time.monotonic() - start

    [record], took = run(scenario())
    assert record["process"] is None and took < 1.0


def test_policy_poll_keeps_the_last_good_policy_and_caches_it(tmp_path):
    fake = FakeDoorman()
    proxy = egress.DoormanEgress(fake, None, None, state_dir=str(tmp_path))
    assert proxy.policy["version"] == rules.policy_example()["version"]  # defaults until Doorman answers
    fake.policy_value = rules.policy_example()
    run(proxy.poll_policy())
    assert json.loads((tmp_path / "policy.json").read_text()) == rules.policy_example()  # kept even if unchanged
    policy = rules.policy_example()
    policy["deny"] = ["blocked.example"]
    policy["version"] = rules.policy_version(policy)
    fake.policy_value = policy
    run(proxy.poll_policy())
    assert proxy.policy["deny"] == ["blocked.example"] and proxy.policy_at > 0
    fake.policy_value = None  # Doorman down
    run(proxy.poll_policy())
    assert proxy.policy["deny"] == ["blocked.example"]
    restarted = egress.DoormanEgress(fake, None, None, state_dir=str(tmp_path))
    assert restarted.policy["deny"] == ["blocked.example"]


def test_log_queue_waits_for_doorman_and_is_bounded(monkeypatch):
    monkeypatch.setattr(egress, "LOG_QUEUE", 3)
    proxy, fake = make()
    fake.send_log = lambda records: False
    for n in range(5):
        proxy._record(None, AGENT_IP, kind="dns", host=f"n{n}.example")
    run(proxy.flush())
    assert len(proxy.records) == 3 and proxy.dropped == 2
    sent = []
    fake.send_log = lambda records: sent.append(list(records)) or True
    monkeypatch.setattr(egress, "LOG_BATCH", 2)
    run(proxy.flush())
    assert [len(b) for b in sent] == [2, 1] and not proxy.records
    assert [r["host"] for b in sent for r in b] == ["n2.example", "n3.example", "n4.example"]


def test_status_body():
    proxy, fake = make()
    run(proxy.send_status())
    [body] = fake.statuses
    assert body["policy_version"] == proxy.policy["version"] and body["geoip"] is None
    assert {"connections", "blocked", "queued", "dropped", "mitmproxy", "started"} <= set(body)
    assert body["observer"] is None  # no observer at all: Doorman says the decoy keys aren't watched


class Health(BaseHTTPRequestHandler):
    answer: dict = {}

    def do_GET(self):  # noqa: N802
        body = json.dumps(Health.answer).encode()
        self.send_response(200 if self.path == "/health" else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_status_says_whether_the_observer_answers_and_its_tripwire_is_armed():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Health)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        proxy, fake = make(observer=f"http://127.0.0.1:{server.server_address[1]}")
        Health.answer = {"ok": True, "tripwire": {"armed": True, "last_error": None, "path": "/x"}}
        run(proxy.send_status())
        assert fake.statuses[-1]["observer"] == {"reachable": True, "armed": True, "error": None}
        Health.answer = {"ok": True, "tripwire": {"armed": False, "last_error": "[Errno 2] No such file", "path": "/x"}}
        run(proxy.send_status())
        assert fake.statuses[-1]["observer"] == {"reachable": True, "armed": False, "error": "[Errno 2] No such file"}
        Health.answer = {"ok": True, "tripwire": None}  # started without OBSERVER_DECOY_PATH
        run(proxy.send_status())
        assert fake.statuses[-1]["observer"]["armed"] is False and "OBSERVER_DECOY_PATH" in \
            fake.statuses[-1]["observer"]["error"]
    finally:
        server.shutdown()
        server.server_close()
    down, fake = make(observer="http://127.0.0.1:9")
    run(down.send_status())
    assert fake.statuses[-1]["observer"] == {"reachable": False, "armed": False, "error": "the observer doesn't answer"}


def test_geoip_loaded_from_the_newest_file(tmp_path):
    (tmp_path / "dbip-country-lite-2026-10.csv").write_text("1.0.0.0,1.0.0.255,AU\n")
    (tmp_path / "dbip-country-lite-2026-11.csv").write_text("1.0.0.0,1.0.0.255,RU\n")
    proxy, _ = make()
    proxy.geoip_path = tmp_path
    run(proxy.refresh_geoip())
    assert proxy.geoip.date == "2026-11" and proxy.geoip.country("1.0.0.7") == "RU"
    f = http_flow("GET", "https://example.ru/", server=("1.0.0.7", 443))
    run(through(proxy, f))
    assert f.response.headers["X-Doorman-Egress"] == "blocked; rule=countries"


def test_script_loads_in_mitmproxy(monkeypatch, tmp_path):
    monkeypatch.setenv("DOORMAN_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("DOORMAN_EGRESS_TOKEN", "dme_x")
    monkeypatch.setenv("EGRESS_GEOIP", "0")
    monkeypatch.setenv("EGRESS_STATE_DIR", str(tmp_path))
    with taddons.context() as tctx:
        module = tctx.script(str(Path(egress.__file__)))  # mitmproxy registers the module, its `addons` below it
        [loaded] = module.addons
        assert type(loaded).__name__ == "DoormanEgress"
        assert loaded.client.token == "dme_x" and loaded.geoip_path is None


# ---- the client ---------------------------------------------------------------------------------------------

class Api(BaseHTTPRequestHandler):
    calls: list = []

    def _answer(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        Api.calls.append(("GET", self.path, self.headers.get("Authorization"), None))
        if self.headers.get("Authorization") != "Bearer dme_good":
            return self._answer(401, {"detail": "no"})
        self._answer(200, rules.policy_example())

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Api.calls.append(("POST", self.path, self.headers.get("Authorization"), body))
        if self.path.endswith("/check"):
            return self._answer(200, {"action": "allow", "chars": 0, "sources": [], "reason": ""})
        self._answer(200, {"ok": len(body.get("records", []))})

    def log_message(self, *args):
        pass


def test_client_against_the_proxy_api(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")  # must be ignored
    server = ThreadingHTTPServer(("127.0.0.1", 0), Api)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    Api.calls = []
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}/"
        good = DoormanClient(base, "dme_good")
        assert good.policy()["version"] == rules.policy_example()["version"]
        assert good.check({"prints": [1]})["action"] == "allow"
        assert good.send_log([{"kind": "dns"}]) is True
        assert good.status({"queued": 0}) is True
        assert [c[1] for c in Api.calls] == ["/v1/egress/proxy/policy", "/v1/egress/proxy/check",
                                             "/v1/egress/proxy/log", "/v1/egress/proxy/status"]
        assert Api.calls[2][3] == {"records": [{"kind": "dns"}]}
        assert all(c[2] == "Bearer dme_good" for c in Api.calls)
        bad = DoormanClient(base, "dme_bad")
        assert bad.policy() is None and "401" in bad.last_error
    finally:
        server.shutdown()
        server.server_close()
    down = DoormanClient("http://127.0.0.1:9", "dme_good", timeout=0.5)
    assert down.policy() is None and down.check({}) is None and down.send_log([]) is False


# ---- review fixes ----------------------------------------------------------------------------------------------

def http_records(proxy):
    run(proxy.settle())
    run(proxy.flush())
    return [r for r in proxy.client.logs if r["kind"] != "dns"]


# 1. a protocol switch to anything but WebSocket

def test_upgrade_to_an_unknown_protocol_gets_a_403_not_a_pipe():
    proxy, fake = make()
    f = http_flow("GET", "http://example.org/chat", headers={"Upgrade": "h2c-tunnel", "Connection": "upgrade"})
    run(proxy.requestheaders(f))
    run(proxy.request(f))
    f.response = http.Response.make(101, b"", {"Upgrade": "h2c-tunnel", "Connection": "upgrade"})
    run(proxy.response(f))
    assert f.response.status_code == 403 and f.response.headers["X-Doorman-Egress"] == "blocked; rule=upgrade"
    assert f.response.headers["Connection"] == "close"
    [record] = http_records(proxy)
    assert (record["decision"], record["rule"], record["status"]) == ("deny", "upgrade", 403)
    assert "h2c-tunnel" in record["detail"]
    # a WebSocket handshake mitmproxy reads (it set flow.websocket before the hook) stays a 101
    ws = http_flow("GET", "https://example.org/socket")
    run(proxy.request(ws))
    ws.response = http.Response.make(101, b"", {"Upgrade": "websocket"})
    ws.websocket = tflow.twebsocket(messages=False)
    run(proxy.response(ws))
    assert ws.response.status_code == 101


# 2. raw TCP is scanned; raw data on a web port is refused

def tcp_flow_to(proxy, dst, name="git.example.org"):
    if name:
        proxy._remember(dst[0], name, time.time())
    conn = client_conn(dst=dst)
    run(proxy.client_connected(conn))
    f = tflow.ttcpflow(client_conn=conn, messages=[])
    proxy.tcp_start(f)
    return f


def send(proxy, f, data, from_client=True):
    from mitmproxy.tcp import TCPMessage
    message = TCPMessage(from_client, data)
    f.messages.append(message)
    run(proxy.tcp_message(f))
    return message


def test_raw_tcp_leak_split_across_packets_cuts_the_connection():
    proxy, fake = make(answer=leak_answer)
    f = tcp_flow_to(proxy, ("185.199.108.153", 4444))
    data = ("PRIVMSG #x :" + SECRET + "\r\n").encode()
    sent = []
    for i in range(0, len(data), 17):  # small packets: no single one holds a whole gram
        sent.append(send(proxy, f, data[i:i + 17]))
        if f.metadata[egress.META].get("cut"):
            break
    assert f.metadata[egress.META]["cut"].rule == "leak"
    assert sent[-1].content == b""  # the packet that completed the leak isn't relayed
    assert all(c.get("kind") == "tcp" for c in fake.checks) and fake.checks
    assert fake.checks[0]["url"] == "tcp://git.example.org:4444"
    later = send(proxy, f, b"more")
    assert later.content == b""
    proxy.tcp_end(f)
    [record] = http_records(proxy)
    assert (record["kind"], record["decision"], record["rule"]) == ("tcp", "deny", "leak")
    assert record["leak"]["chars"] >= 100 and record["scanned"] is True


def test_raw_tcp_without_a_leak_passes():
    proxy, fake = make(answer=leak_answer)
    f = tcp_flow_to(proxy, ("185.199.108.153", 4444))
    for _ in range(3):
        message = send(proxy, f, (RECIPE_TEXT + "\n").encode())
        assert message.content
    assert not f.metadata[egress.META].get("cut")
    checks = len(fake.checks)
    # SSH, TLS records: nothing to ask about. The same bytes every run: random ones hold a readable run now and then
    binary = send(proxy, f, random.Random(1).randbytes(2048))
    assert binary.content and len(fake.checks) == checks


def test_watched_tcp_layer_closes_a_cut_connection():
    from mitmproxy.proxy import events as ev
    from mitmproxy.proxy.layers.tcp import TcpMessageHook
    conn = client_conn(dst=("185.199.108.153", 4444))
    context = Context(conn, options.Options())
    context.server.address = conn.sockname
    context.server.timestamp_start = time.time()
    context.server.state = __import__("mitmproxy").connection.ConnectionState.OPEN
    watched = egress._WatchedTCP(context)
    [start] = list(watched.handle_event(ev.Start()))  # TcpStartHook
    list(watched.handle_event(ev.HookCompleted(start, None)))
    out = list(watched.handle_event(ev.DataReceived(context.client, b"hello")))
    assert isinstance(out[0], TcpMessageHook)
    watched.flow.metadata[egress.META] = {"cut": rules.Decision("deny", "leak", "x")}
    out = list(watched.handle_event(ev.HookCompleted(out[0], None)))
    assert not any(isinstance(c, commands.SendData) for c in out)
    assert any(isinstance(c, commands.CloseConnection) for c in out)


def test_raw_data_on_a_web_port_is_refused_unless_allowed_by_address():
    proxy, fake = make()
    proxy._remember("185.199.108.153", "cdn.example.org", time.time())
    shell = client_conn(dst=("185.199.108.153", 443))
    nl = next_layer_for(shell, b"\x00\x01binary-ish reverse shell")
    run(proxy.next_layer(nl))
    assert type(nl.layer).__name__ == "_Refuse"
    run(proxy.flush())
    assert fake.logs[-1]["rule"] == "raw_on_web_port"
    allowed, _ = make(allow=["185.199.108.153"])
    nl = next_layer_for(client_conn(dst=("185.199.108.153", 443)), b"\x00\x01binary")
    run(allowed.next_layer(nl))
    assert isinstance(nl.layer, egress._WatchedTCP)


def test_a_short_first_packet_is_left_to_the_http_layer():
    proxy, _ = make()
    proxy._remember("185.199.108.153", "cdn.example.org", time.time())
    for dst in (("185.199.108.153", 80), ("185.199.108.153", 4444)):
        nl = next_layer_for(client_conn(dst=dst), b"G")
        run(proxy.next_layer(nl))
        assert nl.layer is None  # mitmproxy's HTTP layer reads on (rawtcp is off)
    assert egress._probably_no_http(b"", b"* OK IMAP ready\r\n")  # the server spoke first


# 3. padding, many prints, budget

def test_padding_doesnt_push_the_secret_out_of_the_scan():
    body = json.dumps([" " * 4_100_000, SECRET]).encode()
    prints, _, complete, _ = egress._scan("http://x/y", [], body, "application/json", [])
    assert fingerprint.prints(SECRET) <= set(prints) and complete is True
    letters = json.dumps(["a" * 4_100_000, SECRET]).encode()
    _, _, complete, _ = egress._scan("http://x/y", [], letters, "application/json", [])
    assert complete is False


def test_incomplete_scan_follows_the_unscanned_setting(monkeypatch):
    monkeypatch.setattr(egress, "MAX_PRINT_CHARS", 2000)
    body = (RECIPE_TEXT * 40).encode()
    proxy, _ = make(answer={"action": "allow", "chars": 0, "sources": [], "reason": ""}, unscanned="block")
    f = http_flow("POST", "https://example.org/x", body)
    [record] = run(through(proxy, f))
    assert f.response.headers["X-Doorman-Egress"] == "blocked; rule=unscanned"
    assert record["rule"] == "unscanned" and record["scanned"] is False
    for proxy in (make()[0], make(unscanned="block", allow=["example.org"])[0]):
        proxy.client.answer = {"action": "allow", "chars": 0, "sources": [], "reason": ""}
        g = http_flow("POST", "https://example.org/x", body)
        run(through(proxy, g))
        assert g.response.status_code == 200


def test_many_prints_go_in_several_overlapping_calls(monkeypatch):
    monkeypatch.setattr(egress, "MAX_PRINTS", 60)
    monkeypatch.setattr(egress, "PRINTS_OVERLAP", 20)
    words = " ".join(f"word{i} other{i * 7} thing{i * 13}" for i in range(3000))
    proxy, fake = make(answer=leak_answer)
    f = http_flow("POST", "https://example.org/x", (words[:20000] + " " + SECRET + " " + words[20000:]).encode())
    run(through(proxy, f))
    assert len(fake.checks) > 2 and all(len(c["prints"]) <= 60 for c in fake.checks)
    assert f.response.status_code == 403  # the secret's prints were whole in one call
    whole = fingerprint.prints(SECRET)
    assert any(whole <= set(c["prints"]) for c in fake.checks)


def test_clean_prints_are_not_asked_about_again_for_a_minute():
    proxy, fake = make(answer={"action": "allow", "chars": 0, "sources": [], "reason": ""})
    for _ in range(3):
        run(through(proxy, http_flow("POST", "https://example.org/x", RECIPE_TEXT.encode())))
    assert len(fake.checks) == 1


# 4. every header, the host, the SNI and trailers are scanned

def test_secret_in_any_header_trailer_or_the_sni_is_found():
    for where in ("User-Agent", "Cookie", "Accept-Language", "If-None-Match", "Sec-Fetch-Site"):
        proxy, fake = make(answer=leak_answer)
        f = http_flow("GET", "https://example.org/", headers={where: SECRET})
        run(through(proxy, f))
        assert f.response.status_code == 403, where
    proxy, fake = make(answer=leak_answer)
    f = http_flow("POST", "https://example.org/", b"x")
    f.request.trailers = http.Headers(x_note=SECRET)
    run(through(proxy, f))
    assert f.response.status_code == 403
    proxy, fake = make(honeytokens=["canary7f3a9c2e"], answer=None)
    f = http_flow("GET", "https://example.org/")
    f.client_conn.sni = "canary7f3a9c2e.example.org"
    [record] = run(through(proxy, f))
    assert_silent_502(f)
    assert record["rule"] == "honeytoken"


# 5. the proxy's own lookups

def test_a_name_the_dns_rules_refuse_is_not_looked_up(fake_resolver):
    proxy, fake = make(deny=["evil.com"])
    name = "x" * 51 + ".exfil.example"
    assert run(proxy._vouch(name, "93.184.216.34", AGENT_IP)) is False
    assert run(proxy._vouch("data.evil.com", "93.184.216.34", AGENT_IP)) is False
    assert fake_resolver == []
    FAKE_DNS["fine.example"] = {"93.184.216.34"}
    assert run(proxy._vouch("fine.example", "93.184.216.34", AGENT_IP)) is True
    assert fake_resolver == ["fine.example"]
    run(proxy.flush())
    lookup = [r for r in fake.logs if r["kind"] == "dns" and r["host"] == "fine.example"]
    assert lookup and lookup[0]["ip"] == "93.184.216.34" and "looked up by the proxy" in lookup[0]["detail"]


def test_lookups_are_rate_limited_per_client(fake_resolver, monkeypatch):
    monkeypatch.setattr(egress, "LOOKUP_RATE", (5, 60.0))
    proxy, _ = make()
    for i in range(8):
        run(proxy._vouch(f"n{i}.example.org", "93.184.216.34", AGENT_IP))
    assert len(fake_resolver) == 5
    run(proxy._vouch("other.example.org", "93.184.216.34", "172.29.0.9"))
    assert len(fake_resolver) == 6


def test_hung_lookups_dont_hold_up_the_default_executor(monkeypatch):
    import socket as sock
    release = threading.Event()
    monkeypatch.setattr(sock, "getaddrinfo", lambda *a, **k: release.wait(5) and [])

    async def scenario():
        lookups = [asyncio.create_task(asyncio.wait_for(REAL_RESOLVE(f"h{i}.example"), 0.2))
                   for i in range(64)]  # more than the default executor has threads
        await asyncio.sleep(0.05)  # the lookups are running
        start = time.monotonic()
        assert await asyncio.wait_for(asyncio.to_thread(lambda: 42), 2) == 42
        took = time.monotonic() - start
        await asyncio.gather(*lookups, return_exceptions=True)
        return took

    try:
        assert run(scenario()) < 1.0
    finally:
        release.set()


# 7. nothing goes upstream before a decision

def test_denied_addresses_and_names_are_never_connected():
    from mitmproxy import tls
    from mitmproxy.proxy import server_hooks
    proxy, _ = make(countries=["RU"], deny=["evil.example"])
    proxy.geoip = type("G", (), {"country": staticmethod(lambda ip: "RU" if ip.startswith("5.") else "NL"),
                                 "rows": 1, "date": None})()
    ru = client_conn(dst=("5.6.7.8", 443))
    run(proxy.client_connected(ru))
    assert ru.error is None  # a web port: the request gets its 403
    data = server_hooks.ServerConnectionHookData(tflow.tserver_conn(), ru)
    proxy.server_connect(data)
    assert "5.6.7.8 is in RU" in data.server.error
    f = http_flow("GET", "https://news.example/", conn=ru, server=("5.6.7.8", 443))
    run(through(proxy, f))
    assert f.response.headers["X-Doorman-Egress"] == "blocked; rule=countries"

    nl = client_conn(dst=("93.184.216.34", 443))
    run(proxy.client_connected(nl))
    context = Context(nl, options.Options())
    context.server.address = nl.sockname
    hello = tls.ClientHelloData(context, type("H", (), {"sni": "api.evil.example"})())
    run(proxy.tls_clienthello(hello))
    data = server_hooks.ServerConnectionHookData(tflow.tserver_conn(), nl)
    proxy.server_connect(data)
    assert "evil.example is on the owner's deny list" in data.server.error
    nl.sni = "api.evil.example"
    g = http_flow("GET", "https://other.example/", conn=nl, server=("93.184.216.34", 443))
    run(through(proxy, g))
    assert g.response.headers["X-Doorman-Egress"] == "blocked; rule=deny_list"

    fine = client_conn(dst=("93.184.216.34", 443))
    run(proxy.client_connected(fine))
    data = server_hooks.ServerConnectionHookData(tflow.tserver_conn(), fine)
    proxy.server_connect(data)
    assert data.server.error is None


def lazy_options():
    opts = options.Options()
    opts.add_option("connection_strategy", str, "lazy", "as configure() makes it")
    return opts


def test_allowed_nonweb_connections_are_opened_right_away():
    proxy, _ = make()
    proxy._remember("185.199.108.153", "mail.example.org", time.time())
    conn = client_conn(dst=("185.199.108.153", 143))
    run(proxy.client_connected(conn))
    context = Context(conn, options.Options())
    context.options = lazy_options()
    context.server.address = conn.sockname
    top = modes.TransparentProxy(context)
    out = list(top.handle_event(events.Start()))
    assert isinstance(out[0], commands.OpenConnection)  # server-first protocols (IMAP) still work
    web = client_conn(dst=("185.199.108.153", 443))
    run(proxy.client_connected(web))
    context = Context(web, options.Options())
    context.options = lazy_options()
    context.server.address = web.sockname
    out = list(modes.TransparentProxy(context).handle_event(events.Start()))
    assert not any(isinstance(c, commands.OpenConnection) for c in out)


# 8. an allow or exception by address doesn't open a denied name

def test_address_allow_still_applies_name_denies():
    proxy, _ = make(allow=["allowed.com"], deny=["evil.com"])
    resolved(proxy, "allowed.com", "104.16.1.1")
    for host, method, rule in (("evil.com", "POST", "deny_list"), ("x.trycloudflare.com", "POST", "exfil_upload")):
        decision, _ = run(proxy._decide_named("http", host, "104.16.1.1", 443, method))
        assert (decision.action, decision.rule) == ("deny", rule), host
    by_ip, _ = make(exemptions=[{"target": "104.16.1.1", "expires": time.time() + 60}], deny=["evil.com"])
    FAKE_DNS["evil.com"] = {"104.16.1.1"}  # even a name that vouches
    decision, _ = run(by_ip._decide_named("http", "evil.com", "104.16.1.1", 443, "GET"))
    assert decision.rule == "deny_list"
    decision, _ = run(by_ip._decide_named("http", "fine.example", "104.16.1.1", 443, "GET"))
    assert decision.rule == "exemption"


# 9. a WebSocket message the proxy can't check doesn't go out

def test_websocket_message_is_dropped_when_checking_fails(monkeypatch):
    from mitmproxy.websocket import WebSocketMessage
    from wsproto.frame_protocol import Opcode
    proxy, fake = make(answer=leak_answer)
    f = http_flow("GET", "https://chat.example.org/socket")
    run(through(proxy, f))
    f.websocket = tflow.twebsocket(messages=False)
    monkeypatch.setattr(egress, "_scan", lambda *a: (_ for _ in ()).throw(RecursionError()))
    f.websocket.messages.append(WebSocketMessage(Opcode.TEXT, True, b"[[[[hello"))
    run(proxy.websocket_message(f))
    assert f.websocket.messages[-1].dropped
    run(proxy.flush())
    assert fake.logs[-1]["rule"] == "error" and fake.logs[-1]["decision"] == "deny"


# 11. many new names under one domain

def test_many_new_names_under_one_domain_are_refused():
    proxy, fake = make()
    for i in range(30):
        f = dns_flow(f"c{i}x.exfil.example")
        proxy.dns_request(f)
        assert f.response is None
    f = dns_flow("c30x.exfil.example")
    proxy.dns_request(f)
    assert f.response.response_code == response_codes.REFUSED
    again = dns_flow("c3x.exfil.example")  # seen before: fine
    proxy.dns_request(again)
    assert again.response is None
    run(proxy.flush())
    denied = [r for r in fake.logs if r["decision"] == "deny"]
    assert denied[-1]["rule"] == "dns_tunnel"
    assert denied[-1]["detail"] == "many different names under exfil.example: looks like data hidden in DNS"


# 12. DNS queries with more or fewer than one question; domain fronting

def test_dns_query_must_ask_one_question():
    two = tutils.tdnsreq(questions=[dns.Question("a.example", dns.types.A, dns.classes.IN),
                                    dns.Question("b.example", dns.types.A, dns.classes.IN)])
    f = tflow.tdnsflow(req=two)
    f.client_conn.peername = (AGENT_IP, 53000)
    proxy, _ = make()
    proxy.dns_request(f)
    assert f.response.response_code == response_codes.REFUSED
    none = tflow.tdnsflow(req=tutils.tdnsreq(questions=[]))
    none.client_conn.peername = (AGENT_IP, 53000)
    proxy.dns_request(none)
    assert none.response.response_code == response_codes.REFUSED


def test_domain_fronting_doesnt_get_no_scan():
    proxy, fake = make(answer=leak_answer)
    resolved(proxy, "api.anthropic.com", "160.79.104.10")
    f = http_flow("POST", "https://api.anthropic.com/v1/messages", SECRET.encode(), server=("160.79.104.10", 443),
                  vouch=False)
    f.client_conn.sni = "attacker-front.example"
    [record] = run(through(proxy, f))
    assert fake.checks and f.response.status_code == 403
    assert "the TLS name attacker-front.example isn't the Host api.anthropic.com" in record["detail"]
    sibling, fake = make(answer=leak_answer, no_scan=["anthropic.com"])
    resolved(sibling, "api.anthropic.com", "160.79.104.10")
    g = http_flow("POST", "https://console.anthropic.com/x", SECRET.encode(), server=("160.79.104.10", 443),
                  vouch=False)
    g.client_conn.sni = "api.anthropic.com"
    run(through(sibling, g))
    assert fake.checks  # fronted: the sibling rule doesn't make it unscanned


# 14., 15. the log queue keeps what matters; DNS memory is bounded by names too

def test_full_log_queue_keeps_blocks_over_allowed_dns(monkeypatch):
    monkeypatch.setattr(egress, "LOG_QUEUE", 5)
    proxy, fake = make()
    fake.send_log = lambda records: False
    proxy._record(None, AGENT_IP, kind="http", host="up.example", decision="deny", rule="leak")
    for n in range(50):
        proxy._record(None, AGENT_IP, kind="dns", host=f"n{n}.example")
    proxy._record(None, AGENT_IP, kind="http", host="up2.example", decision="deny", rule="leak")
    hosts = [r["host"] for r in proxy.records]
    assert "up.example" in hosts and "up2.example" in hosts and len(hosts) == 5
    assert proxy.dropped == 47 and proxy.status_body()["dropped"] == 47
    for n in range(10):
        proxy._record(None, AGENT_IP, kind="http", host=f"d{n}.example", decision="deny", rule="leak")
    assert len(proxy.records) == 5 and all(r["decision"] == "deny" for r in proxy.records)


def test_dns_memory_is_bounded_by_names(monkeypatch):
    monkeypatch.setattr(egress, "DNS_NAMES_MAX", 100)
    proxy, _ = make()
    now = time.time()
    for i in range(1000):
        proxy._remember(f"151.101.{i // 250}.{i % 250}", f"n{i}.example", now)
        proxy._remember("151.101.9.9", f"cdn{i}.example", now)
    assert proxy.dns_entries <= 100 and sum(map(len, proxy.dns_names.values())) == proxy.dns_entries
    assert len(proxy.dns_names["151.101.9.9"]) <= egress.NAMES_PER_ADDRESS


# 16. the contract with Doorman

def test_client_reads_unknown_as_no_answer_and_waits_six_seconds_for_a_check():
    client = DoormanClient("http://127.0.0.1:9", "x")
    assert client.check_timeout == 6.0
    client._call = lambda method, path, body=None, timeout=None: {"action": "unknown", "reason": "busy"}
    assert client.check({"prints": []}) is None and "busy" in client.last_error


def test_exemption_for_other_clients_doesnt_apply():
    soon = time.time() + 60
    proxy, _ = make(exemptions=[{"target": "webhook.site", "expires": soon, "clients": ["172.29.0.77"]}])
    f = http_flow("POST", "https://webhook.site/x", b"hi")
    run(through(proxy, f))
    assert f.response.headers["X-Doorman-Egress"] == "blocked; rule=exfil_upload"
    mine, _ = make(exemptions=[{"target": "webhook.site", "expires": soon, "clients": [AGENT_IP]}])
    g = http_flow("POST", "https://webhook.site/x", b"hi")
    run(through(mine, g))
    assert g.response.status_code == 200
    private, _ = make(exemptions=[{"target": "10.1.2.3:22", "expires": soon, "clients": ["172.29.0.77"]}])
    nas = client_conn(dst=("10.1.2.3", 22))
    run(private.client_connected(nas))
    assert "private address" in nas.error


def test_no_scan_records_carry_the_api_key_hash():
    import hashlib
    proxy, _ = make()
    f = http_flow("POST", "https://api.anthropic.com/v1/messages", b"{}", {"x-api-key": "sk-ant-secret"})
    [record] = run(through(proxy, f))
    assert record["auth_hash"] == hashlib.sha256(b"sk-ant-secret").hexdigest()[:16]
    g = http_flow("POST", "https://api.openai.com/v1/x", b"{}")
    [*_, record] = run(through(proxy, g))
    assert record["auth_hash"] is None
    h = http_flow("POST", "https://example.org/x", b"{}", {"Authorization": "Bearer x"})
    [*_, record] = run(through(proxy, h))
    assert "auth_hash" not in record


# ---- quarantine: a client that touched the decoy keys gets nothing ---------------------------------------------

def test_a_quarantined_client_gets_no_dns_and_no_connection():
    proxy, fake = make(allow=["allowed.example"], quarantine=[AGENT_IP])
    for name in ("api.anthropic.com", "allowed.example", "example.org"):
        f = dns_flow(name)
        proxy.dns_request(f)
        assert f.response.response_code == response_codes.REFUSED, name
    proxy.dns_request(dns_flow("example.org"))  # retried: refused again, logged once a minute
    for dst in (("160.79.104.10", 443), ("185.199.108.153", 4444), ("93.184.215.14", 80)):
        conn = client_conn(dst=dst)
        run(proxy.client_connected(conn))
        assert conn.error and "quarantined" in conn.error, dst
    from mitmproxy.proxy import server_hooks
    data = server_hooks.ServerConnectionHookData(tflow.tserver_conn(), client_conn())
    proxy.server_connect(data)
    assert data.server.error
    run(proxy.settle())
    run(proxy.flush())
    records = fake.logs
    assert {r["rule"] for r in records} == {"quarantine"} and {r["decision"] for r in records} == {"deny"}
    assert sorted(r["host"] for r in records if r["kind"] == "dns") == ["allowed.example", "api.anthropic.com",
                                                                        "example.org"]
    assert sorted(r["port"] for r in records if r["kind"] == "tcp") == [80, 443, 4444]
    # another client on the network isn't touched
    other = client_conn()
    other.peername = ("172.29.0.140", 41000)
    run(proxy.client_connected(other))
    assert other.error is None


def test_a_request_on_a_connection_open_before_the_quarantine_gets_a_silent_502():
    proxy, fake = make()
    conn = client_conn(dst=("160.79.104.10", 443))
    run(proxy.client_connected(conn))  # connected while still allowed
    proxy.policy["quarantine"] = [AGENT_IP]
    f = http_flow("POST", "https://api.anthropic.com/v1/messages", b"{}", conn=conn,
                  server=("160.79.104.10", 443))  # the model API (no_scan) included
    [record] = run(through(proxy, f))
    assert_silent_502(f)
    assert f.response.headers["Connection"] == "close"
    assert (record["decision"], record["rule"], record["status"]) == ("deny", "quarantine", 502)
    assert not fake.checks
    # quarantined while the request's body was arriving: the request hook still stops it
    proxy.policy["quarantine"] = []
    g = http_flow("POST", "https://example.org/x", b"hello")
    run(proxy.requestheaders(g))
    proxy.policy["quarantine"] = [AGENT_IP]
    run(proxy.request(g))
    assert_silent_502(g)


def test_a_quarantined_streaming_upload_is_refused_silently():
    from mitmproxy.proxy.layers.http import ErrorCode, ResponseProtocolError
    proxy, _ = make(quarantine=[AGENT_IP])
    f = big_upload("https://example.org/up")
    run(proxy.requestheaders(f))
    stream, out = start_stream(f)
    assert not stream.connected
    [sent] = [c.event for c in out[1:]]
    assert isinstance(sent, ResponseProtocolError) and sent.code == ErrorCode.GENERIC_SERVER_ERROR
    assert sent.message == "Bad Gateway"


def test_raw_tcp_and_websocket_open_before_the_quarantine_are_cut():
    from mitmproxy.websocket import WebSocketMessage
    from wsproto.frame_protocol import Opcode
    proxy, fake = make()
    f = tcp_flow_to(proxy, ("185.199.108.153", 4444))
    assert send(proxy, f, b"hello").content == b"hello"
    proxy.policy["quarantine"] = [AGENT_IP]
    assert send(proxy, f, b"from the server", from_client=False).content == b""
    assert f.metadata[egress.META]["cut"].rule == "quarantine"
    proxy.tcp_end(f)
    [record] = [r for r in http_records(proxy) if r["kind"] == "tcp"]
    assert (record["decision"], record["rule"]) == ("deny", "quarantine")

    proxy.policy["quarantine"] = []
    ws = http_flow("GET", "https://chat.example.org/socket")
    run(through(proxy, ws))
    ws.websocket = tflow.twebsocket(messages=False)
    proxy.policy["quarantine"] = [AGENT_IP]
    for from_client in (True, False):
        ws.websocket.messages.append(WebSocketMessage(Opcode.TEXT, from_client, b"hi"))
        run(proxy.websocket_message(ws))
        assert ws.websocket.messages[-1].dropped
    assert http_records(proxy)[-1]["rule"] == "quarantine"


def test_a_quarantined_client_isnt_passed_through_or_raw_relayed():
    from mitmproxy import tls
    proxy, _ = make(passthrough=["pinned.example.com"], allow=["185.199.108.153"])
    conn = client_conn(dst=("151.101.1.69", 443))
    context = Context(conn, options.Options())
    context.server.address = conn.sockname
    FAKE_DNS["api.pinned.example.com"] = {"151.101.1.69"}
    proxy.policy["quarantine"] = [AGENT_IP]
    hello = tls.ClientHelloData(context, type("H", (), {"sni": "api.pinned.example.com"})())
    run(proxy.tls_clienthello(hello))
    assert hello.ignore_connection is False and proxy.state[conn.id]["sni_deny"].rule == "quarantine"
    raw = client_conn(dst=("185.199.108.153", 4444))
    proxy.state[raw.id] = {}
    nl = next_layer_for(raw, b"\x00\x01binary")
    run(proxy.next_layer(nl))
    assert isinstance(nl.layer, egress._Refuse)


# ---- the decoy keys file ---------------------------------------------------------------------------------------

class DecoyDoorman(FakeDoorman):
    def __init__(self):
        super().__init__()
        self.policy_value = rules.policy_example()
        self.decoy_answer = {"version": "v1", "filename": "api-keys.env",
                             "content": "# API keys (backup, Oct 2026) - keep out of git\nOPENAI_API_KEY=sk-proj-1\n"}
        self.decoy_calls = 0
        self.trips, self.trip_answer = [], {"ok": True, "action": "noted"}
        self.last_status = None

    def decoys(self):
        self.decoy_calls += 1
        return self.decoy_answer

    def tripwire(self, body):
        answer = self.trip_answer(body) if callable(self.trip_answer) else self.trip_answer
        if answer is not None:
            self.trips.append(body)
        return answer


def new_policy(fake, **changes):
    policy = rules.policy_example()
    policy.update(changes)
    policy["version"] = rules.policy_version(policy)
    fake.policy_value = policy


def test_decoy_file_written_only_when_its_version_changes(tmp_path, monkeypatch):
    decoys, state = tmp_path / "decoys", tmp_path / "state"
    decoys.mkdir()
    state.mkdir()
    target = decoys / "api-keys.env"
    opened = []
    real_open = os.open
    monkeypatch.setattr(os, "open", lambda path, *a, **kw: opened.append(str(path)) or real_open(path, *a, **kw))
    fake = DecoyDoorman()
    proxy = egress.DoormanEgress(fake, None, None, state_dir=str(state), decoy_dir=str(decoys))
    run(proxy.poll_policy())  # at start
    assert target.read_text().startswith("# API keys (backup, Oct 2026)")
    assert target.stat().st_mode & 0o777 == 0o444
    assert [p.name for p in decoys.iterdir()] == ["api-keys.env"]  # no temporary file left
    first = target.stat().st_ino
    run(proxy.poll_policy())  # the same policy: not even asked
    assert fake.decoy_calls == 1
    new_policy(fake, deny=["x.example"])
    run(proxy.poll_policy())  # a new policy, the same keys: asked, nothing written
    assert fake.decoy_calls == 2 and target.stat().st_ino == first
    proxy._decoys_at -= egress.DECOYS_EVERY  # a minute later they are asked for again in any case
    run(proxy.poll_policy())
    assert fake.decoy_calls == 3 and target.stat().st_ino == first
    fake.decoy_answer = {"version": "v2", "filename": "api-keys.env", "content": "GITHUB_TOKEN=ghp_2\n"}
    new_policy(fake, deny=["y.example"])
    run(proxy.poll_policy())
    assert target.read_text() == "GITHUB_TOKEN=ghp_2\n" and target.stat().st_ino != first
    assert target.stat().st_mode & 0o777 == 0o444
    assert str(target) not in opened  # the old file was replaced, never opened
    assert json.loads((state / "decoys.json").read_text()) == {"version": "v2"}
    # a restarted proxy knows what it wrote
    again = egress.DoormanEgress(fake, None, None, state_dir=str(state), decoy_dir=str(decoys))
    second = target.stat().st_ino
    run(again.poll_policy())
    assert target.stat().st_ino == second
    # switched off: the file goes
    fake.decoy_answer = {"version": "off", "filename": "api-keys.env", "content": None}
    new_policy(fake, deny=["z.example"])
    run(again.poll_policy())
    assert not target.exists() and again.decoy_version == "off"
    # Doorman down: kept, asked again at the next poll
    fake.decoy_answer = None
    new_policy(fake, deny=["w.example"])
    run(again.poll_policy())
    fake.decoy_answer = {"version": "v3", "filename": "api-keys.env", "content": "K=3\n"}
    run(again.poll_policy())
    assert target.read_text() == "K=3\n"
    assert str(target) not in opened


def test_a_missing_decoy_file_is_written_again(tmp_path):
    decoys = tmp_path / "decoys"
    decoys.mkdir()
    fake = DecoyDoorman()
    proxy = egress.DoormanEgress(fake, None, None, state_dir=str(tmp_path), decoy_dir=str(decoys))
    run(proxy.poll_policy())
    os.remove(decoys / "api-keys.env")  # the volume was recreated
    proxy._decoys_at -= egress.DECOYS_EVERY
    run(proxy.poll_policy())
    assert (decoys / "api-keys.env").exists()


def test_from_env_finds_the_decoy_folder(monkeypatch, tmp_path):
    monkeypatch.setenv("EGRESS_GEOIP", "0")
    monkeypatch.setenv("EGRESS_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("EGRESS_DECOY_DIR", str(tmp_path))
    assert egress.from_env().decoy_dir == tmp_path
    monkeypatch.setenv("EGRESS_DECOY_DIR", str(tmp_path / "missing"))
    assert egress.from_env().decoy_dir is None


# ---- the tripwire: observer events to Doorman --------------------------------------------------------------------

class Events(BaseHTTPRequestHandler):
    events: list = []
    asked: list = []

    def do_GET(self):  # noqa: N802
        since = int(self.path.partition("since=")[2] or 0)
        Events.asked.append(since)
        if since > (Events.events[-1]["seq"] if Events.events else 0):
            since = 0
        out = [e for e in Events.events if e["seq"] > since][:200]
        body = json.dumps({"events": out, "next": out[-1]["seq"] if out else since}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def events_observer():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Events)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    Events.events, Events.asked = [], []
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def trip(seq, event, ts=None):
    return {"seq": seq, "ts": ts or 1000.0 + seq, "event": event, "path": "/opt/data/.config/secrets/api-keys.env",
            "client_ip": AGENT_IP}


def test_tripwire_events_reach_doorman_in_order_also_after_it_was_down(events_observer, tmp_path):
    fake = DecoyDoorman()
    proxy = egress.DoormanEgress(fake, None, events_observer, state_dir=str(tmp_path))
    Events.events = [trip(5, "dir_open"), trip(6, "open"), trip(7, "access")]
    fake.trip_answer = None  # Doorman down
    run(proxy.poll_tripwire())
    assert fake.trips == [] and [e["seq"] for e in proxy.trip_pending] == [5, 6, 7]
    run(proxy.poll_tripwire())  # nothing fetched twice
    assert [e["seq"] for e in proxy.trip_pending] == [5, 6, 7] and Events.asked == [0, 7]
    fake.trip_answer = {"ok": True, "action": "noted"}
    Events.events.append(trip(8, "open"))
    run(proxy.poll_tripwire())
    assert [(t["event"], t["ts"]) for t in fake.trips] == [("dir_open", 1005.0), ("open", 1006.0),
                                                           ("access", 1007.0), ("open", 1008.0)]
    assert fake.trips[0] == {"client_ip": AGENT_IP, "event": "dir_open",
                             "path": "/opt/data/.config/secrets/api-keys.env", "ts": 1005.0}
    assert not proxy.trip_pending and json.loads((tmp_path / "tripwire.json").read_text()) == {"since": 8}
    # a restarted proxy asks from where it left off
    again = egress.DoormanEgress(fake, None, events_observer, state_dir=str(tmp_path))
    Events.asked = []
    run(again.poll_tripwire())
    assert Events.asked == [8] and len(fake.trips) == 4


def test_tripwire_follows_a_restarted_observer_and_drops_what_doorman_refuses(events_observer, tmp_path):
    fake = DecoyDoorman()
    proxy = egress.DoormanEgress(fake, None, events_observer, state_dir=str(tmp_path))
    proxy.trip_acked = proxy.trip_fetched = 900  # numbers from before the observer restarted
    Events.events = [trip(3, "open"), {"seq": 4, "event": "nonsense"}, trip(5, "access")]
    run(proxy.poll_tripwire())
    assert [t["event"] for t in fake.trips] == ["open", "access"] and proxy.trip_fetched == 5

    def refuse(body):
        fake.last_status = 422
        return None

    fake.trip_answer = refuse
    Events.events.append(trip(6, "open"))
    run(proxy.poll_tripwire())  # an event Doorman refuses as malformed doesn't hold up the rest
    assert not proxy.trip_pending and proxy.trip_acked == 6


def test_tripwire_queue_is_bounded(events_observer, tmp_path, monkeypatch):
    monkeypatch.setattr(egress, "TRIPWIRE_QUEUE", 3)
    fake = DecoyDoorman()
    fake.trip_answer = None
    proxy = egress.DoormanEgress(fake, None, events_observer, state_dir=str(tmp_path))
    Events.events = [trip(n, "open", ts=float(n * 10)) for n in range(1, 6)]
    run(proxy.poll_tripwire())
    assert [e["seq"] for e in proxy.trip_pending] == [1, 2, 3]  # the rest stays with the observer
    run(proxy.poll_tripwire())
    assert Events.asked == [0]  # full: not asked again
    fake.trip_answer = {"ok": True, "action": "alert"}
    run(proxy.poll_tripwire())
    run(proxy.poll_tripwire())
    assert [t["ts"] for t in fake.trips] == [10.0, 20.0, 30.0, 40.0, 50.0]


def test_a_quarantine_from_the_tripwire_takes_effect_at_once(events_observer, tmp_path):
    fake = DecoyDoorman()
    proxy = egress.DoormanEgress(fake, None, events_observer, state_dir=str(tmp_path))
    Events.events = [trip(1, "open")]

    def quarantine(body):
        new_policy(fake, quarantine=[body["client_ip"]])
        return {"ok": True, "action": "quarantine"}

    fake.trip_answer = quarantine
    run(proxy.poll_tripwire())
    assert proxy.policy["quarantine"] == [AGENT_IP]
    conn = client_conn()
    run(proxy.client_connected(conn))
    assert conn.error


def test_tripwire_with_the_observer_down_returns_quickly(tmp_path):
    fake = DecoyDoorman()
    proxy = egress.DoormanEgress(fake, None, "http://127.0.0.1:9", state_dir=str(tmp_path))
    start = time.monotonic()
    run(proxy.poll_tripwire())
    assert time.monotonic() - start < 1.5 and fake.trips == []


def test_running_starts_the_tripwire_loop_only_with_an_observer(events_observer, monkeypatch):
    started = []

    async def scenario(observer):
        proxy = egress.DoormanEgress(DecoyDoorman(), None, observer)
        monkeypatch.setattr(proxy, "poll_tripwire", lambda: started.append(observer) or asyncio.sleep(0))
        proxy.running()
        await asyncio.sleep(0.05)
        proxy.done()

    run(scenario(None))
    run(scenario(events_observer))
    assert started == [events_observer]


class DecoyApi(BaseHTTPRequestHandler):
    calls: list = []

    def _answer(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        DecoyApi.calls.append(("GET", self.path, None))
        self._answer(200, {"version": "v1", "filename": "api-keys.env", "content": "K=1\n"})

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        DecoyApi.calls.append(("POST", self.path, body))
        if body.get("event") == "bad":
            return self._answer(422, {"detail": "no"})
        self._answer(200, {"ok": True, "action": "quarantine"})

    def log_message(self, *args):
        pass


def test_client_decoys_and_tripwire():
    server = ThreadingHTTPServer(("127.0.0.1", 0), DecoyApi)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    DecoyApi.calls = []
    try:
        client = DoormanClient(f"http://127.0.0.1:{server.server_address[1]}", "dme_good")
        assert client.decoys() == {"version": "v1", "filename": "api-keys.env", "content": "K=1\n"}
        body = {"client_ip": AGENT_IP, "event": "open", "path": "/x", "ts": 1.5}
        assert client.tripwire(body) == {"ok": True, "action": "quarantine"} and client.last_status == 200
        assert client.tripwire({**body, "event": "bad"}) is None and client.last_status == 422
        assert [c[:2] for c in DecoyApi.calls] == [("GET", "/v1/egress/proxy/decoys"),
                                                   ("POST", "/v1/egress/proxy/tripwire"),
                                                   ("POST", "/v1/egress/proxy/tripwire")]
        assert DecoyApi.calls[1][2] == body
    finally:
        server.shutdown()
        server.server_close()
    down = DoormanClient("http://127.0.0.1:9", "dme_good", timeout=0.5)
    assert down.decoys() is None and down.tripwire({}) is None and down.last_status is None
