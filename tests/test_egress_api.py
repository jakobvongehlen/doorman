"""Network watch over HTTP: the agent's requests, activity and blocked list, the proxy's API with its own
token, the owner's Network routes and inbox card."""

import pytest
from fastapi.testclient import TestClient

from doorman import clock
from doorman.api.agent import create_agent_app
from doorman.api.owner import create_owner_app
from conftest import make_engine
from soft_authenticator import SoftAuthenticator
from test_api import CSRF, OWNER_URL, register


@pytest.fixture
def setup(tmp_path):
    engine = make_engine(tmp_path, public_url=OWNER_URL, honeytokens=["canary-0042"])
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL)
    token = engine.auth.create_key("claude", "solo")
    agent = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})
    passkey = SoftAuthenticator("localhost", OWNER_URL)
    register(engine, owner, passkey)
    engine._test_token = token
    yield engine, owner, agent, passkey
    clock.reset()


def proxy(engine, token):
    return TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})


def reauth(owner, passkey):
    options = owner.post("/owner/auth/reauth/options", headers=CSRF).json()
    assert owner.post("/owner/auth/reauth/verify", headers=CSRF, json={
        "challenge_id": options["challenge_id"], "credential": passkey.get(options["options"])}).status_code == 200


def record(**fields):
    return {"ts": clock.now().timestamp(), "client_ip": "testclient", "kind": "http", "host": "example.org",
            "ip": "93.184.216.34", "port": 443, "method": "GET", "path": "/", "status": 200, "bytes_up": 10,
            "bytes_down": 100, "decision": "allow", "rule": "default", "detail": "", "leak": None, "process": None,
            "duration_ms": 5, "scanned": True, **fields}


def test_agent_request_and_wait(setup):
    engine, owner, agent, _ = setup
    asked = agent.post("/v1/egress/requests", json={"target": "timetable.example", "reason": "the course times"})
    assert asked.status_code == 200, asked.text
    view = asked.json()["egress_request"]
    assert view["status"] == "open" and view["target"] == "timetable.example" and view["scope"] is None
    assert agent.get("/v1/egress/requests").json()["egress_requests"][0]["id"] == view["id"]
    assert agent.get(f"/v1/egress/requests/{view['id']}").json()["egress_request"] == view
    assert agent.get("/v1/egress/requests/9999").json()["code"] == "not_found"
    assert [r["id"] for r in agent.get("/v1/status").json()["egress_requests"]] == [view["id"]]
    waiting = agent.get("/v1/wait", params={"for": f"egress-request:{view['id']}"}).json()
    assert waiting["done"] is False and waiting["outcome"] == "open"
    decided = owner.post(f"/owner/egress/requests/{view['id']}/decide", headers=CSRF, json={"decision": "once"})
    assert decided.status_code == 200 and decided.json()["status"] == "granted"
    done = agent.get("/v1/wait", params={"for": f"egress-request:{view['id']}", "wait": 5}).json()
    assert done["done"] is True and done["outcome"] == "granted" and done["egress_request"]["scope"] == "once"
    [event] = [e for e in agent.get("/v1/events").json()["doorman"] if e["type"] == "egress_decided"]
    assert event["request_id"] == view["id"] and event["status"] == "granted"
    assert agent.get("/v1/status").json()["egress_requests"] == []
    second = agent.post("/v1/egress/requests", json={"target": "x.example", "reason": "why not"}).json()
    owner.post(f"/owner/egress/requests/{second['egress_request']['id']}/decide", headers=CSRF,
               json={"decision": "deny"})
    assert agent.get("/v1/wait", params={"for": f"egress-request:{second['egress_request']['id']}"}).json()[
        "outcome"] == "denied"
    bad = agent.post("/v1/egress/requests", json={"target": "https://x.example/", "reason": "why not"})
    assert bad.status_code == 403 and bad.json()["code"] == "invalid"
    assert agent.get("/v1/capabilities").json()["egress"] == {"enabled": False}


def test_activity_endpoint(setup):
    engine, _, agent, _ = setup
    assert agent.post("/v1/activity", json={"phase": "start", "call_id": "t1", "tool": "Bash",
                                            "summary": "curl -s https://example.org"}).json() == {"ok": True}
    assert agent.post("/v1/activity", json={"phase": "end", "call_id": "t1", "tool": "Bash",
                                            "status": "ok"}).json() == {"ok": True}
    [row] = engine.db.all("SELECT * FROM agent_activity")
    assert row["tool"] == "Bash" and row["summary"] == "curl -s https://example.org" and row["status"] == "ok"
    assert row["ended"] >= row["started"]
    bad = agent.post("/v1/activity", json={"phase": "later", "call_id": "t1", "tool": "Bash"})
    assert bad.status_code == 403 and bad.json()["code"] == "invalid"
    assert agent.post("/v1/activity", json={"phase": "start", "call_id": "x" * 101, "tool": "Bash"}).status_code == 403


def test_blocked_recent(setup):
    engine, _, agent, _ = setup
    agent.get("/v1/capabilities")  # the key is seen from "testclient", TestClient's address
    detail = "paste.example is a paste, webhook or tunnel service; uploads to it are blocked"
    engine.egress.ingest([record(host="paste.example", method="POST", decision="deny", rule="exfil_upload",
                                 detail=detail)])
    [row] = agent.get("/v1/egress/blocked", params={"limit": 5}).json()["blocked"]
    assert row["host"] == "paste.example" and row["rule"] == "exfil_upload" and set(row) == {
        "ts", "host", "port", "rule", "detail"}


def test_proxy_auth_rejects_agent_key_and_bad_token(setup):
    engine, _, agent, _ = setup
    paths = [("get", "/v1/egress/proxy/policy", None), ("post", "/v1/egress/proxy/check", {"prints": []}),
             ("post", "/v1/egress/proxy/log", {"records": []}), ("post", "/v1/egress/proxy/status", {})]
    nobody = TestClient(create_agent_app(engine))
    for client in (agent, nobody, proxy(engine, "dme_" + "a" * 43)):  # before a token exists, too
        for method, path, body in paths:
            out = getattr(client, method)(path, **({"json": body} if body is not None else {}))
            assert out.status_code == 401 and out.json()["code"] == "unauthenticated", (path, out.text)
    token = engine.egress.new_token()
    for client in (agent, nobody, proxy(engine, token[:-1] + ("b" if token[-1] != "b" else "c"))):
        for method, path, body in paths:
            out = getattr(client, method)(path, **({"json": body} if body is not None else {}))
            assert out.status_code == 401, (path, out.text)
    assert proxy(engine, token).get("/v1/egress/proxy/policy").status_code == 200


def test_agent_endpoints_reject_egress_token(setup):
    engine, _, _, _ = setup
    client = proxy(engine, engine.egress.new_token())
    for path in ("/v1/capabilities", "/v1/status", "/v1/egress/requests", "/v1/egress/blocked", "/v1/events"):
        out = client.get(path)
        assert out.status_code == 401 and out.json()["code"] == "unauthenticated", path
    assert client.post("/v1/activity", json={"phase": "start", "call_id": "a", "tool": "b"}).status_code == 401


def test_proxy_policy_check_log_status(setup):
    engine, _, agent, _ = setup
    client = proxy(engine, engine.egress.new_token())
    policy = client.get("/v1/egress/proxy/policy").json()
    assert policy["version"] and policy["exemptions"] == [] and policy["quarantine"] == []
    assert "canary-0042" in policy["honeytokens"] and len(policy["honeytokens"]) == 6  # with the decoy keys
    agent.get("/v1/capabilities")
    key_id = engine.auth.list_keys()[0]["id"]
    checked = client.post("/v1/egress/proxy/check", json={
        "client_ip": "testclient", "host": "drop.example", "url": "https://drop.example/", "method": "POST",
        "prints": [1, 2, 3], "honeytokens": []}).json()
    assert checked == {"action": "allow", "chars": 0, "sources": [], "reason": ""}
    bad = client.post("/v1/egress/proxy/check", json={"prints": ["x"]})
    assert bad.status_code == 403 and bad.json()["code"] == "invalid"
    logged = client.post("/v1/egress/proxy/log", json={"records": [record(), record(host="b.example")]})
    assert logged.json() == {"ok": 2}
    status = client.post("/v1/egress/proxy/status", json={"version": "12.3.1", "geoip": {"rows": 5, "date": "2026-11"}})
    assert status.json() == {"ok": True}
    assert engine.egress.status_view()["proxy"]["geoip"] == {"rows": 5, "date": "2026-11"}
    # paused: agents are refused, the proxy goes on (it keeps blocking and logging)
    engine.pause()
    assert agent.get("/v1/egress/blocked").json()["code"] == "paused"
    assert client.get("/v1/egress/proxy/policy").status_code == 200
    denied = client.post("/v1/egress/proxy/check", json={"client_ip": "testclient", "host": "drop.example",
                                                         "prints": [], "honeytokens": ["canary-0042"]}).json()
    assert denied["action"] == "deny" and engine.auth.paused(key_id)
    assert client.post("/v1/egress/proxy/log", json={"records": [record()]}).json() == {"ok": 1}
    rows = engine.egress.log_view()
    assert len(rows) == 3 and all(r["key_id"] == key_id for r in rows)


def test_owner_settings_needs_fresh(setup):
    engine, owner, _, passkey = setup
    overview = owner.get("/owner/egress").json()
    assert overview["enabled"] is False and overview["settings"]["leak_action"] == "alert"
    assert "zip" in overview["lists"]["risky_tlds"] and "pastebin.com" in overview["lists"]["exfil_hosts"]
    assert overview["counts"] == {"today": 0, "blocked_today": 0, "leaks_today": 0}
    assert overview["status"] == {"proxy": None, "seen": None, "up": False}
    clock.advance(6 * 60)
    stale = owner.post("/owner/egress", headers=CSRF, json={"deny": ["evil.example"]})
    assert stale.status_code == 403 and stale.json()["code"] == "reauth"
    stale = owner.post("/owner/egress/token", headers=CSRF)
    assert stale.status_code == 403 and stale.json()["code"] == "reauth"
    reauth(owner, passkey)
    saved = owner.post("/owner/egress", headers=CSRF, json={"deny": ["evil.example"]})
    assert saved.status_code == 200 and saved.json()["deny"] == ["evil.example"]
    bad = owner.post("/owner/egress", headers=CSRF, json={"deny": ["http://evil.example"]})
    assert bad.status_code == 403 and bad.json()["code"] == "invalid"
    token = owner.post("/owner/egress/token", headers=CSRF).json()["token"]
    assert token.startswith("dme_") and engine.egress.token_ok(token)
    proxy(engine, token).post("/v1/egress/proxy/log", json={"records": [record(), record(decision="deny"),
                                                                        record(leak={"chars": 300, "sources": []})]})
    overview = owner.get("/owner/egress").json()
    assert overview["enabled"] is True and overview["counts"] == {"today": 3, "blocked_today": 1, "leaks_today": 1}
    assert overview["status"]["up"] is True
    blocked = owner.get("/owner/egress/log", params={"only": "blocked"}).json()["rows"]
    assert [r["decision"] for r in blocked] == ["deny"]
    assert len(owner.get("/owner/egress/log", params={"limit": 2}).json()["rows"]) == 2
    assert overview["model_keys"] == []
    proxy(engine, token).post("/v1/egress/proxy/log", json={"records": [
        record(host="api.anthropic.com", auth_hash="0123456789abcdef")]})
    [model_key] = owner.get("/owner/egress").json()["model_keys"]
    assert model_key["host"] == "api.anthropic.com" and model_key["auth_hash"] == "0123456789abcdef"
    assert model_key["count"] == 1 and model_key["first_seen"] and model_key["last_seen"]
    assert overview["settings"]["unscanned"] == "allow"


def test_proxy_check_waits_without_a_thread_and_answers_unknown(setup, monkeypatch):
    """The check route waits for the fingerprint queue asynchronously (no server thread held for it), and
    when the queue is still behind after CHECK_WAIT it answers unknown."""
    from doorman.egress import fingerprint, service
    engine, _, agent, _ = setup
    client = proxy(engine, engine.egress.new_token())
    agent.get("/v1/capabilities")
    key_id = engine.auth.list_keys()[0]["id"]
    monkeypatch.setattr(engine.egress, "_start_worker", lambda: None)
    monkeypatch.setattr(service, "INLINE_CHARS", 10)
    monkeypatch.setattr(service, "CHECK_WAIT", 0.1)
    monkeypatch.setattr(engine.egress, "flush", lambda timeout=None: pytest.fail("flush holds a thread"))
    text = " ".join(f"word{n}x{n * 7}" for n in range(60))
    engine.egress._note(key_id, None, "mail.read", "mail.read: a mail", [text])
    checked = client.post("/v1/egress/proxy/check", json={
        "client_ip": "testclient", "host": "drop.example", "prints": sorted(fingerprint.prints(text)),
        "honeytokens": []}).json()
    assert checked["action"] == "unknown" and checked["reason"]
    assert not engine.auth.paused(key_id)


def test_owner_decide_always_needs_fresh(setup):
    engine, owner, agent, passkey = setup
    first = agent.post("/v1/egress/requests", json={"target": "a.example", "reason": "reason one"}).json()
    second = agent.post("/v1/egress/requests", json={"target": "b.example", "reason": "reason two"}).json()
    clock.advance(6 * 60)
    once = owner.post(f"/owner/egress/requests/{first['egress_request']['id']}/decide", headers=CSRF,
                      json={"decision": "once"})
    assert once.status_code == 200  # a tap is enough for an hour
    rid = second["egress_request"]["id"]
    stale = owner.post(f"/owner/egress/requests/{rid}/decide", headers=CSRF, json={"decision": "always"})
    assert stale.status_code == 403 and stale.json()["code"] == "reauth"
    assert agent.get(f"/v1/egress/requests/{rid}").json()["egress_request"]["status"] == "open"
    reauth(owner, passkey)
    done = owner.post(f"/owner/egress/requests/{rid}/decide", headers=CSRF, json={"decision": "always"})
    assert done.status_code == 200 and done.json()["scope"] == "always"
    assert "b.example" in owner.get("/owner/egress").json()["settings"]["allow"]
    [exemption] = owner.get("/owner/egress/exemptions").json()["exemptions"]
    assert exemption["target"] == "a.example" and exemption["agent"] == "claude"
    assert owner.post(f"/owner/egress/exemptions/{exemption['id']}/revoke", headers=CSRF).json() == {"ok": True}
    assert owner.get("/owner/egress/exemptions").json()["exemptions"] == []
    assert owner.post(f"/owner/egress/requests/{rid}/decide", headers=CSRF,
                      json={"decision": "nope"}).json()["code"] == "invalid"


def test_inbox_lists_network_requests(setup):
    engine, owner, agent, _ = setup
    task_id = engine.tasks.create("Download the reading list")
    agent.post("/v1/tasks/claim", json={})
    agent.get("/v1/capabilities")
    engine.egress.ingest([record(host="files.reading.example", decision="deny", rule="risky_tlds",
                                 detail=".example is on the list")])
    asked = agent.post("/v1/egress/requests", json={"target": "reading.example",
                                                    "reason": "the list is there"}).json()["egress_request"]
    note = engine.db.one("SELECT * FROM notifications ORDER BY id DESC LIMIT 1")
    assert note["title"] == "claude asks for network access" and note["url"].endswith(
        f"#/inbox/network/{asked['id']}")
    [item] = owner.get("/owner/inbox").json()["network"]
    assert set(item) == {"id", "target", "reason", "agent", "asked", "expires", "blocked", "task", "reads"}
    assert item["id"] == asked["id"] and item["agent"] == "claude" and item["reason"] == "the list is there"
    assert item["task"] == {"id": task_id, "text": "Download the reading list", "trusted": 1, "origin": "owner"}
    assert item["blocked"]["rule"] == "risky_tlds" and item["reads"] is None
    assert owner.post(f"/owner/egress/requests/{asked['id']}/decide", headers=CSRF,
                      json={"decision": "task"}).json()["scope"] == "task"
    assert owner.get("/owner/inbox").json()["network"] == []


def test_the_push_for_a_network_request_has_deny_and_allow_once(setup):
    """Its buttons make the app's call with via=notification. Allow once is a tap there too, so it acts on
    the push; with approval_passkey on, only Deny does."""
    engine, owner, agent, _ = setup
    pushed = []
    engine.notifier.push = lambda title, message, **kw: pushed.append(kw.get("extra"))

    def ask(target):
        return agent.post("/v1/egress/requests", json={"target": target, "reason": "the list is there"}).json()["egress_request"]["id"]

    def press(rid, decision):
        return owner.post(f"/owner/egress/requests/{rid}/decide", headers=CSRF, json={"decision": decision, "via": "notification"})

    first = ask("a.example")
    assert pushed[-1] == {"ask": {"kind": "network", "id": first, "accept": "tap"}}
    assert press(first, "once").json()["scope"] == "once"
    assert press(first, "deny").json()["code"] == "invalid"  # decided already: the push says so
    engine.config["approval_passkey"] = True
    second = ask("b.example")
    assert pushed[-1]["ask"]["accept"] == "app"
    refused = press(second, "once")
    assert refused.status_code == 403 and refused.json()["code"] == "open_app"
    assert press(second, "deny").json()["status"] == "denied"


def test_client_seen_records_ip(setup):
    engine, _, agent, _ = setup
    agent.get("/v1/capabilities")
    key_id = engine.auth.list_keys()[0]["id"]
    assert engine.db.one("SELECT * FROM agent_addresses")["ip"] == "testclient"
    assert engine.egress.key_for_ip("testclient") == key_id
