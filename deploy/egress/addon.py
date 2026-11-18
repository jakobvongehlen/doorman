"""Doorman's network watch: the mitmproxy 12.3.1 addon in the egress container.

The agent's container has no route to the internet but this one. Its DNS questions arrive here (mitmproxy's
DNS mode on 8053) and every TCP connection it opens (transparent mode on 8080, redirected by iptables in
entrypoint.sh). For each the addon applies the owner's rules (doorman.egress.rules, with the policy Doorman
hands out), and for what the agent sends (HTTP requests, WebSocket messages, raw TCP) it fingerprints the
content and asks Doorman whether that is data the agent read through Doorman (POST /v1/egress/proxy/check:
hashes only, the content stays here). Everything ends up in Doorman's network log, tied to the process that
opened the connection (the egress observer, which shares the agent's PID namespace).

What happens where:

- Nothing goes upstream before it is decided. mitmproxy runs with connection_strategy=lazy (enforced in
  configure): a web-port connection is opened when an allowed request needs it, TLS with the agent is
  finished with a certificate made from the SNI alone, and server_connect refuses any upstream connection
  the rules deny. Non-web ports are decided when they come in; allowed ones are opened right away (patched
  finish_start below), so protocols where the server speaks first (SMTP, IMAP) keep working.
- DNS: a name that looks like data hidden in DNS (one long random label, or many new names under one domain
  in a short time), a name the rules block, or a query that isn't exactly one question gets REFUSED before
  it is resolved (this addon runs before mitmproxy's resolver). Answers are remembered for a day, every name
  an address was given for (CDNs share addresses), so a later connection to that address has a name and
  counts as "resolved" (bare_ip_nonweb).
- Names vouch only for addresses: the Host header and TLS SNI are whatever the agent writes. A claimed name
  counts for rules that let things through (allow list, exceptions, no_scan, passthrough) only when the
  connected address is one the proxy's DNS gave for that name, or one a fresh lookup of the name returns
  (a lookup the agent causes: it gets the DNS rules first, is rate-limited and logged like a DNS query).
  Otherwise the connection is decided by its address (and the names that address really has). The deny
  rules about names (deny list, data-in-DNS names, abuse TLDs, uploads to paste services) apply to the
  claimed name always, even when an allow or exception by address lets the connection through. A TLS name
  that differs from the Host header (domain fronting) makes the Host count only if it vouches on its own.
- Data that is neither TLS nor HTTP: on a web port refused unless the owner allows that address or name
  (raw_on_web_port); on other ports relayed as raw TCP when the rules allow it. What the agent sends over raw
  TCP is fingerprinted as it passes (with an overlap, so a secret split across packets is still seen) and
  the connection is cut when Doorman says it carries what the agent read. TLS is intercepted on every port.
- TLS to a host on the passthrough list: not intercepted (for clients that pin certificates); logged as tcp.
- HTTP requests: rules first (403 with X-Doorman-Egress), then the content check unless the host is on the
  no_scan list (the agent's model API, which sees everything the agent read anyway). URL, every header
  (Host, cookies...), the SNI, trailers and the body are scanned. A no_scan host's requests are still
  checked for honeytokens in their URL and headers (a decoy key used as x-api-key), and their bodies,
  WebSocket messages and raw TCP for the decoy keys, as plain text (_no_scan_hits). A request that needs a
  check while Doorman is unreachable follows when_doorman_down. A body too large to scan (over
  stream_large_bodies, 16 MiB, or over the fingerprint budget) follows the owner's `unscanned` setting
  unless the host is allowed or exempt; a blocked one never starts streaming (patched start_request_stream
  below).
- A protocol switch (HTTP 101) to anything but WebSocket gets a 403 (rule upgrade): mitmproxy would relay
  it unread. WebSocket messages from the agent are checked like request bodies; a leaking one is dropped.
- Decoy keys: the proxy writes the file of fake API keys Doorman hands out (GET /v1/egress/proxy/decoys)
  into /decoys, a volume the agent has read-only in its home; the observer watches it (inotify) and this
  addon passes what the observer saw on to Doorman (POST /v1/egress/proxy/tripwire), in order, again while
  Doorman is down. Nothing here ever opens that file once it is written: that would trip the wire.
- Quarantine: a client address on the policy's `quarantine` list (it touched the decoy keys) gets nothing:
  DNS REFUSED, every TCP connection closed when it comes in, a request on a connection already open a 502,
  raw TCP cut, WebSocket messages dropped; the model API (no_scan) and the owner's allow list included.
- Silence: a honeytoken and a quarantined request get a plain "502 Bad Gateway" without X-Doorman-Egress,
  nothing that tells the agent why; the log keeps the real rule.

Policy, log and status go to Doorman in the background; a policy is kept (also on disk) until a newer one
arrives, so a Doorman restart changes nothing here.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import time
import urllib.parse
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from mitmproxy import ctx, http
from mitmproxy import flow as mflow
from mitmproxy import version as mitmproxy_version
from mitmproxy.net.dns import response_codes
from mitmproxy.net.dns import types as dns_types
from mitmproxy.net.tls import starts_like_tls_record
from mitmproxy.proxy import commands, layer, layers
from mitmproxy.proxy.layers import http as http_layers
from mitmproxy.proxy.layers import modes
from mitmproxy.proxy.layers.tcp import TcpEndHook
from mitmproxy.proxy.layers.tls import HTTP_ALPNS
from mitmproxy.proxy.mode_specs import DnsMode, TransparentMode

from doorman.egress import decode, fingerprint, rules
from doorman.egress.geoip import GeoIP
from doorman_client import DoormanClient

ADDON_VERSION = "2"
META = "doorman_egress"
NO_STREAM = "doorman_egress_no_stream"   # flow.metadata: (rule, detail) when the request body mustn't stream
BYTES_STREAMED = "doorman_egress_streamed"

MAX_PRINT_CHARS = 4_000_000   # normalized characters fingerprinted per request (~1.1 µs each: 4.5 s at most)
MAX_PRINTS = 200_000          # what Doorman's check takes in one call; more go in further calls
PRINTS_OVERLAP = 2_000        # shared by consecutive calls, so a secret's prints (in text order) stay together
STREAM_BYTES = 16 * 1024 * 1024  # stream_large_bodies in entrypoint.sh: larger bodies aren't held, so not scanned
TCP_OVERLAP = 4096            # bytes of a raw TCP stream rescanned with the next packet
LOG_BATCH = 500
LOG_QUEUE = 5000              # records kept while Doorman can't take them; allowed DNS records go first
DNS_MEMORY = 86400            # seconds an answer's address stays tied to its name
DNS_MAP_MAX = 50_000          # addresses remembered
DNS_NAMES_MAX = 200_000       # (address, name) pairs remembered in all
NAMES_PER_ADDRESS = 32        # a CDN address collects names; the oldest go first
LOOKUP_TIMEOUT = 1.0          # the proxy's own lookup of a claimed name it hasn't seen resolved
LOOKUP_MEMORY = 300
LOOKUP_MAX = 10_000
LOOKUP_RATE = (30, 60.0)      # lookups per client per minute; past that a claimed name doesn't vouch
RESOLVER_THREADS = 4          # the proxy's own lookups run here, never in the default executor
CLEAN_MEMORY = 60.0           # prints Doorman found in nothing it served aren't asked about again this long
CLEAN_MAX = 200_000
LOOSENING = ("exemption", "allow_list")
DNS_LOG_EVERY = 600           # an allowed name is logged once per client per ten minutes
OBSERVER_TIMEOUT = 0.3
OBSERVER_EVENTS_TIMEOUT = 1.0
POLICY_EVERY, FLUSH_EVERY, STATUS_EVERY, GEOIP_EVERY = 5.0, 2.0, 60.0, 86400.0
TRIPWIRE_EVERY = 2.0          # the observer's tripwire events are fetched this often
TRIPWIRE_QUEUE = 500          # events waiting for Doorman; past that the observer keeps them (its own queue)
TRIPWIRE_BATCH = 50           # events handed to Doorman per round
TRIPWIRE_EVENTS = ("open", "access", "dir_open")
DECOYS_EVERY = 60.0           # the decoy keys are asked for when the policy changes, and at least this often
DECOY_FILE = "api-keys.env"
QUARANTINE_LOG_EVERY = 60.0   # a quarantined client's refused DNS names and connections: one record a minute each
SILENT_RULES = ("honeytoken", "quarantine")  # answered "502 Bad Gateway", nothing that says why
BAD_GATEWAY = b"Bad Gateway\n"
GEOIP_URL = "https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz"
GEOIP_FILE = re.compile(r"dbip-country-lite-\d{4}-\d{2}\.csv(?:\.gz)?$")
AUTH_HEADERS = ("authorization", "x-api-key", "x-goog-api-key")

BLOCK_BODY = ("Doorman's network proxy blocked this request: {detail}. If your task needs {target}, ask the owner: "
              "doorman egress request {target} --reason \"why\"\n")
TLS_FAILED_DETAIL = ("the client doesn't trust the proxy's certificate (pinned?); add the host to the passthrough "
                     "list if it's needed")
DOWN_DETAIL = "Doorman can't be reached to check what this request carries"
DOWN_PASSED = "Doorman couldn't be reached to check this request; let through (the owner's setting)"
LEAK_DETAIL = "this request carries about {chars} characters the agent read through Doorman ({sources})"
HONEYTOKEN_DETAIL = "this request carries protected content (a honeytoken)"
ERROR_DETAIL = "the proxy couldn't check this request"
PRIVATE_DETAIL = "{ip} is a private address; the agent's connections may only go to the internet"
MISMATCH_DETAIL = "the name {host} doesn't match the address {ip}"
FRONTED_DETAIL = "the TLS name {sni} isn't the Host {host}"
UNSCANNED_DETAIL = "this upload is too large to check; ask the owner if the task needs it"
UPGRADE_DETAIL = "an unknown protocol switch ({protocol}): only WebSocket is relayed"
RAW_WEB_DETAIL = "data that is neither TLS nor HTTP on web port {port}"
QUESTIONS_DETAIL = "a DNS query must ask exactly one question"
LOOKUP_DETAIL = "looked up by the proxy to check a name a connection claimed"
QUARANTINE_DETAIL = "quarantined: this agent touched the decoy keys; nothing gets out until the owner lets it out"
QUARANTINE = rules.Decision("deny", "quarantine", QUARANTINE_DETAIL)

logger = logging.getLogger("doorman_egress")

# The proxy's own lookups of claimed names: a few threads of their own, so lookups that hang can't hold up
# the default executor (fingerprinting, Doorman's API, the observer, the policy poll).
_RESOLVER = ThreadPoolExecutor(RESOLVER_THREADS, thread_name_prefix="doorman-resolve")
# The tripwire (observer events to Doorman) in a thread of its own: neither waits for the other work.
_TRIPWIRE = ThreadPoolExecutor(1, thread_name_prefix="doorman-tripwire")
# client connection ids of allowed non-web connections: their server connection is opened right away
# (one set, kept on the class, also when mitmproxy loads the script a second time)
if "_doorman_connect_now" not in modes.DestinationKnown.__dict__:
    modes.DestinationKnown._doorman_connect_now = set()
_CONNECT_NOW: set[str] = modes.DestinationKnown._doorman_connect_now


def _plain_ip(text) -> str | None:
    """The address as text if `text` is an IP literal (IPv4-mapped IPv6 as IPv4), else None."""
    try:
        addr = ipaddress.ip_address(str(text).strip("[]"))
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


def _clip(text, n: int) -> str | None:
    return None if text is None else str(text)[:n]


def _length(message, raw: bytes | None, streamed: int | None = None) -> int:
    """A body's size: what was held, what streamed through, or what Content-Length announced."""
    if streamed is not None:
        return streamed
    if raw is not None and not getattr(message, "stream", None):
        return len(raw)
    try:
        return int(message.headers.get("content-length", 0))
    except (ValueError, AttributeError):
        return 0


def _probably_no_http(data_client: bytes, data_server: bytes) -> bool:
    """mitmproxy's own test (addons/next_layer.py) for "this isn't an HTTP/1 request line", except that a
    first packet of fewer than 3 bytes from the client is left to the HTTP layer, which reads on (and closes
    what turns out not to be HTTP) instead of being taken for raw TCP."""
    if data_server or data_client.startswith(b"SSH"):
        return True
    if len(data_client) < 3:
        return False
    return (b" " not in data_client or data_client.find(b" ") > data_client.find(b"\n")
            or not data_client[:3].isalpha())


def _scan(url: str, headers: list[tuple[str, str]], body: bytes, content_type: str,
          tokens: list[str]) -> tuple[list[int], list[str], bool, int]:
    """(fingerprints in text order, honeytokens found, whether everything was scanned, normalized characters
    fingerprinted). The budget counts normalized characters: padding of spaces or punctuation costs nothing
    and can't push the rest out. Runs in a worker thread."""
    texts = decode.texts_of_request(url, headers, body, content_type)
    hits = decode.honeytoken_hits(texts, tokens) if tokens else []
    complete = sum(map(len, texts)) < decode.MAX_SCAN_BYTES
    found: dict[int, None] = {}
    budget = MAX_PRINT_CHARS
    for text in texts:
        norm = fingerprint.normalize(text)
        if not norm:
            continue
        if budget <= 0:
            complete = False
            break
        if len(norm) > budget:
            norm, complete = norm[:budget], False
        found.update(dict.fromkeys(fingerprint.winnow(norm)))
        budget -= len(norm)
    return list(found), hits, complete, MAX_PRINT_CHARS - budget


def _plain_hits(data: bytes, tokens: list[str]) -> list[str]:
    """The tokens in `data` read as text (UTF-8, stray bytes replaced), not unpacked: a key as it is, or
    spread out or escaped (JSON's \\/), costs a few milliseconds per megabyte. Runs in a worker thread."""
    if not data or not tokens:
        return []
    return decode.honeytoken_hits([data.decode("utf-8", "replace")], tokens)


def _no_scan_hits(url: str, headers: list[tuple[str, str]], body: bytes, tokens: list[str],
                  decoys: list[str]) -> tuple[list[str], list[str]]:
    """What a request to a host on no_scan (the agent's model API) is checked for, as it isn't fingerprinted:
    (every honeytoken in its URL and headers, unpacked as anywhere else: a key being used; the decoy keys in
    its body, read as plain text: the body is the agent's whole conversation, and the owner's honeytokens
    turn up in it whenever the agent read one, while the decoy keys get there only if it read their file).
    Runs in a worker thread."""
    head = decode.honeytoken_hits(decode.texts_of_request(url, headers, b""), tokens) if tokens else []
    return head, [t for t in _plain_hits(body, decoys) if t not in head]


def _chunks(prints: list[int]) -> list[list[int]]:
    """Calls of at most MAX_PRINTS prints, consecutive ones sharing PRINTS_OVERLAP, so a stretch of text
    (its prints are next to each other) is whole in at least one call unless it is very long."""
    if len(prints) <= MAX_PRINTS:
        return [prints]
    step = max(1, MAX_PRINTS - min(PRINTS_OVERLAP, MAX_PRINTS // 2))
    out = []
    for start in range(0, len(prints), step):
        out.append(prints[start:start + MAX_PRINTS])
        if start + MAX_PRINTS >= len(prints):
            break
    return out


def _with_note(detail: str, note: str | None) -> str:
    return "; ".join(part for part in (detail, note) if part)


async def _resolve(host: str) -> set[str]:
    """The addresses `host` has, asked by the proxy itself (the system resolver: Docker's DNS in the image)."""
    lookup = functools.partial(socket.getaddrinfo, host, None, type=socket.SOCK_STREAM)
    try:
        infos = await asyncio.get_running_loop().run_in_executor(_RESOLVER, lookup)
    except (OSError, UnicodeError):
        return set()
    return {ip for info in infos if (ip := _plain_ip(info[4][0]))}


def _get_json(url: str, timeout: float) -> dict | None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout) as response:
            answer = json.loads(response.read(64 * 1024))
    except (OSError, ValueError):  # 404 (no such socket) is an HTTPError, an OSError
        return None
    return answer if isinstance(answer, dict) and answer.get("pid") else None


def _get_health(url: str, timeout: float) -> dict | None:
    """The observer's GET /health: {"ok": true, "tripwire": {armed, last_error, path} or null}, or None."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout) as response:
            answer = json.loads(response.read(64 * 1024))
    except (OSError, ValueError):
        return None
    return answer if isinstance(answer, dict) and answer.get("ok") is True else None


def _get_events(url: str, timeout: float) -> dict | None:
    """The observer's tripwire events after a number: {"events": [...], "next": N}, or None."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout) as response:
            answer = json.loads(response.read(1024 * 1024))
    except (OSError, ValueError):
        return None
    if not isinstance(answer, dict) or not isinstance(answer.get("events"), list):
        return None
    if not isinstance(answer.get("next"), int) or isinstance(answer["next"], bool):
        return None
    return answer


def _tripwire_event(event) -> dict | None:
    """An observer event as Doorman takes it, with its number; None for anything malformed."""
    if not isinstance(event, dict) or event.get("event") not in TRIPWIRE_EVENTS:
        return None
    seq, ts, path, ip = event.get("seq"), event.get("ts"), event.get("path"), event.get("client_ip")
    if not isinstance(seq, int) or isinstance(seq, bool) or not isinstance(ts, (int, float)):
        return None
    if not isinstance(path, str) or not (ip is None or isinstance(ip, str)):
        return None
    return {"seq": seq, "client_ip": ip, "event": event["event"], "path": path[:500], "ts": float(ts)}


def _result(task: asyncio.Task | None):
    if task is None or not task.done() or task.cancelled() or task.exception() is not None:
        return None
    return task.result()


def _auth_hash(headers) -> str | None:
    """sha256 (first 16 hex characters) of the first API key header a request carries: Doorman tells the
    owner when a second key turns up for a model API (someone else's account used as a drop box)."""
    for name in AUTH_HEADERS:
        value = headers.get(name)
        if value:
            return hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()[:16]
    return None


class _Refuse(layer.Layer):
    """In place of a protocol layer for a denied raw connection: both sides closed, nothing relayed."""

    _closed = False

    def _handle_event(self, event):
        if not self._closed:
            self._closed = True
            for conn in (self.context.server, self.context.client):
                if conn.connected:
                    yield commands.CloseConnection(conn)


class _WatchedTCP(layers.TCPLayer):
    """mitmproxy's raw TCP relay, except that a connection the addon cut (the tcp_message hook found a leak)
    is closed on both sides instead of relaying the message: killing a TCP flow alone doesn't stop
    mitmproxy's TCP layer."""

    def relay_messages(self, event):
        inner = super().relay_messages(event)
        sent = None
        while True:
            try:
                command = inner.send(sent)
            except StopIteration:
                return
            if isinstance(command, commands.SendData) and self.flow is not None and \
                    (self.flow.metadata.get(META) or {}).get("cut"):
                inner.close()
                for conn in (self.context.server, self.context.client):
                    if conn.connected:
                        yield commands.CloseConnection(conn)
                self._handle_event = self.done
                yield TcpEndHook(self.flow)
                self.flow.live = False
                return
            sent = yield command


# ---- two small changes to mitmproxy 12.3.1 itself ---------------------------------------------------------
# Both are checked by the tests against the pinned version; on another version the import fails loudly
# rather than the proxy running without them.

def _original(cls, name: str):
    """The method as mitmproxy has it, also when this module is loaded a second time (mitmproxy reloads a
    changed script): each load patches the original, never its own earlier patch."""
    kept = f"_doorman_original_{name}"
    if not hasattr(cls, kept):
        setattr(cls, kept, getattr(cls, name))
    return getattr(cls, kept)


_finish_start = _original(modes.DestinationKnown, "finish_start")
_start_request_stream = _original(http_layers.HttpStream, "start_request_stream")


def _patched_finish_start(self):
    """connection_strategy=lazy keeps mitmproxy from connecting before a request is decided. A non-web
    connection is decided when it comes in (client_connected), and the protocol may start with the server's
    greeting: those the addon allowed are opened right away, as the eager strategy would."""
    server, client = self.context.server, self.context.client
    if (self.context.options.connection_strategy == "lazy" and client.id in _CONNECT_NOW
            and server.address and server.transport_protocol == "tcp"):
        _CONNECT_NOW.discard(client.id)
        err = yield commands.OpenConnection(server)
        if err:
            self._handle_event = self.done
            return err
    return (yield from _finish_start(self))


def _patched_start_request_stream(self):
    """A request body over stream_large_bodies streams to the server unread, and mitmproxy decides that on
    its own, also halfway through a chunked body. The addon marks requests that mustn't go unread
    (flow.metadata[NO_STREAM]); for those the stream is refused with an error to the client before the
    server is contacted. A body that may stream is counted as it passes, for the log's bytes_up."""
    flow = self.flow
    blocked = flow.metadata.get(NO_STREAM)
    if blocked:
        rule, detail = blocked
        meta = flow.metadata.get(META)
        if meta is not None and meta["decision"].action != "deny":
            meta["decision"] = rules.Decision("deny", rule, detail)
        target = (meta or {}).get("host") or flow.request.pretty_host
        if rule in SILENT_RULES:
            message, code = "Bad Gateway", http_layers.ErrorCode.GENERIC_SERVER_ERROR
        else:
            message = BLOCK_BODY.format(detail=detail, target=target).strip()
            code = (http_layers.ErrorCode.REQUEST_TOO_LARGE if rule == "unscanned"
                    else http_layers.ErrorCode.GENERIC_CLIENT_ERROR)
        flow.error = mflow.Error(message)
        yield http_layers.HttpErrorHook(flow)
        yield http_layers.SendHttp(http_layers.ResponseProtocolError(self.stream_id, message, code),
                                   self.context.client)
        self.client_state = self.state_errored
        flow.live = False
        return
    if flow.request.stream is True:
        flow.metadata[BYTES_STREAMED] = 0

        def count(chunk: bytes) -> bytes:
            flow.metadata[BYTES_STREAMED] = flow.metadata.get(BYTES_STREAMED, 0) + len(chunk)
            return chunk

        flow.request.stream = count
    return (yield from _start_request_stream(self))


modes.DestinationKnown.finish_start = _patched_finish_start
http_layers.HttpStream.start_request_stream = _patched_start_request_stream


class _AfterTlsConfig:
    """Runs after mitmproxy's TlsConfig addon (which, with connection_strategy=lazy, never establishes server
    TLS first): for the non-web connections opened right away it restores what the eager strategy does,
    unless the TLS name is one the rules deny (then nothing is sent and next_layer closes the connection)."""

    def __init__(self, owner: DoormanEgress):
        self.owner = owner

    def tls_clienthello(self, data) -> None:
        server = data.context.server
        state = self.owner.state.get(data.context.client.id) or {}
        if server.connected and server.tls and not state.get("sni_deny"):
            data.establish_server_tls_first = True


class DoormanEgress:
    def __init__(self, client: DoormanClient, geoip_path: str | None, observer_url: str | None, *,
                 state_dir: str | None = None, geoip_download: bool = False, decoy_dir: str | None = None):
        self.client = client
        self.geoip_path = Path(geoip_path) if geoip_path else None
        self.geoip_download = geoip_download
        self.observer_url = observer_url.rstrip("/") if observer_url else None
        self.state_dir = Path(state_dir) if state_dir else None
        self.decoy_dir = Path(decoy_dir) if decoy_dir else None
        kept = self._state("decoys.json")
        self.decoy_version: str | None = kept.get("version") if isinstance(kept.get("version"), str) else None
        self._decoys_for: str | None = None   # the policy version the decoy keys were last asked for with
        self._decoys_at = 0.0
        kept = self._state("tripwire.json")
        since = kept.get("since")
        self.trip_acked = since if isinstance(since, int) and not isinstance(since, bool) else 0
        self.trip_fetched = self.trip_acked   # the observer's number of the last event fetched (acked: sent)
        self.trip_pending: deque[dict] = deque()
        self.observer_state: dict | None = None  # {reachable, armed, error}: check_observer, for the status
        self.quarantine_logged: dict[tuple, float] = {}
        self.geoip: GeoIP | None = None
        self._geoip_loaded: tuple[str, float] | None = None
        cached = self._cached_policy()
        self._saved_version = cached["version"] if cached else None
        self.policy: dict = cached or rules.policy_example()
        self.policy_at = 0.0               # when Doorman last answered the policy poll
        self.records: deque[dict] = deque()
        self.dropped = 0
        self.connections = 0
        self.blocked = 0
        self.started = time.time()
        self.dns_names: dict[str, dict[str, float]] = {}            # address -> {name: until}
        self.dns_entries = 0                                        # (address, name) pairs in dns_names
        self.lookups: dict[str, tuple[set[str], float]] = {}       # claimed name -> (its addresses, until)
        self.lookup_times: dict[str | None, deque] = {}             # client -> times of the proxy's lookups
        self.dns_logged: dict[tuple[str | None, str], float] = {}
        self.name_rate = rules.NameRate()
        self.clean: dict[int, float] = {}  # print -> until: Doorman just said it's in nothing it served
        self.state: dict[str, dict] = {}   # per client connection id
        self._tasks: set[asyncio.Task] = set()
        self._loops: list[asyncio.Task] = []
        self._flushing = False
        self._warned: dict[str, float] = {}
        self._late_added = False

    # ---- mitmproxy options and background: policy, log, status, GeoIP -----------------------------------------

    def configure(self, updated) -> None:
        """Options the rules rely on, whatever the command line says: no upstream connection before a decision
        (lazy), and no raw TCP that mitmproxy sets up on its own (rawtcp: after an HTTP 101, or for data it
        doesn't recognise); the raw TCP this addon allows is set up in next_layer."""
        changes = {}
        if ctx.options.connection_strategy != "lazy":
            changes["connection_strategy"] = "lazy"
        if ctx.options.rawtcp:
            changes["rawtcp"] = False
        if changes:
            ctx.options.update(**changes)

    def running(self) -> None:
        if not self._late_added:
            self._late_added = True
            try:
                ctx.master.addons.add(_AfterTlsConfig(self))
            except Exception:  # tests without a master
                logger.debug("doorman egress: no master to add the late TLS hook to")
        if self._loops:
            return
        if not self.client.token:
            logger.warning("DOORMAN_EGRESS_TOKEN is not set: Doorman will refuse the proxy (More > Network in the app)")
        jobs = [self._every(POLICY_EVERY, self.poll_policy), self._every(FLUSH_EVERY, self.flush),
                self._every(STATUS_EVERY, self.send_status, first=POLICY_EVERY),  # after the first policy poll
                self._every(GEOIP_EVERY, self.refresh_geoip)]
        if self.observer_url:
            jobs.append(self._every(TRIPWIRE_EVERY, self.poll_tripwire))
        self._loops = [asyncio.get_running_loop().create_task(coro) for coro in jobs]

    def done(self) -> None:
        for task in self._loops:
            task.cancel()
        if self.records:  # one last try, blocking: mitmproxy is shutting down
            self.client.send_log(list(self.records)[:LOG_BATCH])

    async def _every(self, seconds: float, job, first: float = 0.0) -> None:
        await asyncio.sleep(first)
        while True:
            try:
                await job()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("doorman egress: %s failed", job.__name__)
            await asyncio.sleep(seconds)

    async def poll_policy(self) -> None:
        policy = await asyncio.to_thread(self.client.policy)
        if policy is None:
            self._warn("policy", f"can't get the policy from Doorman ({self.client.last_error}); keeping the last one")
            return
        self.policy_at = time.time()
        self.policy = policy
        if policy["version"] != self._saved_version:
            await asyncio.to_thread(self._save_policy, policy)
        if policy["version"] != self._decoys_for or time.time() - self._decoys_at >= DECOYS_EVERY:
            if await self.refresh_decoys():
                self._decoys_for, self._decoys_at = policy["version"], time.time()

    # ---- the decoy keys and the tripwire --------------------------------------------------------------------------

    def _state(self, name: str) -> dict:
        if not self.state_dir:
            return {}
        try:
            kept = json.loads((self.state_dir / name).read_text())
        except (OSError, ValueError):
            return {}
        return kept if isinstance(kept, dict) else {}

    def _keep_state(self, name: str, value: dict) -> None:
        if not self.state_dir:
            return
        try:
            tmp = self.state_dir / f"{name}.tmp"
            tmp.write_text(json.dumps(value))
            tmp.replace(self.state_dir / name)
        except OSError as e:
            self._warn(f"state-{name}", f"can't keep {name}: {e}")

    async def refresh_decoys(self) -> bool:
        """Asks Doorman for the decoy keys and writes or removes the file when their version changed (or the
        file went missing). False when Doorman couldn't be asked or the file couldn't be written."""
        if self.decoy_dir is None:
            return True
        answer = await asyncio.to_thread(self.client.decoys)
        if answer is None:
            self._warn("decoys", f"can't get the decoy keys from Doorman ({self.client.last_error})")
            return False
        version, content = answer["version"], answer.get("content")
        # lexists: a stat, never an open (an open would trip the observer's wire)
        present = os.path.lexists(self.decoy_dir / DECOY_FILE)
        if version == self.decoy_version and present == (content is not None):
            return True
        if not await asyncio.to_thread(self._write_decoys, content):
            return False
        self.decoy_version = version
        await asyncio.to_thread(self._keep_state, "decoys.json", {"version": version})
        return True

    def _write_decoys(self, content: str | None) -> bool:
        """The decoy file, 0444, put in place in one step (a temporary file renamed over the old one), or
        removed for None. The old file is never opened. Runs in a worker thread."""
        target = self.decoy_dir / DECOY_FILE
        if content is None:
            try:
                target.unlink()
            except FileNotFoundError:
                pass
            except OSError as e:
                self._warn("decoys-write", f"can't remove the decoy keys: {e}")
                return False
            return True
        tmp = self.decoy_dir / f".{DECOY_FILE}.{os.getpid()}.tmp"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                data = content.encode("utf-8")
                while data:
                    data = data[os.write(fd, data):]
                os.fchmod(fd, 0o444)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, target)
        except OSError as e:
            try:
                tmp.unlink()
            except OSError:
                pass
            self._warn("decoys-write", f"can't write the decoy keys into {self.decoy_dir}: {e}")
            return False
        return True

    async def poll_tripwire(self) -> None:
        """Fetches what the observer's tripwire saw and hands it to Doorman, in order, one event at a time;
        what Doorman can't take yet waits (at most TRIPWIRE_QUEUE here, the rest in the observer). The number
        of the last event Doorman took is kept on disk, so a restart doesn't report an event twice. Runs in
        its own thread (_TRIPWIRE), never in the way of the requests."""
        loop = asyncio.get_running_loop()
        if len(self.trip_pending) < TRIPWIRE_QUEUE:
            answer = await loop.run_in_executor(_TRIPWIRE, _get_events,
                                                f"{self.observer_url}/events?since={self.trip_fetched}",
                                                OBSERVER_EVENTS_TIMEOUT)
            if answer is None:
                self._warn("observer-events", "can't fetch the tripwire's events from the observer")
            else:
                room = TRIPWIRE_QUEUE - len(self.trip_pending)
                events = [e for e in map(_tripwire_event, answer["events"]) if e is not None][:room]
                self.trip_pending.extend(events)
                # an observer that restarted counts from its own start: follow its numbers
                self.trip_fetched = events[-1]["seq"] if events else answer["next"]
        acked, quarantine = self.trip_acked, False
        for _ in range(TRIPWIRE_BATCH):
            if not self.trip_pending:
                break
            event = self.trip_pending[0]
            body = {k: event[k] for k in ("client_ip", "event", "path", "ts")}
            answer = await loop.run_in_executor(_TRIPWIRE, self.client.tripwire, body)
            if answer is None and self.client.last_status not in (400, 422):
                self._warn("tripwire", f"can't tell Doorman the decoy keys were touched ({self.client.last_error}); "
                                       f"{len(self.trip_pending)} events wait")
                break
            self.trip_pending.popleft()
            acked = event["seq"]
            if answer is None:
                logger.warning(f"doorman egress: Doorman refused a tripwire event: {self.client.last_error}")
                continue
            logger.warning(f"doorman egress: the decoy keys were touched ({event['event']} {event['path']} from "
                           f"{event['client_ip']}): Doorman says {answer.get('action')}")
            quarantine = quarantine or answer.get("action") == "quarantine"
        if acked != self.trip_acked:
            self.trip_acked = acked
            await asyncio.to_thread(self._keep_state, "tripwire.json", {"since": acked})
        if quarantine:
            await self.poll_policy()  # the quarantine now, not at the next poll

    def _quarantined(self, client_ip: str | None) -> bool:
        return bool(client_ip) and client_ip in (self.policy.get("quarantine") or ())

    def _record_quarantined(self, client_id: str | None, client_ip: str | None, kind: str,
                            host: str | None, ip: str | None, port: int | None) -> None:
        """A quarantined client's refused DNS name or connection, at most once a minute each: a stopped agent
        retrying mustn't flood the log."""
        now = time.time()
        key = (client_ip, kind, host, ip, port)
        if now - self.quarantine_logged.get(key, 0) < QUARANTINE_LOG_EVERY:
            return
        if len(self.quarantine_logged) > 10_000:
            self.quarantine_logged = {k: t for k, t in self.quarantine_logged.items()
                                      if now - t < QUARANTINE_LOG_EVERY}
        self.quarantine_logged[key] = now
        self._record(client_id, client_ip, kind=kind, host=host, ip=ip, port=port, decision="deny",
                     rule="quarantine", detail=QUARANTINE_DETAIL)

    def _cached_policy(self) -> dict | None:
        if not self.state_dir:
            return None
        try:
            policy = json.loads((self.state_dir / "policy.json").read_text())
        except (OSError, ValueError):
            return None
        return policy if isinstance(policy, dict) and policy.get("version") else None

    def _save_policy(self, policy: dict) -> None:
        if not self.state_dir:
            return
        try:
            tmp = self.state_dir / "policy.json.tmp"
            tmp.write_text(json.dumps(policy))
            tmp.replace(self.state_dir / "policy.json")
            self._saved_version = policy["version"]
        except OSError as e:
            self._warn("policy-cache", f"can't keep the policy on disk: {e}")

    async def flush(self) -> None:
        if self._flushing:
            return
        self._flushing = True
        try:
            while self.records:
                batch = list(self.records)[:LOG_BATCH]
                if not await asyncio.to_thread(self.client.send_log, batch):
                    self._warn("log", f"can't send the log to Doorman ({self.client.last_error}); "
                                      f"{len(self.records)} records wait")
                    return
                # the full queue may have pushed some of the batch out meanwhile, from anywhere in it
                sent = {id(record) for record in batch}
                self.records = deque(r for r in self.records if id(r) not in sent)
        finally:
            self._flushing = False

    def status_body(self) -> dict:
        now = time.time()
        return {
            "version": ADDON_VERSION, "mitmproxy": mitmproxy_version.VERSION, "started": self.started,
            "policy_version": self.policy.get("version"),
            "policy_age_s": round(now - self.policy_at) if self.policy_at else None,
            "geoip": {"rows": self.geoip.rows, "date": self.geoip.date} if self.geoip else None,
            "connections": self.connections, "blocked": self.blocked,
            "queued": len(self.records), "dropped": self.dropped,
            "decoys_version": self.decoy_version, "tripwire_queued": len(self.trip_pending),
            "observer": self.observer_state,
        }

    async def send_status(self) -> None:
        await self.check_observer()
        await asyncio.to_thread(self.client.status, self.status_body())

    async def check_observer(self) -> None:
        """Whether the observer answers and its tripwire is armed, for the status: Doorman tells the owner
        when decoy keys are on and they aren't watched. None without an observer (OBSERVER_URL)."""
        if not self.observer_url:
            self.observer_state = None
            return
        answer = await asyncio.get_running_loop().run_in_executor(
            _TRIPWIRE, _get_health, f"{self.observer_url}/health", OBSERVER_EVENTS_TIMEOUT)
        if answer is None:
            self.observer_state = {"reachable": False, "armed": False, "error": "the observer doesn't answer"}
        else:
            trip = answer.get("tripwire") if isinstance(answer.get("tripwire"), dict) else {}
            error = trip.get("last_error") if isinstance(trip.get("last_error"), str) else None
            if not trip:
                error = "the observer has no decoy file to watch (OBSERVER_DECOY_PATH)"
            self.observer_state = {"reachable": True, "armed": trip.get("armed") is True, "error": _clip(error, 300)}
        if not self.observer_state["armed"] and self.decoy_version not in (None, "off"):
            self._warn("tripwire-off", f"the decoy keys' tripwire isn't armed: {self.observer_state['error']}")

    async def refresh_geoip(self) -> None:
        loaded = await asyncio.to_thread(self._refresh_geoip)
        if loaded is not None:
            self.geoip = loaded
            logger.info(f"doorman egress: GeoIP {loaded.date or ''} loaded, {loaded.rows} ranges")

    def _refresh_geoip(self) -> GeoIP | None:
        """Downloads this month's DB-IP file when it's missing (and allowed), then loads the newest file if it
        isn't loaded already. Runs in a worker thread."""
        path = self.geoip_path
        if path is None:
            return None
        if path.is_dir() and self.geoip_download:
            month = time.strftime("%Y-%m", time.gmtime())
            target = path / f"dbip-country-lite-{month}.csv.gz"
            if not target.exists():
                part = target.with_suffix(".part")
                try:
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    with opener.open(GEOIP_URL.format(month=month), timeout=60) as response, open(part, "wb") as f:
                        while chunk := response.read(1 << 16):
                            f.write(chunk)
                    part.replace(target)
                except OSError as e:
                    part.unlink(missing_ok=True)
                    self._warn("geoip", f"can't download the GeoIP table: {e}; keeping the previous one")
        if path.is_dir():
            files = sorted(p for p in path.iterdir() if GEOIP_FILE.search(p.name))
            for old in files[:-2]:
                old.unlink(missing_ok=True)
            file = files[-1] if files else None
        else:
            file = path if path.is_file() else None
        if file is None:
            return None
        key = (str(file), file.stat().st_mtime)
        if key == self._geoip_loaded:
            return None
        try:
            loaded = GeoIP.load(str(file))
        except (OSError, ValueError, EOFError) as e:
            self._warn("geoip", f"can't read {file.name}: {e}")
            return None
        self._geoip_loaded = key
        return loaded

    def _warn(self, key: str, message: str) -> None:
        now = time.time()
        if now - self._warned.get(key, 0) >= 60:
            self._warned[key] = now
            logger.warning(f"doorman egress: {message}")

    # ---- records --------------------------------------------------------------------------------------------

    def _spawn(self, coro) -> asyncio.Task:
        task = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def settle(self) -> None:
        """Waits for the records still waiting on the observer (for tests and shutdown)."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    def _record(self, client_id: str | None, client_ip: str | None, **fields) -> None:
        record = {
            "ts": time.time(), "client_ip": client_ip, "kind": "http", "host": None, "ip": None, "port": None,
            "method": None, "path": None, "status": None, "bytes_up": 0, "bytes_down": 0, "decision": "allow",
            "rule": "default", "detail": "", "leak": None, "process": None, "duration_ms": 0, "scanned": False,
        }
        record.update(fields)
        record["host"] = _clip(record["host"], 253)
        record["path"] = _clip(record["path"], 300)
        record["detail"] = _clip(record["detail"], 500)
        if record["decision"] == "deny":
            self.blocked += 1
        lookup = self.state.get(client_id, {}).get("proc") if client_id else None
        if lookup is None or lookup.done():
            record["process"] = _result(lookup)
            self._append(record)
        else:
            self._spawn(self._finish(record, lookup))

    async def _finish(self, record: dict, lookup: asyncio.Task) -> None:
        try:
            record["process"] = await asyncio.wait_for(asyncio.shield(lookup), OBSERVER_TIMEOUT + 0.2)
        except Exception:  # timed out, or the lookup failed: the record goes without the process
            record["process"] = None
        self._append(record)

    def _append(self, record: dict) -> None:
        """Queues a record for Doorman. A full queue (Doorman away, or the agent flooding it) gives up allowed
        DNS records first, then other allowed records, the oldest first; what was blocked or leaked is kept
        over all of them, so flooding the log can't hide a blocked upload."""
        if len(self.records) >= LOG_QUEUE:
            self.dropped += 1
            victim = None
            for test in (lambda r: r["decision"] == "allow" and r["kind"] == "dns" and not r.get("leak"),
                         lambda r: r["decision"] == "allow" and not r.get("leak")):
                victim = next((r for r in self.records if test(r)), None)
                if victim is not None:
                    break
            if victim is None:
                if record["decision"] == "allow" and not record.get("leak"):
                    return  # all kept ones matter more than this one
                self.records.popleft()
            else:
                self.records.remove(victim)
        self.records.append(record)

    async def _lookup(self, client) -> dict | None:
        port = client.peername[1]
        dst_ip, dst_port = _plain_ip(client.sockname[0]), client.sockname[1]
        if not dst_ip:
            return None
        query = urllib.parse.urlencode({"port": port, "dst": f"{dst_ip}:{dst_port}"})
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(_get_json, f"{self.observer_url}/lookup?{query}", OBSERVER_TIMEOUT),
                OBSERVER_TIMEOUT + 0.1)
        except (asyncio.TimeoutError, OSError):
            return None

    # ---- decisions ------------------------------------------------------------------------------------------

    def _decide(self, conn: rules.Conn, policy: dict | None = None) -> rules.Decision:
        if self.geoip is not None and conn.ip:
            conn.country = self.geoip.country(conn.ip)
        conn.now = time.time()
        if conn.kind != "dns" and conn.ip and not self._reachable(conn.ip, conn.port, conn.now, conn.client):
            return rules.Decision("deny", "private", PRIVATE_DETAIL.format(ip=conn.ip))
        return rules.decide(self.policy if policy is None else policy, conn)

    def _keep_name_denies(self, decision: rules.Decision, kind: str, host: str | None, port: int,
                          method: str | None, client: str | None) -> rules.Decision:
        """A decision that lets a connection through because of its address (an allow or exception for an IP
        or network) still gets the deny rules about the name it claims; one by the name itself doesn't (the
        owner allowed that name)."""
        if decision.rule not in LOOSENING or not host or _plain_ip(host) is not None:
            return decision
        by_name = rules.decide(self.policy, rules.Conn(kind, host, None, port, method=method, resolved=True,
                                                       now=time.time(), client=client))
        if by_name.rule in LOOSENING:
            return decision
        return rules.deny_by_name(self.policy, host, port, method) or decision

    async def _decide_named(self, kind: str, host: str | None, ip: str | None, port: int,
                            method: str | None = None, client: str | None = None) -> tuple[rules.Decision, str | None]:
        """The rules for a connection that claims a name (Host header, SNI), and a note for the log when the
        name doesn't vouch for the address. Then the connection is decided as if it named what the address
        really is (the names the proxy's DNS gave it, or none), so an allow or exception by name for the
        claimed host doesn't apply; the deny rules about names apply to the claimed name all the same."""
        names = self._names(ip)
        if await self._vouch(host, ip, client):
            resolved = bool(names) or (host is not None and _plain_ip(host) is None)
            decision = self._decide(rules.Conn(kind, host, ip, port, method=method, resolved=resolved, client=client))
            return self._keep_name_denies(decision, kind, host, port, method, client), None
        by_address = None
        for name in names[:8] or [None]:
            decision = self._decide(rules.Conn(kind, name, ip, port, method=method, resolved=bool(names),
                                               client=client))
            if decision.rule in LOOSENING:
                by_address = decision
                break
            by_address = by_address or decision
        note = MISMATCH_DETAIL.format(host=host, ip=ip)
        if by_address.action == "deny":
            return by_address, note
        by_name = rules.deny_by_name(self.policy, host, port, method)
        if by_name is not None:
            return by_name, None  # the name itself is denied: whether it has this address doesn't matter
        return by_address, note

    def _dns_decision(self, name: str, client: str | None) -> rules.Decision:
        """The rules for a DNS question, the rate of new names under one domain included."""
        decision = self._decide(rules.Conn("dns", name, None, 53, client=client))
        if decision.action == "deny" or decision.rule in LOOSENING:
            return decision
        if (self.policy.get("categories") or {}).get("dns_tunnel", True):
            domain = self.name_rate.check(client, name, time.time())
            if domain is not None:
                return rules.Decision("deny", "dns_tunnel", rules.DNS_RATE_DETAIL.format(domain=domain))
        return decision

    def _may_look_up(self, client: str | None, now: float) -> bool:
        limit, per = LOOKUP_RATE
        times = self.lookup_times.get(client)
        if times is None:
            if len(self.lookup_times) > 1000:
                self.lookup_times.clear()
            times = self.lookup_times[client] = deque()
        while times and times[0] <= now - per:
            times.popleft()
        if len(times) >= limit:
            return False
        times.append(now)
        return True

    async def _vouch(self, host: str | None, ip: str | None, client: str | None = None) -> bool:
        """Whether the claimed name `host` has the address `ip`: the proxy's DNS gave it out for that name, or
        a lookup of the name by the proxy itself returns it. Nothing to check without a name or an address
        (in regular mode mitmproxy resolves the name itself). The lookup is a DNS query the agent caused, so
        it gets the DNS rules first (a name they refuse isn't looked up and doesn't vouch), is limited per
        client, runs in threads of its own and is logged like the agent's own queries."""
        if host is None or ip is None:
            return True
        literal = _plain_ip(host)
        if literal is not None:
            return literal == ip
        if host in self._names(ip):
            return True
        now = time.time()
        cached = self.lookups.get(host)
        if cached is None or cached[1] <= now:
            decision = self._dns_decision(host, client)
            if decision.action == "deny":
                self._log_dns_record(client, host, None, decision, decision.detail, now)
                return False
            if not self._may_look_up(client, now):
                self._warn("lookups", f"{client} makes the proxy look up names too fast; claimed names don't vouch")
                return False
            try:
                found = await asyncio.wait_for(_resolve(host), LOOKUP_TIMEOUT)
            except asyncio.TimeoutError:
                found = set()
            if len(self.lookups) >= LOOKUP_MAX:
                self.lookups = {h: v for h, v in self.lookups.items() if v[1] > now}
                if len(self.lookups) >= LOOKUP_MAX:
                    self.lookups.clear()
            cached = self.lookups[host] = (found, now + LOOKUP_MEMORY)
            self._log_dns_record(client, host, min(found) if found else None, decision, LOOKUP_DETAIL, now)
        return ip in cached[0]

    def _reachable(self, ip: str, port: int, now: float, client: str | None = None) -> bool:
        """Internet addresses are; private ones (Doorman's own networks among them: the owner app trusts
        172.30.0.0/24, where this container also sits) only when the owner's allow list or an exception names
        that address or network. A host name doesn't count: the Host header and SNI are the agent's to choose."""
        try:
            if ipaddress.ip_address(ip).is_global:
                return True
        except ValueError:
            return True
        entries = list(self.policy.get("allow") or [])
        entries += [e.get("target") for e in self.policy.get("exemptions") or []
                    if rules.exemption_applies(e, client, now)]
        for entry in entries:
            target = rules.parse_target(entry) if isinstance(entry, str) else None
            if target is not None and target.net is not None and rules.matches(target, None, ip, port):
                return True
        return False

    def _web_ports(self) -> set[int]:
        return set(self.policy.get("web_ports") or [80, 443, 8080, 8443])

    def _covers(self, entry, host: str | None, ip: str | None, port: int, vouched: bool,
                siblings: bool = True) -> bool:
        """Whether a list entry applies: an address or network by the connected address; a name by the claimed
        host, only if it vouches for the address, or if the entry also covers a name the address really has."""
        target = rules.parse_target(entry) if isinstance(entry, str) else None
        if target is None:
            return False
        if target.net is not None:
            return rules.matches(target, None, ip, port)
        if not rules.matches(target, host, None, port):
            return False
        return vouched or ip is None or (siblings and any(rules.matches(target, n, None, port)
                                                          for n in self._names(ip)))

    def _listed(self, name: str, host: str | None, ip: str | None, port: int, vouched: bool,
                siblings: bool = True) -> bool:
        return any(self._covers(entry, host, ip, port, vouched, siblings) for entry in self.policy.get(name) or [])

    def _names(self, ip: str | None) -> list[str]:
        """The names the proxy's DNS gave out this address for, newest first."""
        found = self.dns_names.get(ip) if ip else None
        if not found:
            return []
        now = time.time()
        return [name for name, until in sorted(found.items(), key=lambda kv: -kv[1]) if until > now]

    def _dns_name(self, ip: str | None) -> str | None:
        names = self._names(ip)
        return names[0] if names else None

    def _remember(self, ip: str, name: str, now: float) -> None:
        """Ties `name` to `ip` for a day. Bounded by addresses, by names per address and by pairs in all: a
        flood of answers drops what ran out, then the oldest addresses."""
        if ip not in self.dns_names and len(self.dns_names) >= DNS_MAP_MAX or self.dns_entries >= DNS_NAMES_MAX:
            self._shrink(now)
        names = self.dns_names.setdefault(ip, {})
        if name not in names:
            self.dns_entries += 1
        names[name] = now + DNS_MEMORY
        while len(names) > NAMES_PER_ADDRESS:
            del names[min(names, key=names.get)]
            self.dns_entries -= 1

    def _shrink(self, now: float) -> None:
        self.dns_names = {a: kept for a, names in self.dns_names.items()
                          if (kept := {n: t for n, t in names.items() if t > now})}
        self.dns_entries = sum(map(len, self.dns_names.values()))
        while self.dns_names and (len(self.dns_names) >= DNS_MAP_MAX * 0.9 or self.dns_entries >= DNS_NAMES_MAX * 0.9):
            oldest = next(iter(self.dns_names))  # dicts keep insertion order: the address first remembered
            self.dns_entries -= len(self.dns_names.pop(oldest))

    def _decide_address(self, ip: str | None, port: int, client: str | None) -> rules.Decision:
        """What the rules say about an address before any name is known: private addresses, countries, and
        addresses or networks on the lists; a name the proxy's DNS gave the address can open it again."""
        decision = self._decide(rules.Conn("http", None, ip, port, client=client))
        if decision.action != "deny":
            return decision
        for name in self._names(ip)[:8]:
            by_name = self._decide(rules.Conn("http", name, ip, port, resolved=True, client=client))
            if by_name.rule in LOOSENING:
                return by_name
        return decision

    def _decide_raw(self, client) -> dict:
        """The rules for a raw TCP connection, named by a DNS answer through the proxy (if any)."""
        ip, port = _plain_ip(client.sockname[0]), client.sockname[1]
        name = self._dns_name(ip)
        decision = self._decide(rules.Conn("tcp", name, ip, port, resolved=name is not None,
                                           client=_plain_ip(client.peername[0])))
        return {"host": name, "ip": ip, "port": port, "decision": decision, "note": None}

    async def _decide_raw_named(self, client, sni: str | None) -> dict:
        """The same inside TLS, where the client named a host (SNI) that has to vouch for the address."""
        if not sni:
            return self._decide_raw(client)
        ip, port = _plain_ip(client.sockname[0]), client.sockname[1]
        decision, note = await self._decide_named("tcp", sni.lower().rstrip("."), ip, port,
                                                  client=_plain_ip(client.peername[0]))
        return {"host": sni, "ip": ip, "port": port, "decision": decision, "note": note}

    # ---- connections ----------------------------------------------------------------------------------------

    async def client_connected(self, client) -> None:
        state = self.state[client.id] = {}
        if client.transport_protocol != "tcp" or isinstance(client.proxy_mode, DnsMode):
            return
        self.connections += 1
        client_ip = _plain_ip(client.peername[0])
        if self._quarantined(client_ip):  # nothing at all, the model API and allowed hosts included
            state["refused"] = QUARANTINE
            client.error = f"Doorman's network proxy refused this connection: {QUARANTINE_DETAIL}"
            ip = _plain_ip(client.sockname[0]) if client.sockname else None
            port = client.sockname[1] if client.sockname else None
            self._record_quarantined(client.id, client_ip, "tcp", self._dns_name(ip), ip, port)
            return
        if self.observer_url:
            state["proc"] = self._spawn(self._lookup(client))
        if not isinstance(client.proxy_mode, TransparentMode):
            return
        ip, port = _plain_ip(client.sockname[0]), client.sockname[1]
        if port in self._web_ports():
            # the address rules now; names (SNI, Host) come later. Not closed here, so a request gets a 403 that
            # says why; nothing reaches the address (server_connect) unless a name the rules allow opens it
            decision = self._decide_address(ip, port, client_ip)
            if decision.action == "deny":
                state["addr_deny"] = decision
            return
        raw = state["raw"] = self._decide_raw(client)
        decision = raw["decision"]
        if decision.action == "deny":
            if "proc" in state:  # while the agent's socket still exists
                await asyncio.wait({state["proc"]}, timeout=OBSERVER_TIMEOUT)
            client.error = f"Doorman's network proxy blocked this connection: {decision.detail}"
            self._record(client.id, client_ip, kind="tcp", host=raw["host"], ip=raw["ip"],
                         port=raw["port"], decision="deny", rule=decision.rule, detail=decision.detail)
        else:
            _CONNECT_NOW.add(client.id)

    def server_connect(self, data) -> None:
        """The last gate before mitmproxy connects anywhere for the agent: an address the rules deny (and no
        allowed name opened since), a TLS name they deny, or a connection already refused is not connected."""
        client = data.client
        if client.peername and self._quarantined(_plain_ip(client.peername[0])):
            data.server.error = f"Doorman's network proxy blocked this connection: {QUARANTINE_DETAIL}"
            return
        state = self.state.get(client.id)
        if not state:
            return
        denied = state.get("sni_deny") or state.get("refused")
        if denied is None and state.get("addr_deny") and not state.get("opened"):
            denied = state["addr_deny"]
        if denied is not None:
            data.server.error = f"Doorman's network proxy blocked this connection: {denied.detail}"

    def client_disconnected(self, client) -> None:
        _CONNECT_NOW.discard(client.id)
        state = self.state.get(client.id) or {}
        passed = state.get("passthrough")
        if passed:
            decision = passed["decision"]
            detail = decision.detail or f"{passed['host']} is on the passthrough list: not intercepted"
            self._record(client.id, _plain_ip(client.peername[0]), ts=passed["t0"], kind="tcp", host=passed["host"],
                         ip=passed["ip"], port=passed["port"], rule=decision.rule,
                         detail=_with_note(detail, passed["note"]),
                         duration_ms=round((time.time() - passed["t0"]) * 1000))
        self.state.pop(client.id, None)

    async def next_layer(self, nextlayer) -> None:
        """Raw TCP (neither TLS nor HTTP) gets the rules here, before a byte of it is relayed."""
        if nextlayer.layer is not None:
            return
        context = nextlayer.context
        client, stack = context.client, context.layers
        if not isinstance(client.proxy_mode, TransparentMode) or client.transport_protocol != "tcp":
            return
        if not stack or not isinstance(stack[0], modes.TransparentProxy):
            return
        top = len(stack) == 1
        in_tls = len(stack) == 3 and isinstance(stack[-1], layers.ClientTLSLayer)
        if not (top or in_tls):
            return
        data_client, data_server = nextlayer.data_client(), nextlayer.data_server()
        if top and starts_like_tls_record(data_client):
            return  # TLS: intercepted (tls_clienthello may pass it through)
        if in_tls and client.alpn in HTTP_ALPNS:
            return
        if not _probably_no_http(data_client, data_server):
            return  # HTTP: the request hooks decide
        state = self.state.setdefault(client.id, {})
        raw = state.get("raw") if top else None
        if raw is None:
            raw = state["raw"] = (await self._decide_raw_named(client, client.sni) if in_tls
                                  else self._decide_raw(client))
        decision = raw["decision"]
        port = client.sockname[1]
        if self._quarantined(_plain_ip(client.peername[0])):
            decision = QUARANTINE
        if decision.action != "deny" and state.get("sni_deny"):
            decision = state["sni_deny"]
        if decision.action != "deny" and port in self._web_ports() and decision.rule not in LOOSENING:
            decision = rules.Decision("deny", "raw_on_web_port", RAW_WEB_DETAIL.format(port=port))
        raw["decision"] = decision
        if decision.action == "deny":
            state["refused"] = decision
            nextlayer.layer = _Refuse(context)
            self._record(client.id, _plain_ip(client.peername[0]), kind="tcp", host=raw["host"], ip=raw["ip"],
                         port=raw["port"], decision="deny", rule=decision.rule,
                         detail=_with_note(decision.detail, raw["note"]))
        else:
            nextlayer.layer = _WatchedTCP(context)

    async def tls_clienthello(self, data) -> None:
        """The name the agent gives in TLS gets the deny rules about names right away (nothing has gone
        upstream yet: connection_strategy=lazy): what follows on this connection is refused, a request with a
        403. An allowed name on the passthrough list that vouches for the address isn't intercepted."""
        sni = (data.client_hello.sni or "").lower().rstrip(".")
        server = data.context.server.address
        client_id = data.context.client.id
        client_ip = _plain_ip(data.context.client.peername[0]) if data.context.client.peername else None
        if self._quarantined(client_ip):  # not passed through, nothing connected
            self.state.setdefault(client_id, {})["sni_deny"] = QUARANTINE
            return
        if sni and _plain_ip(sni) is None:
            port = server[1] if server else 443
            by_name = self._decide(rules.Conn("http", sni, None, port, resolved=True, client=client_ip))
            denied = None
            if by_name.rule not in LOOSENING:  # an allow or exception for the name itself beats these
                denied = rules.deny_by_name(self.policy, sni, port)
                if denied is None:
                    dns = self._dns_decision(sni, client_ip)
                    denied = dns if dns.action == "deny" else None
            if denied is not None:
                self.state.setdefault(client_id, {})["sni_deny"] = denied
                return
        if not sni or not server or not self.policy.get("passthrough"):
            return
        ip, port = _plain_ip(server[0]), server[1]
        if not self._listed("passthrough", sni, ip, port, await self._vouch(sni, ip, client_ip)):
            return  # also when the name is on the list but isn't this address's: intercepted, read, decided
        decision, note = await self._decide_named("http", sni, ip, port, client=client_ip)
        if decision.action == "deny":
            return  # intercepted after all, so the request gets the 403 that says why
        state = self.state.setdefault(client_id, {})
        if state.get("addr_deny") and decision.rule not in LOOSENING and not await self._vouch(sni, ip, client_ip):
            return
        state["opened"] = True
        data.ignore_connection = True
        state["passthrough"] = {"host": sni, "ip": ip, "port": port, "decision": decision, "note": note,
                                "t0": time.time()}

    def tls_failed_client(self, data) -> None:
        client, server = data.context.client, data.context.server.address
        ip = _plain_ip(server[0]) if server else None
        self._record(client.id, _plain_ip(client.peername[0]), kind="tls_failed", host=client.sni or ip, ip=ip,
                     port=server[1] if server else None, rule="tls_failed", detail=TLS_FAILED_DETAIL)

    # ---- raw TCP --------------------------------------------------------------------------------------------

    def tcp_start(self, flow) -> None:
        flow.metadata[META] = {"t0": time.time(), "up": 0, "down": 0}

    async def tcp_message(self, flow) -> None:
        meta = flow.metadata.setdefault(META, {"t0": time.time(), "up": 0, "down": 0})
        message = flow.messages[-1]
        meta["up" if message.from_client else "down"] += len(message.content)
        del flow.messages[:-1]  # counted; a long connection mustn't pile its traffic up in memory
        if not meta.get("cut") and self._quarantined(_plain_ip(flow.client_conn.peername[0])):
            self._cut(flow, meta, QUARANTINE.rule, QUARANTINE.detail)  # a connection open since before
        if meta.get("cut"):
            message.content = b""
            return
        if not message.from_client or meta.get("unscanned"):
            return
        try:
            await self._scan_tcp(flow, meta, message.content)
        except Exception:
            logger.exception("doorman egress: checking raw TCP failed")
            self._cut(flow, meta, "error", ERROR_DETAIL)
        if meta.get("cut"):
            message.content = b""

    def _raw_of(self, flow) -> dict:
        client = flow.client_conn
        raw = (self.state.get(client.id) or {}).get("raw")
        if raw is None:
            if isinstance(client.proxy_mode, TransparentMode):
                raw = self._decide_raw(client)
            else:
                address = flow.server_conn.address or (None, None)
                raw = {"host": address[0], "ip": _plain_ip(address[0]), "port": address[1],
                       "decision": rules.Decision("allow", "default", ""), "note": None}
        return raw

    async def _scan_tcp(self, flow, meta: dict, data: bytes) -> None:
        """Fingerprints what the agent sends over raw TCP, the end of the previous packets included (a secret
        split across packets is still seen), and asks Doorman about prints not asked about before. To a host
        on no_scan only the decoy keys are looked for."""
        raw = self._raw_of(flow)
        window = meta.get("tail", b"") + data
        meta["tail"] = window[-TCP_OVERLAP:]
        target = raw["host"] or raw["ip"]
        if meta.get("no_scan") or self._listed("no_scan", raw["host"], raw["ip"], raw["port"], vouched=False):
            # not fingerprinted, but the decoy keys are looked for (_no_scan_hits)
            meta["no_scan"] = True
            hits = await asyncio.to_thread(_plain_hits, window, self._decoys())
            if hits:
                check = {"host": raw["host"], "ip": raw["ip"], "decision": raw["decision"], "leak": None}
                blocked = await self._content_verdict(_plain_ip(flow.client_conn.peername[0]), check,
                                                      f"tcp://{target}:{raw['port']}", "TCP", [], hits, kind="tcp",
                                                      no_scan=True)
                meta["leak"] = check["leak"] or meta.get("leak")
                if blocked is not None:
                    self._cut(flow, meta, *blocked)
            return
        prints, hits, complete, chars = await asyncio.to_thread(_scan, "", [], window, "", self._honeytokens())
        # the budget counts this packet's share of what was fingerprinted, not the overlap again
        meta["chars"] = meta.get("chars", 0) + (chars * len(data) // max(1, len(window)))
        asked = meta.setdefault("asked", set())
        if hits or any(p not in asked for p in prints):
            # Doorman judges how much of the window it served, so it gets all of the window's prints
            if len(asked) > 2 * MAX_PRINTS:
                asked.clear()
            asked.update(prints)
            check = {"host": raw["host"], "ip": raw["ip"], "decision": raw["decision"], "leak": None,
                     "note": raw.get("note")}
            blocked = await self._content_verdict(_plain_ip(flow.client_conn.peername[0]), check,
                                                  f"tcp://{target}:{raw['port']}", "TCP", prints, hits, kind="tcp")
            meta["leak"] = check["leak"] or meta.get("leak")
            if blocked is not None:
                return self._cut(flow, meta, *blocked)
        if not complete or meta["chars"] >= MAX_PRINT_CHARS:
            if raw["decision"].rule in LOOSENING or self.policy.get("unscanned", "allow") == "allow":
                meta["unscanned"] = True
            else:
                self._cut(flow, meta, "unscanned", UNSCANNED_DETAIL)

    def _cut(self, flow, meta: dict, rule: str, detail: str) -> None:
        """Ends a raw TCP connection (_WatchedTCP closes it) and logs why, once."""
        if meta.get("cut"):
            return
        meta["cut"] = rules.Decision("deny", rule, detail)

    def tcp_end(self, flow) -> None:
        meta = flow.metadata.get(META) or {"t0": time.time(), "up": 0, "down": 0}
        if meta.get("logged"):
            return
        meta["logged"] = True
        client = flow.client_conn
        raw = self._raw_of(flow)
        decision = meta.get("cut") or raw["decision"]
        detail = _with_note(decision.detail or (f"failed: {flow.error.msg}" if flow.error else ""), raw.get("note"))
        self._record(client.id, _plain_ip(client.peername[0]), ts=meta["t0"], kind="tcp", host=raw["host"],
                     ip=raw["ip"], port=raw["port"], bytes_up=meta["up"], bytes_down=meta["down"],
                     decision=decision.action, rule=decision.rule, detail=detail, leak=meta.get("leak"),
                     scanned=not meta.get("unscanned") and "asked" in meta,
                     duration_ms=round((time.time() - meta["t0"]) * 1000))

    tcp_error = tcp_end

    # ---- DNS ------------------------------------------------------------------------------------------------

    def dns_request(self, flow) -> None:
        client_ip = _plain_ip(flow.client_conn.peername[0])
        questions = flow.request.questions
        if self._quarantined(client_ip):
            flow.response = flow.request.fail(response_codes.REFUSED)
            name = questions[0].name.lower().rstrip(".") if questions else None
            self._record_quarantined(None, client_ip, "dns", name, None, 53)
            return
        if len(questions) != 1:
            flow.response = flow.request.fail(response_codes.REFUSED)
            name = questions[0].name.lower().rstrip(".") if questions else None
            self._record(None, client_ip, kind="dns", host=name, port=53, decision="deny", rule="dns_tunnel",
                         detail=QUESTIONS_DETAIL)
            return
        name = questions[0].name.lower().rstrip(".")
        decision = self._dns_decision(name, client_ip)
        flow.metadata[META] = {"name": name, "decision": decision}
        if decision.action == "deny":
            flow.response = flow.request.fail(response_codes.REFUSED)
            self._record(None, client_ip, kind="dns", host=name, port=53,
                         decision="deny", rule=decision.rule, detail=decision.detail)

    def dns_response(self, flow) -> None:
        meta = flow.metadata.get(META)
        if meta is None or meta["decision"].action == "deny" or flow.response is None:
            return
        now = time.time()
        addresses = []
        for answer in flow.response.answers:
            try:
                if answer.type == dns_types.A:
                    addresses.append(str(answer.ipv4_address))
                elif answer.type == dns_types.AAAA:
                    addresses.append(_plain_ip(answer.ipv6_address))
            except ValueError:
                continue
        for ip in addresses:
            if ip:
                self._remember(ip, meta["name"], now)
        self._log_dns(flow, meta, addresses[0] if addresses else None, "")

    def dns_error(self, flow) -> None:
        meta = flow.metadata.get(META)
        if meta is not None and meta["decision"].action == "allow":
            self._log_dns(flow, meta, None, f"failed: {flow.error.msg}" if flow.error else "")

    def _log_dns(self, flow, meta: dict, ip: str | None, failed: str) -> None:
        decision = meta["decision"]
        self._log_dns_record(_plain_ip(flow.client_conn.peername[0]), meta["name"], ip, decision,
                             decision.detail or failed, flow.timestamp_created)

    def _log_dns_record(self, client_ip: str | None, name: str, ip: str | None, decision: rules.Decision,
                        detail: str, ts: float) -> None:
        """A DNS record, at most one per client and name per ten minutes (repeats are the same record)."""
        now, key = time.time(), (client_ip, name, decision.action)
        if now - self.dns_logged.get(key, 0) < DNS_LOG_EVERY:
            return
        if len(self.dns_logged) > DNS_MAP_MAX:
            self.dns_logged = {k: t for k, t in self.dns_logged.items() if now - t < DNS_LOG_EVERY}
        self.dns_logged[key] = now
        self._record(None, client_ip, ts=ts, kind="dns", host=name, ip=ip, port=53, decision=decision.action,
                     rule=decision.rule, detail=detail)

    # ---- HTTP -----------------------------------------------------------------------------------------------

    async def _http_meta(self, flow) -> dict:
        meta = flow.metadata.get(META)
        if meta is None:
            request, client = flow.request, flow.client_conn
            client_ip = _plain_ip(client.peername[0]) if client.peername else None
            host = (request.pretty_host or "").lower().rstrip(".") or None
            address = flow.server_conn.address
            ip = _plain_ip(address[0]) if address else None  # transparent mode: where the agent connected to
            if ip is None and flow.server_conn.peername and flow.server_conn.peername[0]:
                ip = _plain_ip(flow.server_conn.peername[0])
            sni = (client.sni or "").lower().rstrip(".") or None
            # domain fronting: TLS names one host, the Host header another; only the Host's own DNS counts then
            fronted = bool(sni and host and sni != host and _plain_ip(host) is None)
            vouched = await self._vouch(host, ip, client_ip)
            decision, note = await self._decide_named("http", host, ip, request.port, request.method, client_ip)
            state = self.state.get(client.id) or {}
            if decision.action != "deny" and state.get("sni_deny"):
                decision = state["sni_deny"]
            if self._quarantined(client_ip):
                decision, note = QUARANTINE, None
            if fronted:
                note = _with_note(FRONTED_DETAIL.format(sni=sni, host=host), note)
            meta = flow.metadata.get(META)  # another hook of this flow may have got there while this one waited
            if meta is None:
                meta = flow.metadata[META] = {
                    "t0": time.time(), "host": host, "ip": ip, "port": request.port, "vouched": vouched,
                    "fronted": fronted, "note": note, "decision": decision, "leak": None, "scanned": False,
                    "client_ip": client_ip}
                if decision.action == "allow" and client.id in self.state:
                    self.state[client.id]["opened"] = True
        return meta

    def _no_scan(self, meta: dict) -> bool:
        if meta.get("fronted"):
            return False
        return self._listed("no_scan", meta["host"], meta["ip"], meta["port"], meta["vouched"])

    def _may_go_unscanned(self, meta: dict) -> bool:
        """Whether a body may pass without a complete scan: the host isn't scanned at all, the owner allowed it
        (allow list, exception), or the owner's setting `unscanned` says allow."""
        return (self._no_scan(meta) or meta["decision"].rule in LOOSENING
                or self.policy.get("unscanned", "allow") == "allow")

    async def requestheaders(self, flow) -> None:
        """A blocked request gets its 403 in the request hook, once its body is in. A body that streams (too
        large to hold, known now from Content-Length, or found out halfway through a chunked one) would be on
        its way to the server by then, so a request that mustn't stream is marked here, and mitmproxy's
        streaming refuses it (_patched_start_request_stream)."""
        meta = await self._http_meta(flow)
        decision = meta["decision"]
        if decision.action == "deny":
            flow.metadata[NO_STREAM] = (decision.rule, decision.detail)
        elif self._no_scan(meta):
            # its URL and headers are checked for honeytokens now, before a large body could start streaming
            try:
                blocked = await self._no_scan_verdict(flow, meta, with_body=False)
            except Exception:
                logger.exception("doorman egress: checking a request's headers failed")
                blocked = ("error", ERROR_DETAIL)
            if blocked is not None:
                meta["blocked"] = flow.metadata[NO_STREAM] = blocked
        elif not self._may_go_unscanned(meta):
            flow.metadata[NO_STREAM] = ("unscanned", UNSCANNED_DETAIL)

    async def request(self, flow) -> None:
        meta = await self._http_meta(flow)
        try:
            await self._check_request(flow, meta)
        except Exception:
            logger.exception("doorman egress: checking a request failed")
            self._block(flow, meta, "error", ERROR_DETAIL)

    async def _check_request(self, flow, meta: dict) -> None:
        if self._quarantined(meta["client_ip"]):  # also when it came while the body was arriving
            meta["decision"] = QUARANTINE
        decision = meta["decision"]
        if decision.action == "deny":
            return self._block(flow, meta, decision.rule, decision.detail)
        if flow.response is not None or flow.error is not None or flow.request.stream:
            return  # streamed: allowed to go unscanned (requestheaders), so it went
        if self._no_scan(meta):
            blocked = meta.get("blocked") or await self._no_scan_verdict(flow, meta, with_body=True)
            if blocked is not None:
                self._block(flow, meta, *blocked)
            return
        request = flow.request
        body = request.get_content(strict=False) or b""
        prints, hits, complete, _ = await asyncio.to_thread(
            _scan, request.pretty_url, self._header_texts(flow), body,
            request.headers.get("content-type", ""), self._honeytokens())
        meta["scanned"] = complete
        blocked = await self._content_verdict(meta["client_ip"], meta, _clip(request.pretty_url, 2000),
                                              request.method, prints, hits)
        if blocked is None and not complete and not self._may_go_unscanned(meta):
            blocked = ("unscanned", UNSCANNED_DETAIL)
        if blocked is not None:
            self._block(flow, meta, *blocked)

    def _header_texts(self, flow) -> list[tuple[str, str]]:
        """Every header and trailer, plus what names the host (:authority in HTTP/2, the TLS name): all of it
        is the agent's to write, so all of it can carry data."""
        request = flow.request
        out = list(request.headers.items(multi=True))
        if request.trailers:
            out += list(request.trailers.items(multi=True))
        if request.authority:
            out.append((":authority", request.authority))
        if flow.client_conn.sni:
            out.append((":sni", flow.client_conn.sni))
        return out

    def _honeytokens(self) -> list[str]:
        return [t for t in self.policy.get("honeytokens") or [] if isinstance(t, str) and t]

    def _decoys(self) -> list[str]:
        return [t for t in self.policy.get("decoys") or [] if isinstance(t, str) and t]

    async def _no_scan_verdict(self, flow, meta: dict, with_body: bool) -> tuple[str, str] | None:
        """A request to a host on no_scan isn't fingerprinted, but a honeytoken in its URL or a header (the
        decoy Anthropic key as x-api-key) is blocked and reported like anywhere else, and the decoy keys in
        its body (`with_body`, once it is in) go to Doorman, which decides (check(): the agent read them)."""
        tokens = self._honeytokens()
        if not tokens:
            return None
        request, decoys = flow.request, self._decoys()
        body = (request.get_content(strict=False) or b"") if with_body and decoys else b""
        head, inside = await asyncio.to_thread(_no_scan_hits, request.pretty_url, self._header_texts(flow), body,
                                               tokens, decoys)
        if not head and not inside:
            return None
        return await self._content_verdict(meta["client_ip"], meta, _clip(request.pretty_url, 2000), request.method,
                                           [], head or inside, no_scan=not head)

    async def _content_verdict(self, client_ip: str | None, meta: dict, url: str | None, method: str,
                               prints: list[int], hits: list[str], kind: str | None = None,
                               no_scan: bool = False) -> tuple[str, str] | None:
        """Asks Doorman about what a request, message or raw stream carries: (rule, detail) to block it, or
        None. More prints than one call takes go in several (overlapping, in text order); prints Doorman just
        said are in nothing it served aren't asked about again for a minute. `no_scan`: the hits are decoy
        keys in the content of a connection to a host on no_scan (Doorman's check() treats those apart)."""
        if not prints and not hits:
            return None
        now = time.time()
        if not hits and all(self.clean.get(p, 0) > now for p in prints):
            return None
        chars, sources, answer = 0, [], None
        for n, chunk in enumerate(_chunks(prints)):
            body = {"client_ip": client_ip, "host": meta["host"], "url": url, "method": method,
                    "prints": chunk, "honeytokens": hits if n == 0 else []}
            if kind:
                body["kind"] = kind
            if no_scan:
                body["no_scan"] = True
            answer = await asyncio.to_thread(self.client.check, body)
            if answer is None:
                break
            chars = max(chars, int(answer.get("chars") or 0))
            sources += [str(s)[:200] for s in answer.get("sources") or [] if str(s)[:200] not in sources]
            if answer["action"] == "deny":
                break
            if not hits and not answer.get("chars"):
                self._mark_clean(chunk, now)
        if answer is None:
            self._warn("check", f"can't ask Doorman about a request ({self.client.last_error})")
            if hits:
                return "honeytoken", HONEYTOKEN_DETAIL
            if self.policy.get("when_doorman_down", "allow") != "allow":
                return "doorman_down", DOWN_DETAIL
            meta["detail"] = DOWN_PASSED
            return None
        sources = sources[:20]
        note = int((self.policy.get("match") or {}).get("note_chars") or 0)
        if hits or (chars and chars >= note):
            meta["leak"] = {"chars": chars, "sources": sources}
        if answer["action"] != "deny":
            return None
        if hits:
            return "honeytoken", str(answer.get("reason") or HONEYTOKEN_DETAIL)
        return "leak", str(answer.get("reason") or LEAK_DETAIL.format(chars=chars, sources=", ".join(sources)))

    def _mark_clean(self, prints: list[int], now: float) -> None:
        if len(self.clean) + len(prints) > CLEAN_MAX:
            self.clean = {p: t for p, t in self.clean.items() if t > now}
            if len(self.clean) + len(prints) > CLEAN_MAX:
                self.clean.clear()
        if len(prints) <= CLEAN_MAX:
            until = now + CLEAN_MEMORY
            self.clean.update(dict.fromkeys(prints, until))

    def _block(self, flow, meta: dict, rule: str, detail: str, close: bool = False) -> None:
        target = meta["host"] or meta["ip"]
        meta["decision"] = rules.Decision("deny", rule, detail)
        if rule in SILENT_RULES:  # an ordinary upstream failure, as far as the agent can tell
            headers = {"Content-Type": "text/plain; charset=utf-8"}
            if close or rule == "quarantine":
                headers["Connection"] = "close"
            flow.response = http.Response.make(502, BAD_GATEWAY, headers)
            return
        headers = {"Content-Type": "text/plain; charset=utf-8", "X-Doorman-Egress": f"blocked; rule={rule}"}
        if close:
            headers["Connection"] = "close"
        flow.response = http.Response.make(403, BLOCK_BODY.format(detail=detail, target=target).encode(), headers)

    async def websocket_message(self, flow) -> None:
        message = flow.websocket.messages[-1]
        del flow.websocket.messages[:-1]
        meta = flow.metadata.get(META)
        if meta is not None and self._quarantined(meta.get("client_ip")):
            message.drop()  # both ways: a socket open since before the quarantine carries nothing more
            client = flow.client_conn
            self._record_quarantined(client.id, meta.get("client_ip"), "http", meta["host"], meta["ip"], meta["port"])
            return
        if not message.from_client or meta is None:
            return
        try:
            url = _clip(flow.request.pretty_url, 2000)
            if self._no_scan(meta):  # not fingerprinted, but the decoy keys are looked for (_no_scan_hits)
                hits = await asyncio.to_thread(_plain_hits, message.content, self._decoys())
                blocked = await self._content_verdict(meta.get("client_ip"), dict(meta), url, "WEBSOCKET", [], hits,
                                                      no_scan=True) if hits else None
            else:
                prints, hits, complete, _ = await asyncio.to_thread(
                    _scan, "", [], message.content, "", self._honeytokens())
                blocked = await self._content_verdict(meta.get("client_ip"), dict(meta), url, "WEBSOCKET", prints,
                                                      hits)
                if blocked is None and not complete and not self._may_go_unscanned(meta):
                    blocked = ("unscanned", UNSCANNED_DETAIL)
        except Exception:  # a message the proxy couldn't check doesn't go out
            logger.exception("doorman egress: checking a WebSocket message failed")
            blocked = ("error", ERROR_DETAIL)
        if blocked is not None:
            message.drop()
            client = flow.client_conn
            self._record(client.id, _plain_ip(client.peername[0]), kind="http", host=meta["host"], ip=meta["ip"],
                         port=meta["port"], method="WEBSOCKET", path=flow.request.path,
                         bytes_up=len(message.content), decision="deny", rule=blocked[0],
                         detail=_with_note(blocked[1], meta["note"]), scanned=blocked[0] != "error")

    async def response(self, flow) -> None:
        """A server's 101 to anything but a WebSocket (or a WebSocket handshake mitmproxy won't read, e.g. an
        unknown Sec-WebSocket-Version) would leave a pipe nobody reads: the agent gets a 403 instead, and the
        connection is closed after it."""
        if flow.response is not None and flow.response.status_code == 101 and flow.websocket is None:
            meta = await self._http_meta(flow)
            protocol = _clip(flow.response.headers.get("upgrade", "") or "none", 60)
            self._block(flow, meta, "upgrade", UPGRADE_DETAIL.format(protocol=protocol), close=True)
        await self._http_record(flow)

    async def error(self, flow) -> None:
        await self._http_record(flow)

    async def _http_record(self, flow) -> None:
        meta = await self._http_meta(flow)
        if meta.get("logged"):
            return
        meta["logged"] = True
        request, response, decision = flow.request, flow.response, meta["decision"]
        detail = decision.detail or meta.get("detail") or (f"failed: {flow.error.msg}" if flow.error else "")
        detail = _with_note(detail, meta["note"])
        client = flow.client_conn
        extra = {"auth_hash": _auth_hash(request.headers)} if self._no_scan(meta) else {}
        self._record(client.id, _plain_ip(client.peername[0]), ts=request.timestamp_start, kind="http",
                     host=meta["host"], ip=meta["ip"], port=meta["port"], method=request.method, path=request.path,
                     status=response.status_code if response is not None else None,
                     bytes_up=_length(request, request.raw_content, flow.metadata.get(BYTES_STREAMED)),
                     bytes_down=_length(response, response.raw_content) if response is not None else 0,
                     decision=decision.action, rule=decision.rule, detail=detail, leak=meta["leak"],
                     duration_ms=max(0, round((time.time() - request.timestamp_start) * 1000)),
                     scanned=bool(meta["scanned"]), **extra)


def from_env() -> DoormanEgress:
    env = os.environ
    geoip_off = env.get("EGRESS_GEOIP", "1") == "0"
    decoy_dir = env.get("EGRESS_DECOY_DIR", "/decoys") or None
    if decoy_dir and not os.path.isdir(decoy_dir):
        logger.warning(f"doorman egress: no folder {decoy_dir} (the agent-config volume): no decoy keys")
        decoy_dir = None
    return DoormanEgress(
        DoormanClient(env.get("DOORMAN_URL", "http://doorman:8710"), env.get("DOORMAN_EGRESS_TOKEN", "")),
        None if geoip_off else env.get("EGRESS_GEOIP_PATH", "/data/geoip"),
        env.get("OBSERVER_URL") or None,
        state_dir=env.get("EGRESS_STATE_DIR", "/data"),
        geoip_download=not geoip_off,
        decoy_dir=decoy_dir,
    )


if __name__.startswith("__mitmproxy_script__"):  # loaded by mitmdump -s; tests build their own
    addons = [from_env()]
