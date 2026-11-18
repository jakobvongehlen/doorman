import json
import os
import threading
import time
from urllib.parse import urlparse

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from doorman import clock, webpush
from doorman.approvals_util import BODY_CHARS, accept_in_place, notice_text
from doorman.notify import VAULT_SECTION
from doorman.notify import MAX_PAYLOAD, Notifier, PushGone
from doorman.plugin_api import NotSent
from conftest import FAKE_PLUGINS, Agent, make_engine
from test_api import CSRF, register, setup, tap  # noqa: F401  (setup and tap are fixtures)

http_ece = pytest.importorskip("http_ece")  # an independent aes128gcm implementation checks ours

ENDPOINT = "https://push.example.net/send/abc123"


class Device:
    """A browser's side of a push subscription: its key pair and auth secret."""

    def __init__(self, endpoint=ENDPOINT):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.auth = os.urandom(16)
        self.subscription = {"endpoint": endpoint, "keys": {
            "p256dh": webpush.b64url(webpush.raw_public(self.key.public_key())), "auth": webpush.b64url(self.auth)}}

    def read(self, body: bytes) -> dict:
        return json.loads(http_ece.decrypt(body, private_key=self.key, auth_secret=self.auth, version="aes128gcm"))


class PushService:
    """Records requests and answers each endpoint with its statuses in turn (the last one repeats)."""

    def __init__(self, *statuses, per_endpoint=None, headers=None, body=b""):
        self.default = list(statuses) or [201]
        self.per_endpoint = {k: list(v) for k, v in (per_endpoint or {}).items()}
        self.headers, self.body = headers or {}, body
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        statuses = self.per_endpoint.get(str(request.url), self.default)
        status = statuses.pop(0) if len(statuses) > 1 else statuses[0]
        return httpx.Response(status, headers=self.headers if status >= 400 else {}, content=self.body)


def with_service(engine, *statuses, fast=True, **kw) -> PushService:
    service = PushService(*statuses, **kw)
    engine.notifier.transport = httpx.MockTransport(service)
    if fast:
        engine.notifier.RETRY_DELAYS = (0, 0, 0, 0)
    return service


def delivered(engine, note_id) -> bool:
    return engine.db.one("SELECT delivered FROM notifications WHERE id=?", (note_id,))["delivered"] == 1


def approval_hash(engine, approval_id) -> str:
    return engine.db.one("SELECT payload_hash FROM approvals WHERE id=?", (approval_id,))["payload_hash"]


def wait_for(condition, seconds=5):
    for _ in range(int(seconds / 0.05)):
        if condition():
            return
        time.sleep(0.05)
    raise AssertionError("timed out")


def test_payload_decrypts_with_an_independent_implementation():
    device = Device()
    body = webpush.encrypt(b'{"title":"hi"}', **device.subscription["keys"])
    assert body[16:21] == (4096).to_bytes(4, "big") + bytes([65])  # rs, then the length of the sender key
    assert device.read(body) == {"title": "hi"}
    # a fresh key and salt every time, so equal notices don't look equal on the wire
    assert webpush.encrypt(b"x", **device.subscription["keys"]) != webpush.encrypt(b"x", **device.subscription["keys"])


def test_one_record_holds_at_most_3993_bytes():
    keys = Device().subscription["keys"]
    assert len(webpush.encrypt(b"a" * 3993, **keys)) == 4096  # the most push services must accept (RFC 8291, 4)
    with pytest.raises(ValueError):
        webpush.encrypt(b"a" * 3994, **keys)


def test_vapid_token_is_a_valid_es256_jwt():
    vapid = webpush.Vapid.generate()
    header = vapid.authorization(ENDPOINT + "?x=1", "mailto:owner@example.com", now=1_800_000_000)
    token, key = header.removeprefix("vapid t=").split(", k=")
    head, claims, signature = token.split(".")
    assert json.loads(webpush.b64url_decode(head)) == {"typ": "JWT", "alg": "ES256"}
    assert json.loads(webpush.b64url_decode(claims)) == {
        "aud": "https://push.example.net", "exp": 1_800_000_000 + 12 * 3600, "sub": "mailto:owner@example.com"}
    raw = webpush.b64url_decode(signature)
    public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), webpush.b64url_decode(key))
    public.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                  f"{head}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))
    assert key == vapid.public_key


def test_vapid_key_is_created_once_and_kept_in_the_vault(engine):
    first = engine.notifier.vapid.public_key
    again = Notifier(engine.config, engine.db, engine.vault)
    assert again.vapid.public_key == first
    assert "vapid_private_key" in engine.vault.get(VAULT_SECTION)


def test_notice_reaches_every_device_encrypted(engine):
    phone, tablet = Device(), Device("https://push.example.org/t/1")
    engine.notifier.subscribe(phone.subscription, "phone")
    engine.notifier.subscribe(tablet.subscription, "tablet")
    service = with_service(engine)
    note_id = engine.notifier.push("Approval needed", "Send “Offer” to anna@example.com", url="https://b/app/", wait=True)
    assert len(service.requests) == 2
    request = service.requests[0]
    assert request.headers["Content-Encoding"] == "aes128gcm"
    assert request.headers["TTL"] == "86400" and request.headers["Urgency"] == "normal"
    assert request.headers["Authorization"].startswith("vapid t=")
    assert b"anna@example.com" not in request.content  # the push service only sees ciphertext
    assert phone.read(request.content) == {"title": "Approval needed", "body": "Send “Offer” to anna@example.com",
                                           "url": "https://b/app/", "tag": f"n{note_id}"}
    assert tablet.read(service.requests[1].content)["title"] == "Approval needed"
    assert delivered(engine, note_id)
    assert all(s["last_ok"] for s in engine.notifier.subscriptions())


def test_gone_device_is_removed_and_must_subscribe_afresh(engine):
    device = Device()
    engine.notifier.subscribe(device.subscription, "old phone")
    service = with_service(engine, 410)
    note_id = engine.notifier.push("Hello", "x", wait=True)
    assert len(service.requests) == 1
    assert engine.notifier.subscriptions() == [] and not delivered(engine, note_id)
    with pytest.raises(PushGone):  # the app then asks the browser for a new endpoint
        engine.notifier.subscribe(device.subscription, "old phone")


def test_temporary_failures_are_retried_and_refusals_are_not(engine):
    engine.notifier.subscribe(Device().subscription, "phone")
    service = with_service(engine, 503, 429, 201)
    note_id = engine.notifier.push("Hello", "x", wait=True)
    assert len(service.requests) == 3 and delivered(engine, note_id)

    service = with_service(engine, 400, body=b'{"reason":"BadJwtToken"}')
    engine.notifier.push("Hello", "x", wait=True)
    assert len(service.requests) == 1  # a refused request won't get better by sending it again
    [device] = engine.notifier.subscriptions()
    assert device["failures"] == 1 and device["last_error"] == "HTTP 400 BadJwtToken"


def test_a_failing_device_does_not_hold_up_the_others(engine):
    broken, working = Device("https://push.example.net/broken"), Device("https://push.example.org/ok")
    engine.notifier.subscribe(broken.subscription, "broken")
    engine.notifier.subscribe(working.subscription, "working")
    service = with_service(engine, per_endpoint={"https://push.example.net/broken": [503],
                                                 "https://push.example.org/ok": [201]})
    note_id = engine.notifier.push("Sending in 10 min", "x", wait=True)
    endpoints = [str(r.url) for r in service.requests]
    assert endpoints[:2] == ["https://push.example.net/broken", "https://push.example.org/ok"]
    assert endpoints[2:] == ["https://push.example.net/broken"] * 4  # only the failed one is retried
    assert delivered(engine, note_id)


def test_retries_stop_when_the_notice_is_out_of_date(engine):
    engine.notifier.subscribe(Device().subscription, "phone")
    service = with_service(engine, 503, fast=False)  # the first retry would come after 10 s
    engine.notifier.push("Sending in 1 min", "x", ttl=5, wait=True)
    assert len(service.requests) == 1


def test_retry_after_is_honoured(engine, monkeypatch):
    sleeps = []
    monkeypatch.setattr("doorman.notify.time.sleep", sleeps.append)
    engine.notifier.subscribe(Device().subscription, "phone")
    service = with_service(engine, 429, 201, headers={"Retry-After": "42"})
    engine.notifier.push("Hello", "x", wait=True)
    assert len(service.requests) == 2 and len(sleeps) == 1 and 42 <= sleeps[0] <= 42 * 1.2


def test_long_notices_are_trimmed_to_fit_one_record(engine):
    device = Device()
    engine.notifier.subscribe(device.subscription, "phone")
    service = with_service(engine)
    engine.notifier.push("Approval needed", "ü" * 5000, wait=True)
    data = device.read(service.requests[0].content)
    assert data["body"].endswith("…") and len(json.dumps(data, ensure_ascii=False).encode()) <= MAX_PAYLOAD


def test_agent_cannot_silence_its_changeset_with_a_huge_title(engine, agent):
    device = Device()
    engine.notifier.subscribe(device.subscription, "phone")
    service = with_service(engine)
    note = agent.call("notes.create", {"title": "a"})["result"]["id"]
    engine.propose_changeset(agent.session, agent.key, "x" * 50_000,
                             [{"tool": "notes.update", "args": {"id": note, "body": "b"}}])
    wait_for(lambda: service.requests)
    [request] = service.requests
    assert len(request.content) <= 4096
    title = device.read(request.content)["title"]
    assert title.startswith("Changeset to review: xxx") and len(title) <= 120


@pytest.mark.parametrize("subscription", [
    {"endpoint": "http://push.example.net/x", "keys": Device().subscription["keys"]},
    {"endpoint": ENDPOINT, "keys": {"p256dh": "not-a-key", "auth": Device().subscription["keys"]["auth"]}},
    {"endpoint": ENDPOINT, "keys": {"p256dh": Device().subscription["keys"]["p256dh"], "auth": "c2hvcnQ"}},
    {"endpoint": ENDPOINT},
])
def test_invalid_subscriptions_are_refused(engine, subscription):
    with pytest.raises(ValueError):
        engine.notifier.subscribe(subscription)


def test_resubscribing_updates_instead_of_duplicating(engine):
    device = Device()
    first = engine.notifier.subscribe(device.subscription, "phone")
    engine.db.exec("UPDATE push_subscriptions SET failures=3, last_error='HTTP 403'")
    assert engine.notifier.subscribe(device.subscription, "phone, renamed") == first
    [row] = engine.notifier.subscriptions()
    assert row["label"] == "phone, renamed" and row["failures"] == 3  # the app re-syncs on every load
    engine.notifier.subscribe(Device().subscription | {"endpoint": ENDPOINT}, "phone, new keys")
    assert engine.notifier.subscriptions()[0]["failures"] == 0


def test_every_send_pushes_an_approval_notice(setup):
    engine, _, agent, _ = setup
    device = Device()
    engine.notifier.subscribe(device.subscription, "phone")
    service = with_service(engine)
    engine.db.exec("INSERT INTO trust(kind, value, label, created) VALUES('email','anna@example.com','Anna','x')")
    note = agent.post("/v1/tools/notes.create", json={"args": {"title": "a"}}).json()["result"]["id"]
    waiting = agent.post("/v1/tools/notes.send_copy", json={"args": {"id": note, "to": "anna@example.com"}}).json()
    assert waiting["status"] == "waiting_approval"  # even to a trusted address
    wait_for(lambda: service.requests)
    [request] = service.requests
    assert request.headers["Urgency"] == "high"
    notice = device.read(request.content)
    assert notice["title"] == "Send to anna@example.com" and "anna@example.com" in notice["body"]
    assert notice["tag"] == f"approval-{waiting['approval_id']}"  # the app closes it once decided there
    assert urlparse(notice["url"]).fragment == f"/approvals/{waiting['approval_id']}"  # a tap opens it
    # Accept and Decline act on this approval; Accept sends the hash, so it approves only this payload
    passkey_mode = engine.config["approval_passkey"]
    assert notice["approval"] == {"id": waiting["approval_id"], "hash": approval_hash(engine, waiting["approval_id"]),
                                  "accept": "app" if passkey_mode else "tap"}
    assert "Copy of your note: a" in notice["body"]


def test_owner_api_manages_devices(setup):
    engine, owner, _, passkey = setup
    assert owner.get("/owner/push").status_code == 401
    register(engine, owner, passkey)
    status = owner.get("/owner/push").json()
    assert status["public_key"] == engine.notifier.vapid.public_key and status["subscriptions"] == []
    assert status["subject_ok"] is False  # public_url is http://localhost and no push.subject is set
    assert owner.post("/owner/push/test", headers=CSRF).status_code == 403  # no device yet
    device = Device()
    assert owner.post("/owner/push/subscribe", json={"subscription": device.subscription}).status_code == 403  # CSRF
    added = owner.post("/owner/push/subscribe", headers=CSRF, json={"subscription": device.subscription, "label": "phone"})
    assert added.status_code == 200
    bad = owner.post("/owner/push/subscribe", headers=CSRF, json={"subscription": {"endpoint": "http://x"}})
    assert bad.status_code == 403 and bad.json()["code"] == "invalid"
    service = with_service(engine)
    assert owner.post("/owner/push/test", headers=CSRF).json()["results"] == [
        {"id": added.json()["id"], "label": "phone", "ok": True, "status": 201, "reason": ""}]
    assert device.read(service.requests[0].content)["title"] == "Test notification"
    with_service(engine, 403, body=b'{"reason":"VapidPkHashMismatch"}')
    [result] = owner.post("/owner/push/test", headers=CSRF).json()["results"]
    assert result["ok"] is False and result["status"] == 403 and result["reason"] == "VapidPkHashMismatch"
    assert owner.delete(f"/owner/push/{added.json()['id']}", headers=CSRF).status_code == 200
    assert owner.get("/owner/push").json()["subscriptions"] == []
    gone = Device()
    engine.db.exec("INSERT INTO push_gone(endpoint, ts) VALUES(?, 'x')", (gone.subscription["endpoint"],))
    refused = owner.post("/owner/push/subscribe", headers=CSRF, json={"subscription": gone.subscription})
    assert refused.status_code == 403 and refused.json()["code"] == "push_gone"


# ---------------------------------------------------------------- Accept and Decline on the push

def test_notice_text_shows_recipient_subject_and_the_first_lines():
    mail = {"summary": "Send “Dinner on Friday” to anna@example.com", "tool": "mail.send",
            "args": {"to": ["anna@example.com"], "subject": "Dinner on Friday",
                     "body": "Hi Anna,\n\nare you free on Friday?\nWe could try the new place.\nLine four.\nLine five."}}
    text = notice_text([mail])
    assert text.splitlines()[0] == "Send “Dinner on Friday” to anna@example.com"
    assert "Hi Anna,\nare you free on Friday?\nWe could try the new place. …" in text and "Line four" not in text
    long = notice_text([{**mail, "args": {"text": "x" * 5000}}])
    assert long.endswith("…") and len(long) < 400
    many = notice_text([mail] * 20)
    assert len(many) <= 900 and many.endswith("…")


def test_an_approval_push_with_a_huge_body_fits_and_keeps_its_buttons(setup):
    engine, _, agent, _ = setup
    device = Device()
    engine.notifier.subscribe(device.subscription, "phone")
    service = with_service(engine)
    engine.db.exec("INSERT INTO trust(kind, value, label, created) VALUES('email','anna@example.com','Anna','x')")
    note = agent.post("/v1/tools/notes.create", json={"args": {"title": "ü" * 200, "body": "€" * 20000}}).json()
    waiting = agent.post("/v1/tools/notes.send_copy", json={"args": {
        "id": note["result"]["id"], "to": "anna@example.com", "message": "\"€\n" * 1600}}).json()
    wait_for(lambda: service.requests)
    [request] = service.requests
    assert len(request.content) <= 4096
    notice = device.read(request.content)
    assert len(json.dumps(notice, ensure_ascii=False).encode()) <= MAX_PAYLOAD
    assert notice["approval"]["id"] == waiting["approval_id"]
    assert notice["approval"]["hash"] == approval_hash(engine, waiting["approval_id"])


def test_the_buttons_fall_back_to_the_app_when_the_body_is_dropped(engine):
    device = Device()
    engine.notifier.subscribe(device.subscription, "phone")
    service = with_service(engine)
    engine.notifier.push("Approval needed", "Send it", url="https://x.example/" + "a" * 4000, wait=True,
                         extra={"approval": {"id": 7, "hash": "ab" * 32, "accept": "tap"}})
    notice = device.read(service.requests[0].content)
    assert notice["body"] == "" and notice["approval"] == {"id": 7, "hash": "ab" * 32, "accept": "app"}
    engine.notifier.push("Changeset to review", "1 change", url="https://x.example/" + "a" * 4000, wait=True,
                         extra={"ask": {"kind": "changeset", "id": 3, "accept": "tap"}})
    assert device.read(service.requests[1].content)["ask"] == {"kind": "changeset", "id": 3, "accept": "app"}


def send_copy(agent, to="anna@example.com"):
    note = agent.post("/v1/tools/notes.create", json={"args": {"title": "Plan", "body": "Line 1"}}).json()
    return agent.post("/v1/tools/notes.send_copy", json={"args": {"id": note["result"]["id"], "to": to}}).json()


def from_push(owner, approval_id, approve, payload_hash=None):
    """What the service worker sends for Accept or Decline: the app's call, plus via=notification."""
    body = {"approve": approve, "via": "notification"} | ({"payload_hash": payload_hash} if approve else {})
    return owner.post(f"/owner/approvals/{approval_id}/decide", headers=CSRF, json=body)


def test_decline_from_the_push(setup):
    engine, owner, agent, passkey = setup
    register(engine, owner, passkey)
    waiting = send_copy(agent, "stranger@elsewhere.example")  # warnings don't matter for a decline
    declined = from_push(owner, waiting["approval_id"], False)
    assert declined.status_code == 200 and declined.json()["status"] == "denied"
    assert engine.journal.get(waiting["entry_id"])["status"] == "rejected"
    row = engine.db.one("SELECT status, method FROM approvals WHERE id=?", (waiting["approval_id"],))
    assert row == {"status": "denied", "method": "notification"}
    # a second tap, or Accept after Decline, says it's already decided
    for approve in (False, True):
        late = from_push(owner, waiting["approval_id"], approve, approval_hash(engine, waiting["approval_id"]))
        assert late.status_code == 403 and late.json()["code"] == "decided"
        assert "declined" in late.json()["reason"]


def test_accept_from_the_push_approves_what_the_push_showed(setup):
    engine, owner, agent, passkey = setup
    register(engine, owner, passkey)
    engine.db.exec("INSERT INTO trust(kind, value, label, created) VALUES('email','anna@example.com','Anna','x')")
    waiting = send_copy(agent)
    accepted = from_push(owner, waiting["approval_id"], True, approval_hash(engine, waiting["approval_id"]))
    if engine.config["approval_passkey"]:  # a passkey can't sign from a notification: open the app
        assert accepted.status_code == 403 and accepted.json()["code"] == "open_app"
        assert engine.journal.get(waiting["entry_id"])["status"] == "waiting_approval"
        return
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["results"][0]["status"] == "done"
    row = engine.db.one("SELECT status, method FROM approvals WHERE id=?", (waiting["approval_id"],))
    assert row == {"status": "approved", "method": "notification"}
    # the app (or a second device) tapping later hears that it's done
    late = owner.post(f"/owner/approvals/{waiting['approval_id']}/decide", headers=CSRF, json={"approve": False})
    assert late.status_code == 403 and late.json()["code"] == "decided" and "approved" in late.json()["reason"]


def test_accept_from_the_push_of_a_slow_send_reports_by_push_under_its_tag(tap, monkeypatch):
    """Accept gets "sending" after send_wait_seconds; the outcome follows as a push tagged like the approval's,
    so it replaces the "sending" line the service worker left. A failure's own push carries that tag too."""
    engine, owner, agent, _ = tap
    device = Device()
    engine.notifier.subscribe(device.subscription, "phone")
    service = with_service(engine)
    engine.db.exec("INSERT INTO trust(kind, value, label, created) VALUES('email','anna@example.com','Anna','x')")
    engine.config["send_wait_seconds"] = 0.2
    kind = type(engine.registry.instance("notes").tools["send_copy"])
    real, go = kind.execute, threading.Event()
    monkeypatch.setattr(kind, "execute", lambda self, args, before: (go.wait(10), real(self, args, before))[1])
    waiting = send_copy(agent)
    wait_for(lambda: len(service.requests) == 1)
    accepted = from_push(owner, waiting["approval_id"], True, approval_hash(engine, waiting["approval_id"]))
    assert accepted.status_code == 200 and accepted.json()["sending"], accepted.text
    go.set()
    wait_for(lambda: len(service.requests) == 2)
    late = device.read(service.requests[1].content)
    assert late["title"] == "Sent" and late["tag"] == f"approval-{waiting['approval_id']}"
    assert not late.get("approval")  # no buttons: it only says what happened

    # a send that fails: its Needs attention push replaces the approval's on the phone
    def refused(self, args, before):
        raise NotSent("the server refused it")
    monkeypatch.setattr(kind, "execute", refused)
    failing = send_copy(agent)
    wait_for(lambda: len(service.requests) == 3)
    out = from_push(owner, failing["approval_id"], True, approval_hash(engine, failing["approval_id"])).json()
    assert out["results"][0]["status"] == "failed" and not out["sending"]
    wait_for(lambda: len(service.requests) == 4)
    failed = device.read(service.requests[3].content)
    assert failed["title"] == "A send failed; nothing went out"
    assert failed["tag"] == f"approval-{failing['approval_id']}"


def test_accept_from_the_push_with_a_stale_hash_is_refused(tap):
    engine, owner, agent, _ = tap
    engine.db.exec("INSERT INTO trust(kind, value, label, created) VALUES('email','anna@example.com','Anna','x')")
    first, second = send_copy(agent), send_copy(agent)
    # another approval's hash (what another push showed) doesn't approve this one
    stale = from_push(owner, second["approval_id"], True, approval_hash(engine, first["approval_id"]))
    assert stale.status_code == 403 and stale.json()["code"] == "payload_changed"
    # the payload changed after the push went out: the hash the push carried no longer matches it
    seen = approval_hash(engine, first["approval_id"])
    entry = engine.journal.get(first["entry_id"])
    engine.db.exec("UPDATE journal SET args=? WHERE id=?",
                   (json.dumps({**entry["args"], "to": "evil@x.example"}), first["entry_id"]))
    changed = from_push(owner, first["approval_id"], True, seen)
    assert changed.status_code == 403 and changed.json()["code"] == "payload_changed"
    for waiting in (first, second):
        assert engine.journal.get(waiting["entry_id"])["status"] != "done"


def test_accept_from_the_push_opens_the_app_for_a_warning(tap):
    engine, owner, agent, _ = tap
    device = Device()
    engine.notifier.subscribe(device.subscription, "phone")
    service = with_service(engine)
    waiting = send_copy(agent, "stranger@elsewhere.example")  # a new recipient: the app shows a warning
    wait_for(lambda: service.requests)
    assert device.read(service.requests[0].content)["approval"]["accept"] == "app"
    refused = from_push(owner, waiting["approval_id"], True, approval_hash(engine, waiting["approval_id"]))
    assert refused.status_code == 403 and refused.json()["code"] == "open_app"
    assert engine.journal.get(waiting["entry_id"])["status"] == "waiting_approval"
    # the same tap in the app, which shows the warning, approves it
    approved = owner.post(f"/owner/approvals/{waiting['approval_id']}/decide", headers=CSRF,
                          json={"approve": True, "payload_hash": approval_hash(engine, waiting["approval_id"])})
    assert approved.status_code == 200


@pytest.fixture
def reply_to_stranger(tmp_path):
    """A stranger asks for something; the agent read their mail, so answering them raises no warning.
    send(body, attachments) answers and returns the push it made: (message, approval extra)."""
    engine = make_engine(tmp_path, plugin_paths=[FAKE_PLUGINS], plugins={"mail": {"type": "fake_mail", "enabled": True}})
    pushed = []
    engine.notifier.push = lambda title, message, **kw: pushed.append((message, kw["extra"]["approval"]))
    box = engine.registry.instance("mail")
    asked = box.add("inbox", "stranger@elsewhere.example", "Quick question", "Could you send me the contract?")
    agent = Agent(engine)
    agent.read("mail.read", {"id": asked})

    def send(body, attachments=()):
        out = agent.call("mail.send", {"to": ["stranger@elsewhere.example"], "subject": "Re: Quick question",
                                       "body": body, "in_reply_to": asked, "attachments": list(attachments)})
        assert out["status"] == "waiting_approval" and not out.get("warnings")
        return pushed[-1]
    return engine, agent, send


def test_accept_on_the_push_approves_long_texts_and_attachments_in_place(reply_to_stranger):
    """The owner's call (7 Nov): Accept on the push approves a send without warnings in place, however long
    its text and whatever it attaches. The push shows the first lines; tapping the push opens all of it."""
    engine, agent, send = reply_to_stranger
    message, approval = send("Hi,\nthanks for writing, I'll look for it.\nBest regards")
    assert approval["accept"] == "tap" and "open Doorman" not in message
    assert engine.approvals.accept_from_notification(approval["id"]) is True

    for body in ("one\ntwo\nthree\nfour", "y" * (BODY_CHARS + 1)):
        message, approval = send(body)
        assert approval["accept"] == "tap" and "open Doorman" not in message
        assert engine.approvals.accept_from_notification(approval["id"]) is True

    upload = engine.upload(agent.session, agent.key, "notes.pdf", b"lecture notes")["ref"]
    message, approval = send("Here it is.", [upload])
    assert approval["accept"] == "tap"
    assert engine.approvals.accept_from_notification(approval["id"]) is True


def test_a_note_copy_with_a_message_shows_both_texts():
    """A copy of a note carries the note and the agent's message: the push shows both."""
    view = {"summary": "Send note “Plan” to anna@example.com", "status": "waiting_approval", "tier": "irreversible",
            "args": {"id": "n1", "to": "anna@example.com", "message": "Here's the plan"},
            "outgoing": {"label": "Copy of your note", "title": "Plan", "text": "Line 1"}}
    assert "Here's the plan\nLine 1" in notice_text([view])
    assert accept_in_place([view], False)


def test_buttons_after_expiry_or_without_a_session(tap):
    engine, owner, agent, _ = tap
    engine.db.exec("INSERT INTO trust(kind, value, label, created) VALUES('email','anna@example.com','Anna','x')")
    waiting = send_copy(agent)
    seen = approval_hash(engine, waiting["approval_id"])
    clock.advance(25 * 3600)
    owner.cookies.clear()  # the session lapsed too: the service worker gets a 401 and opens the app instead
    assert from_push(owner, waiting["approval_id"], False).status_code == 401
    owner.cookies.set("doorman_owner", engine.auth.create_owner_session())  # logged in again
    expired = from_push(owner, waiting["approval_id"], True, seen)
    assert expired.status_code == 403 and expired.json()["code"] == "expired"
    again = from_push(owner, waiting["approval_id"], False)  # closed as expired by now
    assert again.status_code == 403 and again.json()["code"] == "expired"
    assert engine.journal.get(waiting["entry_id"])["status"] == "expired"


def test_removing_a_passkey_logs_its_device_out_and_stops_its_pushes(tap):
    """A lost phone: removing its passkey ends its sessions and drops its push subscription, so an approval
    push it already got can't be accepted from it either."""
    from fastapi.testclient import TestClient
    from doorman.api.owner import create_owner_app
    from soft_authenticator import SoftAuthenticator
    from test_api import OWNER_URL

    engine, owner, agent, _ = tap
    engine.db.exec("INSERT INTO trust(kind, value, label, created) VALUES('email','anna@example.com','Anna','x')")
    # a second device, added with a setup code, which turns notifications on
    lost = TestClient(create_owner_app(engine), base_url=OWNER_URL)
    passkey = SoftAuthenticator("localhost", OWNER_URL)
    options = lost.post("/owner/auth/register/options", json={"setup_code": engine.auth.create_setup_code()}).json()
    assert lost.post("/owner/auth/register/verify", json={"challenge_id": options["challenge_id"],
                     "credential": passkey.create(options["options"]), "label": "lost phone"}).status_code == 200
    phone, mine = Device("https://push.example.net/send/lost"), Device("https://push.example.net/send/mine")
    service = with_service(engine)
    assert lost.post("/owner/push/subscribe", headers=CSRF, json={"subscription": phone.subscription,
                                                                    "label": "lost"}).status_code == 200
    assert owner.post("/owner/push/subscribe", headers=CSRF, json={"subscription": mine.subscription,
                                                                     "label": "mine"}).status_code == 200
    wait_for(lambda: len(service.requests) == 1)  # the lost phone heard about the new device
    waiting = send_copy(agent)
    wait_for(lambda: len(service.requests) == 3)  # both devices got the approval with Accept on it
    seen = approval_hash(engine, waiting["approval_id"])

    # a session from before sessions knew their passkey goes with any removal
    legacy = engine.auth.create_owner_session()
    engine.auth.mark_verified(owner.cookies.get("doorman_owner"))
    keys = owner.get("/owner/passkeys").json()["passkeys"]
    removed = owner.post("/owner/passkeys/remove", headers=CSRF,
                         json={"id": next(k["id"] for k in keys if k["label"] == "lost phone")})
    assert removed.status_code == 200 and removed.json()["signed_out"] is False
    assert removed.json()["sessions"] == 2 and removed.json()["push"] == 1

    assert lost.get("/owner/inbox").status_code == 401
    assert not engine.auth.check_owner_session(legacy)
    refused = from_push(lost, waiting["approval_id"], True, seen)  # Accept on the push it already has
    assert refused.status_code == 401
    assert engine.journal.get(waiting["entry_id"])["status"] == "waiting_approval"
    assert [s["label"] for s in owner.get("/owner/push").json()["subscriptions"]] == ["mine"]
    # the device that stays keeps working
    assert owner.get("/owner/inbox").status_code == 200
    assert from_push(owner, waiting["approval_id"], True, seen).status_code == 200


def test_a_session_ends_when_its_passkey_is_gone(tap):
    engine, owner, *_ = tap
    credential = engine.db.one("SELECT id FROM webauthn_credentials")["id"]
    token = engine.auth.create_owner_session(credential)
    assert engine.auth.check_owner_session(token)
    engine.db.exec("DELETE FROM webauthn_credentials WHERE id=?", (credential,))  # however it went
    assert not engine.auth.check_owner_session(token) and not engine.auth.verified_recently(token, 5)


def test_logout_all(tap, tmp_path, capsys):
    import yaml
    from doorman import admin

    engine, owner, *_ = tap
    owner.post("/owner/push/subscribe", headers=CSRF, json={"subscription": Device().subscription})
    config_path = tmp_path / "doorman.yaml"
    config_path.write_text(yaml.safe_dump({"data_dir": str(engine.config.data_dir)}))
    admin.main(["--config", str(config_path), "logout-all"])
    assert "ended 1 owner session(s) and dropped 1 push subscription(s)" in capsys.readouterr().out
    assert owner.get("/owner/inbox").status_code == 401
    assert engine.notifier.subscriptions() == []


# ---------------------------------------------------------------- a new device, and logging out

def login_with(engine, client=None):
    """A fresh login with the owner's passkey (on another device: a synced passkey), as `client`'s cookie."""
    from fastapi.testclient import TestClient
    from doorman.api.owner import create_owner_app
    from test_api import OWNER_URL

    client = client or TestClient(create_owner_app(engine), base_url=OWNER_URL)
    client.cookies.clear()
    credential = engine.db.one("SELECT id FROM webauthn_credentials")["id"]
    client.cookies.set("doorman_owner", engine.auth.create_owner_session(credential))
    return client


def subscribe(client, device, label):
    response = client.post("/owner/push/subscribe", headers=CSRF, json={"subscription": device.subscription, "label": label})
    assert response.status_code == 200, response.text
    return response.json()["id"]


def device_notices(engine):
    return [a["title"] for a in engine.attention_list() if a["kind"] == "push_device"]


def test_a_new_device_is_announced_on_the_others(tap):
    """Someone with the phone for a minute, or with a stolen cookie, could subscribe a browser of their own
    and read every approval from then on. So each new device shows up under Needs attention, with a push to
    the devices that were there already (not to itself), as a new passkey does."""
    engine, owner, *_ = tap
    service = with_service(engine)
    phone, laptop = Device("https://push.example.net/send/phone"), Device("https://push.example.net/send/laptop")
    subscribe(owner, phone, "Chrome on Android")
    assert device_notices(engine) == ["A new device gets Doorman's notifications: Chrome on Android"]
    [item] = [a for a in engine.attention_list() if a["kind"] == "push_device"]
    assert "Not you? Remove it under More → Notifications" in item["detail"] and item["url"].endswith("#/more")
    laptop_id = subscribe(login_with(engine), laptop, "Firefox on Linux")
    wait_for(lambda: len(service.requests) == 1)
    assert str(service.requests[0].url) == phone.subscription["endpoint"]
    assert phone.read(service.requests[0].content)["title"] == "A new device gets Doorman's notifications: Firefox on Linux"
    # the app subscribes again on every start: a device Doorman knows is no news
    subscribe(owner, phone, "Chrome on Android")
    assert len(device_notices(engine)) == 2
    # removing the device takes its notice out of Needs attention
    assert owner.delete(f"/owner/push/{laptop_id}", headers=CSRF).status_code == 200
    assert device_notices(engine) == ["A new device gets Doorman's notifications: Chrome on Android"]
    time.sleep(0.1)
    assert len(service.requests) == 1


def test_logging_out_drops_only_this_devices_subscription(tap):
    """Logging out on a device stops its pushes; another device with the same passkey keeps its own. A login
    that only ran out drops nothing (approvals depend on pushes), and a device that logs in again takes its
    subscription along to the new login."""
    engine, owner, *_ = tap
    with_service(engine)
    phone, laptop = Device("https://push.example.net/send/phone"), Device("https://push.example.net/send/laptop")
    subscribe(owner, phone, "phone")
    other = login_with(engine)
    subscribe(other, laptop, "laptop")
    clock.advance(13 * 3600)  # both logins ran out
    assert owner.get("/owner/inbox").status_code == 401
    assert [s["label"] for s in engine.notifier.subscriptions()] == ["phone", "laptop"]
    for client, device, label in ((login_with(engine, owner), phone, "phone"), (login_with(engine, other), laptop, "laptop")):
        subscribe(client, device, label)  # what the app does after each login
    assert len(device_notices(engine)) == 2  # known devices: no news
    assert other.post("/owner/auth/logout", headers=CSRF).json() == {"ok": True}
    assert [s["label"] for s in engine.notifier.subscriptions()] == ["phone"]
    assert owner.get("/owner/inbox").status_code == 200
    assert owner.post("/owner/auth/logout", headers=CSRF).json() == {"ok": True}
    assert engine.notifier.subscriptions() == []
    clock.reset()


def test_a_device_that_logs_out_and_in_again_is_no_new_device(tap):
    """Logging out drops the device's subscription and the app subscribes it again after the next login: the
    same browser, so no "new device" under Needs attention and no push to the others. Removing its passkey
    or logging out every device (a lost phone) forgets it, and then it is news again."""
    engine, owner, *_ = tap
    service = with_service(engine)
    phone, laptop = Device("https://push.example.net/send/phone"), Device("https://push.example.net/send/laptop")
    subscribe(owner, phone, "Chrome on Android")
    subscribe(login_with(engine), laptop, "Firefox on Linux")
    wait_for(lambda: len(service.requests) == 1)  # the phone heard about the laptop
    assert len(device_notices(engine)) == 2

    assert owner.post("/owner/auth/logout", headers=CSRF).json() == {"ok": True}
    assert [s["label"] for s in engine.notifier.subscriptions()] == ["Firefox on Linux"]
    remembered = engine.db.all("SELECT * FROM push_logged_out")
    assert len(remembered) == 1 and phone.subscription["endpoint"] not in str(remembered)  # not its address
    subscribe(login_with(engine, owner), phone, "Chrome on Android")  # what the app does after the login
    time.sleep(0.1)
    assert len(device_notices(engine)) == 2 and len(service.requests) == 1
    assert engine.db.all("SELECT * FROM push_logged_out") == []  # it's back: nothing left to remember

    # its passkey removed: what logged out with it is forgotten
    credential = engine.db.one("SELECT id FROM webauthn_credentials")["id"]
    assert owner.post("/owner/auth/logout", headers=CSRF).json() == {"ok": True}
    engine.auth.end_passkey_sessions(credential)
    clock.advance(60)  # a notice is per device row (its id and when it came); ids start over in an empty table
    subscribe(login_with(engine, owner), phone, "Chrome on Android")
    assert len(device_notices(engine)) == 3
    # every device logged out (doorman-admin logout-all): the same
    assert owner.post("/owner/auth/logout", headers=CSRF).json() == {"ok": True}
    engine.auth.logout_all()
    clock.advance(60)
    subscribe(login_with(engine, owner), phone, "Chrome on Android")
    assert len(device_notices(engine)) == 4
    clock.reset()


@pytest.fixture
def task_sends(tmp_path):
    """A task whose agent copies one note to several people. send(to, task) returns the approval id and
    the push it made: (title, message, kwargs of Notifier.push)."""
    engine = make_engine(tmp_path)
    pushed = []
    engine.notifier.push = lambda title, message, **kw: pushed.append((title, message, kw))
    engine.db.exec("INSERT INTO trust(kind, value, label, created) VALUES('email','anna@example.com','Anna','x')")
    agent = Agent(engine)
    task = engine.tasks.create("Tell the group the new time")
    note = agent.call("notes.create", {"title": "New time", "body": "Thursday 10:00"}, task_id=task)["result"]["id"]

    def send(to, task_id=task):
        out = agent.call("notes.send_copy", {"id": note, "to": to}, task_id=task_id)
        return out["approval_id"], pushed[-1]
    return engine, task, send, pushed


def test_sends_of_one_task_within_a_minute_share_one_push(task_sends):
    """"Tell my group the new time" makes one approval per person. The first push goes out at once (a
    single send isn't held back); the next ones replace it under the same tag, so the phone buzzes once,
    and the push says how many there are and opens the review screen instead of accepting in place."""
    engine, task, send, pushed = task_sends
    first, (title, _, kw) = send("anna@example.com")
    assert title == "Send to anna@example.com" and kw["extra"]["tag"] == f"approval-{first}"
    accept = "app" if engine.config["approval_passkey"] else "tap"
    assert kw["extra"]["approval"]["accept"] == accept  # alone, it's an ordinary push
    second, _ = send("ben@example.com")
    third, (title, message, kw) = send("carl@example.com")
    assert len(pushed) == 3
    assert title == f"3 sends from task {task}: 2 new recipients"
    assert kw["extra"]["tag"] == f"approval-{first}"  # replaces the first push: no second buzz
    assert kw["extra"]["approval"] == {"id": first, "ids": [first, second, third], "accept": "app"}
    assert urlparse(kw["url"]).fragment == f"/review/{first},{second},{third}"
    assert "ben@example.com" in message and "carl@example.com" in message and "Open Doorman" in message
    # a decided one leaves the group: the next push names only what still waits
    engine.approvals.decide(first, approve=False)
    fourth, (title, _, kw) = send("dana@example.com")
    assert title.startswith(f"3 sends from task {task}") and kw["extra"]["approval"]["ids"] == [second, third, fourth]
    assert kw["extra"]["tag"] == f"approval-{first}"


def test_a_minute_later_or_another_task_buzzes_anew(task_sends):
    engine, task, send, _ = task_sends
    send("anna@example.com")
    other = engine.tasks.create("Something else")
    elsewhere, (_, _, kw) = send("anna@example.com", task_id=other)
    assert kw["extra"]["tag"] == f"approval-{elsewhere}" and "ids" not in kw["extra"]["approval"]
    clock.advance(61)
    later, (title, _, kw) = send("anna@example.com")
    assert kw["extra"]["tag"] == f"approval-{later}" and title == "Send to anna@example.com"


def test_a_lone_send_left_in_its_group_gets_an_ordinary_push(task_sends):
    """Once the owner approved the first from its push, the second is alone again: a push of its own, with
    Accept in place where it may, under the group's tag (it replaces the "Approved" line)."""
    engine, _, send, _ = task_sends
    first, _ = send("anna@example.com")
    engine.approvals.decide(first, approve=True, seen_hash=approval_hash(engine, first))
    second, (title, _, kw) = send("anna@example.com")
    assert title == "Send to anna@example.com" and kw["extra"]["tag"] == f"approval-{first}"
    assert kw["extra"]["approval"]["id"] == second and "ids" not in kw["extra"]["approval"]


def test_a_grouped_push_accepts_all_in_place_when_each_send_could(task_sends):
    """Accept all approves from the push when each send in it could be accepted from a push of its own: the
    push carries every approval's payload hash, and each is decided and checked on its own. One warning
    among them (a new recipient) and the button is Review: no hashes, the review screen."""
    engine, _, send, _ = task_sends
    first, _ = send("anna@example.com")
    second, (title, _, kw) = send("anna@example.com")
    assert title.endswith("to anna@example.com") and title.startswith("2 sends from task")
    assert kw["extra"]["approval"] == {"id": first, "ids": [first, second], "accept": "tap",
                                       "hashes": [approval_hash(engine, first), approval_hash(engine, second)]}
    assert all(engine.approvals.accept_from_notification(i) for i in (first, second))
    third, (_, _, kw) = send("stranger@elsewhere.example")
    assert kw["extra"]["approval"] == {"id": first, "ids": [first, second, third], "accept": "app"}
    assert not engine.approvals.accept_from_notification(third)


def test_a_grouped_push_opens_the_app_when_approvals_take_the_passkey(task_sends):
    engine, _, send, _ = task_sends
    engine.config["approval_passkey"] = True
    send("anna@example.com")
    _, (_, _, kw) = send("anna@example.com")
    assert kw["extra"]["approval"]["accept"] == "app" and "hashes" not in kw["extra"]["approval"]


def changeset(agent, to=None):
    """A changeset with one note edit and, with `to`, a copy of the note sent there."""
    note = agent.post("/v1/tools/notes.create", json={"args": {"title": "Plan", "body": "Line 1"}}).json()["result"]["id"]
    actions = [{"tool": "notes.update", "args": {"id": note, "body": "Line 2"}}]
    if to:
        actions.append({"tool": "notes.send_copy", "args": {"id": note, "to": to}})
    return agent.post("/v1/changesets", json={"title": "Tidy the plan", "actions": actions}).json()["id"], note


def test_a_changeset_push_lists_its_changes_and_applies_from_its_button(tap):
    """Apply all on the push applies a changeset Doorman has no warning on, Deny rejects it; a second press
    (or one after the app decided) is told it's no longer open."""
    engine, owner, agent, _ = tap
    pushed = []
    engine.notifier.push = lambda title, message, **kw: pushed.append((title, message, kw))
    cs, note = changeset(agent)
    title, message, kw = pushed[-1]
    assert title == "Changeset to review: Tidy the plan" and message.startswith("1 change\n· ")
    assert kw["extra"] == {"ask": {"kind": "changeset", "id": cs, "accept": "tap"}}
    applied = owner.post(f"/owner/changesets/{cs}/apply", headers=CSRF, json={"via": "notification"})
    assert applied.status_code == 200 and applied.json()["status"] == "applied"
    assert [r["status"] for r in applied.json()["results"]] == ["done"]
    again = owner.post(f"/owner/changesets/{cs}/reject", headers=CSRF, json={"via": "notification"})
    assert again.status_code == 403 and again.json()["code"] == "changeset"
    assert owner.post(f"/owner/changesets/{cs}/reject", headers=CSRF, json={}).json() == {"ok": True}  # the app's
    other, _ = changeset(agent)
    assert owner.post(f"/owner/changesets/{other}/reject", headers=CSRF, json={"via": "notification"}).json() == {"ok": True}
    assert engine.changeset(other)["status"] == "rejected"


def test_apply_on_the_push_opens_the_app_for_a_warning_or_with_the_passkey(tap):
    engine, owner, agent, _ = tap
    pushed = []
    engine.notifier.push = lambda title, message, **kw: pushed.append(kw.get("extra"))
    cs, _ = changeset(agent, to="stranger@elsewhere.example")  # a new recipient: the changeset shows a warning
    assert engine.changeset(cs)["preview"][1]["warnings"]
    assert pushed[-1] == {"ask": {"kind": "changeset", "id": cs, "accept": "app"}}
    refused = owner.post(f"/owner/changesets/{cs}/apply", headers=CSRF, json={"via": "notification"})
    assert refused.status_code == 403 and refused.json()["code"] == "open_app"
    assert engine.changeset(cs)["status"] == "proposed"
    assert owner.post(f"/owner/changesets/{cs}/apply", headers=CSRF, json={}).status_code == 200  # in the app
    engine.config["approval_passkey"] = True
    clean, _ = changeset(agent)
    assert pushed[-1]["ask"]["accept"] == "app"
    refused = owner.post(f"/owner/changesets/{clean}/apply", headers=CSRF, json={"via": "notification"})
    assert refused.json()["code"] == "open_app" and engine.changeset(clean)["status"] == "proposed"
