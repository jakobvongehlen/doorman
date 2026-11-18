import json
import threading

import pytest
from fastapi.testclient import TestClient

from doorman.api.agent import create_agent_app
from doorman.api.owner import create_owner_app
from conftest import make_engine, put_plugins
from soft_authenticator import SoftAuthenticator

OWNER_URL = "http://localhost:8711"
CSRF = {"X-Requested-With": "doorman"}


@pytest.fixture(params=[False, True], ids=["tap", "passkey"])
def setup(tmp_path, request):
    """Runs each test twice: approvals as a tap (the default) and signed with the passkey."""
    engine = make_engine(tmp_path, public_url=OWNER_URL, approval_passkey=request.param)
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL)
    token = engine.auth.create_key("claude", "solo")
    agent = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})
    passkey = SoftAuthenticator("localhost", OWNER_URL)
    return engine, owner, agent, passkey


def register(engine, owner, passkey):
    code = engine.auth.create_setup_code()
    options = owner.post("/owner/auth/register/options", json={"setup_code": code}).json()
    response = owner.post("/owner/auth/register/verify", json={
        "challenge_id": options["challenge_id"], "credential": passkey.create(options["options"]),
        "label": "test phone"})
    assert response.status_code == 200, response.text


def approve(owner, passkey, approval_id):
    if owner.get("/owner/settings").json()["approval_passkey"] is False:
        seen = owner.get(f"/owner/approvals/{approval_id}").json()["payload_hash"]
        return owner.post(f"/owner/approvals/{approval_id}/decide", headers=CSRF,
                          json={"approve": True, "payload_hash": seen})
    options = owner.post(f"/owner/approvals/{approval_id}/options", headers=CSRF).json()
    return owner.post(f"/owner/approvals/{approval_id}/decide", headers=CSRF, json={
        "approve": True, "challenge_id": options["challenge_id"], "credential": passkey.get(options["options"])})


def test_owner_needs_login_and_setup_code(setup):
    engine, owner, _, passkey = setup
    assert owner.get("/owner/inbox").status_code == 401
    bad = owner.post("/owner/auth/register/options", json={"setup_code": "nope"})
    assert bad.status_code == 403
    register(engine, owner, passkey)
    assert owner.get("/owner/auth/status").json() == {
        "logged_in": True, "sign_in": "passkey", "has_passkey": True,
        "approval_passkey": engine.config["approval_passkey"]}
    # the setup code is single-use, and a second passkey needs a logged-in owner or a new setup code
    owner.cookies.clear()
    assert owner.post("/owner/auth/register/options", json={}).status_code == 401
    assert owner.post("/owner/auth/register/options", json={"setup_code": "x"}).status_code == 403


def test_adding_a_passkey_while_logged_in_needs_a_fresh_check_and_is_announced(setup):
    """A phone left unlocked for a minute, or a stolen session cookie, isn't enough to add a passkey (lasting
    access to approvals and plugins): that takes a passkey check, and the owner hears about every new one."""
    engine, owner, _, passkey = setup
    register(engine, owner, passkey)
    from doorman import clock
    clock.advance(6 * 60)
    stale = owner.post("/owner/auth/register/options", headers=CSRF, json={})
    assert stale.status_code == 403 and stale.json()["code"] == "reauth"
    options = owner.post("/owner/auth/reauth/options", headers=CSRF).json()
    owner.post("/owner/auth/reauth/verify", headers=CSRF, json={
        "challenge_id": options["challenge_id"], "credential": passkey.get(options["options"])})
    laptop = SoftAuthenticator("localhost", OWNER_URL)
    options = owner.post("/owner/auth/register/options", headers=CSRF, json={}).json()
    done = owner.post("/owner/auth/register/verify", json={
        "challenge_id": options["challenge_id"], "credential": laptop.create(options["options"]), "label": "laptop"})
    assert done.status_code == 200
    [item] = [a for a in engine.attention_list() if a["kind"] == "passkey"]
    assert item["title"] == "New passkey added: laptop"
    clock.reset()


def test_a_setup_code_adds_a_passkey_when_none_works_here(setup):
    """A new phone, or a new address (a passkey works only on the domain it was made on): a setup code from
    the host adds one, and the owner hears about it."""
    engine, owner, _, passkey = setup
    register(engine, owner, passkey)
    owner.cookies.clear()
    phone = SoftAuthenticator("localhost", OWNER_URL)
    code = engine.auth.create_setup_code()
    options = owner.post("/owner/auth/register/options", json={"setup_code": code}).json()
    done = owner.post("/owner/auth/register/verify", json={
        "challenge_id": options["challenge_id"], "credential": phone.create(options["options"]), "label": "new phone"})
    assert done.status_code == 200 and owner.get("/owner/auth/status").json()["logged_in"]
    [item] = [a for a in engine.attention_list() if a["kind"] == "passkey"]
    assert "new phone" in item["title"]
    keys = owner.get("/owner/passkeys").json()["passkeys"]
    assert [k["label"] for k in keys] == ["test phone", "new phone"]
    # removing one takes a fresh passkey check, and never the last one
    engine.auth.mark_verified(owner.cookies.get("doorman_owner"))
    assert owner.post("/owner/passkeys/remove", headers=CSRF, json={"id": keys[0]["id"]}).status_code == 200
    last = owner.post("/owner/passkeys/remove", headers=CSRF, json={"id": keys[1]["id"]})
    assert last.status_code == 403 and last.json()["code"] == "last_passkey"


def test_passkey_login(setup):
    engine, owner, _, passkey = setup
    register(engine, owner, passkey)
    owner.cookies.clear()
    options = owner.post("/owner/auth/login/options").json()
    response = owner.post("/owner/auth/login/verify", json={
        "challenge_id": options["challenge_id"], "credential": passkey.get(options["options"])})
    assert response.status_code == 200
    assert owner.get("/owner/inbox").status_code == 200


def test_wrong_passkey_is_rejected(setup):
    engine, owner, _, passkey = setup
    register(engine, owner, passkey)
    owner.cookies.clear()
    impostor = SoftAuthenticator("localhost", OWNER_URL)
    impostor.credential_id = passkey.credential_id
    options = owner.post("/owner/auth/login/options").json()
    response = owner.post("/owner/auth/login/verify", json={
        "challenge_id": options["challenge_id"], "credential": impostor.get(options["options"])})
    assert response.status_code == 403


def test_csrf_header_required(setup):
    engine, owner, _, passkey = setup
    register(engine, owner, passkey)
    assert owner.post("/owner/kill").status_code == 403
    assert owner.post("/owner/kill", headers=CSRF).status_code == 200


def test_full_flow_agent_to_signed_approval(setup):
    engine, owner, agent, passkey = setup
    register(engine, owner, passkey)

    caps = agent.get("/v1/capabilities").json()
    assert caps["role"] == "solo"
    assert [t["name"] for t in caps["plugins"][0]["tools"]] == \
        ["notes.create", "notes.update", "notes.delete", "notes.send_copy"]

    created = agent.post("/v1/tools/notes.create", json={"args": {"title": "Gym", "body": "Thu"}}).json()
    assert created["status"] == "done"
    note_id = created["result"]["id"]
    assert agent.post("/v1/read/notes.list", json={}).json()["data"][0]["id"] == note_id

    sent = agent.post("/v1/tools/notes.send_copy", json={"args": {"id": note_id, "to": "x@elsewhere.example"}})
    body = sent.json()
    assert body["status"] == "waiting_approval"

    inbox = owner.get("/owner/inbox").json()
    assert inbox["approvals"][0]["id"] == body["approval_id"]
    assert inbox["approvals"][0]["entries"][0]["untrusted_destinations"][0]["value"] == "x@elsewhere.example"

    decided = approve(owner, passkey, body["approval_id"])
    assert decided.status_code == 200, decided.text
    assert decided.json()["results"][0]["status"] == "done"
    status = agent.get(f"/v1/journal/{body['entry_id']}").json()
    assert status["status"] == "done"


def test_signature_for_one_approval_cannot_approve_another(setup):
    engine, owner, agent, passkey = setup
    if not engine.config["approval_passkey"]:
        pytest.skip("passkey-signed approvals only")
    register(engine, owner, passkey)
    note_id = agent.post("/v1/tools/notes.create", json={"args": {"title": "a"}}).json()["result"]["id"]
    first = agent.post("/v1/tools/notes.send_copy", json={"args": {"id": note_id, "to": "a@x.example"}}).json()
    second = agent.post("/v1/tools/notes.send_copy", json={"args": {"id": note_id, "to": "b@x.example"}}).json()
    options = owner.post(f"/owner/approvals/{first['approval_id']}/options", headers=CSRF).json()
    signed = passkey.get(options["options"])
    response = owner.post(f"/owner/approvals/{second['approval_id']}/decide", headers=CSRF, json={
        "approve": True, "challenge_id": options["challenge_id"], "credential": signed})
    assert response.status_code == 403
    assert engine.journal.get(second["entry_id"])["status"] == "waiting_approval"


def test_owner_journal_revert_and_plugin_switch(setup):
    engine, owner, agent, passkey = setup
    register(engine, owner, passkey)
    created = agent.post("/v1/tools/notes.create", json={"args": {"title": "Gym"}}).json()
    entries = owner.get("/owner/journal").json()["entries"]
    assert entries[0]["revertable"] and entries[0]["diff"]
    preview = owner.post("/owner/revert", headers=CSRF, json={"since": "2000-01-01", "preview": True}).json()
    assert preview["will_revert"] == [created["entry_id"]]
    reverted = owner.post(f"/owner/journal/{created['entry_id']}/revert", headers=CSRF, json={}).json()
    assert reverted["reverted"] == [created["entry_id"]]

    owner.post("/owner/plugins/notes", headers=CSRF, json={"tool": "notes.send_copy", "tool_enabled": False})
    tools = agent.get("/v1/capabilities").json()["plugins"][0]["tools"]
    assert "notes.send_copy" not in [t["name"] for t in tools]
    denied = agent.post("/v1/tools/notes.send_copy", json={"args": {"id": "a", "to": "b@c.example"}})
    assert denied.status_code == 403 and denied.json()["code"] == "tool_disabled"


def test_agent_tasks_and_reports(setup):
    engine, owner, agent, passkey = setup
    register(engine, owner, passkey)
    owner.post("/owner/tasks", headers=CSRF, json={"text": "Tidy my notes"})
    assert agent.get("/v1/tasks").json()["tasks"][0]["text"] == "Tidy my notes"
    claimed = agent.post("/v1/tasks/claim", json={}).json()
    session = claimed["session"]
    agent.post("/v1/tools/notes.create", json={"args": {"title": "x"}}, headers={"X-Doorman-Session": session})
    report = agent.post(f"/v1/tasks/{claimed['task']['id']}/report", headers={"X-Doorman-Session": session},
                        json={"status": "done", "summary": "Created one note"})
    assert report.status_code == 200
    task = owner.get("/owner/tasks").json()["tasks"][0]
    assert task["status"] == "done" and task["report"] == "Created one note"
    entries = owner.get(f"/owner/journal?task_id={task['id']}").json()["entries"]
    assert len(entries) == 1


def test_an_agent_undoes_its_own_changes_and_only_those(tmp_path):
    engine = make_engine(tmp_path)
    token = engine.auth.create_key("claude", "solo")
    agent = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})
    other = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {engine.auth.create_key('x', 'solo')}"})
    notes = engine.registry.instance("notes")
    made = agent.post("/v1/tools/notes.create", json={"args": {"title": "Gym", "body": "Thu"}}).json()
    note_id = made["result"]["id"]
    moved = agent.post("/v1/tools/notes.update", json={"args": {"id": note_id, "body": "Fri"}}).json()

    out = agent.post(f"/v1/journal/{moved['entry_id']}/undo").json()
    assert out["status"] == "done" and out["reverted"][0]["entry_id"] == moved["entry_id"]
    assert notes.load(note_id)["body"] == "Thu"
    # the revert is the agent's own journaled change, and can be undone in turn
    revert_id = out["reverted"][0]["revert_id"]
    entries = {e["id"]: e for e in agent.get("/v1/journal").json()["entries"]}
    assert entries[revert_id]["kind"] == "revert" and entries[revert_id]["undo"] == f"doorman undo {revert_id}"
    assert entries[moved["entry_id"]]["status"] == "reverted" and "undo" not in entries[moved["entry_id"]]
    assert agent.post(f"/v1/journal/{revert_id}/undo").json()["status"] == "done"
    assert notes.load(note_id)["body"] == "Fri"
    again = agent.post(f"/v1/journal/{revert_id}/undo").json()
    assert again["code"] == "already_undone"
    # no "the owner undid it" event for what the agent undid itself
    assert engine.db.all("SELECT id FROM events WHERE type='entry_reverted'") == []

    # another key's change, a send and the owner's own revert stay the owner's
    refused = other.post(f"/v1/journal/{made['entry_id']}/undo")
    assert refused.status_code == 403 and refused.json()["code"] == "not_yours"
    sent = agent.post("/v1/tools/notes.send_copy", json={"args": {"id": note_id, "to": "x@elsewhere.example"}}).json()
    waiting = agent.post(f"/v1/journal/{sent['entry_id']}/undo").json()
    assert waiting["code"] == "irreversible" and "nothing has gone out" in waiting["reason"]
    engine.approvals.decide(sent["approval_id"], True)
    send = agent.post(f"/v1/journal/{sent['entry_id']}/undo").json()
    assert send["code"] == "irreversible" and "can't be undone" in send["reason"]
    assert agent.get(f"/v1/journal/{sent['entry_id']}").json()["undo"].startswith("can't")
    by_owner = engine.revert_entry(made["entry_id"])["reverted"]
    assert made["entry_id"] in by_owner
    owners = engine.journal.get(made["entry_id"])["reverted_by"]
    assert agent.post(f"/v1/journal/{owners}/undo").json()["code"] == "not_yours"


def test_the_inbox_says_what_a_new_owner_hasnt_done_yet(tmp_path, monkeypatch):
    """The Inbox's Get started card: there until the first agent key is made. The notes and the file archive a
    new Doorman starts with are no account."""
    from doorman.registry import STARTER_PLUGINS
    engine = make_engine(tmp_path, public_url=OWNER_URL)
    monkeypatch.setattr(engine.registry, "starter", STARTER_PLUGINS)
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL)
    register(engine, owner, SoftAuthenticator("localhost", OWNER_URL))
    first_steps = lambda: owner.get("/owner/inbox").json()["first_steps"]  # noqa: E731
    assert first_steps() == {"plugin": False}
    put_plugins(engine, {"cal": {"type": "caldav", "config": {}}})
    assert first_steps() == {"plugin": True}
    made = owner.post("/owner/keys", headers=CSRF, json={"name": "claude", "role": "solo"}).json()
    assert first_steps() is None
    owner.post(f"/owner/keys/{made['key']['id']}/revoke", headers=CSRF)
    assert first_steps() is None   # they know the way by now


def test_an_agent_asks_the_owner_and_hears_the_answer(setup):
    from doorman import clock
    engine, owner, agent, passkey = setup
    register(engine, owner, passkey)
    asked = agent.post("/v1/owner-questions", json={"question": "Group meeting: Tue 14:00 or Wed 10:00?",
                                                    "options": ["Tue 14:00", "Wed 10:00"]}).json()["owner_question"]
    assert asked["status"] == "open" and asked["options"] == ["Tue 14:00", "Wed 10:00"]
    # in the owner's inbox, with a push that opens it; the agent's text is marked as the agent's
    [shown] = owner.get("/owner/inbox").json()["questions"]
    assert shown["question"] == asked["question"] and shown["agent"] == "claude" and shown["task"] is None
    note = engine.db.one("SELECT * FROM notifications ORDER BY id DESC LIMIT 1")
    assert note["title"] == "claude asks" and note["url"].endswith(f"#/inbox/question/{asked['id']}")
    waiting = agent.get("/v1/wait", params={"for": f"owner-question:{asked['id']}"}).json()
    assert waiting["done"] is False and waiting["outcome"] == "open"

    # a logged-in tap answers, like Deny: no fresh passkey check (owner_questions.py says why)
    clock.advance(10 * 60)
    assert owner.post(f"/owner/questions/{asked['id']}/answer", headers=CSRF, json={"option": 1}).status_code == 200
    assert engine.journal.list(limit=1)[0]["tool"] == "owner_question.answer"
    done = agent.get("/v1/wait", params={"for": f"owner-question:{asked['id']}"}).json()
    assert done["outcome"] == "answered" and done["owner_question"]["answer"] == "Wed 10:00"
    assert "spotlight" not in done  # the owner's own words: not third-party content
    [event] = [e for e in agent.get("/v1/events").json()["doorman"] if e["type"] == "owner_answered"]
    assert event["answer"] == "Wed 10:00" and event["question_id"] == asked["id"]
    assert owner.get("/owner/inbox").json()["questions"] == []
    again = owner.post(f"/owner/questions/{asked['id']}/answer", headers=CSRF, json={"answer": "Tue"})
    assert again.status_code == 403 and again.json()["code"] == "invalid"

    # dismissed: the agent hears `declined`; unanswered for a day: `expired`
    second = agent.post("/v1/owner-questions", json={"question": "Is the 16:00 entry the dentist?"}).json()
    owner.post(f"/owner/questions/{second['owner_question']['id']}/dismiss", headers=CSRF)
    assert agent.get("/v1/wait", params={"for": f"owner-question:{second['owner_question']['id']}"}).json()[
        "outcome"] == "declined"
    third = agent.post("/v1/owner-questions", json={"question": "Still want the oat milk?"}).json()["owner_question"]
    clock.advance(25 * 3600)
    engine.owner_questions.sweep(force=True)
    assert agent.get(f"/v1/owner-questions/{third['id']}").json()["owner_question"]["status"] == "expired"
    clock.reset()
    # a few open at a time; a reader key answers questions, it doesn't ask the owner
    for n in range(5):
        agent.post("/v1/owner-questions", json={"question": f"Question {n}?"})
    assert agent.post("/v1/owner-questions", json={"question": "One more?"}).json()["code"] == "too_many"
    reader = TestClient(create_agent_app(engine),
                        headers={"Authorization": f"Bearer {engine.auth.create_key('reader', 'reader')}"})
    assert reader.post("/v1/owner-questions", json={"question": "Hello?"}).json()["code"] == "role"
    assert agent.get("/v1/owner-questions").json()["owner_questions"][0]["question"] == "Question 4?"


def test_an_agent_undoes_a_whole_task(tmp_path):
    engine = make_engine(tmp_path)
    token = engine.auth.create_key("claude", "solo")
    agent = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})
    task_id = engine.tasks.create("Two notes")
    session = {"X-Doorman-Session": agent.post("/v1/tasks/claim", json={}).json()["session"]}
    for title in ("A", "B"):
        agent.post("/v1/tools/notes.create", json={"args": {"title": title}}, headers=session)
    out = agent.post("/v1/undo", json={"task_id": task_id}, headers=session).json()
    assert out["status"] == "done" and len(out["reverted"]) == 2
    # each says what it put back, in a line the agent can pass on
    assert [r["undone"] for r in out["reverted"]] == ["Created note “B”: undone, removed again",
                                                       "Created note “A”: undone, removed again"]
    assert engine.registry.instance("notes").read_list({}) == []
    assert agent.post("/v1/undo", json={"task_id": task_id}, headers=session).json()["code"] == "not_found"


def test_a_report_after_the_lease_ran_out_is_kept(tmp_path):
    from doorman import clock
    engine = make_engine(tmp_path)
    token = engine.auth.create_key("claude", "solo")
    agent = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})
    task_id = engine.tasks.create("Tidy my notes")
    session = {"X-Doorman-Session": agent.post("/v1/tasks/claim", json={}).json()["session"]}
    clock.advance(31 * 60)
    assert engine.tasks.expire_leases() == [task_id]
    out = agent.post(f"/v1/tasks/{task_id}/report", headers=session,
                     json={"status": "done", "summary": "Tidied 4 notes"}).json()
    assert out["late"] is True and out["task_status"] == "failed"
    task = engine.tasks.get(task_id)
    assert task["status"] == "failed" and "Tidied 4 notes" in task["report"] and "No report within" in task["report"]
    twice = agent.post(f"/v1/tasks/{task_id}/report", headers=session, json={"status": "done", "summary": "x"})
    assert twice.json()["code"] == "task_closed"
    stranger = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {engine.auth.create_key('y', 'solo')}"})
    assert stranger.post(f"/v1/tasks/{task_id}/report", json={"status": "done", "summary": "x"}).json()["code"] == "session"


def test_bad_agent_key(setup):
    engine, _, _, _ = setup
    stranger = TestClient(create_agent_app(engine), headers={"Authorization": "Bearer dmn_nope"})
    assert stranger.get("/v1/capabilities").status_code == 401


# ---------------------------------------------------------------- tap approvals


@pytest.fixture
def tap(tmp_path):
    engine = make_engine(tmp_path, public_url=OWNER_URL)
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL)
    token = engine.auth.create_key("claude", "solo")
    agent = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})
    passkey = SoftAuthenticator("localhost", OWNER_URL)
    register(engine, owner, passkey)
    engine._test_passkey = passkey
    note_id = agent.post("/v1/tools/notes.create", json={"args": {"title": "a"}}).json()["result"]["id"]
    return engine, owner, agent, note_id


def test_tap_is_the_default_and_needs_no_passkey(tap):
    engine, owner, agent, note_id = tap
    assert engine.config["approval_passkey"] is False
    sent = agent.post("/v1/tools/notes.send_copy", json={"args": {"id": note_id, "to": "a@x.example"}}).json()
    approval = owner.get(f"/owner/approvals/{sent['approval_id']}").json()
    # the passkey route is closed when approvals are taps
    assert owner.post(f"/owner/approvals/{sent['approval_id']}/options", headers=CSRF).status_code == 403
    decided = owner.post(f"/owner/approvals/{sent['approval_id']}/decide", headers=CSRF,
                         json={"approve": True, "payload_hash": approval["payload_hash"]})
    assert decided.status_code == 200, decided.text
    assert decided.json()["results"][0]["status"] == "done"
    row = engine.db.one("SELECT method, credential_id FROM approvals WHERE id=?", (sent["approval_id"],))
    assert row == {"method": "tap", "credential_id": None}


def test_a_slow_send_answers_sending_and_the_app_follows_it(tap, monkeypatch):
    """Approve returns after send_wait_seconds with "sending"; the results route holds on until the send
    ended, and the agent's doorman wait goes through `approved`/`sending` to `sent`."""
    engine, owner, agent, note_id = tap
    engine.config["send_wait_seconds"] = 0.2
    kind = type(engine.registry.instance("notes").tools["send_copy"])
    real, go = kind.execute, threading.Event()
    monkeypatch.setattr(kind, "execute", lambda self, args, before: (go.wait(10), real(self, args, before))[1])
    sent = agent.post("/v1/tools/notes.send_copy", json={"args": {"id": note_id, "to": "a@x.example"}}).json()
    seen = owner.get(f"/owner/approvals/{sent['approval_id']}").json()["payload_hash"]
    decided = owner.post(f"/owner/approvals/{sent['approval_id']}/decide", headers=CSRF,
                         json={"approve": True, "payload_hash": seen}).json()
    assert decided["sending"] and decided["results"][0]["status"] == "sending", decided
    url = f"/owner/approvals/{sent['approval_id']}/results"
    assert owner.get(url).json()["done"] is False
    waiting = agent.get(f"/v1/wait?for=entry:{sent['entry_id']}").json()
    assert waiting["done"] is False and waiting["outcome"] in ("approved", "sending")
    threading.Timer(0.3, go.set).start()
    out = owner.get(f"{url}?wait=10").json()  # wakes when the send ended, not after 10 s
    assert out["done"] and out["results"][0]["status"] == "done", out
    assert agent.get(f"/v1/wait?for=entry:{sent['entry_id']}").json()["outcome"] == "sent"
    assert owner.get("/owner/approvals/999/results").json()["code"] == "not_found"


def test_ask_the_agent_again_from_the_app(tap):
    """The expired approval's screen offers "Ask the agent again": the agent finds approval_ask_again in its
    feed, and the screen then says it was asked."""
    engine, owner, agent, note_id = tap
    sent = agent.post("/v1/tools/notes.send_copy", json={"args": {"id": note_id, "to": "a@x.example"}}).json()
    url = f"/owner/approvals/{sent['approval_id']}/ask-again"
    early = owner.post(url, headers=CSRF)
    assert early.status_code == 403 and early.json()["code"] == "invalid"  # still waiting: decide it
    # a day passes (moving the clock would end the owner's login too)
    engine.db.exec("UPDATE approvals SET expires='2000-01-01T00:00:00+00:00' WHERE id=?", (sent["approval_id"],))
    engine.approvals.expire()
    assert owner.post(url).status_code == 403  # the CSRF header, as for every owner write
    asked = owner.post(url, headers=CSRF)
    assert asked.status_code == 200, asked.text
    shown = owner.get(f"/owner/approvals/{sent['approval_id']}").json()
    assert shown["status"] == "expired" and shown["asked_again"] == asked.json()["asked"]
    events = agent.get("/v1/events").json()["doorman"]
    assert [e["type"] for e in events][-2:] == ["approval_expired", "approval_ask_again"]
    assert events[-1]["entry_ids"] == [sent["entry_id"]]


def test_tap_needs_the_hash_of_what_was_shown(tap):
    engine, owner, agent, note_id = tap
    first = agent.post("/v1/tools/notes.send_copy", json={"args": {"id": note_id, "to": "a@x.example"}}).json()
    second = agent.post("/v1/tools/notes.send_copy", json={"args": {"id": note_id, "to": "b@x.example"}}).json()
    first_hash = owner.get(f"/owner/approvals/{first['approval_id']}").json()["payload_hash"]
    url = f"/owner/approvals/{second['approval_id']}/decide"
    missing = owner.post(url, headers=CSRF, json={"approve": True})
    assert missing.status_code == 403 and missing.json()["code"] == "invalid"
    # the hash of another approval (what another screen showed) doesn't approve this one
    wrong = owner.post(url, headers=CSRF, json={"approve": True, "payload_hash": first_hash})
    assert wrong.status_code == 403 and wrong.json()["code"] == "payload_changed"
    assert engine.journal.get(second["entry_id"])["status"] == "waiting_approval"


def test_tap_needs_a_logged_in_owner_and_the_csrf_header(tap):
    engine, owner, agent, note_id = tap
    sent = agent.post("/v1/tools/notes.send_copy", json={"args": {"id": note_id, "to": "a@x.example"}}).json()
    seen = owner.get(f"/owner/approvals/{sent['approval_id']}").json()["payload_hash"]
    url = f"/owner/approvals/{sent['approval_id']}/decide"
    assert owner.post(url, json={"approve": True, "payload_hash": seen}).status_code == 403  # no CSRF header
    owner.cookies.clear()
    assert owner.post(url, headers=CSRF, json={"approve": True, "payload_hash": seen}).status_code == 401
    assert engine.journal.get(sent["entry_id"])["status"] == "waiting_approval"


def test_tap_after_the_payload_changed_is_refused(tap):
    engine, owner, agent, note_id = tap
    sent = agent.post("/v1/tools/notes.send_copy", json={"args": {"id": note_id, "to": "a@x.example"}}).json()
    seen = owner.get(f"/owner/approvals/{sent['approval_id']}").json()["payload_hash"]
    entry = engine.journal.get(sent["entry_id"])
    engine.db.exec("UPDATE journal SET args=? WHERE id=?",
                   ('{"id": "%s", "to": "evil@x.example"}' % note_id, entry["id"]))
    response = owner.post(f"/owner/approvals/{sent['approval_id']}/decide", headers=CSRF,
                          json={"approve": True, "payload_hash": seen})
    assert response.status_code == 403 and response.json()["code"] == "payload_changed"
    assert engine.journal.get(sent["entry_id"])["status"] != "done"


def test_inbox_lists_needs_attention_and_dismiss(tap):
    engine, owner, agent, note_id = tap
    engine.attention("plugin", "mail", "mail isn't working", "IMAP login failed")
    items = owner.get("/owner/inbox").json()["attention"]
    assert [i["title"] for i in items] == ["mail isn't working"]
    assert owner.post(f"/owner/attention/{items[0]['id']}/dismiss", headers=CSRF).status_code == 200
    assert owner.get("/owner/inbox").json()["attention"] == []
    assert owner.post(f"/owner/attention/{items[0]['id']}/dismiss", headers=CSRF).json()["code"] == "not_found"


def test_plugins_tab_lists_types_not_set_up(tap):
    engine, owner, agent, note_id = tap
    data = owner.get("/owner/plugins").json()
    assert [p["name"] for p in data["plugins"]] == ["notes"]
    available = {t["type"]: t for t in data["available"]}
    assert available["notes"]["in_use"] and not available["caldav"]["in_use"]
    assert {"caldav", "google_calendar", "mail_imap", "mail_outlook", "files", "whatsapp", "teams", "ics"} \
        <= set(available)
    assert available["caldav"]["credentials"] == ["username", "password"]
    assert available["google_calendar"]["login"] == "oauth" and "client_id" in available["google_calendar"]["config"]


# ---------------------------------------------------------------- plugins set up in the app


def test_adding_a_plugin_needs_a_fresh_passkey_check(tap):
    engine, owner, agent, note_id = tap
    from doorman import clock
    clock.advance(6 * 60)  # logged in, but the passkey check is older than 5 minutes
    body = {"name": "notes2", "type": "notes"}
    stale = owner.post("/owner/instances", headers=CSRF, json=body)
    assert stale.status_code == 403 and stale.json()["code"] == "reauth"
    passkey = engine._test_passkey
    options = owner.post("/owner/auth/reauth/options", headers=CSRF).json()
    owner.post("/owner/auth/reauth/verify", headers=CSRF, json={
        "challenge_id": options["challenge_id"], "credential": passkey.get(options["options"])})
    assert owner.post("/owner/instances", headers=CSRF, json=body).status_code == 200


def test_add_configure_and_use_a_plugin_from_the_app(tap):
    engine, owner, agent, note_id = tap
    added = owner.post("/owner/instances", headers=CSRF, json={
        "name": "uni", "type": "nextcloud_notes", "no_approval": True,
        "config": {"url": "https://cloud.example.com", "trash_category": ""},
        "credentials": {"username": "", "password": "s3cret-pw"}})
    assert added.status_code == 200, added.text
    plugins = {p["name"]: p for p in owner.get("/owner/plugins").json()["plugins"]}
    uni = plugins["uni"]
    assert uni["enabled"] and uni["no_approval"]
    assert uni["config"] == {"url": "https://cloud.example.com"}  # empty fields are left out
    assert uni["credentials_set"] == ["password"] and uni["missing_credentials"] == ["username"]
    assert engine.vault.get("uni")["password"] == "s3cret-pw"
    # the secret is in the vault only: not in the API's answers, not in the database
    assert "s3cret-pw" not in owner.get("/owner/plugins").text
    assert "s3cret-pw" not in owner.get("/owner/journal?include_denied=true").text
    assert b"s3cret-pw" not in (engine.config.data_dir / "doorman.db").read_bytes()
    # the agent sees it right away, no restart
    caps = agent.get("/v1/capabilities").json()
    assert "uni" in [p["name"] for p in caps["plugins"]]

    changed = owner.post("/owner/instances/uni/config", headers=CSRF, json={
        "config": {"url": "https://cloud.example.com", "trash_category": "Bin"}, "no_approval": False})
    assert changed.status_code == 200
    reverted = owner.post(f"/owner/journal/{changed.json()['entry_id']}/revert", headers=CSRF, json={}).json()
    assert reverted["reverted"]
    uni = {p["name"]: p for p in owner.get("/owner/plugins").json()["plugins"]}["uni"]
    assert uni["no_approval"] and "trash_category" not in uni["config"]


def test_config_values_typed_as_lists_and_booleans(tap):
    engine, owner, agent, note_id = tap
    owner.post("/owner/instances", headers=CSRF, json={
        "name": "cal", "type": "caldav", "config": {"url": "https://dav.example/", "calendars": "[Personal, Work]",
                                                     "allow_http": "false"}})
    block = engine.registry.configured()["cal"]
    assert block["config"]["calendars"] == ["Personal", "Work"] and block["config"]["allow_http"] is False
    bad = owner.post("/owner/instances/cal/config", headers=CSRF, json={"config": {"calendars": "[unclosed"}})
    assert bad.json()["code"] == "invalid"


def test_reverting_an_add_removes_the_plugin_and_its_secrets(tap):
    engine, owner, agent, note_id = tap
    added = owner.post("/owner/instances", headers=CSRF, json={
        "name": "work", "type": "mail_imap", "credentials": {"password": "pw"}}).json()
    owner.post(f"/owner/journal/{added['entry_id']}/revert", headers=CSRF, json={})
    assert "work" not in engine.registry.configured() and engine.vault.get("work") == {}


def test_remove_and_credentials(tap):
    engine, owner, agent, note_id = tap
    owner.post("/owner/instances", headers=CSRF, json={"name": "notes2", "type": "notes",
                                                       "credentials": {"token": "x"}})
    assert owner.post("/owner/instances/notes2/remove", headers=CSRF).status_code == 200
    assert "notes2" not in engine.registry.configured() and engine.vault.get("notes2") == {}
    assert owner.post("/owner/instances/notes/credentials", headers=CSRF,
                      json={"key": "api_key", "value": "k"}).status_code == 200
    assert engine.vault.get("notes") == {"api_key": "k"}
    entry = engine.journal.list(limit=1, include_denied=True)[0]
    assert entry["summary"] == "Set notes credential api_key" and "k" not in str(entry["args"].get("value", ""))


def test_every_plugin_is_set_up_in_the_app(tap):
    """No plugin is read-only on the card: the ones a test's engine (or an older doorman.yaml) brought in are
    changed and removed like the ones added here."""
    engine, owner, agent, note_id = tap
    card = next(p for p in owner.get("/owner/plugins").json()["plugins"] if p["name"] == "notes")
    assert "source" not in card and "yaml_only" not in card
    assert owner.post("/owner/instances/notes/config", headers=CSRF,
                      json={"config": {"color": "blue"}}).status_code == 200
    assert engine.registry.configured()["notes"]["config"] == {"color": "blue"}
    assert owner.post("/owner/instances/notes/remove", headers=CSRF).status_code == 200
    assert "notes" not in engine.registry.configured()
    assert owner.post("/owner/instances/notes/take-over", headers=CSRF).status_code in (404, 405)


def test_bad_names_types_and_clashes(tap):
    engine, owner, agent, note_id = tap
    for body in ({"name": "Bad Name", "type": "notes"}, {"name": "notes", "type": "notes"},
                 {"name": "x", "type": "nope"}, {"name": "y", "type": "notes", "config": {"Bad": 1}}):
        assert owner.post("/owner/instances", headers=CSRF, json=body).json()["code"] == "invalid", body


# ---------------------------------------------------------------- agent keys from the app


def test_agent_keys_from_the_app(tap):
    engine, owner, agent, note_id = tap
    listed = owner.get("/owner/keys").json()
    assert listed["agent_url"] == "http://127.0.0.1:8710" and [k["name"] for k in listed["keys"]] == ["claude"]
    created = owner.post("/owner/keys", headers=CSRF, json={"name": "laptop", "role": "reader"})
    assert created.status_code == 200, created.text
    token = created.json()["token"]
    assert token.startswith("dmn_") and created.json()["key"]["role"] == "reader"
    assert token not in owner.get("/owner/keys").text  # shown once, stored as a hash
    stored = b"".join(f.read_bytes() for f in engine.config.data_dir.glob("doorman.db*"))  # db and its WAL
    assert b"laptop" in stored and token.encode() not in stored

    # the new key installs the skill and works right away
    second = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})
    skill = second.get("/v1/skill/SKILL.md")
    assert skill.status_code == 200 and skill.text.startswith("---\nname: doorman")
    assert second.get("/v1/skill/scripts/doorman.py").text.startswith("#!")
    assert second.get("/v1/skill/../../vault.key").status_code in (403, 404)
    assert TestClient(create_agent_app(engine)).get("/v1/skill/SKILL.md").status_code == 401
    assert second.get("/v1/capabilities").json()["role"] == "reader"

    # revoking cuts it off; both show in the journal
    key_id = created.json()["key"]["id"]
    assert owner.post(f"/owner/keys/{key_id}/revoke", headers=CSRF).status_code == 200
    assert second.get("/v1/capabilities").status_code == 401
    summaries = [e["summary"] for e in owner.get("/owner/journal").json()["entries"]]
    assert "Revoked agent key “laptop”" in summaries and "New agent key “laptop” (reader)" in summaries
    assert owner.post("/owner/keys", headers=CSRF, json={"name": " ", "role": "solo"}).status_code == 403
    assert owner.post("/owner/keys", headers=CSRF, json={"name": "x", "role": "root"}).status_code == 403
    # without a role a key is solo, the normal setup
    plain = owner.post("/owner/keys", headers=CSRF, json={"name": "desktop"})
    assert plain.status_code == 200 and plain.json()["key"]["role"] == "solo"


def test_creating_an_agent_key_needs_a_fresh_passkey_check(tap):
    engine, owner, agent, note_id = tap
    from doorman import clock
    clock.advance(6 * 60)
    stale = owner.post("/owner/keys", headers=CSRF, json={"name": "late", "role": "solo"})
    assert stale.status_code == 403 and stale.json()["code"] == "reauth"
    assert owner.post("/owner/keys/1/revoke", headers=CSRF).status_code == 200  # revoking stays easy


def test_pause_refuses_every_agent_call_and_resume_asks_for_the_passkey(tap):
    """P2.12 through the APIs: stopping is one tap, resuming gives access back and needs a fresh check."""
    engine, owner, agent, note_id = tap
    from doorman import clock
    clock.advance(6 * 60)  # the last passkey check is old: pausing doesn't care
    assert owner.post("/owner/pause", headers=CSRF).status_code == 200
    assert owner.get("/owner/settings").json()["paused"] is True
    for method, path, body in [("post", "/v1/tools/notes.create", {"args": {"title": "b"}}),
                               ("post", "/v1/read/notes.list", {"params": {}}), ("get", "/v1/events", None),
                               ("post", "/v1/tasks/claim", {}), ("get", "/v1/tasks", None)]:
        refused = getattr(agent, method)(path, **({"json": body} if body is not None else {}))
        assert refused.status_code == 403 and refused.json()["code"] == "paused", path
        assert "wait" in refused.json()["reason"]
    # the capabilities still answer, so the agent can tell a pause from a broken key
    assert agent.get("/v1/capabilities").json()["paused"] is True
    stale = owner.post("/owner/resume", headers=CSRF)
    assert stale.status_code == 403 and stale.json()["code"] == "reauth"
    engine.auth.mark_verified(owner.cookies.get("doorman_owner"))
    assert owner.post("/owner/resume", headers=CSRF).status_code == 200
    assert agent.post("/v1/tools/notes.create", json={"args": {"title": "c"}}).json()["status"] == "done"
    assert owner.get("/owner/settings").json()["agent_keys"] == 1
    # Revoke all keys is the old kill switch: no key survives it
    assert owner.post("/owner/kill", headers=CSRF).status_code == 200
    assert agent.get("/v1/capabilities").status_code == 401
    assert owner.get("/owner/settings").json()["agent_keys"] == 0


def test_task_screen_and_its_push(tap):
    """P1.4: GET /owner/tasks/{id} has the task, its journal entries and what still waits for the owner."""
    engine, owner, agent, note_id = tap
    task_id = owner.post("/owner/tasks", headers=CSRF, json={"text": "Send Anna the note"}).json()["id"]
    claimed = agent.post("/v1/tasks/claim", json={}).json()
    session = {"X-Doorman-Session": claimed["session"]}
    sent = agent.post("/v1/tools/notes.send_copy", headers=session,
                      json={"args": {"id": note_id, "to": "anna@example.com"}}).json()
    view = owner.get(f"/owner/tasks/{task_id}").json()
    assert view["task"]["text"] == "Send Anna the note" and view["task"]["status"] == "claimed"
    assert [e["id"] for e in view["entries"]] == [sent["entry_id"]]
    assert [a["id"] for a in view["approvals"]] == [sent["approval_id"]]
    assert view["approvals"][0]["entries"][0]["task_text"] == "Send Anna the note"
    agent.post(f"/v1/tasks/{task_id}/report", headers=session, json={"status": "done", "summary": "Asked you to send it"})
    push = engine.db.one("SELECT title, url FROM notifications ORDER BY id DESC LIMIT 1")
    assert push["title"] == "Done: Asked you to send it" and push["url"] == f"{OWNER_URL}/app/#/task/{task_id}"
    assert owner.get(f"/owner/tasks/{task_id}").json()["task"]["report"] == "Asked you to send it"
    assert owner.get("/owner/tasks/999").status_code == 403
def test_a_paused_key_is_refused_until_the_owner_resumes_it_with_a_passkey(tap):
    engine, owner, agent, note_id = tap
    key_id = engine.auth.list_keys()[0]["id"]
    engine.auth.pause_key(key_id, "honeytoken in a notes.send_copy call")
    for path in ("/v1/events", "/v1/tasks"):
        refused = agent.get(path)
        assert refused.status_code == 403 and refused.json()["code"] == "key_paused", path
    # as during the owner's Pause, the capabilities still answer and say so
    caps = agent.get("/v1/capabilities").json()
    assert caps["key_paused"] is True and caps["paused"] is False
    assert owner.get("/owner/keys").json()["keys"][0]["paused"] == "honeytoken in a notes.send_copy call"
    from doorman import clock
    clock.advance(6 * 60)
    stale = owner.post(f"/owner/keys/{key_id}/resume", headers=CSRF)
    assert stale.status_code == 403 and stale.json()["code"] == "reauth"
    passkey = engine._test_passkey
    options = owner.post("/owner/auth/reauth/options", headers=CSRF).json()
    owner.post("/owner/auth/reauth/verify", headers=CSRF, json={
        "challenge_id": options["challenge_id"], "credential": passkey.get(options["options"])})
    assert owner.post(f"/owner/keys/{key_id}/resume", headers=CSRF).status_code == 200
    assert agent.get("/v1/capabilities").json()["key_paused"] is False
    assert agent.get("/v1/events").status_code == 200


def test_agent_url_for_the_compose_stack(tmp_path):
    assert make_engine(tmp_path, agent_listen="0.0.0.0:8710").agent_url() == "http://doorman:8710"
    assert make_engine(tmp_path / "b", agent_url="http://10.0.0.5:8710/").agent_url() == "http://10.0.0.5:8710"


def test_trust_routines_and_logins_need_a_fresh_passkey_and_are_journaled(tap):
    """G4 and G5: these decide what counts as owner-written or which account a plugin uses."""
    engine, owner, agent, note_id = tap
    added = owner.post("/owner/trust", headers=CSRF, json={"kind": "email", "value": "Anna@UNI.example", "label": "Anna"})
    assert added.status_code == 200
    routine = owner.post("/owner/routines", headers=CSRF, json={"name": "Brief", "cron": "0 7 * * *",
                                                                "task_text": "Summarise today"})
    assert routine.status_code == 200
    trust_id = owner.get("/owner/trust").json()["trust"][0]["id"]
    # the id is for the app's Undo, which it offers only when this call added the entry
    assert added.json() == {"ok": True, "value": "anna@uni.example", "id": trust_id, "added": True}
    again = owner.post("/owner/trust", headers=CSRF, json={"kind": "email", "value": "anna@uni.example"}).json()
    assert again["id"] == trust_id and again["added"] is False
    assert owner.delete(f"/owner/trust/{trust_id}", headers=CSRF).status_code == 200
    summaries = [e["summary"] for e in owner.get("/owner/journal").json()["entries"]]
    assert "Trusted email anna@uni.example" in summaries and "No longer trusted: email anna@uni.example" in summaries
    assert "Routine “Brief” added (0 7 * * *): Summarise today" in summaries

    from doorman import clock
    clock.advance(6 * 60)  # logged in, but the last passkey check is old
    for method, path, body in [("post", "/owner/trust", {"kind": "email", "value": "x@evil.example"}),
                               ("post", "/owner/routines", {"name": "x", "cron": "0 7 * * *", "task_text": "x"}),
                               ("post", f"/owner/routines/{routine.json()['id']}", {"enabled": True}),
                               ("post", "/owner/triggers", {"name": "x", "plugin": "notes", "event": "e", "task_text": "x"})]:
        stale = getattr(owner, method)(path, headers=CSRF, json=body)
        assert stale.status_code == 403 and stale.json()["code"] == "reauth", path
    assert owner.get("/owner/trust").json()["trust"] == []
    # narrowing stays easy: deleting a routine needs no new passkey check
    assert owner.delete(f"/owner/routines/{routine.json()['id']}", headers=CSRF).status_code == 200


def test_edit_a_send_in_the_app_then_approve(tap):
    engine, owner, agent, note_id = tap
    out = agent.post("/v1/tools/notes.send_copy", json={"args": {"id": note_id, "to": "anna@example.com",
                                                                 "message": "hi anna heres the note"}}).json()
    approval = owner.get(f"/owner/approvals/{out['approval_id']}").json()
    assert approval["entries"][0]["editable"] == ["message"]
    edit = owner.post(f"/owner/approvals/{approval['id']}/edit", headers=CSRF, json={
        "entry_id": out["entry_id"], "changes": {"message": "Hi Anna, here is the note."},
        "payload_hash": approval["payload_hash"]})
    assert edit.status_code == 200, edit.text
    new = owner.get(f"/owner/approvals/{edit.json()['approval_id']}").json()
    assert new["entries"][0]["args"]["message"] == "Hi Anna, here is the note."
    refused = owner.post(f"/owner/approvals/{new['id']}/edit", headers=CSRF, json={
        "entry_id": new["entries"][0]["id"], "changes": {"to": "x@evil.example"}, "payload_hash": new["payload_hash"]})
    assert refused.status_code == 403
    approve(owner, engine._test_passkey, new["id"])
    sent = (engine.registry.instance("notes").ctx.data_dir / "sent.jsonl").read_text()
    assert "Hi Anna, here is the note." in sent and "heres" not in sent
    status = agent.get(f"/v1/journal/{out['entry_id']}").json()
    assert status["status"] == "superseded" and status["result"]["superseded_by"] == new["entries"][0]["id"]


def test_passkeys_of_an_old_address_dont_block_a_new_one(setup, tmp_path):
    """The demo's tunnel gets a new domain each start. A passkey made on the old one isn't offered there, and
    listing it as 'already registered' made password managers refuse to make a new one."""
    engine, owner, _, passkey = setup
    register(engine, owner, passkey)
    engine.db.exec("UPDATE webauthn_credentials SET rp_id='old.trycloudflare.com'")
    code = engine.auth.create_setup_code()
    options = owner.post("/owner/auth/register/options", json={"setup_code": code}).json()
    assert options["options"].get("excludeCredentials", []) == []
    [old] = owner.get("/owner/passkeys").json()["passkeys"]
    assert old["here"] is False and old["rp_id"] == "old.trycloudflare.com"
    owner.cookies.clear()
    refused = owner.post("/owner/auth/login/options")
    assert refused.status_code == 403 and "setup code" in refused.json()["reason"]
    # one from before rp_id was stored still counts as here, and a new one records its domain
    engine.db.exec("UPDATE webauthn_credentials SET rp_id=NULL")
    assert owner.post("/owner/auth/login/options").status_code == 200


def test_journal_pages_back_past_the_latest_entries(tap):
    """The app shows 150 at a time; "Show older" asks for the ones before the oldest it has."""
    engine, owner, agent, note_id = tap
    for i in range(4):
        agent.post("/v1/tools/notes.create", json={"args": {"title": f"n{i}"}})
    newest = owner.get("/owner/journal?limit=2").json()["entries"]
    older = owner.get(f"/owner/journal?limit=2&before={newest[-1]['id']}").json()["entries"]
    assert len(older) == 2 and all(e["id"] < newest[-1]["id"] for e in older)
    ids = [e["id"] for e in newest + older]
    assert ids == sorted(ids, reverse=True)


def test_triggers_and_routines_from_the_app(tap):
    """P2.4: the app adds and deletes triggers and switches routines on and off; bad input is refused."""
    engine, owner, agent, note_id = tap
    bad = owner.post("/owner/triggers", headers=CSRF, json={"name": "x", "plugin": "nope", "event": "e", "task_text": "x"})
    assert bad.status_code == 403 and bad.json()["code"] == "invalid"
    empty = owner.post("/owner/triggers", headers=CSRF, json={"name": "x", "plugin": "notes", "event": "", "task_text": "x"})
    assert empty.status_code == 403 and empty.json()["code"] == "invalid"
    made = owner.post("/owner/triggers", headers=CSRF, json={"name": "Uni mail", "plugin": "notes", "event": "new_mail",
                                                             "match": {"from": "*@uni.example"}, "task_text": "Sort {subject}"})
    assert made.status_code == 200, made.text
    [trigger] = owner.get("/owner/routines").json()["triggers"]
    assert trigger["name"] == "Uni mail" and '"*@uni.example"' in trigger["match"]
    assert owner.delete(f"/owner/triggers/{trigger['id']}", headers=CSRF).status_code == 200
    assert owner.get("/owner/routines").json()["triggers"] == []

    nameless = owner.post("/owner/routines", headers=CSRF, json={"name": " ", "cron": "0 7 * * *", "task_text": "x"})
    assert nameless.status_code == 403 and nameless.json()["code"] == "invalid"
    routine = owner.post("/owner/routines", headers=CSRF, json={"name": "Brief", "cron": "30 7 * * 1-5",
                                                                "task_text": "Summarise today"}).json()
    assert owner.post(f"/owner/routines/{routine['id']}", headers=CSRF, json={"enabled": False}).status_code == 200
    assert owner.get("/owner/routines").json()["routines"][0]["enabled"] == 0
    summaries = [e["summary"] for e in owner.get("/owner/journal").json()["entries"]]
    assert "Routine “Brief” off" in summaries and "Trigger “Uni mail” deleted" in summaries


def through(client):
    """The agent's CLI, talking to this app instead of over HTTP."""
    import importlib.util
    from pathlib import Path
    from urllib.parse import urlencode
    spec = importlib.util.spec_from_file_location(
        "doorman_cli", Path(__file__).resolve().parent.parent / "doorman/agent_skill/scripts/doorman.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    cli.api = lambda method, path, body=None, query=None, **kw: client.request(
        method, f"{path}?{urlencode({k: v for k, v in (query or {}).items() if v is not None})}", json=body).json()
    return cli


def test_doorman_status_lists_what_waits_on_the_owner(tap, capsys):
    """doorman status without an id: approvals, questions to the owner and the task's lease in one answer."""
    from doorman import clock
    engine, owner, agent, note_id = tap
    cli = through(agent)
    cli.main(["status"])
    assert capsys.readouterr().out.startswith("nothing open")
    sent = agent.post("/v1/tools/notes.send_copy", json={"args": {"id": note_id, "to": "a@x.example"}}).json()
    asked = agent.post("/v1/owner-questions", json={"question": "Tue or Wed?"}).json()["owner_question"]
    task_id = engine.tasks.create("Tidy my notes")
    agent.post("/v1/tasks/claim", json={})
    lease = engine.tasks.get(task_id)["lease_until"]
    clock.advance(5 * 60)
    try:
        out = agent.get("/v1/status").json()
    finally:
        clock.reset()
    assert [(a["id"], a["status"], a["tool"]) for a in out["approvals"]] == \
        [(sent["entry_id"], "waiting_approval", "notes.send_copy")]
    assert [q["id"] for q in out["owner_questions"]] == [asked["id"]] and out["checking"] == []
    assert out["task"]["id"] == task_id and out["task"]["lease_until"] == lease  # looking doesn't renew it
    cli.main(["status"])
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith(f"approval  entry {sent['entry_id']}  notes.send_copy  waiting for the owner")
    assert lines[1].startswith(f"question  owner-question:{asked['id']}  “Tue or Wed?”  asked ")
    assert lines[2].startswith(f"task  #{task_id}  “Tidy my notes”  lease until ")
    cli.main(["status", "--out", "json"])
    assert json.loads(capsys.readouterr().out)["task"]["id"] == task_id
    # decided and answered: nothing waits any more
    approve(owner, engine._test_passkey, sent["approval_id"])
    owner.post(f"/owner/questions/{asked['id']}/answer", headers=CSRF, json={"answer": "Wed"})
    out = agent.get("/v1/status").json()
    assert out["approvals"] == [] and out["owner_questions"] == []
    # MCP agents read it too
    mcp = agent.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                   "params": {"name": "read", "arguments": {"name": "status"}}})
    assert "owner_questions" in mcp.text


def test_call_with_wait_follows_a_send_to_its_end(tap, capsys):
    """doorman call ... --wait N: a send waits for the owner's decision and exits as doorman wait does."""
    engine, owner, agent, note_id = tap
    cli = through(agent)
    with pytest.raises(SystemExit) as stop:  # nobody decides within a second: still waiting (10)
        cli.main(["call", "notes.send_copy", f"id={note_id}", "to=a@x.example", "--wait", "1", "--out", "json"])
    assert stop.value.code == cli.EXIT_STILL_WAITING
    waiting = json.loads(capsys.readouterr().out)
    assert waiting["outcome"] == "waiting_approval" and waiting["call"]["approval_id"]
    approve(owner, engine._test_passkey, waiting["call"]["approval_id"])

    timer = threading.Timer(0.5, lambda: approve(owner, engine._test_passkey, engine.approvals.pending()[0]["id"]))
    timer.start()
    with pytest.raises(SystemExit) as stop:  # the owner approves meanwhile: sent (0)
        cli.main(["call", "notes.send_copy", f"id={note_id}", "to=a@x.example", "--wait", "20", "--out", "json"])
    timer.join()
    assert stop.value.code == 0 and json.loads(capsys.readouterr().out)["outcome"] == "sent"
    with pytest.raises(SystemExit) as stop:  # a write that runs at once: done (0), no waiting
        cli.main(["call", "notes.create", "title=Gym", "--wait", "20"])
    assert stop.value.code == 0 and '"outcome": "done"' in capsys.readouterr().out


def test_the_same_message_several_times_is_one_inbox_entry_with_its_count(tap):
    engine, owner, agent, note_id = tap
    for day in ("2026-11-10", "2026-11-11", "2026-11-12"):  # the backup's ref is the night's date
        engine.attention("backup_failed", day, "The backup failed", f"/backups/doorman-{day}.tar exists already",
                         url="https://doorman.example/app/#/status")
    for n in (1, 2):  # two failed sends say different things: two entries
        engine.attention("send_failed", 100 + n, "A send failed; nothing went out", f"mail to person{'ab'[n - 1]}\nrefused",
                         url="https://doorman.example/app/#/journal")
    items = owner.get("/owner/inbox").json()["attention"]
    assert [(i["title"], i["count"]) for i in items] == [("A send failed; nothing went out", 1)] * 2 + [
        ("The backup failed", 3)]
    backup = items[2]
    assert backup["detail"] == "/backups/doorman-2026-11-12.tar exists already" and len(backup["ids"]) == 3
    assert backup["first"] <= backup["created"]
    assert owner.post(f"/owner/attention/{backup['id']}/dismiss", headers=CSRF).status_code == 200
    assert [i["kind"] for i in owner.get("/owner/inbox").json()["attention"]] == ["send_failed"] * 2
    assert all(i["resolved"] for i in engine.db.all("SELECT resolved FROM attention WHERE kind='backup_failed'"))
