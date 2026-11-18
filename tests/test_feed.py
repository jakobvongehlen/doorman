"""Doorman's own events in the feed (feed.py): what each one carries and who gets it, each key's cursor, the
bell that wakes a waiting request, GET /v1/wait, lease renewal, the owner's note on a Deny, and the owner's
view of the feed (GET /owner/events)."""

import threading
import time
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from doorman import clock
from doorman.api.agent import create_agent_app
from doorman.plugin_api import Denied
from conftest import FAKE_PLUGINS, Agent, make_engine


@pytest.fixture
def engine(tmp_path):
    eng = make_engine(tmp_path)
    yield eng
    clock.reset()


def client(engine, agent):
    return TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {agent.token}"})


def own(engine, agent, after=0):
    """Doorman's own events for this agent, without touching its cursor."""
    return engine.event_feed(agent.session, agent.key, after, 200)["doorman"]


def send_copy(agent, to="x@elsewhere.example"):
    note = agent.call("notes.create", {"title": "Gym", "body": "Thursday"})["result"]["id"]
    return agent.call("notes.send_copy", {"id": note, "to": to})


# ---------------------------------------------------------------- what each event carries, and for whom


def test_a_denied_send_tells_its_own_key_with_the_owners_note(engine):
    agent, other = Agent(engine), Agent(engine)
    sent = send_copy(agent)
    engine.approvals.decide(sent["approval_id"], False, note="  Not to   him, please. Ask Anna first.​ ")
    [event] = [e for e in own(engine, agent) if e["type"] == "approval_decided"]
    assert event == {"id": event["id"], "ts": event["ts"], "type": "approval_decided",
                     "ref": f"approval:{sent['approval_id']}", "approval_id": sent["approval_id"],
                     "entry_ids": [sent["entry_id"]], "changeset_id": None, "decision": "declined",
                     "note": "Not to him, please. Ask Anna first."}
    assert [e for e in own(engine, other) if e["type"] == "approval_decided"] == []
    assert engine.approvals.deny_note(sent["entry_id"]) == "Not to him, please. Ask Anna first."
    status = client(engine, agent).get(f"/v1/journal/{sent['entry_id']}").json()
    assert status["status"] == "declined" and status["note"] == "Not to him, please. Ask Anna first."
    with pytest.raises(Denied):
        engine.approvals.decide(send_copy(agent)["approval_id"], False, note={"x": 1})


def test_an_approved_send_reports_its_result(engine):
    agent = Agent(engine)
    sent = send_copy(agent)
    engine.approvals.decide(sent["approval_id"], True)
    decided, result = [e for e in own(engine, agent) if e["type"] in ("approval_decided", "send_result")]
    assert decided["decision"] == "approved" and "note" not in decided
    assert result["type"] == "send_result" and result["entry_id"] == sent["entry_id"]
    assert result["status"] == "sent" and result["tool"] == "notes.send_copy"
    assert result["approval_id"] == sent["approval_id"] and result["ref"] == f"entry:{sent['entry_id']}"


def test_an_expired_approval_and_an_edited_one(engine):
    agent = Agent(engine)
    first = send_copy(agent)
    clock.advance(25 * 3600)
    engine.approvals.expire()
    [expired] = [e for e in own(engine, agent) if e["type"] == "approval_expired"]
    assert expired["approval_id"] == first["approval_id"] and expired["entry_ids"] == [first["entry_id"]]


def test_a_revert_and_a_changeset_decision(engine):
    agent = Agent(engine)
    created = agent.call("notes.create", {"title": "Gym", "body": "Thu"})
    engine.revert_entry(created["entry_id"])
    [reverted] = [e for e in own(engine, agent) if e["type"] == "entry_reverted"]
    assert reverted["entry_id"] == created["entry_id"] and reverted["revert_id"]
    cs = engine.propose_changeset(agent.session, agent.key, "Tidy", [
        {"tool": "notes.create", "args": {"title": "A", "body": "a"}}])
    engine.reject_changeset(cs["id"], "Keep the old ones")
    [decided] = [e for e in own(engine, agent) if e["type"] == "changeset_decided"]
    assert decided["changeset_id"] == cs["id"] and decided["status"] == "declined"
    assert decided["comment"] == "Keep the old ones"
    engine.reject_changeset(cs["id"], "again")  # not open any more: no second event
    assert len([e for e in own(engine, agent) if e["type"] == "changeset_decided"]) == 1


def test_tasks_go_to_every_key_that_can_take_them_and_reminders_to_their_key(engine):
    solo, actor, reader = Agent(engine), Agent(engine, "actor"), Agent(engine, "reader")
    task_id = engine.tasks.create("Tidy the calendar")
    for agent in (solo, actor):
        [created] = own(engine, agent)
        assert created["type"] == "task_created" and created["task_id"] == task_id and created["trusted"] is True
    assert own(engine, reader) == []
    engine.tasks.close(task_id)
    assert [e["type"] for e in own(engine, solo)] == ["task_created", "task_cancelled"]

    later = clock.iso(clock.now() + timedelta(hours=1))
    reminder = engine.tasks.remind(solo.session, later, "nudge Anna")
    assert engine.feed.announce_due_tasks() == [] and own(engine, solo)[-1]["type"] == "task_cancelled"
    clock.advance(3601)
    assert engine.feed.announce_due_tasks() == [reminder]
    assert engine.feed.announce_due_tasks() == []  # once
    due = own(engine, solo)[-1]
    assert due["type"] == "reminder_due" and due["task_id"] == reminder
    assert [e["type"] for e in own(engine, actor)] == ["task_created", "task_cancelled"]
    # a reminder is for the key that set it: only it lists and takes it
    assert engine.tasks.for_key(actor.key) == [] and engine.tasks.claim(actor.key) is None
    task, _ = engine.tasks.claim(solo.key)
    assert task["id"] == reminder


def test_a_claimed_task_closed_by_the_owner_or_by_its_lease(engine):
    agent, other = Agent(engine), Agent(engine)
    first = engine.tasks.create("one")
    engine.tasks.claim(agent.key)
    engine.tasks.close(first)
    assert own(engine, agent)[-1] == {**own(engine, agent)[-1], "type": "task_cancelled",
                                      "reason": "closed by the owner"}
    assert own(engine, other)[-1]["type"] == "task_created"  # it wasn't working on it
    second = engine.tasks.create("two")
    engine.tasks.claim(agent.key, second)
    clock.advance(31 * 60)
    assert engine.tasks.expire_leases() == [second]
    assert own(engine, agent)[-1]["reason"] == "the lease ran out"


def test_capabilities_changed(engine):
    agent = Agent(engine)
    assert engine.feed.check_caps(force=True) == []  # the first look only notes the version
    engine.plugin_setup.switch("notes", tool="send_copy", mode="off")
    assert engine.feed.caps_dirty  # a config entry in the journal
    assert engine.feed.check_caps() == [agent.key["id"]]
    [changed] = [e for e in own(engine, agent) if e["type"] == "caps_changed"]
    caps = client(engine, agent).get("/v1/capabilities").json()
    assert changed["version"] == caps["version"]
    assert changed["changes"] == ["notes: send_copy switched off"]  # what changed, not only that it did
    assert engine.feed.check_caps(force=True) == []
    engine.plugin_setup.switch("notes", read_only=True)
    assert engine.feed.check_caps() == [agent.key["id"]]
    assert [e for e in own(engine, agent) if e["type"] == "caps_changed"][-1]["changes"] == ["notes: read-only"]


def test_caps_changes_in_words():
    """The owner's feed line and the agent's event say what changed; an update that only rewords a tool is
    an empty list, and a change with nothing known from before has no list at all."""
    from doorman.caps import caps_changes

    def outline(reads=("mail.search",), tools=None, read_only=False, plugins=("mail",)):
        tools = {"mail.send": "ask"} if tools is None else tools
        return {"plugins": {name: {"read_only": read_only, "reads": list(reads), "tools": dict(tools)}
                            for name in plugins}, "setup": True, "questions": False}

    base = outline()
    assert caps_changes(None, base) is None
    assert caps_changes(base, outline()) == []
    assert caps_changes(base, outline(tools={"mail.send": "auto"})) == ["mail: send now runs without asking"]
    assert caps_changes(base, outline(tools={})) == ["mail: send switched off"]
    assert caps_changes(base, outline(reads=())) == ["mail: reading search switched off"]
    assert caps_changes(base, outline(plugins=("mail", "contacts"))) == ["contacts added"]
    assert caps_changes(base, outline(read_only=True, tools={})) == ["mail: read-only"]


def test_doorman_events_reach_actors_whole_and_never_taint(engine):
    engine.config["reader_actor_split"] = True
    actor = Agent(engine, "actor")
    sent = send_copy(actor)
    engine.approvals.decide(sent["approval_id"], False, note="No")
    [event] = [e for e in own(engine, actor) if e["type"] == "approval_decided"]
    assert event["note"] == "No"
    assert not actor.session["read_third_party"]


# ---------------------------------------------------------------- the cursor per key


def test_the_cursor_is_kept_per_key(engine):
    agent = Agent(engine)
    api = client(engine, agent)
    first = engine.tasks.create("one")
    out = api.get("/v1/events").json()
    assert [e["task_id"] for e in out["doorman"]] == [first] and out["events"] == []
    assert "spotlight" not in out and "watch" in out  # no third-party notice around nothing
    assert api.get("/v1/events").json()["doorman"] == out["doorman"]  # not acknowledged yet: again
    assert engine.feed.cursor(agent.key) == 0
    second = engine.tasks.create("two")
    out = api.get("/v1/events", params={"after": out["cursor"]}).json()  # acknowledges the first batch
    assert [e["task_id"] for e in out["doorman"]] == [second] and engine.feed.cursor(agent.key) == 1
    # a restart: no after, so it carries on after the last batch it acknowledged
    assert [e["task_id"] for e in api.get("/v1/events").json()["doorman"]] == [second]
    api.get("/v1/events", params={"after": out["cursor"], "peek": True})
    assert engine.feed.cursor(agent.key) == 1  # peek acknowledges nothing
    api.get("/v1/events", params={"after": out["cursor"]})
    assert engine.feed.cursor(agent.key) == 2
    api.get("/v1/events", params={"after": 0})
    assert engine.feed.cursor(agent.key) == 2  # never back
    api.get("/v1/events", params={"after": 999})
    assert engine.feed.cursor(agent.key) == 2  # never past the newest event


def test_a_new_key_starts_where_the_feed_stood(engine):
    Agent(engine)  # someone to tell
    engine.tasks.create("before the key")
    clock.advance(1)
    agent = Agent(engine)
    assert engine.feed.cursor(agent.key) == 1
    engine.tasks.create("after it")
    assert [e["task_id"] for e in client(engine, agent).get("/v1/events").json()["doorman"]] == [2]
    clock.advance(8 * 86400)
    engine.prune_events()  # after events_days: the events and whom they were for
    assert engine.db.all("SELECT * FROM events") == [] and engine.db.all("SELECT * FROM event_keys") == []
    assert engine.feed.announce_due_tasks() == []  # too old to announce again


# ---------------------------------------------------------------- waking, waiting


def test_a_waiting_request_wakes_at_once(engine):
    agent = Agent(engine)
    api = client(engine, agent)
    timer = threading.Timer(0.3, lambda: engine.tasks.create("now"))
    timer.start()
    began = time.monotonic()
    out = api.get("/v1/events", params={"wait": 30}).json()
    timer.join()
    assert [e["type"] for e in out["doorman"]] == ["task_created"]
    assert time.monotonic() - began < 2  # the bell, not RECHECK_SECONDS


def test_the_bell_does_not_miss_a_ring_before_the_wait():
    import asyncio

    from doorman.feed import Bell

    bell = Bell()
    seen = bell.generation
    bell.ring()
    assert asyncio.run(bell.wait(seen, 5)) is True
    began = time.monotonic()
    assert asyncio.run(bell.wait(bell.generation, 0.1)) is False and time.monotonic() - began < 1


def test_wait_follows_an_action_to_its_end(engine):
    agent = Agent(engine)
    api = client(engine, agent)
    sent = send_copy(agent)
    out = api.get("/v1/wait", params={"for": sent["entry_id"]}).json()
    assert out["done"] is False and out["outcome"] == "waiting_approval" and out["for"] == f"entry:{sent['entry_id']}"

    timer = threading.Timer(0.3, lambda: engine.approvals.decide(sent["approval_id"], False, note="Later"))
    timer.start()
    began = time.monotonic()
    out = api.get("/v1/wait", params={"for": f"entry:{sent['entry_id']}", "wait": 30}).json()
    timer.join()
    assert time.monotonic() - began < 2
    assert out["done"] is True and out["outcome"] == "declined" and out["entry"]["note"] == "Later"

    second = send_copy(agent)
    engine.approvals.decide(second["approval_id"], True)
    assert api.get("/v1/wait", params={"for": second["entry_id"]}).json()["outcome"] == "sent"
    write = agent.call("notes.create", {"title": "x", "body": "y"})
    assert api.get("/v1/wait", params={"for": write["entry_id"]}).json()["outcome"] == "done"

    cs = engine.propose_changeset(agent.session, agent.key, "Tidy", [
        {"tool": "notes.create", "args": {"title": "A", "body": "a"}}])
    assert api.get("/v1/wait", params={"for": f"changeset:{cs['id']}"}).json()["done"] is False
    engine.apply_changeset(cs["id"])
    out = api.get("/v1/wait", params={"for": f"changeset:{cs['id']}"}).json()
    assert out["outcome"] == "applied" and out["changeset"]["status"] == "applied"

    other = client(engine, Agent(engine))
    assert other.get("/v1/wait", params={"for": sent["entry_id"]}).json()["code"] == "not_found"
    assert api.get("/v1/wait", params={"for": "approval:1"}).json()["code"] == "invalid"
    assert engine.feed.cursor(agent.key) == 0  # waiting acknowledges nothing


def test_wait_follows_an_edited_send(engine):
    agent = Agent(engine)
    sent = send_copy(agent)
    editable = engine.approvals.editable(engine.journal.get(sent["entry_id"]))
    assert editable  # notes.send_copy's message can be changed before it goes out
    approval = engine.approvals.get(sent["approval_id"])
    edited = engine.approvals.edit(sent["approval_id"], sent["entry_id"], {editable[0]: "Changed"},
                                  approval["payload_hash"])
    [event] = [e for e in own(engine, agent) if e["type"] == "approval_decided"]
    assert event["decision"] == "edited" and event["replaced_by"]["entry_id"] == edited["entry_id"]
    engine.approvals.decide(edited["approval_id"], True)
    out = client(engine, agent).get("/v1/wait", params={"for": sent["entry_id"]}).json()
    assert out["for"] == f"entry:{edited['entry_id']}" and out["outcome"] == "sent"


def test_a_question_answered(engine):
    asker, reader = Agent(engine), Agent(engine, "reader")
    engine.db.exec("INSERT INTO questions(key_id, session_id, ref, question, status, created) "
                   "VALUES(?,?,?,?,'claimed',?)", (asker.key["id"], asker.session_id, "notes:1", "which?", clock.iso()))
    engine.db.exec("UPDATE questions SET claimed_by=?", (reader.key["id"],))
    engine.questions.answer(reader.key, 1, {"error": "not_found"})
    [event] = own(engine, asker)
    assert event == {**event, "type": "question_answered", "question_id": 1, "item": "notes:1", "status": "failed", "ref": "question:1"}
    assert own(engine, reader) == []
    out = client(engine, asker).get("/v1/wait", params={"for": "question:1"}).json()
    assert out["outcome"] == "failed" and out["done"] is True


# ---------------------------------------------------------------- leases


def test_calls_renew_a_tasks_lease_and_waiting_does_not(engine):
    agent = Agent(engine)
    api = client(engine, agent)
    task_id = engine.tasks.create("long job")
    session = api.post("/v1/tasks/claim", json={}).json()["session"]
    api.headers["X-Doorman-Session"] = session
    lease = lambda: engine.tasks.get(task_id)["lease_until"]  # noqa: E731
    start = lease()
    clock.advance(20 * 60)
    api.get("/v1/events", params={"wait": 0})
    api.get("/v1/wait", params={"for": "entry:1"})
    assert lease() == start  # only waiting: no renewal
    api.get("/v1/capabilities")
    assert lease() > start
    renewed = lease()
    clock.advance(20)
    api.get("/v1/capabilities")
    assert lease() == renewed  # less than a minute gained: not written again
    out = api.post(f"/v1/tasks/{task_id}/renew", json={"minutes": 120}).json()
    assert out["lease_until"] == lease() and lease() > clock.iso(clock.now() + timedelta(minutes=119))
    api.get("/v1/capabilities")
    assert lease() == out["lease_until"]  # never shortened
    assert api.post(f"/v1/tasks/{task_id}/renew", json={"minutes": 999}).json()["code"] == "invalid"
    assert api.post(f"/v1/tasks/{task_id + 1}/renew", json={}).json()["code"] == "session"
    clock.advance(119 * 60)
    assert engine.tasks.expire_leases() == []
    clock.advance(2 * 60)
    assert engine.tasks.expire_leases() == [task_id]


def test_the_owner_app_passes_a_deny_note_on(tmp_path):
    from doorman.api.owner import create_owner_app
    from soft_authenticator import SoftAuthenticator
    from test_api import CSRF, OWNER_URL, register

    engine = make_engine(tmp_path, public_url=OWNER_URL)
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL)
    register(engine, owner, SoftAuthenticator("localhost", OWNER_URL))
    agent = Agent(engine)
    sent = send_copy(agent)
    out = owner.post(f"/owner/approvals/{sent['approval_id']}/decide", headers=CSRF,
                     json={"approve": False, "note": "Ask Anna first"})
    assert out.json()["status"] == "denied"
    assert client(engine, agent).get(f"/v1/journal/{sent['entry_id']}").json()["note"] == "Ask Anna first"
    clock.reset()


# ---------------------------------------------------------------- the owner's view (Journal → Feed)


@pytest.fixture
def mailworld(tmp_path):
    from doorman.api.owner import create_owner_app
    from soft_authenticator import SoftAuthenticator
    from test_api import OWNER_URL, register

    engine = make_engine(tmp_path, public_url=OWNER_URL, plugin_paths=[FAKE_PLUGINS], plugins={
        "mail": {"type": "fake_mail", "enabled": True}, "notes": {"enabled": True}})
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL)
    assert owner.get("/owner/events").status_code == 401
    register(engine, owner, SoftAuthenticator("localhost", OWNER_URL))
    mailbox = engine.registry.instance("mail")
    engine.poll_triggers()  # the first poll only notes where "now" is
    yield engine, owner, mailbox
    clock.reset()


def new_mail(engine, mailbox, *mails):
    for sender, subject in mails:
        mailbox.add("inbox", sender, subject, "...")
    clock.advance(5 * 60)
    return engine.poll_triggers()


def test_the_owner_sees_the_feed_newest_first_and_pages_back(mailworld):
    engine, owner, mailbox = mailworld
    agent = Agent(engine)
    new_mail(engine, mailbox, ("anna@example.com", "Group project"), ("bob@example.com", "Lunch"))
    task_id = engine.tasks.create("Tidy the calendar")
    out = owner.get("/owner/events", params={"limit": 2}).json()
    assert [(e["source"], e["type"]) for e in out["events"]] == [("doorman", "task_created"), ("plugin", "new_mail")]
    assert out["more"] is True and out["latest"] == 3 and out["keep_days"] == 7
    created, mail = out["events"]
    assert created["keys"] == [agent.key["id"]] and created["task_id"] == task_id
    assert out["tasks"][str(task_id)] == {"id": task_id, "text": "Tidy the calendar", "status": "pending",
                                          "closed_by_owner": False}
    assert mail["plugin"] == "mail" and mail["ref"] == "mail:m2" and mail["agents"] == "text"
    assert mail["data"] == {"from": "bob@example.com", "subject": "Lunch"} and mail["triggers"] == []
    assert out["plugins"] == {"mail": "fake_mail", "notes": "notes"}
    older = owner.get("/owner/events", params={"limit": 2, "before": mail["id"]}).json()
    assert [e["data"]["subject"] for e in older["events"]] == ["Group project"] and older["more"] is False
    assert [e["type"] for e in owner.get("/owner/events?source=doorman").json()["events"]] == ["task_created"]
    assert [e["ref"] for e in owner.get("/owner/events?source=plugin").json()["events"]] == ["mail:m2", "mail:m1"]
    assert owner.get("/owner/events?source=nope").status_code == 403
    assert len(owner.get("/owner/events?limit=0").json()["events"]) == 1  # at least one per page


def test_the_owner_feed_leaves_out_what_the_owner_just_did_to_the_tools(mailworld):
    """caps_changed tells agents to look at their tools again; the owner made the change (and the journal has
    it), so their feed doesn't repeat it once per key."""
    engine, owner, _ = mailworld
    agent = Agent(engine)
    engine.feed.check_caps(force=True)
    engine.plugin_setup.switch("notes", tool="send_copy", mode="off")
    assert engine.feed.check_caps() == [agent.key["id"]]
    assert "caps_changed" not in [e["type"] for e in owner.get("/owner/events").json()["events"]]


def test_the_owner_gets_the_apps_cleaning_not_the_agents(mailworld):
    """It's the owner's own mail: no datamarking, placeholders, guard or read log. Invisible characters go,
    and a one-time code stays masked, as everywhere else in the app."""
    engine, owner, mailbox = mailworld
    agent = Agent(engine)
    new_mail(engine, mailbox, ("anna@example.com", "Lunch​ on Friday? Your code is 482913"))
    [event] = owner.get("/owner/events").json()["events"]
    assert event["data"]["subject"] == "Lunch on Friday? Your code is [code redacted]"
    assert engine.db.all("SELECT * FROM reads") == [] and not agent.session["read_third_party"]
    assert engine.db.all("SELECT * FROM agent_feed") == []  # looking moves no agent's cursor


def test_each_event_says_how_much_of_it_agents_get_now(mailworld):
    engine, owner, mailbox = mailworld
    new_mail(engine, mailbox, ("anna@example.com", "Agenda"))
    agents = lambda: [e["agents"] for e in owner.get("/owner/events").json()["events"]]  # noqa: E731
    assert agents() == ["text"]
    engine.plugin_setup.switch("mail", tool="mail.read", tool_enabled=False)
    assert agents() == ["where"]
    for short in ("search", "thread", "attachment"):
        engine.plugin_setup.switch("mail", tool=f"mail.{short}", tool_enabled=False)
    assert agents() == ["none"]
    engine.plugin_setup.switch("mail", enabled=False)
    [event] = owner.get("/owner/events").json()["events"]
    assert event["agents"] == "off" and event["data"]["subject"] == "Agenda"  # the owner still sees it


def test_each_keys_place_in_the_feed(mailworld):
    engine, owner, mailbox = mailworld
    agent, gone = Agent(engine), Agent(engine)
    engine.revoke_agent_key(gone.key["id"])
    new_mail(engine, mailbox, ("anna@example.com", "Agenda"), ("bob@example.com", "Lunch"))
    [key] = owner.get("/owner/events").json()["keys"]
    assert key["id"] == agent.key["id"] and key["cursor"] is None and key["seen"] is None  # it never asked
    api = client(engine, agent)
    first = api.get("/v1/events", params={"limit": 1}).json()
    api.get("/v1/events", params={"after": first["cursor"], "limit": 1})
    [key] = owner.get("/owner/events").json()["keys"]
    assert key["cursor"] == first["events"][0]["id"] and key["seen"] and key["name"] == agent.key["name"]


def test_a_fired_trigger_and_a_tasks_own_events(mailworld):
    engine, owner, mailbox = mailworld
    agent = Agent(engine)
    engine.db.exec("INSERT INTO triggers(name, plugin, event, match, task_text, enabled) VALUES"
                   "('bills','mail','new_mail','{\"from\": \"*@stadtwerke.example\"}','Check bill {ref}: {subject}',1)")
    [task_id] = new_mail(engine, mailbox, ("billing@stadtwerke.example", "Bill October"), ("spam@else.example", "Win"))
    out = owner.get("/owner/events?source=plugin").json()
    spam, bill = out["events"]
    assert bill["triggers"] == [{"name": "bills", "task_id": task_id}] and spam["triggers"] == []
    assert out["tasks"][str(task_id)]["text"] == "Check bill mail:m1: Bill October"

    engine.tasks.create("Something else")
    _, session = engine.tasks.claim(agent.key, task_id)
    note = engine.call_tool(session, agent.key, "notes.create", {"title": "Bill", "body": "84 EUR"})["result"]["id"]
    sent = engine.call_tool(session, agent.key, "notes.send_copy", {"id": note, "to": "x@elsewhere.example"})
    engine.approvals.decide(sent["approval_id"], False, note="Not now")
    send_copy(agent)  # outside the task
    out = owner.get(f"/owner/events?task_id={task_id}").json()
    assert [(e["type"], e["ref"]) for e in out["events"]] == [
        ("approval_decided", f"approval:{sent['approval_id']}"), ("task_created", f"task:{task_id}"),
        ("new_mail", "mail:m1")]
    decided = out["events"][0]
    assert decided["task_id"] == task_id and decided["data"]["note"] == "Not now"
    assert decided["summary"] == engine.journal.get(sent["entry_id"])["summary"]  # what the journal calls it
    assert owner.get("/owner/events?task_id=999").json()["code"] == "not_found"
