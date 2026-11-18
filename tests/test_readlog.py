"""The read log: every agent read is recorded (who, what, which items), outside the journal."""

import pytest
from fastapi.testclient import TestClient

from doorman import clock
from doorman.api.agent import create_agent_app
from doorman.api.owner import create_owner_app
from doorman.plugin_api import Denied
from doorman.readlog import summarize
from conftest import Agent, make_engine

OWNER_URL = "http://localhost:8711"


def test_reads_are_logged_with_who_and_what(engine):
    agent = Agent(engine)
    agent.call("notes.create", {"title": "Honours project", "body": "TEE reading list"})
    agent.call("notes.create", {"title": "Groceries", "body": "milk"})
    items = agent.read("notes.list", {})
    agent.read("notes.get", {"id": items[0]["id"]})

    rows = engine.reads.list()
    assert [r["name"] for r in rows] == ["notes.get", "notes.list"]
    listed = rows[1]
    assert listed["key_name"] == "test-solo" and listed["session_id"] == agent.session_id
    assert listed["status"] == "ok" and listed["items"] == 2
    assert {i["label"] for i in listed["labels"]} == {"Honours project", "Groceries"}
    assert rows[0]["params"] == {"id": items[0]["id"]} and rows[0]["items"] == 1
    # reads are not journal entries: the journal holds only the two creates
    assert [e["tool"] for e in engine.journal.list(limit=10)] == ["notes.create", "notes.create"]


def test_denied_and_failed_reads_are_logged_too(engine):
    agent = Agent(engine)
    with pytest.raises(Denied):
        agent.read("notes.nope", {})
    engine.plugin_setup.switch("notes", enabled=False)
    with pytest.raises(Denied):
        agent.read("notes.list", {})
    rows = engine.reads.list()
    assert [(r["name"], r["status"]) for r in rows] == [("notes.list", "denied"), ("notes.nope", "denied")]
    assert rows[0]["error"] and rows[0]["items"] == 0


def test_records_reads_and_week_count(engine):
    reader, actor = Agent(engine, "reader"), Agent(engine, "actor")
    engine.plugin_setup.add("mail", "mail_imap", {"imap_host": "imap.example.com", "smtp_host": "smtp.example.com"})
    engine.put_record(reader.session, reader.key, {"source": "mail:abc", "category": "question",
                                                   "suggested_action": "reply", "summary": "Can we meet?"})
    engine.list_records(actor.session, actor.key, category="question")
    row = engine.reads.list()[0]
    assert row["name"] == "records" and row["key_name"] == "test-actor"
    assert row["params"] == {"category": "question"} and row["labels"][0]["label"] == "Can we meet?"
    assert engine.week()["reads"] == 1


def test_old_reads_are_pruned(tmp_path):
    engine = make_engine(tmp_path, read_log_days=30)
    agent = Agent(engine)
    agent.read("notes.list", {})
    clock.advance(31 * 86400)
    agent.read("notes.list", {})
    engine.prune_reads()
    assert len(engine.reads.list()) == 1
    clock.reset()


def test_summaries_stay_small():
    count, labels = summarize([{"id": str(i), "subject": "x" * 500, "from": ["a@b.c"]} for i in range(100)])
    assert count == 100 and len(labels) == 30
    assert len(labels[0]["label"]) <= 90 and labels[0]["from"] == "a@b.c" and labels[0]["ref"] == "0"
    assert summarize({"items": [{"title": "a"}, {"title": "b"}]})[0] == 2
    assert summarize(None) == (0, [])


def test_owner_api_lists_reads_with_tasks(tmp_path):
    engine = make_engine(tmp_path, public_url=OWNER_URL, dev_owner_token="dev")
    token = engine.auth.create_key("my-agent", "solo")
    agent = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL, headers={"Authorization": "Bearer dev"})
    assert agent.post("/v1/read/notes.list", json={"params": {}}).status_code == 200
    out = owner.get("/owner/reads").json()
    assert out["reads"][0]["name"] == "notes.list" and out["reads"][0]["key_name"] == "my-agent"
    assert out["keep_days"] == 90
    older = owner.get(f"/owner/reads?before={out['reads'][0]['id']}").json()
    assert older["reads"] == []


def test_an_untrusted_address_names_the_item_it_came_from(engine):
    agent = Agent(engine)
    ref = "mail:AM0PR01MB00000A1B2C3D4E5F60718293A4B5C6@AM0PR01MB0000.eurprd01.prod.outlook.example"
    engine.reads.add(agent.key, agent.session, "mail.search", {}, [
        {"id": "x", "ref": ref, "subject": "Group 2 follow up", "from": ["m.jansen@students.uni.example"]}])
    seen = engine._with_source({"kind": "email", "value": "m.jansen@students.uni.example",
                                "first_seen": {"origin": ref, "ts": "2026-11-05T21:52:23+00:00"}})["first_seen"]
    assert seen["plugin"] == "mail" and seen["label"] == "Group 2 follow up"
    assert seen["from"] == "m.jansen@students.uni.example"
    unknown = engine._with_source({"value": "a@b.c", "first_seen": {"origin": "mail:nope"}})["first_seen"]
    assert unknown["plugin"] == "mail" and "label" not in unknown
