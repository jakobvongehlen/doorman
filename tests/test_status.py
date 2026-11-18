"""The status page: when keys were last used, the reader's rounds, silence checks and the week in numbers."""

import pytest
from fastapi.testclient import TestClient

from doorman import clock
from doorman.api.agent import create_agent_app
from doorman.plugin_api import Denied
from conftest import Agent


def kinds(engine):
    return {(a["kind"], a["ref"]) for a in engine.attention_list()}


def test_keys_remember_when_they_were_last_used(engine):
    token = engine.auth.create_key("claude", "solo")
    client = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})
    assert engine.auth.list_keys()[0]["last_used"] is None
    client.get("/v1/capabilities")
    first = engine.auth.list_keys()[0]["last_used"]
    assert first
    clock.advance(30)
    client.get("/v1/capabilities")
    assert engine.auth.list_keys()[0]["last_used"] == first  # written at most once a minute
    clock.advance(61)
    client.get("/v1/capabilities")
    assert engine.auth.list_keys()[0]["last_used"] > first


def test_no_backup_is_listed_after_a_week_and_clears_with_one(engine):
    assert engine.check_silence(force=True) == []
    clock.advance(8 * 86400)
    assert "backup" in engine.check_silence(force=True)
    assert engine.attention_list()[0]["title"] == "No backup yet"
    engine.db.set_setting("last_backup", clock.iso())
    engine.check_silence(force=True)
    assert ("backup_old", "backup") not in kinds(engine)
    clock.advance(8 * 86400)
    engine.check_silence(force=True)
    assert [a["title"] for a in engine.attention_list() if a["kind"] == "backup_old"] == ["No backup for 7 days"]


def test_a_reader_that_stops_or_keeps_failing_is_listed(engine):
    engine.db.set_setting("last_backup", "2099-01-01T00:00:00+00:00")
    token = engine.auth.create_key("reader", "reader")
    key = engine.auth.key_from_token(token)
    clock.advance(61 * 60)
    engine.check_silence(force=True)
    assert ("reader_silent", str(key["id"])) in kinds(engine)
    assert "hasn't reported a single round" in engine.attention_list()[0]["detail"]
    # a good round clears it
    engine.reader_round(key, {"recorded": 2, "skipped": 0, "failed": 0})
    engine.check_silence(force=True)
    assert kinds(engine) == set()
    # failing rounds: listed once they've failed for an hour, with the reason
    engine.reader_round(key, {"recorded": 0, "skipped": 0, "failed": 3, "error": "model API answered 401"})
    clock.advance(30 * 60)
    engine.reader_round(key, {"recorded": 0, "skipped": 0, "failed": 3, "error": "model API answered 401"})
    engine.check_silence(force=True)
    assert kinds(engine) == set()
    clock.advance(31 * 60)
    engine.reader_round(key, {"recorded": 0, "skipped": 0, "failed": 3, "error": "model API answered 401"})
    engine.check_silence(force=True)
    assert "model API answered 401" in engine.attention_list()[0]["detail"]
    # a round with nothing new isn't a failure
    engine.reader_round(key, {"recorded": 0, "skipped": 5, "failed": 0})
    engine.check_silence(force=True)
    assert kinds(engine) == set()
    # the round is stored as numbers only, and only reader keys report rounds
    engine.reader_round(key, {"recorded": "lots", "failed": -1, "skipped": True})
    assert engine.reader_status(key["id"])["recorded"] == 0
    solo = engine.auth.key_from_token(engine.auth.create_key("claude", "solo"))
    with pytest.raises(Denied):
        engine.reader_round(solo, {"recorded": 1})


def test_tasks_nobody_picks_up_are_listed(engine, agent):
    engine.db.set_setting("last_backup", "2099-01-01T00:00:00+00:00")
    engine.tasks.create("Sort the inbox")
    clock.advance(30 * 60)
    engine.check_silence(force=True)
    assert kinds(engine) == set()
    clock.advance(31 * 60)
    engine.check_silence(force=True)
    assert [a["title"] for a in engine.attention_list()] == ["1 task waiting for over 60 minutes"]
    engine.tasks.claim(agent.key)
    engine.check_silence(force=True)
    assert kinds(engine) == set()


def test_status_and_week(engine, agent):
    engine.db.exec("INSERT INTO trust(kind, value, label, created) VALUES('email','anna@example.com','Anna',?)",
                   (clock.iso(),))
    made = agent.call("notes.create", {"title": "Gym"})
    agent.call("notes.create", {"title": "Dentist"})
    sent = agent.call("notes.send_copy", {"id": made["result"]["id"], "to": "anna@example.com"})
    engine.approvals.decide(sent["approval_id"], approve=True)
    other = agent.call("notes.send_copy", {"id": made["result"]["id"], "to": "anna@example.com"})
    engine.approvals.decide(other["approval_id"], approve=False)
    engine.revert_entry(made["entry_id"], force=True)
    reader = Agent(engine, role="reader")
    engine.put_record(reader.session, reader.key, {"source": "mail:1", "category": "other",
                                                    "suggested_action": "review", "summary": "?"})
    week = engine.week()
    assert {k: week[k] for k in ("actions", "sent", "approved", "denied", "reverted", "records", "records_review")} \
        == {"actions": 2, "sent": 1, "approved": 1, "denied": 1, "reverted": 1, "records": 1, "records_review": 1}

    engine.tick()
    status = engine.status()
    assert status["worker"]["ok"] and status["paused"] is False
    assert [p["name"] for p in status["plugins"]] == ["notes"] and status["plugins"][0]["problem"] is None
    assert status["plugins"][0]["checked"]
    assert {k["role"] for k in status["keys"]} == {"solo", "reader"}
    # no backup.dir: nothing scheduled, nothing run
    assert status["backup"] == {"last": None, "problem": None, "failed": False, "copied": None, "offsite": False,
                                "next": None}
    clock.advance(8 * 86400)
    week = engine.week()
    assert week["actions"] == 0 and week["sent"] == 0


def test_vault_key_file_is_listed_until_the_key_comes_from_the_environment(tmp_path, monkeypatch):
    from conftest import make_engine

    monkeypatch.delenv("DOORMAN_VAULT_KEY", raising=False)
    engine = make_engine(tmp_path, vault_key_file_warn=True)
    engine.db.set_setting("last_backup", "2099-01-01T00:00:00+00:00")
    assert engine.vault.key_source == "file"
    assert engine.check_silence(force=True) == ["vault_key"]
    assert [a["title"] for a in engine.attention_list()] == ["The vault key is stored next to the vault"]
    assert "DOORMAN_VAULT_KEY" in engine.attention_list()[0]["detail"]
    engine.check_silence(force=True)
    assert len(engine.attention_list()) == 1  # listed once

    key = (tmp_path / "data" / "vault.key").read_bytes().decode()
    (tmp_path / "data" / "vault.key").unlink()
    monkeypatch.setenv("DOORMAN_VAULT_KEY", key)
    engine = make_engine(tmp_path, vault_key_file_warn=True)
    assert engine.vault.key_source == "environment"
    assert engine.check_silence(force=True) == []
    assert ("vault_key", "file") not in kinds(engine)

    monkeypatch.delenv("DOORMAN_VAULT_KEY", raising=False)
    (tmp_path / "other").mkdir()
    quiet = make_engine(tmp_path / "other", vault_key_file_warn=False)  # a demo or dev instance
    quiet.db.set_setting("last_backup", "2099-01-01T00:00:00+00:00")
    assert quiet.check_silence(force=True) == []
