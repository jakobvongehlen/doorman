"""Each tool's position in the owner app: Off, Ask me or Auto. Reads are Off or On."""

import pytest
from fastapi.testclient import TestClient

from conftest import FAKE_PLUGINS, Agent, make_engine
from doorman import clock
from doorman.api.owner import create_owner_app
from doorman.plugin_api import Denied
from test_api import CSRF, OWNER_URL, register

TRUSTED = "anna@example.com"


def trust(engine, value=TRUSTED):
    engine.db.exec("INSERT INTO trust(kind, value, label, created) VALUES('email',?,'Anna',?)", (value, clock.iso()))


def modes(engine, name="notes"):
    plugin = next(p for p in engine.registry.list() if p["name"] == name)
    return {t["name"].split(".", 1)[1]: t["approval"] for t in plugin["tools"]}


def test_defaults_are_unchanged(engine):
    # undoable writes run on their own, sends ask: nothing changes until the owner picks a position
    assert modes(engine) == {"create": "auto", "update": "auto", "delete": "auto", "send_copy": "ask"}
    assert engine.registry.tool_mode("notes", "list") == "auto"
    agent = Agent(engine)
    note = agent.call("notes.create", {"title": "a"})
    assert note["status"] == "done"
    trust(engine)
    assert agent.call("notes.send_copy", {"id": note["result"]["id"], "to": TRUSTED})["status"] == "waiting_approval"


def test_ask_me_on_an_undoable_tool_waits_and_stays_revertable(engine):
    agent = Agent(engine)
    engine.plugin_setup.switch("notes", tool="create", mode="ask")
    out = agent.call("notes.create", {"title": "held"})
    assert out["status"] == "waiting_approval"
    assert engine.read(agent.session, agent.key, "notes.list", {}) == []        # nothing ran yet
    done = engine.approvals.decide(out["approval_id"], True)["results"][0]
    assert done["status"] == "done"
    entry = engine.journal.get(done["entry_id"])
    assert entry["tier"] == "reversible" and entry["status"] == "done"
    engine.revert_entry(done["entry_id"])                                      # still undoable
    assert engine.read(agent.session, agent.key, "notes.list", {}) == []


def test_auto_on_a_send_runs_it_while_every_check_passes(engine):
    agent = Agent(engine)
    note_id = agent.call("notes.create", {"title": "a"})["result"]["id"]
    engine.plugin_setup.switch("notes", tool="send_copy", mode="auto")
    assert modes(engine)["send_copy"] == "auto"
    trust(engine)
    sent = agent.call("notes.send_copy", {"id": note_id, "to": TRUSTED})
    assert sent["status"] == "done" and engine.journal.get(sent["entry_id"])["decision"] == "direct"
    # a new recipient still asks
    assert agent.call("notes.send_copy", {"id": note_id, "to": "x@elsewhere.example"})["status"] == "waiting_approval"


def test_ask_me_beats_the_plugins_no_approval(tmp_path):
    engine = make_engine(tmp_path, plugins={"notes": {"enabled": True, "no_approval": True}})
    assert modes(engine)["send_copy"] == "auto"
    engine.plugin_setup.switch("notes", tool="send_copy", mode="ask")
    agent = Agent(engine)
    trust(engine)
    note_id = agent.call("notes.create", {"title": "a"})["result"]["id"]
    assert agent.call("notes.send_copy", {"id": note_id, "to": TRUSTED})["status"] == "waiting_approval"


def test_off_hides_the_tool_and_a_choice_matching_the_default_isnt_stored(engine):
    engine.plugin_setup.switch("notes", tool="send_copy", mode="off")
    assert "send_copy" in engine.registry.state("notes")["disabled_tools"]
    with pytest.raises(Denied):
        Agent(engine).call("notes.send_copy", {"id": "x", "to": TRUSTED})
    engine.plugin_setup.switch("notes", tool="send_copy", mode="ask")                   # back on, at its default
    state = engine.registry.state("notes")
    assert state["disabled_tools"] == [] and state["tool_approval"] == {}
    assert engine.plugin_setup.switch("notes", tool="send_copy", mode="ask")["entry_id"] is None   # no change, no entry


def test_reads_are_on_or_off_and_payments_never_run_unasked(engine):
    with pytest.raises(Denied):
        engine.plugin_setup.switch("notes", tool="list", mode="ask")
    engine.plugin_setup.switch("notes", tool="list", mode="off")
    assert engine.registry.tool_mode("notes", "list") == "off"
    engine.plugin_setup.switch("notes", tool="list", mode="auto")
    assert engine.registry.tool_mode("notes", "list") == "auto"
    with pytest.raises(Denied):
        engine.plugin_setup.switch("notes", tool="send_copy", mode="maybe")


def test_payments_never_run_unasked(tmp_path):
    engine = make_engine(tmp_path, plugin_paths=[FAKE_PLUGINS],
                         plugins={"bank": {"type": "fake_bank", "enabled": True, "no_approval": True}})
    tool = engine.registry.manifest("bank")["tools"][0]["name"]
    with pytest.raises(Denied):
        engine.plugin_setup.switch("bank", tool=tool, mode="auto")
    assert modes(engine, "bank")[tool] == "ask"


def test_a_changeset_asks_for_an_undoable_tool_set_to_ask_me(engine):
    agent = Agent(engine)
    engine.plugin_setup.switch("notes", tool="create", mode="ask")
    cs = engine.propose_changeset(agent.session, agent.key, "a note", [{"tool": "notes.create", "args": {"title": "a"}}])
    assert cs["preview"][0]["decision"] == "approval"
    out = engine.apply_changeset(cs["id"])
    assert engine.read(agent.session, agent.key, "notes.list", {}) == []        # waits for the owner
    assert engine.approvals.pending(), out


def test_revert_puts_the_choice_back(engine):
    out = engine.plugin_setup.switch("notes", tool="create", mode="ask")
    assert modes(engine)["create"] == "ask"
    engine.revert_entry(out["entry_id"])
    assert modes(engine)["create"] == "auto"


def test_loosening_a_send_needs_a_fresh_passkey(tmp_path):
    from soft_authenticator import SoftAuthenticator

    engine = make_engine(tmp_path, public_url=OWNER_URL)
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL)
    register(engine, owner, SoftAuthenticator("localhost", OWNER_URL))
    clock.advance(6 * 60)  # logged in, but the passkey check is older than 5 minutes
    stale = owner.post("/owner/plugins/notes", headers=CSRF, json={"tool": "send_copy", "mode": "auto"})
    assert stale.status_code == 403 and stale.json()["code"] == "reauth"
    # tightening, and undoable tools, don't need one
    for tool, mode in (("send_copy", "off"), ("send_copy", "ask"), ("create", "ask"), ("create", "auto")):
        assert owner.post("/owner/plugins/notes", headers=CSRF, json={"tool": tool, "mode": mode}).status_code == 200
    clock.reset()
    engine2 = make_engine(tmp_path / "b", public_url=OWNER_URL)
    owner2 = TestClient(create_owner_app(engine2), base_url=OWNER_URL)
    register(engine2, owner2, SoftAuthenticator("localhost", OWNER_URL))
    allowed = owner2.post("/owner/plugins/notes", headers=CSRF, json={"tool": "send_copy", "mode": "auto"})
    assert allowed.status_code == 200
    clock.advance(6 * 60)
    ask = owner2.post("/owner/plugins/notes", headers=CSRF, json={"tool": "send_copy", "mode": "ask"}).json()
    assert engine2.plugin_setup.revert_loosens(ask["entry_id"])                              # reverting it would loosen
    stale = owner2.post(f"/owner/journal/{ask['entry_id']}/revert", headers=CSRF, json={})
    assert stale.status_code == 403 and stale.json()["code"] == "reauth"
