"""Agents changing Doorman's setup (agent_setup.py): harmless settings yes, security never, new plugins
switched off, everything in the journal and revertible."""

import pytest
from fastapi.testclient import TestClient

from doorman.api.agent import create_agent_app
from doorman.plugin_api import Denied
from conftest import Agent, make_engine


@pytest.fixture
def world(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    engine = make_engine(tmp_path, plugins={"notes": {"enabled": True}})
    engine.plugin_setup.add("box", "mail_imap", {"imap_host": "imap.example.com", "smtp_host": "smtp.example.com",
                                           "archive": "index"})
    engine.plugin_setup.add("archive", "files", {"root": str(files)})
    return engine, Agent(engine)


def setup_call(engine, agent, tool, args):
    return engine.setup.call(agent.session, agent.key, tool, args)


def test_agents_see_types_and_plugins_with_what_they_may_change(world):
    engine, agent = world
    types = {t["type"]: t for t in engine.setup.read(agent.session, agent.key, "doorman.plugin_types")}
    assert "mcp" not in types and types["mail_imap"]["agent_can_install"] and not types["whatsapp"]["agent_can_install"]
    assert "archive_months" in types["mail_imap"]["agent_settings"] and "imap_host" not in types["mail_imap"]["agent_settings"]
    plugins = {p["name"]: p for p in engine.setup.read(agent.session, agent.key, "doorman.plugins")}
    assert plugins["box"]["settings"]["imap_host"] == "imap.example.com" and "defined_in" not in plugins["box"]


def test_harmless_settings_change_and_revert(world):
    engine, agent = world
    out = setup_call(engine, agent, "doorman.configure", {"plugin": "box", "set": {"archive_months": 24}})
    assert out["status"] == "done" and out["result"]["changed"] == ["archive_months: (default) → 24"]
    assert engine.registry.configured()["box"]["config"]["archive_months"] == 24
    entry = engine.journal.get(out["entry_id"])
    assert entry["session_id"] == agent.session["id"] and "Agent test-solo" in entry["summary"]
    engine.revert_entry(out["entry_id"])
    assert "archive_months" not in engine.registry.configured()["box"]["config"]
    setup_call(engine, agent, "doorman.configure", {"plugin": "box", "set": {"archive": "full"}})
    out = setup_call(engine, agent, "doorman.configure", {"plugin": "box", "unset": ["archive"]})
    assert "archive" not in engine.registry.configured()["box"]["config"]


def test_calendar_and_list_choices_only_narrow(world):
    """`calendars` keeps a therapy or family calendar away from agents: an agent may hide one more
    (narrow), but adding one back or clearing the choice is the owner's, so an injected agent can't widen
    what it sees."""
    engine, agent = world
    engine.plugin_setup.add("cal", "google_calendar", {"calendars": ["primary", "work@example.com"]})
    engine.plugin_setup.add("dav", "caldav", {"url": "https://dav.example.com/", "lists": ["Shopping"]})
    for args in ({"plugin": "cal", "unset": ["calendars"]},
                 {"plugin": "cal", "set": {"calendars": ["primary", "family@example.com"]}},
                 {"plugin": "cal", "set": {"calendars": "[]"}},
                 {"plugin": "dav", "set": {"lists": ["Shopping", "Health"]}},
                 {"plugin": "dav", "set": {"lists": ""}}):
        with pytest.raises(Denied, match="ask the owner") as exc:
            setup_call(engine, agent, "doorman.configure", args)
        assert exc.value.code == "setting", args
    assert engine.registry.configured()["cal"]["config"]["calendars"] == ["primary", "work@example.com"]
    out = setup_call(engine, agent, "doorman.configure", {"plugin": "cal", "set": {"calendars": ["primary"]}})
    assert out["status"] == "done" and engine.registry.configured()["cal"]["config"]["calendars"] == ["primary"]
    # without a choice (every calendar) the agent may pick, as before
    out = setup_call(engine, agent, "doorman.configure", {"plugin": "dav", "set": {"calendars": ["Work"]}})
    assert engine.registry.configured()["dav"]["config"]["calendars"] == ["Work"]
    setup_call(engine, agent, "doorman.configure", {"plugin": "dav", "set": {"timezone": "Europe/Amsterdam"}})


@pytest.mark.parametrize("changes", [{"imap_host": "evil.example"}, {"from_address": "x@evil.example"},
                                     {"check_hidden_text": False}])
def test_security_settings_are_refused(world, changes):
    engine, agent = world
    with pytest.raises(Denied) as exc:
        setup_call(engine, agent, "doorman.configure", {"plugin": "box", "set": changes})
    assert exc.value.code == "setting" and "archive_months" in exc.value.reason
    assert engine.registry.configured()["box"]["config"]["imap_host"] == "imap.example.com"


def test_the_switch(world, tmp_path):
    off = make_engine(tmp_path / "other", agent_setup=False)
    a2 = Agent(off)
    with pytest.raises(Denied) as exc:
        off.setup.read(a2.session, a2.key, "doorman.plugins")
    assert exc.value.code == "setup_off"


def test_installing_starts_switched_off_and_asks_the_owner(world):
    engine, agent = world
    out = setup_call(engine, agent, "doorman.install", {"type": "mail_outlook", "name": "uni",
                                                        "settings": {"address": "j@students.uni.example", "tenant": "uni.example"}})
    assert out["result"]["enabled"] is False
    assert engine.registry.state("uni")["enabled"] is False
    [item] = [a for a in engine.attention_list() if a["kind"] == "setup"]
    assert "uni" in item["title"] and "connect it" in item["detail"]
    listed = {p["name"]: p for p in engine.registry.list()}
    assert listed["uni"]["set_up_by"] == "test-solo"
    # agents never switch on
    with pytest.raises(Denied):
        setup_call(engine, agent, "doorman.configure", {"plugin": "uni", "set": {"enabled": True}})
    # the owner does, and the marks go
    engine.plugin_setup.switch("uni", enabled=True)
    assert {p["name"]: p for p in engine.registry.list()}["uni"]["set_up_by"] is None
    assert not [a for a in engine.attention_list() if a["kind"] == "setup"]
    # undo removes it
    engine.revert_entry(out["entry_id"], force=True)
    assert "uni" not in engine.registry.configured()


@pytest.mark.parametrize("args, code", [
    ({"type": "whatsapp", "name": "chats"}, "setting"),
    ({"type": "files", "name": "root", "settings": {"root": "/"}}, "setting"),
    ({"type": "mcp", "name": "srv"}, "invalid"),
    ({"type": "mail_imap", "name": "doorman"}, "invalid"),
    ({"type": "mail_imap", "name": "box"}, "invalid"),
    ({"type": "mail_imap", "name": "x", "settings": {"no_approval": True}}, "invalid"),
])
def test_what_agents_cant_install(world, args, code):
    engine, agent = world
    with pytest.raises(Denied) as exc:
        setup_call(engine, agent, "doorman.install", args)
    assert exc.value.code == code


def test_switching_off_only(world):
    engine, agent = world
    setup_call(engine, agent, "doorman.disable", {"plugin": "box", "tool": "send"})
    assert "send" in engine.registry.state("box")["disabled_tools"]
    setup_call(engine, agent, "doorman.disable", {"plugin": "box", "read_only": True})
    assert engine.registry.state("box")["read_only"] is True
    out = setup_call(engine, agent, "doorman.disable", {"plugin": "box"})
    assert engine.registry.state("box")["enabled"] is False
    engine.revert_entry(out["entry_id"])
    assert engine.registry.state("box")["enabled"] is True


def test_roles_sessions_and_the_agent_api(world):
    engine, agent = world
    reader = Agent(engine, "reader")
    with pytest.raises(Denied) as exc:
        setup_call(engine, reader, "doorman.disable", {"plugin": "box"})
    assert exc.value.code == "role"
    # an old session row with a plugin allowlist limits nothing any more: the plugins' settings decide
    engine.db.exec("UPDATE sessions SET plugin_allowlist=? WHERE id=?", ('["archive"]', agent.session["id"]))
    assert "box" in [p["name"] for p in engine.setup.read(agent.session, agent.key, "doorman.plugins")]

    other = Agent(engine)
    client = TestClient(create_agent_app(engine))
    headers = {"Authorization": f"Bearer {other.token}"}
    caps = client.get("/v1/capabilities", headers=headers).json()
    assert caps["setup"]["enabled"] and "doorman.configure" in caps["setup"]["tools"]
    listed = client.post("/v1/read/doorman.plugins", headers=headers, json={}).json()
    assert any(p["name"] == "box" for p in listed["data"])
    done = client.post("/v1/tools/doorman.configure", headers=headers,
                       json={"args": {"plugin": "box", "set": {"archive_months": 6}}}).json()
    assert done["status"] == "done"
    refused = client.post("/v1/tools/doorman.configure", headers=headers,
                          json={"args": {"plugin": "box", "set": {"smtp_host": "evil"}}})
    assert refused.status_code == 403 and refused.json()["code"] == "setting"
