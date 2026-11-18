"""What an agent learns about its capabilities cheaply: the brief form, one schema at a time, a version to
cache them by, and close names when it gets one wrong."""

import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from doorman.api.agent import create_agent_app, one_line
from doorman.plugin_api import Denied
from conftest import Agent, make_engine

CLI = Path(__file__).resolve().parents[1] / "doorman" / "agent_skill" / "scripts" / "doorman.py"


@pytest.fixture
def world(tmp_path):
    engine = make_engine(tmp_path, plugins={
        "notes": {"enabled": True},
        "mail": {"type": "mail_imap", "enabled": True, "config": {"imap_host": "127.0.0.1"}}})
    agent = Agent(engine)
    client = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {agent.token}"})
    return engine, agent, client


def test_brief_is_a_line_per_read_and_tool_with_its_mode(world, capsys):
    engine, agent, client = world
    engine.plugin_setup.switch("mail", tool="send", mode="off")
    full = client.get("/v1/capabilities").json()
    brief = client.get("/v1/capabilities", params={"brief": "true"}).json()
    assert brief["version"] == full["version"] and len(brief["version"]) == 12
    mail = next(p for p in brief["plugins"] if p["name"] == "mail")
    tools = {t["name"]: (t["kind"], t["mode"]) for t in mail["tools"]}
    assert tools["mail.reply"] == ("send", "ask") and tools["mail.move"] == ("write", "auto")
    assert tools["mail.send"] == ("send", "off")  # switched off: listed as off, not left out
    assert {r["name"]: r["mode"] for r in mail["reads"]}["mail.search"] == "on"
    assert all("params" not in t for t in mail["tools"]) and "\n" not in mail["about"]
    assert len(str(brief)) < len(str(full)) / 3
    # the CLI's text form
    spec = importlib.util.spec_from_file_location("doorman_cli", CLI)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    cli.print_brief(brief)
    assert {t["name"]: t["args"] for t in mail["tools"]}["mail.move"].startswith("id, ")
    out = capsys.readouterr().out
    assert "  mail.read(id, max_chars?)  " in out and "auto  mail.move(id, folder)  " in out and "?)" in out
    cli.print_plugins(brief)
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == len(brief["plugins"]) and any(l.startswith("mail ") and "tools" in l for l in lines)


def test_a_write_that_can_become_a_send_says_when(tmp_path, capsys):
    # an agent learns before the call that a task on a shared list waits for the owner and can't be undone
    engine = make_engine(tmp_path, plugins={"caldav": {"type": "caldav", "enabled": True,
                                                       "config": {"url": "http://127.0.0.1:9/dav/"}}})
    agent = Agent(engine)
    client = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {agent.token}"})
    brief = client.get("/v1/capabilities", params={"brief": "true"}).json()
    tools = {t["name"]: t for t in brief["plugins"][0]["tools"]}
    assert tools["caldav.create_task"]["kind"] == "write+send"
    assert tools["caldav.create_task"]["may_ask"] == "may ask the owner and then can't be undone: on a shared list"
    assert "guests other than you" in tools["caldav.create_event"]["may_ask"]
    assert "invitation" in tools["caldav.delete_event"]["may_ask"] and "may_ask" not in tools["caldav.respond"]
    assert client.get("/v1/capabilities/caldav.create_task").json()["may_ask"].endswith("on a shared list")
    spec = importlib.util.spec_from_file_location("doorman_cli", CLI)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    cli.print_brief(brief)
    line = next(l for l in capsys.readouterr().out.splitlines() if "caldav.create_task(" in l)
    assert line.endswith("[may ask the owner and then can't be undone: on a shared list]")


def test_the_version_follows_what_the_caps_say(world):
    engine, agent, client = world
    first = client.get("/v1/capabilities").json()["version"]
    assert client.get("/v1/capabilities").json()["version"] == first  # the same caps, the same version
    engine.plugin_setup.switch("notes", tool="create", mode="off")
    second = client.get("/v1/capabilities").json()["version"]
    assert second != first
    entry =engine.journal.create(kind="action", session_id=agent.session_id, tool="notes.x", status="done")
    assert client.get(f"/v1/journal/{entry}").json()["caps_version"] == second


def test_help_gives_one_schema_and_close_names(world):
    engine, agent, client = world
    reply = client.get("/v1/capabilities/mail.reply").json()
    assert reply["kind"] == "tool" and reply["plugin"] == "mail" and "id" in reply["params"]["properties"]
    assert "start" in client.get("/v1/capabilities/agenda").json()["params"]["properties"]
    wrong = client.get("/v1/capabilities/mail.replay")
    assert wrong.status_code == 403 and "did you mean mail.reply" in wrong.json()["reason"]


def test_unknown_names_suggest_close_ones(world):
    engine, agent, client = world
    with pytest.raises(Denied) as exc:
        agent.call("mail.sned", {})
    assert exc.value.code == "unknown_tool" and "did you mean mail.send" in exc.value.reason
    with pytest.raises(Denied) as exc:
        agent.call("mail.search", {})
    assert "mail.search is a read: doorman read mail.search" in exc.value.reason
    with pytest.raises(Denied) as exc:
        agent.read("mial.search", {})
    assert exc.value.code == "unknown_plugin" and "did you mean mail.search" in exc.value.reason
    with pytest.raises(Denied) as exc:
        agent.read("notes", {})
    assert "unknown read notes" in exc.value.reason


def load_cli():
    spec = importlib.util.spec_from_file_location("doorman_cli", CLI)
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    return cli


def test_cli_help_and_mistakes_give_a_line_not_a_traceback(world, monkeypatch, capsys, tmp_path):
    engine, agent, client = world
    cli = load_cli()
    monkeypatch.setenv("DOORMAN_TOKEN", agent.token)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    asked = []
    monkeypatch.setattr(cli, "api", lambda method, path, *a, **kw: asked.append(path) or {"name": "x"})
    cli.main(["help"])  # no name: the commands, and where to start
    out = capsys.readouterr().out
    assert "  journal " in out and "  undo " in out and "doorman caps --brief" in out and not asked
    cli.main(["help", "journal"])  # a command of the CLI: its options, nothing asked of Doorman
    assert "--since" in capsys.readouterr().out and not asked
    cli.main(["help", "search"])  # a command and a read: both
    assert "--out" in capsys.readouterr().out and asked == ["/v1/capabilities/search"]
    for argv, says in ((["jurnal"], "did you mean journal"),
                       (["call", "notes.create", "tags:=[oops"], "field 'tags' isn't JSON"),
                       (["call", "notes.create", f"body@{tmp_path}/missing.txt"], "can't read"),
                       (["propose", "--title", "x", "--json", "{not json"], "the actions isn't JSON"),
                       (["undo"], "undo takes a journal entry"),
                       (["events", "--wait", "900"], "--wait is 0 to 300")):
        with pytest.raises(SystemExit) as stop:
            cli.main(argv)
        assert stop.value.code == cli.EXIT_ERROR and says in capsys.readouterr().err, argv


def test_one_line():
    assert one_line("Send a message. Needs your approval.") == "Send a message"
    assert one_line("x " * 100).endswith("…") and len(one_line("x " * 100)) == 100
