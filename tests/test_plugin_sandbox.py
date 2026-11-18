"""Plugins in their own process (plugin_host.py, plugin_runner.py, sandbox.py): what still works through
the process boundary, and what a plugin can no longer reach. The fake_probe plugin tries the things."""

import asyncio
import json
import os
import socket
import socketserver
import threading
import time

import pytest
from cryptography.fernet import Fernet

from doorman import sandbox
from doorman.plugin_api import Denied, NotSent, PluginError
from doorman.plugin_host import NetworkPolicy, RemotePlugin, fill, parse_host
from doorman.server import _job
from conftest import FAKE_PLUGINS, Agent, make_engine

pytestmark = pytest.mark.skipif(sandbox.landlock_abi() < 4, reason="needs Landlock 4 (Linux 6.7+)")


class Echo(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"pong " + self.rfile.readline())


@pytest.fixture
def echo():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture
def boxed(tmp_path, echo, monkeypatch):
    """An engine with every plugin in its own process; `probe` may reach the echo server only."""
    monkeypatch.setenv("DOORMAN_VAULT_KEY", Fernet.generate_key().decode())
    engine = make_engine(tmp_path, plugin_sandbox=True, plugin_paths=[FAKE_PLUGINS], plugins={
        "notes": {"enabled": True},
        "probe": {"type": "fake_probe", "enabled": True, "config": {"allowed": f"127.0.0.1:{echo}"}},
        "other": {"type": "fake_probe", "enabled": True},
    })
    engine.vault.set("probe", "secret", "probe's own")
    engine.vault.set("other", "secret", "other's own")
    yield engine
    for name in list(engine.registry.instances):
        engine.registry.invalidate(name)


def probe(engine, action, name="probe", **params):
    return engine.registry.instance(name).run_read("probe", {"action": action, **params})


def tool(engine, full_name):
    return engine.registry.find_tool(full_name)[2]


def test_a_plugin_runs_in_a_process_of_its_own_with_only_its_own_credentials(boxed, tmp_path):
    plugin = boxed.registry.instance("probe")
    assert isinstance(plugin, RemotePlugin)
    me = probe(boxed, "whoami")["result"]
    assert me["pid"] != os.getpid()
    assert me["secret"] == "probe's own"
    assert "DOORMAN_VAULT_KEY" not in me["env"]  # Doorman has it in its environment; the plugin doesn't
    assert me["cwd"] == str((tmp_path / "data" / "plugins" / "probe").resolve())
    assert probe(boxed, "whoami", name="other")["result"]["secret"] == "other's own"


def test_files_outside_its_folder_are_out_of_reach(boxed, tmp_path):
    data = tmp_path / "data"
    probe(boxed, "whoami", name="other")
    (data / "plugins" / "other" / "private.txt").write_text("other's file")
    for path in (data / "vault.key", data / "vault.enc", data / "doorman.db", data / "plugins" / "other" / "private.txt"):
        if path.exists():
            out = probe(boxed, "read", path=str(path))
            assert not out["ok"] and "PermissionError" in out["error"], path
    assert not probe(boxed, "list", path=str(data))["ok"]
    assert not probe(boxed, "write", path=str(tmp_path / "escaped.txt"))["ok"]
    assert not (tmp_path / "escaped.txt").exists()
    own = data / "plugins" / "probe" / "mine.txt"
    assert probe(boxed, "write", path=str(own))["ok"] and own.read_text() == "probe"
    assert probe(boxed, "read", path="/etc/hostname")["ok"]  # the system's own files stay readable


def test_the_doorman_process_is_out_of_reach(boxed):
    for action in ("environ", "ptrace", "signal"):
        out = probe(boxed, action, pid=os.getpid())
        assert not out["ok"], (action, out)


def test_connections_go_through_the_doorman_and_only_where_the_plugin_may(boxed, echo):
    assert probe(boxed, "connect", host="127.0.0.1", port=echo) == {"ok": True, "result": "pong ping\n"}
    assert probe(boxed, "connect", host="localhost", port=echo)["ok"] is False  # another host name: not listed
    refused = probe(boxed, "connect", host="127.0.0.1", port=echo + 1 if echo < 65535 else echo - 1)
    assert not refused["ok"] and "may not connect" in refused["error"]
    assert not probe(boxed, "connect", host="example.com", port=443)["ok"]
    raw = probe(boxed, "raw_connect", host="127.0.0.1", port=echo)  # past the redirect, straight to the kernel
    assert not raw["ok"] and "PermissionError" in raw["error"]
    assert not probe(boxed, "udp", host="127.0.0.1", port=echo)["ok"]
    assert not probe(boxed, "connect", name="other", host="127.0.0.1", port=echo)["ok"]  # other has no list


def test_a_tool_runs_and_reverts_through_the_engine(boxed):
    agent = Agent(boxed)
    out = agent.call("probe.note", {"text": "hello"})
    assert out["status"] == "done", out
    assert (boxed.config.data_dir / "plugins" / "probe" / "notes.txt").read_text() == "hello\n"
    reverted = boxed.revert_entry(out["entry_id"])
    assert reverted.get("status") in ("reverted", "done") or reverted.get("ok") is not False, reverted
    assert (boxed.config.data_dir / "plugins" / "probe" / "notes.txt").read_text() == ""


def test_a_built_in_plugin_works_in_its_process(boxed):
    agent = Agent(boxed)
    created = agent.call("notes.create", {"title": "Groceries", "body": "milk"})
    assert created["status"] == "done", created
    assert isinstance(boxed.registry.instance("notes"), RemotePlugin)
    listed = agent.read("notes.list")
    assert "Groceries" in str(listed)


def test_the_recipient_check_asks_an_address_book_in_its_process(boxed):
    agent = Agent(boxed)
    note_id = agent.call("notes.create", {"title": "Groceries"})["result"]["id"]
    out = agent.call("notes.send_copy", {"id": note_id, "to": "anna@probe.example"})
    assert out["warnings"] == []
    known = boxed.approvals.get(out["approval_id"])["entries"][0]["known_destinations"]
    assert [d["source"] for d in known] == ["in your contacts (Probe probe)"]  # the first that knows her
    assert boxed.registry.instance("notes").known_recipients([["email", "anna@probe.example"]]) == {}  # not its job
    assert agent.call("notes.send_copy", {"id": note_id, "to": "x@evil.example"})["warnings"]


def test_errors_keep_their_kind(boxed):
    fail = tool(boxed, "probe.fail")
    with pytest.raises(Denied) as denied:
        fail.execute({"kind": "denied"}, None)
    assert denied.value.code == "probe_code"
    with pytest.raises(NotSent):
        fail.execute({"kind": "notsent"}, None)
    with pytest.raises(PluginError) as bug:
        fail.execute({"kind": "key"}, None)
    assert type(bug.value).__name__ == "KeyError"


def test_attachments_come_through_the_doorman_and_only_those_the_call_names(boxed):
    agent = Agent(boxed)
    note_id = agent.call("notes.create", {"title": "Plan", "body": "the plan"})["result"]["id"]
    result = agent.call("probe.attach", {"ref": f"notes:{note_id}"})["result"]
    assert result == {"filename": "Plan.txt", "size": len("Plan\n\nthe plan"), "text": "Plan\n\nthe plan"}
    sneaky = agent.call("probe.attach", {"ref": f"notes:{note_id}", "sneaky": True})
    assert sneaky["status"] == "failed" and "isn't among this call's arguments" in sneaky["error"]


def test_a_plugin_opens_refs_only_inside_a_checked_write(boxed):
    """A plugin whose parser got owned can't use resolve_ref to read another plugin's items: not from a
    read whose arguments name the ref, not called directly, and not from a ref planted in its own event
    cursor, which Doorman stores and passes back on the next poll."""
    agent = Agent(boxed)
    note_id = agent.call("notes.create", {"title": "Secret", "body": "the owner's secret"})["result"]["id"]
    ref = f"notes:{note_id}"
    out = probe(boxed, "resolve", path=ref)
    assert out["ok"] is False and "wasn't part of the checked request" in out["error"]
    with pytest.raises(PluginError, match="wasn't part of the checked request"):
        tool(boxed, "probe.attach").execute({"ref": ref}, None)
    # a compromised plugin picks it itself
    boxed.registry.save_instance("other", boxed.registry.configured()["other"]["type"], {"plant": ref}, False)
    boxed.poll_triggers(force=True)
    boxed.poll_triggers(force=True)
    [leak] = boxed.db.all("SELECT data FROM events WHERE plugin='other'")
    assert "the owner's secret" not in leak["data"] and "wasn't part of the checked request" in leak["data"]
    # the same ref inside a checked write still opens
    assert agent.call("probe.attach", {"ref": ref})["result"]["text"] == "Secret\n\nthe owner's secret"


def test_a_credential_the_plugin_keeps_reaches_the_vault(boxed):
    tool(boxed, "probe.remember").execute({"key": "token", "value": "fresh"}, None)
    assert boxed.vault.get("probe")["token"] == "fresh"
    boxed.registry.instance("probe").close()
    boxed.registry.invalidate("probe")
    assert boxed.registry.instance("probe").credentials["token"] == "fresh"


def test_a_crash_fails_the_call_and_the_next_call_starts_a_fresh_process(boxed):
    before = probe(boxed, "whoami")["result"]["pid"]
    with pytest.raises(PluginError, match="stopped during execute"):
        tool(boxed, "probe.crash").execute({}, None)
    after = probe(boxed, "whoami")["result"]["pid"]
    assert after != before


def test_a_call_that_hangs_is_cut_off(boxed):
    plugin = boxed.registry.instance("probe")
    plugin.timeout = 1
    started = time.monotonic()
    with pytest.raises(PluginError, match="didn't answer within 1 s"):
        tool(boxed, "probe.sleep").execute({"seconds": 30}, None)
    assert time.monotonic() - started < 10
    assert probe(boxed, "whoami")["ok"]


def test_an_idle_process_stops_and_comes_back(boxed):
    plugin = boxed.registry.instance("probe")
    plugin.idle_seconds = 0.5
    first = probe(boxed, "whoami")["result"]["pid"]
    deadline = time.monotonic() + 10
    while plugin._process is not None and time.monotonic() < deadline:
        time.sleep(0.2)
    assert plugin._process is None
    assert probe(boxed, "whoami")["result"]["pid"] != first


def test_a_jobs_events_cross_the_process(boxed):
    """A job's events come back from the plugin's own process with its status, and go where polled ones go."""
    job = next(j for j in boxed.registry.manifest("probe")["jobs"] if j["name"] == "check")
    asyncio.run(_job(boxed, "probe", job, {}))
    assert boxed.job_status("probe")["check"]["status"] == {"summary": "1 new", "events": 1}
    [row] = boxed.db.all("SELECT * FROM events WHERE plugin='probe'")
    assert (row["type"], row["ref"]) == ("posted", "probe:1")
    data = json.loads(row["data"])
    assert data["title"] == "Exam moved" and data["pid"] != os.getpid()


def test_a_process_that_is_stopped_closes_its_plugin_first(boxed):
    pid = probe(boxed, "whoami")["result"]["pid"]
    boxed.registry.invalidate("probe")
    assert (boxed.config.data_dir / "plugins" / "probe" / "closed").read_text() == str(pid)


def test_sandbox_false_keeps_a_plugin_in_the_doorman(tmp_path):
    engine = make_engine(tmp_path, plugin_sandbox=True, plugins={"notes": {"enabled": True, "sandbox": False}})
    assert not isinstance(engine.registry.instance("notes"), RemotePlugin)


def test_the_data_folder_is_passable_but_not_readable_for_others(boxed, tmp_path):
    data = tmp_path / "data"
    assert oct(data.stat().st_mode & 0o777) == "0o711"
    assert oct((data / "plugins").stat().st_mode & 0o777) == "0o711"
    assert oct((data / "doorman.db").stat().st_mode & 0o777) == "0o600"


# ------------------------------------------------------------------ the network list

def test_network_entries_fill_in_the_instances_settings():
    config, credentials = {"url": "https://cloud.example.com/dav/", "nextcloud": {"url": "https://nc.example.org"}}, \
        {"feed": "webcal://feeds.example.net/x.ics"}
    assert fill("{url}", config, credentials) == ("https://cloud.example.com/dav/", True)
    assert fill("{nextcloud.url}", config, credentials) == ("https://nc.example.org", True)
    assert fill("{feed}", config, credentials)[0] == "webcal://feeds.example.net/x.ics"
    assert fill("{missing|http://127.0.0.1:8720}", config, credentials) == ("http://127.0.0.1:8720", False)
    assert fill("{missing}", config, credentials) == (None, True)
    assert fill("graph.microsoft.com", config, credentials) == ("graph.microsoft.com", False)
    assert parse_host("https://cloud.example.com/dav/") == ("cloud.example.com", None)
    assert parse_host("imap.example.com:993") == ("imap.example.com", 993)
    assert parse_host("[::1]:8080") == ("::1", 8080)


def test_a_host_an_outside_plugin_wrote_into_its_manifest_must_be_public(echo):
    outside = NetworkPolicy.build("x", ["127.0.0.1"], None, {}, {}, builtin=False)
    with pytest.raises(Denied, match="local address"):
        outside.connect("127.0.0.1", echo, socket.AF_INET, 5)
    owner_typed = NetworkPolicy.build("x", ["{host}"], None, {"host": "127.0.0.1"}, {}, builtin=False)
    owner_typed.connect("127.0.0.1", echo, socket.AF_INET, 5).close()
    added_by_owner = NetworkPolicy.build("x", [], ["127.0.0.1"], {}, {}, builtin=False)
    added_by_owner.connect("127.0.0.1", echo, socket.AF_INET, 5).close()
    assert NetworkPolicy.build("x", "any", None, {}, {}, builtin=False).open is False  # only the owner opens it
    assert NetworkPolicy.build("x", [], "any", {}, {}, builtin=False).open is True
    wildcard = NetworkPolicy.build("x", ["*.icloud.com"], None, {}, {}, builtin=True)
    assert wildcard.match("p42-caldav.icloud.com", 443) and not wildcard.match("icloud.com.evil.net", 443)


def test_playwright_still_finds_doormans_browsers(boxed, tmp_path, monkeypatch):
    """HOME is the plugin's folder in its process; a plugin's Chromium lives under Doorman's HOME."""
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    (tmp_path / "home" / ".cache" / "ms-playwright").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    env = boxed.registry.instance("probe")._env()
    assert env["PLAYWRIGHT_BROWSERS_PATH"] == str(tmp_path / "home" / ".cache" / "ms-playwright")
    assert env["HOME"].endswith("plugins/probe")
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "/opt/ms-playwright")  # the image sets it: that wins
    assert boxed.registry.instance("probe")._env()["PLAYWRIGHT_BROWSERS_PATH"] == "/opt/ms-playwright"
