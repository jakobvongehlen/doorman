"""Network watch from the agent's side: `doorman egress ...`, `doorman activity ...` (with the Claude Code
hook that never fails a tool call), the MCP tool request_network_access and the Hermes plugin."""

import importlib.util
import io
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from doorman import clock
from doorman.api.agent import create_agent_app
from conftest import make_engine
from test_api import through
from test_mcp_server import Mcp

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "deploy/egress/hermes-plugin/doorman-activity"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    engine = make_engine(tmp_path)
    token = engine.auth.create_key("claude", "solo")
    agent = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})
    yield engine, agent
    clock.reset()


def run(cli, argv):
    """main(argv) and its exit code (0 when it returned)."""
    try:
        cli.main(argv)
    except SystemExit as stop:
        return stop.code or 0
    return 0


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_cli_egress_request_and_wait(setup, capsys):
    engine, agent = setup
    cli = through(agent)
    assert run(cli, ["egress", "request", "timetable.example", "--reason", "the course times"]) == 0
    asked = json.loads(capsys.readouterr().out)
    assert asked["status"] == "open" and asked["target"] == "timetable.example"
    assert asked["next"].startswith(f"doorman wait egress-request:{asked['id']}")
    assert run(cli, ["status"]) == 0
    assert f"network  egress-request:{asked['id']}  timetable.example" in capsys.readouterr().out
    assert run(cli, ["egress", "requests", "--out", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["egress_requests"][0]["id"] == asked["id"]

    # nobody decides within a second: still waiting (10); then the owner allows it once: 0
    assert run(cli, ["wait", f"egress-request:{asked['id']}", "--timeout", "1"]) == cli.EXIT_STILL_WAITING
    capsys.readouterr()
    engine.egress.decide(asked["id"], "once")
    assert run(cli, ["wait", f"egress-request:{asked['id']}", "--out", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["egress_request"]["scope"] == "once"

    # ask and wait in one go: the owner decides meanwhile
    def decide(decision):
        for _ in range(100):
            open_ = engine.egress.open_requests()
            if open_:
                engine.egress.decide(open_[0]["id"], decision)
                return
            time.sleep(0.05)

    for decision, code in (("always", 0), ("deny", cli.EXIT_DENIED)):
        timer = threading.Thread(target=decide, args=(decision,))
        timer.start()
        got = run(cli, ["egress", "request", f"{decision}.example", "--reason", "a test", "--wait", "20",
                        "--out", "json"])
        timer.join()
        out = json.loads(capsys.readouterr().out)
        assert got == code and out["egress_request"]["target"] == f"{decision}.example", out
    # nobody answers within a day: expired, a refusal too (3)
    run(cli, ["egress", "request", "late.example", "--reason", "a test", "--out", "json"])
    late = json.loads(capsys.readouterr().out)
    clock.advance(25 * 3600)
    assert run(cli, ["wait", f"egress-request:{late['id']}", "--timeout", "0"]) == cli.EXIT_DENIED
    assert '"expired"' in capsys.readouterr().out

    # what the proxy blocked, one line each
    agent.get("/v1/capabilities")  # the key is seen from TestClient's address
    engine.egress.ingest([{"ts": clock.now().timestamp(), "client_ip": "testclient", "kind": "http",
                           "host": "paste.example", "ip": "203.0.113.5", "port": 443, "method": "POST", "path": "/",
                           "status": 403, "bytes_up": 10, "bytes_down": 0, "decision": "deny",
                           "rule": "exfil_upload", "detail": "a paste service", "leak": None, "process": None,
                           "duration_ms": 5, "scanned": True}])
    assert run(cli, ["egress", "blocked", "--limit", "5"]) == 0
    text = capsys.readouterr().out
    assert '"host": "paste.example"' in text and '"rule": "exfil_upload"' in text.splitlines()[1]


def hook(cli, monkeypatch, payload):
    monkeypatch.setattr("sys.stdin", io.StringIO(payload if isinstance(payload, str) else json.dumps(payload)))
    return run(cli, ["activity", "hook"])


def test_cli_activity_hook_pre_and_post(setup, monkeypatch, capsys):
    engine, agent = setup
    cli = through(agent)
    bash = {"tool_name": "Bash", "tool_input": {"command": "curl -s https://example.org", "description": "x"},
            "tool_use_id": "toolu_1", "session_id": "s1"}
    assert hook(cli, monkeypatch, {"hook_event_name": "PreToolUse", **bash}) == 0
    [row] = engine.db.all("SELECT * FROM agent_activity")
    assert (row["call_id"], row["tool"], row["summary"], row["status"]) == \
        ("toolu_1", "Bash", "curl -s https://example.org", "running")
    assert hook(cli, monkeypatch, {"hook_event_name": "PostToolUse", **bash, "tool_response": {"stdout": "x"}}) == 0
    [row] = engine.db.all("SELECT * FROM agent_activity")
    assert row["status"] == "ok" and row["ended"] is not None
    assert capsys.readouterr().out == ""  # a hook's stdout would reach Claude Code: nothing there

    hook(cli, monkeypatch, {"hook_event_name": "PreToolUse", "tool_name": "WebFetch", "tool_use_id": "toolu_2",
                            "tool_input": {"url": "https://example.org/a", "prompt": "the times"}})
    hook(cli, monkeypatch, {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_use_id": "toolu_3",
                            "tool_input": {"file_path": "/tmp/a", "content": "y" * 1000}})
    hook(cli, monkeypatch, {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "toolu_4",
                            "tool_input": {"command": "echo " + "z" * 900}})
    hook(cli, monkeypatch, {"hook_event_name": "PostToolUseFailure", "tool_name": "Bash", "tool_use_id": "toolu_4",
                            "tool_input": {"command": "echo " + "z" * 900}})
    rows = {r["call_id"]: r for r in engine.db.all("SELECT * FROM agent_activity")}
    assert rows["toolu_2"]["summary"] == "https://example.org/a"
    assert rows["toolu_3"]["summary"].startswith('{"file_path":"/tmp/a"') and len(rows["toolu_3"]["summary"]) <= 300
    assert len(rows["toolu_4"]["summary"]) == 500 and rows["toolu_4"]["status"] == "error"

    # by hand, for agents without hooks
    assert run(cli, ["activity", "start", "--call-id", "c9", "--tool", "browser", "--summary", "open the page"]) == 0
    assert run(cli, ["activity", "end", "--call-id", "c9", "--tool", "browser", "--status", "ok"]) == 0
    capsys.readouterr()
    assert engine.db.one("SELECT status FROM agent_activity WHERE call_id='c9'")["status"] == "ok"


def test_cli_activity_hook_never_fails(setup, monkeypatch, capsys):
    cli = importlib.util.module_from_spec(spec := importlib.util.spec_from_file_location(
        "doorman_cli", ROOT / "doorman/agent_skill/scripts/doorman.py"))
    spec.loader.exec_module(cli)
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "t",
             "tool_input": {"command": "ls"}}
    monkeypatch.setenv("DOORMAN_URL", f"http://127.0.0.1:{free_port()}")
    monkeypatch.setenv("DOORMAN_TOKEN", "dmn_nothing")
    started = time.monotonic()
    assert hook(cli, monkeypatch, event) == 0  # nobody listens
    assert time.monotonic() - started < 5
    assert "doorman activity hook" in capsys.readouterr().err
    assert hook(cli, monkeypatch, "not json") == 0
    assert hook(cli, monkeypatch, {"hook_event_name": "Stop"}) == 0
    monkeypatch.delenv("DOORMAN_TOKEN")
    assert hook(cli, monkeypatch, event) == 0
    # a server that never answers: given up after 2 s
    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen()
    monkeypatch.setenv("DOORMAN_TOKEN", "dmn_nothing")
    monkeypatch.setenv("DOORMAN_URL", f"http://127.0.0.1:{silent.getsockname()[1]}")
    started = time.monotonic()
    try:
        assert hook(cli, monkeypatch, event) == 0
    finally:
        silent.close()
    assert time.monotonic() - started < 4
    assert capsys.readouterr().out == ""


def test_mcp_request_network_access(setup):
    engine, agent = setup
    mcp = Mcp(agent)
    tools = {t["name"]: t for t in mcp.rpc("tools/list")["result"]["tools"]}
    assert tools["request_network_access"]["inputSchema"]["required"] == ["target", "reason"]
    text, error = mcp.tool("request_network_access", target="timetable.example", reason="the course times")
    assert not error
    asked = json.loads(text)["egress_request"]
    assert asked["status"] == "open" and asked["target"] == "timetable.example"
    engine.egress.decide(asked["id"], "deny")
    state = json.loads(mcp.tool("wait", **{"for": f"egress-request:{asked['id']}", "timeout": 0})[0])
    assert state["outcome"] == "denied"
    text, error = mcp.tool("request_network_access", target="https://x.example/", reason="why not")
    assert error and '"invalid"' in text


class Recorder(BaseHTTPRequestHandler):
    seen: list = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen.append((self.path, self.headers.get("Authorization"), self.headers.get("X-Doorman-Session"),
                                body))
        payload = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def load_plugin():
    spec = importlib.util.spec_from_file_location("doorman_activity_plugin", PLUGIN / "__init__.py")
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    return plugin


def test_hermes_plugin_posts_activity(tmp_path, monkeypatch):
    manifest = yaml.safe_load((PLUGIN / "plugin.yaml").read_text())
    assert manifest["name"] == "doorman-activity" and manifest["version"] == "1.0" and manifest["description"]
    assert manifest["provides_hooks"] == ["pre_tool_call", "post_tool_call"]
    assert manifest["requires_env"] == ["DOORMAN_URL", "DOORMAN_TOKEN"]
    assert "hermes plugins enable doorman-activity" in (PLUGIN / "README.md").read_text()

    Recorder.seen = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("DOORMAN_URL", f"http://127.0.0.1:{server.server_address[1]}/")
    monkeypatch.setenv("DOORMAN_TOKEN", "dmn_test")
    monkeypatch.setenv("DOORMAN_SESSION", "sess-1")
    plugin = load_plugin()
    hooks = {}

    class Ctx:
        def register_hook(self, name, fn):
            hooks[name] = fn

    plugin.register(Ctx())
    assert set(hooks) == {"pre_tool_call", "post_tool_call"}
    try:
        hooks["pre_tool_call"](tool_name="terminal", args={"command": "curl -s https://example.org"},
                               task_id="t", session_id="s", tool_call_id="call_1", turn_id="u")
        hooks["post_tool_call"](tool_name="terminal", args={"command": "curl -s https://example.org"},
                                tool_call_id="call_1", result="ok", duration_ms=12, status="success",
                                error_type=None, error_message=None, something_new=1)
        hooks["pre_tool_call"](tool_name="web_extract", args={"urls": ["https://example.org/" + "a" * 400]},
                               tool_call_id="call_2")
        for _ in range(100):
            if len(Recorder.seen) == 3:
                break
            time.sleep(0.05)
    finally:
        server.shutdown()
        server.server_close()
    first, second, third = Recorder.seen
    assert first == ("/v1/activity", "Bearer dmn_test", "sess-1", {
        "phase": "start", "call_id": "call_1", "tool": "terminal", "summary": "curl -s https://example.org"})
    assert second[3] == {"phase": "end", "call_id": "call_1", "tool": "terminal",
                         "summary": "curl -s https://example.org", "status": "success"}
    assert third[3]["summary"].startswith('{"urls":["https://example.org/aaa') and len(third[3]["summary"]) <= 300

    # nobody listens, odd arguments, no settings: nothing raises, nothing blocks
    monkeypatch.setenv("DOORMAN_URL", f"http://127.0.0.1:{free_port()}")
    started = time.monotonic()
    hooks["pre_tool_call"](tool_name="terminal", args="not a dict")
    hooks["post_tool_call"]()
    monkeypatch.delenv("DOORMAN_TOKEN")
    hooks["pre_tool_call"](tool_name="terminal", args={"command": "ls"}, tool_call_id="x")
    assert time.monotonic() - started < 0.5
    plugin.flush(5)
