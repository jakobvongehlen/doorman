"""Doorman as an MCP server (api/mcp.py): /mcp on the agent port, the agent keys, a handful of generic tools
over the REST API, third-party content spotlit in the text."""

import base64
import json

import pytest
from fastapi.testclient import TestClient

from doorman import clock
from doorman.api.agent import create_agent_app
from conftest import FAKE_PLUGINS, make_engine


@pytest.fixture
def world(tmp_path):
    engine = make_engine(tmp_path, plugin_paths=[FAKE_PLUGINS], plugins={
        "mail": {"type": "fake_mail", "enabled": True}, "notes": {"enabled": True}})
    engine.poll_triggers()  # the first poll only notes where "now" is
    token = engine.auth.create_key("claude", "solo")
    yield engine, TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})
    clock.reset()


class Mcp:
    def __init__(self, http):
        self.http, self.next = http, 0

    def rpc(self, method, params=None):
        self.next += 1
        out = self.http.post("/mcp", json={"jsonrpc": "2.0", "id": self.next, "method": method,
                                           "params": params or {}})
        assert out.status_code == 200, out.text
        body = out.json()
        assert body["id"] == self.next
        return body

    def tool(self, tool, /, **arguments):
        result = self.rpc("tools/call", {"name": tool, "arguments": arguments})["result"]
        [content] = result["content"]
        assert content["type"] == "text"
        return content["text"], result["isError"]


def test_initialize_and_list_the_tools(world):
    _, http = world
    mcp = Mcp(http)
    init = mcp.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "test", "version": "1"}})["result"]
    assert init["protocolVersion"] == "2025-06-18" and init["serverInfo"]["name"] == "doorman"
    assert init["capabilities"] == {"tools": {"listChanged": False}} and "untrusted_" in init["instructions"]
    assert mcp.rpc("initialize", {"protocolVersion": "1999-01-01"})["result"]["protocolVersion"] == "2025-06-18"
    note = http.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert note.status_code == 202
    tools = {t["name"]: t for t in mcp.rpc("tools/list")["result"]["tools"]}
    assert set(tools) == {"caps", "read", "search", "call", "propose", "ask", "wait", "events", "tasks", "upload",
                          "undo", "ask_owner", "request_network_access"}
    for name in ("caps", "read", "search", "wait", "events"):
        assert tools[name]["annotations"]["readOnlyHint"] is True
    assert tools["call"]["annotations"] == {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False,
                                            "openWorldHint": True}
    assert all(t["inputSchema"]["type"] == "object" for t in tools.values())
    assert mcp.rpc("ping")["result"] == {}
    assert mcp.rpc("resources/list")["error"]["code"] == -32601
    batch = http.post("/mcp", json=[{"jsonrpc": "2.0", "id": "a", "method": "ping"},
                                    {"jsonrpc": "2.0", "method": "notifications/initialized"}]).json()
    assert batch == [{"jsonrpc": "2.0", "id": "a", "result": {}}]


def test_only_agent_keys_and_only_local_pages(world):
    engine, http = world
    anonymous = TestClient(create_agent_app(engine))
    out = anonymous.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert out.status_code == 401 and out.headers["WWW-Authenticate"].startswith("Bearer")
    out = http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    headers={"Origin": "https://evil.example"})
    assert out.status_code == 403
    out = http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}, headers={"Origin": "http://localhost:3000"})
    assert out.status_code == 200
    assert http.get("/mcp").status_code == 405
    assert http.post("/mcp", content=b"{not json").json()["error"]["code"] == -32700


def test_caps_read_and_call(world):
    engine, http = world
    mcp = Mcp(http)
    text, error = mcp.tool("caps")
    assert not error and "notes.create" in text and '"version"' in text
    text, error = mcp.tool("caps", name="notes.create")
    assert not error and '"params"' in text
    text, error = mcp.tool("call", name="notes.create", args={"title": "Gym", "body": "Thursday at six"})
    assert not error
    created = json.loads(text)
    assert created["status"] == "done"
    text, error = mcp.tool("read", name="notes.list")
    assert not error and "Gym" in text
    text, error = mcp.tool("call", name="notes.nope", args={})
    assert error and "unknown_tool" in text
    mailbox = engine.registry.instance("mail")
    mailbox.add("inbox", "anna@example.com", "Lunch on Friday", "See you at noon")
    text, error = mcp.tool("read", name="mail.search", params={})
    assert not error and "<untrusted_" in text and "comes from a third-party source" in text
    assert "LunchˆonˆFriday" in text  # datamarked, as for doorman read
    text, _ = mcp.tool("read", name="journal")
    assert "notes.create" in text
    uploaded, error = mcp.tool("upload", name="hello.txt", content_base64=base64.b64encode(b"hi").decode())
    assert not error and "upload:" in uploaded
    assert mcp.tool("upload", name="x", content_base64="***")[1] is True


def test_wait_and_events(world):
    engine, http = world
    mcp = Mcp(http)
    created = json.loads(mcp.tool("call", name="notes.create", args={"title": "Gym", "body": "Thu"})[0])
    sent = json.loads(mcp.tool("call", name="notes.send_copy",
                               args={"id": created["result"]["id"], "to": "x@elsewhere.example"})[0])
    assert sent["status"] == "waiting_approval"
    state = json.loads(mcp.tool("wait", **{"for": str(sent["entry_id"]), "timeout": 0})[0])
    assert state["done"] is False
    engine.approvals.decide(sent["approval_id"], False, note="Not this week")
    state = json.loads(mcp.tool("wait", **{"for": f"entry:{sent['entry_id']}"})[0])
    assert state["outcome"] == "declined" and state["entry"]["note"] == "Not this week"

    engine.registry.instance("mail").add("inbox", "anna@example.com", "Agenda", "...")
    clock.advance(6 * 60)
    engine.poll_triggers()
    text, error = mcp.tool("events", wait=0)
    assert not error
    head, *lines = text.splitlines()
    cursor = json.loads(head)["cursor"]
    decided = json.loads(lines[0])
    assert decided["type"] == "approval_decided" and decided["note"] == "Not this week"
    assert "<untrusted_" in text and "mail:m1" in text
    text, _ = mcp.tool("events", after=cursor, wait=0)
    assert text.splitlines()[-1] == "nothing new"
    assert engine.feed.cursor(engine.auth.list_keys()[0]) == cursor

    # a question to the owner, and a wait for incoming things only
    asked = json.loads(mcp.tool("ask_owner", question="Tue or Wed?", options=["Tue", "Wed"])[0])["owner_question"]
    engine.owner_questions.answer(asked["id"], answer="Wed, after lunch")
    state = json.loads(mcp.tool("wait", **{"for": f"owner-question:{asked['id']}", "timeout": 0})[0])
    assert state["outcome"] == "answered" and state["owner_question"]["answer"] == "Wed, after lunch"
    text, _ = mcp.tool("events", wait=0, wake="incoming")
    assert '"owner_answered"' in text and '"woke": false' in text


def test_tasks(world):
    engine, http = world
    mcp = Mcp(http)
    task_id = engine.tasks.create("Tidy the calendar")
    listed = json.loads(mcp.tool("tasks", action="list")[0])
    assert [t["id"] for t in listed["tasks"]] == [task_id]
    claimed = json.loads(mcp.tool("tasks", action="claim")[0])
    assert claimed["task"]["id"] == task_id
    renewed = json.loads(mcp.tool("tasks", action="renew", minutes=90)[0])
    assert renewed["task_id"] == task_id
    assert json.loads(mcp.tool("tasks", action="report", summary="tidied")[0]) == {"ok": True}
    assert engine.tasks.get(task_id)["status"] == "done"
    text, error = mcp.tool("tasks", action="renew")
    assert error and "no claimed task" in text


def test_mcp_calls_are_noted_at_the_callers_address_not_127_0_0_1(tmp_path):
    """The tools run as requests to the REST API inside this process: they carry the agent's own address, so
    the network watch ties its connections, leaks and decoy keys to its key (egress client_seen)."""
    engine = make_engine(tmp_path, honeytokens=["canary-7f3a9c2e"])
    engine.egress.new_token()
    token = engine.auth.create_key("claude", "solo")
    key_id = engine.auth.list_keys()[0]["id"]
    http = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"},
                      client=("172.29.0.3", 41000))
    try:
        mcp = Mcp(http)
        mcp.rpc("initialize", {"protocolVersion": "2025-06-18"})  # no tool: still noted
        assert engine.egress.keys_for_ip("172.29.0.3") == [key_id]
        mcp.tool("caps")
        mcp.tool("read", name="notes.list_notes", params={})
        ips = {r["ip"] for r in engine.db.all("SELECT ip FROM agent_addresses WHERE key_id=?", (key_id,))}
        assert ips == {"172.29.0.3"}
        # so a honeytoken leaving from that address pauses the MCP agent's key
        out = engine.egress.check({"client_ip": "172.29.0.3", "host": "x.example", "prints": [],
                                   "honeytokens": ["canary-7f3a9c2e"]})
        assert out["action"] == "deny" and engine.auth.paused(key_id)
    finally:
        clock.reset()
