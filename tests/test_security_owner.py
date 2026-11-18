"""Owner-side hardening from the security review (2026-11-09): fresh passkey checks for every way back to
sends that run without asking, new push devices announced and tied to their session, and the headers that
keep the owner app out of frames."""

import re

import pytest
from fastapi.testclient import TestClient

from conftest import make_engine
from doorman import clock
from doorman.api.owner import APP_DIR, create_owner_app
from doorman.mcp.servers import McpPlugin
from doorman.plugin_api import Denied
from fakes.fake_mcp import URL, FakeMcp
from soft_authenticator import SoftAuthenticator
from test_api import CSRF, OWNER_URL, register


def owner_app(tmp_path, **config):
    engine = make_engine(tmp_path, public_url=OWNER_URL, **config)
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL)
    passkey = SoftAuthenticator("localhost", OWNER_URL)
    register(engine, owner, passkey)
    return engine, owner, passkey


def stale(owner, body, name="notes"):
    return owner.post(f"/owner/plugins/{name}", headers=CSRF, json=body)


def needs_passkey(response) -> bool:
    return response.status_code == 403 and response.json()["code"] == "reauth"


# ---------------------------------------------------------------- sends without asking

def test_every_way_back_to_unasked_sends_needs_a_fresh_passkey(tmp_path):
    """A no_approval plugin made read-only, or switched off, sends nothing; switching it back (read-only
    off, the tool or the plugin on again) lets its sends run unasked once more, like setting no_approval
    did, so it takes a passkey check too. Tightening never does."""
    engine, owner, _ = owner_app(tmp_path, plugins={"notes": {"enabled": True, "no_approval": True}})
    unasked = lambda: engine.plugin_setup.unasked_sends("notes", engine.registry.state("notes"))  # noqa: E731
    assert unasked() == {"send_copy"}
    clock.advance(6 * 60)  # still logged in, but the passkey check is older than 5 minutes
    ways = [({"enabled": False}, [{"enabled": True}], {"enabled": True}),
            ({"read_only": True}, [{"read_only": False}, {"tool": "send_copy", "tool_enabled": True},
                                   {"tool": "send_copy", "mode": "auto"}], {"read_only": False}),
            ({"tool": "send_copy", "mode": "off"}, [{"tool": "send_copy", "tool_enabled": True},
                                                    {"tool": "send_copy", "mode": "auto"}],
             {"tool": "send_copy", "tool_enabled": True})]
    for off, back, host in ways:
        assert stale(owner, off).status_code == 200, off          # tightening: no passkey
        assert unasked() == set()
        for body in back:
            assert needs_passkey(stale(owner, body)), (off, body)
        assert unasked() == set()                                  # nothing changed
        engine.plugin_setup.switch("notes", **host)  # on the host (doorman-admin plugin on): no passkey there
        assert unasked() == {"send_copy"}
    # back on as Ask me: nothing runs unasked, so no check; nor for an undoable tool
    assert stale(owner, {"tool": "send_copy", "mode": "off"}).status_code == 200
    assert stale(owner, {"tool": "send_copy", "mode": "ask"}).status_code == 200
    assert stale(owner, {"tool": "create", "mode": "ask"}).status_code == 200
    assert stale(owner, {"tool": "create", "mode": "auto"}).status_code == 200
    assert unasked() == set()
    clock.reset()


def test_a_tool_set_to_auto_doesnt_come_back_unasked_without_a_passkey(tmp_path):
    """The owner set send_copy to Auto, then made the plugin read-only. Setting the tool to Auto again
    (or switching it on) lifts read-only and lets it send unasked: a passkey check, as when Auto was set."""
    engine, owner, _ = owner_app(tmp_path)
    assert stale(owner, {"tool": "send_copy", "mode": "auto"}).status_code == 200   # fresh from the login
    clock.advance(6 * 60)
    assert stale(owner, {"read_only": True}).status_code == 200
    assert needs_passkey(stale(owner, {"tool": "send_copy", "mode": "auto"}))
    assert needs_passkey(stale(owner, {"tool": "send_copy", "tool_enabled": True}))
    assert needs_passkey(stale(owner, {"read_only": False}))
    assert engine.registry.state("notes")["read_only"] is True                   # nothing changed
    clock.reset()


def test_reverting_back_to_unasked_sends_needs_a_fresh_passkey(tmp_path):
    """Reverting the entry that switched an Auto tool Off (or made the plugin read-only) hands back sends
    without asking; reverting one that only tightened further doesn't."""
    engine, owner, passkey = owner_app(tmp_path)
    assert stale(owner, {"tool": "send_copy", "mode": "auto"}).status_code == 200
    clock.advance(6 * 60)
    off = stale(owner, {"tool": "send_copy", "mode": "off"}).json()
    assert engine.plugin_setup.revert_loosens(off["entry_id"])
    assert needs_passkey(owner.post(f"/owner/journal/{off['entry_id']}/revert", headers=CSRF, json={}))
    read_only = stale(owner, {"read_only": True}).json()
    assert not engine.plugin_setup.revert_loosens(read_only["entry_id"])   # send_copy is still Off one by one
    assert owner.post(f"/owner/journal/{read_only['entry_id']}/revert", headers=CSRF, json={}).status_code == 200
    options = owner.post("/owner/auth/reauth/options", headers=CSRF).json()
    owner.post("/owner/auth/reauth/verify", headers=CSRF, json={
        "challenge_id": options["challenge_id"], "credential": passkey.get(options["options"])})
    done = owner.post(f"/owner/journal/{off['entry_id']}/revert", headers=CSRF, json={})
    assert done.status_code == 200 and engine.plugin_setup.unasked_sends("notes", engine.registry.state("notes")) == {"send_copy"}
    clock.reset()


def test_a_plugin_without_unasked_sends_switches_on_without_a_passkey(tmp_path):
    engine, owner, _ = owner_app(tmp_path)
    clock.advance(6 * 60)
    for body in ({"enabled": False}, {"enabled": True}, {"read_only": True}, {"read_only": False},
                 {"tool": "send_copy", "mode": "off"}, {"tool": "send_copy", "tool_enabled": True}):
        assert stale(owner, body).status_code == 200, body
    clock.reset()


def test_an_allowed_mcp_tool_switched_back_on_needs_a_fresh_passkey(tmp_path, monkeypatch):
    """Always allow on an MCP server's tool is a send without asking too: switching that tool back on goes
    through the same check."""
    server = FakeMcp()
    monkeypatch.setattr(McpPlugin, "transport", server.transport)
    server.auth, server.static_token = True, "secret-token"
    engine = make_engine(tmp_path)
    engine.plugin_setup.add("notion", "mcp", {"url": URL}, credentials={"token": "secret-token"})
    engine.plugin_setup.mcp_tool_rule("notion", "create_page", allowed=True)
    assert engine.plugin_setup.unasked_sends("notion", engine.registry.state("notion")) == {"create_page"}

    def no_passkey():
        raise Denied("confirm with your passkey first", "reauth")

    engine.plugin_setup.switch("notion", tool="create_page", tool_enabled=False, confirm=no_passkey)  # tightens
    engine.plugin_setup.switch("notion", enabled=False, confirm=no_passkey)
    engine.plugin_setup.switch("notion", enabled=True, confirm=no_passkey)  # create_page is still Off
    with pytest.raises(Denied) as refused:
        engine.plugin_setup.switch("notion", tool="create_page", tool_enabled=True, confirm=no_passkey)
    assert refused.value.code == "reauth"
    assert "create_page" in engine.registry.state("notion")["disabled_tools"]
    clock.reset()


# ---------------------------------------------------------------- frames, CSP, logout

def test_every_answer_keeps_the_app_out_of_frames(tmp_path):
    engine = make_engine(tmp_path, public_url=OWNER_URL)
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL)
    for path in ("/app/", "/app/app.js", "/app/sw.js", "/owner/auth/status", "/owner/inbox"):
        response = owner.get(path)
        assert response.status_code in (200, 401), path
        headers = response.headers
        assert headers["x-frame-options"] == "DENY", path
        assert headers["x-content-type-options"] == "nosniff" and headers["referrer-policy"] == "no-referrer"
        policy = dict(part.strip().split(" ", 1) for part in headers["content-security-policy"].split(";"))
        assert policy["frame-ancestors"] == "'none'" and policy["default-src"] == "'self'", path
        assert policy["script-src"] == "'self'" and policy["style-src"] == "'self'"
        assert policy["object-src"] == "'none'" and policy["base-uri"] == "'none'"


def test_the_app_needs_nothing_the_policy_forbids():
    """Its own files only: no inline script, no inline style or style attribute, no handler attributes,
    nothing from another origin. So script-src and style-src 'self' are enough."""
    index = (APP_DIR / "index.html").read_text()
    scripts = re.findall(r"<script[^>]*>", index)
    assert scripts and all(re.fullmatch(r'<script src="[^":]+">', tag) for tag in scripts)
    assert not re.search(r"<style|\sstyle=|\son[a-z]+=|https?://", index)
    for name in ("app.js", "sw.js"):
        code = (APP_DIR / name).read_text()
        # a style attribute (h()'s attrs, setAttribute) or a <style> element; el.style.x is allowed
        assert not re.search(r"""\bstyle["']?\s*[:,]|<style|\sstyle=|eval\(|new Function""", code), name


def test_logging_out_needs_the_apps_header(tmp_path):
    """Like every other POST: another site can't log the owner out."""
    engine, owner, _ = owner_app(tmp_path)
    refused = owner.post("/owner/auth/logout")
    assert refused.status_code == 403 and refused.json()["code"] == "csrf"
    assert owner.get("/owner/auth/status").json()["logged_in"] is True
    assert owner.post("/owner/auth/logout", headers=CSRF).json() == {"ok": True}
    assert owner.get("/owner/auth/status").json()["logged_in"] is False
