"""mail_outlook: Microsoft login (Thunderbird's client id by default) + XOAUTH2 to IMAP and SMTP.

Microsoft's login is faked with httpx.MockTransport. IMAP runs against the Dovecot from
test_mail_imap with oauth2_login checked and then mapped onto a password login (a Dovecot that
validates Microsoft tokens isn't worth building here). SMTP is aiosmtpd with an XOAUTH2 mechanism
that checks the user and the bearer token.
"""

import base64
import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from imapclient import IMAPClient

from doorman.registry import declared_events
from conftest import Agent, make_engine
from test_mail_imap import deliver, free_port, imap_server  # noqa: F401 - imap_server is a fixture

ADDRESS = "j.doe@students.uni.example"
THUNDERBIRD = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"


def fake_jwt(claims: dict) -> str:
    part = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"eyJhbGciOiJub25lIn0.{part}.sig"


class FakeMicrosoft:
    def __init__(self):
        self.refresh_tokens = {"rt-1"}
        self.token_requests: list[dict] = []
        self.access = fake_jwt({"upn": ADDRESS, "aud": "https://outlook.office.com"})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.url.host == "login.microsoftonline.com"
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        self.token_requests.append(form)
        assert form["client_id"] == THUNDERBIRD and "client_secret" not in form
        if request.url.path == "/uni.example/oauth2/v2.0/devicecode":
            assert "IMAP.AccessAsUser.All" in form["scope"]
            return httpx.Response(200, json={"device_code": "dc-1", "user_code": "ABCD-EFGH", "interval": 5,
                                             "verification_uri": "https://microsoft.com/devicelogin",
                                             "expires_in": 900, "message": "Enter ABCD-EFGH at microsoft.com/devicelogin"})
        assert request.url.path == "/uni.example/oauth2/v2.0/token"
        if form["grant_type"] == "urn:ietf:params:oauth:grant-type:device_code":
            assert form["device_code"] == "dc-1"
            if sum(r.get("grant_type", "").endswith("device_code") for r in self.token_requests) < 3:
                return httpx.Response(400, json={"error": "authorization_pending",
                                                 "error_description": "AADSTS70016: pending"})
            return httpx.Response(200, json={"access_token": self.access, "refresh_token": "rt-1", "expires_in": 3600})
        assert "IMAP.AccessAsUser.All" in form["scope"] and "SMTP.Send" in form["scope"]
        if form["grant_type"] == "authorization_code":
            assert form["code"] == "the-code" and form["redirect_uri"] == "https://localhost"
            return httpx.Response(200, json={"access_token": self.access, "refresh_token": "rt-1",
                                             "expires_in": 3600})
        if form["refresh_token"] not in self.refresh_tokens:
            return httpx.Response(400, json={"error": "invalid_grant",
                                             "error_description": "AADSTS700082: The refresh token has expired"})
        return httpx.Response(200, json={"access_token": self.access, "expires_in": 3600})


@pytest.fixture
def xoauth_smtp():
    from aiosmtpd.controller import Controller
    from aiosmtpd.smtp import AuthResult

    class Handler:
        def __init__(self):
            self.messages, self.logins = [], []
            self.reply = None  # set to refuse every login with this text

        async def auth_XOAUTH2(self, server, args):
            if len(args) < 2:
                return AuthResult(success=False, handled=False)
            raw = base64.b64decode(args[1]).decode()
            self.logins.append(raw)
            if self.reply:
                await server.challenge_auth('{"status":"401"}')  # the client answers with an empty line
                return AuthResult(success=False, handled=False, message=self.reply)
            fields = dict(f.split("=", 1) for f in raw.split("\x01") if f)
            return AuthResult(success=fields.get("auth", "").startswith("Bearer ey"), auth_data=fields.get("user"))

        async def handle_DATA(self, server, session, envelope):
            self.messages.append({"to": envelope.rcpt_tos, "data": envelope.content.decode()})
            return "250 OK"

    handler = Handler()
    port = free_port()
    controller = Controller(handler, hostname="127.0.0.1", port=port, auth_require_tls=False,
                            auth_exclude_mechanism=["LOGIN", "PLAIN"])
    controller.start()
    yield port, handler
    controller.stop()


@pytest.fixture
def outlook(tmp_path, imap_server, xoauth_smtp, monkeypatch):  # noqa: F811 - pytest fixture injection
    smtp_port, handler = xoauth_smtp
    engine = make_engine(tmp_path, plugins={
        "outlook": {"type": "mail_outlook", "enabled": True, "config": {
            "address": ADDRESS, "tenant": "uni.example",
            "imap_host": "127.0.0.1", "imap_port": imap_server, "imap_security": "none",
            "smtp_host": "127.0.0.1", "smtp_port": smtp_port, "smtp_security": "none"}}})
    microsoft = FakeMicrosoft()
    plugin_cls = type(engine.registry.instance("outlook"))
    monkeypatch.setattr(plugin_cls, "transport", httpx.MockTransport(microsoft), raising=False)
    imap_logins = []

    def oauth2_login(client, user, token, *args, **kwargs):
        imap_logins.append((user, token))
        assert user == ADDRESS and token == microsoft.access
        return client.login("owner", "secret")

    monkeypatch.setattr(IMAPClient, "oauth2_login", oauth2_login)
    return engine, Agent(engine), microsoft, handler, imap_server, imap_logins


def connect(engine):
    start = engine.plugin_setup.login_start("outlook")
    query = {k: v[0] for k, v in parse_qs(urlparse(start["auth_url"]).query).items()}
    assert start["auth_url"].startswith("https://login.microsoftonline.com/uni.example/oauth2/v2.0/authorize?")
    assert query["client_id"] == THUNDERBIRD and query["redirect_uri"] == "https://localhost"
    assert query["login_hint"] == ADDRESS and query["code_challenge_method"] == "S256"
    return engine.plugin_setup.login_finish("outlook", f"https://localhost/?code=the-code&state={query['state']}")


def test_connect_with_thunderbirds_client_id(outlook):
    engine, *_ = outlook
    status = engine.plugin_setup.login_status("outlook")
    assert status["ready"] is True and status["connected"] is False  # no app registration needed
    assert connect(engine) == {"connected": True, "account": ADDRESS}
    assert engine.vault.get("outlook")["refresh_token"] == "rt-1"
    assert engine.plugin_setup.login_status("outlook")["connected"] is True
    assert engine.registry.instance("outlook").check() is None


def test_read_and_send_over_xoauth2(outlook):
    engine, agent, microsoft, smtp, port, imap_logins = outlook
    connect(engine)
    mid = deliver(port, "anna@uni.example", "Reading group", "Can you send me the reading list?")
    items = agent.read("outlook.search", {})
    assert items[0]["id"] == mid and imap_logins[0][0] == ADDRESS

    out = agent.call("outlook.send", {"to": ["anna@uni.example"], "subject": "Re: Reading group",
                                      "body": "Here it is.", "in_reply_to": mid})
    assert out["status"] == "waiting_approval", out
    result = engine.approvals.decide(out["approval_id"], approve=True)["results"][0]
    assert result["status"] == "done", result
    assert smtp.logins == [f"user={ADDRESS}\x01auth=Bearer {microsoft.access}\x01\x01"]
    assert smtp.messages[0]["to"] == ["anna@uni.example"] and f"From: {ADDRESS}" in smtp.messages[0]["data"]
    # Exchange files SMTP mail in Sent Items itself; a copy from Doorman would show up twice
    assert agent.read("outlook.search", {"folder": "Sent"}) == []
    # one token for all of it
    assert [r["grant_type"] for r in microsoft.token_requests] == ["authorization_code"]


def test_expired_login_means_not_sent(outlook):
    engine, agent, microsoft, smtp, *_ = outlook
    connect(engine)
    engine.registry.instance("outlook")._token = None
    microsoft.refresh_tokens.clear()  # e.g. the university's sign-in rules expired it
    out = agent.call("outlook.send", {"to": ["anna@uni.example"], "subject": "Hi", "body": "x"})
    result = engine.approvals.decide(out["approval_id"], approve=True)["results"][0]
    assert result["status"] == "failed" and "connect again" in result["error"], result
    assert smtp.messages == []
    assert "connect again" in engine.registry.instance("outlook").check()


def test_smtp_auth_off_for_the_tenant_is_not_sent(outlook):
    engine, agent, _, smtp, *_ = outlook
    connect(engine)
    smtp.reply = "535 5.7.139 Authentication unsuccessful, SmtpClientAuthentication is disabled for the Tenant."
    out = agent.call("outlook.send", {"to": ["anna@uni.example"], "subject": "Hi", "body": "x"})
    result = engine.approvals.decide(out["approval_id"], approve=True)["results"][0]
    assert result["status"] == "failed" and "SMTP AUTH is switched off" in result["error"], result
    assert smtp.messages == []


def test_listed_as_a_plugin_with_microsoft_login(outlook):
    engine, *_ = outlook
    manifest = engine.registry.manifest("outlook")
    assert manifest["login"] == "oauth" and manifest["login_provider"] == "Microsoft"
    assert [t["name"] for t in manifest["tools"]] == ["draft", "send", "reply", "draft_reply", "move", "label",
                                                     "delete"]
    assert [e["name"] for e in declared_events(manifest)] == ["new_mail"]
    # its archive feeds doorman search like any mailbox's: mail_imap's index, gated by its read
    assert manifest["index"] == {"read": "read", "kinds": ["mail"], "every_minutes": 5,
                                 "needs": {"attachment": "attachment"}, "settings": ["archive", "check_hidden_text"]}
    assert [r["name"] for r in manifest["reads"]] == ["folders", "search", "recent", "read", "attachment"]


def test_its_archive_feeds_doorman_search(outlook):
    engine, agent, _, _, port, _ = outlook
    connect(engine)
    mid = deliver(port, "anna@uni.example", "Reading group", "Can you send me the reading list?")
    engine.registry.instance("outlook").run_job("archive", 60)
    engine.search.pull("outlook")
    [hit] = engine.search.any_word(agent.session, agent.key, {"query": "reading list"})["results"]
    assert hit["ref"] == f"outlook:{mid}" and hit["source"] == "outlook" and hit["folder"] == "INBOX"
    assert "reading list" in hit["passage"]


def test_device_code_login_in_the_shell(outlook):
    engine, _, microsoft, *_ = outlook
    plugin = engine.registry.instance("outlook")
    said, waits = [], []
    result = plugin.device_login(said.append, sleep=waits.append)
    assert result == {"connected": True, "account": ADDRESS}
    assert said == ["Enter ABCD-EFGH at microsoft.com/devicelogin"] and waits == [5, 5, 5]
    assert engine.vault.get("outlook")["refresh_token"] == "rt-1"
