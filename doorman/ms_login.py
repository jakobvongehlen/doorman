"""Microsoft sign-in shared by the plugins that talk to Microsoft 365 (teams, mail_outlook).

OAuth 2.0 authorization code with PKCE for a public client. The browser ends on a localhost page that
doesn't load; the owner pastes its address back into the owner app or `doorman-admin login`. A device
code login is there for the shell (`login_flow: device`). The refresh token goes to the vault; access
tokens stay in memory.

A plugin mixes this in next to BasePlugin and sets the class attributes below.
"""

import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode, urlparse

import httpx

from .plugin_api import Denied, PluginError

LOGIN = "https://login.microsoftonline.com"
LOGIN_TTL = 15 * 60
# Thunderbird's public client id: no secret, redirect https://localhost, device code allowed. Many tenants
# that don't let users register or consent to apps of their own have Thunderbird allowed already.
THUNDERBIRD = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"


def _q(value: str) -> str:
    return quote(str(value), safe="")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt_claims(token: str | None) -> dict:
    """The claims of a JWT without checking its signature. Only for tokens that came straight from
    Microsoft's token endpoint over TLS, and only to show or prefill the account name."""
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception:  # noqa: BLE001 - opaque or missing token: no claims
        return {}


class MicrosoftLogin:
    DEFAULT_CLIENT_ID: str | None = None      # None: config.client_id is required
    DEFAULT_TENANT = "organizations"
    DEFAULT_SCOPES = "offline_access"
    DEFAULT_REDIRECT: str | None = None       # None: http://localhost:<redirect_port>/
    LOGIN_LABEL = "Microsoft"                 # "Teams isn't connected"
    transport: httpx.BaseTransport | None = None  # tests inject a fake Microsoft here

    _token: str | None = None
    _expires = 0.0

    # ------------------------------------------------------------------ settings

    @property
    def tenant(self) -> str:
        return self.config.get("tenant") or self.DEFAULT_TENANT

    @property
    def scopes(self) -> str:
        return self.config.get("scopes") or self.DEFAULT_SCOPES

    @property
    def client_id(self) -> str:
        client_id = self.config.get("client_id") or self.DEFAULT_CLIENT_ID
        if not client_id:
            raise PluginError(f"{self.ctx.instance}: set config.client_id (an app registration in Entra ID)")
        return client_id

    @property
    def redirect_uri(self) -> str:
        return (self.config.get("redirect_uri") or self.DEFAULT_REDIRECT
                or f"http://localhost:{int(self.config.get('redirect_port', 8799))}/")

    @property
    def _pending_path(self) -> Path:
        return self.ctx.data_dir / "login_pending.json"

    def login_hint(self) -> str | None:
        return None

    def account_from_login(self, body: dict) -> str | None:
        """The account name to show once connected; `body` is the token response."""
        claims = jwt_claims(body.get("id_token")) or jwt_claims(body.get("access_token"))
        return claims.get("preferred_username") or claims.get("upn") or claims.get("unique_name") or self.login_hint()

    # ------------------------------------------------------------------ token endpoint

    def _token_request(self, data: dict, endpoint: str = "token") -> dict:
        try:
            with httpx.Client(transport=self.transport, timeout=30) as client:
                response = client.post(f"{LOGIN}/{_q(self.tenant)}/oauth2/v2.0/{endpoint}",
                                       data={"client_id": self.client_id, **data})
        except httpx.HTTPError as exc:
            raise PluginError(f"Microsoft login unreachable: {exc}") from exc
        try:
            body = response.json()
        except ValueError:
            body = {}
        if endpoint == "devicecode":
            if response.status_code >= 400 or "device_code" not in body:
                raise PluginError(f"Microsoft refused the device login: {_error_text(body, response)}")
            return body
        if response.status_code >= 400 or "access_token" not in body:
            error = _error_text(body, response)
            if body.get("error") == "invalid_grant":
                error += " (the Microsoft login expired or was revoked; connect again)"
            raise PluginError(f"Microsoft login failed: {error}")
        return body

    def _store(self, key: str, value: str | None) -> None:
        if value is None:
            self.credentials.pop(key, None)
        else:
            self.credentials[key] = value
        self.ctx.save_credential(key, value)

    def _connected(self, body: dict) -> dict:
        if not body.get("refresh_token"):
            raise PluginError("Microsoft sent no refresh token; offline_access must be in the scopes")
        self._store("refresh_token", body["refresh_token"])
        self._token, self._expires = body["access_token"], time.monotonic() + int(body.get("expires_in", 3600))
        account = self.account_from_login(body)
        if account:
            self._store("account", account)
        return {"connected": True, "account": account}

    # ------------------------------------------------------------------ the login contract

    def login_ready_error(self) -> str | None:
        if self.config.get("client_id") or self.DEFAULT_CLIENT_ID:
            return None
        return "Not set up yet: put client_id (and tenant) into this plugin's settings"

    def login_status(self) -> dict:
        error = self.login_ready_error()
        return {"connected": bool(self.credentials.get("refresh_token")), "account": self.credentials.get("account"),
                "ready": error is None, **({"error": error} if error else {})}

    def login_start(self, redirect_uri: str | None = None) -> dict:
        redirect_uri = redirect_uri or self.redirect_uri
        if not redirect_uri.startswith(("http://localhost", "https://localhost", "http://127.0.0.1")):
            raise PluginError("the redirect must be a localhost address for a public client")
        verifier, state = _b64(secrets.token_bytes(48)), _b64(secrets.token_bytes(24))
        tmp = self._pending_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"state": state, "verifier": verifier, "redirect_uri": redirect_uri,
                                   "created": time.time()}))
        os.chmod(tmp, 0o600)
        tmp.replace(self._pending_path)
        query = {"client_id": self.client_id, "response_type": "code", "redirect_uri": redirect_uri,
                 "response_mode": "query", "scope": self.scopes, "state": state, "prompt": "select_account",
                 "code_challenge": _b64(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"}
        if self.login_hint():
            query["login_hint"] = self.login_hint()
        return {"auth_url": f"{LOGIN}/{_q(self.tenant)}/oauth2/v2.0/authorize?{urlencode(query)}",
                "redirect_uri": redirect_uri, "expires_in": LOGIN_TTL}

    def login_finish(self, response_url: str) -> dict:
        try:
            pending = json.loads(self._pending_path.read_text())
        except (OSError, ValueError):
            raise Denied("no login in progress; start again", "login") from None
        if time.time() - pending["created"] > LOGIN_TTL:
            self._pending_path.unlink(missing_ok=True)
            raise Denied("the login took too long; start again", "login")
        params = parse_qs(urlparse(response_url.strip()).query)
        if params.get("error"):
            self._pending_path.unlink(missing_ok=True)
            detail = (params.get("error_description") or params["error"])[0].split("\r\n")[0]
            if "AADSTS65001" in detail or "AADSTS65002" in detail or "consent" in detail.lower():
                detail += ". Your organization's admin has to allow this app first."
            raise Denied(f"Microsoft says: {detail}", "login")
        code, state = (params.get("code") or [None])[0], (params.get("state") or [None])[0]
        if not code:
            raise Denied("that address has no code in it; paste the whole address of the page Microsoft sent you to",
                         "login")
        if not state or not secrets.compare_digest(state, pending["state"]):
            raise Denied("that address belongs to a different login attempt; start again", "login")
        self._pending_path.unlink(missing_ok=True)
        body = self._token_request({"grant_type": "authorization_code", "code": code, "scope": self.scopes,
                                    "redirect_uri": pending["redirect_uri"], "code_verifier": pending["verifier"]})
        return self._connected(body)

    def device_login(self, say, sleep=time.sleep) -> dict:
        """Device code flow for the shell: show a code, wait until it is approved in any browser."""
        start = self._token_request({"scope": self.scopes}, endpoint="devicecode")
        say(start.get("message") or f"Open {start['verification_uri']} and enter {start['user_code']}")
        interval = int(start.get("interval", 5))
        deadline = time.monotonic() + int(start.get("expires_in", 900))
        grant = {"grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": start["device_code"]}
        while time.monotonic() < deadline:
            sleep(interval)
            try:
                return self._connected(self._token_request(grant))
            except PluginError as exc:
                text = str(exc)
                if "authorization_pending" in text or "AADSTS70016" in text:
                    continue
                if "slow_down" in text:
                    interval += 5
                    continue
                raise
        raise PluginError("the device code expired before it was approved; start again")

    def logout(self) -> dict:
        # Microsoft has no endpoint to revoke a single refresh token; forgetting it is what's possible.
        for key in ("refresh_token", "account"):
            self._store(key, None)
        self._token = None
        return {"connected": False}

    def interactive_login(self, say, read_line=input, finish=None) -> None:
        if self.config.get("login_flow") == "device":
            result = self.device_login(say)
            say(f"Connected {result.get('account') or 'the Microsoft account'}.")
            return
        start = self.login_start()
        say("Open this address in a browser and sign in:\n")
        say(start["auth_url"] + "\n")
        say("Microsoft ends on a localhost page that doesn't load. Copy that page's whole address and paste it here.")
        url = ""
        while not url:
            url = read_line("> ").strip()
        result = (finish or self.login_finish)(url)
        say(f"Connected {result.get('account') or 'the Microsoft account'}.")

    def access_token(self) -> str:
        if self._token and time.monotonic() < self._expires - 60:
            return self._token
        refresh = self.credentials.get("refresh_token")
        if not refresh:
            raise PluginError(f"{self.LOGIN_LABEL} isn't connected: connect it under Plugins")
        body = self._token_request({"grant_type": "refresh_token", "refresh_token": refresh, "scope": self.scopes})
        self._token, self._expires = body["access_token"], time.monotonic() + int(body.get("expires_in", 3600))
        if body.get("refresh_token") and body["refresh_token"] != refresh:
            self._store("refresh_token", body["refresh_token"])
        return self._token

    def check_login(self) -> str | None:
        if not self.credentials.get("refresh_token"):
            return "not connected: connect it under Plugins"
        self._token = None
        try:
            self.access_token()
        except PluginError as exc:
            return str(exc)
        return None


def _error_text(body: dict, response: httpx.Response) -> str:
    text = body.get("error_description") or body.get("error") or f"HTTP {response.status_code}"
    if body.get("error") and body["error"] not in text:
        text = f"{body['error']}: {text}"
    return text.split("\r\n")[0]
