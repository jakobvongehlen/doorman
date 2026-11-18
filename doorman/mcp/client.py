"""A small client for remote MCP servers: the Streamable HTTP transport and the MCP sign-in.

Only what Doorman needs: initialize, tools/list and tools/call. Each JSON-RPC request is an HTTP POST;
the answer comes back as JSON or as a short SSE stream. The server may hand out a session id
(Mcp-Session-Id), which every later request carries; when the server forgets it (404), the client starts
a new session and asks once more, since a 404 means the request wasn't processed.

Failures of a tools/call that prove nothing happened (no connection, a 4xx answer, a JSON-RPC error the
server raises before running the tool) are NotSent. Anything else (a timeout after the request left,
a 5xx, an error from inside the tool) may have changed something, so it's a plain PluginError and the
engine never retries it.

Sign-in follows the MCP authorization spec: the server's 401 names its protected resource metadata
(RFC 9728), that names the authorization server (RFC 8414), Doorman registers itself there as a
public client (RFC 7591) and signs in with authorization code + PKCE, naming the server as `resource`
(RFC 8707). Servers from before that spec (no resource metadata) get their own origin as the
authorization server.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import threading
from typing import Any, Callable
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from doorman.plugin_api import NotSent, PluginError

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "doorman", "title": "Doorman", "version": "0.1.0"}
# JSON-RPC errors a server raises before it runs anything: parse error, invalid request, unknown method.
# Not invalid params (-32602): SDKs pass on what a tool handler throws, and a handler may throw it halfway.
BEFORE_RUNNING = {-32700, -32600, -32601}


class AuthRequired(NotSent):
    """The server wants a (new) sign-in. Carries its WWW-Authenticate header for discovery."""

    def __init__(self, message: str, www_authenticate: str = ""):
        super().__init__(message)
        self.www_authenticate = www_authenticate


class RpcError(PluginError):
    def __init__(self, code: int, message: str):
        super().__init__(f"{message} (MCP error {code})")
        self.code = code


def canonical_url(url: str) -> str:
    """The server's address as the `resource` of a sign-in: lower-case scheme and host, no fragment."""
    parts = urlparse(url.strip())
    return urlunparse((parts.scheme.lower(), parts.netloc.lower(), parts.path.rstrip("/") or "", "",
                       parts.query, ""))


def check_url(url: Any) -> str:
    """An MCP server address Doorman will talk to: https, or http on this machine (for testing)."""
    if not isinstance(url, str) or not url.strip():
        raise PluginError("the server address is missing")
    url = url.strip()
    parts = urlparse(url)
    local = parts.hostname in ("localhost", "127.0.0.1", "::1")
    if parts.scheme != "https" and not (parts.scheme == "http" and local):
        raise PluginError("the server address must start with https://")
    if not parts.hostname:
        raise PluginError("that isn't a server address")
    return url


def covers(prefix: str, url: str) -> bool:
    """Does the resource `prefix` name this server: same origin, and a whole-segment path prefix?"""
    a, b = urlparse(canonical_url(prefix)), urlparse(canonical_url(url))
    if (a.scheme, a.netloc) != (b.scheme, b.netloc):
        return False
    path = a.path.rstrip("/")
    return not path or b.path == path or b.path.startswith(path + "/")


def _bearer(response: httpx.Response) -> str | None:
    """The token a request was sent with."""
    header = response.request.headers.get("authorization", "")
    return header[7:] if header.startswith("Bearer ") else None


def _header_params(header: str) -> dict[str, str]:
    """key="value" pairs of a WWW-Authenticate header."""
    return {k.lower(): v for k, v in re.findall(r'(\w+)="([^"]*)"', header or "")}


def _sse_messages(lines) -> Any:
    """JSON-RPC messages from an SSE stream, one per event."""
    data: list[str] = []
    for line in lines:
        if line == "":
            if data:
                text = "\n".join(data)
                data = []
                try:
                    yield json.loads(text)
                except ValueError:
                    continue
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        if field == "data":
            data.append(value[1:] if value.startswith(" ") else value)
    if data:
        try:
            yield json.loads("\n".join(data))
        except ValueError:
            pass


class McpClient:
    """One server. `token` returns the current access token (or None); `refresh(failed_token)` gets a new
    one after a 401 and returns True if there is one."""

    def __init__(self, url: str, token: Callable[[], str | None] = lambda: None,
                 refresh: Callable[[str | None], bool] = lambda failed: False,
                 transport: httpx.BaseTransport | None = None,
                 timeout: float = 60):
        self.url = check_url(url)
        self.token = token
        self.refresh = refresh
        self.http = httpx.Client(transport=transport, timeout=httpx.Timeout(timeout, connect=15),
                                 follow_redirects=False)
        self.session_id: str | None = None
        self.protocol: str | None = None
        self.server_info: dict = {}
        self.instructions: str | None = None
        self._lock = threading.Lock()        # request ids
        self._init_lock = threading.RLock()  # one handshake at a time
        self._ids = 0

    def close(self) -> None:
        if self.session_id:
            try:
                self.http.delete(self.url, headers=self._headers())
            except httpx.HTTPError:
                pass
        self.http.close()

    # ------------------------------------------------------------------ transport

    def _headers(self, token: str | None = None) -> dict[str, str]:
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol:
            headers["MCP-Protocol-Version"] = self.protocol
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _next_id(self) -> int:
        with self._lock:
            self._ids += 1
            return self._ids

    def _post(self, message: dict) -> tuple[httpx.Response, dict | None]:
        """Send one message. Returns the response and, for a request, the JSON-RPC answer to it."""
        token = self.token()
        try:
            with self.http.stream("POST", self.url, headers=self._headers(token), json=message) as response:
                if response.status_code >= 300 or "id" not in message or response.status_code == 202:
                    response.read()
                    return response, None
                kind = response.headers.get("content-type", "").split(";")[0].strip().lower()
                if kind == "text/event-stream":
                    for item in _sse_messages(response.iter_lines()):
                        if isinstance(item, dict) and item.get("id") == message["id"] and \
                                ("result" in item or "error" in item):
                            return response, item
                    raise PluginError("the server closed its answer without a result")
                response.read()
                try:
                    body = response.json()
                except ValueError:
                    raise PluginError(f"the server sent something that isn't JSON (HTTP {response.status_code})") from None
                if isinstance(body, list):  # a batch: pick ours
                    body = next((b for b in body if isinstance(b, dict) and b.get("id") == message["id"]), None)
                return response, body
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            raise NotSent(f"can't reach the MCP server: {exc}") from None
        except httpx.HTTPError as exc:
            raise PluginError(f"the MCP server didn't answer: {type(exc).__name__}: {exc}") from None

    def _rpc(self, method: str, params: dict | None, retried: bool = False) -> dict:
        message = {"jsonrpc": "2.0", "id": self._next_id(), "method": method}
        if params is not None:
            message["params"] = params
        response, answer = self._post(message)
        status = response.status_code
        if status == 404 and self.session_id and not retried:
            # the server ended our session; the request wasn't processed, so start over and ask again
            self._restart(response.request.headers.get("mcp-session-id"))
            return self._rpc(method, params, retried=True)
        if status == 401:
            if not retried and self.refresh(_bearer(response)):
                return self._rpc(method, params, retried=True)
            raise AuthRequired("the MCP server wants you to sign in again (Plugins → Connect account)",
                               response.headers.get("www-authenticate", ""))
        if status == 403:
            raise NotSent(f"the MCP server refused this (HTTP 403): {response.text[:300]}")
        if 400 <= status < 500:
            raise NotSent(f"the MCP server refused the request (HTTP {status}): {response.text[:300]}")
        if status >= 300:
            raise PluginError(f"the MCP server failed (HTTP {status}): {response.text[:300]}")
        if answer is None:
            raise PluginError("the MCP server sent no answer")
        if "error" in answer:
            error = answer["error"] or {}
            code = int(error.get("code", 0) or 0)
            text = str(error.get("message") or "unknown error")
            if code in BEFORE_RUNNING:
                raise NotSent(f"{text} (MCP error {code})")
            raise RpcError(code, text)
        return answer.get("result") or {}

    # ------------------------------------------------------------------ protocol

    def _restart(self, lost: str | None) -> None:
        """A new session, unless another call already started one after `lost` ended."""
        with self._init_lock:
            if self.session_id == lost or self.protocol is None:
                self.initialize()

    def initialize(self) -> dict:
        """Start a (new) session."""
        with self._init_lock:
            self.session_id = None
            self.protocol = None
            info = self._initialize()
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
            return info

    def _initialize(self) -> dict:
        message = {"jsonrpc": "2.0", "id": self._next_id(), "method": "initialize",
                   "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO}}
        response, answer = self._post(message)
        if response.status_code == 401:
            if self.refresh(_bearer(response)):
                response, answer = self._post(message)
            if response.status_code == 401:
                raise AuthRequired("sign in to the MCP server first (Plugins → Connect account)",
                                   response.headers.get("www-authenticate", ""))
        if response.status_code >= 400 or answer is None:
            detail = f": {response.text[:300]}" if response.status_code >= 400 and response.text else ""
            raise NotSent(f"the MCP server didn't accept the connection (HTTP {response.status_code}){detail}")
        if "error" in answer:
            raise NotSent(f"the MCP server refused to start: {(answer['error'] or {}).get('message')}")
        result = answer.get("result") or {}
        self.session_id = response.headers.get("mcp-session-id") or ""
        self.protocol = result.get("protocolVersion") or PROTOCOL_VERSION
        self.server_info = result.get("serverInfo") or {}
        self.instructions = result.get("instructions")
        return self.server_info

    def _ready(self) -> None:
        with self._init_lock:
            if self.protocol is None:
                self.initialize()

    def list_tools(self) -> list[dict]:
        self._ready()
        tools: list[dict] = []
        cursor = None
        for _ in range(50):  # a server that pages forever
            result = self._rpc("tools/list", {"cursor": cursor} if cursor else {})
            tools.extend(t for t in result.get("tools") or [] if isinstance(t, dict) and t.get("name"))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools

    def call_tool(self, name: str, arguments: dict) -> dict:
        self._ready()
        return self._rpc("tools/call", {"name": name, "arguments": arguments})

    def probe(self) -> tuple[bool, str]:
        """Can we talk to the server without signing in? (False, its WWW-Authenticate header) if not."""
        try:
            self.initialize()
            return True, ""
        except AuthRequired as exc:
            return False, exc.www_authenticate


# ---------------------------------------------------------------------- sign-in (OAuth 2.1)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def pkce() -> tuple[str, str]:
    verifier = b64url(secrets.token_bytes(48))
    return verifier, b64url(hashlib.sha256(verifier.encode()).digest())


class OAuth:
    """Discovery, client registration and token requests for one MCP server."""

    def __init__(self, server_url: str, transport: httpx.BaseTransport | None = None):
        self.server_url = server_url
        self.transport = transport
        self.local = urlparse(server_url).scheme == "http"  # a test server on this machine

    def _allowed(self, url: str) -> bool:
        """Addresses the server names for its sign-in: https only (http on this machine only when the
        server itself is a local test server), so a server can't send Doorman to plain http."""
        parts = urlparse(url or "")
        if parts.scheme == "https" and parts.hostname:
            return True
        return self.local and parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1")

    def _get_json(self, url: str) -> dict | None:
        try:
            with httpx.Client(transport=self.transport, timeout=20) as http:
                response = http.get(url, headers={"Accept": "application/json",
                                                  "MCP-Protocol-Version": PROTOCOL_VERSION})
        except httpx.HTTPError:
            return None
        if response.status_code != 200:
            return None
        try:
            body = response.json()
        except ValueError:
            return None
        return body if isinstance(body, dict) else None

    @staticmethod
    def _well_known(base: str, name: str) -> list[str]:
        parts = urlparse(base)
        origin = f"{parts.scheme}://{parts.netloc}"
        path = parts.path.rstrip("/")
        urls = [f"{origin}/.well-known/{name}{path}"] if path else []
        if name == "openid-configuration" and path:
            urls.append(f"{origin}{path}/.well-known/{name}")
        urls.append(f"{origin}/.well-known/{name}")
        return urls

    def discover(self, www_authenticate: str = "") -> dict:
        """Where and how to sign in: {resource, issuer, authorization_endpoint, token_endpoint,
        registration_endpoint, scope, ...}."""
        header = _header_params(www_authenticate)
        server = canonical_url(self.server_url)
        candidates = ([header["resource_metadata"]] if self._allowed(header.get("resource_metadata", "")) else []) + \
            self._well_known(self.server_url, "oauth-protected-resource")
        resource_meta = next((m for m in map(self._get_json, candidates) if m), None)
        if resource_meta and resource_meta.get("authorization_servers"):
            issuer = str(resource_meta["authorization_servers"][0])
            if not self._allowed(issuer):
                raise PluginError(f"the MCP server names a sign-in service that isn't https: {issuer}")
            named = canonical_url(str(resource_meta.get("resource") or server))
            if not covers(named, server):
                # a server that claims to be another one would get a token meant for that one
                raise PluginError(f"the MCP server at {server} says it is {named}, so Doorman won't sign in")
            resource = named
            scopes = header.get("scope") or " ".join(resource_meta.get("scopes_supported") or [])
        else:  # a server from before resource metadata: it is its own authorization server
            parts = urlparse(self.server_url)
            issuer = f"{parts.scheme}://{parts.netloc}"
            resource = server
            scopes = header.get("scope", "")
        meta = None
        for url in self._well_known(issuer, "oauth-authorization-server") + \
                self._well_known(issuer, "openid-configuration"):
            meta = self._get_json(url)
            if meta and meta.get("authorization_endpoint") and meta.get("token_endpoint"):
                break
            meta = None
        if meta is None:
            if resource_meta:
                raise PluginError(f"the MCP server's sign-in service ({issuer}) doesn't describe itself")
            meta = {"authorization_endpoint": f"{issuer}/authorize", "token_endpoint": f"{issuer}/token",
                    "registration_endpoint": f"{issuer}/register"}
        for key in ("authorization_endpoint", "token_endpoint", "registration_endpoint", "revocation_endpoint"):
            if meta.get(key) and not self._allowed(str(meta[key])):
                raise PluginError(f"the MCP server's sign-in uses an address that isn't https: {meta[key]}")
        methods = meta.get("code_challenge_methods_supported")
        if methods is not None and "S256" not in methods:
            raise PluginError("the MCP server's sign-in doesn't support PKCE (S256), so Doorman won't use it")
        return {"issuer": meta.get("issuer") or issuer, "resource": resource, "scope": scopes,
                "authorization_endpoint": meta["authorization_endpoint"], "token_endpoint": meta["token_endpoint"],
                "registration_endpoint": meta.get("registration_endpoint"),
                "revocation_endpoint": meta.get("revocation_endpoint")}

    def register(self, meta: dict, redirect_uri: str) -> dict:
        """Register Doorman as a client of the authorization server (dynamic client registration)."""
        if not meta.get("registration_endpoint"):
            raise PluginError("the MCP server doesn't let new apps register; put a client ID from its "
                              "provider into the plugin's client_id setting")
        body = {"client_name": "Doorman", "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
                "token_endpoint_auth_method": "none"}
        if meta.get("scope"):
            body["scope"] = meta["scope"]
        try:
            with httpx.Client(transport=self.transport, timeout=20) as http:
                response = http.post(meta["registration_endpoint"], json=body)
        except httpx.HTTPError as exc:
            raise PluginError(f"registering with the MCP server's sign-in failed: {exc}") from None
        try:
            answer = response.json()
        except ValueError:
            answer = {}
        if response.status_code >= 400 or not answer.get("client_id"):
            error = answer.get("error_description") or answer.get("error") or f"HTTP {response.status_code}"
            raise PluginError(f"registering with the MCP server's sign-in failed: {error}")
        return {"client_id": answer["client_id"], "client_secret": answer.get("client_secret"),
                "auth_method": answer.get("token_endpoint_auth_method") or
                ("client_secret_basic" if answer.get("client_secret") else "none")}

    @staticmethod
    def authorization_url(meta: dict, client: dict, redirect_uri: str, state: str, challenge: str) -> str:
        query = {"response_type": "code", "client_id": client["client_id"], "redirect_uri": redirect_uri,
                 "state": state, "code_challenge": challenge, "code_challenge_method": "S256",
                 "resource": meta["resource"]}
        if meta.get("scope"):
            query["scope"] = meta["scope"]
        sep = "&" if "?" in meta["authorization_endpoint"] else "?"
        return f"{meta['authorization_endpoint']}{sep}{urlencode(query)}"

    @staticmethod
    def _as_client(client: dict, data: dict) -> tuple[dict, tuple[str, str] | None]:
        """A form with the client's proof added the way it registered: in the Authorization header
        (returned), or as form fields; a client without a secret only names itself."""
        if client.get("client_secret") and client.get("auth_method") == "client_secret_basic":
            return data, (client["client_id"], client["client_secret"])
        data = {**data, "client_id": client["client_id"]}
        if client.get("client_secret"):
            data["client_secret"] = client["client_secret"]
        return data, None

    def token(self, meta: dict, client: dict, data: dict) -> dict:
        data, auth = self._as_client(client, {**data, "resource": meta["resource"]})
        try:
            with httpx.Client(transport=self.transport, timeout=30) as http:
                response = http.post(meta["token_endpoint"], data=data, auth=auth,
                                     headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise PluginError(f"the MCP server's sign-in didn't answer: {exc}") from None
        try:
            body = response.json()
        except ValueError:
            body = {}
        if response.status_code >= 400 or not body.get("access_token"):
            error = body.get("error_description") or body.get("error") or f"HTTP {response.status_code}"
            if body.get("error") == "invalid_grant":
                error += " (the sign-in expired or was revoked; connect the account again)"
            raise PluginError(f"signing in to the MCP server failed: {error}")
        return body

    def revoke(self, meta: dict, client: dict, token: str) -> None:
        if not meta.get("revocation_endpoint"):
            return
        data, auth = self._as_client(client, {"token": token})
        try:
            with httpx.Client(transport=self.transport, timeout=20) as http:
                http.post(meta["revocation_endpoint"], data=data, auth=auth)
        except httpx.HTTPError:
            pass
