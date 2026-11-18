"""A remote MCP server (Streamable HTTP) with its own OAuth authorization server, as an httpx transport.

Server: https://mcp.example.com/mcp. Sign-in: https://auth.example.com (resource metadata, dynamic client
registration, authorization code + PKCE, refresh tokens). Tests change `tools`, `auth`, `sse` and friends
and read `calls` to see what reached the server.
"""

import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlparse

import httpx

URL = "https://mcp.example.com/mcp"
AUTH = "https://auth.example.com"


def default_tools():
    return [
        {"name": "search", "title": "Search pages", "description": "Search the workspace",
         "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
         "annotations": {"readOnlyHint": True}},
        {"name": "get_page", "description": "One page", "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
         "annotations": {"readOnlyHint": True}},
        {"name": "create_page", "title": "Create a page", "description": "Create a page",
         "inputSchema": {"type": "object", "properties": {"title": {"type": "string"}, "text": {"type": "string"}},
                         "required": ["title"]}},
        {"name": "share_page", "description": "Share a page with someone",
         "inputSchema": {"type": "object", "properties": {"id": {"type": "string"},
                                                          "email": {"type": "string", "format": "email"}},
                         "required": ["id", "email"]}},
        {"name": "archive_page", "description": "Archive a page",
         "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
         "annotations": {"readOnlyHint": False, "destructiveHint": True}},
    ]


class FakeMcp:
    def __init__(self):
        self.tools = default_tools()
        self.page_size = 3          # tools/list pages
        self.auth = False           # the server wants a bearer token
        self.static_token = None    # a token that always works (like a personal access token)
        self.sse = False            # answer requests as an SSE stream
        self.sessions = set()
        self.calls = []             # (tool name, arguments) that reached the server
        self.fail = {}              # tool name -> "is_error" | "rpc_bad_request" | "rpc_invalid" | "rpc_internal" | "http_500"
        self.connect_error = False
        self.forget_sessions = False
        self.with_resource_metadata = True
        # authorization server
        self.clients = {}
        self.codes = {}
        self.access_tokens = {}     # token -> client_id
        self.refresh_tokens = {}
        self.issued = 0
        self.expires_in = 3600
        self.registrations = []
        self.revocations = []       # (form, Authorization header) of each revocation request
        self.token_requests = []
        self.transport = httpx.MockTransport(self.handle)

    # ------------------------------------------------------------------ helpers

    def authorize(self, auth_url: str, approve: bool = True) -> str:
        """What the browser does on the consent page: returns the address the sign-in redirects to."""
        q = {k: v[0] for k, v in parse_qs(urlparse(auth_url).query).items()}
        assert q["client_id"] in self.clients, "unknown client"
        assert q["code_challenge_method"] == "S256"
        assert q["resource"] == URL
        if not approve:
            return f"{q['redirect_uri']}?error=access_denied&state={q['state']}"
        code = secrets.token_hex(8)
        self.codes[code] = {"client_id": q["client_id"], "challenge": q["code_challenge"],
                            "redirect_uri": q["redirect_uri"], "resource": q["resource"]}
        return f"{q['redirect_uri']}?code={code}&state={q['state']}"

    def _issue(self, client_id):
        self.issued += 1
        access = f"at-{self.issued}"
        refresh = f"rt-{self.issued}"
        self.access_tokens[access] = client_id
        self.refresh_tokens[refresh] = client_id
        return {"access_token": access, "token_type": "Bearer", "expires_in": self.expires_in,
                "refresh_token": refresh}

    @staticmethod
    def _json(status, body, headers=None):
        return httpx.Response(status, json=body, headers=headers or {})

    def _authorized(self, request) -> bool:
        if not self.auth:
            return True
        header = request.headers.get("authorization", "")
        token = header[7:] if header.startswith("Bearer ") else None
        return bool(token) and (token == self.static_token or token in self.access_tokens)

    # ------------------------------------------------------------------ dispatch

    def handle(self, request: httpx.Request) -> httpx.Response:
        if self.connect_error:
            raise httpx.ConnectError("connection refused", request=request)
        url = str(request.url).split("?")[0]
        if url == URL:
            return self.mcp(request)
        if url == "https://mcp.example.com/.well-known/oauth-protected-resource/mcp" and self.with_resource_metadata:
            return self._json(200, {"resource": URL, "authorization_servers": [AUTH], "scopes_supported": ["pages"]})
        if url in (f"{AUTH}/.well-known/oauth-authorization-server",):
            return self._json(200, {"issuer": AUTH, "authorization_endpoint": f"{AUTH}/authorize",
                                    "token_endpoint": f"{AUTH}/token", "registration_endpoint": f"{AUTH}/register",
                                    "revocation_endpoint": f"{AUTH}/revoke",
                                    "code_challenge_methods_supported": ["S256"]})
        if url == f"{AUTH}/register":
            body = json.loads(request.content)
            self.registrations.append(body)
            client_id = f"client-{len(self.clients) + 1}"
            self.clients[client_id] = body
            return self._json(201, {"client_id": client_id, **body})
        if url == f"{AUTH}/token":
            return self.token(request)
        if url == f"{AUTH}/revoke":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.revocations.append((form, request.headers.get("authorization")))
            self.refresh_tokens.pop(form.get("token"), None)
            self.access_tokens.pop(form.get("token"), None)
            return httpx.Response(200)
        return httpx.Response(404)

    def token(self, request):
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        self.token_requests.append(form)
        if form.get("resource") != URL:
            return self._json(400, {"error": "invalid_target"})
        if form["grant_type"] == "authorization_code":
            code = self.codes.pop(form.get("code"), None)
            if not code or code["client_id"] != form.get("client_id") or code["redirect_uri"] != form.get("redirect_uri"):
                return self._json(400, {"error": "invalid_grant"})
            digest = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=").decode()
            if digest != code["challenge"]:
                return self._json(400, {"error": "invalid_grant", "error_description": "PKCE check failed"})
            return self._json(200, self._issue(form["client_id"]))
        if form["grant_type"] == "refresh_token":
            client = self.refresh_tokens.pop(form.get("refresh_token"), None)
            if client is None:
                return self._json(400, {"error": "invalid_grant"})
            return self._json(200, self._issue(client))
        return self._json(400, {"error": "unsupported_grant_type"})

    def mcp(self, request):
        if request.method == "DELETE":
            self.sessions.discard(request.headers.get("mcp-session-id"))
            return httpx.Response(200)
        if not self._authorized(request):
            header = 'Bearer realm="mcp"'
            if self.with_resource_metadata:
                header += ', resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"'
            return httpx.Response(401, headers={"WWW-Authenticate": header})
        message = json.loads(request.content)
        method = message.get("method")
        if method == "initialize":
            session = secrets.token_hex(8)
            self.sessions.add(session)
            return self._answer(message, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                                          "serverInfo": {"name": "fake-notion-mcp", "title": "Notion", "version": "1.2"}},
                                headers={"Mcp-Session-Id": session})
        session = request.headers.get("mcp-session-id")
        if self.forget_sessions:
            self.sessions.clear()
            self.forget_sessions = False
        if session not in self.sessions:
            return httpx.Response(404)
        if "id" not in message:
            return httpx.Response(202)
        if method == "tools/list":
            start = int((message.get("params") or {}).get("cursor") or 0)
            page = self.tools[start:start + self.page_size]
            result = {"tools": page}
            if start + self.page_size < len(self.tools):
                result["nextCursor"] = str(start + self.page_size)
            return self._answer(message, result)
        if method == "tools/call":
            params = message["params"]
            name, args = params["name"], params.get("arguments") or {}
            how = self.fail.get(name)
            if how == "rpc_bad_request":
                return self._answer(message, error={"code": -32600, "message": "Invalid request"})
            if how == "rpc_invalid":  # an SDK passes on what the handler threw, maybe halfway through
                self.calls.append((name, args))
                return self._answer(message, error={"code": -32602, "message": "Invalid arguments"})
            if how == "http_500":
                self.calls.append((name, args))
                return httpx.Response(500, text="boom")
            self.calls.append((name, args))
            if how == "rpc_internal":
                return self._answer(message, error={"code": -32603, "message": "Internal error"})
            if how == "is_error":
                return self._answer(message, {"content": [{"type": "text", "text": "Page is locked"}], "isError": True})
            if name == "search":
                text = json.dumps({"results": [{"id": "p1", "title": f"About {args.get('query')}"}]})
                return self._answer(message, {"content": [{"type": "text", "text": text}]})
            if name == "get_page":
                return self._answer(message, {"content": [{"type": "text", "text": f"Page {args.get('id')}"}]})
            return self._answer(message, {"content": [{"type": "text", "text": f"{name} done"}],
                                          "structuredContent": {"ok": True, "tool": name}})
        return self._answer(message, error={"code": -32601, "message": "Method not found"})

    def _answer(self, message, result=None, error=None, headers=None):
        body = {"jsonrpc": "2.0", "id": message.get("id")}
        if error is not None:
            body["error"] = error
        else:
            body["result"] = result
        if self.sse and message.get("method") != "initialize":
            # a server notification first, then the answer, as Streamable HTTP allows
            note = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}}
            text = f"event: message\ndata: {json.dumps(note)}\n\nevent: message\ndata: {json.dumps(body)}\n\n"
            return httpx.Response(200, content=text.encode(),
                                  headers={"Content-Type": "text/event-stream", **(headers or {})})
        return httpx.Response(200, json=body, headers=headers or {})
