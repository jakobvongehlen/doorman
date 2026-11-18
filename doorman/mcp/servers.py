"""MCP servers as plugin instances: tools come from the server, not from a manifest.yaml.

Each instance of type `mcp` is one remote server. Its tool list is stored in the database (mcp_tools) and
refreshed whenever Doorman connects and on every plugin check, and the instance's manifest is built
from it: a tool the server marks `readOnlyHint: true` is a read, everything else is a write. Writes can't
be undone (Doorman can't snapshot what a foreign tool changes), so each one asks the owner, unless the
owner chose "Always allow" for that tool; it then runs without asking while every check passes, like a
plugin with no_approval.

Rules that keep the server from loosening its own classification:
- the labels count only in the first list Doorman sees, which the owner looks at when connecting;
- a tool that arrives later starts as a write whatever its label says, and a tool first seen as a write
  stays one (so a renamed or new tool can't slip in as a read); the owner can choose "Treat as read";
- the owner's choice wins over the server's label in both directions;
- a different server address under the same name is a new server: its sign-in, token and tool choices
  start from nothing.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import jsonschema

from doorman import clock
from doorman.guard import text_hash
from doorman.sanitize import clean_text
from doorman.plugin_api import BasePlugin, Denied, ExecResult, NotSent, PluginContext, PluginError, Tool
from doorman.util import dumps, loads

from .client import AuthRequired, McpClient, OAuth, b64url, check_url, pkce
from .known import icon_for

LOGIN_TTL = 15 * 60
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
LOGIN_KEYS = ("refresh_token", "access_token", "access_expires", "oauth", "account")

BASE_MANIFEST: dict[str, Any] = {
    "name": "mcp",
    "version": "0.1.0",
    "description": ("A service's own MCP server, e.g. Notion, Linear or GitHub. Reads run freely; every write "
                    "asks you first, unless you allow that tool."),
    "credentials": [],
    "optional_credentials": ["token"],
    "config": {
        "url": "The server's address, e.g. https://mcp.notion.com/mcp",
        "client_id": "Only if the server's sign-in doesn't let apps register: a client ID from the provider",
    },
    "login": "oauth",
    "setup": [
        "Find the address of the service's MCP server in its documentation, e.g. `https://mcp.notion.com/mcp`. "
        "Use servers the service runs itself: Doorman gives the server your sign-in.",
        "Add it under **Add an MCP server → Another server**, then **Connect account** on its card and sign in on the "
        "service's page. A server that takes an access token instead gets it under **Settings and credentials**.",
        "The sign-in ends on a page that doesn't load (`127.0.0.1`): copy that page's whole address and paste "
        "it into the field under **Open sign-in**.",
    ],
    "reads": [],
    "tools": [],
}

EMAIL_WORDS = {"to", "cc", "bcc", "email", "emails", "mail", "recipient", "recipients", "attendee", "attendees",
               "invitee", "invitees", "guest", "guests", "member", "members", "user", "users", "share", "shares"}
NOT_ADDRESSES = {"name", "names", "display_name", "title", "subject", "body", "text", "message", "content", "id"}


def host_of(url: str) -> str:
    return urlparse(url or "").hostname or url or "MCP server"


def title_from_host(url: str) -> str:
    """mcp.notion.com -> Notion: the part people know, when the server doesn't name itself."""
    parts = [p for p in host_of(url).split(".") if p not in ("mcp", "api", "www", "app")]
    name = parts[-2] if len(parts) >= 2 else (parts[0] if parts else "MCP server")
    return name[:1].upper() + name[1:]


def server_title(info: dict) -> str | None:
    """The name the server gives itself, unless it is a package name (notion-mcp-server): then the
    host name reads better."""
    title = str(info.get("title") or "").strip()
    if title:
        return title[:60]
    name = str(info.get("name") or "").strip()
    if name and not re.search(r"[-_/@]", name) and name != name.lower():
        return name[:60]
    return None


_checked: dict[str, bool] = {}  # schema text -> valid; manifests are rebuilt on every lookup


def clean_schema(schema: Any) -> dict:
    """The tool's input schema, if it is a valid one; otherwise any object."""
    if not isinstance(schema, dict) or schema.get("type", "object") != "object":
        return {"type": "object"}
    key = json.dumps(schema, sort_keys=True, default=str)
    if key not in _checked:
        try:
            jsonschema.validators.validator_for(schema).check_schema(schema)
            _checked[key] = True
        except jsonschema.SchemaError:
            _checked[key] = False
        if len(_checked) > 5000:
            _checked.clear()
    return schema if _checked.get(key, False) else {"type": "object"}


def _words(key: str) -> list[str]:
    """toRecipients, to_recipients, to-recipients -> [to, recipients]."""
    return [w for w in re.split(r"[_\-.\s]+", re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(key)).lower()) if w]


def guess_destinations(params: dict) -> list[dict]:
    """Fields that name where something goes (an email address, a phone number), so the usual checks and
    warnings apply: an address the agent wrote itself makes an allowed tool ask again. Field names are a
    guess, so it errs towards too many: a name field that is no address only costs a question."""
    out: list[dict] = []

    def walk(schema: Any, path: str, kind: str | None, depth: int) -> None:
        if not isinstance(schema, dict) or depth > 4:
            return
        if isinstance(schema.get("items"), dict):  # a list: its items are at the same path (get_path expands)
            walk(schema["items"], path, kind, depth + 1)
        for key, prop in (schema.get("properties") or {}).items():
            if not isinstance(prop, dict):
                continue
            words = _words(key)
            items = prop.get("items") if isinstance(prop.get("items"), dict) else {}
            fmt = prop.get("format") or items.get("format")
            here = kind
            if fmt == "email" or any(w in EMAIL_WORDS or w.endswith("mail") for w in words):
                here = "email"
            elif any(w in ("phone", "phones", "mobile", "sms", "whatsapp") for w in words):
                here = "phone"
            sub = f"{path}.{key}" if path else str(key)
            kinds = {prop.get("type"), items.get("type")} - {None}
            nested = "object" in kinds or prop.get("properties") or items.get("properties")
            if nested:
                walk(prop, sub, here, depth + 1)
            elif here and "_".join(words) not in NOT_ADDRESSES and (not kinds or kinds & {"string", "array"}):
                out.append({"field": sub, "kind": here})

    walk(params, "", None, 0)
    return out


def shape_result(result: dict) -> Any:
    """A tools/call result as JSON for the agent: the structured content if there is any, else the text
    (parsed when it is JSON), with images and binary resources left out."""
    if result.get("structuredContent") is not None:
        return result["structuredContent"]
    items: list[Any] = []
    for item in result.get("content") or []:
        if not isinstance(item, dict):
            continue
        kind = item.get("type")
        if kind == "text":
            items.append(str(item.get("text", "")))
        elif kind == "resource_link":
            items.append({k: item[k] for k in ("uri", "name", "title", "description", "mimeType") if item.get(k)})
        elif kind == "resource":
            res = item.get("resource") or {}
            items.append({"uri": res.get("uri"), "text": res["text"]} if "text" in res
                         else {"uri": res.get("uri"), "omitted": res.get("mimeType") or "binary"})
        elif kind in ("image", "audio"):
            items.append({"omitted": item.get("mimeType") or kind})
    if len(items) == 1 and isinstance(items[0], str):
        text = items[0]
        if text.strip()[:1] in ("{", "["):
            try:
                return json.loads(text)
            except ValueError:
                pass
        return {"text": text}
    return items


def error_text(result: dict) -> str:
    texts = [str(i.get("text", "")) for i in result.get("content") or [] if isinstance(i, dict) and i.get("type") == "text"]
    return " ".join(t for t in texts if t).strip()[:500] or "no details"


def _differences(was: dict, now: dict, was_read: bool, now_read: bool) -> list[str]:
    """What of a tool differs between two lists, in the owner's words."""
    what = []
    if (was.get("title"), was.get("description")) != (now.get("title"), now.get("description")):
        what.append("description")
    if was.get("inputSchema") != now.get("inputSchema"):
        what.append("parameters")
    if was_read != now_read or was.get("annotations") != now.get("annotations"):
        what.append("label")
    return what


class ToolStore:
    """The tool lists of all MCP instances, with the owner's choices per tool."""

    def __init__(self, db):
        self.db = db

    @staticmethod
    def _row(row: dict) -> dict:
        row = dict(row)
        row["spec"] = loads(row["spec"], {})
        return row

    def rows(self, instance: str, include_removed: bool = False) -> list[dict]:
        sql = "SELECT * FROM mcp_tools WHERE instance=?" + ("" if include_removed else " AND removed IS NULL")
        return [self._row(r) for r in self.db.all(sql + " ORDER BY name", (instance,))]

    def row(self, instance: str, name: str) -> dict | None:
        row = self.db.one("SELECT * FROM mcp_tools WHERE instance=? AND name=?", (instance, name))
        return self._row(row) if row else None

    @staticmethod
    def is_read(row: dict) -> bool:
        """The owner's choice, else the server's label, but never looser than when the tool was first seen."""
        if row.get("treat_as") in ("read", "write"):
            return row["treat_as"] == "read"
        return bool(row["hint_read"]) and bool(row["first_read"])

    def sync(self, instance: str, tools: list[dict]) -> dict:
        """Store the server's current list. New tools come in on (a write asks anyway); tools that are gone
        are kept, marked removed, and come back with the owner's choices if the server lists them again."""
        now = clock.iso()
        added, changed, seen = [], [], set()
        differences: dict[str, dict] = {}  # name -> what differs from the stored tool, and how it read before
        with self.db.tx() as conn:
            existing = {r["name"]: r for r in conn.execute(
                "SELECT name, spec, hint_read, removed FROM mcp_tools WHERE instance=?", (instance,)).fetchall()}
            first = not existing
            for tool in tools:
                name = str(tool.get("name") or "")
                if not NAME_RE.match(name) or name in seen:
                    continue
                seen.add(name)
                annotations = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
                spec = {"title": tool.get("title") or annotations.get("title") or None,
                        "description": str(tool.get("description") or "")[:4000],
                        "inputSchema": tool.get("inputSchema") or {"type": "object"},
                        "annotations": annotations}
                read = annotations.get("readOnlyHint") is True
                if name in existing:
                    old = existing[name]
                    if old["spec"] != dumps(spec) or bool(old["hint_read"]) != read or old["removed"]:
                        changed.append(name)
                        was = loads(old["spec"], {})
                        differences[name] = {"what": _differences(was, spec, bool(old["hint_read"]), read),
                                             "was": str(was.get("description") or ""), "back": bool(old["removed"])}
                    conn.execute("UPDATE mcp_tools SET spec=?, hint_read=?, removed=NULL WHERE instance=? AND name=?",
                                 (dumps(spec), int(read), instance, name))
                else:
                    added.append(name)
                    # only the first list's labels count; a tool that arrives later starts as a write
                    conn.execute(
                        "INSERT INTO mcp_tools(instance, name, spec, hint_read, first_read, treat_as, allowed, "
                        "first_seen, initial, removed) VALUES(?,?,?,?,?,NULL,0,?,?,NULL)",
                        (instance, name, dumps(spec), int(read), int(read and first), now, int(first)))
            removed = [n for n, r in existing.items() if n not in seen and not r["removed"]]
            for name in removed:
                conn.execute("UPDATE mcp_tools SET removed=? WHERE instance=? AND name=?", (now, instance, name))
        tell = False if first else self._note(instance, now, added, differences, removed)
        return {"added": added, "changed": changed, "removed": removed, "count": len(seen), "tell": tell}

    # What changed since the owner last looked, per server: {"since", "new": [names], "changed": {name:
    # {"what": [...], "was": the description before}}, "removed": [names]}. Kept until they say they saw it.

    def news(self, instance: str) -> dict:
        return loads(self.db.get_setting(f"mcp_news:{instance}"), {}) or {}

    def clear_news(self, instance: str) -> None:
        self.db.exec("DELETE FROM settings WHERE key=?", (f"mcp_news:{instance}",))

    def _note(self, instance: str, now: str, added: list[str], differences: dict[str, dict],
              removed: list[str]) -> bool:
        """Add one sync's changes to the server's news. What undoes itself drops out: a tool that came and
        went unseen, or one that left and is back as it was. True when there is something new to tell the
        owner about: a tool that arrived, or one that reads or takes something else now."""
        news = self.news(instance)
        new, changed, gone = list(news.get("new") or []), dict(news.get("changed") or {}), list(news.get("removed") or [])
        tell = bool(added)
        new += added
        for name, diff in differences.items():
            what = list(diff["what"])
            if diff["back"]:
                if name in gone:
                    gone.remove(name)
                else:
                    what.append("back")  # the owner saw it go: it returns with their choices, so say so
            if name in new or not what:
                continue
            before = changed.get(name) or {"what": [], "was": diff["was"]}
            tell = tell or any(w not in before["what"] for w in what)
            changed[name] = {"what": sorted({*before["what"], *what}), "was": before["was"]}
        for name in removed:
            if name in new:
                new.remove(name)  # it came and went before the owner saw it
            else:
                gone.append(name)
            changed.pop(name, None)
        if not (new or changed or gone):
            self.clear_news(instance)
            return False
        self.db.set_setting(f"mcp_news:{instance}", dumps({"since": news.get("since") or now, "new": sorted(new),
                                                           "changed": changed, "removed": sorted(gone)}))
        return tell

    def rule(self, instance: str, name: str) -> dict:
        row = self.row(instance, name)
        if row is None:
            raise Denied(f"{instance} has no tool {name}", "unknown_tool")
        return {"treat_as": row["treat_as"], "allowed": bool(row["allowed"])}

    def set_rule(self, instance: str, name: str, rule: dict) -> None:
        self.db.exec("UPDATE mcp_tools SET treat_as=?, allowed=? WHERE instance=? AND name=?",
                     (rule["treat_as"], int(bool(rule["allowed"])), instance, name))

    def allowed(self, instance: str, name: str) -> bool:
        row = self.row(instance, name)
        return bool(row and row["allowed"] and not row["removed"] and not self.is_read(row))

    def server(self, instance: str) -> dict:
        return self.db.one("SELECT * FROM mcp_servers WHERE instance=?", (instance,)) or {}

    def set_server(self, instance: str, **fields: Any) -> None:
        current = {k: v for k, v in self.server(instance).items() if k != "instance"}
        current.update(fields)
        cols = ("url", "title", "version", "auth", "synced", "error")
        self.db.exec(
            f"INSERT INTO mcp_servers(instance, {', '.join(cols)}) VALUES(?{',?' * len(cols)}) "
            f"ON CONFLICT(instance) DO UPDATE SET {', '.join(f'{c}=excluded.{c}' for c in cols)}",
            (instance, *(current.get(c) for c in cols)))

    def delete(self, instance: str) -> None:
        self.db.exec("DELETE FROM mcp_tools WHERE instance=?", (instance,))
        self.db.exec("DELETE FROM mcp_servers WHERE instance=?", (instance,))
        self.clear_news(instance)


HELD_DESCRIPTION = ("(description held back: Doorman's injection guard flagged it; the owner can release it. "
                    "Use the tool by its name and parameters only.)")
DESCRIBING = ("title", "description", "examples")


def tool_text(name: str, spec: dict) -> str:
    """What the guard reads of a tool: its title and description, and every description in its schema."""
    lines = [str(spec.get("title") or ""), str(spec.get("description") or "")]

    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key in DESCRIBING and not isinstance(item, dict):
                    lines.append(f"{path}: {item}")
                else:
                    walk(item, f"{path}.{key}" if path else str(key))
        elif isinstance(value, list):
            for item in value:
                walk(item, path)

    walk(spec.get("inputSchema") or {}, name)
    return "\n".join(line for line in lines if line.strip())


def without_descriptions(schema: Any) -> Any:
    """A schema without its free text (descriptions, titles, examples): names and types stay."""
    if isinstance(schema, dict):
        return {k: without_descriptions(v) for k, v in schema.items()
                if not (k in DESCRIBING and not isinstance(v, dict))}
    if isinstance(schema, list):
        return [without_descriptions(v) for v in schema]
    return schema


class McpType:
    """The registry's plugin type for MCP servers. Unlike a plugin directory, its manifest differs per
    instance: it is built from the instance's stored tool list."""

    name = "mcp"
    path = None
    # set by the engine: the guard's verdict per text (None: may pass), so a description that tries to give
    # agents instructions is held back like any third-party item; None here (tests, no engine) scans nothing
    screen = None
    # set by the engine: tell the owner that a server's tool list changed (instance, the server's title)
    tell = None

    def __init__(self, db, vault):
        self.store = ToolStore(db)
        self.vault = vault
        self.manifest = BASE_MANIFEST

    def title(self, instance: str, block: dict) -> str:
        return self.store.server(instance).get("title") or title_from_host((block.get("config") or {}).get("url", ""))

    def bind(self, instance: str, url: str) -> None:
        """The instance's server is the one at `url`. If the name pointed at another address before, that
        server's tools, the owner's choices and its sign-in and token are dropped first: none of it
        belongs to the new server."""
        known = self.store.server(instance).get("url")
        if known == url:
            return
        if known:
            self.store.delete(instance)
            for key in (*LOGIN_KEYS, "token"):
                self.vault.delete(instance, key)
        self.store.set_server(instance, url=url)

    def rescreen(self, instance: str) -> None:
        """After a sync: the guard looks at each tool's title and descriptions (its own and its parameters'),
        which agents read as they are. A flagged tool is listed with its name and schema only until the
        owner releases it on the quarantine screen. Without a scanner nothing changes (the owner's choice:
        unscanned text goes through)."""
        if self.screen is None:
            return
        rows = self.store.rows(instance)
        host = host_of(self.store.server(instance).get("url") or "")
        items = [{"text": tool_text(row["name"], row["spec"]), "source": f"{instance} (MCP tool list)",
                  "ref": f"{instance}.{row['name']}", "label": f"Description of the tool {row['name']}",
                  "sender": host or None} for row in rows]
        verdicts = self.screen(items)
        if verdicts is None:
            return
        held = {row["name"]: text_hash(item["text"]) for row, item, verdict in zip(rows, items, verdicts) if verdict}
        self.store.db.set_setting(f"mcp_held:{instance}", dumps(held))

    def held(self, instance: str) -> set[str]:
        """The tools whose descriptions the guard holds back and the owner hasn't released."""
        held = loads(self.store.db.get_setting(f"mcp_held:{instance}"), {}) or {}
        if not held:
            return set()
        released = {r["sha256"] for r in self.store.db.all(
            f"SELECT sha256 FROM quarantine WHERE status='released' AND sha256 IN ({','.join('?' * len(held))})",
            tuple(held.values()))}
        return {name for name, sha in held.items() if sha not in released}

    def manifest_for(self, instance: str, block: dict) -> dict:
        url = (block.get("config") or {}).get("url", "")
        if url:
            self.bind(instance, url)
        title = self.title(instance, block)
        reads, tools = [], []
        held = self.held(instance)
        for row in self.store.rows(instance):
            spec = row["spec"]
            params = clean_schema(spec.get("inputSchema"))
            entry = {"name": row["name"], "title": clean_text(spec.get("title") or row["name"])[0], "params": params,
                     "description": clean_text(spec.get("description") or spec.get("title") or row["name"])[0].strip()}
            if row["name"] in held:
                entry = {"name": row["name"], "title": row["name"], "params": without_descriptions(params),
                         "description": HELD_DESCRIPTION}
            if self.store.is_read(row):
                reads.append({**entry, "trust": "third_party"})
            else:
                tools.append({**entry, "tier": "irreversible", "destinations": guess_destinations(params)})
        return {**BASE_MANIFEST, "title": title, "login_provider": title, "reads": reads, "tools": tools,
                "description": (f"{title}, through its MCP server at {host_of(url)}. Reads run right away; each "
                                "write waits for the owner unless they allowed that tool.")}

    def card(self, instance: str, block: dict) -> dict:
        """What the owner app shows on the server's card, tool by tool."""
        server = self.store.server(instance)
        news = self.store.news(instance)
        new, changed = set(news.get("new") or []), news.get("changed") or {}
        tools = []
        for row in self.store.rows(instance):
            spec = row["spec"]
            tools.append({
                "name": row["name"], "title": spec.get("title") or row["name"],
                "description": (spec.get("description") or "").strip(),
                "kind": "read" if self.store.is_read(row) else "write",
                "label": "read" if row["hint_read"] else "write",       # what the server says now
                "treat_as": row["treat_as"], "allowed": bool(row["allowed"]),
                "destructive": (spec.get("annotations") or {}).get("destructiveHint") is True,
                "new": row["name"] in new, "changed": changed.get(row["name"]),  # since the owner last looked
            })
        url = (block.get("config") or {}).get("url") or ""
        return {"url": url or None, "host": host_of(url), "icon": icon_for(url),
                "title": self.title(instance, block), "synced": server.get("synced"), "error": server.get("error"),
                "auth": server.get("auth"), "tools": tools,
                "news": {"since": news.get("since"), "new": sorted(new), "changed": sorted(changed),
                         "removed": list(news.get("removed") or [])} if news else None}

    def create(self, ctx: PluginContext, manifest: dict | None = None) -> "McpPlugin":
        return McpPlugin(ctx, self)


class McpTool(Tool):
    """A write tool of an MCP server: it can't be undone, so it is a send."""

    def tier(self, args: dict) -> str:
        return "irreversible"

    def describe(self, args: dict) -> str:
        return f"{self.plugin.title}: {self.spec.get('title') or self.spec['name']}"

    def execute(self, args: dict, before: dict | None) -> ExecResult:
        result = self.plugin.call(self.spec["name"], args)
        return ExecResult(result=result if isinstance(result, dict) else {"content": result},
                          summary=self.describe(args))

    def follow_up(self, args: dict, result: dict | None) -> str | None:
        return f"Doorman can't undo this. If it needs undoing, do it in {self.plugin.title} itself."


class McpPlugin(BasePlugin):
    transport: httpx.BaseTransport | None = None  # tests put a fake server here
    READS: dict[str, str] = {}

    def __init__(self, ctx: PluginContext, kind: McpType):  # noqa: D107 - tools come from the store, not TOOLS
        self.ctx = ctx
        self.config = ctx.config
        self.credentials = ctx.credentials
        self.kind = kind
        self.store = kind.store
        self._client: McpClient | None = None
        self._token: str | None = None
        self._expires = 0.0
        self._lock = threading.RLock()

    @property
    def block(self) -> dict:
        return {"config": self.config}

    @property
    def manifest(self) -> dict:  # type: ignore[override]
        return self.kind.manifest_for(self.ctx.instance, self.block)

    @property
    def tools(self) -> dict[str, Tool]:  # type: ignore[override]
        return {spec["name"]: McpTool(self, spec) for spec in self.manifest["tools"]}

    @property
    def title(self) -> str:
        return self.kind.title(self.ctx.instance, self.block)

    @property
    def url(self) -> str:
        try:
            return check_url(self.config.get("url"))
        except PluginError as exc:
            raise PluginError(f"{self.ctx.instance}: {exc}") from None

    # ---------------------------------------------------------------- calls

    def client(self) -> McpClient:
        with self._lock:
            if self._client is None:
                self._client = McpClient(self.url, token=self._access_token, refresh=self._refresh,
                                         transport=self.transport)
            return self._client

    def call(self, name: str, args: dict) -> Any:
        result = self.client().call_tool(name, args)
        if result.get("isError"):
            raise PluginError(f"{self.title} says: {error_text(result)}")
        return shape_result(result)

    def run_read(self, name: str, params: dict) -> Any:
        if name not in {r["name"] for r in self.manifest["reads"]}:
            raise PluginError(f"{self.ctx.instance} has no read {name}")
        return self.call(name, params)

    def sync(self) -> dict:
        """Fetch the server's tool list and store it."""
        instance = self.ctx.instance
        try:
            client = self.client()
            info = client.server_info if client.protocol else client.initialize()
            tools = client.list_tools()
        except AuthRequired as exc:
            self.store.set_server(instance, error=str(exc), auth=None if self._signed_in() else "oauth")
            raise
        except PluginError as exc:
            self.store.set_server(instance, error=str(exc))
            raise
        changes = self.store.sync(instance, tools)
        self.kind.rescreen(instance)
        self.store.set_server(instance, title=server_title(info) or self.store.server(instance).get("title"),
                              version=info.get("version"), synced=clock.iso(), error=None,
                              auth="signed_in" if self._signed_in() else "none")
        if changes.pop("tell") and self.kind.tell is not None:
            self.kind.tell(instance, self.title)
        return changes

    def check(self) -> str | None:
        try:
            self.sync()
        except AuthRequired:
            return "not signed in: connect it under Plugins"
        except PluginError as exc:
            return str(exc)
        return None

    def close(self) -> None:
        with self._lock:
            client, self._client = self._client, None
        if client:
            client.close()

    # ---------------------------------------------------------------- tokens

    def _signed_in(self) -> bool:
        return bool(self.credentials.get("token") or self.credentials.get("refresh_token")
                    or self._stored_access_token())

    def _stored_access_token(self) -> str | None:
        token = self.credentials.get("access_token")
        expires = float(self.credentials.get("access_expires") or 0)
        return token if token and (not expires or time.time() < expires - 60) else None

    def _oauth(self) -> dict:
        return loads(self.credentials.get("oauth"), {}) or {}

    def _access_token(self) -> str | None:
        if self.credentials.get("token"):
            return self.credentials["token"]
        with self._lock:
            if self._token and time.monotonic() < self._expires - 60:
                return self._token
            if self.credentials.get("refresh_token"):
                if not self._refresh():
                    raise NotSent(f"the {self.title} sign-in expired; connect the account again under Plugins")
                return self._token
        return self._stored_access_token()

    def _refresh(self, failed: str | None = None) -> bool:
        """A new access token from the refresh token. False when there is none or it no longer works.
        `failed` is the token a request was refused with: if another call has replaced it meanwhile, that
        one is used instead of refreshing again (sending a used refresh token can end the sign-in)."""
        with self._lock:
            if failed is not None and self._token and self._token != failed:
                return True
            saved = self._oauth()
            refresh = self.credentials.get("refresh_token")
            if not refresh or not saved.get("meta"):
                return False
            try:
                body = OAuth(self.url, self.transport).token(
                    saved["meta"], saved["client"], {"grant_type": "refresh_token", "refresh_token": refresh})
            except PluginError as exc:
                self.ctx.log.warning("refreshing the %s sign-in failed: %s", self.ctx.instance, exc)
                return False
            self._take_tokens(body)
            return True

    def _take_tokens(self, body: dict) -> None:
        self._token = body["access_token"]
        self._expires = time.monotonic() + int(body.get("expires_in") or 3600)
        if body.get("refresh_token") and body["refresh_token"] != self.credentials.get("refresh_token"):
            self._store("refresh_token", body["refresh_token"])
        if not self.credentials.get("refresh_token"):
            # no refresh token: keep the access token itself, so a restart doesn't lose the sign-in
            self._store("access_token", body["access_token"])
            self._store("access_expires", str(time.time() + int(body["expires_in"])) if body.get("expires_in") else None)

    def _store(self, key: str, value: str | None) -> None:
        if value is None:
            self.credentials.pop(key, None)
        else:
            self.credentials[key] = value
        self.ctx.save_credential(key, value)

    # ---------------------------------------------------------------- sign-in

    @property
    def _pending_path(self) -> Path:
        return self.ctx.data_dir / "login_pending.json"

    def login_status(self) -> dict:
        if not self.config.get("url"):
            return {"connected": False, "ready": False, "error": "Not set up yet: the server address is missing."}
        if not self._signed_in() and not self.store.server(self.ctx.instance).get("auth"):
            try:  # never reached yet: does it need a sign-in at all?
                self.sync()
            except PluginError:
                pass
        if self._signed_in() or self.store.server(self.ctx.instance).get("auth") == "none":
            return {"connected": True, "ready": True, "account": self.credentials.get("account")}
        return {"connected": False, "ready": True}

    def login_start(self, redirect_uri: str | None = None) -> dict:
        url = self.url
        redirect_uri = redirect_uri or f"http://127.0.0.1:{int(self.config.get('redirect_port', 8799))}/"
        if not redirect_uri.startswith(("http://127.0.0.1:", "http://localhost:")):
            raise PluginError("the sign-in must return to a loopback address")
        probe = McpClient(url, transport=self.transport)
        try:
            open_, header = probe.probe()
        finally:
            probe.close()
        if open_:
            self.store.set_server(self.ctx.instance, auth="none")
            self._try_sync()
            return {"auth_url": None, "connected": True}
        oauth = OAuth(url, self.transport)
        meta = oauth.discover(header)
        saved = self._oauth()
        if self.config.get("client_id"):
            client = {"client_id": self.config["client_id"], "client_secret": self.credentials.get("client_secret"),
                      "auth_method": "client_secret_post" if self.credentials.get("client_secret") else "none"}
        elif saved.get("client") and saved.get("meta", {}).get("issuer") == meta["issuer"] \
                and saved.get("redirect_uri") == redirect_uri:
            client = saved["client"]  # registered before with this sign-in service
        else:
            client = oauth.register(meta, redirect_uri)
        verifier, challenge = pkce()
        state = b64url(secrets.token_bytes(24))
        pending = {"state": state, "verifier": verifier, "redirect_uri": redirect_uri, "created": time.time(),
                   "meta": meta, "client": client}
        tmp = self._pending_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(pending))
        os.chmod(tmp, 0o600)
        tmp.replace(self._pending_path)
        return {"auth_url": oauth.authorization_url(meta, client, redirect_uri, state, challenge),
                "redirect_uri": redirect_uri, "expires_in": LOGIN_TTL}

    def login_finish(self, response_url: str) -> dict:
        try:
            pending = json.loads(self._pending_path.read_text())
        except (OSError, ValueError):
            raise Denied("no sign-in in progress; start again", "login") from None
        if time.time() - pending["created"] > LOGIN_TTL:
            self._pending_path.unlink(missing_ok=True)
            raise Denied("the sign-in took too long; start again", "login")
        params = parse_qs(urlparse(response_url.strip()).query)
        if params.get("error"):
            self._pending_path.unlink(missing_ok=True)
            detail = (params.get("error_description") or params["error"])[0]
            raise Denied(f"{self.title} says: {detail}", "login")
        code, state = (params.get("code") or [None])[0], (params.get("state") or [None])[0]
        if not code:
            raise Denied("that address has no code in it; paste the whole address of the page you ended on", "login")
        if not state or not secrets.compare_digest(state, pending["state"]):
            raise Denied("that address belongs to a different sign-in; start again", "login")
        self._pending_path.unlink(missing_ok=True)
        body = OAuth(self.url, self.transport).token(
            pending["meta"], pending["client"],
            {"grant_type": "authorization_code", "code": code, "redirect_uri": pending["redirect_uri"],
             "code_verifier": pending["verifier"]})
        with self._lock:
            self._store("oauth", json.dumps({"meta": pending["meta"], "client": pending["client"],
                                             "redirect_uri": pending["redirect_uri"]}))
            for key in ("refresh_token", "access_token", "access_expires"):
                self._store(key, None)
            if body.get("refresh_token"):
                self._store("refresh_token", body["refresh_token"])
            self._take_tokens(body)
        self.store.set_server(self.ctx.instance, auth="signed_in")
        self.close()  # a fresh session with the new token
        self._try_sync()
        return {"connected": True, "account": self.credentials.get("account")}

    def logout(self) -> dict:
        saved = self._oauth()
        token = self.credentials.get("refresh_token") or self.credentials.get("access_token")
        if token and saved.get("meta"):
            OAuth(self.url, self.transport).revoke(saved["meta"], saved["client"], token)
        with self._lock:
            for key in ("refresh_token", "access_token", "access_expires", "account"):
                self._store(key, None)
            self._token = None
        self.close()
        self.store.set_server(self.ctx.instance, auth="oauth")
        return {"connected": False}

    def interactive_login(self, say, read_line=input, finish=None) -> None:
        """doorman-admin login: open the sign-in, then paste the address it ends on."""
        start = self.login_start()
        if not start.get("auth_url"):
            say("Connected: this server needs no sign-in.")
            return
        say(f"Open this address in a browser and sign in:\n\n{start['auth_url']}\n")
        say("It ends on a page that doesn't load (127.0.0.1). Paste that page's whole address here:")
        (finish or self.login_finish)(read_line().strip())
        say("Connected.")

    def _try_sync(self) -> None:
        try:
            self.sync()
        except PluginError as exc:
            self.ctx.log.warning("listing the tools of %s failed: %s", self.ctx.instance, exc)
