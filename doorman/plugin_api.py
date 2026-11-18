"""The contract every plugin implements.

A plugin is a directory with a manifest.yaml and a plugin.py. The manifest
declares reads and write tools (tier, destination fields, parameter schema);
plugin.py implements them:

    class MyTool(Tool):
        def snapshot(self, args): ...            # state before
        def execute(self, args, before): ...     # do it, return ExecResult
        def current(self, object_ref): ...       # state now (drift check)
        def undo(self, object_ref, before, after): ...
        def render_diff(self, before, after, args): ...   # optional

    class Plugin(BasePlugin):
        TOOLS = {"create": MyTool}
        READS = {"list": "read_list"}            # method name

Tool and read names in the manifest are short ("create"); the agent sees them
prefixed with the plugin instance name ("notes.create").
"""

import json
import logging
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any, Callable, Sequence, TypeVar
from urllib.parse import urlsplit

import httpx

from .util import canonical, get_path, normalize

TIERS = ("reversible", "irreversible", "payment")


class Denied(Exception):
    def __init__(self, reason: str, code: str = "denied"):
        super().__init__(reason)
        self.reason = reason
        self.code = code


def iso_moment(value: Any) -> datetime | None:
    """An ISO date or date-time as an aware UTC datetime (without an offset: UTC); None if it isn't one."""
    if isinstance(value, datetime):
        moment = value
    else:
        try:
            moment = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
        except ValueError:
            return None
    return (moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def since_param(params: dict) -> datetime | None:
    """A read's `since` (an ISO date or date-time; a date is its midnight UTC) as an aware UTC datetime, None
    when there is none. Denied when it isn't one."""
    value = params.get("since")
    if not value:
        return None
    moment = iso_moment(value)
    if moment is None:
        raise Denied(f"since={value} isn't an ISO date or date-time (2026-11-01, 2026-11-01T08:00Z)", "invalid")
    return moment


class PluginError(Exception):
    """A plugin failed to do what it was asked."""


class NotSent(PluginError):
    """A send failed in a way that proves nothing went out (refused before any data was accepted).
    Any other error during a send leaves it "unknown": it may have gone out, so it is never retried."""


T = TypeVar("T")


def before_sending(step: Callable[[], T]) -> T:
    """Run a step that comes before anything leaves the box, such as getting a fresh access token. If it
    fails, the send certainly didn't happen, so its error becomes NotSent: the owner sees "failed" and the
    reason (an expired login says to connect again), not "check whether this went out"."""
    try:
        return step()
    except NotSent:
        raise
    except (PluginError, httpx.HTTPError, OSError) as exc:
        raise NotSent(str(exc) or type(exc).__name__) from exc


# methods that change nothing on the server: however they fail, nothing was done
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _http_reason(response: httpx.Response) -> str:
    """The service's own words for an error: Graph and Google say {"error": {"message"|"code"}}, others
    {"error": "..."} or {"error_description": "..."}; the start of the body otherwise."""
    try:
        body = response.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):
            error = error.get("message") or error.get("code")
        reason = body.get("error_description") or error or body.get("message")
        if reason:
            return str(reason)[:300]
    return response.text[:300] or f"HTTP {response.status_code}"


def http_json(service: str, method: str, url: str, *, token: Callable[[], str] | None = None,
              headers: dict | None = None, transport: httpx.BaseTransport | None = None, timeout: float = 60,
              refused_4xx: bool = True, allow: tuple[int, ...] = (), hints: dict[int, str] | None = None,
              **kwargs) -> Any:
    """One HTTP request to a service: its JSON answer ({} for an empty body), or None for a status in
    `allow` (404 for "it's gone"). `token` returns a bearer token; `kwargs` go to httpx (params, json, ...).

    Its errors say whether the request could have done anything, which decides a send's outcome (NotSent:
    certainly not, "failed"; any other PluginError: it may have, "unknown"):

    - no token (an expired login), no connection (DNS, refused, a connect timeout): NotSent, as nothing
      left the box;
    - any other transport error, such as a read timeout or a dropped connection after the body went out:
      PluginError, except for GET and HEAD, which change nothing;
    - 4xx: NotSent when the service only answers 4xx for a request it didn't carry out (`refused_4xx`,
      true for Graph, Google and the WhatsApp sidecar), else PluginError; 401 says to connect again;
    - 5xx: PluginError.

    `hints` adds a sentence for a status (Teams: 403 may need the admin's consent). Once a send's request
    went through, don't let a NotSent from a later step escape `execute`: it would call a sent message
    failed."""
    hints = {401: "the login was refused; connect it again under Plugins", **(hints or {})}
    where = f"{service} {method} {urlsplit(url).path or url}"
    sent_headers = dict(headers or {})
    if token is not None:
        sent_headers["Authorization"] = f"Bearer {before_sending(token)}"
    try:
        with httpx.Client(transport=transport, timeout=timeout) as client:
            response = client.request(method, url, headers=sent_headers, **kwargs)
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.UnsupportedProtocol, httpx.InvalidURL) as exc:
        raise NotSent(f"{service} unreachable: {exc}") from None
    except httpx.HTTPError as exc:
        error = NotSent if method.upper() in SAFE_METHODS else PluginError
        raise error(f"{where}: {type(exc).__name__} {exc}".rstrip()) from None
    status = response.status_code
    if status in allow:
        return None
    if status >= 400:
        hint = f"; {hints[status]}" if status in hints else ""
        error = NotSent if (refused_4xx and status < 500) or method.upper() in SAFE_METHODS else PluginError
        raise error(f"{where} failed with {status}: {_http_reason(response)}{hint}")
    if not response.content:
        return {}
    try:
        return response.json()
    except ValueError:
        raise PluginError(f"{where}: the answer isn't JSON") from None


class StoreTooNew(PluginError):
    """A plugin's store written by a newer version of the plugin (open_store)."""


class StoreOfAnother(PluginError):
    """A plugin's store made for another account or folder than the plugin's now (open_store)."""

    def __init__(self, path: Path, theirs: str, ours: str):
        super().__init__(f"{path.name} was made for {theirs}, and this plugin is now for {ours}")
        self.path, self.theirs, self.ours = path, theirs, ours


Migration = Callable[[sqlite3.Connection], None]


def open_store(path: str | Path, schema: str, migrations: Sequence[Migration] = (), *,
               belongs_to: str | None = None, **connect: Any) -> sqlite3.Connection:
    """A plugin's own SQLite database (an archive, an index of its own), at the layout this code knows.

    `schema` is the newest layout, CREATE ... IF NOT EXISTS throughout: a new file gets it whole. The layout
    has a version (PRAGMA user_version): the first is 1, and a store from before versions counts as 1.
    migrations[n] brings a store from version n + 1 to n + 2, so the newest is len(migrations) + 1. Append to
    the end; never change or reorder one that shipped. A new table or index needs no migration (the schema
    runs after them and creates what's missing); a new column, or data moved or rewritten, does. A
    migration is a function of the connection, run in one transaction with the version bump: it uses
    conn.execute (rows come as tuples), not executescript, which would commit halfway. Before the first
    pending one runs, the file is copied next to itself (<name>.v<version>.bak), so one that goes wrong
    loses nothing.

    A store of a newer version than this code knows is refused (StoreTooNew), not opened: the plugin was
    rolled back, so run the newer one again or restore a backup made before the upgrade.

    belongs_to: what the store was made for (a mailbox, a folder). A store made for something else raises
    StoreOfAnother: the plugin sets it aside (set_aside) and opens a new one, so another account's data
    never mixes in. A store from before it said is taken as made for this one.

    Other keyword arguments go to sqlite3.connect."""
    path = Path(path)
    latest = len(migrations) + 1
    conn = sqlite3.connect(path, **connect)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone():
            version = latest  # a new store: the schema is its layout
        elif version > latest:
            raise StoreTooNew(f"{path.name} is at version {version} of its layout, and this plugin knows up to "
                              f"{latest}: a newer version of the plugin wrote it. Run that one again, or restore a "
                              "backup from before the upgrade.")
        version = version or 1
        if version < latest:
            _copy_store(conn, path.with_name(f"{path.name}.v{version}.bak"))
            for target in range(version + 1, latest + 1):
                conn.execute("BEGIN IMMEDIATE")
                try:
                    migrations[target - 2](conn)
                    conn.execute(f"PRAGMA user_version={int(target)}")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
                conn.execute("COMMIT")
        conn.executescript(schema)
        conn.execute("CREATE TABLE IF NOT EXISTS store_info(key TEXT PRIMARY KEY, value TEXT)")
        conn.execute(f"PRAGMA user_version={int(latest)}")
        if belongs_to is not None:
            row = conn.execute("SELECT value FROM store_info WHERE key='belongs_to'").fetchone()
            if row is None:
                conn.execute("INSERT INTO store_info(key, value) VALUES('belongs_to', ?)", (belongs_to,))
            elif row[0] != belongs_to:
                raise StoreOfAnother(path, row[0], belongs_to)
        conn.commit()
        return conn
    except BaseException:
        conn.close()
        raise


def _copy_store(conn: sqlite3.Connection, dest: Path) -> None:
    """A consistent copy of an open store (its WAL included), written beside and then moved into place."""
    part = dest.with_name(dest.name + ".part")
    target = sqlite3.connect(part)
    try:
        conn.backup(target)
    finally:
        target.close()
    os.replace(part, dest)


def set_aside(path: str | Path, why: str) -> Path:
    """A plugin's file (with its -wal and -shm) or folder renamed beside itself to <name>.<why>-<when>: kept,
    out of the way of a new one. The store must be closed."""
    path = Path(path)
    target = path.with_name(f"{path.name}.{why}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}")
    path.rename(target)
    for suffix in ("-wal", "-shm"):
        if Path(f"{path}{suffix}").exists():
            Path(f"{path}{suffix}").rename(Path(f"{target}{suffix}"))
    return target


@dataclass
class ExecResult:
    result: dict = field(default_factory=dict)
    after: dict | None = None
    object_ref: str | None = None
    summary: str = ""


@dataclass
class PluginContext:
    instance: str
    config: dict
    credentials: dict
    data_dir: Path
    resolve_ref: Callable[[str], tuple[str, bytes]]
    redactor: Any
    owner_identities: set[str]
    log: logging.Logger
    save_credential: Callable[[str, str], None] = lambda key, value: None
    # (name, bytes, content type, ocr, limit) -> {text, pages?, ocr_pages?, note?}: Doorman's text extractor
    # (pypdfium2, OCR for scanned pages), in its own locked-down process. None: extract in this process
    # without OCR.
    extract: Callable[..., dict] | None = None
    # (texts, background) -> {"model", "dim", "vectors": float16 bytes} | {"off": True} | {"busy": True}:
    # Doorman's embedding model for semantic search (embedder.py), when the owner switched it on
    embed: Callable[..., dict] | None = None

    def embed_texts(self, texts: list[str], background: bool = False) -> dict:
        if self.embed is None:
            return {"off": True}
        return self.embed(list(texts), background=background)

    def extract_text(self, name: str, content: bytes, content_type: str | None = None, ocr: bool = True,
                     limit: int = 2_000_000, check_pdf: bool | str = True, background: bool = False) -> dict:
        """{text, report, pages?, ocr_pages?, note?}: see extract.extract. `background`: nobody waits for
        it (an archive's backfill), so it steps aside for the agent's reads; {busy: True} if it gave up."""
        from .extract import TEXT_TYPES, extract, suffix_for

        plain = suffix_for(name, content_type) in TEXT_TYPES or (content_type or "").startswith("text/")
        if self.extract is not None and not plain:  # PDFs, images, Office files: the extractor's process
            if background:
                return self.extract(name, content, content_type, ocr, limit, check_pdf, background=True)
            return self.extract(name, content, content_type, ocr, limit, check_pdf)
        return extract(name, content, content_type, None, limit=limit, check_pdf=check_pdf)


def _flatten(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).startswith("_"):
                continue
            out.extend(_flatten(item, f"{prefix}{key}."))
        return out
    if isinstance(value, list):
        text = ", ".join(str(item) if not isinstance(item, (dict, list)) else canonical(item) for item in value)
        return [(prefix[:-1], text)]
    return [(prefix[:-1], "" if value is None else str(value))]


def generic_diff(before: dict | None, after: dict | None) -> list[dict]:
    """Field-level diff: '-' lines for old values, '+' lines for new ones."""
    old = dict(_flatten(before or {}))
    new = dict(_flatten(after or {}))
    lines = []
    for key in list(old) + [k for k in new if k not in old]:
        if key in old and key in new and old[key] == new[key]:
            continue
        if key in old:
            lines.append({"sign": "-", "field": key, "value": old[key]})
        if key in new:
            lines.append({"sign": "+", "field": key, "value": new[key]})
    return lines


class Tool:
    # fields that change as a side effect, such as an "updated" timestamp; ignored when comparing states
    IGNORE_FIELDS: frozenset[str] = frozenset()
    # True when undo() already puts back only what the action changed (a folder, a set of tags) and
    # leaves everything else as it is now, so it is safe when other fields changed in the meantime
    FIELD_SCOPED_UNDO = False

    def __init__(self, plugin: "BasePlugin", spec: dict):
        self.plugin = plugin
        self.spec = spec

    @property
    def ctx(self) -> PluginContext:
        return self.plugin.ctx

    def tier(self, args: dict) -> str:
        return self.spec.get("tier", "reversible")

    def destinations(self, args: dict) -> list[tuple[str, str]]:
        found = []
        for dest in self.spec.get("destinations", []):
            values = get_path(args, dest["field"])
            if values is None:
                continue
            if not isinstance(values, list):
                values = [values]
            for value in values:
                if isinstance(value, list):
                    found.extend((dest["kind"], normalize(dest["kind"], v)) for v in value if v)
                elif value:
                    found.append((dest["kind"], normalize(dest["kind"], value)))
        return found

    def trusted_destinations(self, args: dict) -> set[str]:
        """Destinations trusted by context, e.g. the participants of a thread being replied to."""
        return set()

    def prepare(self, args: dict) -> dict:
        """Fill in what the tool works out from its arguments before the call is checked and journaled: a
        reply's recipients, subject and thread headers from the mail it answers. What this returns is what
        the owner sees on the approval, what the payload hash covers and what execute gets. Runs after the
        arguments were checked against the manifest's schema."""
        return args

    def destination_origins(self, args: dict) -> dict[str, dict]:
        """Where destinations not from the owner came from, when the tool knows better than the read log:
        {address: {"origin": ref, "label": ..., "from": ..., "answered": True}} for the people a reply-all
        takes from the mail it answers. Shown with the "new recipient" warning."""
        return {}

    def snapshot(self, args: dict) -> dict | None:
        return None

    def ref_for(self, args: dict) -> str | None:
        """The object an existing-object write works on, so a write that fails halfway can be checked and
        reverted. None for creates and for tools that can't tell."""
        return None

    def preview(self, args: dict, before: dict | None) -> dict | None:
        return None

    def execute(self, args: dict, before: dict | None) -> ExecResult:
        raise NotImplementedError

    def current(self, object_ref: str) -> dict | None:
        raise NotImplementedError

    def undo(self, object_ref: str, before: dict | None, after: dict | None) -> None:
        raise NotImplementedError

    def undo_fields(self, object_ref: str, fields: dict, now: dict) -> str | None:
        """Put back only `fields` (field -> its value before the action) and keep every other field as it
        is `now`. Used when someone changed other fields of the object after the action."""
        raise NotImplementedError

    @classmethod
    def can_undo(cls) -> bool:
        return cls.undo is not Tool.undo

    @classmethod
    def can_undo_fields(cls) -> bool:
        return cls.FIELD_SCOPED_UNDO or cls.undo_fields is not Tool.undo_fields

    @classmethod
    def can_check_drift(cls) -> bool:
        return cls.current is not Tool.current

    def render_diff(self, before: dict | None, after: dict | None, args: dict) -> list[dict]:
        return generic_diff(before, after)

    def describe(self, args: dict) -> str:
        return self.spec["name"]

    def follow_up(self, args: dict, result: dict | None) -> str | None:
        """For actions that can't be undone: what the owner could do instead."""
        return None

    def outgoing(self, args: dict) -> dict | None:
        """For a send whose arguments only point at something (a note id, a file path): what actually goes
        out, so the owner approves the content and not an id. {"label": "Copy of your note", "title": ...,
        "text": ...}; any key may be missing. Shown on the approval as it is now."""
        return None

    def verify_sent(self, args: dict, before: dict | None, error: str) -> str | dict:
        """Optional: did a send whose outcome is unknown go out after all? `before` is what snapshot() returned
        just before the attempt (a send can keep what it needs to recognise itself there, such as the
        Message-ID it is about to use, under a key starting with '_'), `error` what broke off. Answer
        "sent", "failed" (certainly not out) or "unknown" (can't tell yet), or a dict with that `status` and
        optionally `detail` (a sentence for the owner) and `result` (kept as the send's result when sent).
        Doorman asks a few times over about half an hour (sends.VERIFY_AFTER_MINUTES), then leaves it to
        the owner. Say "failed" only on evidence: the owner may send it again."""
        raise NotImplementedError

    @classmethod
    def can_verify(cls) -> bool:
        return cls.verify_sent is not Tool.verify_sent


class BasePlugin:
    TOOLS: dict[str, type[Tool]] = {}
    READS: dict[str, str] = {}

    def __init__(self, ctx: PluginContext, manifest: dict):
        self.ctx = ctx
        self.manifest = manifest
        self.config = ctx.config
        self.credentials = ctx.credentials
        self.tools: dict[str, Tool] = {}
        for spec in manifest.get("tools", []):
            cls = self.TOOLS.get(spec["name"])
            if cls is None:
                raise PluginError(f"{manifest['name']}: tool {spec['name']} has no implementation")
            self.tools[spec["name"]] = cls(self, spec)
        for spec in manifest.get("reads", []):
            if spec["name"] not in self.READS:
                raise PluginError(f"{manifest['name']}: read {spec['name']} has no implementation")
            if not callable(getattr(self, self.READS[spec["name"]], None)):
                raise PluginError(f"{manifest['name']}: read {spec['name']} names {self.READS[spec['name']]}, "
                                  "which the plugin doesn't have")

    def run_read(self, name: str, params: dict) -> Any:
        return getattr(self, self.READS[name])(params)

    def open_ref(self, path: str) -> tuple[str, bytes]:
        """Return (filename, bytes) for a reference like '<instance>:<path>'."""
        raise PluginError(f"{self.ctx.instance} does not provide references")

    def maintenance(self) -> None:
        """Periodic upkeep, e.g. rebuilding a search index. Runs in the worker."""

    def run_job(self, name: str, budget: float) -> dict | None:
        """One slice of a background job the manifest declares (`jobs:`), e.g. syncing a mail archive. Stop
        after about `budget` seconds; the worker calls again every_minutes. Returns a short status for the
        owner app ({"summary": "..."} and anything else worth showing), or None."""
        return None

    def check(self) -> str | None:
        """Can the plugin reach its service with its credentials? A short problem description, or None.
        Runs in the worker every plugin_check_minutes; a problem shows up under Needs attention."""
        return None

    def poll_events(self, cursor: str | None) -> tuple[list[dict], str | None]:
        """New events since cursor, for the event feed and triggers; the manifest declares their types
        (`events:`). Each is {"type": ..., "ref": ..., more fields}. The worker calls this every
        trigger_poll_minutes and stores the cursor. Returns (events, new_cursor); the first poll (cursor None)
        usually only finds where "now" is."""
        return [], cursor

    def index_feed(self, cursor: str | None, budget: float) -> dict:
        """What changed for Doorman's search index (library.py) since `cursor` (None: everything, from the
        start), for a plugin whose manifest has `index: {read, kinds, every_minutes}`. Doorman asks every
        every_minutes, after each of the plugin's jobs, and right after a write it made through the plugin.
        Stop after about `budget` seconds and say `more`. Answer:

            {"items": [item, ...],      # new or changed since the cursor
             "removed": [key, ...],     # gone since the cursor
             "cursor": "...",           # where the next call goes on (any string; kept by Doorman)
             "more": False,             # True: call again right away, there's more
             "complete": False,         # True: `items` is everything there is; anything else of it goes
             "reset": False}            # True: I'm starting over, everything comes again from here

        A call with cursor None, or an answer with `reset`, begins a pass over everything the plugin has:
        once the answers say no `more`, whatever of it the index has that the pass didn't bring is dropped.
        So a plugin needn't remember every deletion forever. It should notice a cursor it didn't give (its
        own store was deleted or put back from a backup: keep an id of the store in the cursor) and answer
        that one from the start with `reset`.

        An item: {"key" (unique in the plugin), "ref"? (default "<instance>:<key>"; what reads and doorman
        meta take), "kind": mail|file|note|event|task|chat, "title", "date" (ISO; what since/until and the
        newest-first order go by), "from"?, "to"?, "in"? (folder, calendar, chat: filters), "has_attachment"?,
        "text" or "parts": [{"part", "name"?, "text"}] (part 0 the body, others attachments), "same"? (a key
        copies elsewhere share, e.g. "mid:<message-id>"), "fields": {...} (shown with a hit as they are)}.
        An item the index can't take (no key, an unknown kind) is skipped and counted, shown to the owner;
        the rest of the answer counts. The text goes no further than the index: what an agent sees of it
        passes the read named in `index:` (its switch, trust, guard and pseudonyms)."""
        return {"items": [], "cursor": cursor}

    def known_recipients(self, destinations: list[list[str]]) -> dict[str, dict]:
        """For a manifest's `known_recipients:` (contacts or sent_mail): which of these [kind, value]
        destinations of a send the owner already knows, so the approval has no "new recipient" warning.
        Answers {value: {...}} for the ones it knows and leaves the rest out:
            contacts:   {"name": "Anna de Vries"}, from the owner's own address books only
            sent_mail:  {"messages": [{"id": Message-ID, "date": ISO}]}, mail in the owner's Sent folder
                        (Doorman drops any message one of its own actions touched)
        Called during the check of a send, so it should be quick: answer from a cache where it can."""
        return {}

    def close(self) -> None:
        pass


def starting_soon(entries: list[dict], announced: dict, minutes: float, now: datetime,
                  zone: tzinfo | None = None) -> tuple[list[dict], dict]:
    """`event_soon` for each calendar entry that starts within `minutes` from now, once per occurrence.
    `announced` (kept in the plugin's cursor) maps ref|start to the start; an entry drops out of it once it
    has started, and a moved entry is announced again at its new time. All-day entries have no start time
    and are left out. Returns (events, the new announced)."""
    soon, keep = [], {}
    horizon = now + timedelta(minutes=minutes)
    for entry in entries:
        if entry.get("all_day") or not isinstance(entry.get("start"), str) or "T" not in entry["start"]:
            continue
        try:
            start = datetime.fromisoformat(entry["start"].replace("Z", "+00:00"))
        except ValueError:
            continue
        if start.tzinfo is None:
            start = start.replace(tzinfo=zone or timezone.utc)
        if not now <= start <= horizon:
            continue
        key = f"{entry['ref']}|{entry['start']}"
        keep[key] = entry["start"]
        if key not in announced:
            soon.append({"type": "event_soon", "ref": entry["ref"], "summary": entry.get("summary") or "",
                         "start": entry["start"], "end": entry.get("end"), "location": entry.get("location") or "",
                         "calendar": entry.get("calendar"), "minutes": int((start - now).total_seconds() // 60)})
    return soon, keep


def soon_minutes(config: dict) -> float:
    """A calendar's `soon_minutes` (default 30). Agents may set it (agent_settings), so a bad value falls back
    instead of stopping the plugin's events."""
    try:
        value = float(config.get("soon_minutes", 30))
    except (TypeError, ValueError):
        return 30.0
    return min(max(value, 1.0), 24 * 60.0) if value == value else 30.0


def calendar_cursor(cursor: str | None) -> dict:
    """A calendar plugin's cursor: {"invites": [...], "soon": {...}}. Before event_soon it was the list of
    invitations alone."""
    value = json.loads(cursor) if cursor else {}
    if isinstance(value, list):
        return {"invites": value, "soon": {}}
    return {"invites": list(value.get("invites") or []), "soon": dict(value.get("soon") or {})}