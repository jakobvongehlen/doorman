"""Doorman's core. Every read, write, revert and switch goes through here."""

import logging
import re
import secrets
import shlex
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import jsonschema
from croniter import croniter

from . import archive_copy, clock, retention, sanitize, spotlight, structure, upkeep
from .approvals import Approvals
from .auth import ROLES, Auth
from .db import Database
from .agent_setup import AgentSetup
from .embedder import Embedder
from .extractor import Extractor
from .feed import Feed
from .guard import REASON as GUARD_REASON
from .guard import Guard, GuardUnavailable, held_row
from .journal import Journal
from .library import Library
from .notify import Notifier
from .plugin_api import TIERS, Denied, NotSent, PluginError, Tool, generic_diff
from .plugin_setup import PluginSetup
from .policy import Policy
from .provenance import Provenance
from .pseudonym import Pseudonymizer
from .owner_questions import OwnerQuestions
from .questions import Questions
from .egress.service import Egress
from .readlog import ReadLog
from .redaction import Redactor
from .registry import Registry, polls_events
from .reviewer import Reviewer
from .search import Search
from .sends import Sends, checking
from .tasks import Tasks
from .util import UPLOAD, canonical, dumps, get_path, loads, safe_filename, sha256_hex
from .vault import Vault

log = logging.getLogger("doorman.engine")

RECORD_CATEGORIES = ["invoice", "meeting_request", "question", "information", "newsletter", "receipt",
                     "delivery", "security", "personal", "other"]
# What an agent hears while the owner has paused Doorman. Its key still works, so it should wait, not
# look for another way in or ask for a new key.
PAUSED = ("the owner paused Doorman: every call is refused until they resume it. Your key still works; "
          "wait and try again later (doorman status says PAUSED until then). Sends waiting for approval "
          "stay waiting: the owner can still decide them.")
# a pause of one key (a honeytoken, a decoy key, a leak): waiting doesn't end it, only the owner does. Neutral on
# purpose: the agent isn't told what tripped it (egress/service.py, "decoy keys").
KEY_PAUSED = ("the owner's Doorman paused your key; nothing more can be done until the owner resumes it. "
              "Stop and report.")
# what a tool call carrying a honeytoken or a decoy key answers: like a failure, not a tripwire
CALL_REJECTED = "the call failed: the service didn't accept it"
RECORD_ACTIONS = ["reply", "pay", "schedule", "file", "forward", "ignore", "review"]
RECORD_SCHEMA = {
    "type": "object",
    "properties": {
        "source": {"type": "string", "pattern": r"^[a-z][a-z0-9_]*:.+$"},
        "category": {"enum": RECORD_CATEGORIES},
        "from": {"type": "string", "maxLength": 200},
        # when the item was sent or changed (set by the reader from the item, not by its model)
        "date": {"type": "string", "pattern": structure.PATTERNS["datetime"].pattern},
        "dates": {"type": "array", "items": {"type": "string", "format": "date"}, "maxItems": 10},
        "due": {"type": "string", "format": "date"},
        "amount": {"type": "number"},
        "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
        "suggested_action": {"enum": RECORD_ACTIONS},
        "summary": {"type": "string", "maxLength": 500},
    },
    "required": ["source", "category", "suggested_action", "summary"],
    "additionalProperties": False,
}
REF_RE = re.compile(r"^([a-z][a-z0-9_]*):(.+)$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
# the reader/actor split (an opt-in role per agent key, not a setting): in plain words, as the owner reads them
# in the journal and the read log too
READER_WRITE = ("this is a reader key: under the reader/actor split it reads mail and writes records, and can't "
                "change or send anything. The actor agent does that")
ACTOR_RAW = ("this is an actor key: under the reader/actor split it can't read raw third-party content (mail "
             "text, attachments, messages); read the reader's records instead (doorman records)")


def strip_private(state: Any) -> Any:
    """Drop fields starting with '_' (raw blobs, timestamps) before comparing states."""
    if isinstance(state, dict):
        return {k: strip_private(v) for k, v in state.items() if not str(k).startswith("_")}
    if isinstance(state, list):
        return [strip_private(v) for v in state]
    return state


def changed_fields(before: dict | None, after: dict | None) -> list[str]:
    """Top-level fields whose value differs; all fields when one side doesn't exist."""
    old, new = before or {}, after or {}
    return [k for k in dict.fromkeys([*old, *new]) if canonical(old.get(k)) != canonical(new.get(k))]


class Engine:
    def __init__(self, config, db: Database | None = None, *, starter_plugins: bool = True):
        self.config = config
        self.db = db or Database(config.data_dir / "doorman.db")
        self.vault = Vault(config.data_dir)
        if self.vault.key_source == "file" and config.get("vault_key_file_warn", True):
            log.warning("the vault key comes from %s, next to the vault it opens; set DOORMAN_VAULT_KEY instead",
                        self.vault.key_path)
        self.redactor = Redactor(config)
        self.extractor = Extractor(config)
        self.embedder = Embedder(config, self.db)
        # the OCR model (~600 MB) and the embedding model (~500 MB) needn't sit in memory together for
        # background work: whichever starts asks the other to go if it isn't busy
        self.embedder.make_room = self.extractor.stop_if_unused
        self.extractor.make_room = self.embedder.stop_if_unused
        self.registry = Registry(config, self.db, self.vault, self.redactor, self.plugin_resolve_ref,
                                 self.extractor.extract, self.embedder.embed)
        if self.db.fresh and starter_plugins:  # a new Doorman: its notes and the file archive from the start
            self.registry.add_starter_plugins()
        # the one search index plugins feed (library.py): derived, so out of backups and rebuilt after a restore
        (config.data_dir / "search").mkdir(parents=True, exist_ok=True)
        (config.data_dir / "search" / ".no-backup").touch()
        self.library = Library(config.data_dir / "search" / "index.db", self.embedder)
        self.search = Search(self)  # one search over that index, as an agent may see it (search.py)
        self.search.tidy()  # a plugin removed while Doorman was down, or no longer fed
        self.journal = Journal(self.db)
        self.provenance = Provenance(self.db)
        self.reads = ReadLog(self.db)
        self.pseudonyms = Pseudonymizer(self.config, self.db)
        self._reads_pruned = 0.0
        self.notifier = Notifier(config, self.db, self.vault)
        self.reviewer = Reviewer(config)
        self.policy = Policy(config, self.db, self.provenance, self.reviewer, self.registry)
        self.auth = Auth(self.db)
        self.guard = Guard(config, self.db, self.attention, self.resolve_attention)
        self.registry.mcp.screen = self._screen_texts  # MCP tool descriptions reach agents as they are
        self.registry.mcp.tell = self._mcp_tools_changed
        self.lock = threading.RLock()  # serializes policy checks with the journal writes they count
        self._local = threading.local()
        self._checked: dict[str, float] = {}  # plugin -> last credentials check (timestamp)
        self._last_sweep = 0.0
        self._polled: dict[str, float] = {}  # plugin -> last event poll (timestamp)
        self._poll_results: dict[str, dict] = {}  # plugin -> {polled, error}: what watch_status tells agents
        self._events_pruned = 0.0
        self._tables_pruned = 0.0
        self.jobs: dict[str, dict] = {}       # "plugin.job" -> its last run (server.start_jobs)
        self.tasks = Tasks(self)              # tasks and the lease an agent holds on one (tasks.py)
        self.approvals = Approvals(self)      # what waits for the owner's word (approvals.py)
        self.plugin_setup = PluginSetup(self) # plugins as the owner sets them up (plugin_setup.py)
        self.setup = AgentSetup(self)         # what agents may change about the setup (agent_setup.py)
        self.questions = Questions(self)      # agents' questions to the reader about one item (questions.py)
        self.owner_questions = OwnerQuestions(self)  # agents' questions to the owner (owner_questions.py)
        self.feed = Feed(self)                # Doorman's own events, each key's cursor, the bell (feed.py)
        self.sends = Sends(self)              # approved sends off the owner's request; unknown ones checked
        self.egress = Egress(self)            # network watch: the proxy's rules, leak check, log (egress/service.py)
        self.reads.on_read = self.egress.note_read  # what agents read, fingerprinted for the leak check
        self.journal.on_config = self.feed.mark_caps_dirty
        self.last_tick: float | None = None
        self._last_silence_check = 0.0
        if self.db.get_setting("first_start") is None:
            self.db.set_setting("first_start", clock.iso())

    def health(self) -> tuple[bool, dict]:
        """For GET /health: the database answers and the worker ticked recently."""
        try:
            self.db.one("SELECT 1 AS ok")
            db_ok = True
        except Exception:  # noqa: BLE001
            db_ok = False
        age = None if self.last_tick is None else round(clock.now().timestamp() - self.last_tick, 1)
        stalled = age is not None and age > max(60.0, 6 * float(self.config.get("worker_interval_seconds", 5)))
        last_backup = self.db.get_setting("last_backup")
        ok = db_ok and not stalled
        return ok, {"status": "ok" if ok else "unhealthy", "db": db_ok, "worker_seconds_ago": age,
                    "last_backup": last_backup}

    # ------------------------------------------------------------------ helpers

    @property
    def public_url(self) -> str:
        return self.config["public_url"].rstrip("/")

    def killed(self) -> bool:
        return self.db.get_setting("killed") == "1"

    def refuse_if_paused(self) -> None:
        if self.killed():
            raise Denied(PAUSED, "paused")

    def resolve_ref(self, ref: str) -> tuple[str, bytes]:
        match = REF_RE.match(ref or "")
        if not match:
            raise Denied(f"not a reference: {ref}", "bad_ref")
        instance, path = match.groups()
        expected = getattr(self._local, "expected_refs", None)
        if instance == UPLOAD:
            # only inside a checked call: _check_refs made sure the upload belongs to the calling key
            if expected is None or ref not in expected:
                raise PluginError(f"{ref} wasn't part of the checked request")
            filename, content = self._upload_file(path)
            if sha256_hex(content) != expected[ref]:
                raise NotSent(f"{ref} changed after the request was checked; send it again")
            return filename, content
        state = self.registry.state(instance)
        if not state["enabled"]:
            raise Denied(f"{instance} is switched off in the owner app (Plugins)", "plugin_disabled")
        filename, content = self.registry.instance(instance).open_ref(path)
        if expected is not None:
            if ref not in expected:
                raise PluginError(f"{ref} wasn't part of the checked request")
            if sha256_hex(content) != expected[ref]:
                raise NotSent(f"{ref} changed after the request was checked; send it again")
        return filename, content

    def plugin_resolve_ref(self, ref: str) -> tuple[str, bytes]:
        """What plugins get as ctx.resolve_ref: only the refs of the checked write Doorman is running for
        them (an attachment, a file to save). Anything else, such as a ref a compromised plugin planted in
        its own event cursor, would open another plugin's item without a check of who asks."""
        expected = getattr(self._local, "expected_refs", None)
        if expected is None or ref not in expected:
            raise PluginError(f"{ref} wasn't part of the checked request")
        return self.resolve_ref(ref)

    def _check_refs(self, session: dict, tool, args: dict) -> list[dict]:
        """Attachments are reads: same switches and taint as reading them directly.
        Returns a fingerprint per reference, which binds approvals to the content."""
        out = []
        for field in tool.spec.get("ref_fields", []):
            values = get_path(args, field) or []
            for ref in values if isinstance(values, list) else [values]:
                match = REF_RE.match(ref or "") if isinstance(ref, str) else None
                if match and match.group(1) == UPLOAD:
                    out.append(self._check_upload(session, ref, match.group(2)))
                    continue
                if not match or match.group(1) not in self.registry.configured():
                    raise Denied(f"not a reference to a plugin: {ref}", "bad_ref")
                instance = match.group(1)
                self._guard(session, instance, write=False)
                manifest = self.registry.manifest(instance)
                read_name = manifest.get("ref_read")
                spec = next((r for r in manifest.get("reads", []) if r["name"] == read_name), None)
                if spec is None:
                    raise Denied(f"{instance} doesn't allow attaching its content", "not_allowed")
                if read_name in self.registry.state(instance)["disabled_tools"]:
                    raise Denied(f"{instance}.{read_name} is Off in {instance}'s settings (Plugins → Tools), so its "
                                 "content can't be attached", "not_allowed")
                filename, content = self.resolve_ref(ref)
                self.auth.taint(session["id"], False, bool(spec.get("private")))
                out.append({"ref": ref, "name": filename, "size": len(content), "sha256": sha256_hex(content),
                            "_content": content})
        return out

    def _check_based_on(self, session: dict, key: dict, tool, args: dict) -> None:
        """What an agent says its work was made from (files.keep's based_on, the tool's `based_on_arg`) shows
        in search as where the work comes from, so each ref must name something this key could read: an item
        of a source it may search (in the index), one its read log has, or its own upload. Refused otherwise."""
        field = tool.spec.get("based_on_arg")
        refs = args.get(field) if field else None
        if not refs:
            return
        sources = {s["name"]: s for s in self.search.sources(session, key["role"])}
        bad = []
        for ref in refs if isinstance(refs, list) else [refs]:
            match = REF_RE.match(ref) if isinstance(ref, str) else None
            if match and match.group(1) == UPLOAD:
                ok = self.db.one("SELECT 1 FROM uploads WHERE sha256=? AND key_id=?", (match.group(2), key["id"]))
            elif match and match.group(1) in sources:
                rule = sources[match.group(1)]
                ok = self.library.knows(match.group(1), ref, rule["skip_kinds"], rule["parts"]) or self._read_by(key, ref)
            else:
                ok = match is not None and self._read_by(key, ref)
            if not ok:
                bad.append(str(ref))
        if bad:
            raise Denied(f"{field} names what this key hasn't read and can't find in search: {', '.join(bad[:5])}; "
                         f"give only refs of items you read", "invalid")

    def _read_by(self, key: dict, ref: str) -> bool:
        """Whether this key's read log has the item (a ref an answer it got held), not held back by the guard."""
        refs = list(dict.fromkeys([ref, re.sub(r"#\d+$", "", ref)]))
        return self.db.one(
            "SELECT 1 FROM reads, json_each(reads.labels) AS label WHERE reads.key_id=? AND reads.status IN "
            f"('ok', 'unscanned') AND json_extract(label.value, '$.ref') IN ({','.join('?' * len(refs))}) AND "
            "coalesce(json_extract(label.value, '$.quarantined'), 0) = 0 LIMIT 1", (key["id"], *refs)) is not None

    # ------------------------------------------------------------------ uploads

    @property
    def uploads_dir(self):
        return self.config.data_dir / "uploads"

    def upload(self, session: dict, key: dict, filename: str, content: bytes) -> dict:
        """A file the agent made, kept so a send or files.save can use it as upload:<sha256>. Nothing goes
        anywhere: a send that attaches it still needs the owner's approval."""
        self._guard(session, None, write=False)
        limit = int(float((self.config.get("uploads") or {}).get("max_mb", 25)) * 1024 * 1024)
        if len(content) > limit:
            raise Denied(f"uploads are at most {limit // (1024 * 1024)} MB", "too_large")
        if not content:
            raise Denied("the upload is empty", "invalid")
        name = safe_filename(filename)
        sha = sha256_hex(content)
        self._upload_quota(key, sha, len(content))
        self.uploads_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = self.uploads_dir / sha
        if not target.is_file():
            part = self.uploads_dir / f".{sha}.{secrets.token_hex(4)}"
            part.write_bytes(content)
            part.replace(target)
        now = clock.iso()
        self.db.exec("INSERT INTO uploads(sha256, key_id, name, size, created, last_used) VALUES(?,?,?,?,?,?) "
                     "ON CONFLICT(sha256, key_id) DO UPDATE SET name=excluded.name, last_used=excluded.last_used",
                     (sha, key["id"], name, len(content), now, now))
        return {"ref": f"{UPLOAD}:{sha}", "name": name, "size": len(content), "sha256": sha}

    def _upload_quota(self, key: dict, sha: str, size: int) -> None:
        """What one key may keep in uploads/ at a time (uploads.max_total_mb, 500; uploads.max_files, 200), so
        a leaked key or an injected agent can't fill the disk Doorman's database lives on. Uploads go after
        keep_days unused, or the owner raises the limits."""
        settings = self.config.get("uploads") or {}
        max_mb, max_files = float(settings.get("max_total_mb", 500)), int(settings.get("max_files", 200))
        row = self.db.one("SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS total FROM uploads WHERE key_id=? "
                          "AND sha256 != ?", (key["id"], sha))
        if row["total"] + size > max_mb * 1024 * 1024:
            raise Denied(f"this key's uploads would take more than {max_mb:g} MB (uploads.max_total_mb); unused "
                         f"ones expire after {settings.get('keep_days', 7)} days", "too_large")
        if row["n"] + 1 > max_files:
            raise Denied(f"this key keeps {row['n']} uploads, the most it may (uploads.max_files); unused ones "
                         f"expire after {settings.get('keep_days', 7)} days", "too_large")

    def _upload_file(self, sha: str, key_id: int | None = None) -> tuple[str, bytes]:
        if not SHA_RE.match(sha or ""):
            raise Denied(f"not an upload reference: upload:{sha}", "bad_ref")
        sql, args = "SELECT name FROM uploads WHERE sha256=?", [sha]
        if key_id is not None:
            sql += " AND key_id=?"
            args.append(key_id)
        row = self.db.one(sql + " ORDER BY last_used DESC LIMIT 1", tuple(args))
        path = self.uploads_dir / sha
        if row is None or not path.is_file():
            raise Denied(f"no upload upload:{sha} from this agent key (uploads expire after "
                         f"{(self.config.get('uploads') or {}).get('keep_days', 7)} days unused)", "bad_ref")
        return row["name"], path.read_bytes()

    def _check_upload(self, session: dict, ref: str, sha: str) -> dict:
        self._guard(session, None, write=False)
        filename, content = self._upload_file(sha, session["key_id"])
        if sha256_hex(content) != sha:
            raise Denied(f"{ref} is damaged; upload it again", "bad_ref")
        self.db.exec("UPDATE uploads SET last_used=? WHERE sha256=? AND key_id=?", (clock.iso(), sha, session["key_id"]))
        return {"ref": ref, "name": filename, "size": len(content), "sha256": sha, "_content": content}

    def prune_uploads(self, force: bool = False) -> int:
        """Hourly: uploads unused for keep_days go. Returns how many files were deleted."""
        if not force and clock.now().timestamp() - getattr(self, "_uploads_pruned", 0.0) < 3600:
            return 0
        self._uploads_pruned = clock.now().timestamp()
        days = float((self.config.get("uploads") or {}).get("keep_days", 7))
        self.db.exec("DELETE FROM uploads WHERE last_used<?", (clock.iso(clock.now() - timedelta(days=days)),))
        keep = {r["sha256"] for r in self.db.all("SELECT DISTINCT sha256 FROM uploads")}
        removed = 0
        if self.uploads_dir.is_dir():
            for path in self.uploads_dir.iterdir():
                if path.name not in keep and not path.name.startswith("."):
                    path.unlink(missing_ok=True)
                    removed += 1
        return removed

    # ------------------------------------------------------------------ the guard, for the owner

    def guard_settings(self, enabled: Any = None, threshold: Any = None) -> dict:
        before, after = self.guard.save(enabled, threshold)
        words = []
        if before["enabled"] != after["enabled"]:
            words.append("on" if after["enabled"] else "OFF: third-party text reaches agents unscanned")
        if before["threshold"] != after["threshold"]:
            words.append(f"threshold {before['threshold']:g} → {after['threshold']:g}")
        self.journal.create(kind="config", tool="guard.settings", tier="irreversible", decision="run",
                            status="done", before=before, after=after,
                            summary="Injection guard: " + (", ".join(words) or "saved, unchanged"))
        if enabled is True and self.guard.backend is None and not self.guard.model_ready():
            self.guard.fetch()  # switched on: its model comes with it, in the background
        return self.guard.status()

    def quarantine_decide(self, qid: int, release: bool) -> dict:
        row = self.guard.decide(qid, release)
        what = row["label"] or row["ref"] or f"item #{qid}"
        self.journal.create(kind="config", tool="guard.release" if release else "guard.keep", tier="irreversible",
                            decision="run", status="done", args={"quarantine": qid, "sha256": row["sha256"]},
                            summary=(f"Released to agents: {what} ({row['source']})" if release
                                     else f"Kept held back: {what} ({row['source']})"))
        return row

    def _guard(self, session: dict, instance: str | None, write: bool) -> None:
        """What an agent may use is decided in one place, each plugin's settings (registry.find_tool and
        find_read). Sessions and tasks carry no limits of their own (their old plugin_allowlist and read_only
        columns are ignored since 2026-11-07); here only a pause and an ended session count."""
        self.refuse_if_paused()
        if self.auth.paused(session["key_id"]):
            raise Denied(KEY_PAUSED, "key_paused")
        if session["killed"]:
            raise Denied("this session was ended", "session_ended")

    @staticmethod
    def _validate(schema: dict | None, value: Any, what: str) -> None:
        if not schema:
            return
        try:
            jsonschema.validate(value, schema, format_checker=jsonschema.FormatChecker())
        except jsonschema.ValidationError as exc:
            path = ".".join(str(p) for p in exc.absolute_path)
            raise Denied(f"invalid {what}{' at ' + path if path else ''}: {exc.message}", "invalid") from None
        except Exception as exc:  # noqa: BLE001 - a broken schema (an MCP server's $ref to nowhere)
            raise Denied(f"can't check the {what}: the tool's schema is broken ({type(exc).__name__})",
                         "invalid") from None

    # ------------------------------------------------------------------ reads

    def read(self, session: dict, key: dict, name: str, params: dict) -> Any:
        """Every read lands in the read log (self.reads), whether it worked, was denied or failed."""
        try:
            data, trust, unscanned = self._read(session, key, name, params)
        except Denied as exc:
            status = "quarantined" if exc.code == "quarantined" else "denied"
            self.reads.add(key, session, name, params, status=status, error=exc.reason)
            raise
        except Exception as exc:
            self.reads.add(key, session, name, params, status="failed", error=str(exc))
            raise
        shown, hidden = self.pseudonyms.hide(data, self.plugin_type(name.split(".", 1)[0]))
        self.reads.add(key, session, name, params, data, trust=trust, hidden=hidden,
                       status="unscanned" if unscanned else "ok", error=unscanned)
        return shown

    def spotlit(self, session: dict, name: str, data: Any, trust: str | None = None) -> dict:
        """A read's response body: third-party data wrapped and datamarked (spotlight.py), anything else as
        {"data": data}. `trust` None: the read's own (from its manifest)."""
        settings = spotlight.settings(self.config)
        if trust is None:
            trust = self.registry.find_read(name)[2].get("trust", "third_party")
        if trust != "third_party" or not settings["enabled"]:
            return {"data": data}
        task = self.tasks.get(session.get("task_id"))
        text = task["text"] if task and task["trusted"] and task["status"] == "claimed" else None
        source = {"records": "records the reader wrote from third-party items",
                  "questions": "the reader's answer, written from a third-party item"}.get(
            name, f"a third-party source ({name})")
        return spotlight.wrap(spotlight.datamark(data, settings["datamark"]), source, text,
                              datamarked=bool(settings["datamark"]))

    def plugin_type(self, instance: str | None) -> str | None:
        return (self.registry.configured().get(instance) or {}).get("type") if instance else None

    def for_agent(self, value: Any, instance: str | None = None) -> Any:
        """Anything from a plugin on its way to an agent: sensitive parts become placeholders."""
        return self.pseudonyms.hide(value, self.plugin_type(instance))[0]

    def _unhide_args(self, name: str, tier: str, args: dict) -> dict:
        """Placeholders an agent passes back turn into the original text, but only for reversible writes:
        a send carrying one would hand the hidden text to someone else. The text put back stays hidden from
        agents wherever it shows up again (a draft's subject, a kept file), whatever the plugin."""
        tokens = self.pseudonyms.tokens_in(args)
        if not tokens:
            return args
        if tier != "reversible":
            raise Denied(f"{name} would send text that is hidden from you ({tokens[0]}); write it without the "
                         "placeholder, or ask the owner to do this one", "pseudonym")
        return self.pseudonyms.restore(args, remember=True)

    def _read(self, session: dict, key: dict, name: str, params: dict) -> tuple[Any, str, str | None]:
        """(data, trust, why it went out unscanned or None)."""
        instance, plugin, spec = self.registry.find_read(name)
        self._guard(session, instance, write=False)
        if self.config["reader_actor_split"] and key["role"] == "actor" and spec.get("raw"):
            raise Denied(ACTOR_RAW, "role")
        self._validate(spec.get("params"), params, "parameters")
        data = plugin.run_read(spec["name"], params)
        return self._screen(session, name, spec, params, data)

    def _screen(self, session: dict, name: str, spec: dict, params: dict, data: Any) -> tuple[Any, str, str | None]:
        """What any read's answer goes through before an agent gets it: third-party text cleaned, redacted and
        scanned by the guard; the session tainted; destinations noted for provenance. (data, trust, why it
        went out unscanned or None). engine.search.query puts each source's hits through it as that source's read."""
        trust = spec.get("trust", "third_party")
        unscanned = None
        if trust == "third_party":
            data = self.redactor.value(sanitize.clean_value(data)[0])
            # before taint and provenance: an item the agent never gets taints nothing
            data, unscanned = self._scan(name, spec, params, data)
            data = _without_guard_text(data)
        else:
            # the owner's own data can still hold names strangers chose (a file saved under its sender's name):
            # cleaned of invisible and look-alike characters, at no cost; not redacted, it's the owner's
            data = sanitize.clean_value(data)[0]
        self.auth.taint(session["id"], trust == "third_party", bool(spec.get("private")))
        self.provenance.record(session["id"], data, name, trust)
        return data, trust, unscanned

    # ------------------------------------------------------------------ the injection guard

    def _scan(self, name: str, spec: dict, params: dict, data: Any) -> tuple[Any, str | None]:
        """Third-party text goes through the guard (guard.py) before any agent gets it. A single item over
        the threshold is refused; in a list, only that item is masked. If the scanner can't run, the data
        goes through as it is and the reason comes back (the read log marks it, Needs attention lists it)."""
        if not self.guard.enabled:
            return data, None
        path = spec.get("scan_items")
        if path and isinstance(data, dict) and isinstance(data.get(path), list):
            items = data[path]
        elif isinstance(data, list):
            items = data
        else:
            items = None
        unscanned = None
        skip = frozenset(spec.get("not_scanned") or ())
        try:
            verdicts = self.guard.check([_scan_item(name, params, item, skip) for item in (items or [data])])
        except GuardUnavailable as exc:
            unscanned = f"unscanned: {exc}"
            verdicts = exc.verdicts or [None] * len(items or [data])
        if items is None:
            held = verdicts[0]
            if held:
                raise Denied(f"held back: {held.get('reason') or GUARD_REASON}. The owner can release it in "
                             "Doorman.", "quarantined")
            return self._mark_held(data), unscanned
        # an item held back before (its full text, read on its own) stays held in every list it shows up in.
        # Not in the event feed: the reader follows it, and its reads of a message with the chat before it
        # can hold a ref whose own text is clean (quarantine goes by text, a ref is only a label there)
        earlier = set() if name == "events" else self.guard.held_refs(
            [i["ref"] for i in items if isinstance(i, dict) and isinstance(i.get("ref"), str)])
        verdicts = [held or ({"reason": GUARD_REASON} if isinstance(item, dict) and item.get("ref") in earlier else None)
                    for item, held in zip(items, verdicts)]
        masked = [held_row(item, held) if held else self._mark_held(item) for item, held in zip(items, verdicts)]
        return ({**data, path: masked} if items is not data else masked), unscanned

    def _screen_texts(self, items: list[dict]) -> list[dict | None] | None:
        """The guard's verdict per text ({text, source, ref, label, sender}) for text that doesn't come
        through a read (an MCP server's tool descriptions): None per text that may pass. None in all when the
        guard is off; with the scanner down, only what was held already stays held."""
        if not self.guard.enabled:
            return [None] * len(items)
        try:
            return self.guard.check([{**item, "text": sanitize.clean_text(item["text"])[0]} for item in items])
        except GuardUnavailable as exc:
            return exc.verdicts or [None] * len(items)

    def _mark_held(self, item: Any) -> Any:
        """Attachments the guard holds back show as quarantined in the message that has them."""
        if not isinstance(item, dict) or not isinstance(item.get("attachments"), list):
            return item
        refs = [a.get("ref") for a in item["attachments"] if isinstance(a, dict) and isinstance(a.get("ref"), str)]
        held = self.guard.held_refs(refs)
        if not held:
            return item
        return {**item, "attachments": [{**a, "quarantined": True} if isinstance(a, dict) and a.get("ref") in held
                                        else a for a in item["attachments"]]}

    # ------------------------------------------------------------------ one item by its ref

    def item_of(self, ref: Any) -> dict:
        """How to read the item a ref points to: {instance, ref, read, params, attachments}. The plugin's
        manifest names the read and its parameter (`item: {read, param}`); an attachment's ref
        (mail:<id>#<n>) points to its message."""
        match = REF_RE.match(ref) if isinstance(ref, str) else None
        if not match or match.group(1) not in self.registry.configured():
            raise Denied(f"not a reference to a plugin: {ref}", "bad_ref")
        instance, path = match.groups()
        spec = self.registry.manifest(instance).get("item")
        if not isinstance(spec, dict) or not spec.get("read") or not spec.get("param"):
            raise Denied(f"{instance} has no items to look up by reference", "not_supported")
        if spec.get("attachments"):
            path = re.sub(r"#\d+$", "", path)
        return {"instance": instance, "ref": f"{instance}:{path}", "read": f"{instance}.{spec['read']}",
                "params": {spec["param"]: path},
                "attachments": f"{instance}.{spec['attachments']}" if spec.get("attachments") else None,
                # a chat message's read includes the messages before it; this parameter (0) leaves them out
                "context": spec.get("context")}

    def meta(self, session: dict, key: dict, ref: Any) -> dict:
        """GET /v1/meta (`doorman meta <ref>`): what an agent needs to act on one item, without its text
        (structure.py): ids, addresses, attachment parts and types, timestamps. Every role may ask, actor keys
        under the split included: Doorman runs the item's read itself and keeps only fields that pass their
        pattern. Placeholders apply first, so what they hide doesn't come back as a field. It's a read like any
        other (switches, read log) and taints like third-party content: the addresses came from
        outside, and provenance remembers them for the recipient check."""
        params = {"ref": str(ref)[:300]}
        try:
            item = self.item_of(ref)
            instance, plugin, spec = self.registry.find_read(item["read"])
            self._guard(session, instance, write=False)
            self._validate(spec.get("params"), item["params"], "reference")
            data = plugin.run_read(spec["name"], item["params"])
        except Denied as exc:
            self.reads.add(key, session, "meta", params, status="denied", error=exc.reason)
            raise
        except Exception as exc:
            self.reads.add(key, session, "meta", params, status="failed", error=str(exc))
            raise
        if isinstance(data, list):  # a read that answers with a list: the item is the one with this ref
            data = next((d for d in data if isinstance(d, dict) and d.get("ref") == item["ref"]), {})
        shown, hidden = self.pseudonyms.hide(data, self.plugin_type(instance))
        out = self._mark_held(structure.project(shown))
        out.setdefault("ref", item["ref"])
        if self.guard.held_refs([item["ref"]]):
            out["quarantined"] = out["held"] = True  # as in lists: `.held` sorts it out
        self.auth.taint(session["id"], True, False)
        self.provenance.record(session["id"], out, "meta", "third_party")
        self.reads.add(key, session, "meta", params, out, trust="third_party", hidden=hidden)
        return out

    # ------------------------------------------------------------------ records

    def put_record(self, session: dict, key: dict, record: dict) -> int:
        """`doorman record`: reader keys only. Records are the reader's summaries of third-party items, and
        the actor reads them as such, so no other key may write one."""
        self._guard(session, None, write=False)
        if key["role"] != "reader":
            raise Denied("records come from the reader (doorman-reader, with a reader key); other keys read them "
                         "with doorman records", "role")
        self._validate(RECORD_SCHEMA, record, "record")
        return self.db.exec(
            "INSERT INTO records(source, data, session_id, created) VALUES(?,?,?,?)",
            (record["source"], dumps(record), session["id"], clock.iso()),
        )

    def record_sources(self) -> list[str]:
        """The plugins whose records agents get: set up, switched on, and with the read that gates their items'
        text on (the manifest's item read, the same switch that decides how much of their events agents get,
        _event_reach). Switching either off hides the plugin's records at once; removing it hides them too."""
        out = []
        for name in self.registry.configured():
            try:
                if not self.registry.state(name)["enabled"]:
                    continue
            except (Denied, PluginError, KeyError):
                continue
            if self._event_reach(name) == "text":
                out.append(name)
        return out

    def list_records(self, session: dict, key: dict, source: str | None = None,
                     category: str | None = None, limit: int = 50, sender: str | None = None,
                     since: str | None = None, until: str | None = None, text: str | None = None) -> list[dict]:
        """Records the reader filed, newest first. `source`: a plugin (`mail`), an exact ref
        (`mail:<id>`), or a ref's start ending in `*` (`whatsapp:<chat>/*`, every message in a chat).
        `since`/`until` (YYYY-MM-DD) go by the item's date, or when it was filed if it has none. `sender`
        and `text` look for words in the sender and the summary, after placeholders: a word that's hidden
        can't be found. Scanned by the guard like other third-party text
        (except for reader keys, which wrote them). Only records of plugins that are set up and switched on
        and whose item read is on (record_sources): a summary is as much the plugin's content as the item."""
        self._guard(session, None, write=False)
        if not isinstance(limit, int) or not 1 <= limit <= 500:
            raise Denied("limit is 1 to 500", "invalid")
        for value in (since, until):
            if value and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                raise Denied("since and until are dates, YYYY-MM-DD", "invalid")
        sources = self.record_sources()
        sql = (f"SELECT id, data, created FROM records WHERE substr(source, 1, instr(source, ':') - 1) "
               f"IN ({','.join('?' * len(sources))})")
        params: list = list(sources)
        if source:
            like = lambda s: s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")  # noqa: E731
            if ":" not in source:  # a plugin: every record from it
                sql += " AND source LIKE ? ESCAPE '\\'"
                params.append(like(source) + ":%")
            elif source.endswith("*"):
                sql += " AND source LIKE ? ESCAPE '\\'"
                params.append(like(source[:-1]) + "%")
            else:
                sql += " AND source=?"
                params.append(source)
        if category:
            sql += " AND json_extract(data, '$.category')=?"
            params.append(category)
        when = "substr(COALESCE(json_extract(data, '$.date'), created), 1, 10)"
        if since:
            sql += f" AND {when} >= ?"
            params.append(since)
        if until:
            sql += f" AND {when} <= ?"
            params.append(until)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(2000 if sender or text else limit)
        records = [{"id": r["id"], "created": r["created"], "ref": loads(r["data"])["source"], **loads(r["data"])}
                   for r in self.db.all(sql, tuple(params))]
        if sender or text:  # on what the agent would see, so a hidden word finds nothing
            fold = lambda value: " ".join(str(value or "").split()).casefold()  # noqa: E731
            records = [r for r, seen in zip(records, self.pseudonyms.hide(records)[0])
                       if (not sender or fold(sender) in fold(seen.get("from")))
                       and (not text or fold(text) in fold(seen.get("summary")))][:limit]
        asked = {k: v for k, v in (("source", source), ("category", category), ("from", sender), ("since", since),
                                   ("until", until), ("text", text)) if v}
        unscanned = None
        if key["role"] != "reader":
            records = self.redactor.value(sanitize.clean_value(records)[0])
            records, unscanned = self._scan("records", {}, asked, records)
        shown, hidden = self.pseudonyms.hide(records)
        self.auth.taint(session["id"], True, False)
        self.provenance.record(session["id"], records, "records", "third_party")
        self.reads.add(key, session, "records", asked, records, trust="third_party", hidden=hidden,
                       status="unscanned" if unscanned else "ok", error=unscanned)
        return shown

    # ------------------------------------------------------------------ write tools

    def _log_denied(self, session: dict, task_id: int | None, name: str, args: dict, denied: Denied) -> None:
        instance = name.split(".", 1)[0] if "." in name else None
        if denied.code == "rejected":  # a honeytoken or decoy key: the journal never keeps the value itself
            args = _mask_tokens(args, self.egress.honeytokens())
        self.journal.create(kind="action", session_id=session["id"], task_id=task_id, plugin=instance, tool=name,
                            args=args, decision="deny", status="denied", error=denied.reason,
                            summary=f"Denied {name}: {denied.reason}")

    def _check_honeytokens(self, session: dict, name: str, args: dict, refs: list[dict]) -> None:
        """The config's honeytokens and every decoy key (egress.honeytokens()) in a call's arguments or the
        files it hands on: the key is paused (a decoy key also cuts its addresses off, egress.decoy_used) and
        the call fails without saying why."""
        tokens = self.egress.honeytokens()
        if not tokens:
            return
        haystack = [canonical(args).lower()]
        for ref in refs:
            haystack.append(ref["name"].lower())
            haystack.append(ref["_content"][:2_000_000].decode("utf-8", "ignore").lower())
        for value in _strings(args):
            match = REF_RE.match(value)
            if match and match.group(1) in self.registry.configured():
                try:
                    filename, content = self.resolve_ref(value)
                    haystack.append(filename.lower())
                    haystack.append(content[:2_000_000].decode("utf-8", "ignore").lower())
                except (Denied, PluginError, OSError):
                    pass
        hits = {token for token in tokens if any(token in text for text in haystack)}
        if hits:
            self.auth.kill_session(session["id"])
            # the whole key: a new session is one missing header away, and the agent is likely compromised
            key = self.db.one("SELECT id, name FROM agent_keys WHERE id=?", (session["key_id"],))
            if hits & self.egress.decoy_values():
                self.egress.decoy_used([key["id"]], None, f"a {name} call")
                raise Denied(CALL_REJECTED, "rejected")
            self.auth.pause_key(key["id"], f"honeytoken in a {name} call")
            self.journal.create(kind="config", tool="key.pause", tier="irreversible", decision="run", status="done",
                                summary=f"Paused agent key “{key['name']}”: a {name} call carried a honeytoken")
            self.attention("key_paused", key["id"], f"Agent key “{key['name']}” paused: honeytoken",
                           f"A {name} call contained a honeytoken, so the agent may be following someone else's "
                           "instructions. Nothing was sent, and the key can't do anything until you resume it "
                           "(More → Agents). Check its pending approvals first.",
                           url=f"{self.public_url}/app/#/more", priority=5)
            raise Denied(CALL_REJECTED, "rejected")

    def call_tool(self, session: dict, key: dict, name: str, args: dict, task_id: int | None = None,
                  changeset_id: int | None = None, defer_approval: bool = False) -> dict:
        out = self._call_tool(session, key, name, args, task_id, changeset_id, defer_approval)
        try:  # what the call gave back (an MCP tool's page, a file): fingerprinted like a read
            self.egress.note_result(key, session, name, args, out)
        except Exception:  # noqa: BLE001 - the call worked; the agent gets its result either way
            log.exception("fingerprints of %s's result", name)
        return out

    def _call_tool(self, session: dict, key: dict, name: str, args: dict, task_id: int | None,
                   changeset_id: int | None, defer_approval: bool) -> dict:
        task_id = task_id or session["task_id"]
        try:
            if self.config["reader_actor_split"] and key["role"] == "reader":
                raise Denied(READER_WRITE, "role")
            instance, plugin, tool = self.registry.find_tool(name)
            self._guard(session, instance, write=True)
            self._validate(tool.spec.get("params"), args, "arguments")
            args = tool.prepare(args)  # a reply's recipients and subject: what the owner approves
            if tool.spec.get("caller_arg"):  # who made it (files.keep's made_by): the key's name, never the agent's say
                args = {**args, tool.spec["caller_arg"]: key["name"]}
            self._check_based_on(session, key, tool, args)
            refs = self._check_refs(session, tool, args)
            self._check_honeytokens(session, name, args, refs)
            fingerprints = [{k: v for k, v in r.items() if k != "_content"} for r in refs]
            task = self.tasks.get(task_id)
            tier = tool.tier(args)
            if tier not in TIERS:
                raise PluginError(f"{name} returned unknown tier {tier}")
            args = self._unhide_args(name, tier, args)
            # an undoable write runs right away, unless the owner set its tool to "Ask me"
            if tier == "reversible" and not self.registry.asks_first(instance, name):
                before = tool.snapshot(args)
                entry_id = self.journal.create(
                    kind="action", session_id=session["id"], task_id=task_id, changeset_id=changeset_id,
                    plugin=instance, tool=name, args=args, tier=tier, decision="run", status="running",
                    before=before, checks={"refs": fingerprints} if fingerprints else None,
                    summary=tool.describe(args))
                return self._execute(entry_id, tool, args, before, fingerprints)
            if tier == "irreversible" and self.registry.no_approval(instance, name):
                # without asking only while every check passes and under the daily cap; else a normal approval
                out = self._run_direct(session, task, task_id, changeset_id, instance, name, tool, args, tier,
                                       fingerprints)
                if out is not None:
                    return out
            with self.lock:
                session = self.auth.get_session(session["id"])
                checks = self.policy.evaluate(session, task, name, tool, args, tier)
                if tier == "irreversible" and self.registry.no_approval(instance, name) and self.direct_cap_reached():
                    checks["checks"].append(self._cap_check())
                checks["refs"] = fingerprints
                # what it points at as it is now: checked again right before it runs (execute_entry)
                checks["outgoing"] = self.approvals.outgoing_digest(tool, args)
                entry_id = self.journal.create(
                    kind="action", session_id=session["id"], task_id=task_id, changeset_id=changeset_id,
                    plugin=instance, tool=name, args=args, tier=tier, decision="approval", checks=checks,
                    status="waiting_approval", summary=tool.describe(args))
        except Denied as denied:
            self._log_denied(session, task_id, name, args, denied)
            raise
        # every send waits for the owner; failed checks become warnings on the approval
        warnings = [c["detail"] for c in checks["checks"] if not c["ok"]]
        if defer_approval:
            return {"entry_id": entry_id, "status": "waiting_approval", "warnings": warnings}
        approval_id = self.approvals.create([entry_id], changeset_id=changeset_id)
        return {"entry_id": entry_id, "status": "waiting_approval", "approval_id": approval_id, "warnings": warnings}

    def direct_cap(self) -> int:
        limits = self.config.get("limits") or {}
        return int(limits.get("direct_per_day", limits.get("sends_per_day", 30)))

    def direct_cap_reached(self) -> bool:
        """no_approval plugins run without asking up to direct_per_day times in 24 h, then ask again: a brake
        on an agent that books and cancels in a loop. Sends that wait for approval don't count."""
        since = clock.iso(clock.now() - timedelta(hours=24))
        row = self.db.one("SELECT COUNT(*) AS n FROM journal WHERE kind='action' AND decision='direct' AND ts>=? "
                          "AND status NOT IN ('failed','denied')", (since,))
        return row["n"] >= self.direct_cap()

    def _cap_check(self) -> dict:
        return {"name": "direct_limit", "ok": False, "data": {},
                "detail": f"{self.direct_cap()} actions ran without asking in 24 h, so this one asks you"}

    def _run_direct(self, session, task, task_id, changeset_id, instance, name, tool, args, tier, fingerprints):
        """An irreversible action of a plugin the owner set to no_approval: it runs now, at most once, and is
        journaled. It can't be reverted. Returns None (ask the owner instead) when a check fails or the
        daily cap is reached; both are decided under the lock, so parallel calls can't overshoot the cap."""
        with self.lock:
            session = self.auth.get_session(session["id"])
            checks = self.policy.evaluate(session, task, name, tool, args, tier)
            if not all(c["ok"] for c in checks["checks"]) or self.direct_cap_reached():
                return None
            checks["refs"] = fingerprints
            before = tool.snapshot(args)
            entry_id = self.journal.create(
                kind="action", session_id=session["id"], task_id=task_id, changeset_id=changeset_id,
                plugin=instance, tool=name, args=args, tier=tier, decision="direct", checks=checks,
                status="sending", before=before, summary=tool.describe(args))
        out = self._execute(entry_id, tool, args, before, fingerprints, send=True)
        out["warnings"] = [c["detail"] for c in checks["checks"] if not c["ok"]]
        return out

    def _execute(self, entry_id: int, tool, args: dict, before: dict | None, refs: list[dict] | None = None,
                 send: bool = False, approval_id: int | None = None) -> dict:
        self._local.expected_refs = {r["ref"]: r["sha256"] for r in refs or []}
        # a failure's push replaces the approval's own (or the "Sending" line Accept left) on the phone
        tag = f"approval-{approval_id}" if approval_id else None
        try:
            outcome = tool.execute(args, before)
        except Exception as exc:  # noqa: BLE001 - any plugin failure ends up in the journal
            log.exception("entry %s failed", entry_id)
            error = f"{type(exc).__name__}: {exc}"
            if send and not isinstance(exc, NotSent):
                # it may have gone out: never retried, and the owner is asked to check (and Doorman checks
                # itself when the tool can: sends.py)
                return self._mark_unknown(entry_id, error, tool, tag)
            self._fail(entry_id, tool, args, before, error)
            if send:
                self.attention("send_failed", entry_id, "A send failed; nothing went out",
                               f"{tool.describe(args)}\n{exc}", url=f"{self.public_url}/app/#/journal", tag=tag)
            return {"entry_id": entry_id, "status": "failed", "error": str(exc)}
        finally:
            self._local.expected_refs = None
        archived = self.copy_to_archive(tool.plugin.ctx.instance, tool.spec["name"])
        if archived and archived["copied"] and isinstance(outcome.result, dict):
            outcome.result = {**outcome.result, "archived": archived}
        self.journal.update(entry_id, status="done", after=outcome.after, object_ref=outcome.object_ref,
                            result=outcome.result, summary=outcome.summary or tool.describe(args))
        self.search.poke(tool.plugin.ctx.instance)
        return {"entry_id": entry_id, "status": "done", "result": outcome.result, "summary": tool.describe(args)}

    def _fail(self, entry_id: int, tool, args: dict, before: dict | None, error: str) -> None:
        """A failed write may have changed part of its object. If it did, keep the diff and the Revert
        button: `after` holds what the object looks like now."""
        fields: dict[str, Any] = {"status": "failed", "error": error}
        try:
            ref = tool.ref_for(args) if before is not None and tool.can_check_drift() else None
            if ref:
                now = tool.current(ref)
                if canonical(self._comparable(tool, now)) != canonical(self._comparable(tool, before)):
                    fields.update(after=now, object_ref=ref, result={"partial": True},
                                  error=f"{error} (it changed part of the object; Revert puts it back)")
        except Exception:  # noqa: BLE001 - the check is a courtesy; the failure is already recorded
            log.exception("checking failed entry %s", entry_id)
        self.journal.update(entry_id, **fields)

    def _mark_unknown(self, entry_id: int, error: str, tool=None, tag: str | None = None) -> dict:
        """A send that broke off: it may have gone out, so it's never retried. When its tool can check
        (verify_sent), the worker asks it over the next half hour (sends.py); the owner is asked meanwhile."""
        entry = self.journal.get(entry_id)
        try:
            tool = tool or self._tool_object(entry)
            verifiable = tool is not None and tool.can_verify()
        except Exception:  # noqa: BLE001 - a plugin that doesn't load can't check
            verifiable = False
        fields: dict[str, Any] = {"status": "unknown",
                                  "error": f"{error}. It may have gone out: check Sent before doing it again."}
        if verifiable:
            fields["result"] = {"verify": {"since": clock.iso(), "tries": 0, "error": error}}
        self.journal.update(entry_id, **fields)
        detail = entry["summary"] + ("\nDoorman checks over the next half hour and tells you." if verifiable else "")
        self.attention("send_unknown", entry_id, "Check whether this went out", detail,
                       url=f"{self.public_url}/app/#/journal", priority=4, tag=tag)
        return {"entry_id": entry_id, "status": "unknown", "error": error, "checking": verifiable}

    # ------------------------------------------------------------------ needs attention

    def push_ask(self, kind: str, ref: int, clean: bool = True) -> dict:
        """The buttons on a push that asks for a yes or no and isn't a send's approval (those: approvals._push):
        a network request, a changeset, an item held back. The service worker (sw.js ASKS) knows each kind's
        two buttons and calls. The no acts in place; the yes only with `accept` "tap", otherwise it opens the
        app at the push's page: `clean` False (a warning to read first), or approval_passkey on."""
        return {"kind": kind, "id": ref, "accept": "tap" if self.push_accepts(clean) else "app"}

    def push_accepts(self, clean: bool = True) -> bool:
        """Checked again when such a yes arrives (via=notification): the push's word isn't enough."""
        return clean and not self.config.get("approval_passkey")

    def attention(self, kind: str, ref: Any, title: str, detail: str = "", url: str | None = None,
                  priority: int = 3, tag: str | None = None, exclude: int | None = None,
                  ask: dict | None = None) -> bool:
        """Something the owner should look at. Each (kind, ref) is listed and pushed once; True if new.
        `tag`: the push replaces the phone's notification with that tag (a send's failure: its approval's).
        `exclude`: a push subscription left out (a new device isn't told about itself).
        `ask`: the push's two buttons (push_ask)."""
        with self.db.tx() as conn:
            existing = conn.execute("SELECT id, resolved FROM attention WHERE kind=? AND ref=?",
                                    (kind, str(ref))).fetchone()
            if existing and existing["resolved"] is None:
                return False
            if existing:  # it came back after being resolved: list it again
                conn.execute("UPDATE attention SET title=?, detail=?, url=?, created=?, resolved=NULL WHERE id=?",
                             (title, detail[:1000], url, clock.iso(), existing["id"]))
            else:
                conn.execute("INSERT INTO attention(kind, ref, title, detail, url, created) VALUES(?,?,?,?,?,?)",
                             (kind, str(ref), title, detail[:1000], url, clock.iso()))
        self.notifier.push(title, detail[:500], url=url or f"{self.public_url}/app/#/inbox", priority=priority,
                           extra={k: v for k, v in (("tag", tag), ("ask", ask)) if v} or None, exclude=exclude)
        return True

    def _mcp_tools_changed(self, instance: str, title: str) -> None:
        """An MCP server lists tools it didn't before, or describes one differently: the owner is told once
        per server until they have looked (Plugins, "Got it"). Nothing is switched off: a new tool asks
        first anyway, and a tool set to run without asking keeps doing so, which the notice says."""
        store = self.registry.mcp.store
        news = store.news(instance)
        new, changed, gone = news.get("new") or [], sorted(news.get("changed") or {}), news.get("removed") or []

        def named(names: list[str]) -> str:  # as the card names them: by title, where the server gives one
            return ", ".join(((store.row(instance, n) or {}).get("spec") or {}).get("title") or n for n in names)

        parts = [f"{label}: {named(names)}." for label, names in (("New", new), ("Changed", changed), ("Gone", gone))
                 if names]
        if new:
            parts.append("New tools ask you first.")
        auto = [name for name in changed if store.allowed(instance, name)]
        if auto:
            parts.append(f"{named(auto)} {'runs' if len(auto) == 1 else 'run'} without asking you, as you set "
                         "it: look at what changed.")
        if new and not changed:
            head = f"{title} has a new tool" if len(new) == 1 else f"{title} has {len(new)} new tools"
        else:
            head = f"{title}'s tools changed"
        self.attention("mcp_tools", instance, head, " ".join(parts), url=f"{self.public_url}/app/#/plugins")

    def resolve_attention(self, kind: str | None = None, ref: Any = None, item_id: int | None = None) -> bool:
        if item_id is not None:
            sql, params = "UPDATE attention SET resolved=? WHERE id=? AND resolved IS NULL", (clock.iso(), item_id)
        else:
            sql, params = ("UPDATE attention SET resolved=? WHERE kind=? AND ref=? AND resolved IS NULL",
                           (clock.iso(), kind, str(ref)))
        with self.db.tx() as conn:
            if item_id is not None:  # dismissed in the inbox: a failing job stays quiet until it works again
                row = conn.execute("SELECT kind, ref FROM attention WHERE id=? AND resolved IS NULL", (item_id,)).fetchone()
                if row and row["kind"] == "job":
                    conn.execute("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                                 (f"job_dismissed:{row['ref']}", clock.iso()))
            return conn.execute(sql, params).rowcount == 1

    def attention_list(self) -> list[dict]:
        return self.db.all("SELECT * FROM attention WHERE resolved IS NULL ORDER BY id DESC")

    def attention_stacked(self) -> list[dict]:
        """Needs attention as the inbox lists it: open entries that say the same thing are one, the newest with
        `count`, `first` (when the oldest came) and `ids`. A backup that failed six nights running is one entry
        per night (its ref is the date): six cards, one message. The same thing: kind, title, link and the
        detail with its numbers left out, so dates and sizes in an error don't split a stack, while two failed
        sends (each detail names its own) or two held-back items (each its own link) stay apart."""
        stacks: dict[tuple, dict] = {}
        for row in self.attention_list():  # newest first: the stack shows its newest
            key = (row["kind"], row["title"], row["url"], re.sub(r"\d+", "#", row["detail"] or ""))
            stack = stacks.get(key)
            if stack is None:
                stacks[key] = {**row, "count": 1, "ids": [row["id"]], "first": row["created"]}
            else:
                stack["count"] += 1
                stack["ids"].append(row["id"])
                stack["first"] = row["created"]
        return list(stacks.values())

    def dismiss_attention(self, item_id: int) -> bool:
        """Done in the inbox: the entry and everything stacked with it (attention_stacked)."""
        ids = next((s["ids"] for s in self.attention_stacked() if item_id in s["ids"]), [item_id])
        return sum(self.resolve_attention(item_id=i) for i in ids) > 0

    def _list_broken_plugins(self) -> None:
        """Plugin folders whose manifest can't work were left out when Doorman started (registry.discover):
        each under Needs attention, gone again once a restart loads it."""
        for path, problem in self.registry.broken.items():
            self.attention("plugin_broken", path, f"The plugin in {Path(path).name} isn't loaded",
                           f"{path}/manifest.yaml: {problem}. Fix it and restart Doorman; "
                           f"doorman-admin plugin check {path} lists every problem.",
                           url=f"{self.public_url}/app/#/plugins")
        for item in self.attention_list():
            if item["kind"] == "plugin_broken" and item["ref"] not in self.registry.broken:
                self.resolve_attention("plugin_broken", item["ref"])

    def check_plugins(self, force: bool = False) -> dict[str, str | None]:
        """Every plugin_check_minutes: switched-on plugins whose credentials are missing or don't work
        get listed (and pushed once); they clear by themselves once the check passes."""
        every = 60 * float(self.config.get("plugin_check_minutes", 60))
        results: dict[str, str | None] = {}
        if not force and clock.now().timestamp() - self._last_sweep < 60:
            return results  # the worker ticks every few seconds; listing plugins reads the vault
        self._last_sweep = clock.now().timestamp()
        self._list_broken_plugins()
        for plugin in self.registry.list():
            name = plugin["name"]
            if not plugin["enabled"]:
                self.resolve_attention("plugin", name)
                continue
            if not force and clock.now().timestamp() - self._checked.get(name, 0) < every:
                continue
            self._checked[name] = clock.now().timestamp()
            missing = [c for c in plugin["missing_credentials"]
                       if not (plugin.get("login") == "oauth" and c == "refresh_token")]
            problem = f"missing credentials: {', '.join(missing)}" if missing else None
            if problem is None:
                try:
                    instance = self.registry.instance(name)
                    if plugin.get("login") == "oauth" and not instance.login_status().get("connected"):
                        problem = "not connected: connect it under Plugins"
                    else:
                        problem = instance.check()
                except Exception as exc:  # noqa: BLE001 - any failure is the problem to report
                    problem = f"{type(exc).__name__}: {exc}"
            results[name] = problem
            if problem:
                self.attention("plugin", name, f"{name} isn't working", problem,
                               url=f"{self.public_url}/app/#/plugins")
            else:
                self.resolve_attention("plugin", name)
        return results

    def recover_interrupted(self) -> dict:
        """At server start: entries a crash cut off. Sends become 'unknown' (never retried); other writes
        become failed, with a Revert button when they changed part of their object. Approved entries that
        were never claimed stay approved: nothing of them went out, and the worker runs them
        (sends.resume)."""
        sends = self.db.all("SELECT id FROM journal WHERE status='sending'")
        for row in sends:
            self.feed.send_result(row["id"], self._mark_unknown(row["id"], "Doorman stopped while sending"))
        writes = self.db.all("SELECT id FROM journal WHERE status='running' AND kind='action'")
        for row in writes:
            entry = self.journal.get(row["id"])
            tool = self._tool_object(entry)
            if tool is None:
                self.journal.update(row["id"], status="failed", error="Doorman stopped during this action")
            else:
                self._fail(row["id"], tool, entry["args"], entry["before"], "Doorman stopped during this action")
        approved = self.db.all("SELECT id FROM journal WHERE status='approved' AND kind='action'")
        return {"sends": [r["id"] for r in sends], "writes": [r["id"] for r in writes],
                "approved": [r["id"] for r in approved]}

    def execute_entry(self, entry_id: int, approval_id: int | None = None) -> dict:
        """Run an entry the owner approved (status 'approved'; sends.py calls this from its thread). At most
        once: the entry is claimed first ('approved' -> 'sending'), and a crash during the send leaves it
        'sending', which the next start turns into 'unknown', never into a retry. An undoable write the owner
        asked to see first (its tool set to "Ask me") runs as any undoable write: 'running', and revertable
        afterwards. `again` in the answer: someone else claimed it first, and it wasn't run here."""
        current = self.journal.get(entry_id)
        send = not (current and current["tier"] == "reversible")
        if not self.journal.transition(entry_id, ("approved",), "sending" if send else "running"):
            entry = self.journal.get(entry_id)
            return {"entry_id": entry_id, "status": entry["status"] if entry else "missing",
                    "error": "already handled; not run again", "again": True}
        entry = self.journal.get(entry_id)
        session = self.auth.get_session(entry["session_id"]) if entry["session_id"] else None
        key = self.db.one("SELECT revoked FROM agent_keys WHERE id=?", (session["key_id"],)) if session else None
        if session is None or session["killed"] or key is None or key["revoked"]:
            self.journal.update(entry_id, status="cancelled", error="not run: the agent's session was ended")
            return {"entry_id": entry_id, "status": "cancelled", "error": "session ended"}
        try:
            _, _, tool = self.registry.find_tool(entry["tool"])
        except Denied as denied:
            self.journal.update(entry_id, status="failed", error=f"not run: {denied.reason}")
            return {"entry_id": entry_id, "status": "failed", "error": denied.reason}
        checks = entry["checks"] or {}
        outgoing = self.approvals.outgoing_digest(tool, entry["args"]) if "outgoing" in checks else None
        if "outgoing" in checks and outgoing != checks["outgoing"]:
            # the note (or whatever the send points at) changed after the owner approved what was shown
            error = ("couldn't read what it would send, to check it against what you approved"
                     if outgoing == self.approvals.UNREADABLE else
                     "what it would send changed after it was asked for, so it isn't what you approved")
            self.journal.update(entry_id, status="failed", error=f"not run: {error}. Nothing went out")
            return {"entry_id": entry_id, "status": "failed", "error": error}
        try:
            before = tool.snapshot(entry["args"])
        except Exception as exc:  # noqa: BLE001 - nothing was sent yet
            self.journal.update(entry_id, status="failed", error=f"not run: {type(exc).__name__}: {exc}")
            return {"entry_id": entry_id, "status": "failed", "error": str(exc)}
        self.journal.update(entry_id, before=before)  # before the send: a send keeps its Message-ID here
        return self._execute(entry_id, tool, entry["args"], before, (entry["checks"] or {}).get("refs"), send=send,
                             approval_id=approval_id)

    # ------------------------------------------------------------------ journal views and reverts

    def _tool_object(self, entry: dict):
        if not entry.get("plugin") or not entry.get("tool") or "." not in entry["tool"]:
            return None
        try:
            _, tool = self.registry.tool_for_revert(entry["plugin"], entry["tool"].split(".", 1)[1])
            return tool
        except (Denied, PluginError, KeyError):
            return None

    def entry_view(self, entry: dict | None) -> dict | None:
        if entry is None:
            return None
        view = dict(entry)
        tool = self._tool_object(entry) if entry["kind"] in ("action", "revert") else None
        if entry["kind"] == "revert":
            original = self.journal.get(entry["reverts"])
            tool = self._tool_object(original) if original else None
        try:
            view["diff"] = (tool.render_diff(entry["before"], entry["after"], entry["args"] or {}) if tool
                            else generic_diff(entry["before"], entry["after"]))
        except Exception:  # noqa: BLE001 - a broken renderer must not hide the entry
            view["diff"] = generic_diff(entry["before"], entry["after"])
        view["revertable"] = self._revertable(entry, tool)[0]
        if entry["kind"] == "action" and entry["tier"] in ("irreversible", "payment") and entry["status"] == "done":
            view["follow_up"] = (tool.follow_up(entry["args"], entry["result"]) if tool else None) or \
                "This already left the system and can't be undone."
        untrusted, known = [], []
        for check in (entry.get("checks") or {}).get("checks", []):
            untrusted.extend(check.get("data", {}).get("untrusted", []))
            known.extend(check.get("data", {}).get("known", []))
        view["untrusted_destinations"] = [self._with_source(d) for d in untrusted]
        # why the other recipients count as the owner's: "in your contacts (Anna)", "trust list (work)"
        view["known_destinations"] = known
        view["editable"] = self.approvals.editable(entry) if entry["status"] == "waiting_approval" else []
        if entry["kind"] == "action" and entry["status"] in ("waiting_approval", "expired"):
            try:
                view["outgoing"] = tool.outgoing(entry["args"] or {}) if tool else None
            except Exception:  # noqa: BLE001 - a broken plugin must not hide the approval
                view["outgoing"] = None
            # asked for before a honeytoken paused its key: the agent may be following someone else
            session = self.auth.get_session(entry["session_id"]) if entry.get("session_id") else None
            view["key_paused"] = self.auth.paused(session["key_id"]) if session else None
            task = self.tasks.get(entry["task_id"]) if entry.get("task_id") else None
            view["task_text"] = task["text"] if task else None
            # who wrote it: the owner (a task or a routine) or not (a trigger's mail, an agent's reminder)
            view["task_origin"] = task["origin"] if task else None
            view["task_trusted"] = task["trusted"] if task else None
        view["edited_from"] = (entry.get("checks") or {}).get("edited_from")
        view["checking"] = checking(entry)  # an unknown send Doorman still checks itself (sends.py)
        if entry["kind"] == "action" and self.registry.is_mcp(entry.get("plugin")) and "." in (entry.get("tool") or ""):
            short = entry["tool"].split(".", 1)[1]
            try:
                block = self.registry.configured()[entry["plugin"]]
                row = self.registry.mcp.store.row(entry["plugin"], short)
                view["mcp"] = {"server": self.registry.mcp.title(entry["plugin"], block), "tool": short,
                               "title": ((row or {}).get("spec") or {}).get("title") or short,
                               "allowed": bool(row and row["allowed"]),
                               "can_allow": bool(row and not row["removed"] and not self.registry.mcp.store.is_read(row))}
            except (KeyError, Denied, PluginError):
                pass
        return view

    def _with_source(self, destination: dict) -> dict:
        """Name the item an address first came from (a mail's subject and sender, from the read log)
        instead of only its reference, which for mail is a long Message-ID."""
        seen = destination.get("first_seen") or {}
        origin = seen.get("origin") or ""
        if ":" not in origin:
            return destination
        out = {**destination, "first_seen": {**seen, "plugin": origin.split(":", 1)[0]}}
        for row in self.db.all("SELECT labels FROM reads WHERE labels LIKE ? ORDER BY id DESC LIMIT 5",
                               (f"%{origin}%",)):
            item = next((i for i in loads(row["labels"], []) if i.get("ref") == origin), None)
            if item:
                out["first_seen"].update({k: item[k] for k in ("label", "from", "when") if item.get(k)})
                break
        return out

    def _revertable(self, entry: dict, tool) -> tuple[bool, str]:
        partial = entry["status"] == "failed" and (entry.get("result") or {}).get("partial")
        if entry["status"] != "done" and not partial:
            return False, f"status is {entry['status']}"
        if entry["kind"] == "config":
            return entry["tool"] in ("plugin.state", "plugin.add", "plugin.config", "mcp.tool"), "config"
        if entry["kind"] not in ("action", "revert"):
            return False, "not an action"
        if entry["kind"] == "action" and entry["tier"] != "reversible":
            return False, "already left the system"
        if entry["kind"] == "revert":
            target = self.journal.get(entry["reverts"])
            if target is None or target["kind"] == "revert":
                return False, "revert the original action instead"
        if tool is None or not tool.can_undo():
            return False, "this tool can't undo"
        return True, ""

    def revert_entry(self, entry_id: int, force: bool = False, session_id: str | None = None) -> dict:
        """Undo one journal entry (and the later changes to the same object first). `session_id`: an agent
        undoing its own change (agent_undo); the revert is journaled under its session, and it gets no
        entry_reverted event for what it did itself."""
        entry = self.journal.get(entry_id)
        if entry is None:
            raise Denied("no such journal entry", "not_found")
        if entry["kind"] == "config":
            return self.plugin_setup.revert_config(entry, force)
        original = self.journal.get(entry["reverts"]) if entry["kind"] == "revert" else entry
        tool = self._tool_object(original)
        ok, why = self._revertable(entry, tool)
        if not ok:
            return {"reverted": [], "skipped": [{"entry_id": entry_id, "reason": why}], "conflicts": [], "failed": []}
        result = {"reverted": [], "skipped": [], "conflicts": [], "failed": []}
        for dependent in self.journal.dependents(entry):
            sub = self.revert_entry(dependent["id"], force=force, session_id=session_id)
            for key in result:
                result[key].extend(sub[key])
            if sub["conflicts"] or sub["skipped"] or sub["failed"]:
                result["skipped"].append({"entry_id": entry_id, "reason": f"depends on entry {dependent['id']}"})
                return result
        partial = None  # field -> value before, when only this action's fields are put back
        if tool.can_check_drift() and entry["object_ref"]:
            now = tool.current(entry["object_ref"])
            seen = lambda state: self._comparable(tool, state)  # noqa: E731
            if canonical(seen(now)) != canonical(seen(entry["after"])) and not force:
                before, after, current = seen(entry["before"]), seen(entry["after"]), seen(now)
                if before is None or after is None or current is None:
                    clash = ["the whole object"]  # created, deleted, or gone since
                else:
                    clash = [f for f in changed_fields(before, after)
                             if canonical(current.get(f)) != canonical(after.get(f))]
                if not clash and tool.can_undo_fields():
                    partial = {f: before.get(f) for f in changed_fields(before, after)}
                else:
                    reason = ("changed again since" if clash else
                              "other fields changed since, and this tool can only put back the whole object")
                    result["conflicts"].append({"entry_id": entry_id, "before": entry["before"],
                                                "after": entry["after"], "now": now, "fields": clash,
                                                "reason": reason})
                    return result
            if partial is not None:
                new_ref = (tool.undo_fields(entry["object_ref"], partial, now)
                           if type(tool).undo_fields is not Tool.undo_fields
                           else tool.undo(entry["object_ref"], entry["before"], entry["after"]))
            else:
                new_ref = tool.undo(entry["object_ref"], entry["before"], entry["after"])
        else:
            new_ref = tool.undo(entry["object_ref"], entry["before"], entry["after"])
        problem = self._check_undo(tool, new_ref or entry["object_ref"], entry)
        self.search.poke(entry["plugin"])
        revert_id = self.journal.create(
            kind="revert", reverts=entry_id, plugin=entry["plugin"], tool=entry["tool"], session_id=session_id,
            args={"entry": entry_id, **({"fields": sorted(partial)} if partial else {})}, tier="reversible",
            decision="run", status="failed" if problem else "done", error=problem,
            object_ref=new_ref or entry["object_ref"], before=entry["after"], after=entry["before"],
            task_id=entry["task_id"],
            summary=f"Reverted{' ' + ', '.join(sorted(partial)) + ' of' if partial else ''}: {entry['summary']}")
        if problem:
            result["failed"].append({"entry_id": entry_id, "revert_id": revert_id, "reason": problem})
            return result
        self.journal.update(entry_id, status="reverted", reverted_by=revert_id)
        if entry["kind"] == "action" and session_id is None:
            self.feed.entry_reverted(entry, revert_id)
        if entry["kind"] == "revert":
            # undoing a revert re-applies the original action: it counts as applied again
            self.journal.update(entry["reverts"], status="done", reverted_by=None)
        result["reverted"].append(entry_id)
        return result

    def agent_undo(self, session: dict, key: dict, entry_id: int | None = None, task_id: int | None = None) -> dict:
        """`doorman undo`: an agent reverts reversible changes its own key made, with the owner's revert
        (revert_entry), so the revert is a journaled change of its own that can be undone in turn. What the
        owner or another key did, what the owner approved, setup changes and sends stay the owner's.
        `task_id`: every change of this key filed under that task, newest first. A conflict (the item changed
        since) is reported, never forced."""
        self._guard(session, None, write=True)
        mine = {r["id"] for r in self.db.all("SELECT id FROM sessions WHERE key_id=?", (key["id"],))}
        if task_id is not None:
            # actions only, like the owner's Revert this task: undoing a revert would redo what it undid
            ids = [e["id"] for e in self.journal.list(task_id=task_id, kinds=("action",), status=("done",),
                                                      limit=10_000)
                   if e["session_id"] in mine and e["tier"] == "reversible" and e["decision"] != "approval"]
            if not ids:
                raise Denied(f"nothing of yours in task {task_id} can be undone: doorman journal --task {task_id} "
                             "shows what's there", "not_found")
        else:
            ids = [entry_id]
        out: dict = {"reverted": [], "problems": []}
        for one in ids:
            if task_id is not None and self.journal.get(one)["status"] != "done":
                continue  # undone already, as a later change to the same object
            try:
                result = self._agent_undo_one(session, mine, one)
            except Denied as exc:
                if task_id is None:
                    raise
                out["problems"].append({"entry_id": one, "reason": exc.reason})
                continue
            out["reverted"] += [{"entry_id": i, "revert_id": self.journal.get(i)["reverted_by"],
                                 "undone": self.undone_text(self.journal.get(i))} for i in result["reverted"]]
            for kind in ("skipped", "conflicts", "failed"):
                for item in result[kind]:
                    reason = item.get("reason") or "changed since"
                    if item.get("fields"):
                        reason += ": " + ", ".join(item["fields"])
                    out["problems"].append({"entry_id": item["entry_id"], "reason": reason})
        out["status"] = ("done" if out["reverted"] and not out["problems"] else
                         "partly" if out["reverted"] else "not_undone")
        if out["problems"]:
            out["next"] = "tell the owner which entries are left; they can revert them in Doorman (Journal)"
        return out

    def _agent_undo_one(self, session: dict, mine: set, entry_id: int) -> dict:
        entry = self.journal.get(entry_id)
        if entry is None:
            raise Denied(f"no journal entry {entry_id}", "not_found")
        self._agent_may_undo(entry, mine)
        # revert_entry undoes later changes to the same object first: each must be one the agent could undo
        # by itself (its own key's, not approved by the owner, its tool still on and not set to Ask me), else
        # nothing is undone and the owner decides
        later, seen = list(self.journal.dependents(entry)), set()
        while later:
            dependent = later.pop()
            if dependent["id"] in seen:
                continue
            seen.add(dependent["id"])
            try:
                self._agent_may_undo(dependent, mine)
            except Denied as exc:
                raise Denied(f"undoing entry {entry_id} would also undo entry {dependent['id']}, a later change to "
                             f"the same item, which you may not undo ({exc.reason}). Nothing was undone",
                             "owner_only") from None
            later += self.journal.dependents(dependent)
        return self.revert_entry(entry_id, session_id=session["id"])

    def _agent_may_undo(self, entry: dict, mine: set) -> None:
        """Raises Denied unless an agent whose key made the sessions `mine` may undo this entry itself."""
        entry_id = entry["id"]
        owner = "the owner can revert it in Doorman (Journal → Undo)"
        if entry["session_id"] not in mine:
            raise Denied(f"entry {entry_id} isn't yours: {owner}", "not_yours")
        if entry["kind"] == "config":
            raise Denied(f"entry {entry_id} changed Doorman's setup: {owner}", "owner_only")
        if entry["kind"] not in ("action", "revert"):
            raise Denied(f"entry {entry_id} isn't a change", "invalid")
        if entry["tier"] != "reversible" and entry["status"] in ("waiting_approval", "sending"):
            raise Denied(f"entry {entry_id} is a send that waits for the owner: nothing has gone out, and only "
                         "the owner can deny it; tell them if it's no longer wanted", "irreversible")
        if entry["tier"] != "reversible":
            inverse = self.inverse_call(entry) if entry["status"] == "done" else None
            instead = (f" To take it away again: `{inverse}` (a send too: it waits for the owner's approval)."
                       if inverse else " A correction is a new send, which waits for their approval.")
            raise Denied(f"entry {entry_id} was a send: it left Doorman (others may have seen it) and can't be "
                         f"undone. Tell the owner.{instead}", "irreversible")
        if entry["status"] == "reverted":
            raise Denied(f"entry {entry_id} is undone already (by entry {entry['reverted_by']})", "already_undone")
        if entry["status"] != "done":
            raise Denied(f"entry {entry_id} is {entry['status']}: nothing to undo", "invalid")
        original = self.journal.get(entry["reverts"]) if entry["kind"] == "revert" else entry
        if original is None or original["session_id"] not in mine or original["decision"] == "approval":
            raise Denied(f"entry {entry_id} is or undoes a change the owner approved: {owner}", "owner_only")
        try:
            self.registry.find_tool(original["tool"])  # switched off or read-only since: not through the agent
        except Denied as exc:
            raise Denied(f"{exc.reason}; {owner}", exc.code) from None
        if self.registry.asks_first(original["plugin"], original["tool"]):
            raise Denied(f"{original['tool']} is set to Ask me: {owner}", "owner_only")

    # the fields an undo names when it says what it put back ("folder back to INBOX"): short ones people know
    UNDONE_FIELDS = ("folder", "list", "calendar", "start", "end", "due", "summary", "title", "status", "done",
                     "flags", "path", "name", "location", "priority", "tags")

    def undone_text(self, entry: dict) -> str:
        """What an undo put back, in a line for the agent to pass on: "Moved “Axon Weekly” to Archive: undone,
        folder back to INBOX". Built from the entry's summary and its before/after states, so every plugin
        gets it; the private values of the object become placeholders, as in the journal."""
        before, after = entry.get("before"), entry.get("after")
        summary = entry.get("summary") or entry.get("tool")
        done = "undone"
        if entry.get("kind") == "revert":  # undoing an undo: the original change is back
            original = self.journal.get(entry["reverts"]) if entry.get("reverts") else None
            summary, done = (original or {}).get("summary") or summary, "redone"
        if before is None and after is not None:
            what = f"{done}, removed again"
        elif after is None and before is not None:
            what = f"{done}, restored"
        else:
            back = []
            for field in changed_fields(before, after):
                value = (before or {}).get(field)
                if field not in self.UNDONE_FIELDS or isinstance(value, dict):
                    continue
                text = ", ".join(map(str, value)) if isinstance(value, list) else "nothing" if value in (None, "") \
                    else str(value)
                back.append(f"{field} back to {text[:60]}")
            what = done + (", " + "; ".join(back[:4]) if back else "")
        plugin_type = self.plugin_type(entry.get("plugin"))
        line = f"{summary}: {what}"
        return self.pseudonyms.summary(self.redactor.text(line), [before, after], plugin_type)

    def inverse_call(self, entry: dict) -> str | None:
        """For a create that went out as a send (a task on a shared list, an event with guests): the call that
        takes it away again, when the plugin has a matching delete whose required arguments the create's
        result names (caldav.delete_task uid=...). None when there is no such call."""
        instance, _, short = str(entry.get("tool") or "").partition(".")
        if not short.startswith("create_"):
            return None
        name = f"{instance}.delete_{short[len('create_'):]}"
        try:
            _, _, tool = self.registry.find_tool(name)
        except Denied:
            return None
        params = tool.spec.get("params") or {}
        result = entry.get("result") if isinstance(entry.get("result"), dict) else {}
        required = params.get("required") or []
        args = {k: result[k] for k in params.get("properties") or {} if isinstance(result.get(k), (str, int))}
        if not required or any(k not in args for k in required):
            return None
        return f"doorman call {name} " + " ".join(f"{k}={shlex.quote(str(v))}" for k, v in args.items())

    @staticmethod
    def _comparable(tool, state: Any) -> Any:
        state = strip_private(state)
        if isinstance(state, dict) and tool.IGNORE_FIELDS:
            state = {k: v for k, v in state.items() if k not in tool.IGNORE_FIELDS}
        return state

    def _check_undo(self, tool, object_ref: str | None, entry: dict) -> str | None:
        """After an undo, read the object back: the fields the action changed must be as they were before."""
        if not tool.can_check_drift() or not object_ref:
            return None
        try:
            now = self._comparable(tool, tool.current(object_ref))
        except Exception as exc:  # noqa: BLE001 - a failed check is reported, not raised
            return f"couldn't check the result: {exc}"
        before, after = self._comparable(tool, entry["before"]), self._comparable(tool, entry["after"])
        if before is None:
            return None if now is None else "the object still exists"
        if now is None:
            return "the object is gone"
        wrong = [f for f in changed_fields(before, after) if canonical(now.get(f)) != canonical(before.get(f))]
        return f"didn't take for {', '.join(wrong)}" if wrong else None

    def _scope_entries(self, task_id: int | None = None, since: str | None = None) -> list[dict]:
        # failed entries are included when they changed part of their object (_revertable decides)
        return self.journal.list(task_id=task_id, since=since, kinds=("action",), status=("done", "failed"),
                                 limit=10_000)

    def revert_scope(self, task_id: int | None = None, since: str | None = None, preview: bool = False) -> dict:
        entries = self._scope_entries(task_id=task_id, since=since)
        plan, skipped = [], []
        for entry in entries:
            if entry["status"] == "failed" and not (entry.get("result") or {}).get("partial"):
                continue  # failed without changing anything: nothing to undo
            tool = self._tool_object(entry)
            ok, why = self._revertable(entry, tool)
            if ok:
                plan.append(entry["id"])
            else:
                skipped.append({"entry_id": entry["id"], "summary": entry["summary"], "reason": why,
                                "follow_up": tool.follow_up(entry["args"], entry["result"]) if tool else None})
        if preview:
            also = []
            for entry_id in plan:
                for dependent in self.journal.dependents(self.journal.get(entry_id)):
                    if dependent["id"] not in plan and dependent["id"] not in (a["entry_id"] for a in also):
                        also.append({"entry_id": dependent["id"], "summary": dependent["summary"],
                                     "reason": f"changed the same object after entry {entry_id}"})
            return {"will_revert": plan, "also_reverts": also, "skipped": skipped}
        # every entry gets its chance: a conflict or failure on one object doesn't stop the others
        result = {"reverted": [], "skipped": skipped, "conflicts": [], "failed": []}
        for entry_id in plan:
            if self.journal.get(entry_id)["status"] not in ("done", "failed"):
                continue  # already reverted as a dependent of an earlier one
            try:
                sub = self.revert_entry(entry_id)
            except Exception as exc:  # noqa: BLE001 - one broken service must not block the rest
                log.exception("reverting entry %s", entry_id)
                result["failed"].append({"entry_id": entry_id, "reason": f"{type(exc).__name__}: {exc}"})
                continue
            for key in result:
                for item in sub.get(key, []):
                    # an entry can come up twice: on its own, and as a later edit of another entry's object
                    if key == "reverted" and item not in result[key] or key != "reverted" and not any(
                            seen.get("entry_id") == item.get("entry_id") and seen.get("reason") == item.get("reason")
                            for seen in result[key]):
                        result[key].append(item)
        return result

    # ------------------------------------------------------------------ changesets

    def propose_changeset(self, session: dict, key: dict, title: str, actions: list[dict],
                          task_id: int | None = None) -> dict:
        task_id = task_id or session["task_id"]
        title = str(title)[:200]
        if self.config["reader_actor_split"] and key["role"] == "reader":
            raise Denied(READER_WRITE, "role")
        if not actions:
            raise Denied("a changeset needs at least one action", "invalid")
        task = self.tasks.get(task_id)
        preview = []
        if not isinstance(actions, list):
            raise Denied("actions must be a list", "invalid")
        for index, action in enumerate(actions):
            if not isinstance(action, dict) or not isinstance(action.get("tool"), str) or \
                    not isinstance(action.get("args", {}), dict):
                raise Denied(f"action {index + 1} must be {{tool, args}}", "invalid")
            name, args = action["tool"], action.get("args") or {}
            instance, plugin, tool = self.registry.find_tool(name)
            self._guard(session, instance, write=True)
            self._validate(tool.spec.get("params"), args, f"arguments of action {index + 1}")
            tier = tool.tier(args)
            args = self._unhide_args(name, tier, args)
            actions[index] = {**action, "args": args}  # as the agent wrote them: Apply checks them again
            args = tool.prepare(args)
            before = tool.snapshot(args)
            after = tool.preview(args, before)
            item = {"index": index, "tool": name, "args": args, "tier": tier, "summary": tool.describe(args),
                    "before": before, "after": after,
                    # a send's before holds only what it keeps for itself ('_message_id'): show its arguments
                    "diff": tool.render_diff(before, after, args) if after is not None or strip_private(before)
                    else [{"sign": "+", "field": k, "value": canonical(v)} for k, v in args.items()]}
            if tier == "reversible" and not self.registry.asks_first(instance, name):
                item["decision"] = "run"
            else:
                checks = self.policy.evaluate(session, task, name, tool, args, tier)
                # no_approval plugins run on Apply without a second question unless
                # the tool always asks, a check failed or the daily cap is reached
                direct = tier == "irreversible" and self.registry.no_approval(instance, name)
                if direct and self.direct_cap_reached():
                    checks["checks"].append(self._cap_check())
                clean = all(c["ok"] for c in checks["checks"])
                item["decision"] = "direct" if direct and clean else "approval"
                item["warnings"] = [c["detail"] for c in checks["checks"] if not c["ok"]]
            preview.append(item)
        changeset_id = self.db.exec(
            "INSERT INTO changesets(title, task_id, session_id, actions, preview, status, created) "
            "VALUES(?,?,?,?,?,?,?)",
            (title, task_id, session["id"], dumps(actions), dumps(preview), "proposed", clock.iso()))
        # every changeset waits for the owner's review (a task's old auto_apply column is ignored). The push
        # lists what Apply all would do; with a warning on any of it, Apply all opens the changeset instead
        lines = "\n".join(f"· {str(item['summary'])[:120]}" for item in preview)
        self.notifier.push(f"Changeset to review: {title}",
                           f"{len(actions)} change{'' if len(actions) == 1 else 's'}\n{lines}"[:700],
                           url=f"{self.public_url}/app/#/changesets/{changeset_id}", priority=3,
                           extra={"ask": self.push_ask("changeset", changeset_id, self.changeset_clean(preview))})
        return self.changeset(changeset_id)

    def changeset(self, changeset_id: int) -> dict | None:
        row = self.db.one("SELECT * FROM changesets WHERE id=?", (changeset_id,))
        if row:
            for field in ("actions", "preview", "result"):
                row[field] = loads(row[field])
        return row

    @staticmethod
    def changeset_clean(preview: list[dict]) -> bool:
        """No item carries a warning: Apply all on the push may apply it in place."""
        return not any(item.get("warnings") for item in preview)

    def apply_changeset(self, changeset_id: int, selected: list[int] | None = None) -> dict:
        cs = self.changeset(changeset_id)
        # claimed atomically, so two taps on Apply can't run its actions twice
        with self.db.tx() as conn:
            claimed = conn.execute("UPDATE changesets SET status='applying' WHERE id=? AND status='proposed'",
                                   (changeset_id,)).rowcount == 1
        if cs is None or not claimed:
            raise Denied("no open changeset with that id", "changeset")
        session = self.auth.get_session(cs["session_id"])
        key = self.db.one("SELECT * FROM agent_keys WHERE id=?", (session["key_id"],))
        indexes = selected if selected is not None else list(range(len(cs["actions"])))
        results, deferred = [], []
        for index in indexes:
            action, preview = cs["actions"][index], cs["preview"][index]
            try:
                _, _, tool = self.registry.find_tool(action["tool"])
                now_before = tool.snapshot(action["args"])
                if canonical(strip_private(now_before)) != canonical(strip_private(preview["before"])):
                    results.append({"index": index, "status": "conflict", "before": preview["before"],
                                    "now": now_before})
                    continue
                outcome = self.call_tool(session, key, action["tool"], action["args"], task_id=cs["task_id"],
                                         changeset_id=changeset_id, defer_approval=True)
            except Denied as denied:
                outcome = {"status": "denied", "error": denied.reason}
            outcome["index"] = index
            results.append(outcome)
            if outcome.get("status") == "waiting_approval":
                deferred.append(outcome["entry_id"])
        approval_id = self.approvals.create(deferred, changeset_id=changeset_id) if deferred else None
        status = "applied" if len(indexes) == len(cs["actions"]) and all(
            r["status"] not in ("conflict", "denied", "failed") for r in results) else "partially_applied"
        self.db.exec("UPDATE changesets SET status=?, result=? WHERE id=?",
                     (status, dumps({"results": results, "approval_id": approval_id}), changeset_id))
        self.feed.changeset_decided(changeset_id)
        return {"changeset_id": changeset_id, "status": status, "results": results, "approval_id": approval_id}

    def reject_changeset(self, changeset_id: int, comment: str = "") -> bool:
        """True if it was open and is rejected now."""
        with self.db.tx() as conn:
            rejected = conn.execute("UPDATE changesets SET status='rejected', comment=? WHERE id=? AND "
                                    "status='proposed'", (comment, changeset_id)).rowcount == 1
        if rejected:
            self.feed.changeset_decided(changeset_id)
        return rejected

    # ------------------------------------------------------------------ agent keys

    def agent_url(self) -> str:
        """The address agents use for the agent API: config agent_url, else guessed from agent_listen
        (0.0.0.0 means the compose stack, where agents reach Doorman as http://doorman:<port>)."""
        if self.config.get("agent_url"):
            return str(self.config["agent_url"]).rstrip("/")
        host, _, port = str(self.config["agent_listen"]).rpartition(":")
        return f"http://{'doorman' if host in ('0.0.0.0', '::', '') else host}:{port}"

    def first_steps(self) -> dict | None:
        """For the Inbox's Get started card: what a new owner hasn't done yet, None once an agent key was ever
        made. `plugin`: something is connected besides what a new Doorman starts with."""
        if self.db.one("SELECT 1 FROM agent_keys LIMIT 1"):
            return None
        names = {row["name"] for row in self.db.all("SELECT name FROM plugin_instances")}
        return {"plugin": bool(names - set(self.registry.starter))}

    def create_agent_key(self, name: str, role: str) -> dict:
        name = (name or "").strip()
        if not name or len(name) > 60:
            raise Denied("give the key a name (up to 60 characters)", "invalid")
        if role not in ROLES:
            raise Denied(f"role must be one of {', '.join(ROLES)}", "invalid")
        if self.killed():
            raise Denied("Doorman is paused; resume it first", "paused")
        token = self.auth.create_key(name, role)
        key = self.db.one("SELECT id, name, role, created, revoked FROM agent_keys ORDER BY id DESC LIMIT 1")
        self.journal.create(kind="config", tool="key.create", tier="irreversible", decision="run", status="done",
                            summary=f"New agent key “{name}” ({role})")
        return {"key": key, "token": token, "agent_url": self.agent_url()}

    def revoke_agent_key(self, key_id: int) -> dict:
        key = self.db.one("SELECT id, name, revoked FROM agent_keys WHERE id=?", (key_id,))
        if key is None or key["revoked"]:
            raise Denied("no active key with that id", "not_found")
        self.auth.revoke_key(key_id)
        self.journal.create(kind="config", tool="key.revoke", tier="irreversible", decision="run", status="done",
                            summary=f"Revoked agent key “{key['name']}”")
        return {"ok": True}

    def resume_agent_key(self, key_id: int) -> dict:
        """The owner lets a paused key (a honeytoken, a decoy key, a leak) work again; the addresses the
        network proxy cut it off at are let out too."""
        key = self.db.one("SELECT id, name, revoked FROM agent_keys WHERE id=?", (key_id,))
        if key is None or key["revoked"] or not self.auth.paused(key_id):
            raise Denied("no paused key with that id", "not_found")
        self.auth.resume_key(key_id)
        self.resolve_attention("key_paused", key_id)
        self.journal.create(kind="config", tool="key.resume", tier="irreversible", decision="run", status="done",
                            summary=f"Resumed agent key “{key['name']}”")
        # its quarantine (decoy keys) ends with the pause, and the leaks the network proxy blocked are seen
        self.egress.key_resumed(key_id, key["name"])
        return {"ok": True}

    def pause(self) -> None:
        """Every agent call is refused until resume; the keys stay, so resuming needs no new setup. Waiting
        approvals stay waiting (the owner's call, 7 Nov): the owner can still approve or deny each one, during
        the pause or after it, and nothing goes out without that. Revoke all keys cancels them."""
        if self.killed():
            raise Denied("Doorman is already paused", "paused")
        self.db.set_setting("killed", "1")
        self.journal.create(kind="config", tool="pause", tier="irreversible", decision="run", status="done",
                            summary="Paused: every agent call refused, keys kept")
        self.notifier.push("Agents paused", "Every agent call is refused until you resume. The keys stay; "
                           "waiting sends still wait for you.", url=f"{self.public_url}/app/#/more", priority=4)

    def kill(self) -> None:
        """Revoke all keys: a pause plus every agent key revoked. For a key that may have leaked; resuming
        then means new keys and the agent's setup again."""
        self.db.set_setting("killed", "1")
        self.auth.revoke_all()
        self.approvals.cancel_pending()
        self.journal.create(kind="config", tool="kill", tier="irreversible", decision="run", status="done",
                            summary="Kill switch: all agent keys revoked, pending approvals cancelled")
        self.notifier.push("Kill switch used", "All agent keys are revoked, and pending approvals are cancelled.",
                           url=f"{self.public_url}/app/#/more", priority=4)

    def resume(self) -> None:
        """Agents with a key that still works can call again at once. A task claimed before the pause gets a
        full lease back: the agent couldn't work on it or report while paused."""
        if not self.killed():
            raise Denied("Doorman isn't paused", "invalid")
        self.db.set_setting("killed", "0")
        until = clock.iso(clock.now() + timedelta(minutes=self.tasks.lease_minutes()))
        self.db.exec("UPDATE tasks SET lease_until=? WHERE status='claimed' AND lease_until<?", (until, until))
        keys = self.db.one("SELECT COUNT(*) AS n FROM agent_keys WHERE revoked=0")["n"]
        self.journal.create(kind="config", tool="resume", tier="irreversible", decision="run", status="done",
                            summary="Doorman resumed; agents with a key can call again" if keys
                            else "Doorman resumed; create new agent keys to reconnect")

    # ------------------------------------------------------------------ routines and triggers

    def run_routines(self) -> list[int]:
        created = []
        zone = ZoneInfo(self.config.get("timezone") or "UTC")
        for routine in self.db.all("SELECT * FROM routines WHERE enabled=1"):
            base = clock.parse(routine["last_run"]) if routine["last_run"] else clock.now() - timedelta(minutes=1)
            next_run = croniter(routine["cron"], base.astimezone(zone)).get_next(datetime)
            if next_run <= clock.now():
                # a routine is its text and its schedule; old plugin_allowlist/read_only columns are ignored
                created.append(self.tasks.create(routine["task_text"], origin=f"routine:{routine['name']}",
                                                trusted=True))
                self.db.exec("UPDATE routines SET last_run=? WHERE id=?", (clock.iso(), routine["id"]))
        return created

    def poll_triggers(self, force: bool = False) -> list[int]:
        """Asks every switched-on plugin that declares events (or has a trigger) for new ones, every
        trigger_poll_minutes per plugin (the worker ticks every few seconds; a mailbox doesn't need asking that
        often). Each event goes into the feed agents follow (GET /v1/events) and to the triggers it matches, from
        the same poll: one cursor per plugin. Returns the tasks the triggers created."""
        created = []
        every = 60 * float(self.config.get("trigger_poll_minutes", 5))
        triggers = self.db.all("SELECT * FROM triggers WHERE enabled=1")
        # a plugin whose events all come from its jobs isn't asked: they arrive with the job's run (job_events)
        polled = {t["plugin"] for t in triggers if self._polls_events(t["plugin"])}
        for instance in sorted(polled | set(self.registry.event_sources())):
            now = clock.now().timestamp()
            if not force and now - self._polled.get(instance, -1e18) < every:
                continue
            self._polled[instance] = now
            try:
                if not self.registry.state(instance)["enabled"]:
                    continue
                plugin = self.registry.instance(instance)
                events, cursor = plugin.poll_events(self.registry.cursor(instance))
                events = [e for e in events or [] if isinstance(e, dict) and isinstance(e.get("type"), str)]
                with self.db.tx():  # the cursor moves only together with the events it passed
                    self.registry.set_cursor(instance, cursor)
                    self._store_events(instance, events)
                if events:
                    self.feed.bell.ring()  # wake the agents waiting on GET /v1/events
                self._poll_results[instance] = {"polled": clock.iso()}
            except Exception as exc:  # noqa: BLE001 - one failing plugin must not stop the others
                log.warning("polling %s for events: %s", instance, exc)
                self._poll_results[instance] = {"polled": clock.iso(), "error": str(exc)[:200]}
                continue
            created += self._fire_triggers(instance, events, triggers)
        return created

    def _polls_events(self, instance: str) -> bool:
        """False for a plugin whose declared events all come from jobs; True when it declares none (an old
        trigger on it still polls) or isn't there any more (the poll's own error handling takes over)."""
        try:
            manifest = self.registry.manifest(instance)
        except (Denied, PluginError, KeyError):
            return True
        return not manifest.get("events") or polls_events(manifest)

    def _fire_triggers(self, instance: str, events: list[dict], triggers: list | None = None) -> list[int]:
        """A task for each switched-on trigger an event matches. Not trusted: the event's text is a stranger's."""
        if triggers is None:
            triggers = self.db.all("SELECT * FROM triggers WHERE enabled=1")
        created = []
        for event in events:
            for trigger in (t for t in triggers if t["plugin"] == instance and t["event"] == event.get("type")):
                if self._trigger_matches(loads(trigger["match"], {}), event):
                    text = _fill(trigger["task_text"], event)
                    created.append(self.tasks.create(text, origin=f"trigger:{trigger['name']}", trusted=False,
                                                    source_ref=event.get("ref")))
        return created

    def job_events(self, instance: str, job: str, status: Any) -> Any:
        """A job's run may return events (`{"summary": ..., "events": [...]}`), for what is too heavy to ask
        for every few minutes (a plugin that has to log in with a browser first). They go where polled events go:
        into the feed, where an agent gets them cleaned, redacted, past the guard and spotlit (event_feed),
        and to the triggers. Only types the manifest declares with `job: <this job>` are kept. The plugin keeps
        its own record of what it has seen, so no cursor moves here. Returns the status without the events,
        with how many there were."""
        if not isinstance(status, dict) or "events" not in status:
            return status
        status = dict(status)
        given = status.pop("events")
        try:
            manifest = self.registry.manifest(instance)
        except (Denied, PluginError, KeyError):
            manifest = {}
        allowed = {e["name"] for e in manifest.get("events") or [] if isinstance(e, dict) and e.get("job") == job}
        events = [e for e in given if isinstance(e, dict) and e.get("type") in allowed] \
            if isinstance(given, list) else []
        if len(events) < (len(given) if isinstance(given, list) else 1):
            log.warning("%s.%s returned events its manifest doesn't declare for it; left out", instance, job)
        if events:
            with self.db.tx():
                self._store_events(instance, events)
            self.feed.bell.ring()  # wake the agents waiting on GET /v1/events
            self._fire_triggers(instance, events)
            status["events"] = len(events)
        return status

    def _store_events(self, instance: str, events: list[dict]) -> None:
        """Into the feed as the plugin sent them. Cleaning, the guard and placeholders run when an agent
        fetches them (event_feed), as they do for reads."""
        ts = clock.iso()
        for event in events:
            data = {k: _capped(v) for k, v in event.items() if k not in EVENT_KEYS}
            self.db.exec("INSERT INTO events(ts, plugin, type, ref, data) VALUES(?,?,?,?,?)",
                         (ts, instance, event["type"][:100], str(event.get("ref") or "")[:500] or None, dumps(data)))

    def watch_status(self) -> dict:
        """For each switched-on plugin with events: when Doorman last asked it (`polled`, None before the first
        time since the start), how often (`every_minutes`) and the last poll's error. An empty event answer
        then says how fresh "nothing new" is."""
        every = float(self.config.get("trigger_poll_minutes", 5))
        out = {}
        for instance in sorted(self.registry.event_sources()):
            try:
                if not self.registry.state(instance)["enabled"]:
                    continue
            except (Denied, KeyError):
                continue
            out[instance] = {"polled": None, **self._poll_results.get(instance, {}), "every_minutes": every}
        return out

    def latest_event_id(self) -> int:
        """The newest id the feed ever handed out. It stays after pruning (AUTOINCREMENT), so a cursor does too."""
        row = self.db.one("SELECT seq FROM sqlite_sequence WHERE name='events'")
        return int(row["seq"]) if row else 0

    def event_feed(self, session: dict, key: dict, after: int = 0, limit: int = 50,
                   only_doorman: bool = False) -> dict:
        """GET /v1/events: what happened after event `after`, oldest first: `events` from the plugins this
        session may use, `doorman` for Doorman's own events for this key (feed.py). Plugin event text comes
        from strangers (a sender, a subject, a message's start), so it takes the path of a raw third-party read:
        cleaned, redacted, scanned by the guard (a flagged event is masked like a flagged list item), taint and
        provenance, placeholders, the read log. Actor keys under the reader/actor split get what happened and
        where, without the text, as they can't read raw content. Doorman's own events come from Doorman and
        the owner: whole, for every role, and no taint. `only_doorman` leaves plugin events out (doorman wait).
        `cursor` is what to pass as `after` next time; limit 0 only asks for it."""
        self._guard(session, None, write=False)
        latest = self.latest_event_id()
        if limit <= 0:
            return {"events": [], "doorman": [], "cursor": latest, "more": False}
        reach = {} if only_doorman else {name: self._event_reach(name) for name in self.registry.configured()
                                         if self.registry.state(name)["enabled"]}
        visible = [name for name, how in reach.items() if how]
        which = "(plugin IS NULL AND id IN (SELECT event_id FROM event_keys WHERE key_id=?))"
        if visible:
            which = f"({which} OR plugin IN ({','.join('?' * len(visible))}))"
        rows = self.db.all(f"SELECT * FROM events WHERE id>? AND id<=? AND {which} ORDER BY id LIMIT ?",
                           (after, latest, key["id"], *visible, limit + 1))
        more = len(rows) > limit
        rows = rows[:limit]
        # not past the newest id: a cursor from before a restore starts over instead of waiting for ever
        cursor = rows[-1]["id"] if more else latest
        own = [{"id": r["id"], "ts": r["ts"], "type": r["type"], **({"ref": r["ref"]} if r["ref"] else {}),
                **loads(r["data"], {})} for r in rows if r["plugin"] is None]
        rows = [r for r in rows if r["plugin"] is not None]
        if not rows:
            return {"events": [], "doorman": own, "cursor": cursor, "more": more}
        meta = [{"id": r["id"], "ts": r["ts"], "plugin": r["plugin"], "type": r["type"], "ref": r["ref"]} for r in rows]
        params = {"after": after}
        if self.config["reader_actor_split"] and key["role"] == "actor":
            shown = [self.for_agent(m, m["plugin"]) for m in meta]
            self.reads.add(key, session, "events", params, shown)
            return {"events": shown, "doorman": own, "cursor": cursor, "more": more}
        # from a plugin whose item read the owner switched Off (or an event whose own read is Off): what
        # happened and where, without the text
        typed = {name: self._event_reach_by_type(name) for name in {m["plugin"] for m in meta}}
        bare = {m["id"]: self.for_agent(m, m["plugin"]) for m in meta
                if typed[m["plugin"]].get(m["type"], reach[m["plugin"]]) != "text"}
        if len(bare) == len(meta):
            shown = list(bare.values())
            self.reads.add(key, session, "events", params, shown)
            return {"events": shown, "doorman": own, "cursor": cursor, "more": more}
        meta, rows = zip(*[(m, r) for m, r in zip(meta, rows) if m["id"] not in bare])
        items = [{**m, **loads(r["data"], {})} for m, r in zip(meta, rows)]
        items = self.redactor.value(sanitize.clean_value(items)[0])
        items, unscanned = self._scan("events", {}, params, items)
        # a held-back event still says what happened and where, without its text
        items = [{**m, **item, "id": m["id"]} if item.get("quarantined") else item for m, item in zip(meta, items)]
        self.auth.taint(session["id"], True, False)
        self.provenance.record(session["id"], items, "events", "third_party")
        shown, changed = [], set()
        for m, item in zip(meta, items):
            value, hid = self.pseudonyms.hide(item, self.plugin_type(m["plugin"]))
            shown.append({**value, **self.for_agent(m, m["plugin"])})  # a hidden item keeps when and where
            if hid:
                changed.add(m["id"])
        shown = sorted(shown + list(bare.values()), key=lambda event: event["id"])
        hidden = [i for i, event in enumerate(shown) if event["id"] in changed]
        self.reads.add(key, session, "events", params, shown, trust="third_party", hidden=hidden,
                       status="unscanned" if unscanned else "ok", error=unscanned)
        return {"events": shown, "doorman": own, "cursor": cursor, "more": more}

    def _event_reach(self, instance: str) -> str | None:
        """How much of a plugin's events an agent gets, by the owner's switches for its reads (Plugins ->
        Tools): "text" while its item read is on (manifest `item.read`, else `recent`, else any third-party
        read), "where" (what happened and where) once that is Off, None when every read is Off."""
        try:
            manifest = self.registry.manifest(instance)
            off = set(self.registry.state(instance)["disabled_tools"])
        except (Denied, PluginError, KeyError):
            return None
        reads = [r["name"] for r in manifest.get("reads", [])]
        if reads and all(name in off for name in reads):
            return None
        item = (manifest.get("item") or {}).get("read") or manifest.get("recent")
        gate = [item] if item else [r["name"] for r in manifest.get("reads", [])
                                    if r.get("trust", "third_party") == "third_party"]
        return "text" if not gate or any(name not in off for name in gate) else "where"

    def _event_reach_by_type(self, instance: str) -> dict[str, str]:
        """Events declared with their own `read:` follow that read's switch instead of the plugin's item read:
        a plugin's grade events carry the course and grade item only while its grades read is on, its
        announcements only while its news read is. {event type: "text" or "where"}."""
        try:
            manifest = self.registry.manifest(instance)
            off = set(self.registry.state(instance)["disabled_tools"])
        except (Denied, PluginError, KeyError):
            return {}
        return {e["name"]: "where" if e["read"] in off else "text" for e in manifest.get("events") or []
                if isinstance(e, dict) and e.get("read")}

    def prune_events(self) -> None:
        """Hourly: drop events older than events_days (default 7)."""
        if clock.now().timestamp() - self._events_pruned < 3600:
            return
        self._events_pruned = clock.now().timestamp()
        days = float(self.config.get("events_days", 7))
        if days > 0:
            with self.db.tx() as conn:
                conn.execute("DELETE FROM events WHERE ts<?", (clock.iso(clock.now() - timedelta(days=days)),))
                # who Doorman's own events were for goes with them
                conn.execute("DELETE FROM event_keys WHERE NOT EXISTS (SELECT 1 FROM events WHERE id=event_id)")

    def _trigger_matches(self, match: dict, event: dict) -> bool:
        import fnmatch

        for field, expected in match.items():
            if field == "from_trusted":
                if not self.policy.trusted_entry(expected, str(event.get("from", "")).lower()):
                    return False
                continue
            value = str(event.get(field, ""))
            if not fnmatch.fnmatch(value.lower(), str(expected).lower()):
                return False
        return True

    # ------------------------------------------------------------------ status

    def reader_round(self, key: dict, counts: dict) -> dict:
        """doorman-reader reports each round, so the owner can see it runs (it lives in its own container).
        A round that only failed starts (or continues) failing_since; one that recorded or found nothing
        to do ends it."""
        if key["role"] != "reader":
            raise Denied("only reader keys report rounds", "role")
        def count(name: str) -> int:
            value = counts.get(name, 0)
            return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 10**6 else 0
        now = clock.iso()
        previous = loads(self.db.get_setting(f"reader:{key['id']}") or "null") or {}
        failed = count("failed") > 0 and count("recorded") == 0
        status = {"at": now, "recorded": count("recorded"), "skipped": count("skipped"), "failed": count("failed"),
                  "error": str(counts.get("error") or "")[:300] or None,
                  "failing_since": (previous.get("failing_since") or now) if failed else None,
                  "last_record": now if count("recorded") else previous.get("last_record"),
                  # how far it got in the event feed (chats, files); the reader keeps no state of its own
                  "events_cursor": counts["events_cursor"] if isinstance(counts.get("events_cursor"), int)
                  and not isinstance(counts["events_cursor"], bool) and 0 <= counts["events_cursor"] < 2**62
                  else previous.get("events_cursor")}
        self.db.set_setting(f"reader:{key['id']}", dumps(status))
        return status

    def reader_status(self, key_id: int) -> dict | None:
        return loads(self.db.get_setting(f"reader:{key_id}") or "null")

    def check_silence(self, force: bool = False) -> list[str]:
        """Things that went quiet, listed under Needs attention (and pushed once); each clears by itself.
        Checked once a minute."""
        now = clock.now()
        if not force and now.timestamp() - self._last_silence_check < 60:
            return []
        self._last_silence_check = now.timestamp()
        found = []
        app = f"{self.public_url}/app/#/status"

        if upkeep.check_backup(self, now):  # 36 hours when the worker makes them nightly
            found.append("backup")

        minutes = float(self.config.get("reader_silent_minutes", 60))
        for key in self.db.all("SELECT id, name, created FROM agent_keys WHERE role='reader' AND revoked=0"):
            status = self.reader_status(key["id"]) or {}
            limit = now - timedelta(minutes=minutes)
            problem = None
            if not minutes:
                pass
            elif not status and clock.parse(key["created"]) < limit:
                problem = "It hasn't reported a single round. Is its container running?"
            elif status and clock.parse(status["at"]) < limit:
                problem = f"Its last round was at {status['at'][:16].replace('T', ' ')} UTC. Is its container running?"
            elif status.get("failing_since") and clock.parse(status["failing_since"]) < limit:
                problem = f"Every round fails since {status['failing_since'][:16].replace('T', ' ')} UTC: " \
                          f"{status.get('error') or 'see its log'}"
            if problem:
                found.append(f"reader:{key['id']}")
                self.attention("reader_silent", key["id"], f"The reader “{key['name']}” isn't working", problem, url=app)
            else:
                self.resolve_attention("reader_silent", key["id"])

        minutes = float(self.config.get("task_wait_warn_minutes", 60))
        cutoff = clock.iso(now - timedelta(minutes=minutes))
        waiting = self.db.one("SELECT COUNT(*) AS n FROM tasks WHERE status='pending' AND due<? AND created<?",
                              (cutoff, cutoff))["n"] if minutes else 0
        agents = self.db.one("SELECT COUNT(*) AS n FROM agent_keys WHERE role IN ('solo','actor') AND revoked=0")["n"]
        if waiting and agents and not self.killed():
            found.append("tasks")
            self.attention("tasks_waiting", "tasks", f"{waiting} task{'s' if waiting != 1 else ''} waiting for over "
                           f"{int(minutes)} minutes", "No agent has picked them up. Is the agent running?",
                           url=f"{self.public_url}/app/#/tasks")
        else:
            self.resolve_attention("tasks_waiting", "tasks")

        if self.vault.key_source == "file" and self.config.get("vault_key_file_warn", True):
            found.append("vault_key")
            self.attention("vault_key", "file", "The vault key is stored next to the vault",
                           f"Doorman opened the vault with {self.vault.key_path}, so anyone who gets a copy of the "
                           "data folder can read every stored password. Put the key in your password manager, "
                           "pass it as DOORMAN_VAULT_KEY and delete vault.key (docs/running.md).", url=app)
        else:
            self.resolve_attention("vault_key", "file")
        return found

    def week(self) -> dict:
        """The last 7 days in plain numbers, for the top of the journal and the status page."""
        since = clock.iso(clock.now() - timedelta(days=7))
        one = lambda sql, *args: self.db.one(sql, (since, *args))["n"]  # noqa: E731
        return {
            "since": since,
            "actions": one("SELECT COUNT(*) AS n FROM journal WHERE ts>=? AND kind='action' "
                           "AND status IN ('done','reverted') AND tier NOT IN ('irreversible','payment') "
                           "AND reverts IS NULL"),
            "sent": one("SELECT COUNT(*) AS n FROM journal WHERE ts>=? AND kind='action' AND status='done' "
                        "AND tier IN ('irreversible','payment')"),
            "approved": one("SELECT COUNT(*) AS n FROM approvals WHERE decided>=? AND status='approved'"),
            "denied": one("SELECT COUNT(*) AS n FROM approvals WHERE decided>=? AND status='denied'"),
            "expired": one("SELECT COUNT(*) AS n FROM approvals WHERE created>=? AND status='expired'"),
            "refused": one("SELECT COUNT(*) AS n FROM journal WHERE ts>=? AND decision='deny'"),
            "failed": one("SELECT COUNT(*) AS n FROM journal WHERE ts>=? AND kind='action' AND status='failed'"),
            "reverted": one("SELECT COUNT(*) AS n FROM journal WHERE ts>=? AND reverts IS NOT NULL AND status='done'"),
            "records": one("SELECT COUNT(*) AS n FROM records WHERE created>=?"),
            "reads": self.reads.count_since(since),
            "records_review": one("SELECT COUNT(*) AS n FROM records WHERE created>=? "
                                  "AND json_extract(data, '$.suggested_action')='review'"),
        }

    def status(self) -> dict:
        """Is everything working? One row per part, for the status page."""
        ok, health = self.health()
        problems = {(a["kind"], a["ref"]): a for a in self.attention_list()}
        keys = []
        for key in self.auth.list_keys():
            if key["revoked"]:
                continue
            row = {**key, "problem": None}
            if key["role"] == "reader":
                row["reader"] = self.reader_status(key["id"])
                item = problems.get(("reader_silent", str(key["id"])))
                row["problem"] = item["detail"] if item else None
            keys.append(row)
        plugins = []
        for plugin in self.registry.list():
            if not plugin["enabled"]:
                continue
            item = problems.get(("plugin", plugin["name"]))
            checked = self._checked.get(plugin["name"])
            plugins.append({"name": plugin["name"], "description": plugin["description"],
                            "problem": item["detail"] if item else None,
                            "checked": clock.iso(datetime.fromtimestamp(checked, timezone.utc)) if checked else None})
        return {
            "worker": {"ok": ok, "seconds_ago": health["worker_seconds_ago"]},
            "paused": self.killed(),
            "backup": upkeep.backup_row(self, health["last_backup"], problems),
            "tasks": {"pending": self.db.one("SELECT COUNT(*) AS n FROM tasks WHERE status='pending'")["n"],
                      "claimed": self.db.one("SELECT COUNT(*) AS n FROM tasks WHERE status='claimed'")["n"],
                      "problem": problems[("tasks_waiting", "tasks")]["title"]
                      if ("tasks_waiting", "tasks") in problems else None},
            "keys": keys,
            "plugins": plugins,
            "attention": len(problems),
            "week": self.week(),
        }

    def job_done(self, instance: str, job: str, status: dict | None, error: str | None = None) -> None:
        """A plugin job's run ended (server.start_jobs). Kept for the owner app; a job failing for an hour
        shows under Needs attention."""
        name = f"{instance}.{job}"
        before = self.jobs.get(name) or {}
        entry = {"last_run": clock.iso(), "error": error,
                 "status": status if status is not None else before.get("status"),
                 "failing_since": (before.get("failing_since") or clock.iso()) if error else None}
        self.jobs[name] = entry
        dismissed = self.db.get_setting(f"job_dismissed:{name}") is not None
        if error and not dismissed and clock.now() - clock.parse(entry["failing_since"]) > timedelta(hours=1):
            self.attention("job", name, f"{name} keeps failing", error)
        elif not error:
            if before.get("failing_since"):
                self.resolve_attention("job", name)
            if dismissed:  # it works again, so the next failure shows
                self.db.exec("DELETE FROM settings WHERE key=?", (f"job_dismissed:{name}",))

    def dismiss_job_error(self, instance: str, job: str) -> dict:
        """The owner has seen a job's failure: hide it (and its Needs attention item) until the job works
        again. Kept in the database, so a restart doesn't bring it back."""
        name = f"{instance}.{job}"
        if not (self.jobs.get(name) or {}).get("error"):
            raise Denied("that job isn't failing", "not_found")
        self.db.set_setting(f"job_dismissed:{name}", clock.iso())
        self.resolve_attention("job", name)
        return {"ok": True}

    def copy_to_archive(self, instance: str, after: str) -> dict | None:
        """After a job or tool run: copy what the plugin downloaded into the files archive, as its manifest's
        `copy_to_archive:` says (archive_copy.py). A failure is the owner's to fix, not the run's: the
        download itself worked."""
        try:
            out = archive_copy.copy_after(self.registry, Path(self.config["data_dir"]), instance, after)
        except Exception as exc:  # noqa: BLE001
            log.warning("copying into the archive after %s.%s: %s", instance, after, exc)
            self.attention("archive_copy", instance, f"{instance}: copying into the archive failed", str(exc))
            return None
        if out and out["copied"]:
            log.info("%s.%s: %d new or changed files into %s", instance, after, out["copied"], ", ".join(out["into"]))
        if out is not None:
            self.resolve_attention("archive_copy", instance)
        return out

    def job_status(self, instance: str) -> dict:
        return {name.split(".", 1)[1]: {**entry, "dismissed": bool(entry.get("error"))
                                        and self.db.get_setting(f"job_dismissed:{name}") is not None}
                for name, entry in self.jobs.items() if name.split(".", 1)[0] == instance}

    def prune_reads(self) -> None:
        """Hourly: drop read log rows older than read_log_days (default 90; 0 keeps them all)."""
        if clock.now().timestamp() - self._reads_pruned < 3600:
            return
        self._reads_pruned = clock.now().timestamp()
        self.reads.prune(float(self.config.get("read_log_days", 90)))

    def prune_tables(self) -> None:
        """Hourly: what grows with use goes after its time (retention.py, `retention:`), then a VACUUM now
        and then."""
        if clock.now().timestamp() - self._tables_pruned < 3600:
            return
        self._tables_pruned = clock.now().timestamp()
        settings = {**retention.DEFAULTS, **(self.config.get("retention") or {})}
        pruned = retention.prune(self.db, settings)
        if pruned:
            log.info("pruned %s", ", ".join(f"{n} from {table}" for table, n in pruned.items()))
        retention.maybe_vacuum(self.db, float(settings.get("vacuum_days") or 0))

    def import_credential_files(self) -> None:
        """Credentials a sidecar leaves in a shared volume (the WhatsApp sidecar's token) go to the vault."""
        for name, key in self.registry.import_credential_files():
            self.journal.create(kind="config", plugin=name, tool="credential.set", tier="irreversible",
                                decision="run", status="done", args={"key": key, "from_file": True},
                                summary=f"Set {name} credential {key} from the file its sidecar wrote")

    def tick(self) -> None:
        self.last_tick = clock.now().timestamp()
        for step in (self.approvals.expire, self.sends.tick, self.tasks.expire_leases, self.run_routines,
                     self.feed.announce_due_tasks,
                     self.feed.check_caps, self.poll_triggers,
                     self.import_credential_files, self.check_plugins, self.check_silence, self.prune_reads,
                     self.prune_events,
                     self.guard.stop_if_idle,
                     self.extractor.stop_if_idle, self.embedder.stop_if_idle, self.embedder.ensure_downloaded,
                     self.prune_uploads, self.prune_tables, self.owner_questions.sweep, self.egress.sweep):
            try:
                step()
            except Exception:  # noqa: BLE001 - the worker must keep running
                log.exception("worker step %s", step.__name__)















EVENT_KEYS = {"id", "ts", "plugin", "type", "ref"}  # the feed's own fields; a plugin's event can't set them


def _capped(value: Any, n: int = 1000) -> Any:
    """An event is a notice, not the content: long texts are cut (the agent reads the item by its ref)."""
    if isinstance(value, str):
        return value if len(value) <= n else value[: n - 1] + "…"
    if isinstance(value, list):
        return [_capped(v, n) for v in value[:50]]
    if isinstance(value, dict):
        return {k: _capped(v, n) for k, v in list(value.items())[:50]}
    return value


SCAN_CHARS = 250_000  # above the 200000 max_chars of mail.read, mail.attachment and files.read, plus field names


def _scan_item(name: str, params: dict, item: Any, skip: frozenset[str] = frozenset()) -> dict:
    """What the guard scans for one item: every string in it as `field: value` lines (what the agent would
    get), plus what the owner sees on the quarantine screen.

    Left out: every `ref` (Doorman's `<instance>:<key>`, made of fields the item carries itself) and the
    fields its read lists under `not_scanned` (`skip`, by path: `id`, `attendees.id`), IDs the service makes
    and nobody writes words into. The model reads long random strings as encoded payloads: a Google Calendar
    event whose title was three harmless words scored 0.67 with its calendar ID, event ID and link, and
    0.00 without them."""
    lines = []

    def walk(value: Any, prefix: str) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                path = f"{prefix}.{k}" if prefix else str(k)
                if not str(k).startswith("_") and k != "ref" and path not in skip:
                    walk(v, path)
        elif isinstance(value, list):
            for v in value:
                walk(v, prefix)
        elif isinstance(value, str) and value.strip():
            lines.append(f"{prefix}: {value}" if prefix else value)

    walk(item, "")
    meta = item if isinstance(item, dict) else {}
    if isinstance(meta.get("_guard_text"), str):
        # the whole text behind a list row's snippet: scanned with it, never handed out (_without_guard_text),
        # so an injection cut off at the snippet's end still holds the row back
        lines.append(meta["_guard_text"])
    sender = meta.get("from")
    if isinstance(sender, list):
        sender = ", ".join(str(s) for s in sender[:3])
    label = next((meta[k] for k in ("subject", "title", "name", "summary", "path", "topic")
                  if isinstance(meta.get(k), str) and meta[k].strip()), None)
    ref = meta.get("ref") or meta.get("id") or f"{name} {canonical(params)}"
    out = {"text": "\n".join(lines), "source": name, "ref": str(ref), "label": label,
           "sender": sender if isinstance(sender, str) else None}
    hidden = meta.get("hidden_text")
    if isinstance(hidden, dict) and hidden.get("reason"):
        out["flag"] = str(hidden["reason"])  # held back whatever the model says (sanitize.py)
    elif len(out["text"]) > SCAN_CHARS:
        # the guard scans ~400 characters a second while every other read waits: an item this long (what
        # no read returns unless asked to) is held back instead of keeping it busy for minutes
        out["flag"] = (f"too long to scan ({len(out['text'])} characters); read less of it at a time "
                       "(max_chars)")
    return out


def _without_guard_text(data: Any) -> Any:
    """A read's rows without `_guard_text`, the text only the guard sees (_scan_item)."""
    if isinstance(data, list):
        return [_without_guard_text(v) for v in data]
    if isinstance(data, dict):
        return {k: _without_guard_text(v) for k, v in data.items() if k != "_guard_text"}
    return data


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _mask_tokens(value: Any, tokens: list[str]) -> Any:
    """`value` with every token (case-insensitive) in its strings replaced by "[removed]"."""
    if not tokens:
        return value
    pattern = re.compile("|".join(re.escape(t) for t in sorted(tokens, key=len, reverse=True)), re.I)
    def walk(v: Any) -> Any:
        if isinstance(v, str):
            return pattern.sub("[removed]", v)
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        return v
    return walk(value)


def _fill(template: str, event: dict) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: str(event.get(m.group(1), m.group(0))), template)
