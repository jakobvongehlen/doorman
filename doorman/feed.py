"""Doorman's own events in the agents' feed, each key's place in it, and the bell that wakes a waiting request.

The feed (GET /v1/events) has two kinds of rows in one table, `events`, numbered by one id:

- plugin events (new mail, a message, an entry starting soon): `plugin` names the plugin; who sees them and
  how follows the plugin's rules (engine.event_feed);
- Doorman's own events (an approval decided, a send's result, a task for the agent...): `plugin` is NULL,
  and `event_keys` names the key or keys each one is for. They come from Doorman and the owner, never from a
  stranger, so they reach every role whole; anything third-party in them is a ref or an id, never text.

Each key has a cursor here (`agent_feed`): the newest event id it has acknowledged. GET /v1/events without
`after` starts from it; with `after=N` it acknowledges everything up to N first. So an agent that passes
back the cursor of the last batch on its next call sees every event once, and one that restarts carries on
after the last batch it acknowledged (that batch comes again). A key's cursor starts where the feed stood
when the key was made.

The bell: every insert into `events` rings it, and a request holding on (GET /v1/events?wait=,
GET /v1/wait) wakes at once. The API, the owner app and the worker run in one process, so that covers
plugin polls, approvals, tasks and answers. `doorman-admin` is a separate process; what it adds is noticed
by the waiting requests' slow re-check (RECHECK_SECONDS).

The owner sees the same feed in the app (Journal → Feed, GET /owner/events): `owner_view` below.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from datetime import timedelta
from typing import Any, Iterable

from . import clock, sanitize
from .plugin_api import Denied, PluginError
from .util import dumps, loads

log = logging.getLogger("doorman.feed")

RECHECK_SECONDS = 5.0   # a waiting request looks at the database this often anyway (other processes' inserts)
MAX_WAIT = 60.0         # the longest a request may hold on
CAPS_CHECK_SECONDS = 60  # how often the worker compares every key's capabilities even without a config change

# Doorman's own event types, for the docs and the tests: what each carries besides id, ts, type and ref
TYPES = {
    "approval_decided": "approval_id, entry_ids, changeset_id, decision (approved, declined, edited), note "
                        "(the owner's word on a Deny), replaced_by {approval_id, entry_id} when edited",
    "approval_expired": "approval_id, entry_ids, changeset_id",
    "approval_ask_again": "approval_id, entry_ids, task_id, changeset_id: the owner still wants a send whose "
                          "approval expired; make the same call again",
    "send_result": "entry_id, approval_id, tool, status (sent, done, failed, unknown, cancelled), error; an "
                   "unknown send Doorman checks (mail) gets a second one, sent or failed, once it "
                   "can tell",
    "entry_reverted": "entry_id, revert_id, tool",
    "changeset_decided": "changeset_id, status (applied, partially_applied, declined), comment, approval_id",
    "task_created": "task_id, origin, trusted, due",
    "task_cancelled": "task_id, reason (closed by the owner, or the lease ran out)",
    "reminder_due": "task_id, due",
    "question_answered": "question_id, item (the ref it asked about), status (answered, failed, expired)",
    "owner_answered": "question_id, status (answered, dismissed, expired), answer (the owner's own text), "
                      "question",
    "egress_decided": "request_id, target, status (granted, denied, expired), scope (once, task, always; null "
                      "unless granted), expires (when the exception ends; null for always and when not granted)",
    "caps_changed": "version, changes (what changed, in words: \"mail: send switched off\"; empty when only "
                    "descriptions or parameters changed, e.g. after an update; missing when it isn't known)",
}


# Doorman events the owner's view leaves out: they repeat, per key, what the owner just did in the app
AGENT_ONLY = ("caps_changed",)


class Bell:
    """Rung from any thread after an insert into `events`; awaited by request handlers on the event loop.

    `generation` goes up with every ring. A waiter reads it before it looks at the database and waits only
    while it's unchanged, so a ring between the look and the wait isn't missed."""

    def __init__(self):
        self.generation = 0
        self._lock = threading.Lock()
        self._waiters: set[tuple[asyncio.AbstractEventLoop, asyncio.Event]] = set()

    def ring(self) -> None:
        with self._lock:
            self.generation += 1
            waiters = list(self._waiters)
        for loop, event in waiters:
            try:
                loop.call_soon_threadsafe(event.set)
            except RuntimeError:  # its loop is closed (a test client that went away)
                pass

    async def wait(self, seen: int, timeout: float) -> bool:
        """Until the bell rang after generation `seen`, at most `timeout` seconds. True if it rang."""
        event = asyncio.Event()
        entry = (asyncio.get_running_loop(), event)
        with self._lock:
            if self.generation != seen:
                return True
            self._waiters.add(entry)
        try:
            await asyncio.wait_for(event.wait(), timeout=max(0.0, timeout))
            return True
        except asyncio.TimeoutError:
            return self.generation != seen
        finally:
            with self._lock:
                self._waiters.discard(entry)


class Feed:
    def __init__(self, engine):
        self.engine = engine
        self.db = engine.db
        self.bell = Bell()
        self.caps_dirty = True
        self._caps_checked = 0.0

    # ------------------------------------------------------------------ emitting

    def emit(self, type_: str, key_ids: Iterable[int], ref: str | None = None, /, **data: Any) -> int | None:
        """One Doorman event for these keys. Nothing when there's no key to tell."""
        keys = sorted({int(k) for k in key_ids if k is not None})
        if not keys:
            return None
        with self.db.tx() as conn:
            event_id = conn.execute("INSERT INTO events(ts, plugin, type, ref, data) VALUES(?,?,?,?,?)",
                                    (clock.iso(), None, type_, ref, dumps(data))).lastrowid
            conn.executemany("INSERT INTO event_keys(event_id, key_id) VALUES(?,?)", [(event_id, k) for k in keys])
        self.bell.ring()
        return event_id

    def key_of_session(self, session_id: str | None) -> int | None:
        row = self.db.one("SELECT key_id FROM sessions WHERE id=?", (session_id,)) if session_id else None
        return row["key_id"] if row else None

    def key_of_entry(self, entry: dict | None) -> int | None:
        return self.key_of_session(entry.get("session_id")) if entry else None

    def keys_for_task(self, task: dict) -> list[int]:
        """A task with a key (a reminder) is for that key; any other task for every key that can take one."""
        if task.get("key_id"):
            return [task["key_id"]]
        return [r["id"] for r in self.db.all("SELECT id FROM agent_keys WHERE revoked=0 AND role!='reader'")]

    def keys_working_on(self, task_id: int) -> list[int]:
        return [r["key_id"] for r in self.db.all("SELECT DISTINCT key_id FROM sessions WHERE task_id=?", (task_id,))]

    # ------------------------------------------------------------------ what happened to an agent's actions

    def approval_decided(self, approval: dict, decision: str, note: str | None = None,
                         replaced_by: dict | None = None) -> None:
        entry_ids = approval["journal_ids"] if isinstance(approval["journal_ids"], list) \
            else loads(approval["journal_ids"], [])
        for key_id, ids in self._entries_by_key(entry_ids).items():
            data = {"approval_id": approval["id"], "entry_ids": ids, "changeset_id": approval.get("changeset_id"),
                    "decision": decision}
            if note:
                data["note"] = note
            if replaced_by:
                data["replaced_by"] = replaced_by
            self.emit("approval_decided", [key_id], f"approval:{approval['id']}", **data)

    def approval_expired(self, approval_id: int, entry_ids: list[int], changeset_id: int | None) -> None:
        for key_id, ids in self._entries_by_key(entry_ids).items():
            self.emit("approval_expired", [key_id], f"approval:{approval_id}", approval_id=approval_id,
                      entry_ids=ids, changeset_id=changeset_id)

    def send_result(self, entry_id: int, outcome: dict, approval_id: int | None = None) -> None:
        entry = self.engine.journal.get(entry_id)
        if entry is None:
            return
        status = outcome.get("status") or entry["status"]
        if status == "done" and entry["tier"] != "reversible":
            status = "sent"
        data = {"entry_id": entry_id, "approval_id": approval_id, "tool": entry["tool"], "status": status}
        if outcome.get("error") and status != "sent":
            data["error"] = self.engine.redactor.text(str(outcome["error"]))[:300]
        self.emit("send_result", [self.key_of_entry(entry)], f"entry:{entry_id}", **data)

    def entry_reverted(self, entry: dict, revert_id: int) -> None:
        self.emit("entry_reverted", [self.key_of_entry(entry)], f"entry:{entry['id']}", entry_id=entry["id"],
                  revert_id=revert_id, tool=entry["tool"])

    def changeset_decided(self, changeset_id: int) -> None:
        cs = self.engine.changeset(changeset_id)
        if cs is None:
            return
        result = cs["result"] or {}
        self.emit("changeset_decided", [self.key_of_session(cs["session_id"])], f"changeset:{changeset_id}",
                  changeset_id=changeset_id, status="declined" if cs["status"] == "rejected" else cs["status"],
                  comment=cs["comment"] or None,
                  approval_id=result.get("approval_id") if isinstance(result, dict) else None)

    def question_answered(self, question: dict) -> None:
        self.emit("question_answered", [question["key_id"]], f"question:{question['id']}",
                  question_id=question["id"], item=question["ref"], status=question["status"])

    def owner_answered(self, question: dict) -> None:
        """The owner answered (or dismissed) a question the agent asked them, or nobody did in time. The answer
        is the owner's own text, so it comes in the event itself."""
        data = {"question_id": question["id"], "status": question["status"], "question": question["question"]}
        if question["status"] == "answered":
            data["answer"] = question.get("answer")
        self.emit("owner_answered", [question["key_id"]], f"owner-question:{question['id']}", **data)

    def egress_decided(self, request: dict) -> None:
        """The owner decided the agent's request for network access (egress/service.py), or nobody did in
        time (status expired)."""
        self.emit("egress_decided", [request["key_id"]], f"egress-request:{request['id']}",
                  request_id=request["id"], target=request["target"], status=request["status"],
                  scope=request.get("scope"), expires=request.get("expires"))

    def _entries_by_key(self, entry_ids: list[int]) -> dict[int, list[int]]:
        out: dict[int, list[int]] = {}
        for entry_id in entry_ids:
            key_id = self.key_of_entry(self.engine.journal.get(entry_id))
            if key_id is not None:
                out.setdefault(key_id, []).append(entry_id)
        return out

    # ------------------------------------------------------------------ tasks

    def announce_task(self, task_id: int) -> bool:
        """task_created (or reminder_due, for a reminder) once a pending task is due, once per task."""
        with self.db.tx() as conn:
            task = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
            if task is None or task["status"] != "pending" or task["due"] > clock.iso():
                return False
            if conn.execute("SELECT 1 FROM events WHERE ref=? AND plugin IS NULL AND type IN "
                            "('task_created','reminder_due')", (f"task:{task_id}",)).fetchone():
                return False
            task = dict(task)
            if task["origin"] == "agent" and task.get("key_id"):
                return self.emit("reminder_due", [task["key_id"]], f"task:{task_id}", task_id=task_id,
                                 due=task["due"]) is not None
            return self.emit("task_created", self.keys_for_task(task), f"task:{task_id}", task_id=task_id,
                             origin=task["origin"], trusted=bool(task["trusted"]), due=task["due"]) is not None

    def announce_due_tasks(self) -> list[int]:
        """Each tick: tasks that became due since (a reminder, a task for later). Only tasks younger than the
        feed keeps events, so an old task isn't announced again after its event was pruned."""
        since = clock.iso(clock.now() - timedelta(days=float(self.engine.config.get("events_days", 7))))
        rows = self.db.all("SELECT t.id FROM tasks t WHERE t.status='pending' AND t.due<=? AND t.due>=? AND NOT "
                           "EXISTS (SELECT 1 FROM events e WHERE e.ref='task:'||t.id AND e.plugin IS NULL AND "
                           "e.type IN ('task_created','reminder_due'))", (clock.iso(), since))
        return [r["id"] for r in rows if self.announce_task(r["id"])]

    def task_cancelled(self, task_id: int, reason: str, pending_keys: list[int] | None = None) -> None:
        keys = self.keys_working_on(task_id) or pending_keys or []
        self.emit("task_cancelled", keys, f"task:{task_id}", task_id=task_id, reason=reason)

    # ------------------------------------------------------------------ capabilities

    def mark_caps_dirty(self) -> None:
        self.caps_dirty = True

    def check_caps(self, force: bool = False) -> list[int]:
        """caps_changed for each key whose capabilities version moved since the last check. Run by the worker
        after a config change (journal kind config) and once a minute anyway."""
        now = time.monotonic()
        if not force and not self.caps_dirty and now - self._caps_checked < CAPS_CHECK_SECONDS:
            return []
        self.caps_dirty, self._caps_checked = False, now
        from .caps import caps_changes, caps_for, caps_outline  # caps.py builds on the engine: imported late

        changed = []
        for key in self.db.all("SELECT * FROM agent_keys WHERE revoked=0"):
            base = {"id": "", "task_id": None}
            try:
                caps = caps_for(self.engine, key, base)
            except Exception:  # noqa: BLE001 - one broken plugin listing must not stop the others
                log.exception("capabilities of key %s", key["id"])
                continue
            version, outline = caps["version"], caps_outline(caps)
            row = self._row(key)
            if row["caps_version"] == version:
                continue
            # the outline from the last version, so the event can say what changed, not only that it did
            setting = f"caps_outline:{key['id']}"
            before = loads(self.db.get_setting(setting), None)
            self.db.exec("UPDATE agent_feed SET caps_version=? WHERE key_id=?", (version, key["id"]))
            self.db.set_setting(setting, dumps(outline))
            if row["caps_version"] is not None:
                changes = caps_changes(before, outline)
                self.emit("caps_changed", [key["id"]], None, version=version,
                          **({"changes": changes} if changes is not None else {}))
                changed.append(key["id"])
        return changed

    # ------------------------------------------------------------------ cursors

    def _row(self, key: dict) -> dict:
        row = self.db.one("SELECT * FROM agent_feed WHERE key_id=?", (key["id"],))
        if row is None:
            # the feed as it stood when the key was made: what came after is for it
            start = self.db.one("SELECT MAX(id) AS n FROM events WHERE ts<?", (key.get("created") or clock.iso(),))
            self.db.exec("INSERT OR IGNORE INTO agent_feed(key_id, cursor, updated) VALUES(?,?,?)",
                         (key["id"], int(start["n"] or 0), clock.iso()))
            row = self.db.one("SELECT * FROM agent_feed WHERE key_id=?", (key["id"],))
        return row

    def cursor(self, key: dict) -> int:
        return int(self._row(key)["cursor"])

    def ack(self, key: dict, upto: int) -> int:
        """Everything up to `upto` is acknowledged. The cursor only moves forward, and never past the newest
        event (a cursor from a restored backup can't skip what comes next)."""
        self._row(key)
        upto = min(int(upto), self.engine.latest_event_id())
        self.db.exec("UPDATE agent_feed SET cursor=MAX(cursor, ?), updated=? WHERE key_id=?",
                     (upto, clock.iso(), key["id"]))
        return self.cursor(key)

    # ------------------------------------------------------------------ the owner's view

    def owner_view(self, before: int | None = None, limit: int = 50, source: str | None = None,
                   task_id: int | None = None) -> dict:
        """GET /owner/events: the feed as the owner app shows it (Journal → Feed, and on a task's screen),
        newest first, paged back with `before` like the journal. Both kinds of events; `source` picks one
        (`plugin` or `doorman`), `task_id` the events about one task: its own (created, cancelled, reminder),
        those about its actions (approvals, sends, reverts, changesets, questions) and the plugin event a
        trigger made it from.

        It's the owner's own data, so it gets what the app's other third-party text gets: the cheap cleaning
        (invisible and look-alike characters) and, for plugin events, the masking of one-time codes the
        journal and the read log show too (redaction.codes). No guard, placeholders, spotlighting or read log:
        those are for agents. The read switches decide
        what agents get, not what the owner sees; each plugin event says how much of it agents get now
        (`agents`: text, where, none, off). Each key's cursor answers "has my agent seen this?"; a fired
        trigger links the event to the task it made."""
        limit = max(1, min(int(limit), 200))
        # caps_changed is for agents (call caps again); the owner made the change and the journal has it
        where, args = [f"type NOT IN ({','.join('?' * len(AGENT_ONLY))})"], list(AGENT_ONLY)
        if before is not None:
            where.append("id<?")
            args.append(int(before))
        if source == "plugin":
            where.append("plugin IS NOT NULL")
        elif source == "doorman":
            where.append("plugin IS NULL")
        elif source not in (None, "", "all"):
            raise Denied("source is plugin or doorman", "invalid")
        if task_id is not None:
            refs, origin = self._task_refs(int(task_id))
            about = f"(plugin IS NULL AND ref IN ({','.join('?' * len(refs))}))"
            where.append(f"({about} OR id=?)" if origin else about)
            args.extend(refs)
            if origin:
                args.append(origin)
        sql = "SELECT * FROM events" + (f" WHERE {' AND '.join(where)}" if where else "")
        rows = self.db.all(f"{sql} ORDER BY id DESC LIMIT ?", (*args, limit + 1))
        more = len(rows) > limit
        rows = rows[:limit]

        own = [r["id"] for r in rows if r["plugin"] is None]
        keys_of: dict[int, list[int]] = {}
        if own:
            for r in self.db.all(f"SELECT event_id, key_id FROM event_keys WHERE event_id IN "
                                 f"({','.join('?' * len(own))}) ORDER BY key_id", tuple(own)):
                keys_of.setdefault(r["event_id"], []).append(r["key_id"])
        reach: dict[str, dict] = {}
        events = []
        for r in rows:
            data = loads(r["data"], {})
            data = sanitize.clean_value(data if isinstance(data, dict) else {})[0]
            if r["plugin"] is not None:  # one-time codes stay masked, as in the journal and the read log
                data = self.engine.redactor.value(data)
            event = {"id": r["id"], "ts": r["ts"], "source": "doorman" if r["plugin"] is None else "plugin",
                     "plugin": r["plugin"], "type": r["type"], "ref": r["ref"], "data": data}
            if r["plugin"] is None:
                event["keys"] = keys_of.get(r["id"], [])
                event["task_id"], event["summary"] = self._about(r["ref"], event["data"])
            else:
                if r["plugin"] not in reach:
                    reach[r["plugin"]] = self._agents_get(r["plugin"])
                how = reach[r["plugin"]]
                # an event with a read of its own follows that one, as in engine.event_feed
                event["agents"] = how["types"].get(r["type"], how["all"]) if how["all"] in ("text", "where") \
                    else how["all"]
                event["triggers"] = []
            events.append(event)
        self._fired(events)

        task_ids = {e["task_id"] for e in events if e.get("task_id")} | \
            {t["task_id"] for e in events for t in e.get("triggers", [])}
        closed = self.engine.tasks._closed_by_owner() if task_ids else set()
        tasks = [t for t in (self.engine.tasks.get(i) for i in sorted(task_ids)) if t]
        return {
            "events": events, "more": more, "latest": self.engine.latest_event_id(),
            "keep_days": float(self.engine.config.get("events_days", 7)),
            # how far each key has read: "has my agent seen this?" (no row yet: it never asked)
            "keys": [{"id": k["id"], "name": k["name"], "role": k["role"], "cursor": k["cursor"],
                      "seen": k["updated"]} for k in self.db.all(
                "SELECT k.id, k.name, k.role, f.cursor, f.updated FROM agent_keys k "
                "LEFT JOIN agent_feed f ON f.key_id=k.id WHERE k.revoked=0 ORDER BY k.id")],
            "plugins": {name: block.get("type") or name for name, block in self.engine.registry.configured().items()},
            "tasks": {str(t["id"]): {"id": t["id"], "text": t["text"], "status": t["status"],
                                     "closed_by_owner": t["id"] in closed} for t in tasks},
        }

    def _agents_get(self, instance: str) -> dict:
        """How much of this plugin's events agents get by the owner's switches now: "all" is text, where
        (item read Off), none (every read Off) or off (the plugin is switched off or gone); "types" holds
        the events with a read of their own."""
        try:
            if not self.engine.registry.state(instance)["enabled"]:
                return {"all": "off", "types": {}}
        except (Denied, PluginError, KeyError):
            return {"all": "off", "types": {}}
        return {"all": self.engine._event_reach(instance) or "none",
                "types": self.engine._event_reach_by_type(instance)}

    def _task_refs(self, task_id: int) -> tuple[list[str], int | None]:
        """The refs of Doorman's own events about a task, and the id of the plugin event a trigger made it
        from (the newest event with its source_ref from before the task)."""
        task = self.engine.tasks.get(task_id)
        if task is None:
            raise Denied("no such task", "not_found")
        refs = [f"task:{task_id}"]
        refs += [f"entry:{r['id']}" for r in self.db.all("SELECT id FROM journal WHERE task_id=?", (task_id,))]
        refs += [f"approval:{r['id']}" for r in self.db.all(
            "SELECT DISTINCT a.id FROM approvals a, json_each(a.journal_ids) j WHERE j.value IN "
            "(SELECT id FROM journal WHERE task_id=?)", (task_id,))]
        refs += [f"changeset:{r['id']}" for r in self.db.all(
            "SELECT c.id FROM changesets c LEFT JOIN sessions s ON s.id=c.session_id "
            "WHERE c.task_id=? OR s.task_id=?", (task_id, task_id))]
        refs += [f"question:{r['id']}" for r in self.db.all(
            "SELECT q.id FROM questions q JOIN sessions s ON s.id=q.session_id WHERE s.task_id=?", (task_id,))]
        refs += [f"owner-question:{r['id']}" for r in self.db.all(
            "SELECT id FROM owner_questions WHERE task_id=?", (task_id,))]
        refs += [f"egress-request:{r['id']}" for r in self.db.all(
            "SELECT id FROM egress_requests WHERE task_id=?", (task_id,))]
        origin = None
        if task.get("source_ref") and str(task.get("origin") or "").startswith("trigger:"):
            row = self.db.one("SELECT MAX(id) AS id FROM events WHERE plugin IS NOT NULL AND ref=? AND ts<=?",
                              (task["source_ref"], task["created"]))
            origin = row["id"] if row else None
        return refs, origin

    def _about(self, ref: str | None, data: dict) -> tuple[int | None, str | None]:
        """For one of Doorman's own events on the owner's screen: the task it belongs to (a link), and the
        journal summary of the action it is about ("Send “Slides” to anna@..."), as the journal shows it."""
        entries = [data["entry_id"]] if data.get("entry_id") else list(data.get("entry_ids") or [])
        rows = [self.db.one("SELECT task_id, summary FROM journal WHERE id=?", (i,)) for i in entries[:20]]
        rows = [r for r in rows if r]
        summary = rows[0]["summary"] if rows else None
        if summary and len(rows) > 1:
            summary = f"{summary} (+{len(rows) - 1} more)"
        if data.get("task_id"):
            return data["task_id"], summary
        task = next((r["task_id"] for r in rows if r["task_id"]), None)
        kind, _, ident = (ref or "").partition(":")
        sql = {"changeset": "SELECT COALESCE(c.task_id, s.task_id) AS t FROM changesets c "
                            "LEFT JOIN sessions s ON s.id=c.session_id WHERE c.id=?",
               "owner-question": "SELECT task_id AS t FROM owner_questions WHERE id=?",
               "egress-request": "SELECT task_id AS t FROM egress_requests WHERE id=?",
               "question": "SELECT s.task_id AS t FROM questions q JOIN sessions s ON s.id=q.session_id "
                           "WHERE q.id=?"}.get(kind)
        if task is None and sql is not None and ident.isdigit():
            row = self.db.one(sql, (int(ident),))
            task = row["t"] if row else None
        return task, summary

    def _fired(self, events: list[dict]) -> None:
        """Which triggers each plugin event fired. A trigger's task keeps the event's ref (source_ref) and is
        made right after the event is stored, so it goes to the newest event with that ref from before it,
        within ten minutes."""
        plugin_events = [e for e in events if e["source"] == "plugin" and e["ref"]]
        if not plugin_events:
            return
        refs = sorted({e["ref"] for e in plugin_events})
        tasks = self.db.all(f"SELECT id, origin, created, source_ref FROM tasks WHERE origin LIKE 'trigger:%' "
                            f"AND source_ref IN ({','.join('?' * len(refs))}) ORDER BY id", tuple(refs))
        for task in tasks:
            made = clock.parse(task["created"])
            candidates = [e for e in plugin_events if e["ref"] == task["source_ref"]
                          and timedelta(0) <= made - clock.parse(e["ts"]) <= timedelta(minutes=10)]
            if candidates:
                max(candidates, key=lambda e: e["id"])["triggers"].append(
                    {"name": task["origin"][len("trigger:"):], "task_id": task["id"]})
