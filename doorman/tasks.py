"""Tasks: what the owner (or a routine, a trigger, an agent's reminder) hands to an agent, and the lease
an agent holds while it works on one.

A task is its text. A key claims it and gets a session bound to it; every call the key makes pushes the
lease out, and a report ends it. A lease that runs out, or the owner closing the task, ends the task and
never the agent: its next call goes through its own session again.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from . import clock
from .plugin_api import Denied
from .util import loads

MAX_LEASE_MINUTES = 240  # the longest a task's lease can be pushed out at once (doorman task renew)


class Tasks:
    def __init__(self, engine):
        self.engine = engine
        self.db = engine.db

    def get(self, task_id: int | None) -> dict | None:
        if not task_id:
            return None
        row = self.db.one("SELECT * FROM tasks WHERE id=?", (task_id,))
        if row:
            row["trusted"] = bool(row["trusted"])
        return row

    def create(self, text: str, origin: str = "owner", trusted: bool = True, due: str | None = None,
                    source_ref: str | None = None, key_id: int | None = None) -> int:
        """A task is its text. What the agent may do while on it is what each plugin's settings allow.
        `key_id`: only that key sees and takes it (an agent's reminder); None, any key. Once it's due, the
        keys it's for get task_created (reminder_due for a reminder) in their feed."""
        now = clock.iso()
        task_id = self.db.exec(
            "INSERT INTO tasks(text, origin, trusted, status, created, due, source_ref, key_id) "
            "VALUES(?,?,?,?,?,?,?,?)", (text, origin, int(trusted), "pending", now, due or now, source_ref, key_id))
        if origin.startswith("trigger:"):  # someone else's words the agent gets: fingerprinted like a read
            self.engine.egress.note_task(task_id, text, origin)
        self.engine.feed.announce_task(task_id)  # due now: right away; later: the worker's tick
        return task_id

    def list(self, status: str | None = None, limit: int = 100) -> list[dict]:
        sql, params = "SELECT * FROM tasks", []
        if status:
            sql += " WHERE status=?"
            params.append(status)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = self.db.all(sql, tuple(params))
        closed = self._closed_by_owner()
        for row in rows:  # columns from before 2026-11-07, no longer used
            for old in ("plugin_allowlist", "read_only", "auto_apply"):
                row.pop(old, None)
            row["closed_by_owner"] = row["id"] in closed
        return rows

    def _closed_by_owner(self) -> set[int]:
        """Tasks the owner closed are stored as failed (agents and the feed know no other end); the journal
        entry of the Close tells them apart, so the app can say "Closed by you" instead of "Failed"."""
        return {r["task_id"] for r in self.db.all("SELECT task_id FROM journal WHERE tool='task.close' "
                                                  "AND task_id IS NOT NULL")}

    def for_key(self, key: dict) -> list[dict]:
        """Pending, due tasks this key may take: those for any key and those for it alone."""
        return [t for t in self.list("pending") if t["due"] <= clock.iso()
                and (t.get("key_id") is None or t["key_id"] == key["id"])]

    def claim(self, key: dict, task_id: int | None = None) -> tuple[dict, dict] | None:
        """Take the oldest due task (or a given one) and start a session bound to it."""
        self.engine.refuse_if_paused()
        active = self.engine.auth.active_task_session(key)
        if active:
            raise Denied(f"finish task #{active['task_id']} first (doorman report)", "task_active")
        with self.db.tx() as conn:
            mine = "(key_id IS NULL OR key_id=?)"  # a reminder is only for the key that set it
            if task_id:
                row = conn.execute(f"SELECT * FROM tasks WHERE id=? AND status='pending' AND {mine}",
                                   (task_id, key["id"])).fetchone()
            else:
                row = conn.execute(f"SELECT * FROM tasks WHERE status='pending' AND due<=? AND {mine} "
                                   "ORDER BY due, id LIMIT 1", (clock.iso(), key["id"])).fetchone()
            if row is None:
                return None
            lease = clock.iso(clock.now() + timedelta(minutes=self.lease_minutes()))
            conn.execute("UPDATE tasks SET status='claimed', claimed_by=?, lease_until=? WHERE id=?",
                         (key["name"], lease, row["id"]))
        task = self.get(row["id"])
        session = self.engine.auth.new_session(key, task_id=task["id"])
        return task, session

    def lease_minutes(self) -> float:
        return float(self.engine.config.get("task_lease_minutes", 30))

    def renew_lease(self, session: dict, task_id: int | None = None, minutes: Any = None,
                    explicit: bool = False) -> dict | None:
        """Push the lease of the task this session works on out to `minutes` from now (default
        task_lease_minutes, at most MAX_LEASE_MINUTES). Every API call a key makes while it holds a task does
        this on its own (explicit False: written only when it gains a minute or more); `doorman task renew`
        asks for it, for a long job between calls. Never shortens a lease. None when there's no claimed task."""
        if task_id is not None and session["task_id"] != task_id:
            raise Denied("this session isn't working on that task", "session")
        if not session.get("task_id"):
            if explicit:
                raise Denied("this session has no task to renew; claim one first", "session")
            return None
        if minutes is None:
            minutes = self.lease_minutes()  # the owner's setting, whatever its size
        elif isinstance(minutes, bool) or not isinstance(minutes, (int, float)) or not 1 <= minutes <= MAX_LEASE_MINUTES:
            raise Denied(f"minutes is a number from 1 to {MAX_LEASE_MINUTES}", "invalid")
        now = clock.now()
        until = clock.iso(now + timedelta(minutes=float(minutes)))
        floor = until if explicit else clock.iso(now + timedelta(minutes=float(minutes) - 1))
        with self.db.tx() as conn:
            row = conn.execute("SELECT status, lease_until FROM tasks WHERE id=?", (session["task_id"],)).fetchone()
            if row is None or row["status"] != "claimed":
                if explicit:
                    raise Denied(f"task #{session['task_id']} isn't open any more", "task_closed")
                return None
            if (row["lease_until"] or "") < floor:
                conn.execute("UPDATE tasks SET lease_until=? WHERE id=?", (until, session["task_id"]))
                return {"task_id": session["task_id"], "lease_until": until}
        return {"task_id": session["task_id"], "lease_until": row["lease_until"]}

    def report(self, session: dict, task_id: int, status: str, summary: str, key: dict | None = None) -> dict:
        if status not in ("done", "failed"):
            raise Denied("status must be done or failed", "invalid")
        if session["task_id"] != task_id:
            # the task ended under the agent (lease, or the owner closed it): its session fell back to the key's
            worked_on = key is not None and self.db.one("SELECT 1 FROM sessions WHERE key_id=? AND task_id=?",
                                                        (key["id"], task_id))
            if not worked_on:
                raise Denied("this session isn't working on that task", "session")
            return self._late_report(task_id, status, str(summary or ""))
        with self.db.tx() as conn:
            cur = conn.execute("UPDATE tasks SET status=?, report=? WHERE id=? AND status='claimed'",
                               (status, str(summary or "")[:4000], task_id))
        if cur.rowcount == 0:
            return self._late_report(task_id, status, str(summary or ""))
        self._push_end(task_id, status, str(summary or ""))
        return {"ok": True}

    LATE_REPORT = "The agent's report, after the task had ended"
    LEASE_REPORT = "No report within"  # how a task the lease ended starts its report (expire_leases)

    def _late_report(self, task_id: int, status: str, summary: str) -> dict:
        """A report that came after the lease ran out or the owner closed the task isn't lost: it goes onto
        the task (once) for the owner to read, and the task keeps the status it ended with."""
        closed = task_id in self._closed_by_owner()
        with self.db.tx() as conn:
            row = conn.execute("SELECT status, report FROM tasks WHERE id=?", (task_id,)).fetchone()
            # only a task Doorman or the owner ended; one the agent reported on keeps that report
            ended_for_it = row is not None and row["status"] not in ("pending", "claimed") and (
                closed or (row["report"] or "").startswith(self.LEASE_REPORT))
            if not ended_for_it or self.LATE_REPORT in (row["report"] or ""):
                raise Denied(f"task #{task_id} isn't open any more and has its report; put what you did in your "
                             "reply to the owner", "task_closed")
            report = f"{row['report'] or ''}\n\n{self.LATE_REPORT} ({status}): {summary}".strip()
            conn.execute("UPDATE tasks SET report=? WHERE id=?", (report[:8000], task_id))
        self._push_end(task_id, status, summary)
        return {"ok": True, "late": True, "task_status": row["status"],
                "note": f"task #{task_id} had already ended ({row['report'] or row['status']}); your report is kept "
                        "on it for the owner, and its status stays as it was"}

    def url(self, task_id: int) -> str:
        return f"{self.engine.public_url}/app/#/task/{task_id}"

    def _push_end(self, task_id: int, status: str, report: str) -> None:
        """The owner hands tasks over from the phone; the push says how it ended and opens the task screen.
        The title starts with what the agent reported, the body says which task it was."""
        task = self.get(task_id) or {"text": ""}
        said = " ".join(report.split()) or " ".join(task["text"].split())
        start = said if len(said) <= 80 else said[:79].rstrip() + "…"
        self.engine.notifier.push(f"{'Done' if status == 'done' else 'Failed'}: {start}",
                           f"Task {task_id}: {task['text'][:300]}", url=self.url(task_id))

    def view(self, task_id: int) -> dict | None:
        """One task as the owner's task screen shows it: its text and where it came from, how it ended, every
        journal entry filed under it (newest first) and the approvals of it that wait for the owner."""
        task = self.get(task_id)
        if task is None:
            return None
        for old in ("plugin_allowlist", "read_only", "auto_apply"):  # columns from before 2026-11-07
            task.pop(old, None)
        task["closed_by_owner"] = task_id in self._closed_by_owner()
        entries = [self.engine.entry_view(e) for e in self.engine.journal.list(task_id=task_id, limit=500)]
        approvals = []
        for row in self.db.all("SELECT id, journal_ids FROM approvals WHERE status='pending' ORDER BY id"):
            ids = loads(row["journal_ids"])
            if any((self.engine.journal.get(i) or {}).get("task_id") == task_id for i in ids):
                approvals.append(self.engine.approvals.get(row["id"]))
        return {"task": task, "entries": entries, "approvals": approvals,
                "revertable": sum(1 for e in entries if e["revertable"] and e["kind"] == "action")}

    def close(self, task_id: int, reason: str | None = None) -> dict:
        """The owner ends a pending or claimed task. The agent keeps running (it is a long-lived agent, not a
        run per task): its next call goes through its own session, no longer filed under the task."""
        with self.db.tx() as conn:
            row = conn.execute("SELECT id, text, status FROM tasks WHERE id=?", (task_id,)).fetchone()
            if row is None or row["status"] not in ("pending", "claimed"):
                raise Denied("no open task with that id", "not_found")
            conn.execute("UPDATE tasks SET status='failed', report=COALESCE(report, ?) WHERE id=?",
                         (reason or "closed by the owner", task_id))
        self.engine.journal.create(kind="config", tool="task.close", tier="irreversible", decision="run", status="done",
                            task_id=task_id, summary=f"Closed task {task_id}: {row['text'][:80]}")
        # a claimed task: the key working on it; a pending one: every key it was for
        self.engine.feed.task_cancelled(task_id, "closed by the owner",
                                 self.engine.feed.keys_for_task(self.get(task_id)) if row["status"] == "pending" else [])
        return {"ok": True}

    def expire_leases(self) -> list[int]:
        """Claimed tasks past their lease fail: the key is free again and the owner gets a push. Covers an
        agent that hangs or forgets to report. The agent itself keeps running. Not while Doorman is paused:
        the agent can't report then, and resume gives the leases their time back."""
        expired = []
        if self.engine.killed():
            return expired
        for row in self.db.all("SELECT id, text FROM tasks WHERE status='claimed' AND lease_until<?", (clock.iso(),)):
            with self.db.tx() as conn:
                cur = conn.execute(
                    "UPDATE tasks SET status='failed', report=? WHERE id=? AND status='claimed'",
                    (f"{self.LEASE_REPORT} {self.engine.config.get('task_lease_minutes', 30)} minutes; Doorman ended it.",
                     row["id"]))
            if cur.rowcount == 0:
                continue
            self.engine.feed.task_cancelled(row["id"], "the lease ran out")
            # the same push as a failed report gets, through Needs attention: it opens the task screen
            self.engine.attention("task_unreported", row["id"], f"Task #{row['id']} ran out of time", row["text"][:200],
                           url=self.url(row["id"]))
            expired.append(row["id"])
        return expired

    def remind(self, session: dict, when: str, text: str) -> int:
        try:
            if not isinstance(when, str):
                raise ValueError(when)
            due = clock.iso(clock.parse(when))
        except (TypeError, ValueError):
            raise Denied("when must be an ISO date-time, e.g. 2026-11-07T09:00:00+01:00", "invalid") from None
        if not isinstance(text, str) or not text.strip():
            raise Denied("a reminder needs text", "invalid")
        return self.create(text, origin="agent", trusted=False, due=due, key_id=session["key_id"])
