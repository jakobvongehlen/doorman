"""Approved sends run here, off the owner's request, and sends whose outcome is unknown get checked.

Approving records the decision and the entries become `approved` in one transaction; a thread of its own
then runs the approval's entries one after another (`Run`). The approve call waits for that run up to
`send_wait_seconds` (3 by default): a mail is usually out by then and the app says "Sent" as before,
while a 20-minute file upload answers "sending" at once instead of running into a reverse proxy's
timeout. The app then follows `GET /owner/approvals/<id>/results`, which holds on until the run ends.

At most once, as before: an entry is claimed (`approved` -> `sending`, engine.execute_entry) right before
it runs. What a crash leaves behind:
- `approved`: never claimed, so nothing went out. The worker starts it again (`resume`), unless the
  approval is older than `approval_ttl_hours`; then it is cancelled and the owner told.
- `sending`: claimed, maybe out. The next start makes it `unknown` (engine.recover_interrupted), never a
  second try.

An `unknown` send whose tool can check (`Tool.verify_sent`: mail looks for its Message-ID, a file
transfer for its upload) is asked again VERIFY_AFTER_MINUTES after it broke off. "sent" makes it done,
"failed" failed; either goes into the journal, to the agent (`send_result` once more) and to the owner
(a push). After the last try it stays unknown, for the owner to check.
"""

from __future__ import annotations

import logging
import threading
from datetime import timedelta
from typing import Any

from . import clock
from .util import loads

log = logging.getLogger("doorman.sends")

WAIT_SECONDS = 3.0                      # the approve call's wait for the result before it says "sending"
VERIFY_AFTER_MINUTES = (1, 5, 15, 30)   # when an unknown send is checked, counted from when it broke off
CHECK_EVERY_SECONDS = 15                # how often the worker looks for sends to resume or check
PENDING = ("sending", "running")        # results still under way (an `approved` entry shows as one of them)


class Run:
    """One approval's entries, run in order in one thread. `results` fills in as they end; `done` is set
    when the last one did."""

    def __init__(self, approval_id: int, entry_ids: list[int]):
        self.approval_id = approval_id
        self.entry_ids = entry_ids
        self.results: dict[int, dict] = {}
        self.done = threading.Event()
        self.lock = threading.Lock()
        self.tell_owner = False  # push the outcome when it ends: Accept on a push answered "sending"


class Sends:
    def __init__(self, engine):
        self.engine = engine
        self.db = engine.db
        self._runs: dict[int, Run] = {}  # approval id -> its run, while it runs
        self._lock = threading.Lock()
        self._checked = 0.0
        self._verifying = threading.Lock()

    # ------------------------------------------------------------------ running approved sends

    def start(self, approval_id: int, entry_ids: list[int]) -> Run:
        """Run an approval's entries in a thread of their own; the run already under way if there is one."""
        with self._lock:
            run = self._runs.get(approval_id)
            if run is not None:
                return run
            run = self._runs[approval_id] = Run(approval_id, list(entry_ids))
        threading.Thread(target=self._run, args=(run,), name=f"send-{approval_id}", daemon=True).start()
        return run

    def _run(self, run: Run) -> None:
        try:
            for entry_id in run.entry_ids:
                try:
                    result = self.engine.execute_entry(entry_id, approval_id=run.approval_id)
                except Exception as exc:  # noqa: BLE001 - Doorman's own failure: settle it, never retry
                    log.exception("running entry %s", entry_id)
                    result = self._broke_off(entry_id, f"{type(exc).__name__}: {exc}")
                if result.get("again"):  # another run got there first, and tells the agent itself
                    run.results[entry_id] = result_of(self.engine.journal.get(entry_id), entry_id)
                    continue
                run.results[entry_id] = result
                try:
                    self.engine.feed.send_result(entry_id, result, run.approval_id)
                except Exception:  # noqa: BLE001 - the next entry of the approval still runs
                    log.exception("telling the agent about entry %s", entry_id)
        finally:
            with self._lock:
                self._runs.pop(run.approval_id, None)
            with run.lock:
                run.done.set()
                tell = run.tell_owner
            self.engine.feed.bell.ring()  # an owner app waiting for the results wakes up
            if tell:
                self._tell_owner(run)

    def _broke_off(self, entry_id: int, error: str) -> dict:
        """Doorman itself failed around a send (not the plugin, which execute_entry catches). Not claimed yet:
        nothing went out. Claimed: it may have, so unknown, as after a crash."""
        entry = self.engine.journal.get(entry_id)
        if entry is None:
            return {"entry_id": entry_id, "status": "missing", "error": error}
        if self.engine.journal.transition(entry_id, ("approved",), "failed"):
            self.engine.journal.update(entry_id, error=f"not run: {error}")
            return {"entry_id": entry_id, "status": "failed", "error": error}
        if entry["status"] == "sending":
            return self.engine._mark_unknown(entry_id, error)
        if entry["status"] == "running":
            self.engine.journal.update(entry_id, status="failed", error=error)
            return {"entry_id": entry_id, "status": "failed", "error": error}
        return result_of(entry)

    def wait(self, run: Run, seconds: float) -> list[dict]:
        """The run's results after at most `seconds`: what ended, and "sending" for the rest."""
        run.done.wait(max(0.0, seconds))
        return [run.results.get(i) or result_of(self.engine.journal.get(i), i) for i in run.entry_ids]

    def tell_owner_when_done(self, run: Run) -> None:
        """Accept on a push got "sending": the outcome comes as a push of its own when the run ends."""
        with run.lock:
            if not run.done.is_set():
                run.tell_owner = True
                return
        self._tell_owner(run)

    def _tell_owner(self, run: Run) -> None:
        """One push under the approval's tag, so it replaces the "Sending" line Accept left on the phone (and
        any failure's own push, which the inbox's Needs attention keeps)."""
        results = [run.results.get(i) or result_of(self.engine.journal.get(i), i) for i in run.entry_ids]
        entries = [self.engine.journal.get(i) for i in run.entry_ids]
        summary = "\n".join(e["summary"] for e in entries if e)[:500]
        sent = sum(r["status"] == "done" for r in results)
        unknown = sum(r["status"] == "unknown" for r in results)
        if sent == len(results):
            title = "Sent" if len(results) == 1 else f"All {len(results)} sent"
        elif unknown and sent + unknown == len(results):
            title = "Maybe not sent: check whether it went out"
        else:
            title = "Not sent" if not sent else f"{sent} of {len(results)} sent"
        self.engine.notifier.push(title, summary, url=f"{self.engine.public_url}/app/#/journal",
                                  priority=3 if sent == len(results) else 4,
                                  extra={"tag": f"approval-{run.approval_id}"})

    def view(self, approval_id: int) -> dict | None:
        """GET /owner/approvals/<id>/results: each entry's result, and whether all of them ended."""
        row = self.db.one("SELECT id, status, journal_ids FROM approvals WHERE id=?", (approval_id,))
        if row is None:
            return None
        ids = loads(row["journal_ids"], [])
        with self._lock:
            run = self._runs.get(approval_id)
        results = [(run.results.get(i) if run else None) or result_of(self.engine.journal.get(i), i) for i in ids]
        return {"approval_id": approval_id, "status": row["status"], "results": results,
                "done": not any(r["status"] in PENDING for r in results)}

    def running(self, approval_id: int) -> bool:
        with self._lock:
            return approval_id in self._runs

    # ------------------------------------------------------------------ the worker's part

    def tick(self, force: bool = False) -> None:
        """From the worker: approved sends nobody runs (after a restart), and unknown sends due a check."""
        now = clock.now().timestamp()
        if not force and now - self._checked < CHECK_EVERY_SECONDS:
            return
        self._checked = now
        self.resume()
        self.verify_due()

    def resume(self) -> list[int]:
        """Approved entries no run holds: Doorman stopped between the approval and the claim, so nothing of
        them went out. They run now, unless the approval is older than an approval lasts: a message meant
        for a day ago shouldn't go out today without the owner seeing it again."""
        started = []
        approvals: dict[int, dict] = {}
        for row in self.db.all("SELECT id FROM journal WHERE status='approved' AND kind='action'"):
            approval = approval_of(self.db, row["id"])
            if approval is None:  # approved without an approval: can't be, so never send it
                if self.engine.journal.transition(row["id"], ("approved",), "cancelled"):
                    self.engine.journal.update(row["id"], error="not run: no approval for it")
                continue
            approvals[approval["id"]] = approval
        ttl = timedelta(hours=float(self.engine.config.get("approval_ttl_hours", 24)))
        for approval_id, approval in approvals.items():
            if self.running(approval_id):
                continue
            ids = loads(approval["journal_ids"], [])
            if approval["decided"] and clock.parse(approval["decided"]) < clock.now() - ttl:
                self._too_late(approval_id, ids)
                continue
            log.warning("approval %s was decided but not run (Doorman stopped): running it now", approval_id)
            self.start(approval_id, ids)
            started.append(approval_id)
        return started

    def _too_late(self, approval_id: int, entry_ids: list[int]) -> None:
        for entry_id in entry_ids:
            if not self.engine.journal.transition(entry_id, ("approved",), "cancelled"):
                continue
            error = ("not sent: Doorman stopped right after you approved it and was back only after the approval "
                     "would have expired. Nothing went out; ask the agent again if it's still wanted")
            self.engine.journal.update(entry_id, error=error)
            entry = self.engine.journal.get(entry_id)
            self.engine.feed.send_result(entry_id, {"status": "cancelled", "error": error}, approval_id)
            self.engine.attention("send_failed", entry_id, "An approved send didn't go out",
                                  f"{entry['summary']}\n{error}", url=f"{self.engine.public_url}/app/#/journal")

    # ------------------------------------------------------------------ checking unknown sends

    def verify_due(self, background: bool = True) -> list[int]:
        """Unknown sends whose next check is due, checked in a thread (one round at a time): asking a mail
        server or starting a plugin's browser mustn't hold up the worker's tick."""
        due = []
        for row in self.db.all("SELECT id, result FROM journal WHERE status='unknown' AND kind='action'"):
            check = verify_state(loads(row["result"]))
            if check is None or check["tries"] >= len(VERIFY_AFTER_MINUTES):
                continue
            if clock.now() >= clock.parse(check["since"]) + timedelta(minutes=VERIFY_AFTER_MINUTES[check["tries"]]):
                due.append(row["id"])
        if not due:
            return due

        def round_() -> None:
            for entry_id in due:
                try:
                    self.verify(entry_id)
                except Exception:  # noqa: BLE001 - one broken check mustn't stop the others
                    log.exception("checking entry %s", entry_id)
        if not background:
            round_()
            return due
        if not self._verifying.acquire(blocking=False):
            return []  # the last round is still at it

        def in_thread() -> None:
            try:
                round_()
            finally:
                self._verifying.release()
        threading.Thread(target=in_thread, name="verify-sends", daemon=True).start()
        return due

    def verify(self, entry_id: int) -> str:
        """Ask the send's tool once whether it went out; settle the entry on a clear answer. Returns the
        answer ("sent", "failed" or "unknown")."""
        entry = self.engine.journal.get(entry_id)
        check = verify_state(entry["result"]) if entry and entry["status"] == "unknown" else None
        if check is None:
            return entry["status"] if entry else "missing"
        tool = self.engine._tool_object(entry)
        tries = check["tries"] + 1
        if tool is None or not tool.can_verify():  # the plugin is gone, or changed since: leave it to the owner
            self.engine.journal.update(entry_id, result={**entry["result"], "verify": {
                **check, "tries": len(VERIFY_AFTER_MINUTES), "detail": "this send can't be checked any more"}})
            return "unknown"
        try:
            answer = tool.verify_sent(entry["args"] or {}, entry["before"], check.get("error") or entry["error"] or "")
        except Exception as exc:  # noqa: BLE001 - a check that fails says nothing either way
            log.warning("checking entry %s: %s", entry_id, exc)
            answer = {"status": "unknown", "detail": f"the check failed: {exc}"}
        status, detail, result = _answer(answer)
        if status == "sent":
            self._went_out(entry, detail, result)
        elif status == "failed":
            self._did_not(entry, check, detail)
        else:
            self._note(entry, {**check, "tries": tries, "last": clock.iso(), "detail": detail})
        return status

    def _note(self, entry: dict, check: dict) -> None:
        fields: dict[str, Any] = {"result": {**(entry["result"] or {}), "verify": check}}
        if check["tries"] >= len(VERIFY_AFTER_MINUTES):
            fields["error"] = (f"{check.get('error') or 'it broke off'}. Doorman checked {check['tries']} times "
                               f"over {VERIFY_AFTER_MINUTES[-1]} minutes and couldn't tell whether it went out: "
                               "check before doing it again.")
        self.engine.journal.update(entry["id"], **fields)

    def _went_out(self, entry: dict, detail: str | None, result: dict | None) -> None:
        if not self.engine.journal.transition(entry["id"], ("unknown",), "done"):
            return
        detail = detail or "Doorman checked: it went out"
        self.engine.journal.update(entry["id"], error=None, result={**(result or {}), "verified": detail})
        self.engine.resolve_attention("send_unknown", entry["id"])
        approval = approval_of(self.db, entry["id"])
        self.engine.feed.send_result(entry["id"], {"status": "done"}, approval["id"] if approval else None)
        self.engine.notifier.push("It went out after all", f"{entry['summary']}\n{detail}"[:500],
                                  url=f"{self.engine.public_url}/app/#/journal", priority=3,
                                  extra={"tag": f"approval-{approval['id']}"} if approval else None)

    def _did_not(self, entry: dict, check: dict, detail: str | None) -> None:
        if not self.engine.journal.transition(entry["id"], ("unknown",), "failed"):
            return
        error = f"{check.get('error') or 'it broke off'}. Doorman checked: {detail or 'it did not go out'}. Nothing went out."
        self.engine.journal.update(entry["id"], error=error, result={**(entry["result"] or {}), "verify": {
            **check, "tries": check["tries"] + 1, "last": clock.iso(), "detail": detail}})
        self.engine.resolve_attention("send_unknown", entry["id"])
        approval = approval_of(self.db, entry["id"])
        self.engine.feed.send_result(entry["id"], {"status": "failed", "error": error},
                                     approval["id"] if approval else None)
        self.engine.attention("send_failed", entry["id"], "It didn't go out after all", f"{entry['summary']}\n{error}",
                              url=f"{self.engine.public_url}/app/#/journal",
                              tag=f"approval-{approval['id']}" if approval else None)


def result_of(entry: dict | None, entry_id: int | None = None) -> dict:
    """An entry's state in the words of decide's results: an approved entry not yet claimed is "sending"
    (or "running", for an undoable write the owner asked to see first)."""
    if entry is None:
        return {"entry_id": entry_id, "status": "missing"}
    status = entry["status"]
    if status == "approved":
        status = "running" if entry["tier"] == "reversible" else "sending"
    out = {"entry_id": entry["id"], "status": status}
    if entry.get("error"):
        out["error"] = entry["error"]
    if status == "done" and entry.get("result") is not None:
        out["result"] = entry["result"]
    if checking(entry):
        out["checking"] = True
    return out


def approval_of(db, entry_id: int) -> dict | None:
    """The approved approval an entry went out under."""
    return db.one("SELECT a.id, a.journal_ids, a.decided FROM approvals a, json_each(a.journal_ids) j "
                  "WHERE j.value=? AND a.status='approved' ORDER BY a.id DESC LIMIT 1", (entry_id,))


def verify_state(result: Any) -> dict | None:
    check = result.get("verify") if isinstance(result, dict) else None
    return check if isinstance(check, dict) and check.get("since") else None


def checking(entry: dict) -> bool:
    """An unknown send Doorman still checks on its own."""
    check = verify_state(entry.get("result")) if entry.get("status") == "unknown" else None
    return bool(check and check.get("tries", 0) < len(VERIFY_AFTER_MINUTES))


def _answer(answer: Any) -> tuple[str, str | None, dict | None]:
    if isinstance(answer, dict):
        status, detail, result = answer.get("status"), answer.get("detail"), answer.get("result")
    else:
        status, detail, result = answer, None, None
    if status not in ("sent", "failed", "unknown"):
        status = "unknown"
    return status, (str(detail)[:300] if detail else None), (result if isinstance(result, dict) else None)
