"""How long doorman.db keeps what grows with use, and an occasional VACUUM. The worker runs this hourly.

`retention:` in doorman.yaml, each in days (0 keeps everything of that kind):

- scans_days: the injection guard's score per text. A text read again later is scanned again.
- quarantine_days: held-back items you decided (released or kept), counted from the decision. Undecided ones
  stay until you decide. A text read again after that is scanned again and, if it still scores high, held
  back again, as new.
- provenance_days: where each address an agent saw came from. After that a new recipient still gets its
  warning, just without "first seen in".
- notifications_days, attention_days (resolved Needs attention items), records_days (the mail reader's
  records).

Always: owner sessions that expired, passkey prompts nobody answered, push endpoints a service dropped over
30 days ago, devices that logged out over a year ago. Elsewhere: the read log (read_log_days), the event feed (events_days), uploads (uploads.keep_days),
and the network watch (egress/service.py sweep): fingerprints of reads after egress.match_hours, the proxy's
log, tool calls, agent addresses and decided access requests after egress.log_days.

Kept on purpose: the journal and what hangs off it (approvals, changesets, tasks, agent sessions), which is
your history and what undo works from; and `pseudonyms`. A placeholder can sit in a long-lived agent's
memory or notes for months, and a reversible write that carries it gets the real text back from that table.
Its rows are small, one per distinct private text an agent was shown, and HMAC-derived, so a pruned row would
come back unchanged the next time the same text is read, but a write from memory before that would put the
placeholder itself into your calendar.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from . import clock

log = logging.getLogger("doorman.retention")

DEFAULTS = {"scans_days": 180, "quarantine_days": 365, "provenance_days": 90, "notifications_days": 90,
            "attention_days": 90, "records_days": 365, "vacuum_days": 7}
VACUUM_FREE_SHARE = 0.25          # VACUUM when at least this share of the file is free pages
VACUUM_MIN_FREE = 8 * 1024 * 1024  # and at least this many bytes


def _before(days: float) -> str:
    return clock.iso(clock.now() - timedelta(days=days))


def prune(db, settings: dict | None = None) -> dict[str, int]:
    """Deletes what's past its time. Returns the number of rows per table."""
    days = {**DEFAULTS, **(settings or {})}
    steps: list[tuple[str, str, tuple]] = [
        ("owner_sessions", "DELETE FROM owner_sessions WHERE expires<=?", (clock.iso(),)),
        ("challenges", "DELETE FROM challenges WHERE created<?", (_before(1),)),
        ("push_gone", "DELETE FROM push_gone WHERE ts<?", (_before(30),)),
        # a device that logged out a year ago and logs in again is announced as a new one
        ("push_logged_out", "DELETE FROM push_logged_out WHERE ts<?", (_before(365),)),
    ]
    by_age = {"scans": ("scans_days", "DELETE FROM scans WHERE ts<?"),
              "quarantine": ("quarantine_days", "DELETE FROM quarantine WHERE status IN ('released', 'kept') "
                                                "AND coalesce(decided, created)<?"),
              "provenance": ("provenance_days", "DELETE FROM provenance WHERE ts<?"),
              "notifications": ("notifications_days", "DELETE FROM notifications WHERE ts<?"),
              "attention": ("attention_days", "DELETE FROM attention WHERE resolved IS NOT NULL AND resolved<?"),
              "records": ("records_days", "DELETE FROM records WHERE created<?")}
    for table, (key, sql) in by_age.items():
        if float(days.get(key) or 0) > 0:
            steps.append((table, sql, (_before(float(days[key])),)))
    counts = {}
    for table, sql, params in steps:
        with db.tx() as conn:
            counts[table] = conn.execute(sql, params).rowcount
    return {table: n for table, n in counts.items() if n}


def maybe_vacuum(db, every_days: float) -> bool:
    """VACUUM at most every `every_days`, and only when enough of the file is free pages (after pruning, or
    after a big delete). It rewrites the file and holds the write lock while it runs: a few seconds for a
    database of a few hundred MB."""
    if every_days <= 0 or db.path == ":memory:":
        return False
    last = db.get_setting("last_vacuum")
    if last and last > _before(every_days):
        return False
    with db.lock:
        pages = db.conn.execute("PRAGMA page_count").fetchone()[0]
        free = db.conn.execute("PRAGMA freelist_count").fetchone()[0]
        size = db.conn.execute("PRAGMA page_size").fetchone()[0]
        if not pages or free < pages * VACUUM_FREE_SHARE or free * size < VACUUM_MIN_FREE:
            db.set_setting("last_vacuum", clock.iso())  # looked: nothing to win until the next round
            return False
        db.conn.execute("VACUUM")
        db.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.set_setting("last_vacuum", clock.iso())
    log.info("vacuumed doorman.db: %d of %d pages were free", free, pages)
    return True
