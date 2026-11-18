"""Who read what: one row per agent read, next to the journal rather than in it.

The journal holds changes, each with a diff, a way back and a hash chain. A read changes nothing, and an
agent makes dozens of them per task, so reads get this lighter log instead: who (agent key, session,
task), which read with which parameters, how many items came back, and a short label for each item
(its subject, title or name) so the owner can tell what was seen. Not hash-chained; rows older than
`read_log_days` (default 90) are pruned.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from . import clock
from .util import dumps, loads

log = logging.getLogger("doorman.readlog")

MAX_ITEMS = 30          # item labels kept per read
LABEL_CHARS = 90
PARAM_CHARS = 200
LABEL_KEYS = ("subject", "title", "summary", "name", "topic", "filename", "path", "text", "body")


def _short(value: Any, n: int) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= n else text[: n - 1] + "…"


def _item(value: Any) -> dict:
    if not isinstance(value, dict):
        return {"label": _short(value, LABEL_CHARS)}
    label = next((value[k] for k in LABEL_KEYS if isinstance(value.get(k), str) and value[k].strip()), None)
    who = value.get("from")
    if isinstance(who, list):
        who = who[0] if who else None
    out = {"ref": value.get("ref") or value.get("id")}
    if label:
        out["label"] = _short(label, LABEL_CHARS)
    if isinstance(who, str) and who:
        out["from"] = _short(who, 60)
    when = value.get("date") or value.get("start") or value.get("sent") or value.get("created")
    if isinstance(when, str):
        out["when"] = when[:16]
    if value.get("quarantined") is True:  # held back by the guard: the agent got only the id
        out["quarantined"] = True
    return {k: (str(v) if k == "ref" and v is not None else v) for k, v in out.items() if v is not None}


def summarize(data: Any) -> tuple[int, list[dict]]:
    """(how many items, labels for the first MAX_ITEMS)."""
    if isinstance(data, list):
        return len(data), [_item(x) for x in data[:MAX_ITEMS]]
    if isinstance(data, dict):
        for key in ("items", "events", "results", "value"):  # a page wrapper around the list
            if isinstance(data.get(key), list):
                return summarize(data[key])
        return 1, [_item(data)]
    return (0, []) if data is None else (1, [_item(data)])


class ReadLog:
    def __init__(self, db, on_read: Callable[[dict, dict, str, Any], None] | None = None):
        """`on_read(key, session, name, data)`: called after each read that returned data, with what came
        back (the network watch fingerprints it, egress/service.py). It must be quick and must not raise
        into the read: a failure there is logged, the read goes on."""
        self.db = db
        self.on_read = on_read

    def add(self, key: dict, session: dict, name: str, params: dict, data: Any = None,
            status: str = "ok", error: str | None = None, trust: str | None = None,
            hidden: list[int] | None = None) -> None:
        """`hidden`: indices of the items the agent only got as placeholders (marked for the owner)."""
        count, items = summarize(data) if status in ("ok", "unscanned") else (0, [])
        for i in hidden or []:
            if i < len(items):
                items[i]["hidden"] = True
        self.db.exec(
            "INSERT INTO reads(ts, key_id, key_name, session_id, task_id, name, params, trust, items, labels, "
            "status, error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (clock.iso(), key.get("id"), key.get("name"), session.get("id"), session.get("task_id"), name,
             dumps({k: _short(v, PARAM_CHARS) if isinstance(v, str) else v for k, v in (params or {}).items()}),
             trust, count, dumps(items), status, _short(error, 300) if error else None))
        if self.on_read is not None and status in ("ok", "unscanned") and data is not None:
            try:
                self.on_read(key, session, name, data)
            except Exception:  # noqa: BLE001 - the read itself worked; the agent gets it either way
                log.exception("on_read for %s", name)

    def list(self, task_id: int | None = None, key_id: int | None = None, before: int | None = None,
             limit: int = 100) -> list[dict]:
        sql, args = "SELECT * FROM reads WHERE 1=1", []
        for column, value in (("task_id", task_id), ("key_id", key_id)):
            if value is not None:
                sql += f" AND {column}=?"
                args.append(value)
        if before is not None:
            sql += " AND id<?"
            args.append(before)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(int(limit), 500)))
        return [{**row, "params": loads(row["params"], {}), "labels": loads(row["labels"], [])}
                for row in self.db.all(sql, tuple(args))]

    def count_since(self, since: str) -> int:
        row = self.db.one("SELECT COUNT(*) AS n FROM reads WHERE ts>=?", (since,))
        return int(row["n"]) if row else 0

    def prune(self, days: float) -> None:
        if days and days > 0:
            self.db.exec("DELETE FROM reads WHERE ts<?", (clock.iso(clock.now() - timedelta(days=days)),))
