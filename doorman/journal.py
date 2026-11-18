"""Append-only, hash-chained log of everything that happens.

Each entry's hash covers the request (who, what tool, which arguments) and the
previous entry's hash, like commits. Status and results are filled in as the
action progresses; they are not part of the chain.
"""

from __future__ import annotations

from typing import Any

from . import clock
from .util import canonical, dumps, loads, sha256_hex

JSON_FIELDS = ("args", "checks", "before", "after", "result")
HASHED_FIELDS = ("id", "ts", "kind", "session_id", "task_id", "plugin", "tool", "args", "tier", "reverts")
COLUMNS = ("ts", "kind", "session_id", "task_id", "changeset_id", "plugin", "tool", "args", "tier",
           "decision", "checks", "status", "object_ref", "before", "after", "result", "error",
           "summary", "reverts", "reverted_by")


class Journal:
    def __init__(self, db):
        self.db = db
        self.on_config = None  # called after each config entry: the engine's feed checks the capabilities next

    @staticmethod
    def _entry_hash(row: dict, parent_hash: str) -> str:
        core = {field: row.get(field) for field in HASHED_FIELDS}
        return sha256_hex(parent_hash + canonical(core))

    def create(self, **fields: Any) -> int:
        fields.setdefault("ts", clock.iso())
        row = {column: fields.get(column) for column in COLUMNS}
        for field in JSON_FIELDS:
            row[field] = dumps(row[field])
        with self.db.tx() as conn:
            last = conn.execute("SELECT hash FROM journal ORDER BY id DESC LIMIT 1").fetchone()
            parent = last["hash"] if last else ""
            cur = conn.execute(
                f"INSERT INTO journal({', '.join(COLUMNS)}, parent_hash) VALUES({', '.join('?' * len(COLUMNS))}, ?)",
                (*[row[c] for c in COLUMNS], parent),
            )
            entry_id = cur.lastrowid
            row["id"] = entry_id
            conn.execute("UPDATE journal SET hash=? WHERE id=?", (self._entry_hash(row, parent), entry_id))
        if row["kind"] == "config" and self.on_config:
            self.on_config()
        return entry_id

    def update(self, entry_id: int, **fields: Any) -> None:
        if not fields:
            return
        values = []
        for key, value in fields.items():
            if key not in COLUMNS or key in ("ts", "kind", "session_id", "task_id", "plugin", "tool", "args", "tier", "reverts"):
                raise ValueError(f"journal field {key} can't be changed")
            values.append(dumps(value) if key in JSON_FIELDS else value)
        sets = ", ".join(f"{key}=?" for key in fields)
        self.db.exec(f"UPDATE journal SET {sets} WHERE id=?", (*values, entry_id))

    def transition(self, entry_id: int, expected: tuple[str, ...], status: str) -> bool:
        """Set status only if it is still one of `expected`; False if someone else got there first."""
        with self.db.tx() as conn:
            cur = conn.execute(f"UPDATE journal SET status=? WHERE id=? AND status IN ({','.join('?' * len(expected))})",
                               (status, entry_id, *expected))
            return cur.rowcount == 1

    @staticmethod
    def _decode(row: dict | None) -> dict | None:
        if row is None:
            return None
        for field in JSON_FIELDS:
            row[field] = loads(row[field])
        return row

    def get(self, entry_id: int) -> dict | None:
        return self._decode(self.db.one("SELECT * FROM journal WHERE id=?", (entry_id,)))

    def list(self, *, task_id: int | None = None, since: str | None = None, session_id: str | None = None,
             include_denied: bool = False, kinds: tuple[str, ...] | None = None, limit: int = 200,
             status: tuple[str, ...] | None = None, before: int | None = None) -> list[dict]:
        """Newest first. `before` pages back: only entries older than that id (the app's "Show older")."""
        sql, params = ["SELECT * FROM journal WHERE 1=1"], []
        if before is not None:
            sql.append("AND id<?")
            params.append(before)
        if task_id is not None:
            sql.append("AND task_id=?")
            params.append(task_id)
        if since:
            sql.append("AND ts>=?")
            params.append(since)
        if session_id:
            sql.append("AND session_id=?")
            params.append(session_id)
        if not include_denied:
            sql.append("AND status!='denied'")
        if kinds:
            sql.append(f"AND kind IN ({','.join('?' * len(kinds))})")
            params.extend(kinds)
        if status:
            sql.append(f"AND status IN ({','.join('?' * len(status))})")
            params.extend(status)
        sql.append("ORDER BY id DESC LIMIT ?")
        params.append(limit)
        return [self._decode(row) for row in self.db.all(" ".join(sql), tuple(params))]

    def dependents(self, entry: dict) -> list[dict]:
        """Later, still-applied actions that touched the same object.

        Revert entries don't count: they only undo something that happened later, which
        brings the object back towards this entry's state rather than building on it.
        """
        if not entry.get("object_ref"):
            return []
        rows = self.db.all(
            "SELECT * FROM journal WHERE plugin=? AND object_ref=? AND id>? AND status='done' "
            "AND kind='action' ORDER BY id DESC",
            (entry["plugin"], entry["object_ref"], entry["id"]),
        )
        return [self._decode(row) for row in rows]

    def verify(self) -> tuple[bool, int | None]:
        parent = ""
        for row in self.db.all("SELECT * FROM journal ORDER BY id"):
            if row["parent_hash"] != parent or row["hash"] != self._entry_hash(row, parent):
                return False, row["id"]
            parent = row["hash"]
        return True, None
