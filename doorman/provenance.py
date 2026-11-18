"""Remembers where every destination-like value served to an agent came from."""

from typing import Any

from . import clock
from .util import extract_destinations, walk_strings


class Provenance:
    def __init__(self, db):
        self.db = db

    def record(self, session_id: str, data: Any, default_origin: str, trust: str) -> None:
        items = data if isinstance(data, list) else [data]
        seen: set[tuple[str, str]] = set()
        rows = []
        for item in items:
            origin = item.get("ref", default_origin) if isinstance(item, dict) else default_origin
            for text in walk_strings(item):
                for kind, value in extract_destinations(text):
                    if (value, origin) in seen:
                        continue
                    seen.add((value, origin))
                    rows.append((session_id, kind, value, origin, trust, clock.iso()))
        if rows:
            with self.db.tx() as conn:
                conn.executemany(
                    "INSERT INTO provenance(session_id, kind, value, origin, trust, ts) VALUES(?,?,?,?,?,?)", rows
                )

    def origin_of(self, value: str) -> dict | None:
        """First place a value showed up, preferring third-party sources."""
        return self.db.one(
            "SELECT origin, trust, ts, session_id FROM provenance WHERE value=? "
            "ORDER BY CASE trust WHEN 'third_party' THEN 0 ELSE 1 END, id LIMIT 1",
            (value,),
        )
