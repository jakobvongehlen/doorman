"""Doorman's one search index over everything the plugins keep: mail archives, files, notes, calendars,
chats. The single place `doorman search` looks.

Plugins don't search; they feed. A plugin whose manifest has an `index:` block hands over its new and
changed items when Doorman asks (`index_feed(cursor, budget)`, see plugin_api.BasePlugin), and Doorman keeps
them here, keyed by the plugin instance (the source) and the plugin's own key:

    {"key": "<message-id>", "kind": "mail", "title": "Ihre Kaution", "date": "2026-03-02T09:14:00+00:00",
     "from": "Hausverwaltung <verwaltung@haus.example>", "to": "...", "in": "INBOX", "has_attachment": true,
     "parts": [{"part": 0, "text": "<the body>"},
               {"part": 2, "name": "abrechnung.pdf", "text": "...", "unchecked": true}],  # see PART_FLAGS
     "same": "mid:<message-id>",            # copies elsewhere share it (the same mail in two mailboxes)
     "refs": ["<ref>", ...],                # what it's made of (a chat's day: its messages), for guard holds
     "fields": {"subject": "...", "folder": "INBOX", "unread": true, ...}}   # shown with a hit as they are

An item's parts (a mail's body and attachments; a file, a note, an event have one) are searched each on its
own: whole words (the title counts more), word stems in German, Dutch and English, parts of words and close
spellings when those find little, and, when the owner switched semantic search on, meaning, each part in
chunks of ~800 characters with a vector each (textsearch.chunks). One ranking over all of it: one word
statistic, one vector store, one embedding of the query. A hit is an item, its passage the chunk of its best
part. Two hits with the same text (a PDF attached to a mail and saved in the files) come once, with the other
place under `also` (engine.once); items that share `same` only when they read the same too. One search does a
bounded amount of work (textsearch.MAX_TERMS, PASSAGE_CHARS).

This is a cache of what the plugins keep: it isn't backed up, and `rebuild` feeds everything again. What an
agent may see of it is decided per hit in engine.search.query, by the source's switches and its reads per kind and
attachment (`scope`), the actor rule, the guard, pseudonyms and the read log, as if the agent had read the
item from its plugin. When a source's settings change (settle), its items wait until it has fed them again.

Being a cache, it is never migrated or repaired, only made anew from the feeds:
- an index.db of another layout (INDEX_VERSION) is deleted at start; a damaged one is set aside as
  index.db.damaged, at start, when a search or a feed runs into the damage, or when the first upkeep round's
  full check (`check`) finds it. Every source then feeds again from the start.
- the vectors are what's slow to make again (a big archive takes the model hours), so they are also kept in
  vectors.db by model and chunk text: a text read once is never read again, whatever happens to index.db.
  It keeps what no part uses any more until the index has settled (SETTLE_DAYS).
- a feed asked from the start (a new or rebuilt index, a plugin that says `reset`) is a pass over everything
  the source has: what the pass didn't bring goes when it's through, so nothing outlives a rebuild that the
  plugin no longer has, whether or not it remembered the deletion.
- an item the index can't take (an unknown kind, a broken part) is skipped and counted on the feed; the rest
  of the feed goes on.
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Iterable

from . import clock, textsearch

log = logging.getLogger("doorman.library")

# The layout of index.db. Bump it with any change to SCHEMA, the tokenizers, textsearch's stems, or what goes
# into an item's title, people and body: an index of another version is deleted at start and every source
# feeds again (the vectors come back from vectors.db, not from the model).
INDEX_VERSION = 4
STORE_VERSION = 1         # the layout of vectors.db
SETTLE_DAYS = 7           # vectors.db keeps vectors no part uses until the index is this old, fed and read through

SCHEMA = """
CREATE TABLE IF NOT EXISTS items(
    id INTEGER PRIMARY KEY, source TEXT NOT NULL, key TEXT NOT NULL, ref TEXT NOT NULL, kind TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '', date TEXT, sender TEXT, recipients TEXT, place TEXT,
    has_attachment INTEGER NOT NULL DEFAULT 0, same TEXT, refs TEXT, fields TEXT, hash TEXT,
    seen INTEGER NOT NULL DEFAULT 0, UNIQUE(source, key));
CREATE INDEX IF NOT EXISTS items_date ON items(date);
CREATE INDEX IF NOT EXISTS items_source ON items(source, kind);
CREATE TABLE IF NOT EXISTS parts(
    id INTEGER PRIMARY KEY, item INTEGER NOT NULL, part INTEGER NOT NULL, name TEXT, text TEXT NOT NULL DEFAULT '',
    text_hash TEXT, same TEXT, flags TEXT, stemmed INTEGER NOT NULL DEFAULT 0, embedded INTEGER NOT NULL DEFAULT 0,
    UNIQUE(item, part));
CREATE INDEX IF NOT EXISTS parts_embedded ON parts(embedded);
CREATE INDEX IF NOT EXISTS parts_stemmed ON parts(stemmed);
CREATE VIRTUAL TABLE IF NOT EXISTS words USING fts5(title, people, body, content='', contentless_delete=1,
    tokenize='unicode61 remove_diacritics 2');
CREATE VIRTUAL TABLE IF NOT EXISTS stems USING fts5(title, people, body, content='', contentless_delete=1,
    tokenize='unicode61 remove_diacritics 2');
CREATE VIRTUAL TABLE IF NOT EXISTS grams USING fts5(title, people, body, content='', contentless_delete=1,
    tokenize='trigram remove_diacritics 1');
CREATE TABLE IF NOT EXISTS vectors(id INTEGER PRIMARY KEY, part INTEGER NOT NULL, chunk INTEGER NOT NULL,
    vec BLOB NOT NULL, hash TEXT NOT NULL, chars INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS vectors_part ON vectors(part);
CREATE INDEX IF NOT EXISTS vectors_hash ON vectors(hash);
CREATE TABLE IF NOT EXISTS feeds(source TEXT PRIMARY KEY, cursor TEXT, pulled TEXT, error TEXT, items INTEGER,
    complete INTEGER, sweep INTEGER NOT NULL DEFAULT 0, sweeping INTEGER NOT NULL DEFAULT 0,
    skipped INTEGER NOT NULL DEFAULT 0, skip_note TEXT, fence INTEGER NOT NULL DEFAULT 0, settings TEXT);
CREATE TABLE IF NOT EXISTS info(key TEXT PRIMARY KEY, value TEXT);
CREATE VIRTUAL TABLE IF NOT EXISTS temp.vocab USING fts5vocab(main, words, row);
CREATE TABLE IF NOT EXISTS store.chunks(hash TEXT PRIMARY KEY, vec BLOB NOT NULL) WITHOUT ROWID;
"""
# feeds: where each source's feed is. sweep counts its passes from the start, sweeping says one is under way
# (items.seen holds the pass that last brought an item); skipped and skip_note what it couldn't take since.
# settings: a hash of the plugin's settings its items were fed under (settle); fence: the first pass whose
# items search shows, after those settings changed (an earlier pass's items wait until they're fed again).
FEED_DEFAULTS = {"cursor": None, "pulled": None, "error": None, "items": 0, "complete": 0, "sweep": 0,
                 "sweeping": 0, "skipped": 0, "skip_note": None, "fence": 0, "settings": None}
KINDS = ("mail", "file", "note", "event", "task", "chat")
TITLE_WEIGHT = 3.0        # the title (a subject, a file name) counts three times as much as the text
PEOPLE_WEIGHT = 2.0       # who it's from and to (part 0 only): `doorman search finanzamt` finds their mail
EMBED_BATCH = 16          # chunks per call of the model
TEXT_LIMIT = 300_000      # characters kept per part
PASSAGE_CHARS = 100_000   # of those, what a hit's passage is cut from (its chunks lie in the first ~28,000)
# what a part may say besides its text: a hidden-text check's finding (the guard holds every hit whose
# passage comes from it), or that no check has cleared it yet (no passage from it until then)
PART_FLAGS = ("hidden_text", "unchecked")
FEED_EVERY = 5            # minutes between asking a source for changes, unless its manifest says otherwise
DAMAGED = "the search index was damaged and is being made anew from the plugins; ask again in a few minutes"


def _hash(*parts: Any) -> str:
    return hashlib.sha256("\x00".join(json.dumps(p, sort_keys=True, ensure_ascii=False, default=str)
                                      for p in parts).encode()).hexdigest()[:32]


def _chunk_hash(model: str, text: str) -> str:
    """A chunk's name in vectors.db: its vector depends on nothing else."""
    return hashlib.sha256(f"{model}\x00{text}".encode()).hexdigest()[:32]


def damaged(exc: BaseException) -> bool:
    """Whether an SQLite error means the file itself is broken, not a busy lock or a query it can't run."""
    return isinstance(exc, sqlite3.DatabaseError) and getattr(exc, "sqlite_errorname", "") in (
        "SQLITE_CORRUPT", "SQLITE_NOTADB")


def _healthy(path: Path) -> bool:
    """A full look at a database file (PRAGMA quick_check), on a connection of its own."""
    if not path.exists():
        return True
    try:
        conn = sqlite3.connect(path)
        try:
            return conn.execute("PRAGMA quick_check(1)").fetchone()[0] == "ok"
        finally:
            conn.close()
    except sqlite3.DatabaseError as exc:
        if damaged(exc):
            return False
        raise


def _drop(path: Path, keep_as: str | None = None) -> None:
    """A database file gone with its -wal and -shm; with keep_as, the file kept under that suffix (replacing
    one kept before)."""
    if keep_as and path.exists():
        os.replace(path, path.with_name(path.name + keep_as))
    for suffix in ("", "-wal", "-shm"):
        Path(f"{path}{suffix}").unlink(missing_ok=True)


def _prepare(path: Path, version: int, label: str) -> None:
    """Leaves path ready to open at this layout: a file that isn't a database set aside (<name>.damaged), one
    of another layout version deleted. Both are made anew, the index from the feeds, the vectors by the model."""
    if not path.exists():
        return
    try:
        conn = sqlite3.connect(path)
        try:
            have = conn.execute("PRAGMA user_version").fetchone()[0]
            tables = conn.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
        finally:
            conn.close()
    except sqlite3.DatabaseError as exc:
        if not damaged(exc):
            raise
        log.warning("%s is damaged (%s): set aside as %s.damaged and made anew", label, exc, path.name)
        _drop(path, ".damaged")
        return
    if tables and have != version:
        log.warning("%s has layout version %s and this Doorman uses %s: made anew", label, have, version)
        _drop(path)


def _mends(fallback):
    """For the index's ways in (search, a pull, upkeep): damage found on the way is mended (_recover) and the
    caller gets fallback(self) instead of an error."""
    def wrap(method):
        @functools.wraps(method)
        def run(self, *args, **kwargs):
            try:
                return method(self, *args, **kwargs)
            except sqlite3.DatabaseError as exc:
                if not damaged(exc):
                    raise
                self._recover(exc)
                return fallback(self)
        return run
    return wrap


def until_bound(value: str) -> str:
    """The first moment after an `until` date (the day included); a date-time stays as it is."""
    return str(date.fromisoformat(value) + timedelta(days=1)) if len(value) == 10 else value


def _like(value: str) -> str:
    return "%" + value.lower().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _text(value: Any) -> str:
    """A filter field as text: a list (several addresses) joined."""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value if v)
    return str(value or "")


def _flags(part: dict) -> str | None:
    """What a part says besides its text (PART_FLAGS), as the index keeps it, or None."""
    out: dict = {}
    hidden = part.get("hidden_text")
    if hidden:
        out["hidden_text"] = hidden if isinstance(hidden, dict) and hidden.get("reason") else {"reason": str(hidden)}
    if part.get("unchecked"):
        out["unchecked"] = True
    return json.dumps(out, ensure_ascii=False, sort_keys=True, default=str) if out else None


def parts_of(item: dict) -> list[dict]:
    """An item's parts as given, or its one `text` (with the item's PART_FLAGS) as part 0; always a part 0,
    so the title is searchable."""
    parts = item.get("parts")
    if parts is None:
        parts = [{"part": 0, "text": item.get("text") or "", **{k: item.get(k) for k in PART_FLAGS}}]
    out = [{"part": int(p.get("part", i)), "name": p.get("name"), "text": str(p.get("text") or "")[:TEXT_LIMIT],
            "flags": _flags(p)} for i, p in enumerate(parts) if isinstance(p, dict)]
    if not any(p["part"] == 0 for p in out):
        out.insert(0, {"part": 0, "name": None, "text": "", "flags": None})
    return out


class Library:
    def __init__(self, path: Path | str, embedder=None):
        self.path = Path(path)
        self.store_path = self.path.with_name("vectors.db")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.embedder = embedder              # .embed(texts, background) -> {model, dim, vectors} | {off} | {busy}
        self.lock = threading.RLock()
        self.vectors = textsearch.VectorCache()
        self.pulling: dict[str, threading.Lock] = {}
        self.dropped: set[str] = set()        # sources purged; a pull of theirs still running stops and goes
        self.generation = 0                   # how often the index was made anew while running (_recover)
        self.epochs: dict[str, int] = {}      # per source, how often its settings changed (settle): a pull stops
        _prepare(self.path, INDEX_VERSION, "The search index")
        _prepare(self.store_path, STORE_VERSION, "The vector store")
        try:
            self.db = self._connect()
        except sqlite3.DatabaseError as exc:  # damage further in than the first page
            if not damaged(exc):
                raise
            self._set_aside_damaged(exc)
            self.db = self._connect()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, check_same_thread=False)
        try:
            db.row_factory = sqlite3.Row
            db.execute("ATTACH DATABASE ? AS store", (str(self.store_path),))
            for schema in ("main", "store"):
                db.execute(f"PRAGMA {schema}.journal_mode=WAL")
                db.execute(f"PRAGMA {schema}.synchronous=NORMAL")
            new = not db.execute("SELECT 1 FROM sqlite_master WHERE name='items'").fetchone()
            db.executescript(SCHEMA)
            db.execute(f"PRAGMA main.user_version={INDEX_VERSION}")
            db.execute(f"PRAGMA store.user_version={STORE_VERSION}")
            if new:
                db.execute("INSERT OR REPLACE INTO info(key, value) VALUES('created', ?)", (clock.iso(),))
            db.commit()
        except BaseException:
            db.close()
            raise
        return db

    def _set_aside_damaged(self, why: BaseException) -> None:
        """The damaged one of the two files set aside (both if both are; the index if neither looks it)."""
        broken = [p for p in (self.path, self.store_path) if not _healthy(p)] or [self.path]
        for path in broken:
            log.error("%s is damaged (%s): set aside as %s.damaged and made anew", path, why, path.name)
            _drop(path, ".damaged")

    def _recover(self, why: BaseException) -> None:
        """Damage found while running: the damaged file set aside and the index opened anew. Every source
        then feeds again from the start; pulls and upkeep under way see the new generation and stop."""
        with self.lock:
            try:
                self.db.close()
            except sqlite3.Error:
                pass
            self._set_aside_damaged(why)
            self.db = self._connect()
            self.generation += 1
            self.vectors.invalidate()

    def check(self) -> bool:
        """A full look at both files (on connections of their own: search goes on meanwhile), after start;
        a damaged one is set aside and made anew. True if both are whole."""
        if all(_healthy(p) for p in (self.path, self.store_path)):
            return True
        self._recover(sqlite3.DatabaseError("PRAGMA quick_check found damage"))
        return False

    def close(self) -> None:
        with self.lock:
            self.db.close()

    # ------------------------------------------------------------------ items in and out

    def put(self, source: str, item: dict, stem: bool = True, seen: int | None = None) -> bool:
        """Add or replace one item of a source. An unchanged item costs one lookup; a part whose text didn't
        change keeps its stems and vectors. `seen`: the feed's pass that brings it (apply). True if anything
        changed.

        `same` (the plugin's word that two items are one: a Message-ID, an iCalendar UID) is kept together
        with a hash of the item's title and texts: anyone can send a mail with another's Message-ID or an
        invitation with another's UID, so only items that also read the same come once (engine.once)."""
        key = str(item["key"])
        kind = item.get("kind") or "note"
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {', '.join(KINDS)}, not {kind!r}")
        parts = parts_of(item)
        fields = item.get("fields") or {}
        ref = str(item.get("ref") or "")
        if not ref.startswith(f"{source}:"):  # a plugin names its own items only, never another plugin's
            ref = f"{source}:{key}"
        refs = [str(r) for r in item.get("refs") or [] if str(r).startswith(f"{source}:")][:1000]
        title = str(item.get("title") or "")
        same = item.get("same") or None
        if same:
            same = f"{same}|" + _hash(textsearch.fold(textsearch.flat(title)),
                                      [textsearch.fold(textsearch.flat(p["text"])) for p in parts])[:16]
        row_values = {
            "ref": ref, "kind": kind, "title": title,
            "date": item.get("date") or None, "sender": _text(item.get("from")).lower() or None,
            "recipients": _text(item.get("to")).lower() or None, "place": _text(item.get("in")) or None,
            "has_attachment": int(bool(item.get("has_attachment"))), "same": same,
            "refs": json.dumps(refs) if refs else None,
            "fields": json.dumps(fields, ensure_ascii=False, sort_keys=True, default=str)}
        full = _hash(row_values, [(p["part"], p["name"], p["text"], p["flags"]) for p in parts])
        dropped: list[int] = []
        with self.lock, self.db:
            row = self.db.execute("SELECT id, hash, title, sender, recipients, seen FROM items WHERE source=? AND key=?",
                                  (source, key)).fetchone()
            if row is not None and row["hash"] == full:
                if seen is not None and row["seen"] != seen:
                    self.db.execute("UPDATE items SET seen=? WHERE id=?", (seen, row["id"]))
                return False
            columns = ", ".join(row_values)
            if row is None:
                item_id = self.db.execute(
                    f"INSERT INTO items(source, key, {columns}, hash, seen) "
                    f"VALUES(?,?,{','.join('?' * len(row_values))},?,?)",
                    (source, key, *row_values.values(), full, seen or 0)).lastrowid
                old: dict[int, sqlite3.Row] = {}
            else:
                item_id = row["id"]
                self.db.execute(f"UPDATE items SET {', '.join(f'{c}=?' for c in row_values)}, hash=?"
                                + (", seen=?" if seen is not None else "") + " WHERE id=?",
                                (*row_values.values(), full, *([seen] if seen is not None else []), item_id))
                old = {r["part"]: r for r in self.db.execute(
                    "SELECT id, part, name, text_hash, flags FROM parts WHERE item=?", (item_id,))}
            people = " ".join(_text(item.get(k)) for k in ("from", "to")).strip()
            title_changed = row is not None and (row["title"] != row_values["title"]
                                                 or (row["sender"], row["recipients"]) != (row_values["sender"],
                                                                                           row_values["recipients"]))
            keep = set()
            for p in parts:
                text_hash = _hash(p["name"], p["text"])
                before = old.get(p["part"])
                if before is not None and before["text_hash"] == text_hash and not (title_changed and p["part"] == 0):
                    keep.add(p["part"])
                    if before["flags"] != p["flags"]:  # checked for hidden text since: the same text, a new verdict
                        self.db.execute("UPDATE parts SET flags=? WHERE id=?", (p["flags"], before["id"]))
                    continue
                if before is not None:
                    self._unindex(before["id"])
                    dropped.append(before["id"])
                    self.db.execute("UPDATE parts SET name=?, text=?, text_hash=?, same=?, flags=?, stemmed=0, "
                                    "embedded=0 WHERE id=?", (p["name"], p["text"], text_hash,
                                                              textsearch.same_key(p["text"]), p["flags"], before["id"]))
                    part_id = before["id"]
                else:
                    part_id = self.db.execute(
                        "INSERT INTO parts(item, part, name, text, text_hash, same, flags) VALUES(?,?,?,?,?,?,?)",
                        (item_id, p["part"], p["name"], p["text"], text_hash, textsearch.same_key(p["text"]),
                         p["flags"])).lastrowid
                keep.add(p["part"])
                title = row_values["title"] if p["part"] == 0 else (p["name"] or "")
                who = people if p["part"] == 0 else ""
                self.db.execute("INSERT INTO words(rowid, title, people, body) VALUES(?,?,?,?)",
                                (part_id, title, who, p["text"]))
                if stem:
                    self._stem(part_id, title, who, p["text"])
            for number, gone in old.items():
                if number not in keep:
                    self._unindex(gone["id"])
                    self.db.execute("DELETE FROM parts WHERE id=?", (gone["id"],))
                    dropped.append(gone["id"])
        if dropped and set(dropped) & self.vectors.keys():
            self.vectors.invalidate()
        return True

    def _stem(self, part_id: int, title: str, people: str, text: str) -> None:
        """Stems and parts of words for one part (the caller holds the lock and a transaction)."""
        for table in ("stems", "grams"):
            self.db.execute(f"DELETE FROM {table} WHERE rowid=?", (part_id,))
        self.db.execute("INSERT INTO stems(rowid, title, people, body) VALUES(?,?,?,?)",
                        (part_id, textsearch.stemmed_text(title), people, textsearch.stemmed_text(text)))
        self.db.execute("INSERT INTO grams(rowid, title, people, body) VALUES(?,?,?,?)", (part_id, title, people, text))
        self.db.execute("UPDATE parts SET stemmed=1 WHERE id=?", (part_id,))

    def _unindex(self, part_id: int) -> None:
        for table in ("words", "stems", "grams"):
            self.db.execute(f"DELETE FROM {table} WHERE rowid=?", (part_id,))
        self.db.execute("DELETE FROM vectors WHERE part=?", (part_id,))

    def remove(self, source: str, keys: Iterable[str]) -> int:
        count, dropped = 0, []
        with self.lock, self.db:
            for key in keys:
                row = self.db.execute("SELECT id FROM items WHERE source=? AND key=?", (source, str(key))).fetchone()
                if row is None:
                    continue
                for part in self.db.execute("SELECT id FROM parts WHERE item=?", (row["id"],)).fetchall():
                    self._unindex(part["id"])
                    dropped.append(part["id"])
                self.db.execute("DELETE FROM parts WHERE item=?", (row["id"],))
                self.db.execute("DELETE FROM items WHERE id=?", (row["id"],))
                count += 1
        if dropped and set(dropped) & self.vectors.keys():
            self.vectors.invalidate()
        return count

    def count(self, source: str) -> int:
        with self.lock:
            return self.db.execute("SELECT count(*) FROM items WHERE source=?", (source,)).fetchone()[0]

    def keys(self, source: str) -> set[str]:
        with self.lock:
            return {r[0] for r in self.db.execute("SELECT key FROM items WHERE source=?", (source,))}

    @_mends(lambda self: 0)
    def purge(self, source: str) -> int:
        """Everything of a source, and where its feed was: a plugin instance that was removed. A pull of it
        still running puts nothing back (pull)."""
        self.dropped.add(source)
        count = self.remove(source, self.keys(source))
        with self.lock, self.db:
            self.db.execute("DELETE FROM feeds WHERE source=?", (source,))
        return count

    def sources(self) -> set[str]:
        with self.lock:
            return {r[0] for r in self.db.execute("SELECT DISTINCT source FROM items UNION SELECT source FROM feeds")}

    def knows(self, source: str, ref: str, skip_kinds: Iterable[str] = (), parts: bool = True) -> bool:
        """Whether the index holds this ref of a source as something search may show: an item's ref, one of
        its parts' (<ref>#<n>, when `parts`), or a message it holds (`refs`, a chat's day). Not of a kind in
        skip_kinds."""
        skip = list(skip_kinds)
        kinds = f" AND i.kind NOT IN ({','.join('?' * len(skip))})" if skip else ""
        base, _, number = ref.rpartition("#")
        with self.lock:
            if self.db.execute(f"SELECT 1 FROM items i WHERE i.source=? AND i.ref=?{kinds}", (source, ref, *skip)).fetchone():
                return True
            if parts and number.isdigit() and self.db.execute(
                    f"SELECT 1 FROM items i JOIN parts p ON p.item = i.id WHERE i.source=? AND i.ref=? AND p.part=?{kinds}",
                    (source, base, int(number), *skip)).fetchone():
                return True
            return self.db.execute(f"SELECT 1 FROM items i, json_each(i.refs) AS r WHERE i.source=? AND i.refs IS NOT "
                                   f"NULL AND r.value=?{kinds} LIMIT 1", (source, ref, *skip)).fetchone() is not None

    def get(self, source: str, key: str) -> dict | None:
        with self.lock:
            row = self.db.execute("SELECT * FROM items WHERE source=? AND key=?", (source, key)).fetchone()
            if row is None:
                return None
            parts = [dict(p) for p in self.db.execute("SELECT part, name, text FROM parts WHERE item=? ORDER BY part",
                                                      (row["id"],))]
        out = dict(row)
        out["fields"] = json.loads(out["fields"] or "{}")
        out["refs"] = json.loads(out["refs"] or "[]")
        out["parts"] = parts
        return out

    # ------------------------------------------------------------------ feeds

    def feed_state(self, source: str) -> dict:
        with self.lock:
            row = self.db.execute("SELECT * FROM feeds WHERE source=?", (source,)).fetchone()
        return dict(row) if row else {"source": source, **FEED_DEFAULTS}

    def _save_feed(self, source: str, **values) -> None:
        with self.lock, self.db:
            state = {**self.feed_state(source), **values}
            self.db.execute(f"INSERT OR REPLACE INTO feeds(source, {', '.join(FEED_DEFAULTS)}) "
                            f"VALUES(?{', ?' * len(FEED_DEFAULTS)})", (source, *[state[k] for k in FEED_DEFAULTS]))

    def apply(self, source: str, batch: dict, from_start: bool = False, epoch: int | None = None) -> dict:
        """One answer of a source's feed: {items, removed?, cursor?, more?, complete?, reset?}. `complete`:
        these items are all the source has (whatever else is here of it goes). A feed asked from the start
        (from_start: its cursor was None) or answering `reset` begins a pass over everything the source has;
        the answer without `more` ends it, and what the pass didn't bring goes then. An item that can't be
        taken is skipped and counted on the feed. `epoch`: the source's settings epoch the answer was asked
        under (pull); if they changed since (settle), nothing is taken ({stale: true}). {changed, removed,
        skipped?}."""
        if not isinstance(batch, dict):
            raise ValueError("a feed answers {items, removed?, cursor?, more?, complete?, reset?}")
        with self.lock:
            if epoch is not None and epoch != self.epochs.get(source, 0):  # asked under settings since changed
                return {"changed": 0, "removed": 0, "stale": True}
            state = self.feed_state(source)
            sweep, sweeping = state["sweep"], bool(state["sweeping"])
            skipped, note = state["skipped"], state["skip_note"]
            if from_start or batch.get("reset"):
                sweep, sweeping, skipped, note = sweep + 1, True, 0, None
                self._save_feed(source, sweep=sweep, sweeping=1, skipped=0, skip_note=None)
        changed, bad, seen = 0, 0, set()
        for item in batch.get("items") or []:
            key = item.get("key") if isinstance(item, dict) else None
            try:
                if key in (None, ""):
                    raise ValueError("an item without a key")
                # every item a feed brings carries its pass (seen), also between passes: a fence (settle)
                # shows only what came since
                changed += self.put(source, item, seen=sweep)
            except sqlite3.Error:
                raise                             # the index's trouble, not the item's: the pull fails, tries again
            except Exception as exc:  # noqa: BLE001 - one item the index can't take mustn't hold up the rest
                bad += 1
                note = note or (f"{key}: {exc}" if key not in (None, "") else str(exc))[:300]
                continue
            seen.add(str(key))
        removed = self.remove(source, [str(k) for k in batch.get("removed") or []])
        if batch.get("complete"):
            removed += self.remove(source, self.keys(source) - seen)
        if sweeping and not batch.get("more"):  # the pass is through: what it didn't bring is gone
            with self.lock:
                stale = [r[0] for r in self.db.execute("SELECT key FROM items WHERE source=? AND seen<?",
                                                       (source, sweep))]
            removed += self.remove(source, stale)
            sweeping = False
        self._save_feed(source, sweeping=int(sweeping), skipped=skipped + bad, skip_note=note)
        if bad:
            log.warning("the search index skipped %d item(s) of %s: %s", bad, source, note)
        out = {"changed": changed, "removed": removed}
        if bad:
            out["skipped"] = bad
        return out

    @_mends(lambda self: {"error": DAMAGED})
    def pull(self, source: str, plugin, budget: float = 60.0) -> dict:
        """Ask one source for what changed since its cursor, until it has nothing more or the budget is
        spent. One pull per source at a time; a second caller gets {"busy": true}. Failures are kept on the
        feed (the owner app shows them) and raised no further. A source purged meanwhile (its plugin
        removed) or an index made anew (_recover) stops it: nothing it brought counts."""
        lock = self.pulling.setdefault(source, threading.Lock())
        if not lock.acquire(blocking=False):
            return {"busy": True}
        try:
            self.dropped.discard(source)
            generation, epoch = self.generation, self.epochs.get(source, 0)
            deadline = time.monotonic() + budget
            totals = {"changed": 0, "removed": 0, "skipped": 0, "batches": 0}
            while True:
                with self.lock:
                    current = self._current(source, generation, epoch)
                    state = self.feed_state(source)
                if not current:
                    if source in self.dropped:
                        self.purge(source)
                    return {**totals, "stopped": "the source was removed, its settings changed or the index was made "
                                                 "anew meanwhile"}
                left = max(1.0, deadline - time.monotonic())
                try:
                    batch = plugin.index_feed(state["cursor"], left) or {}
                    done = self.apply(source, batch, from_start=state["cursor"] is None, epoch=epoch)
                except Exception as exc:  # noqa: BLE001 - one source failing leaves the others
                    if damaged(exc):
                        raise
                    log.warning("feeding the search index from %s failed: %s", source, exc)
                    with self.lock:
                        if self._current(source, generation, epoch):
                            self._save_feed(source, error=f"{type(exc).__name__}: {exc}"[:300], pulled=clock.iso())
                    return {**totals, "error": str(exc)[:300]}
                if done.get("stale"):
                    return {**totals, "stopped": "the plugin's settings changed meanwhile"}
                for k in ("changed", "removed", "skipped"):
                    totals[k] += done.get(k, 0)
                totals["batches"] += 1
                with self.lock:
                    current = self._current(source, generation, epoch)
                    if current:
                        self._save_feed(source, cursor=batch.get("cursor", state["cursor"]), pulled=clock.iso(),
                                        error=None, items=self.count(source), complete=int(not batch.get("more")))
                if not current:
                    if source in self.dropped:
                        self.purge(source)
                    return {**totals, "stopped": "the source was removed, its settings changed or the index was made "
                                                 "anew meanwhile"}
                if not batch.get("more") or time.monotonic() >= deadline:
                    return {**totals, "more": bool(batch.get("more"))}
        finally:
            lock.release()

    def _current(self, source: str, generation: int, epoch: int = 0) -> bool:
        """Whether a pull begun at this generation (and this epoch of the source's settings) still feeds this
        index (the caller holds the lock)."""
        return source not in self.dropped and generation == self.generation and epoch == self.epochs.get(source, 0)

    def settle(self, source: str, settings: str) -> bool:
        """The source's settings now, as a hash (engine.search.feed_settings: the plugin's config, the security
        senders). When they differ from what its items were fed under (narrower calendars, a sender added to
        security_senders), none of its items show in search from now on, and it feeds again from the start
        under the new settings: an item shows again once that feed brings it (the fence), so what the plugin
        no longer hands over is gone at once, even while its feed fails (an expired login). The rest of the
        pass costs a lookup per unchanged item; vectors come back from vectors.db. A pull still running under
        the old settings stops. True if the settings changed."""
        with self.lock:
            state = self.feed_state(source)
            if state["settings"] == settings:
                return False
            if state["settings"] is None:  # the first look: what it has fed so far was fed under these
                self._save_feed(source, settings=settings)
                return False
            self.epochs[source] = self.epochs.get(source, 0) + 1
            self._save_feed(source, settings=settings, fence=state["sweep"] + 1, cursor=None, sweeping=0)
        log.info("search index: the settings of %s changed; its items wait until it has fed them again", source)
        return True

    def refeeding(self, source: str) -> bool:
        """Whether the source's items wait for its feed to bring them again after its settings changed (the
        pass at its fence isn't through)."""
        state = self.feed_state(source)
        return bool(state["fence"]) and (state["sweep"] < state["fence"]
                                         or (state["sweep"] == state["fence"] and bool(state["sweeping"])))

    def rebuild(self, source: str | None = None) -> None:
        """Feed a source (or every one) from the start again at the next pull: a pass over everything it has,
        after which what it didn't bring is gone (apply). Unchanged items keep their stems and vectors."""
        with self.lock, self.db:
            if source is None:
                self.db.execute("UPDATE feeds SET cursor=NULL")
            else:
                self.db.execute("UPDATE feeds SET cursor=NULL WHERE source=?", (source,))

    # ------------------------------------------------------------------ upkeep: stems, vectors

    @_mends(lambda self: self.status())
    def run(self, deadline: float) -> dict:
        """One slice of upkeep until `deadline` (time.monotonic()): stems and parts of words for parts put
        without them, then vectors, newest items first. {stemmed, embedded, more}."""
        stemmed = self._stem_missing(deadline)
        embedded = self._embed_missing(deadline)
        self._prune_store()
        status = self.status()
        meaning = status.get("semantic") or {}
        status["last_run"] = {"stemmed": stemmed, "embedded": embedded}
        status["more"] = bool(stemmed and status["unstemmed"]) or bool(
            embedded and meaning.get("embedded", 0) < meaning.get("of", 0))
        return status

    def _stem_missing(self, deadline: float) -> int:
        count = 0
        while time.monotonic() < deadline:
            with self.lock, self.db:
                rows = self.db.execute("SELECT p.id, p.part, p.name, p.text, i.title, i.sender, i.recipients "
                                       "FROM parts p JOIN items i ON i.id = p.item WHERE p.stemmed=0 LIMIT 50").fetchall()
                for row in rows:
                    first = row["part"] == 0
                    people = " ".join(v for v in (row["sender"], row["recipients"]) if v) if first else ""
                    self._stem(row["id"], row["title"] if first else (row["name"] or ""), people, row["text"])
            if not rows:
                break
            count += len(rows)
        return count

    def model(self) -> str | None:
        """The model Doorman embeds with, or None when semantic search is off."""
        if self.embedder is None:
            return None
        probe = self.embedder.embed([])
        return None if probe.get("off") else probe.get("model")

    def info(self, key: str, value: str | None = None) -> str | None:
        with self.lock, self.db:
            if value is None:
                row = self.db.execute("SELECT value FROM info WHERE key=?", (key,)).fetchone()
                return row[0] if row else None
            self.db.execute("INSERT OR REPLACE INTO info(key, value) VALUES(?,?)", (key, value))
            return value

    def _embed_missing(self, deadline: float) -> int:
        """Vectors for parts without them, newest items first, a few at a time, while the agent leaves the
        model alone (it answers busy then, and the rest waits for the next run). A chunk read before (by this
        model, in any index since) comes from vectors.db instead of the model."""
        model = self.model()
        if not model:
            return 0
        chunking = f"{textsearch.CHUNK_CHARS}/{textsearch.CHUNK_OVERLAP}/{textsearch.MAX_CHUNKS}"
        if self.info("embed_model") != model or self.info("chunking") != chunking:
            # vectors of another model mean nothing here; of other chunks, they'd point at the wrong passage
            with self.lock, self.db:
                self.db.execute("DELETE FROM vectors")
                self.db.execute("UPDATE parts SET embedded=0")
            self.info("embed_model", model)
            self.info("chunking", chunking)
            self.vectors.invalidate()
        count = 0
        while time.monotonic() < deadline - 10:
            with self.lock:
                generation = self.generation
                rows = self.db.execute(
                    "SELECT p.id, p.part, p.name, p.text, p.text_hash, i.title FROM parts p JOIN items i ON i.id = p.item "
                    "WHERE p.embedded=0 ORDER BY i.date IS NULL, i.date DESC, p.id DESC LIMIT 4").fetchall()
            if not rows:
                break
            owners, texts = [], []
            for row in rows:
                title = row["title"] if row["part"] == 0 else f"{row['title']}: {row['name'] or ''}"
                for chunk, piece in enumerate(textsearch.chunk_texts(title, row["text"])):
                    owners.append((row["id"], chunk))
                    texts.append(piece)
            hashes = [_chunk_hash(model, t) for t in texts]
            with self.lock:
                known = {r[0]: r[1] for r in self.db.execute(
                    f"SELECT hash, vec FROM store.chunks WHERE hash IN ({','.join('?' * len(hashes))})", hashes)}
            missing = [i for i, h in enumerate(hashes) if h not in known]
            fresh: dict[str, bytes] = {}
            for start in range(0, len(missing), EMBED_BATCH):
                batch = missing[start:start + EMBED_BATCH]
                result = self.embedder.embed([texts[i] for i in batch], background=True)
                if result.get("off") or result.get("busy") or result.get("model") != model:
                    return count
                for i, vector in zip(batch, textsearch.unpack(result)):
                    fresh[hashes[i]] = vector.tobytes()
            with self.lock, self.db:
                if self.generation != generation:  # the index was made anew meanwhile: these parts are gone
                    return count
                now = {r["id"]: (r["text_hash"], r["title"]) for r in self.db.execute(
                    "SELECT p.id, p.text_hash, i.title FROM parts p JOIN items i ON i.id = p.item "
                    f"WHERE p.id IN ({','.join('?' * len(rows))}) AND p.embedded=0", [r["id"] for r in rows])}
                done = {r["id"] for r in rows if now.get(r["id"]) == (r["text_hash"], r["title"])}  # else changed meanwhile
                for part in done:
                    self.db.execute("DELETE FROM vectors WHERE part=?", (part,))
                self.db.executemany("INSERT INTO vectors(part, chunk, vec, hash, chars) VALUES(?,?,?,?,?)",
                                    [(part, chunk, known.get(hashes[i]) or fresh[hashes[i]], hashes[i], len(texts[i]))
                                     for i, (part, chunk) in enumerate(owners) if part in done])
                self.db.executemany("INSERT OR IGNORE INTO store.chunks(hash, vec) VALUES(?,?)", fresh.items())
                self.db.executemany("UPDATE parts SET embedded=1 WHERE id=?", [(part,) for part in done])
            if done & self.vectors.keys():
                self.vectors.invalidate()
            count += len(done)
        return count

    def _prune_store(self) -> int:
        """Vectors in vectors.db no part uses any more (a text changed or gone, another model), at most once
        a day and only once the index has settled: SETTLE_DAYS old, no pass under way, every part read.
        Sooner, right after the index was made anew, they are what spares the model reading it all again."""
        today = clock.now().date().isoformat()
        with self.lock:
            created = self.info("created")
            if self.info("store_pruned") == today or not created:
                return 0
            if (clock.now() - clock.parse(created)).days < SETTLE_DAYS:
                return 0
            if self.db.execute("SELECT 1 FROM feeds WHERE sweeping=1 UNION ALL "
                               "SELECT 1 FROM parts WHERE embedded=0 LIMIT 1").fetchone():
                return 0
            with self.db:
                gone = self.db.execute("DELETE FROM store.chunks WHERE NOT EXISTS "
                                       "(SELECT 1 FROM main.vectors v WHERE v.hash = chunks.hash)").rowcount
            self.info("store_pruned", today)
        if gone:
            log.info("vector store: %d vectors no part uses any more removed", gone)
        return gone

    @_mends(lambda self: self.status())
    def status(self, source: str | None = None) -> dict:
        """{items, parts, unstemmed, semantic?: {embedded, of}, summary}, for one source or all."""
        where, args = ("WHERE i.source=?", (source,)) if source else ("", ())
        with self.lock:
            items = self.db.execute(f"SELECT count(*) FROM items i {where}", args).fetchone()[0]
            parts, stemmed, embedded = self.db.execute(
                f"SELECT count(*), coalesce(sum(p.stemmed), 0), coalesce(sum(p.embedded), 0) FROM parts p "
                f"JOIN items i ON i.id = p.item {where}", args).fetchone()
        out = {"items": items, "parts": parts, "unstemmed": parts - stemmed,
               "summary": f"{items} items indexed" + (f", {parts - stemmed} parts still to stem" if parts > stemmed else "")}
        if self.info("embed_model"):
            out["semantic"] = {"embedded": embedded, "of": parts}
            if embedded < parts:
                out["summary"] += f"; semantic search covers {embedded} of {parts} parts so far"
        return out

    # ------------------------------------------------------------------ search

    def _fences(self, sources: list[str]) -> dict[str, int]:
        """Per source, the first feed pass whose items search shows (settle); 0 for all."""
        with self.lock:
            return {r[0]: r[1] for r in self.db.execute(
                f"SELECT source, fence FROM feeds WHERE fence > 0 AND source IN ({','.join('?' * len(sources))})",
                tuple(sources))}

    def _filters(self, params: dict, scope: dict[str, dict]) -> tuple[str, list, str, list]:
        """(where on items i, its args, where on parts p, its args) for a search over these sources. Per
        source: kinds it may not show (`skip_kinds`), whether parts besides part 0 may (`parts`: a mail's
        attachments), and its fence."""
        fences = self._fences(list(scope))
        per_source, args = [], []
        for source, rule in scope.items():
            clause = "i.source = ?"
            args.append(source)
            skip = list(rule.get("skip_kinds") or [])
            if skip:
                clause += f" AND i.kind NOT IN ({','.join('?' * len(skip))})"
                args += skip
            if fences.get(source):
                clause += " AND i.seen >= ?"
                args.append(fences[source])
            per_source.append(f"({clause})")
        where = ["(" + " OR ".join(per_source) + ")"]
        kinds = params.get("kind")
        if kinds:
            kinds = [kinds] if isinstance(kinds, str) else list(kinds)
            where.append(f"i.kind IN ({','.join('?' * len(kinds))})")
            args += kinds
        for name, column in (("from", "sender"), ("to", "recipients")):
            if params.get(name):
                where.append(f"i.{column} LIKE ? ESCAPE '\\'")
                args.append(_like(params[name]))
        if params.get("in"):
            where.append("lower(i.place) LIKE ? ESCAPE '\\'")
            args.append(_like(params["in"]))
        if params.get("has_attachment"):
            where.append("i.has_attachment=1")
        if params.get("since"):
            where.append("i.date >= ?")
            args.append(params["since"])
        if params.get("until"):
            where.append("i.date < ?")
            args.append(until_bound(params["until"]))
        whole = [source for source, rule in scope.items() if rule.get("parts", True) is False]
        parts = f"(p.part = 0 OR i.source NOT IN ({','.join('?' * len(whole))}))" if whole else "1"
        return " AND ".join(where), args, parts, whole

    def _part_ids(self, table: str, match: str, where: str, args: list, limit: int) -> list[int]:
        try:
            with self.lock:
                return [r[0] for r in self.db.execute(
                    f"SELECT p.id FROM {table} JOIN parts p ON p.id = {table}.rowid JOIN items i ON i.id = p.item "
                    f"WHERE {table} MATCH ? AND {where} ORDER BY bm25({table}, {TITLE_WEIGHT}, {PEOPLE_WEIGHT}, 1.0) LIMIT ?",
                    (match, *args, limit))]
        except sqlite3.OperationalError:  # a query FTS5 can't parse (only punctuation, say): no hits
            return []

    def _vocabulary(self, first: str) -> list[tuple[str, int]]:
        with self.lock:
            return [tuple(r) for r in self.db.execute("SELECT term, doc FROM temp.vocab WHERE term >= ? AND term < ?",
                                                      (first, chr(ord(first) + 1)))]

    def _vector_rows(self, after: int) -> list:
        with self.lock:
            return [tuple(r) for r in self.db.execute(
                "SELECT id, part, chunk, vec, chars FROM vectors WHERE id > ? ORDER BY id", (after,))]

    def _by_meaning(self, query: str, limit: int, where: str, args: list, notes: list[str]) -> list[tuple]:
        """[(part id, chunk, z, clear)] that stand out from the index (textsearch.VectorCache.nearest), the
        clear ones and the near ones, within the filters."""
        model = self.info("embed_model")
        if not model or self.embedder is None or not query.strip():
            return []
        result = self.embedder.embed([query])
        if result.get("off") or result.get("busy"):
            return []
        if result.get("model") != model:
            notes.append("semantic search is switching models; its vectors are being rebuilt")
            return []
        near = self.vectors.nearest(self._vector_rows, result["vectors"], limit, min_z=textsearch.MEANING_MIN_Z,
                                    near_z=textsearch.MEANING_NEAR_Z)
        if not near:
            return []
        with self.lock:
            allowed = {r[0] for r in self.db.execute(
                f"SELECT p.id FROM parts p JOIN items i ON i.id = p.item WHERE p.id IN ({','.join('?' * len(near))}) "
                f"AND {where}", (*[x[0] for x in near], *args))}
        return [x for x in near if x[0] in allowed]

    def _worded(self, items: list[int], terms: list[tuple[str, bool]], where: str, args: list) -> set[int]:
        """Of these items, those where any of the terms occurs as a word, a stem or a part of a word (in the
        parts the search may show): a hit by meaning that isn't one of them was found by meaning alone."""
        if not items or not terms:
            return set()
        found: set[int] = set()
        for table, match in textsearch.any_term(terms).items():
            try:
                with self.lock:
                    found |= {r[0] for r in self.db.execute(
                        f"SELECT DISTINCT p.item FROM {table} JOIN parts p ON p.id = {table}.rowid "
                        f"JOIN items i ON i.id = p.item WHERE {table} MATCH ? AND {where} "
                        f"AND p.item IN ({','.join('?' * len(items))})", (match, *args, *items))}
            except sqlite3.OperationalError:
                continue
        return found

    @_mends(lambda self: {"hits": [], "notes": [DAMAGED], "close": {}})
    def search(self, params: dict, sources: list[str] | dict[str, dict], limit: int, allow=None,
               hide_part=None, meaning: bool = True) -> dict:
        """{"hits": [...], "notes": [...], "close": {term: [spellings]}}: items of these sources, best first
        (or the newest first without words, or with sort=date), at most limit*2 of them, so the caller can drop
        copies and still have enough. When fewer than MEANING_NEAR_WHEN hits stand out clearly, the closest by
        meaning come after them (near: True). Each hit: {source, kind, ref, key, title, date, passage, where?,
        part, refs, hidden_text?, unchecked?, by_meaning, meaning (how far it stands out by meaning, z; None
        when only words found it), near, same: [keys], fields}.

        `sources`: names, or {name: {skip_kinds, parts}} for what a source may show (engine.search.sources: a
        kind or an attachment whose read is off). `allow(word)` False keeps a close spelling out of the search
        (a word hidden from the agent); `close` says which ones were searched, for the caller to mention.
        `hide_part(source, name)` True: a part (besides part 0) by that name doesn't find its item (its name
        is hidden from the agent, so its text is too).

        By meaning too unless meaning=False (search.any_word's single words). Bounded per search: at most
        textsearch.MAX_TERMS words, close spellings for a few of them, and a passage cut from the start of its
        part (PASSAGE_CHARS) for each hit."""
        scope = {s: {} for s in sources} if not isinstance(sources, dict) else dict(sources)
        if not scope:
            return {"hits": [], "notes": [], "close": {}}
        where, args, part_where, part_args = self._filters(params, scope)
        terms = textsearch.terms_of(params.get("query") or "")
        notes: list[str] = []
        if len(terms) > textsearch.MAX_TERMS:
            notes.append(f"only the first {textsearch.MAX_TERMS} words were searched: "
                         f"{' '.join(t for t, _ in terms[textsearch.MAX_TERMS:])} left out")
            terms = terms[:textsearch.MAX_TERMS]
        want = limit * 2
        if not terms:
            with self.lock:
                rows = self.db.execute(f"SELECT i.id FROM items i WHERE {where} ORDER BY i.date IS NULL, i.date DESC "
                                       "LIMIT ?", (*args, want)).fetchall()
            return {"hits": self._hits([(r[0], None, None, None, False) for r in rows], [], scope), "notes": notes,
                    "close": {}}
        deep = max(want * 3, 40)
        both, both_args = f"{where} AND {part_where}", [*args, *part_args]
        query = " ".join(f'"{t}"' if " " in t else t for t, _ in terms)  # what the meaning is taken from
        found = textsearch.rank(
            terms, deep,
            words=lambda m: self._part_ids("words", m, both, both_args, deep),
            stems=lambda m: self._part_ids("stems", m, both, both_args, deep),
            grams=lambda m: self._part_ids("grams", m, both, both_args, deep),
            vocabulary=self._vocabulary, allow=allow,
            meaning=(lambda: self._by_meaning(query, deep, both, both_args, notes)) if meaning else None)
        order, near = found["order"], found["near"] if params.get("sort") != "date" else []
        if not order and not near:
            return {"hits": [], "notes": notes, "close": found["close"]}
        with self.lock:
            owner = {r[0]: tuple(r)[1:] for r in self.db.execute(
                f"SELECT p.id, p.item, p.part, p.name, i.source FROM parts p JOIN items i ON i.id = p.item "
                f"WHERE p.id IN ({','.join('?' * len(order + near))})", tuple(order + near))}
        picked, seen = [], set()

        def take(part: int) -> int | None:
            """The item this part finds, unless it is taken or the part's name is hidden."""
            item, number, name, source = owner.get(part) or (None, 0, None, None)
            if item is None or item in seen:
                return None
            if number and hide_part is not None and hide_part(source, name or ""):
                return None  # an attachment whose name is hidden from the agent finds nothing; its other parts may
            seen.add(item)
            return item

        for part in order:  # an item takes the place of its best part
            if (item := take(part)) is not None:
                by = found["meaning"].get(part)
                picked.append((item, part, by[0] if by else None, by[1] if by else None, False))
        if len(picked) < textsearch.MEANING_NEAR_WHEN:  # little stands out: the closest by meaning, after the rest
            room = textsearch.MEANING_NEAR_MAX
            for part in near:
                if room == 0:
                    break
                if (item := take(part)) is not None:
                    room -= 1
                    chunk, z = found["meaning"][part]
                    picked.append((item, part, chunk, z, True))
        if params.get("sort") == "date":  # the newest of what was found, before passages are cut for want of them
            with self.lock:
                dates = {r[0]: r[1] or "" for r in self.db.execute(
                    f"SELECT id, date FROM items WHERE id IN ({','.join('?' * len(picked))})", [p[0] for p in picked])}
            picked.sort(key=lambda p: dates.get(p[0], ""), reverse=True)
        picked = picked[:want]
        worded = self._worded([p[0] for p in picked if p[3] is not None], terms, both, both_args)
        return {"hits": self._hits(picked, found["terms"], scope, worded), "notes": notes, "close": found["close"]}

    def _hits(self, picked: list[tuple], shown_terms: list[str], scope: dict[str, dict],
              worded: set[int] | None = None) -> list[dict]:
        """The hits for (item, part, chunk, z by meaning, near): each item's passage from that part (or its first
        part the source may show), cut from the first PASSAGE_CHARS of it, so one search reads a bounded
        amount of text however long the parts are."""
        if not picked:
            return []
        items = [p[0] for p in picked]
        with self.lock:
            rows = {r["id"]: r for r in self.db.execute(
                f"SELECT * FROM items WHERE id IN ({','.join('?' * len(items))})", tuple(items))}
            parts: dict[int, list] = {}
            for r in self.db.execute(f"SELECT id, item, part, name, same, flags FROM parts WHERE item IN "
                                     f"({','.join('?' * len(items))}) ORDER BY part", tuple(items)):
                parts.setdefault(r["item"], []).append(r)
        chosen: dict[int, sqlite3.Row] = {}
        for item, part_id, *_ in picked:
            row = rows.get(item)
            if row is None:
                continue
            whole = scope.get(row["source"], {}).get("parts", True) is not False
            own = [p for p in parts.get(item, []) if whole or p["part"] == 0]
            best = next((p for p in own if p["id"] == part_id), None) or (own[0] if own else None)
            if best is not None:
                chosen[item] = best
        with self.lock:
            ids = [p["id"] for p in chosen.values()]
            texts = {r[0]: r[1] for r in self.db.execute(
                f"SELECT id, substr(text, 1, ?) FROM parts WHERE id IN ({','.join('?' * len(ids))})",
                (PASSAGE_CHARS, *ids))} if ids else {}
        out = []
        for item, _, chunk, score, near in picked:
            row = rows.get(item)
            if row is None:
                continue
            best = chosen.get(item)
            hit = {"source": row["source"], "kind": row["kind"], "ref": row["ref"], "key": row["key"],
                   "title": row["title"], "date": row["date"], "fields": json.loads(row["fields"] or "{}"),
                   "passage": None, "part": 0, "refs": json.loads(row["refs"] or "[]"), "by_meaning": False,
                   "meaning": score, "near": near, "same": []}
            if best is not None:
                hit["part"] = best["part"]
                flags = json.loads(best["flags"] or "{}")
                if flags.get("unchecked"):
                    hit["unchecked"] = True  # not cleared of hidden text yet: no passage from it until then
                else:
                    hit["passage"] = textsearch.passage(texts.get(best["id"]) or "", shown_terms, chunk)
                if flags.get("hidden_text"):
                    hit["hidden_text"] = flags["hidden_text"]
                if best["part"] != 0:
                    hit["where"] = best["name"] or f"part {best['part']}"
                if best["same"]:
                    hit["same"].append(best["same"])
            if row["same"]:
                hit["same"].append(row["same"])
            if score is not None and worded is not None:
                hit["by_meaning"] = item not in worded
            out.append(hit)
        return out
