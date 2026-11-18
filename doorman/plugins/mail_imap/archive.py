"""The mail archive: every message of a mailbox with the text of its attachments. Doorman's search index is
fed from it (Archive.feed, through plugin.index_feed; library.py does the searching).

The server stays the source of truth for what exists, where and with which flags; the archive follows it and
never writes back. It is Doorman's memory of the mailbox: a message that leaves the mailbox (deleted, moved to
Trash, gone with an expired university account) stays findable, marked deleted_on_server.

    archive: index     (default) metadata and the text of bodies and attachments; originals come from the
                       server, so a message gone from it can still be found and read as text
    archive: full      also each original message (.eml, gzipped), so it can be read, forwarded and its
                       attachments sent after it's gone from the server
    archive: off       none; mail isn't in doorman search, and mail.search asks the server

Files in the plugin's folder:

    archive/archive.db        metadata, text, where each message is (backed up)
    archive/eml/xx/<sha256>.eml.gz    full mode: the originals, named by their hash, never changed, so
                              backups hard-link them

Sync (the `archive` job, every few minutes, a slice of time each run): per folder a UIDVALIDITY and a UID
range already seen. New mail first, then what left each folder, flags every half hour, then the backfill,
newest first, until it reaches the oldest message. Junk, Trash, Drafts and the Agent trash aren't
archived; a message moved there counts as deleted. archive_months keeps only the last N months. A message is
fetched once: copies and moves are found by Message-ID. The first pass reads text layers only; a later,
lowest-priority pass reads scans with OCR (archive_ocr) and checks PDFs for hidden text (check_hidden_text,
whatever archive_ocr says), when the agent hasn't used the extractor for a minute. The first pass already looks
at each PDF's pages for hidden text (extract's structural check, milliseconds a page): a PDF it finds clean is
searchable at once, one that hides text is held at once; one it can't decide (a scan's invisible text layer
over the picture of the page) gives no passage until the OCR check has read it. The OCR check runs for every
PDF as the backstop, and what it finds holds a PDF already shown.

The search feed goes by a change counter: each message carries `seq`, the counter's value when it last
changed in a way search shows (it arrived, moved, its flags changed, it was deleted on the server, OCR filled
in an attachment's text), and a message dropped from the archive leaves a tombstone with its own `seq`.
Triggers in the schema keep both, so no code path that changes a message can forget it, a sync in another
process (doorman-admin job) included. A feed hands over what has a higher `seq` than its cursor.
"""

from __future__ import annotations

import email
import email.policy
import fcntl
import gzip
import hashlib
import json
import mimetypes
import os
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import date, datetime, timezone
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path

from doorman.plugin_api import PluginError, StoreOfAnother, open_store, set_aside
from doorman.sanitize import describe, html_to_text

MODES = ("index", "full", "off")
TEXT_LIMIT = 300_000             # characters of text kept per body or attachment
FETCH_BYTES = 8 * 1024 * 1024    # originals fetched together up to this size
HEADER_BATCH = 200
FLAGS_EVERY = 30 * 60            # seconds between full flag refreshes of a folder
FLAGS_BATCH = 1000               # UIDs per FLAGS fetch (imapclient's fetch() can't take "1:*")
MIN_OCR_IMAGE = 20_000           # smaller images (logos, signatures) aren't worth OCR
FEED_BATCH = 200                 # messages per answer of the search feed,
FEED_CHARS = 4_000_000           # and about this much text at most (long attachments): the answer is held in memory
# Junk, Trash and Drafts aren't archived; neither are views of other folders (Gmail's Starred, Important)
SKIP_FLAGS = (b"\\Junk", b"\\Trash", b"\\Drafts", b"\\Noselect", b"\\NonExistent", b"\\Flagged", b"\\Important")
# by name too, for servers without special-use flags: English, German and Dutch (Outlook's names included)
SKIP_NAMES = {"junk", "spam", "trash", "drafts", "deleted items", "junk email", "junk e-mail", "deleted messages",
              "bin", "outbox", "bulk mail",
              "papierkorb", "entwürfe", "gelöschte elemente", "gelöschte objekte", "junk-e-mail", "postausgang",
              "ongewenste e-mail", "ongewenste mail", "verwijderde items", "prullenbak", "concepten", "postvak uit",
              "[gmail]/spam", "[gmail]/trash", "[gmail]/drafts", "[gmail]/bin", "[gmail]/important",
              "[gmail]/starred"}

_now = time.monotonic  # tests replace it to cut a sync short

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages(
    n INTEGER PRIMARY KEY, mid TEXT UNIQUE NOT NULL, subject TEXT, sender TEXT, sender_names TEXT,
    recipients TEXT, cc TEXT, recipient_names TEXT, reply_to TEXT, date TEXT, ts REAL, in_reply_to TEXT,
    refs TEXT, size INTEGER, attachments TEXT, folder TEXT, flags TEXT, deleted_on_server TEXT, eml TEXT,
    security INTEGER DEFAULT 0, added TEXT, seq INTEGER);
CREATE INDEX IF NOT EXISTS messages_ts ON messages(ts);
CREATE INDEX IF NOT EXISTS messages_seq ON messages(seq);
CREATE TABLE IF NOT EXISTS texts(
    mid TEXT NOT NULL, part INTEGER NOT NULL, name TEXT, type TEXT, size INTEGER, text TEXT, pages INTEGER,
    ocr_pages TEXT, note TEXT, hidden TEXT, sanitized TEXT, state TEXT, attempts INTEGER DEFAULT 0,
    hidden_check TEXT, PRIMARY KEY(mid, part));
CREATE INDEX IF NOT EXISTS texts_state ON texts(state);
CREATE TABLE IF NOT EXISTS locations(folder TEXT NOT NULL, uid INTEGER NOT NULL, mid TEXT NOT NULL, flags TEXT,
    PRIMARY KEY(folder, uid));
CREATE INDEX IF NOT EXISTS locations_mid ON locations(mid);
CREATE TABLE IF NOT EXISTS folders(name TEXT PRIMARY KEY, uidvalidity INTEGER, top INTEGER, bottom INTEGER,
    flags_checked REAL DEFAULT 0, complete INTEGER DEFAULT 0, seen TEXT);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS removed(mid TEXT PRIMARY KEY, seq INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS removed_seq ON removed(seq);
INSERT OR IGNORE INTO meta(key, value) VALUES('seq', '0');

-- the search feed's change counter (meta 'seq'): a new message, a change search shows, a message dropped
CREATE TRIGGER IF NOT EXISTS messages_new AFTER INSERT ON messages BEGIN
    UPDATE meta SET value = value + 1 WHERE key = 'seq';
    UPDATE messages SET seq = (SELECT value FROM meta WHERE key = 'seq') WHERE n = NEW.n;
    DELETE FROM removed WHERE mid = NEW.mid;
END;
CREATE TRIGGER IF NOT EXISTS messages_changed AFTER UPDATE OF folder, flags, deleted_on_server ON messages
WHEN OLD.folder IS NOT NEW.folder OR OLD.flags IS NOT NEW.flags OR OLD.deleted_on_server IS NOT NEW.deleted_on_server
BEGIN
    UPDATE meta SET value = value + 1 WHERE key = 'seq';
    UPDATE messages SET seq = (SELECT value FROM meta WHERE key = 'seq') WHERE n = NEW.n;
END;
CREATE TRIGGER IF NOT EXISTS texts_changed AFTER UPDATE OF text, hidden, hidden_check ON texts
WHEN OLD.text IS NOT NEW.text OR OLD.hidden IS NOT NEW.hidden OR OLD.hidden_check IS NOT NEW.hidden_check
BEGIN
    UPDATE meta SET value = value + 1 WHERE key = 'seq';
    UPDATE messages SET seq = (SELECT value FROM meta WHERE key = 'seq') WHERE mid = NEW.mid;
END;
CREATE TRIGGER IF NOT EXISTS messages_gone AFTER DELETE ON messages BEGIN
    UPDATE meta SET value = value + 1 WHERE key = 'seq';
    INSERT OR REPLACE INTO removed(mid, seq) VALUES(OLD.mid, (SELECT value FROM meta WHERE key = 'seq'));
END;
-- a PDF the OCR check has read, with nothing found: search may show its passage now (unless it did already,
-- the structural check having found it clean)
CREATE TRIGGER IF NOT EXISTS texts_checked AFTER UPDATE OF state ON texts
WHEN OLD.state IN ('check', 'ocr') AND NEW.state = 'done' AND OLD.text IS NEW.text AND OLD.hidden IS NEW.hidden
    AND OLD.hidden_check IS NOT 'clean'
BEGIN
    UPDATE meta SET value = value + 1 WHERE key = 'seq';
    UPDATE messages SET seq = (SELECT value FROM meta WHERE key = 'seq') WHERE mid = NEW.mid;
END;
"""
# Changes to archive.db's layout after SCHEMA (version 1), in order (plugin_api.open_store): MIGRATIONS[n]
# brings an archive from version n + 1 to n + 2. SCHEMA always shows the newest layout, for new archives.
# Append; never change one that shipped: the archive is the only copy of mail deleted on the server.


def _hidden_check(conn) -> None:
    """Version 2: texts.hidden_check, what extract's structural check said of a PDF (clean, hidden, undecided;
    NULL: not looked at yet, which the second pass catches up on), and the two triggers that go by it."""
    conn.execute("ALTER TABLE texts ADD COLUMN hidden_check TEXT")
    conn.execute("DROP TRIGGER IF EXISTS texts_changed")  # SCHEMA makes them again, as they are now
    conn.execute("DROP TRIGGER IF EXISTS texts_checked")


MIGRATIONS: list = [_hidden_check]


def attachment_parts(message) -> list[tuple[int, str, str, bytes]]:
    """(n, name, content type, bytes) for each attachment, numbered from 1 in the message's own order, so
    mail:<message-id>#<n> names one even when two share a file name or one has none."""
    out = []
    for n, part in enumerate(message.iter_attachments(), 1):
        ctype = part.get_content_type()
        try:
            content = part.get_payload(decode=True)
        except Exception:  # noqa: BLE001 - a broken part: no bytes
            content = b""
        if content is None:  # an attached message (message/rfc822): its raw form
            content = part.get_payload(0).as_bytes() if part.is_multipart() else b""
        try:
            name = part.get_filename()
        except Exception:  # noqa: BLE001 - a malformed header
            name = None
        name = name or f"attachment-{n}{mimetypes.guess_extension(ctype) or '.bin'}"
        out.append((n, name, ctype, content))
    return out


def is_pdf(name: str | None, ctype: str | None) -> bool:
    return ctype == "application/pdf" or (name or "").lower().endswith(".pdf")


def unchecked(t, checking: bool) -> bool:
    """Whether a stored attachment (a texts row) is a PDF whose text nothing has cleared yet: the structural
    check didn't find it clean and the OCR check hasn't read it. Search gives no passage of it and
    mail.attachment no text, as a live read never gives a PDF's text unchecked."""
    return (checking and not t["hidden"] and t["state"] in ("check", "ocr") and t["attempts"] < 3
            and t["hidden_check"] != "clean" and is_pdf(t["name"], t["type"]))


def flags_of(raw) -> list[str]:
    return sorted(f.decode() if isinstance(f, bytes) else str(f) for f in raw if f not in (b"\\Recent", "\\Recent"))


def body_text(message) -> tuple[str, str | None]:
    """(text of the message body, what sanitizing removed or None)."""
    part = message.get_body(preferencelist=("plain", "html"))
    if part is None:
        return "", None
    try:
        body = part.get_content()
    except Exception:  # noqa: BLE001 - an unknown charset, a broken encoding
        body = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
    if part.get_content_type() == "text/html":
        body, report = html_to_text(body)
        return body, describe(report)
    return body, None


def clean_mid(value) -> str:
    return str(value or "").strip().strip("<>").strip()


def _addresses(header_value) -> tuple[list[str], list[str]]:
    """(addresses, display names) from a header value."""
    pairs = getaddresses([str(header_value or "")])
    return [a.lower() for _, a in pairs if a and "@" in a], [n for n, _ in pairs if n]


def _header(message, name: str) -> str:
    try:
        return str(message.get(name, "") or "")
    except Exception:  # noqa: BLE001 - a malformed header
        return ""


class Archive:
    def __init__(self, plugin):
        self.plugin = plugin
        self.ctx = plugin.ctx
        mode = str(plugin.config.get("archive") or "index").lower()
        if mode not in MODES:
            raise PluginError(f"{self.ctx.instance}: archive must be one of {', '.join(MODES)}, not {mode}")
        self.mode = mode
        self.root = Path(self.ctx.data_dir) / "archive"
        self.lock = threading.RLock()        # the database connection
        self.syncing = threading.Lock()      # one sync at a time in this process (a file lock across processes)
        self._db: sqlite3.Connection | None = None
        self._size = (0.0, 0)                # (when measured, bytes on disk)

    @property
    def on(self) -> bool:
        return self.mode != "off"

    # ------------------------------------------------------------------ storage

    @property
    def db(self) -> sqlite3.Connection:
        if self._db is None:
            with self.lock:
                if self._db is None:
                    self._db = self._open()
        return self._db

    def _open(self) -> sqlite3.Connection:
        """archive.db at the layout this code knows (plugin_api.open_store, MIGRATIONS). An archive made for
        another mailbox (the plugin's login or server changed) is set aside whole, as
        archive.other-mailbox-<when>, and a new one begins: one mailbox's mail never shows as another's."""
        mailbox = self.plugin.mailbox()
        for attempt in (1, 2):
            self.root.mkdir(parents=True, exist_ok=True)
            try:
                conn = open_store(self.root / "archive.db", SCHEMA, MIGRATIONS, belongs_to=mailbox,
                                  check_same_thread=False, timeout=30)
                break
            except StoreOfAnother as exc:
                if attempt == 2:
                    raise
                kept = set_aside(self.root, "other-mailbox")
                self.ctx.log.warning("archive: %s; it is kept in %s, and a new archive begins", exc, kept.name)
        if self.mode == "full":
            (self.root / "eml").mkdir(exist_ok=True)
            (self.root / "eml" / ".immutable").touch()
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        # which archive a feed's cursor belongs to: one made anew (its folder deleted) counts from 0 again
        conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('feed_id', ?)",
                     (json.dumps(secrets.token_hex(8)),))
        conn.commit()
        return conn

    @contextmanager
    def tx(self):
        with self.lock:
            try:
                yield self.db
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    def query(self, sql: str, args=()) -> list[sqlite3.Row]:
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def meta(self, key: str, value=None):
        if value is None:
            row = self.query("SELECT value FROM meta WHERE key=?", (key,))
            return json.loads(row[0]["value"]) if row else None
        with self.tx() as db:
            db.execute("INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       (key, json.dumps(value)))

    def close(self) -> None:
        with self.lock:
            if self._db is not None:
                self._db.close()
                self._db = None

    # ------------------------------------------------------------------ sync

    @contextmanager
    def _sync_lock(self):
        """None when another sync runs (here, or in another process such as doorman-admin job)."""
        if not self.syncing.acquire(blocking=False):
            yield None
            return
        handle = None
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            handle = open(self.root / "sync.lock", "w")
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                yield None
                return
            yield handle
        finally:
            if handle is not None:
                handle.close()
            self.syncing.release()

    def run(self, budget: float, background: bool = True) -> dict:
        """One slice of syncing: new mail and changes in every folder, then backfill and (`background`) the
        OCR pass while time is left. Returns the status the owner app shows. Doorman pulls the search feed
        after each run."""
        if not self.on:
            return {"summary": "archive off"}
        deadline = _now() + budget
        with self._sync_lock() as held:
            if held is None:
                return {**self.status(), "busy": True}
            stats = {"new": 0, "backfilled": 0, "deleted": 0, "read": 0}
            with self.plugin.imap() as client:
                folders = self.folders(client)
                removed: set[str] = set()
                for name in folders:
                    stats["new"] += self.refresh(client, name, removed, deadline)
                stats["deleted"] = self.settle(removed, set(folders))
                stats["outside_window"] = self.apply_window()
                for name in folders:
                    if _now() > deadline - 5:
                        break
                    stats["backfilled"] += self.backfill(client, name, deadline)
            if background:
                stats["read"] = self.second_pass(deadline)
        status = self.status()
        status["last_run"] = stats
        # still downloading or reading scans: the worker comes back soon instead of in every_minutes
        status["more"] = bool(not status.get("complete") or
                              (stats["read"] and status.get("attachments_waiting_for_ocr")))
        return status

    def folders(self, client) -> list[str]:
        skip = {str(s).lower() for s in (self.plugin.config.get("archive_skip_folders") or [])}
        skip |= SKIP_NAMES | {self.plugin.agent_trash_name().lower()}
        names = []
        for flags, _, name in client.list_folders():
            if any(f in flags for f in SKIP_FLAGS) or name.lower() in skip:
                continue
            names.append(name)
        return sorted(names, key=lambda n: (n.upper() != "INBOX", n.lower()))

    def refresh(self, client, name: str, removed: set[str], deadline: float) -> int:
        """New mail in one folder, what left it, and (every half hour) its flags. Returns how many messages
        arrived."""
        info = client.select_folder(name, readonly=True)
        validity = int(info[b"UIDVALIDITY"])
        row = self.query("SELECT * FROM folders WHERE name=?", (name,))
        row = row[0] if row else None
        uids = sorted(client.search(["ALL"]))
        top_now = uids[-1] if uids else 0
        if row is None or row["uidvalidity"] != validity:
            # a new folder, or one the server rebuilt: its UIDs mean nothing any more. Messages stay; they
            # are found again by Message-ID, without fetching them, as the backfill comes past.
            with self.tx() as db:
                removed.update(r["mid"] for r in db.execute("SELECT mid FROM locations WHERE folder=?", (name,)))
                db.execute("DELETE FROM locations WHERE folder=?", (name,))
                db.execute("INSERT INTO folders(name, uidvalidity, top, bottom, flags_checked, complete) "
                           "VALUES(?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET uidvalidity=excluded.uidvalidity, "
                           "top=excluded.top, bottom=excluded.bottom, flags_checked=excluded.flags_checked, "
                           "complete=excluded.complete",
                           (name, validity, top_now, top_now + 1, time.time(), int(not uids)))
            return 0
        # what left: UIDs we know in the range seen that the server no longer has
        present = set(uids)
        known = {r["uid"]: r["mid"] for r in self.query("SELECT uid, mid FROM locations WHERE folder=?", (name,))}
        gone = [uid for uid in known if uid not in present]
        if gone:
            with self.tx() as db:
                db.executemany("DELETE FROM locations WHERE folder=? AND uid=?", [(name, u) for u in gone])
            removed.update(known[u] for u in gone)
        # new mail, oldest first, so `top` only moves past what is stored
        new = [u for u in uids if u > row["top"]]
        done = self.ingest(client, name, new, deadline)
        if done:
            with self.tx() as db:
                db.execute("UPDATE folders SET top=? WHERE name=?", (max(done), name))
        # flags (read, flagged, labels): every half hour, one FETCH for the whole folder
        if time.time() - (row["flags_checked"] or 0) > FLAGS_EVERY and known:
            self.refresh_flags(client, name, sorted(u for u in known if u in present))
        return len(done)

    def refresh_flags(self, client, name: str, uids: list[int]) -> None:
        """Flags of the archived messages in a folder, FLAGS_BATCH UIDs per FETCH."""
        rows = []
        for i in range(0, len(uids), FLAGS_BATCH):
            data = client.fetch(uids[i:i + FLAGS_BATCH], ["FLAGS"])
            rows += [(json.dumps(flags_of(item.get(b"FLAGS") or ())), name, uid) for uid, item in data.items()]
        with self.tx() as db:
            db.executemany("UPDATE locations SET flags=? WHERE folder=? AND uid=?", rows)
            db.execute("UPDATE messages SET flags=(SELECT l.flags FROM locations l WHERE l.mid=messages.mid "
                       "AND l.folder=messages.folder) WHERE mid IN (SELECT mid FROM locations WHERE folder=?)",
                       (name,))
            db.execute("UPDATE folders SET flags_checked=? WHERE name=?", (time.time(), name))

    def settle(self, removed: set[str], archived: set[str]) -> int:
        """Messages that left a folder: still somewhere archived (a move) or deleted on the server."""
        count = 0
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.tx() as db:
            for mid in removed:
                where = db.execute("SELECT folder FROM locations WHERE mid=? ORDER BY folder", (mid,)).fetchall()
                if where:
                    db.execute("UPDATE messages SET folder=? WHERE mid=? AND folder NOT IN "
                               f"({','.join('?' * len(where))})", (where[0]["folder"], mid, *[w["folder"] for w in where]))
                else:
                    count += db.execute("UPDATE messages SET deleted_on_server=? WHERE mid=? AND deleted_on_server "
                                        "IS NULL", (now, mid)).rowcount
            # folders gone from the server (or newly skipped) take their messages with them
            for row in db.execute("SELECT name FROM folders").fetchall():
                if row["name"] not in archived:
                    mids = [r["mid"] for r in db.execute("SELECT mid FROM locations WHERE folder=?", (row["name"],))]
                    db.execute("DELETE FROM locations WHERE folder=?", (row["name"],))
                    db.execute("DELETE FROM folders WHERE name=?", (row["name"],))
                    for mid in mids:
                        if not db.execute("SELECT 1 FROM locations WHERE mid=?", (mid,)).fetchone():
                            count += db.execute("UPDATE messages SET deleted_on_server=? WHERE mid=? AND "
                                                "deleted_on_server IS NULL", (now, mid)).rowcount
        return count

    def cutoff(self) -> date | None:
        """archive_months: only the last N months are archived (unset or 0: everything)."""
        try:
            months = int(self.plugin.config.get("archive_months") or 0)
        except (TypeError, ValueError):
            raise PluginError(f"{self.ctx.instance}: archive_months must be a number of months") from None
        if months <= 0:
            return None
        today = datetime.now(timezone.utc).date()
        total = today.year * 12 + (today.month - 1) - months
        year, month = divmod(total, 12)
        day = min(today.day, 28)
        return date(year, month + 1, day)

    def apply_window(self) -> int:
        """Keep the archive to archive_months: drop what got older than that, and when the window grew (or
        was removed), walk every folder again so the backfill fetches what is now inside it (messages
        already archived cost only a header fetch). Returns how many messages were dropped."""
        cut = self.cutoff()
        current = cut.isoformat() if cut else None
        before = self.meta("window")
        if before is not None and before.get("cutoff") and (current is None or current < before["cutoff"]):
            with self.tx() as db:
                db.execute("UPDATE folders SET bottom=top+1, complete=0")
        if before is None or before.get("cutoff") != current:
            self.meta("window", {"cutoff": current})
        if cut is None:
            return 0
        limit = datetime(cut.year, cut.month, cut.day, tzinfo=timezone.utc).timestamp()
        dropped = 0
        while True:
            rows = self.query("SELECT n, mid, eml FROM messages WHERE ts < ? LIMIT 500", (limit,))
            if not rows:
                return dropped
            with self.tx() as db:
                for row in rows:  # each leaves a tombstone for the search feed (the messages_gone trigger)
                    db.execute("DELETE FROM texts WHERE mid=?", (row["mid"],))
                    db.execute("DELETE FROM locations WHERE mid=?", (row["mid"],))
                    db.execute("DELETE FROM messages WHERE n=?", (row["n"],))
            for row in rows:
                if row["eml"] and not self.query("SELECT 1 FROM messages WHERE eml=?", (row["eml"],)):
                    (self.root / row["eml"]).unlink(missing_ok=True)
            dropped += len(rows)

    def backfill(self, client, name: str, deadline: float) -> int:
        row = self.query("SELECT * FROM folders WHERE name=?", (name,))
        if not row or row[0]["complete"]:
            return 0
        row = row[0]
        client.select_folder(name, readonly=True)
        if row["bottom"] <= 1:
            older = []
        else:
            older = sorted((u for u in client.search(["UID", f"1:{row['bottom'] - 1}"]) if u < row["bottom"]),
                           reverse=True)
        cutoff = self.cutoff()
        if cutoff and older:
            keep = set(client.search(["UID", f"1:{row['bottom'] - 1}", "SINCE", cutoff]))
            older = [u for u in older if u in keep]
        if not older:
            with self.tx() as db:
                db.execute("UPDATE folders SET complete=1, bottom=1 WHERE name=?", (name,))
            return 0
        done = self.ingest(client, name, older, deadline)
        if done:
            with self.tx() as db:
                # newest first: everything from min(done) up is stored
                db.execute("UPDATE folders SET bottom=? WHERE name=?", (min(done), name))
                if len(done) == len(older):
                    db.execute("UPDATE folders SET complete=1 WHERE name=?", (name,))
        return len(done)

    def ingest(self, client, folder: str, uids: list[int], deadline: float) -> list[int]:
        """Store the messages at these UIDs (in this order) until the deadline; the UIDs done, a prefix of
        `uids`. A Message-ID already archived only gets a new location: no download."""
        done: list[int] = []
        for start in range(0, len(uids), HEADER_BATCH):
            if _now() > deadline:
                break
            chunk = uids[start:start + HEADER_BATCH]
            heads = client.fetch(chunk, ["FLAGS", "RFC822.SIZE", "INTERNALDATE",
                                         "BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]"])
            pending: list[tuple[int, list[str], int]] = []
            known = []
            for uid in chunk:
                item = heads.get(uid)
                if item is None:  # expunged meanwhile
                    continue
                flags = flags_of(item.get(b"FLAGS") or ())
                header = item.get(b"BODY[HEADER.FIELDS (MESSAGE-ID)]") or b""
                mid = clean_mid(email.message_from_bytes(header, policy=email.policy.default).get("Message-ID"))
                if mid and self.query("SELECT 1 FROM messages WHERE mid=?", (mid,)):
                    known.append((uid, mid, flags))
                else:
                    pending.append((uid, flags, int(item.get(b"RFC822.SIZE") or 0), item.get(b"INTERNALDATE")))
            self._place(folder, known)
            stored = {uid for uid, _, _ in known}
            # originals, several per FETCH up to FETCH_BYTES
            batch: list = []
            size = 0
            for entry in pending + [None]:
                if entry is not None and (not batch or size + entry[2] <= FETCH_BYTES):
                    batch.append(entry)
                    size += entry[2]
                    continue
                if batch:
                    if _now() > deadline:
                        break
                    bodies = client.fetch([e[0] for e in batch], ["BODY.PEEK[]"])
                    for uid, flags, _, internal in batch:
                        raw = (bodies.get(uid) or {}).get(b"BODY[]")
                        if raw is not None:
                            self.store(raw, folder, uid, flags, internal)
                        stored.add(uid)
                batch = [entry] if entry is not None else []
                size = entry[2] if entry is not None else 0
            # report only a prefix in the order asked, so top/bottom never skip a message
            for uid in chunk:
                if uid in stored or uid not in heads:
                    done.append(uid)
                else:
                    return done
        return done

    def _place(self, folder: str, found: list[tuple[int, str, list[str]]]) -> None:
        if not found:
            return
        with self.tx() as db:
            for uid, mid, flags in found:
                db.execute("INSERT OR REPLACE INTO locations(folder, uid, mid, flags) VALUES(?,?,?,?)",
                           (folder, uid, mid, json.dumps(flags)))
                db.execute("UPDATE messages SET deleted_on_server=NULL, folder=?, flags=? WHERE mid=? AND "
                           "(deleted_on_server IS NOT NULL OR folder IS NULL OR folder NOT IN "
                           "(SELECT folder FROM locations WHERE mid=? AND folder != ?))",
                           (folder, json.dumps(flags), mid, mid, folder))

    def store(self, raw: bytes, folder: str, uid: int, flags: list[str], internal=None) -> str:
        """Archive one message: metadata, text of body and attachments, the original in full mode."""
        sha = hashlib.sha256(raw).hexdigest()
        message = email.message_from_bytes(raw, policy=email.policy.default)
        mid = clean_mid(_header(message, "Message-ID")) or f"{sha[:32]}@archive.doorman"
        if self.query("SELECT 1 FROM messages WHERE mid=?", (mid,)):
            self._place(folder, [(uid, mid, flags)])
            return mid
        senders, sender_names = _addresses(_header(message, "From"))
        to, to_names = _addresses(_header(message, "To"))
        cc, cc_names = _addresses(_header(message, "Cc"))
        reply_to, _ = _addresses(_header(message, "Reply-To"))
        when = None
        try:
            when = parsedate_to_datetime(_header(message, "Date"))
        except (TypeError, ValueError, IndexError):
            when = None
        if when is None and isinstance(internal, datetime):
            when = internal
        if when is not None and when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        when = (when or datetime.now(timezone.utc)).astimezone(timezone.utc)
        security = self.plugin.from_security_sender({"from": senders})
        parts = attachment_parts(message)
        texts = []
        if security:
            texts.append((0, None, "text/plain", len(raw), "", None, None, None, None, None, "redacted", None))
        else:
            body, removed = body_text(message)
            texts.append((0, None, "text/plain", len(body), body[:TEXT_LIMIT], None, None, None, None, removed,
                          "done", None))
        for n, name, ctype, content in parts:
            if security:
                texts.append((n, name, ctype, len(content), "", None, None, None, None, None, "redacted", None))
                continue
            texts.append((n, name, ctype, len(content), *self.read_part(name, ctype, content)))
        eml = None
        if self.mode == "full":
            eml = self.save_original(sha, raw)
        attachments = [{"part": n, "name": name, "type": ctype, "size": len(content)}
                       for n, name, ctype, content in parts]
        subject = _header(message, "Subject")
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.tx() as db:
            db.execute("INSERT INTO messages(mid, subject, sender, sender_names, recipients, cc, recipient_names, "
                       "reply_to, date, ts, in_reply_to, refs, size, attachments, folder, flags, eml, security, added) "
                       "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (mid, subject, json.dumps(senders), json.dumps(sender_names), json.dumps(to), json.dumps(cc),
                        json.dumps(to_names + cc_names), json.dumps(reply_to), when.isoformat(timespec="seconds"),
                        when.timestamp(), clean_mid(_header(message, "In-Reply-To")) or None,
                        _header(message, "References") or None, len(raw), json.dumps(attachments), folder,
                        json.dumps(flags), eml, int(security), now))
            db.executemany("INSERT OR REPLACE INTO texts(mid, part, name, type, size, text, pages, ocr_pages, note, "
                           "hidden, sanitized, state, hidden_check) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           [(mid, *t) for t in texts])
            db.execute("INSERT OR REPLACE INTO locations(folder, uid, mid, flags) VALUES(?,?,?,?)",
                       (folder, uid, mid, json.dumps(flags)))
        return mid

    def read_part(self, name: str, ctype: str, content: bytes, ocr: bool = False, check: bool = False) -> tuple:
        """(text, pages, ocr_pages, note, hidden, sanitized, state, hidden_check) for one attachment. The first
        pass reads text layers only (cheap, no OCR model) and looks at a PDF's pages for hidden text
        (extract's structural check; `hidden_check` says clean, hidden or undecided); state 'ocr' asks the
        second pass to read scans (archive_ocr), 'check' to check a PDF for hidden text with OCR, the backstop
        for every PDF the first pass didn't find hiding text. The checks are the owner's (check_hidden_text),
        not tied to archive_ocr, which agents may switch off: until a PDF is found clean or OCR has checked it,
        search gives no passage of it, as mail.attachment never gives its text unchecked."""
        checking = self.checking()
        first = not ocr and not check
        found = self.ctx.extract_text(name, content, ctype, ocr=ocr, limit=TEXT_LIMIT,
                                      check_pdf=checking and ("fast" if first else True), background=True)
        if found.get("busy"):
            return "", None, None, None, None, None, "retry", None
        text = found.get("text") or ""
        report = dict(found.get("report") or {})
        hidden = report.pop("hidden_text", None)
        note = found.get("note")
        # a PDF the structural check couldn't look at (an extraction that failed) counts as undecided
        glance = (found.get("hidden_check") or "undecided") if checking and is_pdf(name, ctype) else None
        state = "done"
        if first:
            if self.ocr_wanted() and is_pdf(name, ctype) and note and "weren't read" in note:
                state = "ocr"
            elif self.ocr_wanted() and ctype.startswith("image/") and len(content) >= MIN_OCR_IMAGE:
                state = "ocr"
            elif checking and is_pdf(name, ctype) and text.strip() and not hidden:
                state = "check"
        return (text, found.get("pages"), json.dumps(found.get("ocr_pages") or []), note,
                json.dumps(hidden) if hidden else None, describe(report) or None, state, glance)

    def ocr_wanted(self) -> bool:
        return bool(self.plugin.config.get("archive_ocr", True))

    def checking(self) -> bool:
        """Whether PDFs are checked for hidden text (check_hidden_text, the owner's; default on)."""
        return bool(self.plugin.config.get("check_hidden_text", True))

    def _requeue_checks(self) -> None:
        """check_hidden_text switched on (or an archive from before the check was the owner's alone): every
        PDF with text is checked again, except one found hiding text, which stays held; switched off: none
        waits for it."""
        checking = self.checking()
        if self.meta("checks") == checking:
            return
        with self.tx() as db:
            if checking:
                where = ("state='done' AND part > 0 AND coalesce(text, '') != '' AND hidden IS NULL AND "
                         "(type='application/pdf' OR lower(name) LIKE '%.pdf')")
                mids = db.execute(f"SELECT DISTINCT mid FROM texts WHERE {where}").fetchall()
                db.execute(f"UPDATE texts SET state='check', attempts=0 WHERE {where}")
                # the search feed hands them over again, as waiting for the check (one seq each, as the triggers do)
                for row in mids:
                    db.execute("UPDATE meta SET value = value + 1 WHERE key = 'seq'")
                    db.execute("UPDATE messages SET seq = (SELECT value FROM meta WHERE key = 'seq') WHERE mid=?",
                               (row[0],))
            else:  # texts_checked hands each over again
                db.execute("UPDATE texts SET state='done' WHERE state='check'")
        self.meta("checks", checking)

    def save_original(self, sha: str, raw: bytes) -> str:
        rel = f"eml/{sha[:2]}/{sha}.eml.gz"
        path = self.root / rel
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            with gzip.open(tmp, "wb", compresslevel=6) as fh:
                fh.write(raw)
            os.replace(tmp, path)
        return rel

    def original(self, mid: str) -> bytes | None:
        rows = self.query("SELECT eml FROM messages WHERE mid=?", (mid,))
        if not rows or not rows[0]["eml"]:
            return None
        try:
            with gzip.open(self.root / rows[0]["eml"], "rb") as fh:
                return fh.read()
        except OSError:
            return None

    # ------------------------------------------------------------------ the second pass: OCR, hidden text

    def second_pass(self, deadline: float) -> int:
        """Scanned attachments and unchecked PDFs, newest first, while the agent leaves the extractor alone.
        Before them: text layers the first pass couldn't read, then PDFs the structural check hasn't looked
        at (archived before it, or while check_hidden_text was off), both quick."""
        self._requeue_checks()
        count = 0
        while _now() < deadline - 30:
            rows = self.query("SELECT t.mid, t.part, t.name, t.type, t.state, t.hidden_check FROM texts t JOIN "
                              "messages m ON m.mid=t.mid WHERE t.state IN ('retry', 'ocr', 'check') AND "
                              "t.attempts < 3 ORDER BY t.state != 'retry', t.hidden_check IS NOT NULL OR t.state "
                              "NOT IN ('ocr', 'check') OR NOT (coalesce(t.type, '')='application/pdf' OR "
                              "lower(coalesce(t.name, '')) LIKE '%.pdf'), m.ts DESC LIMIT 1")
            if not rows:
                break
            row = rows[0]
            with self.tx() as db:
                db.execute("UPDATE texts SET attempts=attempts+1 WHERE mid=? AND part=?", (row["mid"], row["part"]))
            content = self.part_bytes(row["mid"], row["part"])
            if content is None:
                with self.tx() as db:
                    db.execute("UPDATE texts SET state='done', note=coalesce(note || '; ', '') || ? WHERE mid=? AND "
                               "part=?", ("the original was gone before its scans could be read", row["mid"],
                                          row["part"]))
                continue
            # 'retry': the first pass found the extractor busy and does its text-layer read now, and so does a
            # PDF the structural check hasn't looked at; 'ocr' reads scans (and checks), 'check' only checks
            glance = self.checking() and row["hidden_check"] is None and is_pdf(row["name"], row["type"])
            first = row["state"] == "retry" or glance
            result = self.read_part(row["name"] or "", row["type"] or "", content,
                                    ocr=row["state"] == "ocr" and self.ocr_wanted() and not first, check=not first)
            if result[6] == "retry":
                break  # the agent is reading: next run
            text, pages, ocr_pages, note, hidden, sanitized, state, hidden_check = result
            state = state if first else "done"
            with self.tx() as db:  # new text, hidden text found, or found clean: the search feed has it again
                db.execute("UPDATE texts SET text=?, pages=?, ocr_pages=?, note=?, hidden=?, sanitized=?, "
                           "state=?, hidden_check=?, attempts=CASE WHEN ? THEN 0 ELSE attempts END "
                           "WHERE mid=? AND part=?",
                           (text, pages, ocr_pages, note, hidden, sanitized, state, hidden_check,
                            int(first and state != "done"), row["mid"], row["part"]))
            count += 1
        return count

    def part_bytes(self, mid: str, part: int) -> bytes | None:
        raw = self.original(mid)
        if raw is None:
            raw = self.fetch_live(mid)
        if raw is None:
            return None
        message = email.message_from_bytes(raw, policy=email.policy.default)
        found = next((p for p in attachment_parts(message) if p[0] == part), None)
        return found[3] if found else None

    def fetch_live(self, mid: str) -> bytes | None:
        """The original from the server, where the archive last saw it."""
        try:
            with self.plugin.imap() as client:
                for row in self.query("SELECT folder, uid FROM locations WHERE mid=?", (mid,)):
                    client.select_folder(row["folder"], readonly=True)
                    raw = (client.fetch([row["uid"]], ["BODY.PEEK[]"]).get(row["uid"]) or {}).get(b"BODY[]")
                    if raw is not None:
                        return raw
        except Exception:  # noqa: BLE001 - offline, login expired: try again next run
            return None
        return None

    # ------------------------------------------------------------------ what Doorman itself changed

    def touch(self, state: dict | None) -> None:
        """A move, label or delete Doorman just made: the archive shows it now, not at the next sync."""
        if not self.on or not state or not state.get("message_id"):
            return
        with self.tx() as db:
            db.execute("UPDATE messages SET folder=?, flags=? WHERE mid=?",
                       (state["folder"], json.dumps(state.get("flags") or []), state["message_id"]))

    # ------------------------------------------------------------------ the search feed

    def feed(self, cursor: str | None, budget: float) -> dict:
        """What changed since `cursor` for Doorman's search index (plugin.index_feed): the messages whose
        `seq` is past it, FEED_BATCH at a time in the order they changed, and the tombstones of messages
        dropped from the archive meanwhile. The cursor is "<feed_id>:<seq>"; one from another archive, or
        from further than this one counted (archive.db put back from a backup), starts over with `reset`:
        everything comes again, and what doesn't leaves search once that's through. With the archive off
        there's nothing."""
        if not self.on:
            return {"items": [], "complete": True, "cursor": None}
        deadline = time.monotonic() + max(1.0, budget - 5)
        feed_id, counted = self.meta("feed_id"), int(self.meta("seq") or 0)
        mine, _, seen = (cursor or "").partition(":")
        reset = bool(cursor) and not (mine == feed_id and seen.isdigit() and int(seen) <= counted)
        start = int(seen) if cursor and not reset else 0
        changes = self.query("SELECT seq, mid, 0 AS gone FROM messages WHERE seq > ? UNION ALL "
                             "SELECT seq, mid, 1 AS gone FROM removed WHERE seq > ? ORDER BY seq LIMIT ?",
                             (start, start, FEED_BATCH))
        items, removed, last, size = [], [], start, 0
        for change in changes:
            if (time.monotonic() > deadline or size > FEED_CHARS) and (items or removed):
                break
            if change["gone"]:
                removed.append(change["mid"])
            elif (row := self.message(change["mid"])) is not None:  # one at a time: attachments can be long
                texts = self.query("SELECT part, name, type, text, hidden, state, attempts, hidden_check FROM texts "
                                   "WHERE mid=? ORDER BY part", (row["mid"],))
                items.append(self.feed_item(row, texts))
                size += sum(len(p["text"]) for p in items[-1]["parts"])
            last = change["seq"]
        more = bool(self.query("SELECT 1 FROM messages WHERE seq > ? UNION ALL SELECT 1 FROM removed WHERE seq > ? "
                               "LIMIT 1", (last, last)))
        out = {"items": items, "removed": removed, "cursor": f"{feed_id}:{last}", "more": more}
        if reset:
            out["reset"] = True
        return out

    def feed_item(self, row, texts: list) -> dict:
        """One message as the search index takes it: the body as part 0, each attachment with text as part n
        (its number in mail.read and mail:<id>#<n>). Mail from a security sender (by the setting as it is
        now, as mail.read goes by) gives only its subject and addresses, as it does to mail.read. A PDF's part
        carries what the hidden-text checks found (`hidden_text`: the guard holds back a hit whose passage is
        from it, as it holds back reading that PDF) or that neither has cleared it yet (`unchecked`: the
        structural check couldn't decide and OCR hasn't read it; no passage from it until then)."""
        mid = row["mid"]
        senders, to, cc = (json.loads(row[k] or "[]") for k in ("sender", "recipients", "cc"))
        attachments = [a["name"] for a in json.loads(row["attachments"] or "[]")]
        fields = {"id": mid, "subject": row["subject"] or "", "from": senders, "to": to, "folder": row["folder"],
                  "unread": "\\Seen" not in json.loads(row["flags"] or "[]"), "attachments": attachments}
        if row["deleted_on_server"]:
            fields["deleted_on_server"] = row["deleted_on_server"]
        security = row["security"] or self.plugin.from_security_sender({"from": senders})
        checking = self.checking()
        parts = []
        for t in [] if security else texts:
            text = t["text"] or ""
            if t["part"] != 0 and not text.strip():
                continue
            part = {"part": t["part"], "name": t["name"], "text": text}
            if t["hidden"]:
                part["hidden_text"] = json.loads(t["hidden"])
            elif unchecked(t, checking):
                part["unchecked"] = True
            parts.append(part)
        return {"key": mid, "ref": f"{self.ctx.instance}:{mid}", "kind": "mail", "title": row["subject"] or "",
                "date": row["date"], "from": ", ".join(json.loads(row["sender_names"] or "[]") + senders),
                "to": ", ".join(json.loads(row["recipient_names"] or "[]") + to + cc), "in": row["folder"],
                "has_attachment": bool(attachments), "parts": parts, "same": f"mid:{mid}", "fields": fields}

    # ------------------------------------------------------------------ status and reads

    def coverage(self) -> dict:
        folders = self.query("SELECT name, complete FROM folders")
        counts = self.query("SELECT count(*) AS n, min(date) AS oldest FROM messages")[0]
        pending = self.query("SELECT count(*) AS n FROM texts WHERE state IN ('ocr', 'retry', 'check') "
                             "AND attempts < 3")[0]["n"]
        out = {"messages": counts["n"], "complete": bool(folders) and all(f["complete"] for f in folders),
               "oldest": (counts["oldest"] or "")[:10] or None}
        cut = self.cutoff()
        if cut:
            out["window"] = f"the last {self.plugin.config.get('archive_months')} months (since {cut})"
        if not out["complete"]:
            out["incomplete_folders"] = [f["name"] for f in folders if not f["complete"]]
        if pending:
            out["attachments_waiting_for_ocr"] = pending
        return out

    def status(self) -> dict:
        if not self.on:
            return {"summary": "archive off"}
        cover = self.coverage()
        if _now() - self._size[0] > 3600 or not self._size[1]:
            total = sum(p.stat().st_size for p in self.root.rglob("*") if p.is_file()) if self.root.exists() else 0
            self._size = (_now(), total)
        size = self._size[1]
        state = "complete" if cover["complete"] else "downloading"
        summary = f"{cover['messages']} messages archived ({self.mode}, {size / 1e6:.0f} MB), {state}"
        if cover.get("window"):
            summary += f", {cover['window']}"
        elif cover.get("oldest"):
            summary += f", back to {cover['oldest']}"
        if cover.get("attachments_waiting_for_ocr"):
            summary += f"; {cover['attachments_waiting_for_ocr']} attachments wait for OCR"
        return {"summary": summary, "mode": self.mode, "bytes": size, **cover}

    def message(self, mid: str) -> dict | None:
        rows = self.query("SELECT * FROM messages WHERE mid=?", (mid,))
        return dict(rows[0]) if rows else None

    def sent_to(self, folder: str, addresses: list[str], own: set[str], limit: int = 20) -> dict[str, dict]:
        """Mail in `folder` (the Sent folder) from one of the owner's own addresses to each address (To or
        Cc), newest first: {address: {"messages": [{"id", "date"}]}}. For the recipient check
        (plugin.known_recipients); one indexed lookup of the folder per address."""
        found = {}
        for address in addresses:
            like = "%" + address.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            rows = self.query(
                "SELECT m.mid, m.date, m.sender, m.recipients, m.cc FROM messages m WHERE m.mid IN "
                "(SELECT mid FROM locations WHERE folder=?) AND (m.recipients LIKE ? ESCAPE '\\' "
                "OR m.cc LIKE ? ESCAPE '\\') ORDER BY m.ts DESC LIMIT ?", (folder, like, like, limit))
            messages = [{"id": r["mid"], "date": r["date"]} for r in rows
                        if address in json.loads(r["recipients"] or "[]") + json.loads(r["cc"] or "[]")
                        and own & set(json.loads(r["sender"] or "[]"))]
            if messages:
                found[address] = {"messages": messages}
        return found

    def texts(self, mid: str) -> dict[int, dict]:
        return {r["part"]: dict(r) for r in self.query("SELECT * FROM texts WHERE mid=?", (mid,))}

    def state_of(self, row: dict) -> dict:
        """A stored message in the shape plugin.state() gives for one on the server."""
        return {"message_id": row["mid"], "folder": row["folder"], "subject": row["subject"] or "",
                "from": json.loads(row["sender"] or "[]"), "reply_to": json.loads(row["reply_to"] or "[]"),
                "to": json.loads(row["recipients"] or "[]"), "date": row["date"],
                "flags": json.loads(row["flags"] or "[]")}
