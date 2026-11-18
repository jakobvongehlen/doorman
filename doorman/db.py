"""SQLite storage. One file, WAL mode, one lock for writes.

sessions, tasks and routines keep their plugin_allowlist and read_only columns (tasks also auto_apply) so older
databases still open, but nothing reads or writes them since 2026-11-07: what an agent may do is set in each
plugin's settings only."""

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from . import clock

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS agent_keys (
    id INTEGER PRIMARY KEY, name TEXT, token_hash TEXT UNIQUE, role TEXT,
    created TEXT, revoked INTEGER DEFAULT 0, third_party_at TEXT, private_at TEXT);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY, key_id INTEGER, task_id INTEGER, created TEXT,
    read_third_party INTEGER DEFAULT 0, read_private INTEGER DEFAULT 0,
    plugin_allowlist TEXT, read_only INTEGER DEFAULT 0, killed INTEGER DEFAULT 0);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY, text TEXT, origin TEXT, trusted INTEGER, status TEXT,
    created TEXT, due TEXT, claimed_by TEXT, report TEXT, auto_apply INTEGER DEFAULT 0,
    plugin_allowlist TEXT, read_only INTEGER DEFAULT 0, source_ref TEXT);

CREATE TABLE IF NOT EXISTS journal (
    id INTEGER PRIMARY KEY, ts TEXT, kind TEXT, session_id TEXT, task_id INTEGER,
    changeset_id INTEGER, plugin TEXT, tool TEXT, args TEXT, tier TEXT, decision TEXT,
    checks TEXT, status TEXT, object_ref TEXT, before TEXT, after TEXT, result TEXT,
    error TEXT, summary TEXT, reverts INTEGER, reverted_by INTEGER,
    parent_hash TEXT, hash TEXT);
CREATE INDEX IF NOT EXISTS journal_task ON journal(task_id);
CREATE INDEX IF NOT EXISTS journal_object ON journal(plugin, object_ref);
-- the worker looks for approved sends to run and unknown ones to check every few seconds (sends.py)
CREATE INDEX IF NOT EXISTS journal_status ON journal(status);

CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY, journal_ids TEXT, changeset_id INTEGER, payload_hash TEXT,
    nonce TEXT, reasons TEXT, status TEXT, created TEXT, expires TEXT, decided TEXT,
    credential_id TEXT);

CREATE TABLE IF NOT EXISTS changesets (
    id INTEGER PRIMARY KEY, title TEXT, task_id INTEGER, session_id TEXT, actions TEXT,
    preview TEXT, status TEXT, comment TEXT, created TEXT, result TEXT);

CREATE TABLE IF NOT EXISTS trust (
    id INTEGER PRIMARY KEY, kind TEXT, value TEXT, label TEXT, created TEXT,
    UNIQUE(kind, value));

CREATE TABLE IF NOT EXISTS provenance (
    id INTEGER PRIMARY KEY, session_id TEXT, kind TEXT, value TEXT, origin TEXT,
    trust TEXT, ts TEXT);
CREATE INDEX IF NOT EXISTS provenance_value ON provenance(value);

CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY, source TEXT, data TEXT, session_id TEXT, created TEXT);
CREATE INDEX IF NOT EXISTS records_source ON records(source);

-- questions an agent asks the reader about one item (doorman ask, questions.py); the answer is JSON in a
-- fixed form (structure.ANSWER_SCHEMA), error one of structure.ANSWER_ERRORS
CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY, key_id INTEGER, session_id TEXT, ref TEXT, question TEXT, status TEXT,
    created TEXT, claimed_by INTEGER, lease_until TEXT, answered TEXT, answer TEXT, error TEXT);
CREATE INDEX IF NOT EXISTS questions_status ON questions(status);

-- questions an agent asks the owner (doorman ask-owner, owner_questions.py): status open, answered,
-- dismissed or expired; options a JSON list; answer the owner's own text
CREATE TABLE IF NOT EXISTS owner_questions (
    id INTEGER PRIMARY KEY, key_id INTEGER, session_id TEXT, task_id INTEGER, question TEXT, options TEXT,
    status TEXT, created TEXT, expires TEXT, answered TEXT, answer TEXT);
CREATE INDEX IF NOT EXISTS owner_questions_status ON owner_questions(status);

CREATE TABLE IF NOT EXISTS routines (
    id INTEGER PRIMARY KEY, name TEXT, cron TEXT, task_text TEXT, plugin_allowlist TEXT,
    read_only INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1, last_run TEXT);

CREATE TABLE IF NOT EXISTS triggers (
    id INTEGER PRIMARY KEY, name TEXT, plugin TEXT, event TEXT, match TEXT,
    task_text TEXT, enabled INTEGER DEFAULT 1);

-- what plugins reported (new mail, a message, an entry starting soon), for agents polling GET /v1/events.
-- AUTOINCREMENT: ids never come back after pruning, so an agent's cursor stays valid
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, plugin TEXT, type TEXT, ref TEXT, data TEXT);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_ref ON events(ref);

-- Doorman's own events (plugin NULL in `events`: an approval decided, a send's result, a task...) and the
-- keys each is for (feed.py)
CREATE TABLE IF NOT EXISTS event_keys (event_id INTEGER, key_id INTEGER, PRIMARY KEY(key_id, event_id));

-- each agent key's place in the feed: the newest event id it acknowledged, and the capabilities version it
-- was last told about (feed.py)
CREATE TABLE IF NOT EXISTS agent_feed (key_id INTEGER PRIMARY KEY, cursor INTEGER, caps_version TEXT, updated TEXT);

CREATE TABLE IF NOT EXISTS plugin_state (
    name TEXT PRIMARY KEY, enabled INTEGER, read_only INTEGER DEFAULT 0,
    disabled_tools TEXT, cursor TEXT);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id TEXT PRIMARY KEY, public_key BLOB, sign_count INTEGER, label TEXT, created TEXT);

CREATE TABLE IF NOT EXISTS owner_sessions (token_hash TEXT PRIMARY KEY, created TEXT, expires TEXT);

CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY, purpose TEXT, challenge BLOB, created TEXT, ref TEXT);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY, ts TEXT, title TEXT, message TEXT, url TEXT, delivered INTEGER);

CREATE TABLE IF NOT EXISTS push_subscriptions (
    id INTEGER PRIMARY KEY, endpoint TEXT UNIQUE, p256dh TEXT, auth TEXT, label TEXT, created TEXT,
    last_ok TEXT, failures INTEGER DEFAULT 0, last_error TEXT);

CREATE TABLE IF NOT EXISTS push_gone (endpoint TEXT PRIMARY KEY, ts TEXT);

-- devices that logged out (a hash of their push endpoint, the passkey they used): the same browser logging in
-- again is no new device (notify.py)
CREATE TABLE IF NOT EXISTS push_logged_out (endpoint_hash TEXT PRIMARY KEY, credential_id TEXT, ts TEXT);

CREATE TABLE IF NOT EXISTS plugin_instances (
    name TEXT PRIMARY KEY, type TEXT, config TEXT, no_approval INTEGER DEFAULT 0, created TEXT);

-- the Linux user each plugin runs as when Doorman starts as root (privsep.py); kept for good, so a
-- plugin's folder stays its own across restarts and a re-added plugin gets its old user back
CREATE TABLE IF NOT EXISTS plugin_users (name TEXT PRIMARY KEY, uid INTEGER UNIQUE NOT NULL);

CREATE TABLE IF NOT EXISTS reads (
    id INTEGER PRIMARY KEY, ts TEXT, key_id INTEGER, key_name TEXT, session_id TEXT, task_id INTEGER,
    name TEXT, params TEXT, trust TEXT, items INTEGER, labels TEXT, status TEXT, error TEXT);
CREATE INDEX IF NOT EXISTS reads_ts ON reads(ts);
CREATE INDEX IF NOT EXISTS reads_task ON reads(task_id);

CREATE TABLE IF NOT EXISTS pseudonyms (token TEXT PRIMARY KEY, original TEXT, label TEXT, created TEXT);
-- placeholders a reversible write turned back into text: that text stays hidden wherever an agent meets it
CREATE TABLE IF NOT EXISTS pseudonyms_restored (token TEXT PRIMARY KEY, created TEXT);

CREATE TABLE IF NOT EXISTS attention (
    id INTEGER PRIMARY KEY, kind TEXT, ref TEXT, title TEXT, detail TEXT, url TEXT, created TEXT,
    resolved TEXT, UNIQUE(kind, ref));

-- the injection guard (guard.py): one score per text and model, and the texts it held back
CREATE TABLE IF NOT EXISTS scans (
    sha256 TEXT, model TEXT, score REAL, start INTEGER, end INTEGER, ts TEXT, PRIMARY KEY(sha256, model));

CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY, sha256 TEXT UNIQUE, source TEXT, ref TEXT, label TEXT, sender TEXT, score REAL,
    excerpt TEXT, status TEXT, created TEXT, decided TEXT);
CREATE INDEX IF NOT EXISTS quarantine_ref ON quarantine(ref);

-- files an agent made, to attach by upload:<sha256>; only the key that uploaded one can use it
CREATE TABLE IF NOT EXISTS uploads (
    sha256 TEXT, key_id INTEGER, name TEXT, size INTEGER, created TEXT, last_used TEXT,
    PRIMARY KEY(sha256, key_id));

CREATE TABLE IF NOT EXISTS mcp_servers (
    instance TEXT PRIMARY KEY, url TEXT, title TEXT, version TEXT, auth TEXT, synced TEXT, error TEXT);

-- network watch (egress/service.py): what agents read, as fingerprints (egress_prints.hash, from
-- egress.fingerprint), so the proxy's leak check can tell Doorman's data in a request without seeing it
-- (digest: a hash of the text, so reading the same thing again adds nothing; key_id NULL: a trigger's task)
CREATE TABLE IF NOT EXISTS egress_sources (
    id INTEGER PRIMARY KEY, key_id INTEGER, task_id INTEGER, ts TEXT, name TEXT, label TEXT, digest TEXT);
CREATE INDEX IF NOT EXISTS egress_sources_ts ON egress_sources(ts);
CREATE TABLE IF NOT EXISTS egress_prints (hash INTEGER, source_id INTEGER);
CREATE INDEX IF NOT EXISTS egress_prints_hash ON egress_prints(hash);
CREATE INDEX IF NOT EXISTS egress_prints_source ON egress_prints(source_id);

-- every connection the proxy saw, as it reported it (leak and process are JSON)
CREATE TABLE IF NOT EXISTS egress_log (
    id INTEGER PRIMARY KEY, ts TEXT, client_ip TEXT, key_id INTEGER, task_id INTEGER, kind TEXT, host TEXT,
    ip TEXT, port INTEGER, method TEXT, path TEXT, status INTEGER, bytes_up INTEGER, bytes_down INTEGER,
    decision TEXT, rule TEXT, detail TEXT, leak TEXT, process TEXT, duration_ms INTEGER, scanned INTEGER);
CREATE INDEX IF NOT EXISTS egress_log_ts ON egress_log(ts);
CREATE INDEX IF NOT EXISTS egress_log_key ON egress_log(key_id);
CREATE INDEX IF NOT EXISTS egress_log_task ON egress_log(task_id);

-- an agent asks for network access (doorman egress request): status open, granted, denied or expired; scope
-- once, task or always once granted
CREATE TABLE IF NOT EXISTS egress_requests (
    id INTEGER PRIMARY KEY, key_id INTEGER, session_id TEXT, task_id INTEGER, target TEXT, reason TEXT,
    status TEXT, scope TEXT, created TEXT, expires TEXT, decided TEXT);
CREATE INDEX IF NOT EXISTS egress_requests_status ON egress_requests(status);

-- the owner's exceptions: "Allow once" (an hour) and "For this task" (until the task ends, at most a day)
CREATE TABLE IF NOT EXISTS egress_exemptions (
    id INTEGER PRIMARY KEY, target TEXT, scope TEXT, task_id INTEGER, key_id INTEGER, request_id INTEGER,
    created TEXT, expires TEXT);

-- the agent's tool calls as its hooks report them (doorman activity): what ties a connection to a call
CREATE TABLE IF NOT EXISTS agent_activity (
    id INTEGER PRIMARY KEY, key_id INTEGER, session_id TEXT, task_id INTEGER, call_id TEXT, tool TEXT,
    summary TEXT, started TEXT, ended TEXT, status TEXT);
CREATE INDEX IF NOT EXISTS agent_activity_key ON agent_activity(key_id, started);

-- which agent keys called Doorman from which address, and when last: the proxy knows a connection only by its
-- source IP (kept a day)
CREATE TABLE IF NOT EXISTS agent_addresses (ip TEXT, key_id INTEGER, seen TEXT, PRIMARY KEY(ip, key_id));

-- the API keys seen on requests to model providers (no_scan hosts), as the proxy's hash of the header: a
-- second one for a host may be someone else's account
CREATE TABLE IF NOT EXISTS egress_model_keys (
    host TEXT, auth_hash TEXT, first_seen TEXT, last_seen TEXT, count INTEGER, PRIMARY KEY(host, auth_hash));

CREATE TABLE IF NOT EXISTS mcp_tools (
    instance TEXT, name TEXT, spec TEXT, hint_read INTEGER, first_read INTEGER, treat_as TEXT,
    allowed INTEGER DEFAULT 0, first_seen TEXT, initial INTEGER DEFAULT 0, removed TEXT,
    PRIMARY KEY(instance, name));
"""


# Columns added before the schema had versions. A database that has them all is version 1.
_COLUMNS_V1 = [("agent_keys", "third_party_at", "TEXT"), ("agent_keys", "private_at", "TEXT"),
               ("approvals", "method", "TEXT"), ("tasks", "lease_until", "TEXT"),
               ("owner_sessions", "verified", "TEXT"), ("agent_keys", "last_used", "TEXT"),
               ("quarantine", "reason", "TEXT"),
               ("webauthn_credentials", "rp_id", "TEXT"),  # the domain it was made on; NULL from before
               ("plugin_state", "tool_approval", "TEXT")]  # {tool: "ask" | "auto"}, the owner's choice per tool


def add_column(conn: sqlite3.Connection, table: str, column: str, kind: str) -> None:
    """For migrations: ALTER TABLE ... ADD COLUMN, unless the column is there already."""
    if column not in {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")


def _v1(conn: sqlite3.Connection) -> None:
    for table, column, kind in _COLUMNS_V1:
        add_column(conn, table, column, kind)


def _v2(conn: sqlite3.Connection) -> None:
    # an owner session and a push subscription belong to the passkey that logged in; removing that passkey
    # ends both (webauthn_support.py). Rows from before don't say which: NULL, ended by any removal.
    add_column(conn, "owner_sessions", "credential_id", "TEXT")
    add_column(conn, "push_subscriptions", "credential_id", "TEXT")


def _v3(conn: sqlite3.Connection) -> None:
    # the key a task is for: a reminder belongs to the key that set it (only it sees and takes it, and gets
    # reminder_due in its feed). NULL: any key may take it, as before.
    add_column(conn, "tasks", "key_id", "INTEGER")


def _v4(conn: sqlite3.Connection) -> None:
    # network watch: a read's digest (re-reads add nothing), and an address can belong to several keys
    add_column(conn, "egress_sources", "digest", "TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS egress_sources_digest ON egress_sources(digest)")
    pk = [row[1] for row in conn.execute("PRAGMA table_info(agent_addresses)") if row[5]]
    if pk == ["ip"]:  # one key per address before: what it knew is learned again from the next call
        conn.execute("DROP TABLE agent_addresses")
        conn.execute("CREATE TABLE agent_addresses (ip TEXT, key_id INTEGER, seen TEXT, PRIMARY KEY(ip, key_id))")


def _v5(conn: sqlite3.Connection) -> None:
    # a plugin from doorman.yaml the owner moved into the app (engine.plugin_take_over): its row then wins
    # over doorman.yaml's block of the same name, which otherwise wins a name clash
    add_column(conn, "plugin_instances", "taken_over", "INTEGER DEFAULT 0")


def _v6(conn: sqlite3.Connection) -> None:
    # plugins live in the database only: no plugin is "taken over" from doorman.yaml any more, the rows
    # that were are ordinary ones
    if "taken_over" in {row[1] for row in conn.execute("PRAGMA table_info(plugin_instances)")}:
        conn.execute("ALTER TABLE plugin_instances DROP COLUMN taken_over")


def _v7(conn: sqlite3.Connection) -> None:
    # the guard no longer scans refs or a read's not_scanned IDs (engine._scan_item), so every text it scans
    # changed. What it held back and the owner hasn't decided goes, with its Needs attention entry: the next
    # read scans the item as it is scanned now and holds it again if it still scores. Otherwise a held ref
    # would keep the item masked in every list (Guard.held_refs), however it scores now. Kept and released
    # stay as the owner decided.
    held = [row[0] for row in conn.execute("SELECT id FROM quarantine WHERE status='held'")]
    if not held:
        return
    marks = ",".join("?" * len(held))
    conn.execute(f"UPDATE attention SET resolved=? WHERE kind='quarantine' AND resolved IS NULL AND ref IN ({marks})",
                 [clock.iso(), *(str(qid) for qid in held)])
    conn.execute(f"DELETE FROM quarantine WHERE id IN ({marks})", held)


def _v8(conn: sqlite3.Connection) -> None:
    # a push subscription belongs to the login that made it too (its token_hash): logging out on a device
    # drops that device's subscription. NULL from before: tied again when the app next subscribes.
    add_column(conn, "push_subscriptions", "session_hash", "TEXT")


def _v9(conn: sqlite3.Connection) -> None:
    # the guard no longer scans the random pieces of links (guard.quiet_links): what it held back and the
    # owner hasn't decided is scanned again, as in _v7
    _v7(conn)


def _v10(conn: sqlite3.Connection) -> None:
    # network watch's leak check tells the owner and lets the request go out, unless the owner has it blocked
    # (egress.leak_action alert, when_doorman_down and unscanned allow; all three were block). Blocking was
    # never switched on by hand: it came with the example doorman.yaml, and it lost agents' replies without
    # a word. So what the owner never set in the app now lets through, whatever doorman.yaml says; More →
    # Network switches blocking on again. A new Doorman has nothing to carry over: its doorman.yaml decides.
    if not conn.execute("SELECT 1 FROM agent_keys UNION ALL SELECT 1 FROM journal "
                        "UNION ALL SELECT 1 FROM webauthn_credentials LIMIT 1").fetchone():
        return
    row = conn.execute("SELECT value FROM settings WHERE key='egress_settings'").fetchone()
    try:
        stored = json.loads(row["value"]) if row else {}
    except ValueError:
        stored = {}
    if not isinstance(stored, dict):
        return
    loose = {"leak_action": "alert", "when_doorman_down": "allow", "unscanned": "allow"}
    missing = {k: v for k, v in loose.items() if k not in stored}
    if not missing:
        return
    conn.execute("INSERT INTO settings(key, value) VALUES('egress_settings', ?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps({**stored, **missing}),))


def _v11(conn: sqlite3.Connection) -> None:
    # the injection guard is off unless switched on (it was on unless switched off). An install from before
    # keeps it on: what the owner never set in the app is stored as on. A new Doorman starts without it.
    if not conn.execute("SELECT 1 FROM agent_keys UNION ALL SELECT 1 FROM journal "
                        "UNION ALL SELECT 1 FROM webauthn_credentials LIMIT 1").fetchone():
        return
    conn.execute("INSERT INTO settings(key, value) VALUES('guard_enabled', '1') ON CONFLICT(key) DO NOTHING")


# Schema versions, in order: MIGRATIONS[n] brings a database from version n to n + 1 (PRAGMA user_version).
# Append to the end; never change or reorder an entry that shipped. SCHEMA above runs first on every start,
# so a new table can simply go there (CREATE TABLE IF NOT EXISTS). A change to an existing table (a column,
# data moved or rewritten) is a migration: a function of the connection, run in one transaction together
# with the version bump. Before the first pending migration runs, doorman.db is copied next to itself.
MIGRATIONS: list[Callable[[sqlite3.Connection], None]] = [
    _v1,  # the schema before versions
    _v2,  # owner sessions and push subscriptions remember their passkey
    _v3,  # a task can be for one key (an agent's reminder)
    _v4,  # network watch: read digests, several keys per address
    _v5,  # plugins moved from doorman.yaml into the app
    _v6,  # plugins in the database only: taken_over goes
    _v7,  # the guard's held-back items from before it left IDs out are scanned again
    _v8,  # push subscriptions remember their login
    _v9,  # the guard's held-back items from before it left links' random pieces out are scanned again
    _v10,  # network watch: the leak check tells and lets through, unless the owner chose blocking in the app
    _v11,  # the injection guard became opt-in: an install that had it on keeps it on
]
SCHEMA_VERSION = len(MIGRATIONS)


class SchemaTooNew(Exception):
    """The database was written by a newer Doorman. Refuse to start rather than run code that doesn't know
    its tables (and might write over what it doesn't understand)."""


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.lock = threading.RLock()
        with self.lock:
            self._check_version()
            # a database made just now (no table yet): a new Doorman, which starts with STARTER_PLUGINS
            self.fresh = self.conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone() is None
            self.conn.executescript(SCHEMA)
            self._migrate()

    def version(self) -> int:
        return self.conn.execute("PRAGMA user_version").fetchone()[0]

    def _check_version(self) -> None:
        version = self.version()
        if version > SCHEMA_VERSION:
            self.conn.close()
            raise SchemaTooNew(
                f"{self.path} is at schema version {version}, and this Doorman knows versions up to "
                f"{SCHEMA_VERSION}: a newer Doorman has used it. Run that version again, or restore a backup "
                f"made before the upgrade")

    def _migrate(self) -> None:
        if self.version() >= SCHEMA_VERSION:
            return
        if self.path != ":memory:" and self._has_data():
            self._copy_before_migrating(self.version())
        for target in range(self.version() + 1, SCHEMA_VERSION + 1):
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                if self.version() < target:  # else another process (doorman-admin) got there first
                    MIGRATIONS[target - 1](self.conn)
                    self.conn.execute(f"PRAGMA user_version={int(target)}")
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            self.conn.execute("COMMIT")

    def _has_data(self) -> bool:
        """Worth a copy: an older version, or a database from before versions. A new file isn't."""
        if self.version() > 0:
            return True
        return bool(self.conn.execute("SELECT 1 FROM agent_keys UNION ALL SELECT 1 FROM journal "
                                      "UNION ALL SELECT 1 FROM webauthn_credentials LIMIT 1").fetchone())

    def _copy_before_migrating(self, version: int) -> Path:
        """doorman.db as it was, next to it: doorman.db.v<version>-<time>.bak, through SQLite's backup API so
        the copy is consistent. Backups leave it out; delete it once the new version runs well."""
        target = Path(f"{self.path}.v{version}-{clock.now().strftime('%Y%m%d-%H%M%S')}.bak")
        copy = sqlite3.connect(target)
        try:
            self.conn.backup(copy)
        finally:
            copy.close()
        return target

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self.lock:
            if self.conn.in_transaction:
                yield self.conn
                return
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            else:
                self.conn.execute("COMMIT")

    def exec(self, sql: str, params: tuple | dict = ()) -> int:
        with self.tx() as conn:
            cur = conn.execute(sql, params)
            return cur.lastrowid

    def one(self, sql: str, params: tuple | dict = ()) -> dict[str, Any] | None:
        with self.lock:
            row = self.conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def all(self, sql: str, params: tuple | dict = ()) -> list[dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def get_setting(self, key: str, default: Any = None) -> Any:
        row = self.one("SELECT value FROM settings WHERE key=?", (key,))
        return default if row is None else row["value"]

    def set_setting(self, key: str, value: Any) -> None:
        self.exec(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, None if value is None else str(value)),
        )

    def close(self) -> None:
        self.conn.close()
