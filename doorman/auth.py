"""Agent keys and sessions; owner sessions, one-time setup codes, and the owner's password where a Doorman
signs in with one."""

import base64
import hashlib
import hmac
import secrets
import threading
from datetime import timedelta

from . import clock
from .plugin_api import Denied
from .notify import endpoint_hash
from .util import hash_token, new_token

ROLES = ("reader", "actor", "solo")
OWNER_SESSION_HOURS = 12

MIN_PASSWORD = 10
# scrypt with 32 MiB a check (N=2^15, r=8, p=3: one of the settings OWASP lists); Python's standard library has it
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 3}
FREE_TRIES = 5           # wrong passwords before each further try has to wait
FIRST_WAIT, LONGEST_WAIT = 15, 300   # seconds: 15, 30, 60, ... up to five minutes


class PasswordLocked(Denied):
    """Too many wrong passwords: no try counts for `seconds` more."""

    def __init__(self, seconds: int):
        super().__init__(f"too many wrong passwords: try again in {seconds} seconds", "locked")
        self.seconds = self.retry_after = seconds


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=2 * 128 * n * r)


class Auth:
    def __init__(self, db):
        self._password_lock = threading.Lock()   # one scrypt at a time: each takes 32 MiB
        self._wrong = 0                          # wrong passwords in a row, in this process
        self._locked_until = None
        self.db = db

    # agent keys

    def create_key(self, name: str, role: str) -> str:
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        token = new_token("dmn_")
        self.db.exec(
            "INSERT INTO agent_keys(name, token_hash, role, created) VALUES(?,?,?,?)",
            (name, hash_token(token), role, clock.iso()),
        )
        return token

    def list_keys(self) -> list[dict]:
        keys = self.db.all("SELECT id, name, role, created, revoked, last_used FROM agent_keys ORDER BY id")
        return [{**key, "paused": self.paused(key["id"])} for key in keys]

    # A key is paused when one of its calls carried a honeytoken: ending only that session would leave the
    # agent one missing header away from a fresh one. Kept in settings, so no table changes.

    def pause_key(self, key_id: int, why: str) -> None:
        self.db.set_setting(f"key_paused:{key_id}", why)

    def resume_key(self, key_id: int) -> None:
        self.db.exec("DELETE FROM settings WHERE key=?", (f"key_paused:{key_id}",))

    def paused(self, key_id: int) -> str | None:
        """Why the key is paused, or None."""
        return self.db.get_setting(f"key_paused:{key_id}")

    def touch(self, key: dict) -> None:
        """When the key was last used, for the status page. Written at most once a minute per key."""
        now = clock.now()
        if key.get("last_used") and key["last_used"] > clock.iso(now - timedelta(minutes=1)):
            return
        self.db.exec("UPDATE agent_keys SET last_used=? WHERE id=?", (clock.iso(now), key["id"]))

    def revoke_key(self, key_id: int) -> None:
        self.db.exec("UPDATE agent_keys SET revoked=1 WHERE id=?", (key_id,))
        self.db.exec("UPDATE sessions SET killed=1 WHERE key_id=?", (key_id,))

    def revoke_all(self) -> None:
        self.db.exec("UPDATE agent_keys SET revoked=1")
        self.db.exec("UPDATE sessions SET killed=1")

    def key_from_token(self, token: str | None) -> dict | None:
        if not token:
            return None
        return self.db.one("SELECT * FROM agent_keys WHERE token_hash=? AND revoked=0", (hash_token(token),))

    # sessions

    def new_session(self, key: dict, task_id: int | None = None) -> dict:
        session_id = "ses_" + secrets.token_hex(8)
        self.db.exec("INSERT INTO sessions(id, key_id, task_id, created) VALUES(?,?,?,?)",
                     (session_id, key["id"], task_id, clock.iso()))
        return self.get_session(session_id)

    def get_session(self, session_id: str) -> dict | None:
        return self.db.one("SELECT * FROM sessions WHERE id=?", (session_id,))

    def active_task_session(self, key: dict) -> dict | None:
        return self.db.one(
            "SELECT s.* FROM sessions s JOIN tasks t ON t.id = s.task_id "
            "WHERE s.key_id=? AND s.killed=0 AND t.status='claimed' ORDER BY s.created DESC LIMIT 1",
            (key["id"],))

    def session_for(self, key: dict, session_id: str | None) -> dict:
        active = self.active_task_session(key)
        if active:
            # while a task runs, its restrictions (plugins, read-only) apply to everything this key does
            if session_id and session_id != active["id"]:
                raise Denied(f"finish task #{active['task_id']} first; until then only its session works",
                             "task_active")
            return active
        if session_id:
            session = self.get_session(session_id)
            if session is None or session["key_id"] != key["id"]:
                raise Denied("unknown session for this key: run doorman session clear (or drop DOORMAN_SESSION)",
                             "session")
            if not self._task_ended(session):
                return session
            # its task was closed or ran out: the agent carries on as itself, without that task's limits
        session = self.db.one(
            "SELECT * FROM sessions WHERE key_id=? AND killed=0 AND task_id IS NULL ORDER BY created DESC LIMIT 1",
            (key["id"],),
        )
        return session or self.new_session(key)

    def _task_ended(self, session: dict) -> bool:
        if session["task_id"] is None:
            return False
        task = self.db.one("SELECT status FROM tasks WHERE id=?", (session["task_id"],))
        return task is None or task["status"] != "claimed"

    def taint(self, session_id: str, third_party: bool, private: bool) -> None:
        """Record what a session (and its key) has read. The key keeps a timestamp because the
        agent's memory outlives a session: a fresh session id doesn't make its context clean."""
        now = clock.iso()
        if third_party:
            self.db.exec("UPDATE sessions SET read_third_party=1 WHERE id=?", (session_id,))
            self.db.exec("UPDATE agent_keys SET third_party_at=? WHERE id=(SELECT key_id FROM sessions WHERE id=?)",
                         (now, session_id))
        if private:
            self.db.exec("UPDATE sessions SET read_private=1 WHERE id=?", (session_id,))
            self.db.exec("UPDATE agent_keys SET private_at=? WHERE id=(SELECT key_id FROM sessions WHERE id=?)",
                         (now, session_id))

    def kill_session(self, session_id: str) -> None:
        self.db.exec("UPDATE sessions SET killed=1 WHERE id=?", (session_id,))

    # owner

    def create_owner_session(self, credential_id: str | None = None) -> str:
        """A login. `credential_id`: the passkey it came from (a login, or a passkey just registered, with a
        setup code or not); removing that passkey ends the session."""
        token = new_token("own_")
        expires = clock.now() + timedelta(hours=OWNER_SESSION_HOURS)
        self.db.exec(
            "INSERT INTO owner_sessions(token_hash, created, expires, verified, credential_id) VALUES(?,?,?,?,?)",
            (hash_token(token), clock.iso(), clock.iso(expires), clock.iso(), credential_id),
        )
        return token

    def mark_verified(self, token: str, credential_id: str | None = None) -> None:
        """The owner just proved the passkey again (step-up for sensitive changes). A session from before
        sessions knew their passkey takes this one."""
        self.db.exec("UPDATE owner_sessions SET verified=?, credential_id=coalesce(credential_id, ?) "
                     "WHERE token_hash=?", (clock.iso(), credential_id, hash_token(token)))

    def owner_session(self, token: str | None) -> dict | None:
        """The live session for this cookie, or None: unknown, expired, or its passkey was removed."""
        if not token:
            return None
        row = self.db.one("SELECT * FROM owner_sessions WHERE token_hash=?", (hash_token(token),))
        if row is None or row["expires"] <= clock.iso():
            return None
        if row["credential_id"] is not None and not self.db.one(
                "SELECT 1 AS x FROM webauthn_credentials WHERE id=?", (row["credential_id"],)):
            return None
        return row

    def verified_recently(self, token: str | None, minutes: float) -> bool:
        row = self.owner_session(token)
        return bool(row and row["verified"]
                    and row["verified"] >= clock.iso(clock.now() - timedelta(minutes=minutes)))

    def check_owner_session(self, token: str | None) -> bool:
        return self.owner_session(token) is not None

    def end_owner_session(self, token: str) -> dict:
        """Logging out: the login ends, and the push subscriptions it made (this device's) go with it. Other
        devices keep theirs, even with the same passkey (a synced one is on several devices). The device is
        remembered (push_logged_out), so logging in on it again isn't announced as a new one."""
        with self.db.tx() as c:
            gone = c.execute("SELECT endpoint, credential_id FROM push_subscriptions WHERE session_hash=?",
                             (hash_token(token),)).fetchall()
            c.executemany("INSERT OR REPLACE INTO push_logged_out(endpoint_hash, credential_id, ts) VALUES(?,?,?)",
                          [(endpoint_hash(row[0]), row[1], clock.iso()) for row in gone])
            return {"sessions": c.execute("DELETE FROM owner_sessions WHERE token_hash=?",
                                          (hash_token(token),)).rowcount,
                    "push": c.execute("DELETE FROM push_subscriptions WHERE session_hash=?",
                                      (hash_token(token),)).rowcount}

    def end_passkey_sessions(self, credential_id: str, conn=None) -> dict:
        """A passkey was removed: its sessions end and its device's push subscriptions go, so a lost phone
        neither stays logged in nor keeps getting approvals with an Accept button. Sessions and
        subscriptions from before they knew their passkey (NULL) can't be told apart, so they go too; the
        owner's other devices log in again and re-subscribe on their next start. Devices that logged out with
        it are forgotten: one that comes back is announced."""
        def run(c) -> dict:
            where = "credential_id=? OR credential_id IS NULL"
            c.execute(f"DELETE FROM push_logged_out WHERE {where}", (credential_id,))
            return {"sessions": c.execute(f"DELETE FROM owner_sessions WHERE {where}", (credential_id,)).rowcount,
                    "push": c.execute(f"DELETE FROM push_subscriptions WHERE {where}", (credential_id,)).rowcount}
        if conn is not None:
            return run(conn)
        with self.db.tx() as c:
            return run(c)

    def logout_all(self) -> dict:
        """Every owner session ends and every device stops getting pushes (`doorman-admin logout-all`); a device
        that subscribes again afterwards is announced, also one that had logged out before."""
        with self.db.tx() as c:
            c.execute("DELETE FROM push_logged_out")
            return {"sessions": c.execute("DELETE FROM owner_sessions").rowcount,
                    "push": c.execute("DELETE FROM push_subscriptions").rowcount}

    # the owner's password, for a Doorman opened without HTTPS and a domain (no passkeys there). One method
    # per Doorman: a stored password is what makes it a password one. Set on the host only.

    def sign_in(self) -> str:
        return "password" if self.db.get_setting("owner_password") else "passkey"

    def set_password(self, password: str) -> None:
        if len(password) < MIN_PASSWORD:
            raise ValueError(f"a password needs at least {MIN_PASSWORD} characters")
        salt = secrets.token_bytes(16)
        digest = _scrypt(password, salt, **SCRYPT)
        encode = lambda raw: base64.b64encode(raw).decode()  # noqa: E731
        self.db.set_setting("owner_password", "$".join(
            ["scrypt", str(SCRYPT["n"]), str(SCRYPT["r"]), str(SCRYPT["p"]), encode(salt), encode(digest)]))
        self._wrong, self._locked_until = 0, None

    def clear_password(self) -> None:
        self.db.set_setting("owner_password", None)

    def check_password(self, password: str) -> bool:
        """True for the right password. After FREE_TRIES wrong ones in a row every further try waits, longer
        each time (PasswordLocked says how long), so nobody who reaches the owner app can run through a
        list; a try made while it waits isn't looked at, the right password included."""
        stored = self.db.get_setting("owner_password")
        if not stored:
            return False
        with self._password_lock:
            if self._locked_until and clock.now() < self._locked_until:
                raise PasswordLocked(max(1, round((self._locked_until - clock.now()).total_seconds())))
            _, n, r, p, salt, digest = stored.split("$")
            given = _scrypt(str(password), base64.b64decode(salt), int(n), int(r), int(p))
            if hmac.compare_digest(given, base64.b64decode(digest)):
                self._wrong, self._locked_until = 0, None
                return True
            self._wrong += 1
            if self._wrong >= FREE_TRIES:
                wait = min(LONGEST_WAIT, FIRST_WAIT * 2 ** (self._wrong - FREE_TRIES))
                self._locked_until = clock.now() + timedelta(seconds=wait)
            return False

    def wrong_passwords(self) -> int:
        return self._wrong

    def create_setup_code(self, minutes: int = 30) -> str:
        code = "-".join(secrets.token_hex(2) for _ in range(3))
        expires = clock.iso(clock.now() + timedelta(minutes=minutes))
        self.db.set_setting("setup_code", f"{hash_token(code)}|{expires}")
        return code

    def consume_setup_code(self, code: str) -> bool:
        stored = self.db.get_setting("setup_code")
        if not stored or not code:
            return False
        code_hash, expires = stored.split("|", 1)
        if code_hash != hash_token(code.strip()) or expires < clock.iso():
            return False
        self.db.set_setting("setup_code", None)
        return True
