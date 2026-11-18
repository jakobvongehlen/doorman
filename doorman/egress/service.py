"""Network watch, Doorman's side: the rules, what agents read as fingerprints, the leak check, the log,
access requests and the owner's exceptions.

The proxy (deploy/egress/) sits in front of the acting agent's container and asks Doorman over the proxy API
(api/agent.py, /v1/egress/proxy/*, with a token of its own):

- the policy (policy()): the owner's settings, built-in lists, honeytokens and the exceptions that are still
  running, as one dict that egress.rules.decide() reads. `version` changes whenever anything in it does.
- the leak check (check()): the proxy fingerprints what a request carries and Doorman counts how many of
  those prints it has from reads in the last `match_hours`. Only hashes cross, so the content stays where
  it is. About `leak_chars` characters is a leak: the request goes out and the owner is told (leak_action
  alert, the default), or it is blocked and the agent's key paused (block). Either way the owner hears of it,
  every time (_leak). A honeytoken is always blocked.
- the log (ingest()): one record per connection, filed under the key and its task.

Which agent a connection belongs to: the proxy knows only its source address. Every agent call to Doorman
notes the caller's address (client_seen, from api/agent.py's caller). A connection is logged under the key
last seen from its address; a leak from an address pauses every key seen there in the last day (an agent
mustn't get to choose which key takes the blame). An address no key called from is logged without a key
and never pauses anyone.

What is fingerprinted: every read (ReadLog.on_read), the results of the agent's tool calls (engine.call_tool:
an MCP tool can fetch anything; strings the call itself passed are left out) and the text of tasks a trigger
wrote from someone else's message (no key: any agent may take it). Reading the same text again adds nothing
(a digest per key); it only stays fresh.

Fingerprinting costs about 1.1 µs per character. A small read is done on the spot; a larger one goes to one
worker thread, and a check waits (up to CHECK_WAIT seconds, without holding a thread: wait_flushed) for
what was queued before it, so a read followed at once by a leak is still caught. When the queue is still
behind by then, the check answers `unknown`, which the proxy treats like Doorman being down. The queue is
bounded (QUEUE_CHARS, QUEUE_JOBS), and so is what one key gets fingerprinted per hour (BUDGET_CHARS); a read
past either isn't fingerprinted, and until it would have been forgotten (match_hours) checks for that key's
addresses answer `unknown` too: the key is "blind" (attention egress_blind).

The agent may ask for an exception (request_access, `doorman egress request <target> --reason ...`); the
owner allows it once (an hour), for the task it came from (until that task ends, at most a day), always
(the allow list) or denies it. Like owner_questions.py: a push, the inbox, a journal entry, and an
`egress_decided` event that `doorman wait egress-request:<id>` follows.

The agent's hooks report its tool calls (activity()); the log ties each connection to the call that made
it (correlate) by the process the observer found or else by time, and marks traffic outside any call.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import queue
import re
import secrets
import string
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from .. import clock, readlog, sanitize
from ..plugin_api import Denied
from ..util import dumps, hash_token, loads, new_token
from . import fingerprint, rules

log = logging.getLogger("doorman.egress")

TOKEN_SETTING = "egress_token_hash"
TOKEN_MADE = "egress_token_created"
SETTINGS = "egress_settings"
STATUS = "egress_proxy_status"

READ_CHARS = 4_000_000     # of one read, only the first this many characters are fingerprinted
CHECK_WAIT = 3.0           # a check waits this long at most for reads queued before it (the proxy waits 6 s)
INLINE_CHARS = 20_000      # a read smaller than this is fingerprinted in the request (about 20 ms)
QUEUE_CHARS = 16_000_000   # the worker's queue holds at most this many characters (about 18 s of work)
QUEUE_JOBS = 2000          # and this many reads
BUDGET_CHARS = 50_000_000  # one key gets at most this many characters fingerprinted per hour
DELETE_BATCH = 20_000      # the sweep deletes in batches: the database lock is shared with every request
ADDRESS_HOURS = 24         # an address belongs to the keys seen calling from it this recently
ACTIVITY_RATE = (600, 600)  # a key reports at most 600 tool-call events per 600 seconds
ACTIVITY_OPEN = 200        # calls a key has open at most; a start past it closes the oldest (abandoned)
CALL_HOURS = 1             # a call open longer than this counts as ended then (abandoned)
MODEL_KEYS_PER_HOST = 20   # API keys kept per model provider
DROPPED_QUIET = 3600       # the proxy dropped log records: listed until it drops none for this long
MAX_PRINTS = 200_000       # per check
MAX_RECORDS = 500          # per log call
PROXY_DOWN_SECONDS = 300
EXPIRE_HOURS = 24          # a request nobody decided by then is given up
ONCE_HOURS = 1
TASK_HOURS = 24            # "For this task" ends with the task, and after this at the latest
OPEN_PER_KEY = 5
SEEN_EVERY = 60            # client_seen writes an address at most this often (unless its key changes)
UPLOAD_NEW_DAYS = 30       # a host not in the log for this long counts as new for the large-upload notice
TASK_OPEN = ("pending", "claimed")
DECISIONS = ("once", "task", "always", "deny")
LIST_KEYS = ("allow", "deny", "passthrough", "no_scan")
MAX_LIST = 1000
TEXT_FIELDS = {"client_ip": 64, "kind": 16, "host": 253, "ip": 64, "method": 16, "path": 300, "decision": 8,
               "rule": 40, "detail": 500}
INT_FIELDS = ("port", "status", "bytes_up", "bytes_down", "duration_ms")
KINDS = ("http", "tcp", "dns", "tls_failed")
NUMBERS = {"match_hours": (1, 720), "note_chars": (24, 10_000), "leak_chars": (24, 1_000_000),
           "log_days": (1, 3650), "large_upload_mb": (0, 100_000)}
ENUMS = {"leak_action": ("block", "alert"), "nonweb": ("log", "block"), "when_doorman_down": ("block", "allow"),
         "unscanned": ("block", "allow")}
BLIND = "egress_blind"      # setting: {key id, "" for none: until (epoch)}, keys whose reads weren't all fingerprinted
DROPPED = "egress_dropped"  # setting: {"last": the proxy's dropped count, "grew": when it last grew (epoch)}
_HASH16 = re.compile(r"[0-9a-f]{16}")

# Decoy keys: a file of fake API keys in the agent's container that it's told never to touch (SKILL.md, "The
# network"). The proxy writes it (GET /v1/egress/proxy/decoys); the observer reports a read of it (tripwire()).
DECOYS = "egress_decoys"                # setting: {version, created, filename, keys: [{name, value}]}
DECOY_HISTORY = "egress_decoy_history"  # setting: every value ever made (they all stay honeytokens)
DECOY_TRIP = "egress_decoy_trip"        # setting: {ts, event, client_ip} of the last read of the file
QUARANTINE = "egress_quarantine"        # setting: [{client_ip, since, reason, key_ids}], cut off by the proxy
DECOY_FILE = "api-keys.env"
DECOY_HEADER = "# API keys (backup, Oct 2026) - keep out of git"
DECOY_EVENTS = ("open", "access", "dir_open")
TRIP_QUIET = 60   # seconds: more events for the same address within this are one alarm
LEAK_QUIET = 600  # seconds: the same address's leaks to one host within this are one notice (a refused request
                  # is tried again, and a long reply goes out in pieces)
MODEL_QUIET = 86400  # decoy keys sent to the model API with on_trip alert: the owner is told once a day per address
TRIPWIRE_GRACE = 50  # seconds the tripwire may be off before the owner hears of it: two statuses in a row (60 s)
OWN_PREFIXES = ("dmn_", "dme_")  # Doorman's own tokens: a decoy never looks like one
SILENT_RULES = ("honeytoken", "quarantine")  # the proxy's blocks the agent isn't told about
_URLSAFE = string.ascii_letters + string.digits + "-_"


def _pick(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


DECOY_SHAPES = (  # realistic shapes, random per install
    ("ANTHROPIC_API_KEY", lambda: f"sk-ant-api03-{_pick(_URLSAFE, 93)}-{_pick(_URLSAFE, 6)}AA"),
    ("OPENAI_API_KEY", lambda: "sk-proj-" + _pick(_URLSAFE, 156)),
    ("AWS_ACCESS_KEY_ID", lambda: "AKIA" + _pick(string.ascii_uppercase + "234567", 16)),
    ("AWS_SECRET_ACCESS_KEY", lambda: _pick(string.ascii_letters + string.digits + "/+", 40)),
    ("GITHUB_TOKEN", lambda: "ghp_" + _pick(string.ascii_letters + string.digits, 36)),
)

REQUEST_SCHEMA = {
    "type": "object",
    "properties": {"target": {"type": "string", "minLength": 1, "maxLength": 300},
                   "reason": {"type": "string", "minLength": 3, "maxLength": 500}},
    "required": ["target", "reason"],
    "additionalProperties": False,
}
ACTIVITY_SCHEMA = {
    "type": "object",
    "properties": {"phase": {"enum": ["start", "end"]},
                   "call_id": {"type": "string", "minLength": 1, "maxLength": 100},
                   "tool": {"type": "string", "minLength": 1, "maxLength": 100},
                   "summary": {"type": "string", "maxLength": 500},
                   "status": {"type": "string", "maxLength": 40}},
    "required": ["phase", "call_id", "tool"],
    "additionalProperties": False,
}

_TLD = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _ms(dt: datetime | None = None) -> str:
    """Timestamps in the network tables carry milliseconds: a connection is tied to a tool call by time."""
    return (dt or clock.now()).astimezone(timezone.utc).isoformat(timespec="milliseconds")


def _us(dt: datetime | None = None) -> str:
    """When a key was seen at an address: in microseconds, so the latest of two keys is clear."""
    return (dt or clock.now()).astimezone(timezone.utc).isoformat(timespec="microseconds")


def _epoch(text: str | None) -> float | None:
    return clock.parse(text).timestamp() if text else None


def _clip(text: str, n: int = 80) -> str:
    return text if len(text) <= n else text[:n - 1].rstrip() + "…"


def _one_line(text: str) -> str:
    return " ".join(sanitize.clean_text(text)[0].split())


def _invalid(why: str) -> Denied:
    return Denied(why, "invalid")


class Egress:
    def __init__(self, engine):
        self.engine = engine
        self.db = engine.db
        self._swept = 0.0
        self._seen: dict[tuple[str, int], float] = {}  # (ip, key id) -> when last written
        self._ip_key: dict[str, int] = {}  # ip -> the key last written for it
        self._proxy_seen: float | None = None
        self._proxy_seen_saved = 0.0
        # the fingerprint worker: jobs are numbered; `_done` is the number of the last one finished
        self._jobs: queue.Queue = queue.Queue()
        self._queued = 0
        self._done = 0
        self._queued_chars = 0
        self._pending: set[tuple[int | None, str]] = set()  # (key id, digest) of reads queued, not stored yet
        self._budget: dict[int | None, tuple[int, int]] = {}  # key id -> (hour, characters fingerprinted in it)
        self._cond = threading.Condition()
        self._worker: threading.Thread | None = None
        self._activity: dict[int, deque] = {}  # key id -> times of its latest tool-call events
        self._decoy_lock = threading.Lock()
        self._alarms: dict[tuple[str, str], float] = {}  # (address or key, kind of alarm) -> when last raised
        self._tripwire_off: float | None = None  # since when the proxy's status says the tripwire isn't armed

    # ------------------------------------------------------------------ settings, token

    def settings(self) -> dict:
        """The config's `egress` block with the owner's changes from the app over it; `enabled` says whether
        a proxy token exists."""
        out = dict(self.engine.config.get("egress") or {})
        stored = loads(self.db.get_setting(SETTINGS), {}) or {}
        for key, value in stored.items():
            if key in ("categories", "decoys") and isinstance(value, dict):
                out[key] = {**(out.get(key) or {}), **value}
            else:
                out[key] = value
        out["enabled"] = self.enabled()
        return out

    def save_settings(self, body: Any) -> dict:
        """The owner's changes (any of the keys settings() has; `enabled` is ignored, the token decides it).
        Each is checked; nothing is stored unless all are good. One journal entry says what changed."""
        if not isinstance(body, dict):
            raise _invalid("the settings are a JSON object")
        current = self.settings()
        changes: dict[str, Any] = {}
        for key, value in body.items():
            if key == "enabled":
                continue
            if key not in current:
                raise _invalid(f"there is no network setting {key}")
            changes[key] = self._valid(key, value, current)
        note = changes.get("note_chars", current["note_chars"])
        leak = changes.get("leak_chars", current["leak_chars"])
        if note > leak:
            raise _invalid("note_chars can't be more than leak_chars")
        for key in ("categories", "decoys"):
            if key in changes:
                changes[key] = {**current[key], **changes[key]}
        changed = [k for k, v in changes.items() if v != current.get(k)]
        if not changed:
            return current
        stored = loads(self.db.get_setting(SETTINGS), {}) or {}
        stored.update({k: changes[k] for k in changed})
        self.db.set_setting(SETTINGS, dumps(stored))
        self.engine.journal.create(kind="config", tool="egress.settings", tier="irreversible", decision="run",
                                   status="done", args={k: changes[k] for k in changed},
                                   summary="Network watch settings: " + "; ".join(
                                       self._said(k, current.get(k), changes[k]) for k in changed))
        return self.settings()

    @staticmethod
    def _said(key: str, before: Any, after: Any) -> str:
        if isinstance(after, list) and isinstance(before, list):
            added = [x for x in after if x not in before]
            removed = [x for x in before if x not in after]
            parts = (([f"+{', '.join(added[:5])}"] if added else [])
                     + ([f"-{', '.join(removed[:5])}"] if removed else []))
            return f"{key} {' '.join(parts) or 'reordered'}"
        if key == "categories":
            flips = [f"{name} {'on' if on else 'off'}" for name, on in after.items() if (before or {}).get(name) != on]
            return f"categories: {', '.join(flips)}"
        if key == "decoys":
            flips = [f"{name} {(before or {}).get(name)} → {value}" for name, value in after.items()
                     if (before or {}).get(name) != value]
            return f"decoy keys: {', '.join(flips)}"
        if after is None:
            return f"{key}: the built-in list"
        if before is None:
            return f"{key}: own list of {len(after)}"
        return f"{key} {before} → {after}"

    @staticmethod
    def _valid(key: str, value: Any, current: dict) -> Any:
        if key in NUMBERS:
            low, high = NUMBERS[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
                raise _invalid(f"{key} is a number from {low} to {high}")
            return int(value) if float(value).is_integer() else float(value)
        if key in ENUMS:
            if value not in ENUMS[key]:
                raise _invalid(f"{key} is {' or '.join(ENUMS[key])}")
            return value
        if key == "categories":
            if not isinstance(value, dict) or any(k not in rules.CATEGORIES or not isinstance(v, bool)
                                                  for k, v in value.items()):
                raise _invalid(f"categories maps {', '.join(rules.CATEGORIES)} to true or false")
            return dict(value)
        if key == "decoys":
            if (not isinstance(value, dict) or any(k not in ("enabled", "on_trip") for k in value)
                    or not isinstance(value.get("enabled", True), bool)
                    or value.get("on_trip", "quarantine") not in ("quarantine", "alert")):
                raise _invalid('decoys is {"enabled": true or false, "on_trip": "quarantine" or "alert"}')
            return dict(value)
        if key == "web_ports":
            if (not isinstance(value, list) or not value or len(value) > 50
                    or any(isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535 for p in value)):
                raise _invalid("web_ports is a list of port numbers (1 to 65535)")
            return list(dict.fromkeys(value))
        if key in ("risky_tlds", "exfil_hosts") and value is None:
            return None  # the built-in list
        if not isinstance(value, list) or len(value) > MAX_LIST or any(not isinstance(v, str) for v in value):
            raise _invalid(f"{key} is a list of at most {MAX_LIST} entries, one per line")
        if key == "countries":
            out = [v.strip().upper() for v in value]
            if any(not re.fullmatch(r"[A-Z]{2}", c) for c in out):
                raise _invalid("countries are two-letter codes, like RU")
            return list(dict.fromkeys(out))
        if key == "risky_tlds":
            out = [v.strip().lower().removeprefix(".") for v in value]
            bad = next((t for t in out if not _TLD.fullmatch(t)), None)
            if bad is not None:
                raise _invalid(f"“{bad}” isn't a top-level domain; write it without dots, like zip")
            return list(dict.fromkeys(out))
        if key in LIST_KEYS or key == "exfil_hosts":
            out = []
            for entry in value:
                entry = entry.strip()
                if not entry:
                    continue
                if rules.parse_target(entry) is None:
                    raise _invalid(f"“{_clip(entry, 60)}” in {key} isn't a host, *.domain, IP address or network")
                out.append(entry.lower())
            return list(dict.fromkeys(out))
        raise _invalid(f"there is no network setting {key}")

    def enabled(self) -> bool:
        return self.db.get_setting(TOKEN_SETTING) is not None

    def new_token(self) -> str:
        """The proxy's token, shown to the owner once; a new one replaces the old."""
        self._decoys()  # the proxy writes the decoy file from its first start
        token = new_token("dme_")
        self.db.set_setting(TOKEN_SETTING, hash_token(token))
        self.db.set_setting(TOKEN_MADE, clock.iso())
        self.engine.journal.create(kind="config", tool="egress.token", tier="irreversible", decision="run",
                                   status="done", summary="Made a new token for the network proxy")
        return token

    def token_ok(self, token: str | None) -> bool:
        stored = self.db.get_setting(TOKEN_SETTING)
        if not stored or not isinstance(token, str) or not token.startswith("dme_"):
            return False
        return hmac.compare_digest(hash_token(token), stored)

    # ------------------------------------------------------------------ the policy for the proxy

    def policy(self, seen: bool = False) -> dict:
        """Everything the proxy decides with (egress.rules.policy_example() has the shape). `seen`: the proxy
        asked for it, which counts as a sign of life."""
        if seen:
            self.proxy_seen()
        s = self.settings()
        policy = {
            "nonweb": s["nonweb"], "web_ports": list(s["web_ports"]),
            "categories": {name: bool(s["categories"].get(name, True)) for name in rules.CATEGORIES},
            "countries": list(s["countries"]),
            "risky_tlds": list(s["risky_tlds"]) if s["risky_tlds"] is not None else rules.default_list("risky_tlds"),
            "exfil_hosts": (list(s["exfil_hosts"]) if s["exfil_hosts"] is not None
                            else rules.default_list("exfil_hosts")),
            "deny": list(s["deny"]), "allow": list(s["allow"]), "passthrough": list(s["passthrough"]),
            "no_scan": list(s["no_scan"]),
            # an exception holds only for the addresses of the key that asked (none known yet: for nobody)
            "exemptions": [{"target": e["target"], "expires": _epoch(e["expires"]),
                            "clients": self.ips_for_key(e["key_id"])} for e in self._running()],
            "honeytokens": self.honeytokens(),
            "decoys": sorted(self.decoy_values()),  # also honeytokens; the ones the proxy looks for at no_scan hosts
            "quarantine": [q["client_ip"] for q in self.quarantine()],
            "when_doorman_down": s["when_doorman_down"],
            "unscanned": s["unscanned"],
            "match": {"k": fingerprint.K, "w": fingerprint.W, "note_chars": s["note_chars"]},
        }
        return {"version": rules.policy_version(policy), **policy}

    def honeytokens(self) -> list[str]:
        """The config's honeytokens and every decoy key ever made, lower-cased: the proxy's check, Egress.check
        and the engine's check of tool calls (engine._check_honeytokens) all use this."""
        return sorted({str(t).lower() for t in self.engine.config.get("honeytokens") or [] if t}
                      | self.decoy_values())

    def _running(self) -> list[dict]:
        """Exceptions in force now: not run out, and a task's only while the task is open."""
        return self.db.all(
            "SELECT e.* FROM egress_exemptions e LEFT JOIN tasks t ON t.id=e.task_id WHERE e.expires>? AND "
            f"(e.scope!='task' OR t.status IN ({','.join('?' * len(TASK_OPEN))})) ORDER BY e.id",
            (_ms(), *TASK_OPEN))

    # ------------------------------------------------------------------ decoy keys, the tripwire, quarantine
    #
    # A file of fake API keys sits in the agent's container (deploy/egress: the proxy writes it from
    # decoys_file(), the agent gets it read-only); the agent is told never to touch it. Reading it (the
    # observer's tripwire()) or using one of its keys (check(), engine._check_honeytokens: decoy_used()) stops
    # the agent: its keys are paused and the proxy cuts its address off (quarantine), until the owner lets it
    # out (lift_quarantine) or resumes a key (key_resumed). The keys in what goes to its model API count as a
    # read (decoys_sent_to_model). With on_trip "alert" the owner is only told of a read. Whether the
    # observer watches the file comes with the proxy's status (_check_tripwire). The values never leave
    # Doorman except to the proxy; nothing the agent reads says what tripped it.

    def decoy_values(self) -> set[str]:
        """Every decoy key ever made, lower-cased: they all stay honeytokens after a rotation."""
        current = loads(self.db.get_setting(DECOYS), None) or {}
        history = loads(self.db.get_setting(DECOY_HISTORY), []) or []
        return ({str(v).lower() for v in history if v}
                | {str(k.get("value")).lower() for k in current.get("keys") or [] if k.get("value")})

    def _decoys(self, rotate: bool = False) -> dict:
        """The decoy set: made on first need (the proxy's token, its first fetch of the file) or anew."""
        with self._decoy_lock:
            current = loads(self.db.get_setting(DECOYS), None)
            if current and not rotate:
                return current
            history = loads(self.db.get_setting(DECOY_HISTORY), []) or []
            taken = {str(v).lower() for v in history}
            keys = []
            for name, make in DECOY_SHAPES:
                value = make()
                while value.lower() in taken or any(p in value.lower() for p in OWN_PREFIXES):
                    value = make()
                taken.add(value.lower())
                keys.append({"name": name, "value": value})
            content = self._decoy_content(keys)
            made = {"version": hashlib.sha256(content.encode()).hexdigest()[:16], "created": clock.iso(),
                    "filename": DECOY_FILE, "keys": keys}
            self.db.set_setting(DECOY_HISTORY, dumps(history + [k["value"] for k in keys]))  # first: never lost
            self.db.set_setting(DECOYS, dumps(made))
            return made

    @staticmethod
    def _decoy_content(keys: list[dict]) -> str:
        return "\n".join([DECOY_HEADER, *(f"{k['name']}={k['value']}" for k in keys)]) + "\n"

    def decoys_file(self) -> dict:
        """The file the proxy writes into the agent's container; `version` changes with every new set, and
        is "off" (no content: the proxy removes the file) while the owner has decoy keys switched off."""
        self.proxy_seen()
        if not self.settings()["decoys"].get("enabled", True):
            return {"version": "off", "filename": DECOY_FILE, "content": None}
        made = self._decoys()
        return {"version": made["version"], "filename": DECOY_FILE, "content": self._decoy_content(made["keys"])}

    def rotate_decoys(self) -> dict:
        """The owner's "Make new keys": a new set (the proxy replaces the file); the old ones stay honeytokens."""
        made = self._decoys(rotate=True)
        self.engine.journal.create(kind="config", tool="egress.decoys.rotate", tier="irreversible", decision="run",
                                   status="done", args={"version": made["version"]},
                                   summary="Made new decoy keys; the old ones still stop an agent that uses them")
        return self.decoys_view()

    def decoys_view(self) -> dict:
        """For the owner's Network screen: never the values."""
        s = self.settings()["decoys"]
        made = loads(self.db.get_setting(DECOYS), None) or {}
        return {"enabled": bool(s.get("enabled", True)), "on_trip": s.get("on_trip", "quarantine"),
                "version": made.get("version"), "created": made.get("created"),
                "last_trip": loads(self.db.get_setting(DECOY_TRIP), None)}

    def quarantine(self) -> list[dict]:
        """The addresses the proxy cuts off: [{client_ip, since, reason, key_ids}]."""
        return [q for q in loads(self.db.get_setting(QUARANTINE), []) or [] if isinstance(q, dict) and q.get("client_ip")]

    def quarantine_view(self) -> list[dict]:
        names = {r["id"]: r["name"] for r in self.db.all("SELECT id, name FROM agent_keys")}
        return [{**q, "agents": [names[k] for k in q["key_ids"] if k in names]} for q in self.quarantine()]

    def _quarantine(self, ip: str, reason: str, key_ids: list[int]) -> None:
        with self._decoy_lock:
            entries = self.quarantine()
            entry = next((q for q in entries if q["client_ip"] == ip), None)
            if entry is None:
                entries.append({"client_ip": ip, "since": clock.iso(), "reason": reason, "key_ids": sorted(set(key_ids))})
            else:
                entry["key_ids"] = sorted(set(entry["key_ids"]) | set(key_ids))
            self.db.set_setting(QUARANTINE, dumps(entries))

    def lift_quarantine(self, ip: Any, resumed: str | None = None) -> dict:
        """The owner's "Let it out again" (or `resumed`: the name of a key the owner resumed). Its keys stay
        paused until the owner resumes them."""
        if not isinstance(ip, str) or not ip:
            raise _invalid("client_ip is the address to let out")
        with self._decoy_lock:
            entries = self.quarantine()
            entry = next((q for q in entries if q["client_ip"] == ip), None)
            if entry is None:
                raise Denied("that address isn't cut off", "not_found")
            self.db.set_setting(QUARANTINE, dumps([q for q in entries if q is not entry]))
            self._alarms = {k: v for k, v in self._alarms.items() if k[0] != ip}
        self.engine.resolve_attention("egress_tripwire", ip)
        self.engine.journal.create(kind="config", tool="egress.quarantine.lift", tier="irreversible", decision="run",
                                   status="done", args={"client_ip": ip, "key_ids": entry["key_ids"]},
                                   summary=f"Let {ip} reach the network again"
                                   + (f": resumed agent key “{resumed}”" if resumed else ""))
        return {"ok": True}

    def key_resumed(self, key_id: int, name: str) -> None:
        """The owner resumed a key (engine.resume_agent_key): the addresses it was cut off at are let out."""
        for entry in self.quarantine():
            if key_id in entry["key_ids"]:
                self.lift_quarantine(entry["client_ip"], resumed=name)
        self.engine.resolve_attention("egress_tripwire", f"key:{key_id}")
        self._leaks_seen(key_id)
        if not self.db.one("SELECT 1 FROM settings WHERE key LIKE 'key_paused:%' LIMIT 1"):
            self.engine.resolve_attention("egress_tripwire", "unknown")

    def _repeat(self, ref: str | None, kind: str, quiet: float = TRIP_QUIET) -> bool:
        """True when this alarm was raised for this address less than `quiet` seconds ago."""
        now = clock.now().timestamp()
        with self._decoy_lock:
            last = self._alarms.get((ref or "", kind))
            if last is not None and now - last < quiet:
                return True
            if len(self._alarms) > 1000:
                self._alarms = {k: v for k, v in self._alarms.items() if now - v < TRIP_QUIET}
            self._alarms[(ref or "", kind)] = now
            return False

    def _keys_behind_proxy(self) -> list[int]:
        """Keys seen in the last ADDRESS_HOURS at an address that also went through the proxy then."""
        since = clock.now() - timedelta(hours=ADDRESS_HOURS)
        return [r["key_id"] for r in self.db.all(
            "SELECT DISTINCT key_id FROM agent_addresses WHERE seen>=? AND ip IN (SELECT DISTINCT client_ip FROM "
            "egress_log WHERE ts>=? AND client_ip IS NOT NULL) ORDER BY key_id", (_us(since), _ms(since)))]

    def _who(self, keys: list[int], ip: str | None) -> tuple[list[int], str]:
        """The keys that exist, and the words for them."""
        names = {r["id"]: r["name"] for r in self.db.all(
            f"SELECT id, name FROM agent_keys WHERE id IN ({','.join('?' * len(keys))})", tuple(keys))} if keys else {}
        known = [k for k in keys if k in names]
        quoted = [f"“{names[k]}”" for k in known]
        who = (f"agent key {quoted[0]}" if len(known) == 1 else
               f"agent keys {', '.join(quoted[:-1])} and {quoted[-1]} (they share an address)" if known else
               f"an unknown agent at {ip or 'an unknown address'}")
        return known, who

    def _pause(self, keys: list[int], why: str) -> None:
        for key_id in keys:
            if not self.engine.auth.paused(key_id):
                self.engine.auth.pause_key(key_id, why)

    def tripwire(self, body: Any) -> dict:
        """The observer saw the decoy file opened or read (open, access) or its folder listed (dir_open):
        {client_ip, event, path, ts} → {ok, action}. A read stops every key seen at that address lately and
        cuts the address off (on_trip quarantine), or only tells the owner (alert); an address no key called
        from pauses the keys that used the proxy in the last day and cuts nothing off. A listing is only
        told. More events from one address within TRIP_QUIET seconds are one alarm."""
        if not isinstance(body, dict):
            raise _invalid("the event is a JSON object")
        event, path, ip, ts = body.get("event"), body.get("path"), body.get("client_ip"), body.get("ts")
        if event not in DECOY_EVENTS:
            raise _invalid(f"event is {', '.join(DECOY_EVENTS)}")
        if not isinstance(path, str):
            raise _invalid("path is the file or folder that was touched")
        if ip is not None and not isinstance(ip, str):
            raise _invalid("client_ip is an address or null")
        if ts is not None and (isinstance(ts, bool) or not isinstance(ts, (int, float))):
            raise _invalid("ts is a number (epoch seconds)")
        self.proxy_seen()
        ip = ip.strip()[:64] or None if ip else None
        path = _clip(_one_line(path), 300)
        keys = self.keys_for_ip(ip)
        url = f"{self.engine.public_url}/app/#/network"
        if event == "dir_open":
            if not self._repeat(ip, "dir"):
                known, who = self._who(keys, ip)
                self.engine.journal.create(
                    kind="config", tool="egress.decoy_dir", tier="irreversible", decision="run", status="done",
                    args={"event": event, "client_ip": ip, "path": path, "key_ids": known},
                    summary=_clip(f"{who[0].upper()}{who[1:]} listed the folder of the decoy keys ({path})", 300))
                self.engine.attention(
                    "egress_decoy_dir", ip if keys else "unknown", "Your agent looked into the decoy keys' folder",
                    f"{who[0].upper()}{who[1:]} listed {path}, the folder with the fake API keys it's told never to "
                    "touch. It hasn't opened them; if it does, it's stopped (More → Network).", url=url, priority=4)
            return {"ok": True, "action": "noted"}

        stop = self.settings()["decoys"].get("on_trip", "quarantine") == "quarantine"
        now = clock.now().timestamp()
        when = ts if ts is not None and abs(ts - now) < 86400 else now
        self.db.set_setting(DECOY_TRIP, dumps({"ts": clock.iso(datetime.fromtimestamp(when, timezone.utc)),
                                               "event": event, "client_ip": ip}))
        known_ip = bool(keys)
        known, who = self._who(keys if known_ip else self._keys_behind_proxy(), ip)
        if stop:
            self._pause(known, "it read the decoy keys")
            if known_ip:
                self._quarantine(ip, f"read the decoy keys ({path})", known)
        if self._repeat(ip, "trip"):
            return {"ok": True, "action": "quarantine" if stop else "alert"}
        keys_word = "the key" if len(known) == 1 else "the keys"
        if not known_ip:
            who = f"something at {ip or 'an unknown address'} in the agent's network"
            done = (f"Doorman doesn't know which agent that is, so it paused every key that used the network proxy "
                    f"in the last day ({len(known)})." if stop and known else
                    "Doorman doesn't know which agent that is, and no key used the network proxy in the last day."
                    if stop else "You set decoy keys to only tell you (More → Network), so nothing was stopped.")
        else:
            done = (f"{keys_word.capitalize()} {'is' if len(known) == 1 else 'are'} paused and the proxy cut {ip} off "
                    f"from the network. Check what it was doing; resuming {keys_word} (More → Agents) lets it out "
                    "again." if stop else
                    "You set decoy keys to only tell you (More → Network), so nothing was stopped.")
        self.engine.journal.create(
            kind="config", tool="egress.tripwire", tier="irreversible", decision="run", status="done",
            args={"event": event, "client_ip": ip, "path": path, "key_ids": known,
                  "action": "quarantine" if stop else "alert"},
            summary=_clip(f"{who[0].upper()}{who[1:]} read the decoy keys ({path})"
                          + (f"; paused {keys_word}" if stop and known else "")
                          + (f" and cut {ip} off" if stop and known_ip else ""), 300))
        self.engine.attention(
            "egress_tripwire", ip if known_ip else "unknown", "Your agent read the decoy keys",
            f"{who[0].upper()}{who[1:]} opened {path}, the fake API keys it's told never to touch: something may "
            f"be steering it. {done}", url=url, priority=5)
        return {"ok": True, "action": "quarantine" if stop else "alert"}

    def decoy_used(self, keys: list[int], ip: str | None, where: str) -> None:
        """A decoy key went out: in a request the proxy checked (`ip`, the keys seen there) or in a tool call
        (engine._check_honeytokens: its key, no address). Like any honeytoken the keys are paused; with
        on_trip quarantine the address and every address of the keys are cut off too."""
        stop = self.settings()["decoys"].get("on_trip", "quarantine") == "quarantine"
        known, who = self._who(keys, ip)
        self._pause(known, f"it used one of the decoy keys in {where}")
        addresses = sorted(({ip} if ip else set()) | {a for k in known for a in self.ips_for_key(k)})
        if stop:
            for address in addresses:
                self._quarantine(address, f"used a decoy key in {where}", known)
        ref = ip or (f"key:{known[0]}" if known else "unknown")
        if self._repeat(ref, "used"):
            return
        cut = f" and the proxy cut {', '.join(addresses)} off from the network" if stop and addresses else ""
        self.engine.journal.create(
            kind="config", tool="egress.decoy_used", tier="irreversible", decision="run", status="done",
            args={"where": where, "client_ip": ip, "key_ids": known, "quarantined": addresses if stop else []},
            summary=_clip(f"{who[0].upper()}{who[1:]} used a decoy key in {where}"
                          + ("; paused" if known else "") + (f", cut off {', '.join(addresses)}" if cut else ""), 300))
        self.engine.attention(
            "egress_tripwire", ref, "Your agent used a decoy key",
            f"{who[0].upper()}{who[1:]} used one of the fake API keys it's told never to touch, in {where}: something "
            f"may be steering it. Nothing went out. "
            + (f"{'The key is' if len(known) == 1 else 'The keys are'} paused{cut}; resuming "
               f"{'it' if len(known) == 1 else 'them'} (More → Agents) lets it out again." if known else
               f"The proxy cut {ip} off." if cut else ""),
            url=f"{self.engine.public_url}/app/#/network", priority=5)

    def decoys_sent_to_model(self, keys: list[int], ip: str | None, host: str) -> bool:
        """The decoy keys in what went to a host on no_scan (the agent's model API, check() with no_scan): the
        agent has them in its conversation, so it read their file, whether the tripwire saw that or not. With
        on_trip quarantine that stops it like using a key (decoy_used): True, the request is blocked. With
        alert, like a read, the owner is told (once a day per address: every later call carries them too) and
        the request goes: False."""
        if self.settings()["decoys"].get("on_trip", "quarantine") == "quarantine":
            self.decoy_used(keys, ip, f"a request to {host}")
            return True
        if self._repeat(ip, "model", quiet=MODEL_QUIET):
            return False
        known, who = self._who(keys, ip)
        self.engine.journal.create(
            kind="config", tool="egress.decoys_to_model", tier="irreversible", decision="run", status="done",
            args={"host": host, "client_ip": ip, "key_ids": known, "action": "alert"},
            summary=_clip(f"{who[0].upper()}{who[1:]} sent the decoy keys to {host}", 300))
        self.engine.attention(
            "egress_tripwire", ip if keys else "unknown", "Your agent has the decoy keys",
            f"{who[0].upper()}{who[1:]} sent the fake API keys it's told never to touch to {host}, its model: it "
            "has read them, and something may be steering it. You set decoy keys to only tell you (More → "
            "Network), so nothing was stopped.", url=f"{self.engine.public_url}/app/#/network", priority=5)
        return False

    # ------------------------------------------------------------------ what agents read

    def note_read(self, key: dict, session: dict, name: str, data: Any) -> None:
        """A read's data, for the leak check (ReadLog.on_read). Nothing while the network watch is off."""
        if not self.enabled():
            return
        _, items = readlog.summarize(data)
        first = next((i["label"] for i in items if i.get("label")), None)
        self._note(key.get("id"), session.get("task_id"), name, _clip(f"{name}: {first}" if first else name, 120),
                   fingerprint.strings_of(data))

    def note_result(self, key: dict, session: dict, name: str, args: Any, result: Any) -> None:
        """What a tool call gave back (engine.call_tool): an MCP tool can fetch a page, a plugin's tool can
        return a file. The strings the call passed itself (a note's text echoed back) are left out: the
        agent wrote them, it didn't read them."""
        if not self.enabled() or not isinstance(result, dict):
            return
        own = set(fingerprint.strings_of(args))
        self._note(key.get("id"), session.get("task_id"), name, _clip(f"{name} (its result)", 120),
                   (t for t in fingerprint.strings_of(result.get("result")) if t not in own))

    def note_task(self, task_id: int, text: str, origin: str) -> None:
        """A task a trigger wrote from someone else's message: any agent may take it, so no key."""
        if self.enabled():
            self._note(None, task_id, "task", _clip(f"task {task_id} ({origin}): {_one_line(text)}", 120), [text])

    def _note(self, key_id: int | None, task_id: int | None, name: str, label: str, strings) -> None:
        """Collects the strings (up to READ_CHARS) and has them fingerprinted: here when small, else by the
        worker. A text this key had fingerprinted within match_hours only gets its time renewed. Past the
        key's hourly budget or a full queue it isn't fingerprinted, and the key goes blind."""
        texts, total = [], 0
        for text in strings:
            if total + len(text) > READ_CHARS:
                texts.append(text[:READ_CHARS - total])
                total = READ_CHARS
                break
            texts.append(text)
            total += len(text)
        if not texts or total == 0:
            return
        digest = hashlib.sha256("\x00".join(texts).encode("utf-8", "surrogatepass")).hexdigest()[:32]
        ts = _ms()
        with self._cond:
            if (key_id, digest) in self._pending:
                return
        hours = float(self.settings()["match_hours"])
        known = self.db.one("SELECT id FROM egress_sources WHERE digest=? AND key_id IS ? AND ts>=? LIMIT 1",
                            (digest, key_id, _ms(clock.now() - timedelta(hours=hours))))
        if known:
            self.db.exec("UPDATE egress_sources SET ts=? WHERE id=?", (ts, known["id"]))
            return
        hour = int(clock.now().timestamp() // 3600)
        with self._cond:
            spent = self._budget.get(key_id)
            used = spent[1] if spent and spent[0] == hour else 0
            over = used + total > BUDGET_CHARS
            if not over:
                self._budget[key_id] = (hour, used + total)
        if over:
            self._blind(key_id, f"it read more than {BUDGET_CHARS:,} characters within an hour, more than "
                                "Doorman fingerprints")
            return
        job = (key_id, task_id, ts, name, label, texts, digest)
        if total < INLINE_CHARS:
            try:
                self._store(*job)
            except Exception:  # noqa: BLE001 - the read itself worked; the agent gets it either way
                log.exception("fingerprints of a read")
            return
        with self._cond:
            full = self._queued_chars + total > QUEUE_CHARS or self._queued - self._done >= QUEUE_JOBS
            if not full:
                self._queued += 1
                self._queued_chars += total
                self._pending.add((key_id, digest))
                self._jobs.put((total, job))
        if full:
            self._blind(key_id, "Doorman's fingerprint queue was full")
            return
        self._start_worker()

    def _start_worker(self) -> None:
        with self._cond:
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(target=self._work, name="egress-prints", daemon=True)
                self._worker.start()

    def _work(self) -> None:
        while True:
            try:
                total, job = self._jobs.get(timeout=30)
            except queue.Empty:
                with self._cond:  # nothing for a while: the thread ends; the next read starts another
                    if self._jobs.empty():
                        self._worker = None
                        return
                continue
            try:
                self._store(*job)
            except Exception:  # noqa: BLE001 - one bad read mustn't stop the leak check for the next
                log.exception("fingerprints of a read")
            finally:
                with self._cond:
                    self._done += 1
                    self._queued_chars -= total
                    self._pending.discard((job[0], job[-1]))
                    self._cond.notify_all()

    def _store(self, key_id: int | None, task_id: int | None, ts: str, name: str, label: str,
               texts: list[str], digest: str) -> None:
        prints: set[int] = set()
        for text in texts:
            prints |= fingerprint.prints(text)
        # kept even without prints (short texts only: a subject, a name), so reading it again costs nothing
        source_id = self.db.exec("INSERT INTO egress_sources(key_id, task_id, ts, name, label, digest) "
                                 "VALUES(?,?,?,?,?,?)", (key_id, task_id, ts, name, label, digest))
        rows = [(h, source_id) for h in prints]
        for start in range(0, len(rows), 20_000):  # in pieces: the database lock is shared with every request
            with self.db.tx() as conn:
                conn.executemany("INSERT INTO egress_prints(hash, source_id) VALUES(?,?)", rows[start:start + 20_000])

    def flush(self, timeout: float | None = None) -> bool:
        """Until every read queued so far is fingerprinted, at most `timeout` seconds (CHECK_WAIT). True
        if done."""
        with self._cond:
            target = self._queued
            return self._cond.wait_for(lambda: self._done >= target,
                                       timeout=CHECK_WAIT if timeout is None else timeout)

    async def wait_flushed(self, timeout: float | None = None) -> bool:
        """flush() for the proxy's check route: waits without holding one of the server's threads."""
        target = self._queued
        deadline = time.monotonic() + (CHECK_WAIT if timeout is None else timeout)
        while self._done < target:
            if time.monotonic() >= deadline:
                return False
            await asyncio.sleep(0.02)
        return True

    # ------------------------------------------------------------------ blind keys

    def _blind_map(self) -> dict[str, float]:
        stored = loads(self.db.get_setting(BLIND), {}) or {}
        now = clock.now().timestamp()
        return {k: v for k, v in stored.items() if isinstance(v, (int, float)) and v > now}

    def _blind(self, key_id: int | None, why: str) -> None:
        """Something this key got wasn't fingerprinted: until it would have been forgotten, the leak check
        can't judge this key's uploads and answers `unknown` (the proxy then does what when_doorman_down
        says). The owner hears of it once."""
        hours = float(self.settings()["match_hours"])
        until = clock.now().timestamp() + hours * 3600
        blind = self._blind_map()
        ref = "" if key_id is None else str(key_id)
        blind[ref] = until
        self.db.set_setting(BLIND, dumps(blind))
        key = self.db.one("SELECT name FROM agent_keys WHERE id=?", (key_id,)) if key_id else None
        who = f"agent key “{key['name']}”" if key else "an agent"
        self.engine.attention(
            "egress_blind", ref or "tasks", f"Uploads of {who} can't be checked for now",
            f"Not everything {who} read was fingerprinted: {why}. For the next {hours:g} hours the network "
            f"proxy can't tell whether its uploads carry what it read, and treats them like Doorman being down "
            f"(More → Network, “Block what can't be checked”).", url=f"{self.engine.public_url}/app/#/network",
            priority=4)

    def _blind_keys(self) -> set[int | None]:
        return {None if k == "" else int(k) for k in self._blind_map()}

    # ------------------------------------------------------------------ which key, the leak check

    def client_seen(self, ip: str | None, key_id: int) -> None:
        """An agent key called Doorman from this address (api/agent.py's caller)."""
        if not ip:
            return
        ip = str(ip)[:64]
        now = clock.now().timestamp()
        last = self._seen.get((ip, key_id))
        if last is not None and now - last < SEEN_EVERY and self._ip_key.get(ip) == key_id:
            return
        self._seen[(ip, key_id)] = now
        self._ip_key[ip] = key_id  # the key last written for the address: another key calling is written at once
        self.db.exec("INSERT INTO agent_addresses(ip, key_id, seen) VALUES(?,?,?) ON CONFLICT(ip, key_id) DO UPDATE "
                     "SET seen=excluded.seen", (ip, key_id, _us()))

    def keys_for_ip(self, ip: str | None) -> list[int]:
        """The keys seen calling from this address in the last ADDRESS_HOURS, the latest first."""
        if not ip:
            return []
        return [r["key_id"] for r in self.db.all(
            "SELECT key_id FROM agent_addresses WHERE ip=? AND seen>=? ORDER BY seen DESC",
            (ip, _us(clock.now() - timedelta(hours=ADDRESS_HOURS))))]

    def key_for_ip(self, ip: str | None) -> int | None:
        """The key a connection from this address is logged under: the one seen there last."""
        keys = self.keys_for_ip(ip)
        return keys[0] if keys else None

    def ips_for_key(self, key_id: int | None) -> list[str]:
        if key_id is None:
            return []
        return [r["ip"] for r in self.db.all(
            "SELECT ip FROM agent_addresses WHERE key_id=? AND seen>=? ORDER BY ip",
            (key_id, _us(clock.now() - timedelta(hours=ADDRESS_HOURS))))]

    def check(self, body: Any, flushed: bool | None = None) -> dict:
        """The proxy's question about one request: does it carry what an agent read through Doorman, or a
        honeytoken? {client_ip, host, url, method, prints, honeytokens[, no_scan]} → {action, chars, sources,
        reason}. `no_scan`: the honeytokens were found in the content of a request to a host on no_scan, where
        only the decoy keys count (decoys_sent_to_model).
        `action` is allow, deny or unknown: the reads before it aren't all fingerprinted (the queue is behind,
        `flushed` False, or a key at that address is blind), and the proxy treats it like Doorman being down.
        `flushed`: whether the route waited for the queue (wait_flushed); None, wait here.
        `sources` names only what the keys at that address read; the owner hears everything."""
        if not isinstance(body, dict):
            raise _invalid("the check is a JSON object")
        prints = body.get("prints") or []
        hits = body.get("honeytokens") or []
        if (not isinstance(prints, list) or len(prints) > MAX_PRINTS
                or any(isinstance(p, bool) or not isinstance(p, int) for p in prints)):
            raise _invalid(f"prints is a list of at most {MAX_PRINTS} integers")
        if not isinstance(hits, list) or any(not isinstance(h, str) for h in hits):
            raise _invalid("honeytokens is a list of strings")
        self.proxy_seen()
        ip = str(body.get("client_ip") or "")[:64] or None
        host = str(body.get("host") or "")[:253] or "an unknown host"
        keys = self.keys_for_ip(ip)
        s = self.settings()

        found = {h.lower() for h in hits} & set(self.honeytokens())
        if body.get("no_scan") is True:
            # the content of a request to a host on no_scan (the agent's model API) carries what the agent read,
            # the owner's honeytokens included: only the decoy keys count there
            decoys = found & self.decoy_values()
            if decoys and self.decoys_sent_to_model(keys, ip, host):
                return {"action": "deny", "chars": 0, "sources": [],
                        "reason": "this request carries protected content (a honeytoken)"}
            found = set()
        if found:
            if found & self.decoy_values():  # one of the decoy keys: its address is cut off too
                self.decoy_used(keys, ip, f"a request to {host}")
            else:
                self._leak(keys, ip, host, None, [], pause=True)
            return {"action": "deny", "chars": 0, "sources": [],
                    "reason": "this request carries protected content (a honeytoken)"}
        if not prints:
            return {"action": "allow", "chars": 0, "sources": [], "reason": ""}

        if flushed is None:
            flushed = self.flush()
        if not flushed:
            return {"action": "unknown", "chars": 0, "sources": [],
                    "reason": "Doorman is still fingerprinting what the agent read and couldn't check this in time"}
        blind = self._blind_keys()
        if None in blind or blind & set(keys) or (blind and not keys):
            return {"action": "unknown", "chars": 0, "sources": [],
                    "reason": "the agent read more than Doorman could fingerprint, so its uploads can't be checked "
                              "for now"}

        chars, best = self._match(prints, s["match_hours"])
        everything = list(dict.fromkeys(label for label, _ in best))
        own = list(dict.fromkeys(label for label, key_id in best if key_id is not None and key_id in keys))
        if chars >= s["leak_chars"]:
            block = s["leak_action"] == "block"
            self._leak(keys, ip, host, chars, everything, pause=block)
            if block:
                return {"action": "deny", "chars": chars, "sources": own,
                        "reason": f"this request carries about {chars} characters the agent read through Doorman"
                                  + (f" ({', '.join(own)})" if own else "")}
        return {"action": "allow", "chars": chars, "sources": own if chars >= s["note_chars"] else [],
                "reason": ""}

    def _match(self, prints: list[int], hours: float) -> tuple[int, list[tuple[str, int | None]]]:
        """About how many characters of the one read that shares the most with the request (pieces of
        several reads don't add up), and (label, key id) of the three that share most."""
        since = _ms(clock.now() - timedelta(hours=hours))
        per_source: dict[int, set[int]] = {}
        unique = list(set(prints))
        for start in range(0, len(unique), 5000):
            chunk = unique[start:start + 5000]
            rows = self.db.all(
                f"SELECT p.hash, p.source_id FROM egress_prints p JOIN egress_sources s ON s.id=p.source_id "
                f"WHERE p.hash IN ({','.join('?' * len(chunk))}) AND s.ts>=?", (*chunk, since))
            for row in rows:
                per_source.setdefault(row["source_id"], set()).add(row["hash"])
        if not per_source:
            return 0, []
        best = sorted(per_source, key=lambda sid: (-len(per_source[sid]), -sid))[:3]
        info = {r["id"]: r for r in self.db.all(
            f"SELECT id, label, key_id FROM egress_sources WHERE id IN ({','.join('?' * len(best))})", tuple(best))}
        return (fingerprint.estimate_chars(len(per_source[best[0]])),
                [(info[sid]["label"], info[sid]["key_id"]) for sid in best if sid in info])

    def _leak(self, keys: list[int], ip: str | None, host: str, chars: int | None, sources: list[str],
              pause: bool) -> None:
        """A leak or a honeytoken: it's journaled and the owner hears of it (Needs attention, a push). With
        `pause` the request was blocked, and every key seen at that address lately is paused until the owner
        resumes it; never a key that isn't known for sure.
        A blocked request is something the agent wanted to do and couldn't, so each one is told: an entry and
        a push of its own, however many are open already (the inbox stacks the ones that say the same). One
        let through (leak_action alert) is told once per key and host while its entry is open. The same
        address's leaks to one host within LEAK_QUIET are one notice."""
        known, who = self._who(keys, ip)
        what = (f"about {chars} characters it read through Doorman ({', '.join(sources)})" if chars is not None
                else "a honeytoken")
        already = bool(known) and all(self.engine.auth.paused(key_id) for key_id in known)
        paused = bool(known and pause)
        if paused:
            self._pause(known, f"a request to {host} carried {what}")
        if self._repeat(f"{ip}:{host}", f"leak:{'block' if pause else 'alert'}:{chars is None}", LEAK_QUIET):
            return
        verb = "Blocked" if pause else "Let through"
        key_word = f"the key{'s' if len(known) > 1 else ''}"
        self.engine.journal.create(
            kind="config", tool="egress.leak", tier="irreversible", decision="run", status="done",
            args={"host": host, "key_id": known[0] if known else None, "key_ids": known, "client_ip": ip,
                  "chars": chars, "sources": sources},
            summary=_clip(f"{verb} a request from {who} to {host} carrying {what}"
                          + (f"; {key_word} stayed paused" if paused and already else
                             f"; paused {key_word}" if paused else ""), 300))
        if paused:
            outcome = (f"It was blocked and didn't go out, and {key_word} can't do anything through Doorman until "
                       f"you resume {'it' if len(known) == 1 else 'them'} (More → Agents).")
        elif pause:
            outcome = "It was blocked and didn't go out."
        else:
            outcome = "It went out: network watch tells you about these and doesn't block them."
        if chars is not None:  # a honeytoken is blocked whatever the settings say
            outcome += (f" Under More → Network you can allow {host}, so requests to it aren't checked, "
                        + ("or have such requests only reported." if pause else "or have such requests blocked."))
        base = known[0] if known else f"ip:{ip}"
        self.engine.attention("egress_leak", f"{base}:{host}:{_us()}" if pause else f"{base}:{host}",
                              f"{'Blocked' if pause else 'Possible'} leak to {host}",
                              f"A request from {who} to {host} carried {what}. {outcome}",
                              url=f"{self.engine.public_url}/app/#/network", priority=5)

    def _leaks_seen(self, key_id: int) -> None:
        """The key was resumed: its leaks leave Needs attention (one entry per blocked request, _leak)."""
        for row in self.db.all("SELECT ref FROM attention WHERE kind='egress_leak' AND resolved IS NULL "
                               "AND (ref=? OR ref LIKE ?)", (str(key_id), f"{key_id}:%")):
            self.engine.resolve_attention("egress_leak", row["ref"])

    # ------------------------------------------------------------------ the proxy's log and status

    def proxy_seen(self) -> None:
        now = clock.now().timestamp()
        self._proxy_seen = now
        if now - self._proxy_seen_saved >= 60:
            self._proxy_seen_saved = now
            self.db.set_setting("egress_proxy_seen", clock.iso())

    def _last_seen(self) -> float | None:
        if self._proxy_seen is None:
            stored = self.db.get_setting("egress_proxy_seen")
            self._proxy_seen = _epoch(stored) if stored else None
        return self._proxy_seen

    def ingest(self, records: Any) -> int:
        """The proxy's log records (one per connection); unknown fields are dropped, text clipped."""
        if not isinstance(records, list) or len(records) > MAX_RECORDS:
            raise _invalid(f"records is a list of at most {MAX_RECORDS}")
        self.proxy_seen()
        s = self.settings()
        keys: dict[str | None, tuple[int | None, int | None]] = {}
        rows, uploads, model_keys = [], [], []
        for record in records:
            if not isinstance(record, dict):
                continue
            row = self._record(record)
            auth = record.get("auth_hash")
            if isinstance(auth, str) and _HASH16.fullmatch(auth) and row["host"]:
                model_keys.append((row["host"].lower(), auth, row["ts"]))
            ip = row["client_ip"]
            if ip not in keys:
                key_id = self.key_for_ip(ip)
                task = self.db.one("SELECT s.task_id FROM sessions s JOIN tasks t ON t.id=s.task_id WHERE "
                                   "s.key_id=? AND s.killed=0 AND t.status='claimed' ORDER BY s.created DESC LIMIT 1",
                                   (key_id,)) if key_id else None
                keys[ip] = (key_id, task["task_id"] if task else None)
            row["key_id"], row["task_id"] = keys[ip]
            rows.append(row)
            if (row["decision"] == "allow" and row["host"] and s["large_upload_mb"]
                    and (row["bytes_up"] or 0) >= s["large_upload_mb"] * 1024 * 1024):
                uploads.append(row)
        new_hosts = set()
        for row in uploads:
            since = _ms(clock.parse(row["ts"]) - timedelta(days=UPLOAD_NEW_DAYS))
            if row["host"] not in new_hosts and not self.db.one(
                    "SELECT 1 FROM egress_log WHERE host=? AND ts>=? AND ts<? LIMIT 1",
                    (row["host"], since, row["ts"])):
                new_hosts.add(row["host"])
        columns = list(rows[0]) if rows else []
        if rows:
            with self.db.tx() as conn:
                conn.executemany(f"INSERT INTO egress_log({','.join(columns)}) VALUES({','.join('?' * len(columns))})",
                                 [tuple(r[c] for c in columns) for r in rows])
        for host in new_hosts:
            row = next(r for r in uploads if r["host"] == host)
            key = self.db.one("SELECT name FROM agent_keys WHERE id=?", (row["key_id"],)) if row["key_id"] else None
            who = f"Agent key “{key['name']}”" if key else "An agent"
            self.engine.attention(
                "egress_upload", f"{host}:{row['ts'][:10]}", f"Large upload to {host}",
                f"{who} sent {row['bytes_up'] / (1024 * 1024):.1f} MB to {host}, a host it hadn't contacted in the "
                f"last {UPLOAD_NEW_DAYS} days.", url=f"{self.engine.public_url}/app/#/network", priority=4)
        for host, auth, ts in model_keys:
            self._model_key(host, auth, ts)
        return len(rows)

    def _model_key(self, host: str, auth: str, ts: str) -> None:
        """An API key (the proxy's hash of it) on a request to a model provider. A second one for a host is
        told: the agent may be sending what it read to someone else's account there."""
        with self.db.tx() as conn:
            if conn.execute("UPDATE egress_model_keys SET last_seen=?, count=count+1 WHERE host=? AND auth_hash=?",
                            (ts, host, auth)).rowcount:
                return
            others = conn.execute("SELECT COUNT(*) FROM egress_model_keys WHERE host=?", (host,)).fetchone()[0]
            if others >= MODEL_KEYS_PER_HOST:
                return  # told already; more of them add nothing
            conn.execute("INSERT INTO egress_model_keys(host, auth_hash, first_seen, last_seen, count) "
                         "VALUES(?,?,?,?,1)", (host, auth, ts, ts))
        if others:
            self.engine.attention(
                "egress_model_key", host, f"Another API key used with {host}",
                f"The agent sent a request to {host} with an API key Doorman hadn't seen there before ({others + 1} "
                f"different keys now). Requests to model providers aren't checked for your data, so a key that "
                f"isn't yours would let the agent hand what it read to someone else's account. More → Network "
                f"lists the keys.", url=f"{self.engine.public_url}/app/#/network", priority=4)

    def model_keys(self) -> list[dict]:
        """The API keys seen with model providers, for the owner's Network screen."""
        return self.db.all("SELECT host, auth_hash, first_seen, last_seen, count FROM egress_model_keys "
                           "ORDER BY host, first_seen LIMIT 500")

    @staticmethod
    def _record(record: dict) -> dict:
        row: dict[str, Any] = {}
        ts = record.get("ts")
        try:
            when = datetime.fromtimestamp(float(ts), timezone.utc) if ts is not None else clock.now()
        except (TypeError, ValueError, OverflowError, OSError):
            when = clock.now()
        row["ts"] = _ms(when)
        for name, n in TEXT_FIELDS.items():
            value = record.get(name)
            row[name] = str(value)[:n] if value is not None else None
        if row["kind"] not in KINDS:
            row["kind"] = "http"
        if row["decision"] not in ("allow", "deny"):
            row["decision"] = "allow"
        for name in INT_FIELDS:
            value = record.get(name)
            row[name] = int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None
        leak = record.get("leak")
        row["leak"] = dumps({"chars": int(leak.get("chars") or 0),
                             "sources": [str(x)[:120] for x in (leak.get("sources") or [])[:5]]}) \
            if isinstance(leak, dict) else None
        process = record.get("process")
        if isinstance(process, dict):
            chain = [{"pid": c.get("pid"), "cmdline": str(c.get("cmdline") or "")[:300]}
                     for c in (process.get("chain") or [])[:20] if isinstance(c, dict)]
            row["process"] = dumps({"pid": process.get("pid"), "exe": str(process["exe"])[:300]
                                    if process.get("exe") else None,
                                    "cmdline": str(process.get("cmdline") or "")[:300], "chain": chain})
        else:
            row["process"] = None
        row["scanned"] = int(bool(record.get("scanned")))
        return row

    def proxy_status(self, body: Any) -> None:
        """What the proxy says about itself (version, GeoIP rows and date...), kept as it came, small."""
        status = body if isinstance(body, dict) else {}
        text = dumps(status) or "{}"
        if len(text) > 4000:
            status = {"error": "the status was too large"}
        self.db.set_setting(STATUS, dumps({**status, "seen": clock.iso()}))
        self.proxy_seen()
        dropped = status.get("dropped")
        if isinstance(dropped, int) and not isinstance(dropped, bool) and dropped >= 0:
            self._dropped(dropped)
        self._check_tripwire(status)

    def _check_tripwire(self, status: dict) -> None:
        """Decoy keys only stop an agent that opens them while the observer watches their file. The proxy's
        status says whether it does (`observer`: {reachable, armed, error}; None without an observer). Off in
        two statuses in a row (not just new keys being put in place), with decoy keys on, the owner hears of
        it; the item goes once the wire is armed again or decoy keys are switched off."""
        why = None
        if self.settings()["decoys"].get("enabled", True):
            observer = status.get("observer")
            if not isinstance(observer, dict):
                why = "the network proxy has no observer to watch them (OBSERVER_URL in compose.egress.yaml)"
            elif observer.get("reachable") is not True:
                why = "the network proxy can't reach the observer (the egress-observer container)"
            elif observer.get("armed") is not True:
                error = _clip(_one_line(str(observer.get("error") or "")), 200)
                why = "the observer isn't watching their file" + (f" ({error})" if error else "")
        now = clock.now().timestamp()
        if why is None:
            self._tripwire_off = None
            self.engine.resolve_attention("egress_tripwire_off", "proxy")
            return
        if self._tripwire_off is None:
            self._tripwire_off = now
        if now - self._tripwire_off >= TRIPWIRE_GRACE:
            self.engine.attention(
                "egress_tripwire_off", "proxy", "The decoy keys aren't watched",
                f"Decoy keys are on, but {why}, so an agent that opens them isn't stopped (one that uses a key from "
                "them still is). Check the egress-observer container (docker compose ps, docker compose logs "
                "egress-observer) and that AGENT_HOME in deploy/.env is the agent's home.",
                url=f"{self.engine.public_url}/app/#/network", priority=4)

    def _dropped(self, dropped: int) -> None:
        """The proxy counts the log records it had to drop (its queue was full) since it started. When the
        count grows (or starts again above 0 after a restart) the log has gaps: the owner hears of it, until
        an hour passes without new drops (sweep)."""
        before = loads(self.db.get_setting(DROPPED), {}) or {}
        last = before.get("last") or 0
        grew = dropped > last or (dropped < last and dropped > 0)
        now = clock.now().timestamp()
        self.db.set_setting(DROPPED, dumps({"last": dropped, "grew": now if grew else before.get("grew")}))
        if grew:
            self.engine.attention(
                "egress_log_dropped", "proxy", "The network proxy dropped log records",
                f"The proxy couldn't hand some connections to Doorman in time and dropped their log records "
                f"({dropped} since it started). They were still checked and blocked as usual, but the log has gaps. "
                f"A flood of connections can cause this.", url=f"{self.engine.public_url}/app/#/network", priority=3)

    def status_view(self) -> dict:
        status = loads(self.db.get_setting(STATUS), None)
        seen = self._last_seen()
        return {"proxy": status, "seen": clock.iso(datetime.fromtimestamp(seen, timezone.utc)) if seen else None,
                "up": seen is not None and clock.now().timestamp() - seen < PROXY_DOWN_SECONDS}

    def counts(self) -> dict:
        """Today's connections, blocked ones and leaks (today in the owner's timezone)."""
        zone = ZoneInfo(self.engine.config.get("timezone") or "UTC")
        midnight = clock.now().astimezone(zone).replace(hour=0, minute=0, second=0, microsecond=0)
        row = self.db.one("SELECT COUNT(*) AS n, SUM(decision='deny') AS blocked, SUM(leak IS NOT NULL OR rule IN "
                          "('leak','honeytoken')) AS leaks FROM egress_log WHERE ts>=?", (_ms(midnight),))
        return {"today": row["n"] or 0, "blocked_today": row["blocked"] or 0, "leaks_today": row["leaks"] or 0}

    def log_view(self, task_id: int | None = None, key_id: int | None = None, only: str = "all",
                 before: int | None = None, limit: int = 100) -> list[dict]:
        sql, args = "SELECT * FROM egress_log WHERE 1=1", []
        for column, value in (("task_id", task_id), ("key_id", key_id)):
            if value is not None:
                sql += f" AND {column}=?"
                args.append(int(value))
        if only == "blocked":
            sql += " AND decision='deny'"
        elif only == "leaks":
            sql += " AND (leak IS NOT NULL OR rule IN ('leak','honeytoken'))"
        elif only not in ("all", None, ""):
            raise _invalid("only is all, blocked or leaks")
        if before is not None:
            sql += " AND id<?"
            args.append(int(before))
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(int(limit), 500)))
        rows = [{**r, "leak": loads(r["leak"], None), "process": loads(r["process"], None),
                 "scanned": bool(r["scanned"])} for r in self.db.all(sql, tuple(args))]
        return self.correlate(rows)

    def blocked_recent(self, key: dict, limit: int = 20) -> list[dict]:
        """What the proxy blocked for this key lately (doorman egress blocked). A honeytoken's or a quarantine's
        block is silent (the agent got a plain 502), so it isn't listed either."""
        return self.db.all("SELECT ts, host, port, rule, detail FROM egress_log WHERE key_id=? AND decision='deny' "
                           f"AND (rule IS NULL OR rule NOT IN ({','.join('?' * len(SILENT_RULES))})) "
                           "ORDER BY id DESC LIMIT ?", (key["id"], *SILENT_RULES, max(1, min(int(limit), 100))))

    # ------------------------------------------------------------------ the agent's tool calls

    def activity(self, session: dict, key: dict, body: Any) -> dict:
        """A tool call starting or ending, from the agent's hooks."""
        self.engine._validate(ACTIVITY_SCHEMA, body, "activity")
        most, seconds = ACTIVITY_RATE
        stamp = clock.now().timestamp()
        times = self._activity.setdefault(key["id"], deque(maxlen=most))
        if len(times) >= most and stamp - times[0] < seconds:
            raise Denied(f"more than {most} tool-call reports in {seconds // 60} minutes; wait a little",
                         "too_many")
        times.append(stamp)
        now = _ms()
        summary = _one_line(body.get("summary") or "")[:500]
        status = body.get("status") or "done"
        if body["phase"] == "start":
            with self.db.tx() as conn:
                conn.execute("INSERT INTO agent_activity(key_id, session_id, task_id, call_id, tool, summary, "
                             "started, status) VALUES(?,?,?,?,?,?,?,?)",
                             (key["id"], session.get("id"), session.get("task_id"), body["call_id"], body["tool"],
                              summary, now, "running"))
                # at most ACTIVITY_OPEN open calls: the oldest beyond that were abandoned
                conn.execute("UPDATE agent_activity SET ended=?, status='abandoned' WHERE id IN (SELECT id FROM "
                             "agent_activity WHERE key_id=? AND ended IS NULL ORDER BY id DESC LIMIT -1 OFFSET ?)",
                             (now, key["id"], ACTIVITY_OPEN))
            return {"ok": True}
        with self.db.tx() as conn:
            row = conn.execute("SELECT id FROM agent_activity WHERE key_id=? AND call_id=? AND ended IS NULL "
                               "ORDER BY id DESC LIMIT 1", (key["id"], body["call_id"])).fetchone()
            if row:
                conn.execute("UPDATE agent_activity SET ended=?, status=? WHERE id=?", (now, status, row["id"]))
            else:  # the start was missed: kept as a call of no length
                conn.execute("INSERT INTO agent_activity(key_id, session_id, task_id, call_id, tool, summary, started, "
                             "ended, status) VALUES(?,?,?,?,?,?,?,?,?)",
                             (key["id"], session.get("id"), session.get("task_id"), body["call_id"], body["tool"],
                              summary, now, now, status))
        return {"ok": True}

    def correlate(self, rows: list[dict]) -> list[dict]:
        """Ties each log row of a known key to the tool call that made it: the call whose summary (the
        command) shows in the connection's process or one of its parents, or else the latest one running
        at the time (from a second before it started to two after it ended). A row of a key that reported
        calls in the 24 hours before, but none then, gets `outside_call`."""
        by_key: dict[int, list[dict]] = {}
        for row in rows:
            if row.get("key_id") is not None:
                by_key.setdefault(row["key_id"], []).append(row)
        now = clock.now()
        longest = timedelta(hours=CALL_HOURS)  # an open call counts as ended after this (sweep closes it)
        for key_id, mine in by_key.items():
            times = [clock.parse(r["ts"]) for r in mine]
            # only calls that can hold one of these rows: started at most CALL_HOURS before the first
            calls = self.db.all("SELECT * FROM agent_activity WHERE key_id=? AND started<=? AND started>=? AND "
                                "(ended IS NULL OR ended>=?) ORDER BY started LIMIT 20000",
                                (key_id, _ms(max(times) + timedelta(seconds=1)),
                                 _ms(min(times) - longest - timedelta(seconds=2)),
                                 _ms(min(times) - timedelta(seconds=2))))
            spans = []
            for c in calls:
                start = clock.parse(c["started"])
                spans.append((c, start, clock.parse(c["ended"]) if c["ended"] else min(now, start + longest)))
            for row, ts in zip(mine, times):
                inside = [c for c, start, end in spans
                          if start - timedelta(seconds=1) <= ts <= end + timedelta(seconds=2)]
                commands = self._commands(row.get("process"))
                by_chain = [c for c in inside if len(c["summary"] or "") >= 4
                            and any(c["summary"] in cmd for cmd in commands)]
                match = (by_chain or inside or [None])[-1]
                if match:
                    row["call"] = {"id": match["call_id"], "tool": match["tool"], "summary": match["summary"]}
                elif self.db.one("SELECT 1 FROM agent_activity WHERE key_id=? AND started<=? AND started>=? LIMIT 1",
                                 (key_id, row["ts"], _ms(ts - timedelta(hours=24)))):
                    row["outside_call"] = True
        return rows

    @staticmethod
    def _commands(process: Any) -> list[str]:
        if not isinstance(process, dict):
            return []
        chain = process.get("chain") or []
        return [str(process.get("cmdline") or "")] + [str(c.get("cmdline") or "") for c in chain if isinstance(c, dict)]

    # ------------------------------------------------------------------ the agent asks for access

    def request_access(self, session: dict, key: dict, body: Any) -> dict:
        engine = self.engine
        engine._guard(session, None, write=False)
        if key["role"] == "reader":
            raise Denied("reader keys don't reach the network through Doorman's proxy; the acting agent asks", "role")
        engine._validate(REQUEST_SCHEMA, body, "request")
        target = body["target"].strip()
        if rules.parse_target(target) is None:
            raise _invalid("target is a host (example.com), *.example.com, an IP address or a network, with an "
                           "optional :port; no scheme or path")
        reason = _one_line(body["reason"])
        if len(reason) < 3:
            raise _invalid("say why the task needs it")
        self.sweep()
        waiting = self.db.one("SELECT COUNT(*) AS n FROM egress_requests WHERE key_id=? AND status='open'",
                              (key["id"],))["n"]
        if waiting >= OPEN_PER_KEY:
            raise Denied(f"{waiting} of your network requests are still open; wait for the owner (doorman wait "
                         "egress-request:<id>) before asking for more", "too_many")
        now = clock.now()
        rid = self.db.exec(
            "INSERT INTO egress_requests(key_id, session_id, task_id, target, reason, status, created, expires) "
            "VALUES(?,?,?,?,?,'open',?,?)",
            (key["id"], session["id"], session.get("task_id"), target.lower(), reason, clock.iso(now),
             clock.iso(now + timedelta(hours=EXPIRE_HOURS))))
        engine.notifier.push(f"{key.get('name') or 'Your agent'} asks for network access",
                             _clip(f"{target.lower()}: {reason}", 300),
                             url=f"{engine.public_url}/app/#/inbox/network/{rid}", priority=4,
                             extra={"ask": engine.push_ask("network", rid)})  # Deny and Allow once
        return self.view(self._row(rid))

    def _row(self, rid: int) -> dict | None:
        return self.db.one("SELECT * FROM egress_requests WHERE id=?", (rid,))

    @staticmethod
    def view(row: dict) -> dict:
        """What the agent sees of its request."""
        out = {"id": row["id"], "target": row["target"], "reason": row["reason"], "status": row["status"],
               "scope": row["scope"], "asked": row["created"], "expires": row["expires"]}
        if row["task_id"]:
            out["task_id"] = row["task_id"]
        if row["decided"]:
            out["decided"] = row["decided"]
        return out

    def get_request(self, session: dict, key: dict, rid: int) -> dict:
        self.sweep()
        row = self._row(rid)
        if row is None or row["key_id"] != key["id"]:
            raise Denied("no such network request", "not_found")
        return self.view(row)

    def my_requests(self, session: dict, key: dict, limit: int = 20) -> list[dict]:
        self.sweep()
        rows = self.db.all("SELECT * FROM egress_requests WHERE key_id=? ORDER BY id DESC LIMIT ?",
                           (key["id"], max(1, min(int(limit), 100))))
        return [self.view(r) for r in rows]

    # ------------------------------------------------------------------ the owner decides

    def open_requests(self) -> list[dict]:
        """The owner's inbox: open requests, oldest first, with what was blocked, the task and what the
        agent read lately (so the owner can judge what it might take along)."""
        self.sweep()
        hours = self.settings()["match_hours"]
        out = []
        for row in self.db.all("SELECT r.*, k.name AS key_name FROM egress_requests r LEFT JOIN agent_keys k "
                               "ON k.id=r.key_id WHERE r.status='open' ORDER BY r.id"):
            task = self.engine.tasks.get(row["task_id"]) if row["task_id"] else None
            out.append({"id": row["id"], "target": row["target"], "reason": row["reason"], "agent": row["key_name"],
                        "asked": row["created"], "expires": row["expires"], "blocked": self._blocked_for(row),
                        "task": {"id": task["id"], "text": task["text"], "trusted": task["trusted"],
                                 "origin": task.get("origin")} if task else None,
                        "reads": self._reads_line(row["key_id"], hours)})
        return out

    def _blocked_for(self, row: dict) -> dict | None:
        """The latest connection of this key the target would have let through, blocked in the day before
        the request."""
        target = rules.parse_target(row["target"])
        since = _ms(clock.parse(row["created"]) - timedelta(hours=24))
        for hit in self.db.all("SELECT ts, host, ip, port, rule, detail FROM egress_log WHERE key_id=? AND "
                               "decision='deny' AND ts>=? ORDER BY id DESC LIMIT 200", (row["key_id"], since)):
            if target and rules.matches(target, hit["host"], hit["ip"], hit["port"] or 0):
                return {"ts": hit["ts"], "rule": hit["rule"], "detail": hit["detail"]}
        return None

    def _reads_line(self, key_id: int, hours: float) -> str | None:
        since = clock.iso(clock.now() - timedelta(hours=hours))
        rows = self.db.all("SELECT name, SUM(items) AS n FROM reads WHERE key_id=? AND ts>=? AND status IN "
                           "('ok','unscanned') GROUP BY name", (key_id, since))
        by_source: dict[str, int] = {}
        for row in rows:
            source = row["name"].split(".", 1)[0]
            by_source[source] = by_source.get(source, 0) + int(row["n"] or 0)
        parts = []
        for source, n in sorted(by_source.items(), key=lambda kv: -kv[1]):
            if n <= 0:
                continue
            noun = ("file" if source == "files" else f"{source} item") + ("" if n == 1 else "s")
            parts.append(f"{n} {noun}")
        hours_text = f"{hours:g}"
        return f"read {', '.join(parts)} in the last {hours_text} h" if parts else None

    def decide(self, rid: int, decision: str) -> dict:
        """once (an hour), task (until the request's task ends, a day at most), always (the allow list) or
        deny. The asking key hears it (egress_decided)."""
        if decision not in DECISIONS:
            raise _invalid("decision is once, task, always or deny")
        self.sweep()
        row = self._row(rid)
        if row is None:
            raise Denied("no such network request", "not_found")
        if row["status"] != "open":
            raise _invalid(f"this request is {row['status']} already")
        now = clock.now()
        expires = None
        if decision == "task":
            task = self.engine.tasks.get(row["task_id"]) if row["task_id"] else None
            if task is None or task["status"] not in TASK_OPEN:
                raise _invalid("the agent didn't ask for an open task; allow it once or always instead")
            expires = now + timedelta(hours=TASK_HOURS)
        elif decision == "once":
            expires = now + timedelta(hours=ONCE_HOURS)
        status = "denied" if decision == "deny" else "granted"
        scope = None if decision == "deny" else decision
        with self.db.tx() as conn:
            changed = conn.execute("UPDATE egress_requests SET status=?, scope=?, decided=? WHERE id=? AND "
                                   "status='open'", (status, scope, clock.iso(now), rid)).rowcount
            if changed and expires is not None:
                conn.execute("INSERT INTO egress_exemptions(target, scope, task_id, key_id, request_id, created, "
                             "expires) VALUES(?,?,?,?,?,?,?)",
                             (row["target"], decision, row["task_id"] if decision == "task" else None, row["key_id"],
                              rid, _ms(now), _ms(expires)))
        if not changed:
            raise _invalid("this request was decided meanwhile")
        if decision == "always":
            stored = loads(self.db.get_setting(SETTINGS), {}) or {}
            allow = list(self.settings()["allow"])
            if row["target"] not in allow:
                stored["allow"] = [*allow, row["target"]]
                self.db.set_setting(SETTINGS, dumps(stored))
        row = self._row(rid)
        key = self.db.one("SELECT name FROM agent_keys WHERE id=?", (row["key_id"],)) or {}
        agent = key.get("name") or "the agent"
        said = {"once": f"Allowed {agent} to reach {row['target']} for an hour",
                "task": f"Allowed {agent} to reach {row['target']} for task {row['task_id']}",
                "always": f"Added {row['target']} to the network allow list, as {agent} asked",
                "deny": f"Denied {agent} network access to {row['target']}"}[decision]
        self.engine.journal.create(kind="config", tool=f"egress.request.{decision}", tier="irreversible",
                                   decision="run", status="done", task_id=row["task_id"],
                                   args={"request_id": rid, "target": row["target"]}, summary=said)
        self.engine.feed.egress_decided({**row, "expires": clock.iso(expires) if expires else None})
        return self.view(row)

    def exemptions(self) -> list[dict]:
        """The exceptions in force now, for the owner's Network screen."""
        names = {r["id"]: r["name"] for r in self.db.all("SELECT id, name FROM agent_keys")}
        return [{"id": e["id"], "target": e["target"], "scope": e["scope"], "task_id": e["task_id"],
                 "key_id": e["key_id"], "agent": names.get(e["key_id"]), "request_id": e["request_id"],
                 "created": e["created"], "expires": e["expires"]} for e in self._running()]

    def revoke_exemption(self, eid: int) -> None:
        row = self.db.one("SELECT * FROM egress_exemptions WHERE id=?", (eid,))
        if row is None:
            raise Denied("no such exception", "not_found")
        self.db.exec("DELETE FROM egress_exemptions WHERE id=?", (eid,))
        self.engine.journal.create(kind="config", tool="egress.exemption.revoke", tier="irreversible", decision="run",
                                   status="done", task_id=row["task_id"], args={"exemption_id": eid},
                                   summary=f"Ended the network exception for {row['target']}")

    # ------------------------------------------------------------------ housekeeping

    def sweep(self, force: bool = False) -> None:
        """At most once a minute: give up requests nobody decided (the agent hears `expired`), drop exceptions
        that ran out or whose task ended, forget reads after match_hours and the log after log_days, and tell
        the owner when the proxy stopped calling in."""
        if not force and clock.now().timestamp() - self._swept < 60:
            return
        self._swept = clock.now().timestamp()
        s = self.settings()
        now = clock.iso()
        with self.db.tx() as conn:
            expired = [dict(r) for r in conn.execute("SELECT * FROM egress_requests WHERE status='open' AND "
                                                     "expires<?", (now,)).fetchall()]
            conn.execute("UPDATE egress_requests SET status='expired' WHERE status='open' AND expires<?", (now,))
        for row in expired:
            self.engine.feed.egress_decided({**row, "status": "expired", "expires": None})
        self.db.exec("DELETE FROM egress_exemptions WHERE expires<=? OR (scope='task' AND (task_id IS NULL OR "
                     f"task_id NOT IN (SELECT id FROM tasks WHERE status IN ({','.join('?' * len(TASK_OPEN))}))))",
                     (_ms(), *TASK_OPEN))
        reads_before = _ms(clock.now() - timedelta(hours=float(s["match_hours"])))
        self._delete_batches("DELETE FROM egress_prints WHERE rowid IN (SELECT p.rowid FROM egress_prints p JOIN "
                             "egress_sources s ON s.id=p.source_id WHERE s.ts<? LIMIT ?)", (reads_before,))
        self._delete_batches("DELETE FROM egress_sources WHERE id IN (SELECT id FROM egress_sources WHERE ts<? "
                             "LIMIT ?)", (reads_before,))
        log_before = _ms(clock.now() - timedelta(days=float(s["log_days"])))
        self._delete_batches("DELETE FROM egress_log WHERE id IN (SELECT id FROM egress_log WHERE ts<? LIMIT ?)",
                             (log_before,))
        self._delete_batches("DELETE FROM agent_activity WHERE id IN (SELECT id FROM agent_activity WHERE started<? "
                             "LIMIT ?)", (log_before,))
        self._close_calls()
        with self.db.tx() as conn:
            conn.execute("DELETE FROM agent_addresses WHERE seen<?",
                         (_us(clock.now() - timedelta(hours=ADDRESS_HOURS)),))
            conn.execute("DELETE FROM egress_requests WHERE status!='open' AND created<?", (clock.iso(
                clock.now() - timedelta(days=float(s["log_days"]))),))
        self._seen = {k: v for k, v in self._seen.items() if self._swept - v < SEEN_EVERY}
        self._activity = {k: v for k, v in self._activity.items() if v and self._swept - v[-1] < ACTIVITY_RATE[1]}
        self._sight_back()
        self._check_proxy()

    def _delete_batches(self, sql: str, args: tuple) -> None:
        """A DELETE ... LIMIT ? (its last parameter) run until nothing is left, a transaction per batch, so
        the shared database lock is never held for long."""
        while True:
            with self.db.tx() as conn:
                if conn.execute(sql, (*args, DELETE_BATCH)).rowcount < DELETE_BATCH:
                    return

    def _close_calls(self) -> None:
        """A call open longer than CALL_HOURS ends then, as abandoned: an agent mustn't cover all its
        traffic with one call it never ends."""
        before = clock.now() - timedelta(hours=CALL_HOURS)
        while True:
            rows = self.db.all("SELECT id, started FROM agent_activity WHERE ended IS NULL AND started<? LIMIT ?",
                               (_ms(before), DELETE_BATCH))
            if not rows:
                return
            with self.db.tx() as conn:
                conn.executemany("UPDATE agent_activity SET ended=?, status='abandoned' WHERE id=?",
                                 [(_ms(clock.parse(r["started"]) + timedelta(hours=CALL_HOURS)), r["id"])
                                  for r in rows])

    def _sight_back(self) -> None:
        """Keys no longer blind (what they read is forgotten by now): off the owner's list."""
        blind = self._blind_map()
        stored = loads(self.db.get_setting(BLIND), {}) or {}
        if stored != blind:
            self.db.set_setting(BLIND, dumps(blind))
        refs = {k or "tasks" for k in blind}
        for row in self.db.all("SELECT ref FROM attention WHERE kind='egress_blind' AND resolved IS NULL"):
            if row["ref"] not in refs:
                self.engine.resolve_attention("egress_blind", row["ref"])

    def _check_proxy(self) -> None:
        dropped = loads(self.db.get_setting(DROPPED), {}) or {}
        if not dropped.get("grew") or clock.now().timestamp() - dropped["grew"] >= DROPPED_QUIET:
            self.engine.resolve_attention("egress_log_dropped", "proxy")
        if not self.enabled():
            self.engine.resolve_attention("egress_proxy_down", "proxy")
            self.engine.resolve_attention("egress_tripwire_off", "proxy")
            return
        seen = self._last_seen()
        made = self.db.get_setting(TOKEN_MADE)
        since = seen if seen is not None else (_epoch(made) if made else None)
        if since is not None and clock.now().timestamp() - since > PROXY_DOWN_SECONDS:
            self.engine.attention(
                "egress_proxy_down", "proxy", "The network proxy isn't calling in",
                "Doorman hasn't heard from the network proxy for over 5 minutes. While it's down the agent's "
                "container can't reach the internet (or, if the proxy is gone, isn't watched). Check the egress "
                "container (docker compose ps).", url=f"{self.engine.public_url}/app/#/network", priority=4)
        else:
            self.engine.resolve_attention("egress_proxy_down", "proxy")
