"""Push notifications to the owner app through Web Push. Every notice is also stored, pushed or not."""

import json
import logging
import math
import random
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from . import clock
from .util import sha256_hex
from .webpush import Vapid, b64url_decode, encrypt, load_subscriber_key

log = logging.getLogger("doorman.notify")

VAULT_SECTION = "_broker"  # named before the rename to Doorman; existing vaults keep the VAPID key here
MAX_PAYLOAD = 3000       # bytes of JSON; one record holds 3993 bytes of plaintext (RFC 8291, section 4)
MAX_SUBSCRIPTIONS = 10
MAX_DELIVERIES = 16      # notices being delivered (or waiting to retry) at the same time


class PushGone(ValueError):
    """The push service said this endpoint no longer exists; the browser must subscribe afresh."""


@dataclass
class Attempt:
    ok: bool
    status: int | None = None
    reason: str = ""
    retry: bool = False
    retry_after: float = 0.0


def _clip(text: str, limit: int) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _reason(response: httpx.Response) -> str:
    """Apple answers with {"reason": ...}; the others with plain text."""
    try:
        return str(response.json().get("reason", ""))[:200]
    except (ValueError, AttributeError):
        return response.text[:200].strip()


def _retry_after(response: httpx.Response) -> float:
    try:
        return max(0.0, float(response.headers.get("Retry-After", "")))
    except ValueError:
        return 0.0


def endpoint_hash(endpoint: str) -> str:
    """How a device that logged out is remembered (push_logged_out): not by its endpoint, which is enough to
    address pushes to it."""
    return sha256_hex("push-endpoint:" + endpoint)


def subject_ok(subject: str | None) -> bool:
    """Push services (Apple most strictly) want a reachable contact: mailto: or an https URL, not localhost."""
    if not subject or " " in subject or "<" in subject:
        return False
    if subject.startswith("mailto:"):
        return "@" in subject and not subject.rstrip(".").endswith(("localhost", ".local"))
    host = urlsplit(subject).hostname or ""
    return subject.startswith("https://") and host not in ("localhost", "127.0.0.1", "::1") and not host.endswith(".local")


class Notifier:
    RETRY_DELAYS = (10, 30, 120, 600)  # seconds before each retry; a Retry-After from the service can stretch them

    def __init__(self, config, db, vault, transport: httpx.BaseTransport | None = None):
        self.config = config
        self.db = db
        self.vault = vault
        self.transport = transport  # tests pass an httpx.MockTransport
        push = config.get("push") or {}
        self.ttl = int(push.get("ttl_seconds") or 86400)
        public_url = config.get("public_url") or ""
        self.subject = push.get("subject") or (public_url if public_url.startswith("https://") else None)
        if not subject_ok(self.subject):
            log.warning("push.subject should be a mailto: address or an https URL; Apple refuses pushes without one")
        self._vapid: Vapid | None = None
        self._vapid_lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(MAX_DELIVERIES)

    @property
    def vapid(self) -> Vapid:
        """Doorman's VAPID key, created on first use and kept in the vault."""
        with self._vapid_lock:
            if self._vapid is None:
                pem = self.vault.get(VAULT_SECTION).get("vapid_private_key")
                if not pem:
                    pem = Vapid.generate().to_pem()
                    self.vault.set(VAULT_SECTION, "vapid_private_key", pem)  # saved before it's ever used
                self._vapid = Vapid.from_pem(pem)
            return self._vapid

    # ---------------------------------------------------------------- subscriptions

    def subscribe(self, subscription: dict, label: str = "", credential_id: str | None = None,
                  session_hash: str | None = None) -> int:
        """Stores a browser's PushSubscription (its toJSON() form). Raises ValueError if it isn't one.
        `credential_id`: the passkey the device is logged in with; removing it drops the subscription.
        `session_hash`: the login (owner_sessions.token_hash); logging out drops the subscription. The app
        subscribes again on every start and after every login, so a subscription follows the login and the
        passkey its device uses now."""
        endpoint = str(subscription.get("endpoint") or "")
        keys = subscription.get("keys") or {}
        parts = urlsplit(endpoint)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError("the push endpoint must be an https URL")
        try:
            load_subscriber_key(str(keys.get("p256dh") or ""))
            auth = b64url_decode(str(keys.get("auth") or ""))
        except (ValueError, TypeError) as exc:
            raise ValueError("the subscription keys are not valid") from exc
        if len(auth) != 16:
            raise ValueError("the subscription keys are not valid")
        if self.db.one("SELECT 1 AS gone FROM push_gone WHERE endpoint=?", (endpoint,)):
            raise PushGone("the push service dropped this subscription; subscribe again for a new one")
        self.db.exec("DELETE FROM push_logged_out WHERE endpoint_hash=?", (endpoint_hash(endpoint),))  # it's back
        existing = self.db.one("SELECT id, p256dh, auth FROM push_subscriptions WHERE endpoint=?", (endpoint,))
        if existing:
            owners = "credential_id=coalesce(?, credential_id), session_hash=coalesce(?, session_hash)"
            if (existing["p256dh"], existing["auth"]) == (keys["p256dh"], keys["auth"]):
                self.db.exec(f"UPDATE push_subscriptions SET label=?, {owners} WHERE id=?",
                             (label[:80], credential_id, session_hash, existing["id"]))
            else:
                self.db.exec(f"UPDATE push_subscriptions SET p256dh=?, auth=?, label=?, failures=0, last_error=NULL, "
                             f"{owners} WHERE id=?",
                             (keys["p256dh"], keys["auth"], label[:80], credential_id, session_hash, existing["id"]))
            return existing["id"]
        if self.db.one("SELECT COUNT(*) AS n FROM push_subscriptions")["n"] >= MAX_SUBSCRIPTIONS:
            raise ValueError(f"at most {MAX_SUBSCRIPTIONS} devices; remove one first")
        return self.db.exec(
            "INSERT INTO push_subscriptions(endpoint, p256dh, auth, label, created, failures, credential_id, "
            "session_hash) VALUES(?,?,?,?,?,0,?,?)",
            (endpoint, keys["p256dh"], keys["auth"], label[:80], clock.iso(), credential_id, session_hash))

    def known(self, endpoint: object) -> bool:
        """Whether this push endpoint gets Doorman's notifications, or did until its device logged out (the
        owner logging in again on their own phone is no new device). Removing the device, its passkey or
        every login (doorman-admin logout-all) forgets it: coming back after that is news again."""
        endpoint = str(endpoint or "")
        return bool(self.db.one("SELECT 1 AS x FROM push_subscriptions WHERE endpoint=?", (endpoint,))
                    or self.db.one("SELECT 1 AS x FROM push_logged_out WHERE endpoint_hash=?", (endpoint_hash(endpoint),)))

    def unsubscribe(self, subscription_id: int | None = None, endpoint: str | None = None) -> bool:
        if subscription_id is not None:
            row = self.db.one("SELECT id FROM push_subscriptions WHERE id=?", (subscription_id,))
        else:
            row = self.db.one("SELECT id FROM push_subscriptions WHERE endpoint=?", (endpoint,))
        if row:
            self.db.exec("DELETE FROM push_subscriptions WHERE id=?", (row["id"],))
        return row is not None

    def subscriptions(self) -> list[dict]:
        return self.db.all("SELECT id, label, created, last_ok, failures, last_error FROM push_subscriptions ORDER BY id")

    # ---------------------------------------------------------------- sending

    def push(self, title: str, message: str, url: str | None = None, priority: int = 3, wait: bool = False,
             ttl: int | None = None, extra: dict | None = None, exclude: int | None = None) -> int:
        """Stores the notice and pushes it to every subscribed device in the background; a tap opens url.
        `extra` (small) goes into the payload as it is: `approval` (a send's id and hash) or `ask` (any
        other yes or no, Engine.push_ask) for the buttons, `tag` to replace an earlier push.
        `exclude`: a subscription that doesn't get this one (a new device isn't told about itself)."""
        note_id = self.db.exec(
            "INSERT INTO notifications(ts, title, message, url, delivered) VALUES(?,?,?,?,0)",
            (clock.iso(), title, message, url),
        )
        subscriptions = [s for s in self.db.all("SELECT * FROM push_subscriptions") if s["id"] != exclude]
        if not subscriptions:
            return note_id
        if not self._slots.acquire(blocking=False):
            log.warning("%d notices are still being delivered; notice %s is stored but not pushed",
                        MAX_DELIVERIES, note_id)
            return note_id
        payload = self._payload(note_id, title, message, url, extra)
        urgency = "high" if priority >= 4 else "normal"
        thread = threading.Thread(target=self._deliver, daemon=True,
                                  args=(note_id, payload, subscriptions, urgency, ttl or self.ttl))
        thread.start()
        if wait:
            thread.join(timeout=30)
        return note_id

    def test(self, url: str | None = None) -> list[dict]:
        """Sends a test notice to every device once, right now, and says how each push service answered."""
        payload = self._payload(0, "Test notification", "Notifications from Doorman reach this device.", url)
        results = []
        with httpx.Client(transport=self.transport, timeout=15) as client:
            for subscription in self.db.all("SELECT * FROM push_subscriptions"):
                attempt = self._attempt(client, subscription, payload, "normal", 300)
                results.append({"id": subscription["id"], "label": subscription["label"], "ok": attempt.ok,
                                "status": attempt.status, "reason": attempt.reason})
        return results

    def _payload(self, note_id: int, title: str, message: str, url: str | None, extra: dict | None = None) -> bytes:
        extra = extra or {}
        data = {"title": _clip(title, 120), "body": _clip(message, 1000), "url": url or "/app/", "tag": f"n{note_id}",
                **extra}
        encoded = json.dumps(data, ensure_ascii=False).encode()
        if len(encoded) > MAX_PAYLOAD:
            # every byte cut from the body shortens the JSON by at least one byte
            body = data["body"].encode()
            data["body"] = body[: max(0, len(body) - (len(encoded) - MAX_PAYLOAD) - 3)].decode("utf-8", "ignore") + "…"
            encoded = json.dumps(data, ensure_ascii=False).encode()
        if len(encoded) > MAX_PAYLOAD:  # only very long URLs get here: a plain notice beats none
            for key in ("approval", "ask"):  # with nothing shown, Accept must open the app
                if key in extra:
                    extra = {**extra, key: {**extra[key], "accept": "app"}}
            encoded = json.dumps({"title": data["title"], "body": "", "url": "/app/", "tag": data["tag"], **extra},
                                 ensure_ascii=False).encode()
        return encoded

    def _deliver(self, note_id: int, payload: bytes, subscriptions: list[dict], urgency: str, ttl: int) -> None:
        """Tries every device once, then retries only the ones that failed, until the notice's TTL runs out."""
        try:
            deadline = time.monotonic() + ttl
            delays = iter(self.RETRY_DELAYS)
            pending, delivered, remaining = list(subscriptions), False, ttl
            with httpx.Client(transport=self.transport, timeout=15) as client:
                while True:
                    retry, wait = [], 0.0
                    for subscription in pending:
                        attempt = self._attempt(client, subscription, payload, urgency, remaining)
                        if attempt.ok and not delivered:
                            delivered = True
                            self.db.exec("UPDATE notifications SET delivered=1 WHERE id=?", (note_id,))
                        elif attempt.retry:
                            retry.append(subscription)
                            wait = max(wait, attempt.retry_after)
                    pending = retry
                    if not pending:
                        return
                    delay = next(delays, None)
                    wait = min(max(wait, delay or 0.0), 3600.0)
                    if delay is None or time.monotonic() + wait >= deadline:
                        log.warning("notice %s: gave up on %d device(s) before its TTL ran out", note_id, len(pending))
                        return
                    time.sleep(wait * random.uniform(1.0, 1.2))
                    remaining = max(1, math.ceil(deadline - time.monotonic()))
        except Exception:  # never let a bad notice take the delivery thread down silently
            log.exception("delivering notice %s failed", note_id)
        finally:
            self._slots.release()

    def _attempt(self, client: httpx.Client, subscription: dict, payload: bytes, urgency: str, ttl: int) -> Attempt:
        try:
            headers = {
                "Authorization": self.vapid.authorization(
                    subscription["endpoint"], self.subject if subject_ok(self.subject) else "mailto:doorman@localhost",
                    int(clock.now().timestamp())),
                "Content-Encoding": "aes128gcm",
                "Content-Type": "application/octet-stream",
                "TTL": str(ttl),
                "Urgency": urgency,
            }
            body = encrypt(payload, subscription["p256dh"], subscription["auth"])
            response = client.post(subscription["endpoint"], content=body, headers=headers)
        except httpx.HTTPError as exc:
            self._failed(subscription, f"unreachable: {exc}")
            return Attempt(ok=False, reason=str(exc), retry=True)
        except Exception as exc:  # a broken subscription row or key: skip this device, keep the others
            log.exception("push to device %s failed", subscription["id"])
            self._failed(subscription, f"{type(exc).__name__}: {exc}")
            return Attempt(ok=False, reason=str(exc))
        status = response.status_code
        if 200 <= status < 300:
            self.db.exec("UPDATE push_subscriptions SET last_ok=?, failures=0, last_error=NULL WHERE id=?",
                         (clock.iso(), subscription["id"]))
            return Attempt(ok=True, status=status)
        reason = _reason(response)
        if status in (404, 410):
            log.info("push service dropped device %s; removing it", subscription["id"])
            self.unsubscribe(subscription_id=subscription["id"])
            self.db.exec("INSERT OR IGNORE INTO push_gone(endpoint, ts) VALUES(?,?)",
                         (subscription["endpoint"], clock.iso()))
            return Attempt(ok=False, status=status, reason=reason)
        self._failed(subscription, f"HTTP {status} {reason}".strip())
        retry = status == 429 or status >= 500
        if not retry:
            log.warning("push service refused the notice for device %s (HTTP %s %s)", subscription["id"], status, reason)
        return Attempt(ok=False, status=status, reason=reason, retry=retry, retry_after=_retry_after(response))

    def _failed(self, subscription: dict, error: str) -> None:
        self.db.exec("UPDATE push_subscriptions SET failures=failures+1, last_error=? WHERE id=?",
                     (error[:200], subscription["id"]))
