"""Doorman's WhatsApp sidecar: wacli (github.com/steipete/wacli) plus a small HTTP API.

wacli is a WhatsApp Web client on whatsmeow. It keeps a linked-device session and a copy of the
messages in SQLite. This script keeps `wacli sync --follow` running and answers Doorman over HTTP by
running wacli commands; it never talks to WhatsApp itself.

    GET  /status                      linked?, sync running?, last error, linking (as /link)
    GET  /chats?limit=N&query=Q       wacli chats list (Q: part of a name or JID)
    GET  /messages?chat=J&limit=N     wacli messages list (newest first)
    GET  /messages?chat=J&after=T     ... only messages after T (RFC 3339), oldest first
    GET  /messages?chat=J&before=T    ... only messages before T, newest first; with after=A too, between A and T
                                      (Doorman's search index reads a chat's history and its days this way)
    GET  /changes                     a checkpoint for "from now on" (wacli messages changes --checkpoint)
    GET  /changes?since=C&limit=N     what changed in the message store since checkpoint C
    POST /send {"chat": J, "text": T} wacli send text; only while sync runs, so the send goes through it
    GET  /link                        linking: its state and the latest QR or pairing code
    POST /link {"phone": P}           start linking (wacli auth); with phone, a pairing code instead of a QR code.
                                      While one runs: the same again returns it, another way replaces it
    POST /unlink                      stop sync and log this device out of WhatsApp (wacli auth logout)

Every request needs `Authorization: Bearer <token>`. The token is $SIDECAR_TOKEN or, without it, the one in
$SIDECAR_TOKEN_FILE, which the shim makes up on its first start. The shim writes the token it uses to that
file, which Doorman reads from a volume both containers mount. Answers are wacli's `data`, as JSON.
A 4xx on /send means the message was certainly not sent; a 5xx means it may have been.

Link the account first (sync never shows a QR code): Connect in Doorman's app (Plugins → whatsapp), which
uses /link, or in the shell while this runs:
    docker compose exec whatsapp wacli auth            (QR code), or
    docker compose exec whatsapp wacli auth --phone +49...   (pairing code)
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

WACLI = os.environ.get("WACLI", "wacli")
JID = re.compile(r"^[0-9a-zA-Z.:-]+@(s\.whatsapp\.net|g\.us|lid)$")
STAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$")
PHONE = re.compile(r"^\+?[0-9][0-9 ()./-]{5,24}$")
SYNC_ARGS = ["sync", "--follow", "--presence-mode", "quiet", "--max-reconnect", "0",
             "--stale-threshold", "2m", "--refresh-contacts", "--refresh-groups"]


class WacliError(Exception):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


def run(args: list[str], timeout: float = 60) -> object:
    """One wacli command with --json; returns its data or raises WacliError with wacli's message."""
    try:
        done = subprocess.run([WACLI, "--json", *args], capture_output=True, text=True, timeout=timeout,
                              stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        raise WacliError(f"wacli {args[0]} took longer than {timeout:.0f} s") from None
    except OSError as exc:
        raise WacliError(f"can't run wacli: {exc}") from None
    return envelope(done.stdout, done.stderr, done.returncode)


def envelope(stdout: str, stderr: str, returncode: int) -> object:
    """wacli's --json answer: its data, or WacliError with wacli's message."""
    answer = None
    for stream in (stdout, stderr):  # the error envelope may come on either
        for line in reversed(stream.strip().splitlines()):
            if line.startswith("{"):
                try:
                    answer = json.loads(line)
                except ValueError:
                    continue
                if isinstance(answer, dict) and "success" in answer:
                    break
                answer = None
        if answer:
            break
    if answer and answer.get("success") and returncode == 0:
        return answer.get("data")
    message = (answer or {}).get("error") or stderr.strip()[-500:] or f"wacli exited {returncode}"
    raise WacliError(message)


class Sync:
    """Keeps `wacli sync --follow` running once the account is linked; waits while it isn't."""

    def __init__(self):
        self.process: subprocess.Popen | None = None
        self.linked: bool | None = None
        self.phone: str | None = None
        self.last_error = ""
        self.started = 0.0
        self.paused = False  # /unlink: sync stays stopped while the device logs out
        self.wake = threading.Event()
        self.lock = threading.Lock()

    def running(self) -> bool:
        with self.lock:
            return self.process is not None and self.process.poll() is None

    def check_linked(self) -> bool:
        try:  # read-only: it doesn't wait for the store lock that sync or a running auth holds
            status = run(["--read-only", "auth", "status"], timeout=30)
            self.linked = bool(isinstance(status, dict) and status.get("authenticated"))
            self.phone = status.get("phone") if self.linked else None
        except WacliError as exc:
            self.last_error = str(exc)
            self.linked = False
        return self.linked

    def stop(self) -> None:
        with self.lock:
            process = self.process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(5)

    def loop(self):
        delay = 5
        while True:
            if not self.running() and not self.paused and not LINK.busy() and self.check_linked():
                with self.lock:
                    self.process = subprocess.Popen([WACLI, *SYNC_ARGS], stdin=subprocess.DEVNULL,
                                                    stdout=sys.stdout, stderr=subprocess.PIPE, text=True)
                    self.started = time.monotonic()
                    process = self.process
                tail: list[str] = []
                for line in process.stderr:  # pass sync's log through, keep the end for /status
                    sys.stderr.write(line)
                    tail = (tail + [line.strip()])[-5:]
                code = process.wait()
                if not self.paused:  # stopped on purpose by /unlink: not an error
                    self.last_error = f"sync stopped ({code}): " + " | ".join(tail)
                # A sync that ran for a while gets a quick restart; one that keeps dying waits longer.
                delay = 5 if time.monotonic() - self.started > 600 else min(delay * 2, 300)
            self.wake.wait(delay if self.linked else 30)  # a finished link wakes it early
            self.wake.clear()


class Link:
    """Linking from Doorman's Connect: one `wacli auth` at a time. It keeps the latest QR code (WhatsApp sends
    a new one about every 20 seconds) or the pairing code, until the phone links or wacli gives up.

    States: idle; starting; scan (a QR code); enter_code (a pairing code); linked (the phone linked, wacli
    still fetches the recent history; sync starts when it's done); failed (error says why)."""

    CHECK_SECONDS = 3  # while a code is shown, how often to look whether the phone has linked

    def __init__(self):
        self.process: subprocess.Popen | None = None
        self.state = "idle"
        self.qr: str | None = None
        self.pair_code: str | None = None
        self.phone: str | None = None
        self.error = ""
        self.checked = 0.0
        self.lock = threading.Lock()
        self.starting = threading.Lock()  # one start (or unlink) at a time

    def busy(self) -> bool:
        with self.lock:
            return self.process is not None and self.process.poll() is None

    def start(self, phone: object = None) -> dict:
        digits = None
        if phone not in (None, ""):
            if not isinstance(phone, str) or not PHONE.match(phone.strip()):
                raise WacliError("phone: a phone number with its country code, e.g. +49 151 23456789", 400)
            digits = re.sub(r"\D", "", phone)
            if not 7 <= len(digits) <= 15:
                raise WacliError("phone: a phone number with its country code, e.g. +49 151 23456789", 400)
        with self.starting:
            if self.busy():
                if self.phone == digits:
                    return self.snapshot()  # the running one keeps its code
                self.cancel()  # QR code instead of pairing code, or another number: start over
            if SYNC.running() or SYNC.check_linked():
                raise WacliError("WhatsApp is already linked", 409)
            args = [WACLI, "--json", "--events", "auth", "--idle-exit", "30s"]
            if digits:
                args.append(f"--phone={digits}")
            try:
                process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
            except OSError as exc:
                raise WacliError(f"can't run wacli: {exc}") from None
            with self.lock:
                self.process, self.state, self.qr, self.pair_code = process, "starting", None, None
                self.phone, self.error, self.checked = digits, "", time.monotonic()
            threading.Thread(target=self._watch, args=(process,), daemon=True).start()
        return self.snapshot()

    def cancel(self) -> None:
        with self.lock:
            process = self.process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                process.kill()

    def _watch(self, process: subprocess.Popen) -> None:
        """Reads wacli's NDJSON events (--events, on stderr); the codes stay out of the log."""
        kept: list[str] = []
        for line in process.stderr:
            try:
                event = json.loads(line) if line.startswith("{") else None
            except ValueError:
                event = None
            if not isinstance(event, dict) or "event" not in event:
                sys.stderr.write(line)
                kept = (kept + [line])[-20:]
                continue
            name, data = event["event"], event.get("data") or {}
            with self.lock:
                if self.process is not process:  # replaced by a newer link: its events aren't ours
                    pass
                elif name == "qr_code" and data.get("code"):
                    self.qr, self.state = str(data["code"]), "scan"
                elif name == "pair_code" and data.get("code"):
                    self.pair_code, self.state = str(data["code"]), "enter_code"
                elif name == "error":
                    self.error = str(data.get("message") or "")
            if name not in ("qr_code", "pair_code"):
                sys.stderr.write(line)
        stdout = process.stdout.read()
        code = process.wait()
        try:
            envelope(stdout, "".join(kept), code)
            failed = ""
        except WacliError as exc:
            failed = self.error or str(exc)
        with self.lock:
            if self.process is not process:
                return
            self.qr = self.pair_code = None
            if failed:
                self.state = "failed"
                self.error = ("The code expired before the phone linked. Start again."
                              if "timed out" in failed else failed)
            else:
                self.state, self.error = "linked", ""
        SYNC.wake.set()

    def snapshot(self) -> dict:
        with self.lock:
            look = self.state in ("scan", "enter_code") and time.monotonic() - self.checked > self.CHECK_SECONDS
            if look:
                self.checked = time.monotonic()
        if look and SYNC.check_linked():  # scanned: wacli now fetches the history, the code is used up
            with self.lock:
                if self.state in ("scan", "enter_code"):
                    self.state, self.qr, self.pair_code = "linked", None, None
        with self.lock:
            out: dict = {"state": self.state}
            if self.state == "scan":
                out["qr"] = self.qr
            if self.state == "enter_code":
                out["pair_code"], out["phone"] = self.pair_code, self.phone
            if self.error:
                out["error"] = self.error
            return out


SYNC = Sync()
LINK = Link()


def unlink() -> dict:
    """Stop sync and log this device out, so WhatsApp drops it from Linked devices."""
    with LINK.starting:
        LINK.cancel()
        with LINK.lock:  # its watcher then leaves the state alone
            LINK.process, LINK.state, LINK.error, LINK.qr, LINK.pair_code = None, "idle", "", None, None
        SYNC.paused = True
        try:
            SYNC.stop()
            try:
                run(["--timeout", "60s", "auth", "logout"], timeout=90)
            except WacliError:
                if SYNC.check_linked():
                    raise
                # not linked anyway (WhatsApp dropped the device already): nothing left to log out
        finally:
            SYNC.paused = False
            SYNC.last_error = ""
        SYNC.check_linked()
        return {"linked": SYNC.linked}


def _limit(query: dict, default: int, top: int) -> str:
    try:
        return str(max(1, min(int(query.get("limit", default)), top)))
    except ValueError:
        raise WacliError("limit must be a number", 400) from None


def _jid(value: str | None, name: str = "chat") -> str:
    if not value or not JID.match(value):
        raise WacliError(f"{name} must be a WhatsApp JID", 400)
    return value


def handle_get(path: str, query: dict) -> object:
    if path == "/status":
        return {"linked": SYNC.linked, "phone": SYNC.phone, "sync_running": SYNC.running(),
                "last_error": SYNC.last_error, "link": LINK.snapshot()}
    if path == "/link":
        return LINK.snapshot()
    if path == "/chats":
        args = ["--read-only", "chats", "list", "--limit", _limit(query, 200, 1000)]
        if query.get("query"):
            text = " ".join(query["query"].split())
            if not text or len(text) > 100:
                raise WacliError("query: 1 to 100 characters", 400)
            args.append(f"--query={text}")  # one word with its option, so it can't be read as another option
        return run(args) or []
    if path == "/messages":
        args = ["--read-only", "messages", "list", f"--chat={_jid(query.get('chat'))}",
                "--limit", _limit(query, 30, 500)]
        for bound in ("after", "before"):
            if query.get(bound):
                if not STAMP.match(query[bound]):
                    raise WacliError(f"{bound} must be an RFC 3339 time", 400)
                args.append(f"--{bound}={query[bound]}")
        if query.get("after") and not query.get("before"):
            args.append("--asc")  # what came after: oldest first, as the event poll reads it
        return (run(args) or {}).get("messages") or []
    if path == "/changes":
        if not query.get("since"):
            return run(["--read-only", "messages", "changes", "--checkpoint"])
        if not re.fullmatch(r"[A-Za-z0-9_=.:+/-]{1,512}", query["since"]):
            raise WacliError("bad checkpoint", 400)
        return run(["--read-only", "messages", "changes", f"--since={query['since']}",
                    "--limit", _limit(query, 200, 500)])
    raise WacliError("not found", 404)


def handle_send(body: dict) -> object:
    chat, text = _jid(body.get("chat")), body.get("text")
    if not isinstance(text, str) or not text.strip() or len(text) > 4000:
        raise WacliError("text: 1 to 4000 characters", 400)
    if not SYNC.running():
        # Without a running sync, wacli would open its own connection; we only send through sync, whose
        # queue says plainly whether a send went out.
        raise WacliError("WhatsApp sync isn't running (not linked yet, or it stopped); nothing was sent", 503)
    try:
        return run(["--timeout", "90s", "send", "text", f"--to={chat}", f"--message={text}", "--no-preview"],
                   timeout=120)
    except WacliError as exc:
        if "it was not sent" in str(exc):
            exc.status = 409
        raise


class Handler(BaseHTTPRequestHandler):
    server_version = "doorman-whatsapp"

    def _answer(self, status: int, data: object):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        given = self.headers.get("Authorization", "")
        return hmac.compare_digest(given.encode(), f"Bearer {TOKEN}".encode())

    def _serve(self, work):
        if not self._authorized():
            return self._answer(401, {"error": "unauthorized"})
        try:
            self._answer(200, work())
        except WacliError as exc:
            # 503 from /send is "certainly not sent" too, but the plugin reads every 5xx as "may have
            # been"; say 409 for anything we know didn't go out.
            status = 409 if exc.status == 503 and self.command == "POST" else exc.status
            self._answer(status, {"error": str(exc)})

    def do_GET(self):
        url = urlparse(self.path)
        query = {k: v[-1] for k, v in parse_qs(url.query).items()}
        self._serve(lambda: handle_get(url.path, query))

    def do_POST(self):
        path = urlparse(self.path).path
        if path not in ("/send", "/link", "/unlink"):
            return self._answer(404, {"error": "not found"})

        def post():
            try:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(min(length, 65536)) or b"{}")
            except ValueError:
                raise WacliError("body must be JSON", 400) from None
            if not isinstance(body, dict):
                raise WacliError("body must be a JSON object", 400)
            if path == "/link":
                return LINK.start(body.get("phone"))
            if path == "/unlink":
                return unlink()
            return handle_send(body)

        self._serve(post)

    def log_message(self, fmt, *args):  # no message text in the log, only the request line's path
        sys.stderr.write(f"{self.command} {urlparse(self.path).path} {args[1] if len(args) > 1 else ''}\n")


TOKEN = ""


def load_token() -> str:
    """$SIDECAR_TOKEN, else the token file's, else a new one. Written back to the file, which Doorman reads."""
    token = os.environ.get("SIDECAR_TOKEN", "").strip()
    path = Path(os.environ["SIDECAR_TOKEN_FILE"]) if os.environ.get("SIDECAR_TOKEN_FILE") else None
    if path is None:
        return token
    try:
        kept = path.read_text().strip()
    except FileNotFoundError:
        kept = ""
    except OSError as exc:
        sys.exit(f"can't read {path}: {exc}")
    token = token or kept or secrets.token_hex(24)
    if token != kept:
        try:
            tmp = path.with_name(path.name + ".tmp")
            tmp.write_text(token + "\n")
            os.chmod(tmp, 0o600)  # Doorman reads it as the same uid (10001)
            tmp.replace(path)
        except OSError as exc:
            sys.exit(f"can't write the token to {path}: {exc}")
    return token


def main():
    global TOKEN
    TOKEN = load_token()
    if len(TOKEN) < 16:
        sys.exit("set SIDECAR_TOKEN (at least 16 characters; openssl rand -hex 24) or SIDECAR_TOKEN_FILE")
    host, _, port = os.environ.get("LISTEN", "0.0.0.0:8720").rpartition(":")
    threading.Thread(target=SYNC.loop, daemon=True).start()
    server = ThreadingHTTPServer((host or "0.0.0.0", int(port)), Handler)
    print(f"listening on {host}:{port}; link the account under Plugins → whatsapp in Doorman's app, or with: "
          "wacli auth (or wacli auth --phone +49...)", file=sys.stderr, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
