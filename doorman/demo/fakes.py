"""The local stand-ins the demo's plugins talk to: Dovecot for IMAP, an SMTP sink that keeps what was sent,
Radicale for CalDAV, and one small HTTP server for the timetable feed and a fake WhatsApp sidecar. All
listen on 127.0.0.1 only and run as the user who started the demo."""

import grp
import json
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DOVECOT_CONF = """
dovecot_config_version = 2.4.0
dovecot_storage_version = 2.4.0
base_dir = {run}
state_dir = {root}/state
log_path = {root}/dovecot.log
protocols = imap
listen = 127.0.0.1
ssl = no
auth_allow_cleartext = yes
default_login_user = {user}
default_internal_user = {user}
default_internal_group = {group}
mail_driver = maildir
mail_path = {root}/mail/%{{user}}
mail_home = {root}/home/%{{user}}
passdb passwd-file {{
  passwd_file_path = {root}/users
}}
userdb static {{
  fields {{
    uid = {uid}
    gid = {gid}
    home = {root}/home/%{{user}}
  }}
}}
service imap-login {{
  inet_listener imap {{
    port = {port}
  }}
  inet_listener imaps {{
    port = 0
  }}
  chroot =
}}
service anvil {{
  chroot =
}}
namespace inbox {{
  inbox = yes
  separator = /
  mailbox Drafts {{
    special_use = \\\\Drafts
    auto = create
  }}
  mailbox Sent {{
    special_use = \\\\Sent
    auto = create
  }}
  mailbox Trash {{
    special_use = \\\\Trash
    auto = create
  }}
  mailbox Archive {{
    special_use = \\\\Archive
    auto = create
  }}
}}
"""


class FakeError(Exception):
    """A fake didn't come up."""


def dovecot_binary() -> str | None:
    return shutil.which("dovecot") or ("/usr/sbin/dovecot" if os.path.exists("/usr/sbin/dovecot") else None)


def radicale_available() -> bool:
    try:
        import radicale  # noqa: F401
    except ImportError:
        return False
    return True


def wait_for_port(port: int, seconds: float = 10, proc: subprocess.Popen | None = None) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            if proc is not None and proc.poll() is not None:
                raise FakeError(f"it exited with code {proc.returncode}") from None
            time.sleep(0.1)
    raise FakeError(f"nothing listens on port {port} after {seconds:g} s")


def port_free(port: int) -> bool:
    with socket.socket() as sock:
        # as the servers bind: connections a stopped demo left in TIME_WAIT don't make a port busy
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    try:  # a process that exited but wasn't reaped yet (a zombie) is gone for our purposes
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return True


# ---------------------------------------------------------------------------------------------- Dovecot


def dovecot_run_dir() -> str:
    """Dovecot's run directory (sockets, master.pid). It lives under /tmp because Unix socket paths must stay
    short. The caller records it before Dovecot starts, so a stop finds it whatever happens next."""
    return tempfile.mkdtemp(prefix="dmdemo", dir="/tmp")


def start_dovecot(root: Path, port: int, user: str, password: str, run: str) -> None:
    """Dovecot with one user and a maildir under root. It goes to the background by itself, so its output
    goes to dovecot.log: a pipe would stay open for as long as Dovecot runs."""
    binary = dovecot_binary()
    if binary is None:
        raise FakeError("dovecot isn't installed")
    for sub in ("state", "mail", "home"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    (root / "users").write_text(f"{user}:{{PLAIN}}{password}::::::\n")
    conf = root / "dovecot.conf"
    conf.write_text(DOVECOT_CONF.format(run=run, root=root, port=port, user=pwd.getpwuid(os.getuid()).pw_name,
                                        group=grp.getgrgid(os.getgid()).gr_name, uid=os.getuid(), gid=os.getgid()))
    with open(root / "dovecot.log", "ab") as log:
        code = subprocess.run([binary, "-c", str(conf)], stdin=subprocess.DEVNULL, stdout=log,
                              stderr=subprocess.STDOUT).returncode
    if code != 0:
        raise FakeError(f"dovecot didn't start (exit code {code}); see {root / 'dovecot.log'}")
    wait_for_port(port)


def stop_dovecot(run: str | None) -> None:
    if not run:
        return
    pid_file = Path(run) / "master.pid"
    try:
        pid = int(pid_file.read_text().strip())
    except (OSError, ValueError):
        pid = None
    if alive(pid):
        os.kill(pid, signal.SIGTERM)
        for _ in range(30):
            if not alive(pid):
                break
            time.sleep(0.1)
    shutil.rmtree(run, ignore_errors=True)


# ---------------------------------------------------------------------------------------------- SMTP


def start_smtp(port: int, outbox: Path):
    """An SMTP server that delivers nowhere: each message lands in outbox/NNNN.eml, so the demo shows what
    an approved send would have sent. Returns the aiosmtpd controller (stop() ends it)."""
    from aiosmtpd.controller import Controller

    outbox.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()

    class Sink:
        async def handle_DATA(self, server, session, envelope):
            with lock:
                number = len(list(outbox.glob("*.eml"))) + 1
                path = outbox / f"{number:04d}.eml"
                head = f"X-Demo-Envelope-From: {envelope.mail_from}\r\nX-Demo-Envelope-To: " \
                       f"{', '.join(envelope.rcpt_tos)}\r\n".encode()
                path.write_bytes(head + envelope.content)
            print(f"demo smtp: a mail to {', '.join(envelope.rcpt_tos)} went out, kept in {path}", flush=True)
            return "250 OK"

    controller = Controller(Sink(), hostname="127.0.0.1", port=port)
    controller.start()
    return controller


# ---------------------------------------------------------------------------------------------- Radicale


def start_radicale(storage: Path, port: int, log: Path) -> subprocess.Popen:
    """Radicale without authentication (any user name and password work), its collections under storage."""
    storage.mkdir(parents=True, exist_ok=True)
    with open(log, "ab") as out:
        proc = subprocess.Popen(
            [sys.executable, "-m", "radicale", "--server-hosts", f"127.0.0.1:{port}", "--auth-type", "none",
             "--storage-filesystem-folder", str(storage), "--logging-level", "warning"],
            stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        wait_for_port(port, 20, proc)
    except FakeError as exc:
        stop_process(proc.pid)
        raise FakeError(f"radicale didn't start ({exc}); see {log}") from None
    return proc


def stop_process(pid: int | None, seconds: float = 5) -> None:
    if not alive(pid):
        return
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if os.waitpid(pid, os.WNOHANG)[0] == pid:
                return
        except ChildProcessError:  # not our child (stop from another process): just watch it go
            if not alive(pid):
                return
        time.sleep(0.1)
    if alive(pid):
        os.kill(pid, signal.SIGKILL)


# ---------------------------------------------------------------------------------------------- HTTP fakes


class WhatsAppState:
    """The fake sidecar's chats and messages, in a JSON file so a restart keeps what the agent sent."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.data = json.loads(path.read_text())
        self.data.setdefault("changes", [])

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=1))
        tmp.replace(self.path)

    def chats(self, query: str | None, limit: int) -> list[dict]:
        chats = sorted(self.data["chats"], key=lambda c: c["last_message_ts"], reverse=True)
        if query:
            q = query.lower()
            chats = [c for c in chats if q in c["name"].lower() or q in c["jid"]]
        return chats[:limit]

    def messages(self, chat: str, limit: int, after: str | None, before: str | None = None) -> list[dict]:
        """As the sidecar answers: newest first, but oldest first for `after` alone (what came since)."""
        found = [m for m in self.data["messages"] if m["ChatJID"] == chat and (not after or m["Timestamp"] > after)
                 and (not before or m["Timestamp"] < before)]
        oldest_first = bool(after and not before)
        return sorted(found, key=lambda m: m["Timestamp"], reverse=not oldest_first)[:limit]

    def send(self, chat: str, text: str) -> dict | None:
        with self.lock:
            target = next((c for c in self.data["chats"] if c["jid"] == chat), None)
            if target is None:
                return None
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            msg_id = f"DEMOSENT{len(self.data['messages']) + 1:04d}"
            self.data["messages"].append({"MsgID": msg_id, "ChatJID": chat, "SenderJID": "31600000100@s.whatsapp.net",
                                          "SenderName": "Sam de Vries", "FromMe": True, "Text": text, "Timestamp": ts})
            target["last_message_ts"], target["unread_count"] = ts, 0
            self.data["changes"].append({"operation": "upsert", "chat_jid": chat, "msg_id": msg_id,
                                         "message_time": ts, "recorded_at": ts})
            self.save()
        print(f"demo whatsapp: a message to {target['name']} went out: {text[:80]}", flush=True)
        return {"id": msg_id, "to": chat}

    def changes(self, since: str | None, limit: int) -> dict:
        start = int(since or len(self.data["changes"]))
        page = self.data["changes"][start:start + limit]
        return {"changes": page, "next_checkpoint": str(start + len(page)),
                "has_more": start + len(page) < len(self.data["changes"])}


def start_http(port: int, ics_path: Path, whatsapp: WhatsAppState | None, token: str) -> ThreadingHTTPServer:
    """GET /timetable.ics serves the timetable feed; everything else is the WhatsApp sidecar's API (the
    subset Doorman's whatsapp plugin uses), behind its bearer token."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # quiet: the demo's log is for what matters
            pass

        def reply(self, code: int, body, kind: str = "application/json") -> None:
            data = body if isinstance(body, bytes) else json.dumps(body, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def sidecar(self, method: str) -> None:
            if whatsapp is None:
                return self.reply(404, {"error": "no WhatsApp in this demo"})
            if self.headers.get("Authorization") != f"Bearer {token}":
                return self.reply(401, {"error": "wrong token"})
            url = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            limit = int(q.get("limit") or 50)
            if method == "GET" and url.path == "/status":
                return self.reply(200, {"linked": True, "phone": "31600000100", "sync_running": True})
            if method == "GET" and url.path == "/chats":
                return self.reply(200, whatsapp.chats(q.get("query"), limit))
            if method == "GET" and url.path == "/messages":
                return self.reply(200, whatsapp.messages(q.get("chat", ""), limit, q.get("after"), q.get("before")))
            if method == "GET" and url.path == "/changes":
                return self.reply(200, whatsapp.changes(q.get("since"), limit))
            if method == "POST" and url.path == "/send":
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                sent = whatsapp.send(str(body.get("chat", "")), str(body.get("text", "")))
                return self.reply(200, sent) if sent else self.reply(400, {"error": "no such chat"})
            if method == "POST" and url.path in ("/link", "/unlink"):
                return self.reply(200, {"state": "linked"})
            return self.reply(404, {"error": f"no {method} {url.path}"})

        def do_GET(self):
            if urlparse(self.path).path == "/timetable.ics":
                return self.reply(200, ics_path.read_bytes(), "text/calendar; charset=utf-8")
            self.sidecar("GET")

        def do_POST(self):
            self.sidecar("POST")

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="demo-http", daemon=True).start()
    return server
