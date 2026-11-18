"""Which process in the agent's container opened a connection: the egress observer.

The proxy sees a connection come in from the agent's IP and a source port; that says nothing about whether
it was the agent's own HTTP client, a `curl` it ran, or something a package's install script started. The
observer runs in its own small container that shares the agent's PID namespace (and nothing else: no
network to the internet, a read-only root, only SYS_PTRACE to read other users' /proc entries), and
answers the proxy's question "who has the socket from port P to D?":

1. find the socket in /proc/<pid>/net/tcp and tcp6 (the kernel's table for that process's network
   namespace; any pid will do, every pid of the agent shares one) by local port and remote address;
2. find the process holding that socket's inode among /proc/*/fd/*;
3. report its pid, executable and command line, and its parents up to pid 1, so Doorman can tie the
   connection to the tool call whose command started it.

It also keeps the tripwire on the decoy keys: a file of fake API keys in the agent's container
(OBSERVER_DECOY_PATH, written by the egress proxy into a volume the agent has read-only) that the agent is
told never to touch. inotify watches that file and its folder through /proc/1/root (a watch belongs to the
inode, so the agent's opens fire it whatever mount namespace they come from): the file opened or read is an
event `open` / `access`, the folder listed is `dir_open`. The watcher never opens the file itself, and the
proxy replacing it (a new set of keys) only re-arms the watch. The proxy fetches the events
(GET /events?since=N) and hands them to Doorman, which stops the agent, and asks whether the wire is armed
(GET /health): Doorman tells the owner when decoy keys are on and it isn't.

Standard library only: the observer's image is python:3.13-slim plus this directory.
"""

from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import select
import struct
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

CMDLINE_CHARS = 300
MAX_CHAIN = 64
DECOY_PATH = "/opt/data/.config/secrets/api-keys.env"
EVENTS_KEPT = 1000       # the queue the proxy fetches from; the oldest go first
EVENTS_PAGE = 200        # events per answer of /events
REPEAT_WITHIN = 2.0      # the same event on the same path again within this is one event (a long read)
REARM_EVERY = 5.0        # how often a missing path is tried again (the agent restarting)
PAIR_WITHIN = 0.5        # the file's watch and its folder's report one open (or read) back to back: one event

# inotify(7)
IN_ACCESS, IN_OPEN, IN_CREATE = 0x1, 0x20, 0x100
IN_MOVED_TO, IN_DELETE_SELF, IN_MOVE_SELF = 0x80, 0x400, 0x800
IN_Q_OVERFLOW, IN_IGNORED = 0x4000, 0x8000
IN_ONLYDIR, IN_DONT_FOLLOW, IN_ISDIR = 0x1000000, 0x2000000, 0x40000000
FILE_MASK = IN_OPEN | IN_ACCESS | IN_DELETE_SELF | IN_MOVE_SELF | IN_DONT_FOLLOW
DIR_MASK = IN_OPEN | IN_ACCESS | IN_CREATE | IN_MOVED_TO | IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR
GONE = IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED
EVENT_HEAD = struct.Struct("iIII")  # struct inotify_event: wd, mask, cookie, len; then len bytes of name

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _pids(proc: str) -> list[int]:
    try:
        return sorted(int(name) for name in os.listdir(proc) if name.isdigit())
    except OSError:
        return []


def _plain(addr: IPAddress) -> IPAddress:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


def _kernel_addr(text: str) -> tuple[IPAddress, int] | None:
    """"0100007F:1F90" -> (127.0.0.1, 8080): the kernel prints each 32-bit word of the address in host
    (little-endian) byte order."""
    addr, _, port = text.partition(":")
    try:
        raw = bytes.fromhex(addr)
        swapped = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
        return _plain(ipaddress.ip_address(swapped)), int(port, 16)
    except ValueError:
        return None


def _socket_inode(proc: str, port: int, dst: IPAddress, dst_port: int) -> int | None:
    seen = set()
    for pid in _pids(proc):
        try:
            namespace = os.readlink(f"{proc}/{pid}/ns/net")
        except OSError:
            namespace = None
        if namespace is not None:
            if namespace in seen:
                continue
            seen.add(namespace)
        for table in ("tcp", "tcp6"):
            try:
                with open(f"{proc}/{pid}/net/{table}", encoding="ascii", errors="replace") as f:
                    lines = f.read().splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                fields = line.split()
                if len(fields) < 10 or fields[9] == "0":  # inode 0: TIME_WAIT, nobody holds it any more
                    continue
                local, remote = _kernel_addr(fields[1]), _kernel_addr(fields[2])
                if local and remote and local[1] == port and remote == (dst, dst_port):
                    return int(fields[9])
    return None


def _holder(proc: str, inode: int) -> int | None:
    target = f"socket:[{inode}]"
    for pid in _pids(proc):
        try:
            fds = os.listdir(f"{proc}/{pid}/fd")
        except OSError:
            continue
        for fd in fds:
            try:
                if os.readlink(f"{proc}/{pid}/fd/{fd}") == target:
                    return pid
            except OSError:
                continue
    return None


def _cmdline(proc: str, pid: int) -> str:
    try:
        with open(f"{proc}/{pid}/cmdline", "rb") as f:
            raw = f.read(CMDLINE_CHARS * 4)
    except OSError:
        return ""
    return raw.rstrip(b"\0").replace(b"\0", b" ").decode("utf-8", "replace")[:CMDLINE_CHARS]


def _ppid(proc: str, pid: int) -> int | None:
    try:
        with open(f"{proc}/{pid}/stat", encoding="utf-8", errors="replace") as f:
            stat = f.read()
        # "pid (comm) state ppid ...": comm may hold spaces and parentheses, so split after the last ")"
        return int(stat[stat.rindex(")") + 1:].split()[1])
    except (OSError, ValueError, IndexError):
        return None


def process_info(proc: str, pid: int) -> dict:
    try:
        exe = os.readlink(f"{proc}/{pid}/exe")
    except OSError:
        exe = None
    chain = []
    parent = _ppid(proc, pid)
    seen = {pid}
    while parent and parent not in seen and len(chain) < MAX_CHAIN:
        seen.add(parent)
        chain.append({"pid": parent, "cmdline": _cmdline(proc, parent)})
        parent = _ppid(proc, parent)
    return {"pid": pid, "exe": exe, "cmdline": _cmdline(proc, pid), "chain": chain}


def lookup(proc: str, port: int, dst_ip: str, dst_port: int) -> dict | None:
    """The process holding the TCP socket from local `port` to dst_ip:dst_port, or None."""
    try:
        dst = _plain(ipaddress.ip_address(dst_ip.strip("[]")))
    except ValueError:
        return None
    inode = _socket_inode(proc, port, dst, dst_port)
    if inode is None:
        return None
    pid = _holder(proc, inode)
    return process_info(proc, pid) if pid is not None else None


# ---- the decoy tripwire ----------------------------------------------------------------------------------------

def agent_ip(proc: str = "/proc", override: str | None = None) -> str | None:
    """The agent's IPv4 address: `override` (AGENT_IP) if set, else the first LOCAL /32 that isn't 127.x in
    the routing table of PID 1's network namespace ({proc}/1/net/fib_trie)."""
    if override:
        return override
    try:
        with open(f"{proc}/1/net/fib_trie", encoding="ascii", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    last = None
    for line in lines:
        text = line.strip()
        if text.startswith("|--"):
            last = text[3:].strip()
        elif text.startswith("/32") and text.split()[-1] == "LOCAL" and last:
            try:
                addr = ipaddress.IPv4Address(last)
            except ValueError:
                continue
            if not addr.is_loopback:
                return str(addr)
    return None


class EventLog:
    """What the tripwire saw, numbered: the proxy asks for the events after the last number it has. Bounded;
    the same event on the same path again within REPEAT_WITHIN seconds is kept once (a `cat` of a long file
    reads it in many pieces). Numbers start at the start time in milliseconds, so they keep growing across a
    restart of the observer; a `since` past the last number (an observer that restarted with a clock behind)
    gets everything kept."""

    def __init__(self, maxlen: int = EVENTS_KEPT, start: int | None = None):
        self._events: deque[dict] = deque(maxlen=maxlen)
        self._seq = int(time.time() * 1000) if start is None else start
        self._lock = threading.Lock()

    @property
    def last(self) -> int:
        return self._seq

    def add(self, event: str, path: str, client_ip: str | None, ts: float | None = None) -> dict | None:
        ts = time.time() if ts is None else ts
        with self._lock:
            if self._events:
                prev = self._events[-1]
                if prev["event"] == event and prev["path"] == path and 0 <= ts - prev["ts"] < REPEAT_WITHIN:
                    return None
            self._seq += 1
            item = {"seq": self._seq, "ts": ts, "event": event, "path": path, "client_ip": client_ip}
            self._events.append(item)
            return item

    def since(self, seq: int, limit: int = EVENTS_PAGE) -> dict:
        with self._lock:
            if seq > self._seq:
                seq = 0
            out = [dict(e) for e in self._events if e["seq"] > seq][:limit]
            return {"events": out, "next": out[-1]["seq"] if out else max(seq, 0)}


class _Inotify:
    """inotify_init1 / inotify_add_watch / inotify_rm_watch from libc; the events read with os.read."""

    def __init__(self):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.fd = self.libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, f"inotify_init1: {os.strerror(err)}")

    def add(self, path: str, mask: int) -> int:
        wd = self.libc.inotify_add_watch(self.fd, os.fsencode(path), ctypes.c_uint32(mask))
        if wd < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err), path)
        return wd

    def rm(self, wd: int) -> None:
        self.libc.inotify_rm_watch(self.fd, wd)  # EINVAL for a watch the kernel already dropped: fine

    def read(self, timeout: float) -> list[tuple[int, int, str]]:
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return []
        try:
            data = os.read(self.fd, 64 * 1024)
        except BlockingIOError:
            return []
        out, i = [], 0
        while i + EVENT_HEAD.size <= len(data):
            wd, mask, _cookie, size = EVENT_HEAD.unpack_from(data, i)
            i += EVENT_HEAD.size
            name = data[i:i + size].split(b"\0", 1)[0].decode("utf-8", "replace")
            i += size
            out.append((wd, mask, name))
        return out

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class DecoyWatch:
    """The tripwire on the decoy file `path` (as the agent sees it), watched at {proc}/1/root{path}.

    Watches the file (opened -> `open`, read -> `access`) and its folder (listed -> `dir_open`). The file
    deleted, moved or replaced (the proxy writing new keys: a new file renamed over the old) re-arms the
    watch on whatever is at the path now, without an event; a path that isn't there (the agent restarting,
    no keys yet) is tried again every `rearm_every` seconds. Nothing here opens the file or the folder:
    inotify_add_watch only looks the path up.

    The folder's watch reports an open or read of the file too (with its name), so the moment between a new
    file arriving and its own watch being set is covered; one open seen by both watches is one event."""

    def __init__(self, proc: str, path: str, events: EventLog, ip_override: str | None = None,
                 rearm_every: float = REARM_EVERY):
        self.proc, self.path, self.events = proc, path, events
        self.ip_override = ip_override
        self.rearm_every = rearm_every
        self.dir_path = os.path.dirname(path) or "/"
        self.name = os.path.basename(path)
        self.file_wd: int | None = None
        self.dir_wd: int | None = None
        self.next_try = 0.0
        self.last_error: str | None = None
        self._pair: dict[str, tuple[str, float]] = {}  # event -> (which watch reported it, when): see _file_event
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._inotify = _Inotify()

    def _real(self, path: str) -> str:
        return f"{self.proc}/1/root{path}"

    @property
    def armed(self) -> bool:
        return self.file_wd is not None and self.dir_wd is not None

    def health(self) -> dict:
        """For GET /health: whether the watch is set on the file and its folder and its thread runs, and the
        last error (the file missing, the agent's /proc/1/root gone). The proxy passes it on to Doorman, which
        tells the owner when decoy keys are on and the wire isn't armed."""
        running = self._thread is not None and self._thread.is_alive()
        error = self.last_error or (None if running else "the watch isn't running")
        return {"armed": self.armed and running, "last_error": error, "path": self.path}

    def arm(self) -> bool:
        """Sets whichever watch is missing; True when both are set, else tried again in `rearm_every`."""
        try:
            if self.dir_wd is None:
                self.dir_wd = self._inotify.add(self._real(self.dir_path), DIR_MASK)
            if self.file_wd is None:
                self.file_wd = self._inotify.add(self._real(self.path), FILE_MASK)
            self.last_error = None
        except OSError as e:
            self.last_error = str(e)
        if not self.armed:
            self.next_try = time.monotonic() + self.rearm_every
        return self.armed

    def _rearm_file(self) -> None:
        """A new file at the path (renamed over the old one, or created): watch it, drop the old watch."""
        old = self.file_wd
        try:
            new = self._inotify.add(self._real(self.path), FILE_MASK)
        except OSError as e:
            self.last_error = str(e)
            new = None
        if old is not None and old != new:
            self._inotify.rm(old)
        self.file_wd = new
        if new is None:
            self.next_try = time.monotonic() + self.rearm_every

    def _emit(self, event: str, path: str) -> None:
        self.events.add(event, path, agent_ip(self.proc, self.ip_override))

    def _file_event(self, event: str, watch: str) -> None:
        """An open or read of the file, from its own watch ("file") or its folder's ("dir"). One open gives an
        event on both, back to back, so the second of such a pair is dropped. The folder's alone still counts:
        between the proxy renaming new keys over the file (or switching them on again) and the new file's
        watch being set, only the folder's watch sees it opened."""
        now = time.monotonic()
        last = self._pair.pop(event, None)
        if last is not None and last[0] != watch and now - last[1] < PAIR_WITHIN:
            return
        self._pair[event] = (watch, now)
        self._emit(event, self.path)

    def handle(self, wd: int, mask: int, name: str) -> None:
        if mask & IN_Q_OVERFLOW:  # events were lost: start the watches afresh
            for old in (self.file_wd, self.dir_wd):
                if old is not None:
                    self._inotify.rm(old)
            self.file_wd = self.dir_wd = None
            self.arm()
            return
        if wd == self.file_wd:
            if mask & GONE:
                self.file_wd = None
                self._rearm_file()
            elif mask & IN_OPEN:
                self._file_event("open", "file")
            elif mask & IN_ACCESS:
                self._file_event("access", "file")
        elif wd == self.dir_wd:
            if mask & GONE:
                self.dir_wd = None
                self.arm()
            elif not name:
                if mask & IN_OPEN and mask & IN_ISDIR:
                    self._emit("dir_open", self.dir_path)
            elif name == self.name and mask & (IN_CREATE | IN_MOVED_TO):
                self._rearm_file()
            elif name == self.name and mask & IN_OPEN:
                self._file_event("open", "dir")
            elif name == self.name and mask & IN_ACCESS:
                self._file_event("access", "dir")
            # what else happens in the folder (the proxy's temporary file) doesn't count
        # events of a watch dropped meanwhile (an old file's IN_IGNORED) don't either

    def step(self, timeout: float = 1.0) -> None:
        if not self.armed and time.monotonic() >= self.next_try:
            self.arm()
        for wd, mask, name in self._inotify.read(timeout):
            self.handle(wd, mask, name)

    def run(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    self.step(0.5)
                except Exception as e:  # noqa: BLE001 - the wire must say it's off (health), not die quietly
                    self.last_error = f"the watch failed: {e}"
                    self.file_wd = self.dir_wd = None
                    self.next_try = time.monotonic() + self.rearm_every
                    self._stop.wait(self.rearm_every)
        finally:
            self._inotify.close()

    def start(self) -> threading.Thread:
        self._thread = threading.Thread(target=self.run, name="decoy-watch", daemon=True)
        self._thread.start()
        return self._thread

    def stop(self) -> None:
        self._stop.set()


# ---- the HTTP server ------------------------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def do_GET(self) -> None:  # noqa: N802 (http.server's name)
        url = urlsplit(self.path)
        if url.path == "/health":
            watch = self.server.watch
            return self._send(200, {"ok": True, "tripwire": watch.health() if watch is not None else None})
        if url.path == "/events":
            try:
                since = int(parse_qs(url.query).get("since", ["0"])[0])
            except ValueError:
                return self._send(400, {})
            if self.server.events is None:
                return self._send(200, {"events": [], "next": since})
            return self._send(200, self.server.events.since(since))
        if url.path != "/lookup":
            return self._send(404, {})
        query = parse_qs(url.query)
        try:
            port = int(query["port"][0])
            host, _, dst_port = query["dst"][0].rpartition(":")
            dst_port = int(dst_port)
            if not host:
                raise ValueError
        except (KeyError, IndexError, ValueError):
            return self._send(400, {})
        found = lookup(self.server.proc, port, host, dst_port)
        self._send(200 if found else 404, found or {})

    def _send(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args) -> None:  # the proxy logs; one line per connection here is noise
        pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    proc = "/proc"
    events: EventLog | None = None
    watch: DecoyWatch | None = None


def make_server(proc: str = "/proc", host: str = "0.0.0.0", port: int = 8720,
                events: EventLog | None = None, watch: DecoyWatch | None = None) -> ThreadingHTTPServer:
    """The observer's HTTP server, not started yet (port 0 picks a free one: server.server_address[1])."""
    server = _Server((host, port), _Handler)
    server.proc = proc
    server.events = events
    server.watch = watch
    return server


def serve(proc: str = "/proc", host: str = "0.0.0.0", port: int = 8720, decoy_path: str | None = DECOY_PATH,
          ip_override: str | None = None) -> None:
    """GET /lookup?port=<source port>&dst=<ip>:<port> -> the process as JSON (404 {} when none);
    GET /events?since=N -> {"events": [{seq, ts, event, path, client_ip}], "next": N};
    GET /health -> {"ok": true, "tripwire": {armed, last_error, path} or null}. With a decoy_path the
    tripwire watches that file."""
    events = EventLog()
    watch = None
    if decoy_path:
        watch = DecoyWatch(proc, decoy_path, events, ip_override)
        watch.start()
    make_server(proc, host, port, events, watch).serve_forever()


if __name__ == "__main__":
    serve(os.environ.get("OBSERVER_PROC", "/proc"), os.environ.get("OBSERVER_HOST", "0.0.0.0"),
          int(os.environ.get("OBSERVER_PORT", "8720")), os.environ.get("OBSERVER_DECOY_PATH", DECOY_PATH),
          os.environ.get("AGENT_IP") or None)
