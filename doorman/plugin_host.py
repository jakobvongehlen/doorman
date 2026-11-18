"""Doorman's side of plugins that run in their own process (see plugin_runner.py).

RemotePlugin stands in for the plugin object the engine used to get: the same methods, each sent to the
plugin's process. The process starts on first use and stops after plugin_idle_minutes without a call.
A crash or a call that takes too long fails that call, and the next call starts a fresh process.

The plugin's process gets its settings, its own credentials, its folder, the attachments a call names,
and the connections its network list allows; nothing else of Doorman. When Doorman runs as root
(privsep.py), each plugin also runs as a Linux user of its own.

Where a plugin may connect: the hosts its manifest lists under `network:`, where "{key}" stands for a
setting of the instance (a URL or host the owner typed, e.g. "{url}" or "{imap_host}"), plus the hosts the
owner adds under `plugin_sandbox_overrides: {<name>: {network: [...]}}` in doorman.yaml. A host the plugin's author wrote into the
manifest of a plugin that doesn't ship with Doorman must be a public address; hosts the owner typed
may be local (a Radicale on the LAN). `network: any` (owner, or a built-in manifest) leaves the network open.
"""

from __future__ import annotations

import collections
import ipaddress
import itertools
import json
import logging
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time
import weakref
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .extract import check_mode
from .plugin_api import Denied, ExecResult, PluginError, Tool
from .plugin_wire import Channel, error_payload, make_error
from .privsep import FD_ENV, UID_BASE, UID_COUNT
from .worker_process import ENV_PASSED

log = logging.getLogger("doorman.plugin_host")

PACKAGE_PARENT = Path(__file__).resolve().parent.parent
RUNNER_ARGS = ["-E", "-s", "-B", "-u", "-m", "doorman.plugin_runner"]
START_TIMEOUT = 60.0


# ------------------------------------------------------------------ settings

_TEMPLATE = re.compile(r"^\{([A-Za-z0-9_.]+)(?:\|([^}]*))?\}(?::(\d+))?$")


def _lookup(key: str, config: dict, credentials: dict) -> Any:
    value: Any = config
    for part in key.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    if value in (None, "") and "." not in key:
        value = credentials.get(key)
    return value


def fill(entry: str, config: dict, credentials: dict) -> tuple[str | None, bool]:
    """A manifest entry with "{key}" filled from the instance's settings (then its credentials).
    Returns (value, typed by the owner); None when the setting is empty and there is no default."""
    match = _TEMPLATE.match(str(entry).strip())
    if not match:
        return str(entry).strip(), False
    value = _lookup(match.group(1), config, credentials)
    owner = value not in (None, "")
    if not owner:
        value = match.group(2)
    if value in (None, ""):
        return None, True
    value = str(value)
    if match.group(3):
        value = f"{value}:{match.group(3)}"
    return value, owner


def parse_host(value: str) -> tuple[str, int | None]:
    """'https://cloud.example.com/dav/', 'imap.example.com:993', '[::1]:8080' or a bare host."""
    value = value.strip()
    if "://" in value:
        url = urlparse(value)
        return (url.hostname or "").lower(), url.port
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        return host.lower(), int(rest[1:]) if rest[1:].isdigit() else None
    if value.count(":") == 1:
        host, port = value.split(":")
        return host.lower(), int(port) if port.isdigit() else None
    return value.lower(), None


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%")[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global


class NetworkPolicy:
    """Which host:port the plugin may reach; Doorman connects for it and hands over the socket."""

    def __init__(self, instance: str, rules: list[tuple[str, int | None, bool]], open_: bool = False):
        self.instance = instance
        self.rules = rules  # (host or *.domain, port or None for any, local addresses allowed)
        self.open = open_

    @classmethod
    def build(cls, instance: str, entries: list, owner_entries: Any, config: dict, credentials: dict,
              builtin: bool) -> "NetworkPolicy":
        if owner_entries == "any" or (builtin and entries == "any"):
            return cls(instance, [], open_=True)
        rules = []
        for entry, from_owner in [(e, False) for e in (entries if isinstance(entries, list) else [])] + \
                                 [(e, True) for e in (owner_entries if isinstance(owner_entries, list) else [])]:
            value, typed = fill(entry, config, credentials)
            if not value:
                continue
            host, port = parse_host(value)
            if host:
                rules.append((host, port, builtin or from_owner or typed))
        return cls(instance, rules)

    def match(self, host: str, port: int) -> tuple[str, int | None, bool] | None:
        host = host.lower().rstrip(".")
        for rule in self.rules:
            pattern, rule_port, _ = rule
            if rule_port is not None and rule_port != port:
                continue
            if host == pattern or (pattern.startswith("*.") and host.endswith(pattern[1:])):
                return rule
        return None

    def describe(self) -> list[str]:
        if self.open:
            return ["any"]
        return [f"{host}:{port}" if port else host for host, port, _ in self.rules]

    def connect(self, host: str, port: int, family: int, timeout: float | None) -> socket.socket:
        rule = self.match(host, port)
        if rule is None:
            raise Denied(f"{self.instance} may not connect to {host}:{port} "
                         f"(its network list: {', '.join(self.describe()) or 'none'})", "network")
        if family not in (socket.AF_INET, socket.AF_INET6):
            family = socket.AF_INET
        last: Exception | None = None
        for fam, kind, proto, _, address in socket.getaddrinfo(host, port, family, socket.SOCK_STREAM):
            if not rule[2] and not _is_public(address[0]):
                last = Denied(f"{host} is a local address; only the owner can allow those", "network")
                continue
            sock = socket.socket(fam, kind, proto)
            try:
                sock.settimeout(timeout or 30)
                sock.connect(address)
                sock.settimeout(None)
                return sock
            except OSError as exc:
                sock.close()
                last = exc
        raise last or OSError(f"can't resolve {host}")


def sandbox_settings(registry, name: str, plugin_type, block: dict, ctx) -> dict:
    """What the plugin's process may touch: built-in manifests may widen it (one that drives a browser, say),
    the owner may widen it in doorman.yaml (`plugin_sandbox_overrides`, which registry.configured puts
    into the block as `sandbox`), other plugins can't."""
    builtin = plugin_type.builtin
    manifest_box = (plugin_type.manifest.get("sandbox") or {}) if builtin else {}
    owner_box = block.get("sandbox") if isinstance(block.get("sandbox"), dict) else {}

    def paths(key: str) -> list[str]:
        out = []
        for entry in list(manifest_box.get(key) or []) + list(owner_box.get(key) or []):
            value, _ = fill(entry, ctx.config, ctx.credentials)
            if value:
                out.append(str(Path(value).expanduser().resolve()))
        return out

    read = [str(plugin_type.path.resolve())]
    if plugin_type.manifest.get("extends"):
        read.append(str((plugin_type.path.parent / plugin_type.manifest["extends"]).resolve()))
    return {
        "builtin": builtin,
        "user": owner_box.get("user", manifest_box.get("user", "own")),
        "filesystem": owner_box.get("filesystem", manifest_box.get("filesystem", "limited")),
        "read": read + paths("read"),
        "write": paths("write"),
        "call_timeout": owner_box.get("call_timeout_seconds", manifest_box.get("call_timeout_seconds")),
        "network": NetworkPolicy.build(name, manifest_box.get("network") if manifest_box.get("network") == "any"
                                       else plugin_type.manifest.get("network") or [],
                                       owner_box.get("network"), ctx.config, ctx.credentials, builtin),
    }


def harden_data_dir(data_dir: Path) -> None:
    """Doorman's own files private to its user; the data and plugins folders only passable, so a
    plugin user reaches its own folder by name but can't list or open anything else. The models folder
    is passable too: a helper process's own user reads its model there (worker_process.share_with_helper)."""
    data_dir.mkdir(parents=True, exist_ok=True)
    plugins = data_dir / "plugins"
    plugins.mkdir(exist_ok=True)
    models = data_dir / "models"
    me = os.getuid()
    for path in (data_dir, plugins, models):
        if path.is_dir() and not path.is_symlink() and path.stat().st_uid == me:
            path.chmod(0o711)
    for entry in data_dir.iterdir():
        if entry in (plugins, models) or entry.is_symlink():
            continue
        try:
            if entry.stat().st_uid == me:
                entry.chmod(0o700 if entry.is_dir() else 0o600)
        except OSError:
            pass


# ------------------------------------------------------------------ the root side (privsep.py)

class Spawner:
    """Asks the root process (privsep.py) to start a plugin, or a helper process (worker_process.py), as its
    own user."""

    _instance: "Spawner | None" = None
    _checked = False

    def __init__(self, fd: int):
        self.sock = socket.socket(fileno=fd)
        self.lock = threading.Lock()

    @classmethod
    def get(cls) -> "Spawner | None":
        if not cls._checked:
            cls._checked = True
            fd = os.environ.pop(FD_ENV, None)
            if fd:
                os.set_inheritable(int(fd), False)  # not for anything Doorman starts
            cls._instance = cls(int(fd)) if fd else None
        return cls._instance

    def request(self, message: dict, fds: list[int] | None = None) -> dict:
        data = json.dumps(message).encode()
        with self.lock:
            if fds:
                socket.send_fds(self.sock, [data], fds)
            else:
                self.sock.send(data)
            reply = json.loads(self.sock.recv(65536) or b'{"error": "the root process is gone"}')
        if reply.get("error"):
            raise PluginError(f"the root process refused: {reply['error']}")
        return reply


def plugin_uid(db, name: str) -> int:
    with db.tx() as conn:
        row = conn.execute("SELECT uid FROM plugin_users WHERE name=?", (name,)).fetchone()
        if row:
            return int(row[0])
        used = {r[0] for r in conn.execute("SELECT uid FROM plugin_users")}
        uid = next(u for u in range(UID_BASE, UID_BASE + UID_COUNT) if u not in used)
        conn.execute("INSERT INTO plugin_users(name, uid) VALUES(?,?)", (name, uid))
        return uid


# ------------------------------------------------------------------ one running process

class PluginProcess:
    def __init__(self, remote: "RemotePlugin"):
        self.remote = remote
        self.channel: Channel | None = None
        self.pid: int | None = None
        self.popen: subprocess.Popen | None = None
        self.via_spawner = False
        self.pending: dict[int, queue.Queue] = {}
        self.pending_lock = threading.Lock()
        self.ids = itertools.count(1)
        self.dead = False
        self.death = ""
        self.stderr_tail: collections.deque[str] = collections.deque(maxlen=20)
        self.last_used = time.monotonic()

    # start and stop

    def start(self, init: dict, env: dict, uid: int | None) -> dict:
        name = self.remote.name
        main, main_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        sockets, sockets_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        err_read, err_write = os.pipe()
        try:
            spawner = Spawner.get() if uid is not None else None
            if spawner:
                reply = spawner.request({"op": "spawn", "instance": name, "uid": uid, "env": env},
                                        [main_child.fileno(), sockets_child.fileno(), err_write])
                self.pid, self.via_spawner = int(reply["pid"]), True
            else:
                self.popen = subprocess.Popen(
                    [sys.executable, *RUNNER_ARGS, str(main_child.fileno()), str(sockets_child.fileno())],
                    pass_fds=(main_child.fileno(), sockets_child.fileno()), stdin=subprocess.DEVNULL,
                    stdout=err_write, stderr=err_write, cwd=PACKAGE_PARENT, env=env, start_new_session=True)
                self.pid = self.popen.pid
        except BaseException:
            for sock in (main, sockets):
                sock.close()
            os.close(err_read)
            raise
        finally:
            main_child.close()
            sockets_child.close()
            os.close(err_write)
        threading.Thread(target=self._read_stderr, args=(err_read,), daemon=True, name=f"{name}-stderr").start()
        self.channel = Channel(main, sockets)
        main.settimeout(START_TIMEOUT)
        try:
            self.channel.send(init)
            first = self.channel.recv()
        except (OSError, ValueError) as exc:
            self.kill()
            raise PluginError(f"{name} didn't start: {exc}. {self.tail()}".strip()) from None
        finally:
            main.settimeout(None)
        if not first:
            self.kill()
            raise PluginError(f"{name} stopped while starting. {self.tail()}".strip())
        if first.get("op") == "failed":
            log.warning("%s couldn't start:\n%s", name, first.get("trace", ""))
            self.kill()
            raise make_error(first["error"])
        threading.Thread(target=self._read, daemon=True, name=f"{name}-reader").start()
        return first

    def tail(self) -> str:
        return " | ".join(list(self.stderr_tail)[-3:])

    def _read_stderr(self, fd: int) -> None:
        plugin_log = logging.getLogger(f"doorman.plugin.{self.remote.name}")
        with os.fdopen(fd, "r", errors="replace") as stream:
            for line in stream:
                line = line.rstrip()
                if line:
                    self.stderr_tail.append(line)
                    plugin_log.info("%s", line)

    def kill(self, reason: str = "") -> None:
        if reason and not self.death:
            self.death = reason
        if self.via_spawner and self.pid:
            try:
                Spawner.get().request({"op": "kill", "pid": self.pid})
            except Exception:  # noqa: BLE001 - it may be gone already
                pass
        elif self.popen is not None and self.popen.poll() is None:
            self.popen.kill()
            try:
                self.popen.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if self.channel:
            self.channel.close()

    def stop(self) -> None:
        """A friendly exit first, then kill."""
        if self.channel and not self.dead:
            try:
                self.channel.send({"op": "exit"})
            except OSError:
                pass
            if self.popen is not None:
                try:
                    self.popen.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
        self.kill("stopped")
        if self.popen is not None and self.popen.poll() is None:
            self.popen.wait(timeout=5)

    # messages from the plugin

    def _read(self) -> None:
        try:
            while True:
                message = self.channel.recv()
                if message is None:
                    break
                if "rid" in message:
                    if message.get("op") == "connect":
                        threading.Thread(target=self._connect, args=(message,), daemon=True).start()
                        continue
                    with self.pending_lock:
                        waiting = self.pending.get(message.get("call")) if message.get("call") is not None else None
                    if waiting is not None:
                        waiting.put(message)  # answered in the calling thread (attachment checks are per thread)
                    else:
                        threading.Thread(target=self._answer, args=(message, None, None), daemon=True).start()
                elif "id" in message:
                    with self.pending_lock:
                        waiting = self.pending.get(message["id"])
                    if waiting is not None:
                        waiting.put(message)
        except (OSError, ValueError) as exc:
            self.death = self.death or f"lost the connection: {exc}"
        finally:
            self.dead = True
            if self.popen is not None:
                try:
                    code = self.popen.wait(timeout=5)
                    self.death = self.death or f"exited with code {code}"
                except subprocess.TimeoutExpired:
                    pass
            with self.pending_lock:
                waiting_all = list(self.pending.values())
            for waiting in waiting_all:
                waiting.put({"__dead__": True})

    def _answer(self, message: dict, callbacks: dict | None, call_args: Any) -> None:
        """A request the plugin made: an attachment, a credential to keep, a callback (`say`)."""
        try:
            op = message.get("op")
            result: Any = None
            if op == "resolve_ref":
                ref = message.get("ref")
                if callbacks is None or not isinstance(ref, str) or not _mentions(call_args, ref):
                    raise Denied(f"{ref} isn't among this call's arguments", "ref")
                filename, content = self.remote.ctx.resolve_ref(ref)
                result = [filename, content]
            elif op == "extract":
                content = message.get("content")
                if not isinstance(content, bytes):
                    raise PluginError("extract needs the document's bytes")
                result = self.remote.ctx.extract_text(str(message.get("name") or ""), content,
                                                      message.get("content_type"), bool(message.get("ocr", True)),
                                                      int(message.get("limit") or 2_000_000),
                                                      check_mode(message.get("check_pdf", True)),
                                                      background=bool(message.get("background")))
            elif op == "embed":
                texts = message.get("texts")
                if not isinstance(texts, list) or len(texts) > 64 or not all(isinstance(t, str) for t in texts):
                    raise PluginError("embed takes a list of up to 64 texts")
                result = self.remote.ctx.embed_texts(texts, background=bool(message.get("background")))
            elif op == "save_credential":
                key, value = message.get("key"), message.get("value")
                if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", key) or \
                        (value is not None and not isinstance(value, str)):
                    raise PluginError("a credential is a name and a text")
                self.remote.save_credential(key, value)
            elif op == "callback":
                function = (callbacks or {}).get(message.get("name"))
                if function is None:
                    raise PluginError(f"no callback {message.get('name')} here")
                result = function(*(message.get("args") or []))
            else:
                raise PluginError(f"unknown request {op}")
            self.channel.send({"rid": message["rid"], "ok": result})
        except Exception as exc:  # noqa: BLE001 - the plugin gets the error, Doorman goes on
            try:
                self.channel.send({"rid": message["rid"], "error": error_payload(exc)})
            except OSError:
                pass

    def _connect(self, message: dict) -> None:
        rid = message["rid"]
        host, port = str(message.get("host") or ""), int(message.get("port") or 0)
        try:
            sock = self.remote.network.connect(host, port, int(message.get("family") or socket.AF_INET),
                                               message.get("timeout"))
        except Exception as exc:  # noqa: BLE001 - refused or unreachable: the plugin sees a failed connect
            log.info("%s: no connection to %s:%s: %s", self.remote.name, host, port, exc)
            self.channel.send({"rid": rid, "error": error_payload(exc)})
            return
        try:
            self.channel.send_socket(rid, sock)
            self.channel.send({"rid": rid, "ok": True})
        except OSError:
            pass
        finally:
            sock.close()

    # calls

    def call(self, target: list, method: str, args: list, kwargs: dict, callbacks: dict, timeout: float | None):
        if self.dead:
            raise PluginError(f"{self.remote.name} isn't running: {self.death or 'stopped'}")
        call_id = next(self.ids)
        waiting: queue.Queue = queue.Queue()
        with self.pending_lock:
            self.pending[call_id] = waiting
        self.last_used = time.monotonic()
        try:
            self.channel.send({"id": call_id, "op": "call", "target": target, "method": method,
                               "args": args, "kwargs": kwargs})
            deadline = time.monotonic() + timeout if timeout else None
            while True:
                left = None if deadline is None else deadline - time.monotonic()
                if left is not None and left <= 0:
                    self.remote.restart_after(self, f"{method} took longer than {int(timeout)} s")
                    raise PluginError(f"{self.remote.name} didn't answer within {int(timeout)} s ({method}); "
                                      f"it was stopped and starts again on the next call")
                try:
                    message = waiting.get(timeout=left)
                except queue.Empty:
                    continue
                if message.get("__dead__"):
                    raise PluginError(f"{self.remote.name} stopped during {method}: "
                                      f"{self.death or 'it crashed'}. {self.tail()}".strip())
                if "rid" in message:
                    self._answer(message, callbacks, [args, kwargs])
                    continue
                if "error" in message:
                    raise make_error(message["error"])
                return message.get("ok")
        except OSError as exc:
            raise PluginError(f"{self.remote.name}: lost the connection to its process ({exc})") from None
        finally:
            with self.pending_lock:
                self.pending.pop(call_id, None)
            self.last_used = time.monotonic()

    def busy(self) -> bool:
        with self.pending_lock:
            return bool(self.pending)


def _mentions(value: Any, ref: str) -> bool:
    if isinstance(value, str):
        return ref in value
    if isinstance(value, dict):
        return any(_mentions(v, ref) for v in value.values())
    if isinstance(value, (list, tuple)):
        return any(_mentions(v, ref) for v in value)
    return False


# ------------------------------------------------------------------ the stand-in the engine uses

_live: "weakref.WeakSet[RemotePlugin]" = weakref.WeakSet()


def stop_all() -> None:
    """Stops every plugin process this doorman started (shutdown, and between tests)."""
    for plugin in list(_live):
        try:
            plugin.close()
        except Exception:  # noqa: BLE001 - stopping one must not keep the others running
            log.exception("stopping %s", plugin.name)


class RemotePlugin:
    """What registry.instance() returns for a plugin in its own process: the plugin object's methods,
    sent to that process."""

    def __init__(self, registry, name: str, plugin_type, block: dict, manifest: dict, ctx):
        self.registry = registry
        self.name = name
        self.plugin_type = plugin_type
        self.manifest = manifest
        self.ctx = ctx
        self.config = ctx.config
        self.credentials = ctx.credentials
        self.settings = sandbox_settings(registry, name, plugin_type, block, ctx)
        self.network: NetworkPolicy = self.settings["network"]
        self.tools = {spec["name"]: RemoteTool(self, spec) for spec in manifest.get("tools", [])}
        self.timeout = float(self.settings["call_timeout"] or registry.config.get("plugin_call_timeout_seconds") or 300)
        self.idle_seconds = 60 * float(registry.config.get("plugin_idle_minutes") or 15)
        self._process: PluginProcess | None = None
        self._info: dict | None = None
        self._lock = threading.Lock()
        self._closed = threading.Event()
        self._watcher: threading.Thread | None = None
        _live.add(self)

    # the process

    def _uid(self) -> int | None:
        if self.settings["user"] != "own" or Spawner.get() is None:
            return None
        return plugin_uid(self.registry.db, self.name)

    def _init(self, uid: int | None) -> dict:
        data_dir = Path(self.ctx.data_dir).resolve()
        return {
            "op": "init", "instance": self.name, "type": self.plugin_type.name,
            "plugin_path": str((self.plugin_type.path / "plugin.py").resolve()),
            "manifest": self.manifest, "config": self.config, "credentials": self.credentials,
            "data_dir": str(data_dir), "owner_identities": sorted(self.ctx.owner_identities),
            "security_senders": list(getattr(self.ctx.redactor, "security_senders", [])),
            # group-readable: the folder's group is doorman (backups), and a file `doorman-admin login` writes
            # as Doorman's user stays usable for the plugin's own user; the folder keeps others out
            "umask": 0o007,
            "sandbox": {"enabled": True, "filesystem": self.settings["filesystem"], "read": self.settings["read"],
                        "write": self.settings["write"], "network": "any" if self.network.open else "closed",
                        "forbidden": [str(Path(self.registry.config["data_dir"]).resolve())]},
        }

    def _env(self) -> dict:
        data_dir = Path(self.ctx.data_dir).resolve()
        env = {key: os.environ[key] for key in ENV_PASSED if key in os.environ}
        env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
        browsers = Path.home() / ".cache" / "ms-playwright"  # Playwright's default, found through HOME
        if "PLAYWRIGHT_BROWSERS_PATH" not in env and browsers.is_dir():
            env["PLAYWRIGHT_BROWSERS_PATH"] = str(browsers)  # HOME becomes the plugin's folder below
        env.update(HOME=str(data_dir), TMPDIR=str(data_dir / "tmp"))
        return env

    def process(self) -> PluginProcess:
        with self._lock:
            if self._closed.is_set():
                raise PluginError(f"{self.name} was switched off or changed; ask again")
            if self._process is not None and not self._process.dead:
                return self._process
            if self._process is not None:
                self._process.kill()
            uid = self._uid()
            process = PluginProcess(self)
            info = process.start(self._init(uid), self._env(), uid)
            self._info, self._process = info, process
            log.info("%s runs in its own process: pid %s, user %s, files %s, network %s", self.name, process.pid,
                     info.get("uid"), info["sandbox"]["files"], ", ".join(self.network.describe()) or "closed")
            if self._watcher is None:
                self._watcher = threading.Thread(target=self._watch_idle, daemon=True, name=f"{self.name}-idle")
                self._watcher.start()
            return process

    def info(self) -> dict:
        if self._info is None:
            self.process()
        return self._info

    def _watch_idle(self) -> None:
        while not self._closed.wait(min(30.0, max(self.idle_seconds / 4, 1.0))):
            with self._lock:
                process = self._process
                if process and not process.dead and not process.busy() and \
                        time.monotonic() - process.last_used > self.idle_seconds:
                    log.info("%s: no calls for %d minutes, stopping its process", self.name, self.idle_seconds // 60)
                    process.stop()
                    self._process = None

    def restart_after(self, process: PluginProcess, reason: str) -> None:
        log.warning("%s: %s; stopping its process", self.name, reason)
        process.kill(reason)
        with self._lock:
            if self._process is process:
                self._process = None

    def close(self) -> None:
        self._closed.set()
        with self._lock:
            if self._process is not None:
                self._process.stop()
                self._process = None

    def save_credential(self, key: str, value: str | None) -> None:
        self.ctx.save_credential(key, value)
        if value is None:
            self.credentials.pop(key, None)
        else:
            self.credentials[key] = value  # a restart after idling sends the fresh one

    def call(self, target: list, method: str, *args, _callbacks: dict | None = None,
             _timeout: float | None = None, **kwargs) -> Any:
        return self.process().call(target, method, list(args), kwargs, _callbacks or {}, _timeout or self.timeout)

    def _overrides(self, method: str) -> bool:
        return method in self.info()["overrides"]

    # BasePlugin's methods

    def run_read(self, name: str, params: dict) -> Any:
        return self.call(["plugin"], "run_read", name, params)

    def open_ref(self, path: str) -> tuple[str, bytes]:
        if not self._overrides("open_ref"):
            raise PluginError(f"{self.name} does not provide references")
        filename, content = self.call(["plugin"], "open_ref", path)
        return filename, content

    def maintenance(self) -> None:
        if self._info is not None and not self._overrides("maintenance"):
            return  # nothing to do: don't wake the process for it
        self.call(["plugin"], "maintenance", _timeout=max(self.timeout, 3600))

    def run_job(self, name: str, budget: float) -> dict | None:
        return self.call(["plugin"], "run_job", name, budget, _timeout=budget + 600)

    def check(self) -> str | None:
        if self._info is not None and not self._overrides("check"):
            return None
        return self.call(["plugin"], "check")

    def poll_events(self, cursor: str | None) -> tuple[list[dict], str | None]:
        if self._info is not None and not self._overrides("poll_events"):
            return [], cursor
        events, new_cursor = self.call(["plugin"], "poll_events", cursor)
        return events, new_cursor

    def index_feed(self, cursor: str | None, budget: float) -> dict:
        return self.call(["plugin"], "index_feed", cursor, budget, _timeout=float(budget) + 120)

    def known_recipients(self, destinations: list[list[str]]) -> dict[str, dict]:
        if self._info is not None and not self._overrides("known_recipients"):
            return {}
        # asked while a send is checked, under the engine's lock: a slow server must not hold it long; one that
        # doesn't answer in time only means the warning stays
        return self.call(["plugin"], "known_recipients", destinations, _timeout=min(self.timeout, 8)) or {}

    # logins (plugins with login: oauth)

    def _login(self, method: str):
        if method not in self.info()["login"]:
            raise AttributeError(method)

    def login_status(self) -> dict:
        self._login("login_status")
        return self.call(["plugin"], "login_status")

    def login_start(self, *args, **kwargs) -> dict:
        self._login("login_start")
        return self.call(["plugin"], "login_start", *args, **kwargs)

    def login_finish(self, response_url: str) -> dict:
        self._login("login_finish")
        return self.call(["plugin"], "login_finish", response_url)

    def logout(self) -> dict:
        self._login("logout")
        return self.call(["plugin"], "logout")

    def device_login(self, say, sleep=None) -> dict:
        self._login("device_login")
        return self.call(["plugin"], "device_login", {"__callback__": "say"}, _callbacks={"say": say},
                         _timeout=1200)

    @property
    def interactive_login(self):
        """doorman-admin login, run here: the shell, the loopback port and the pasted address are the
        admin's; the plugin's process only makes and finishes the login."""
        if "interactive_login" not in self.info()["login"]:
            raise AttributeError("interactive_login")
        return self._interactive_login

    def _interactive_login(self, say, read_line=input, finish=None) -> None:
        if self.config.get("login_flow") == "device" and "device_login" in self.info()["login"]:
            result = self.device_login(say)
            say(f"Connected {result.get('account') or self.name}.")
            return
        start = self.login_start()
        caught: dict = {}
        server = _catch_redirect(start.get("redirect_uri") or "", caught, say)
        say("Open this address in a browser and sign in:\n")
        say(start["auth_url"] + "\n")
        say("If the browser runs on another machine, the sign-in ends on a page that doesn't load.\n"
            "Copy that page's whole address and paste it here.")
        url = _wait_for_address(caught, read_line)
        if server:
            server.server_close()
        result = (finish or self.login_finish)(url)
        say(f"Connected {result.get('account') or self.name}.")


def _catch_redirect(redirect_uri: str, caught: dict, say):
    """A loopback redirect (http://127.0.0.1:8799/) is caught here, in the admin's process."""
    url = urlparse(redirect_uri)
    if url.scheme != "http" or url.hostname not in ("127.0.0.1", "localhost") or not url.port:
        return None
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            caught["url"] = f"http://{url.hostname}:{url.port}{self.path}"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write("Done. You can close this tab and go back to the terminal.".encode())

        def log_message(self, *args):
            pass

    try:
        server = HTTPServer(("127.0.0.1", url.port), Handler)
    except OSError:
        say("(the loopback port is busy; paste the address instead)")
        return None
    threading.Thread(target=server.handle_request, daemon=True).start()
    return server


def _wait_for_address(caught: dict, read_line) -> str:
    import select

    while True:
        if caught.get("url"):
            return caught["url"]
        if read_line is input and sys.stdin.isatty():
            ready, _, _ = select.select([sys.stdin], [], [], 0.5)
            if ready:
                line = sys.stdin.readline().strip()
                if line:
                    return line
        else:
            line = read_line("> ").strip()
            if line:
                return line


class RemoteTool(Tool):
    """A tool of a plugin in its own process. Whether it can undo or check drift comes from the plugin's
    process when it starts."""

    def _call(self, method: str, *args) -> Any:
        return self.plugin.call(["tool", self.spec["name"]], method, *args)

    def _capability(self, key: str) -> Any:
        return self.plugin.info()["tools"].get(self.spec["name"], {}).get(key)

    def can_undo(self) -> bool:  # type: ignore[override] - an instance's answer, not the class's
        return bool(self._capability("can_undo"))

    def can_undo_fields(self) -> bool:  # type: ignore[override]
        return bool(self._capability("can_undo_fields"))

    def can_check_drift(self) -> bool:  # type: ignore[override]
        return bool(self._capability("can_check_drift"))

    def can_verify(self) -> bool:  # type: ignore[override]
        return bool(self._capability("can_verify"))

    @property
    def IGNORE_FIELDS(self) -> frozenset[str]:  # type: ignore[override]  # noqa: N802 - Tool's name
        return frozenset(self._capability("ignore_fields") or ())

    @property
    def FIELD_SCOPED_UNDO(self) -> bool:  # type: ignore[override]  # noqa: N802
        return bool(self._capability("field_scoped_undo"))

    def tier(self, args):
        return self._call("tier", args)

    def destinations(self, args):
        return [tuple(item) for item in self._call("destinations", args) or []]

    def trusted_destinations(self, args):
        return set(self._call("trusted_destinations", args) or [])

    def prepare(self, args):
        return self._call("prepare", args)

    def destination_origins(self, args):
        return self._call("destination_origins", args) or {}

    def snapshot(self, args):
        return self._call("snapshot", args)

    def ref_for(self, args):
        return self._call("ref_for", args)

    def preview(self, args, before):
        return self._call("preview", args, before)

    def execute(self, args, before):
        result = self._call("execute", args, before)
        return result if isinstance(result, ExecResult) else ExecResult(**(result or {}))

    def current(self, object_ref):
        return self._call("current", object_ref)

    def undo(self, object_ref, before, after):
        return self._call("undo", object_ref, before, after)

    def undo_fields(self, object_ref, fields, now):
        return self._call("undo_fields", object_ref, fields, now)

    def render_diff(self, before, after, args):
        return self._call("render_diff", before, after, args)

    def describe(self, args):
        return self._call("describe", args)

    def follow_up(self, args, result):
        return self._call("follow_up", args, result)

    def outgoing(self, args):
        return self._call("outgoing", args)

    def verify_sent(self, args, before, error):
        return self._call("verify_sent", args, before, error)
