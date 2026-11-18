"""Runs one plugin in a process of its own: `python -m doorman.plugin_runner <channel fd> <socket fd>`.

Doorman starts it (as the plugin's own Linux user when Doorman runs as root, see privsep.py) and
sends the plugin's settings and credentials over the channel; nothing else of Doorman reaches this
process. The runner locks itself down (sandbox.py), only then loads the plugin's code, and answers the
doorman's calls, each in its own thread, like Doorman's threads call an in-process plugin.

With the network closed the plugin can't open connections itself. Name lookups give it a stand-in
address, and connecting to it asks Doorman, which checks the plugin's network list, connects, and
hands over the connected socket; the libraries see an ordinary TCP connection.
"""

from __future__ import annotations

import errno
import importlib.util
import ipaddress
import itertools
import logging
import os
import socket
import sys
import threading
import traceback
from pathlib import Path
from typing import Any

from .plugin_api import Denied, PluginContext, PluginError
from .plugin_wire import Channel, error_payload, make_error
from .redaction import Redactor

log = logging.getLogger("doorman.plugin_runner")

PLUGIN_METHODS = {"run_read", "open_ref", "maintenance", "run_job", "check", "poll_events", "known_recipients",
                  "index_feed",
                  "login_status", "login_start", "login_finish", "logout", "device_login"}
TOOL_METHODS = {"tier", "destinations", "trusted_destinations", "snapshot", "ref_for", "preview", "execute",
                "current", "undo", "undo_fields", "render_diff", "describe", "follow_up", "outgoing", "prepare",
                "destination_origins", "verify_sent"}
LOGIN_METHODS = ("login_status", "login_start", "login_finish", "logout", "device_login", "interactive_login")


class Runner:
    def __init__(self, channel: Channel):
        self.channel = channel
        self.plugin = None
        self._local = threading.local()
        self._rids = itertools.count(1)
        self._waiting: dict[int, dict] = {}
        self._waiting_lock = threading.Lock()
        self._connect_lock = threading.Lock()

    # ------------------------------------------------------------------ asking Doorman

    def request(self, op: str, **params) -> Any:
        rid = next(self._rids)
        slot = {"event": threading.Event()}
        with self._waiting_lock:
            self._waiting[rid] = slot
        try:
            self.channel.send({"rid": rid, "call": getattr(self._local, "call", None), "op": op, **params})
            slot["event"].wait()
        finally:
            with self._waiting_lock:
                self._waiting.pop(rid, None)
        answer = slot["answer"]
        if "error" in answer:
            raise make_error(answer["error"])
        return answer.get("ok")

    def _answered(self, message: dict) -> None:
        with self._waiting_lock:
            slot = self._waiting.get(message["rid"])
        if slot is not None:
            slot["answer"] = message
            slot["event"].set()

    def resolve_ref(self, ref: str) -> tuple[str, bytes]:
        filename, content = self.request("resolve_ref", ref=ref)
        return filename, content

    def extract(self, name: str, content: bytes, content_type: str | None = None, ocr: bool = True,
                limit: int = 2_000_000, check_pdf: bool = True, background: bool = False) -> dict:
        return self.request("extract", name=name, content=content, content_type=content_type, ocr=ocr,
                            limit=limit, check_pdf=check_pdf, background=background)

    def embed(self, texts: list[str], background: bool = False) -> dict:
        return self.request("embed", texts=list(texts), background=background)

    def save_credential(self, key: str, value: str | None) -> None:
        self.request("save_credential", key=key, value=value)

    def open_connection(self, host: str, port: int, family: int, timeout: float | None) -> int:
        """A connected TCP socket from Doorman, as a file descriptor."""
        with self._connect_lock:  # one at a time, so the socket that arrives belongs to this request
            rid = next(self._rids)
            slot = {"event": threading.Event()}
            with self._waiting_lock:
                self._waiting[rid] = slot
            try:
                self.channel.send({"rid": rid, "call": None, "op": "connect", "host": host, "port": port,
                                   "family": family, "timeout": timeout})
                slot["event"].wait()
            finally:
                with self._waiting_lock:
                    self._waiting.pop(rid, None)
            answer = slot["answer"]
            if "error" in answer:
                raise OSError(errno.EACCES, answer["error"].get("message") or "Doorman refused the connection")
            return self.channel.recv_socket(rid)

    # ------------------------------------------------------------------ answering Doorman

    def _callbacks(self, value: Any) -> Any:
        """{"__callback__": name} in the arguments: a function that calls back into Doorman (the
        shell login's `say`)."""
        if isinstance(value, dict) and set(value) == {"__callback__"}:
            name = value["__callback__"]
            return lambda *args: self.request("callback", name=name, args=list(args))
        return value

    def run_call(self, message: dict) -> None:
        self._local.call = message["id"]
        try:
            target, method = message.get("target") or ["plugin"], message["method"]
            if target[0] == "tool":
                if method not in TOOL_METHODS:
                    raise PluginError(f"no tool method {method}")
                obj = self.plugin.tools[target[1]]
            else:
                if method not in PLUGIN_METHODS:
                    raise PluginError(f"no plugin method {method}")
                obj = self.plugin
            args = [self._callbacks(a) for a in message.get("args") or []]
            kwargs = {k: self._callbacks(v) for k, v in (message.get("kwargs") or {}).items()}
            result = getattr(obj, method)(*args, **kwargs)
            reply = {"id": message["id"], "ok": result}
        except BaseException as exc:  # noqa: BLE001 - every failure goes back to Doorman
            if not isinstance(exc, (PluginError, Denied)):
                log.warning("%s failed:\n%s", message.get("method"), traceback.format_exc())  # a bug: keep the trace
            reply = {"id": message["id"], "error": error_payload(exc)}
        try:
            self.channel.send(reply)
        except TypeError as exc:  # a value JSON can't carry
            self.channel.send({"id": message["id"], "error": error_payload(PluginError(f"can't send the result: {exc}"))})

    def serve(self) -> None:
        while True:
            message = self.channel.recv()
            if message is None or message.get("op") == "exit":
                return
            if "rid" in message:
                self._answered(message)
            elif message.get("op") == "call":
                threading.Thread(target=self.run_call, args=(message,), daemon=True,
                                 name=f"call-{message['id']}").start()


# ------------------------------------------------------------------ the network, through Doorman

STAND_IN = ipaddress.ip_network("198.18.0.0/15")  # reserved for benchmarking: never a real server


class NetworkRedirect:
    """getaddrinfo hands out stand-in addresses; connect() to one (or to a literal address) asks the
    doorman for the connection and puts the socket it sends in place of the plugin's unconnected one."""

    def __init__(self, runner: Runner):
        self.runner = runner
        self.names: dict[str, str] = {}
        self.addresses: dict[str, str] = {}
        self.lock = threading.Lock()
        self.real_getaddrinfo = socket.getaddrinfo
        self.real_connect = socket.socket.connect

    def stand_in(self, host: str) -> str:
        with self.lock:
            if host not in self.addresses:
                address = str(STAND_IN[len(self.addresses) + 1])
                self.addresses[host] = address
                self.names[address] = host
            return self.addresses[host]

    def getaddrinfo(self, host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002 - socket's names
        if host is None or isinstance(host, bytes) and not host:
            return self.real_getaddrinfo(host, port, family, type, proto, flags)
        name = host.decode() if isinstance(host, bytes) else str(host)
        try:
            ipaddress.ip_address(name.strip("[]"))
            return self.real_getaddrinfo(host, port, family, type, proto, flags)
        except ValueError:
            pass
        if family not in (0, socket.AF_INET):
            raise socket.gaierror(socket.EAI_FAMILY, "only IPv4 stand-in addresses")
        if type not in (0, socket.SOCK_STREAM):
            raise socket.gaierror(socket.EAI_SOCKTYPE, "plugins only get TCP connections")
        if isinstance(port, (bytes, str)) and not str(port if isinstance(port, str) else port.decode()).isdigit():
            port = socket.getservbyname(port if isinstance(port, str) else port.decode(), "tcp")
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (self.stand_in(name), int(port or 0)))]

    def connect(self, sock: socket.socket, address) -> None:
        if sock.family not in (socket.AF_INET, socket.AF_INET6) or sock.type != socket.SOCK_STREAM:
            return self.real_connect(sock, address)
        host, port = str(address[0]), int(address[1])
        host = self.names.get(host, host)
        timeout = sock.gettimeout()
        fd = self.runner.open_connection(host, port, int(sock.family), timeout)
        try:
            os.dup2(fd, sock.fileno(), inheritable=False)
        finally:
            os.close(fd)
        sock.settimeout(timeout)  # the new descriptor gets the blocking mode the socket object expects

    def connect_ex(self, sock: socket.socket, address) -> int:
        try:
            self.connect(sock, address)
            return 0
        except OSError as exc:
            return exc.errno or errno.ECONNREFUSED

    def install(self) -> None:
        redirect = self
        socket.getaddrinfo = self.getaddrinfo
        socket.socket.connect = lambda sock, address: redirect.connect(sock, address)
        socket.socket.connect_ex = lambda sock, address: redirect.connect_ex(sock, address)


# ------------------------------------------------------------------ start-up

def load_plugin_class(name: str, path: str):
    spec = importlib.util.spec_from_file_location(f"doorman_plugin_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Plugin


def describe(plugin) -> dict:
    from .plugin_api import BasePlugin

    tools = {}
    for name, tool in plugin.tools.items():
        cls = type(tool)
        tools[name] = {"can_undo": cls.can_undo(), "can_undo_fields": cls.can_undo_fields(),
                       "can_check_drift": cls.can_check_drift(), "ignore_fields": sorted(cls.IGNORE_FIELDS),
                       "field_scoped_undo": bool(cls.FIELD_SCOPED_UNDO), "can_verify": cls.can_verify()}
    cls = type(plugin)
    overrides = [m for m in ("maintenance", "check", "poll_events", "open_ref", "known_recipients")
                 if getattr(cls, m, None) is not getattr(BasePlugin, m)]
    return {"tools": tools, "login": [m for m in LOGIN_METHODS if callable(getattr(plugin, m, None))],
            "overrides": overrides}


def setup(init: dict, runner: Runner) -> dict:
    from . import sandbox

    os.umask(int(init.get("umask", 0o077)))
    data_dir = Path(init["data_dir"])
    (data_dir / "tmp").mkdir(parents=True, exist_ok=True)
    os.chdir(data_dir)
    box = init.get("sandbox") or {}
    applied = {"files": "open", "network": "open"}
    if box.get("enabled", True):
        applied = sandbox.lock_down(None if box.get("filesystem") == "open" else list(box.get("read") or []),
                                    [str(data_dir), *(box.get("write") or [])],
                                    close_network=box.get("network") != "any", forbidden=list(box.get("forbidden") or []))
        if applied["network"] == "closed":
            NetworkRedirect(runner).install()
    # the plugin's code loads only now, inside the sandbox
    cls = load_plugin_class(init["type"], init["plugin_path"])
    ctx = PluginContext(
        instance=init["instance"],
        config=dict(init.get("config") or {}),
        credentials=dict(init.get("credentials") or {}),
        data_dir=data_dir,
        resolve_ref=runner.resolve_ref,
        redactor=Redactor({"redaction": {"security_senders": init.get("security_senders") or []}}),
        owner_identities=set(init.get("owner_identities") or []),
        log=logging.getLogger(f"doorman.plugin.{init['instance']}"),
        save_credential=runner.save_credential,
        extract=runner.extract,
        embed=runner.embed,
    )
    runner.plugin = cls(ctx, init["manifest"])
    return {**describe(runner.plugin), "sandbox": applied, "uid": os.getuid()}


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s %(name)s: %(message)s")
    sys.stdout = sys.stderr  # fd 1 isn't the channel; a stray print lands in Doorman's log
    channel = Channel(socket.socket(fileno=int(argv[1])), socket.socket(fileno=int(argv[2])))
    runner = Runner(channel)
    init = channel.recv()
    if not init or init.get("op") != "init":
        return 2
    try:
        ready = setup(init, runner)
    except BaseException as exc:  # noqa: BLE001 - Doorman reports it as the plugin's problem
        channel.send({"op": "failed", "error": error_payload(exc), "trace": traceback.format_exc()})
        return 1
    channel.send({"op": "ready", **ready})
    runner.serve()
    try:
        runner.plugin.close()  # Doorman said exit (or is gone): the plugin lets go of what it holds open
    except Exception:  # noqa: BLE001 - the process ends either way
        log.exception("closing the plugin")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
