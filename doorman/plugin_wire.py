"""How Doorman and a plugin process talk: JSON lines over a socket pair, plus a second socket that
only carries connected sockets (Doorman opens the plugin's connections and hands them over).

Messages:
- doorman -> plugin: {"op": "init", ...} once, then {"id": n, "op": "call", "target": [...], "method": ...,
  "args": [...], "kwargs": {...}} and {"op": "exit"}.
- plugin -> doorman: {"op": "ready", ...} or {"op": "failed", ...} once, then {"id": n, "ok": value} or
  {"id": n, "error": {...}} for each call.
- plugin -> doorman requests, from inside a call or not: {"rid": m, "call": n | None, "op": "resolve_ref" |
  "save_credential" | "callback" | "connect", ...}, answered with {"rid": m, "ok": ...} or
  {"rid": m, "error": {...}}.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import socket
import threading
from pathlib import Path
from typing import Any

from .plugin_api import Denied, ExecResult, NotSent, PluginError


def _default(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return {"__bytes__": base64.b64encode(bytes(value)).decode()}
    if isinstance(value, (set, frozenset)):
        return {"__set__": list(value)}
    if isinstance(value, ExecResult):
        return {"__exec__": dataclasses.asdict(value)}
    if isinstance(value, Path):
        return str(value)
    return str(value)  # dates, decimals: as the journal would store them


def _hook(value: dict) -> Any:
    if len(value) == 1:
        if "__bytes__" in value:
            return base64.b64decode(value["__bytes__"])
        if "__set__" in value:
            return {tuple(item) if isinstance(item, list) else item for item in value["__set__"]}
        if "__exec__" in value:
            return ExecResult(**value["__exec__"])
    return value


def encode(message: dict) -> bytes:
    return (json.dumps(message, default=_default, ensure_ascii=False) + "\n").encode()


def decode(line: bytes) -> dict:
    return json.loads(line, object_hook=_hook)


class Channel:
    def __init__(self, sock: socket.socket, fd_sock: socket.socket):
        self.sock = sock
        self.fd_sock = fd_sock
        self._reader = sock.makefile("rb")
        self._write_lock = threading.Lock()

    def send(self, message: dict) -> None:
        data = encode(message)
        with self._write_lock:
            self.sock.sendall(data)

    def recv(self) -> dict | None:
        line = self._reader.readline()
        return decode(line) if line else None

    def send_socket(self, tag: int, sock: socket.socket) -> None:
        socket.send_fds(self.fd_sock, [str(tag).encode()], [sock.fileno()])

    def recv_socket(self, tag: int) -> int:
        data, fds, _, _ = socket.recv_fds(self.fd_sock, 64, 1)
        if data.decode() != str(tag) or len(fds) != 1:
            for fd in fds:
                socket.close(fd)
            raise ConnectionError("Doorman sent a socket for a different request")
        return fds[0]

    def close(self) -> None:
        for sock in (self.sock, self.fd_sock):
            try:
                sock.close()
            except OSError:
                pass


# ------------------------------------------------------------------ errors cross the wire as data

def error_payload(exc: BaseException) -> dict:
    kind = ("Denied" if isinstance(exc, Denied) else "NotSent" if isinstance(exc, NotSent)
            else "PluginError" if isinstance(exc, PluginError) else "other")
    return {"kind": kind, "type": type(exc).__name__, "message": str(exc), "code": getattr(exc, "code", None)}


_REMOTE_TYPES: dict[str, type] = {}


def remote_error_type(name: str) -> type:
    """An error the plugin raised that isn't one of the plugin API's: a PluginError under its own name,
    so messages read as before ("KeyError: 'x'")."""
    if name not in _REMOTE_TYPES:
        _REMOTE_TYPES[name] = type(name, (PluginError,), {"__module__": "doorman.plugin_host"})
    return _REMOTE_TYPES[name]


def make_error(payload: dict) -> Exception:
    kind, message = payload.get("kind"), payload.get("message", "")
    if kind == "Denied":
        return Denied(message, payload.get("code") or "denied")
    if kind == "NotSent":
        return NotSent(message)
    if kind == "PluginError" and payload.get("type") == "PluginError":
        return PluginError(message)
    return remote_error_type(payload.get("type") or "PluginError")(message)
