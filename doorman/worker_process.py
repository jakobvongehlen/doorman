"""A helper process that speaks JSON lines: the injection guard's scanner, the document extractor and the
embedding model.

Doorman writes one request per line and reads one answer per line. The first line the process writes is
{"ready": true} or {"error": ...}. Each worker locks itself down (Landlock, seccomp) before it loads
anything that parses untrusted input, and refuses to start when the kernel can't do that, as a plugin does
(`plugin_sandbox: false` runs them without). When Doorman runs as root (privsep.py), each also runs as a
Linux user of its own, so a parser bug a stranger's file sets off doesn't run as Doorman's user. All are
stopped after a while without use.
"""

from __future__ import annotations

import json
import os
import queue
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

from .privsep import HELPERS

PACKAGE_PARENT = Path(__file__).resolve().parent.parent
PYTHON_ARGS = ["-E", "-s", "-B", "-u", "-m"]
# What a helper process or a plugin gets of Doorman's environment: nothing secret. DOORMAN_VAULT_KEY, API keys
# (ANTHROPIC_API_KEY, the reader's) and the root process's socket stay behind.
ENV_PASSED = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "PLAYWRIGHT_BROWSERS_PATH", "SSL_CERT_FILE", "SSL_CERT_DIR")
HELPER_NAMES = {module: name for name, (module, _) in HELPERS.items()}
_live: "set[Worker]" = set()


def clean_env() -> dict[str, str]:
    """A helper's environment: the allowlist above, HOME and TMPDIR, one thread for OpenMP."""
    env = {key: os.environ[key] for key in (*ENV_PASSED, "HOME", "TMPDIR") if key in os.environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env["OMP_NUM_THREADS"] = "1"
    return env


def stop_all() -> None:
    """Stops every helper process this Doorman started (shutdown, and between tests)."""
    for worker in list(_live):
        worker.stop()


def share_with_helper(folder: Path) -> None:
    """A helper's own user reads only what any user may. Its model folder (files Doorman downloaded and checked
    against pinned hashes, nothing secret) becomes readable for it: the models folder passable, the model's
    folder and files readable. Nothing else in the data directory opens up; links are left alone."""
    me = os.getuid()
    for path, mode in ((folder.parent, 0o711), (folder, 0o755)):
        if path.is_dir() and not path.is_symlink() and path.stat().st_uid == me:
            path.chmod(mode)
    for entry in folder.iterdir() if folder.is_dir() else []:
        info = entry.lstat()
        if stat.S_ISREG(info.st_mode) and info.st_uid == me and stat.S_IMODE(info.st_mode) != 0o644:
            entry.chmod(0o644)


def _spawner():
    from .plugin_host import Spawner  # plugin_host imports this module

    return Spawner.get()


class WorkerUnavailable(Exception):
    """The helper process can't do its job right now."""


class Worker:
    """One helper process and its channel. Callers serialize requests (one at a time).

    own_user: run it as its own Linux user when Doorman runs as root (privsep.py). The root process starts it
    then, so Doorman can't wait for it or signal it: it ends it through the root process, and learns that it
    died when its output closes. shared: a folder that user must read (the model)."""

    def __init__(self, module: str, args: list[str], what: str, own_user: bool = False, shared: Path | None = None):
        self.what = what
        self.popen: subprocess.Popen | None = None
        self.spawner = None
        self.ended = threading.Event()
        helper = HELPER_NAMES.get(module)
        spawner = _spawner() if own_user and helper else None
        if spawner is not None:
            if shared is not None:
                share_with_helper(Path(shared))
            self._spawn(spawner, helper, args)
        else:
            self.popen = subprocess.Popen([sys.executable, *PYTHON_ARGS, module, *args], stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE, stderr=None, cwd=PACKAGE_PARENT, text=True,
                                          bufsize=1, start_new_session=True, env=clean_env())
            self.pid, self.stdin, self.stdout = self.popen.pid, self.popen.stdin, self.popen.stdout
        self.lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._pump, daemon=True, name=f"{what}-out").start()
        self.last_used = time.monotonic()
        _live.add(self)

    def _spawn(self, spawner, helper: str, args: list[str]) -> None:
        stdin_read, stdin_write = os.pipe2(os.O_CLOEXEC)
        stdout_read, stdout_write = os.pipe2(os.O_CLOEXEC)
        try:
            reply = spawner.request({"op": "helper", "helper": helper, "args": list(args), "env": clean_env()},
                                    [stdin_read, stdout_write, 2])  # its errors go where Doorman's go
        except Exception as exc:  # noqa: BLE001 - the root process refused, or is gone
            os.close(stdin_write)
            os.close(stdout_read)
            raise WorkerUnavailable(f"The {self.what} didn't start: {exc}") from None
        finally:
            os.close(stdin_read)
            os.close(stdout_write)
        self.pid, self.spawner = int(reply["pid"]), spawner
        self.stdin = os.fdopen(stdin_write, "w", buffering=1)
        self.stdout = os.fdopen(stdout_read, "r")

    def _pump(self) -> None:
        try:
            for line in self.stdout:
                self.lines.put(line)
        finally:
            self.ended.set()
            self.lines.put(None)
            if self.popen is None:
                self.stdout.close()

    def exit_code(self) -> int | None:
        return self.popen.poll() if self.popen is not None else None

    def receive(self, timeout: float) -> dict:
        try:
            line = self.lines.get(timeout=timeout)
        except queue.Empty:
            self.stop()
            raise WorkerUnavailable(f"The {self.what} didn't answer within {int(timeout)} s.") from None
        if line is None:
            code = self.exit_code()
            raise WorkerUnavailable(f"The {self.what} stopped" + (f" (exit code {code})." if code is not None else "."))
        message = json.loads(line)
        if "error" in message:
            raise WorkerUnavailable(f"The {self.what} failed: {message['error']}")
        return message

    def start(self, timeout: float = 180) -> "Worker":
        try:
            self.receive(timeout)  # the ready line
        except Exception:
            self.stop()
            raise
        return self

    def call(self, message: dict, timeout: float) -> dict:
        try:
            self.stdin.write(json.dumps(message) + "\n")
            self.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise WorkerUnavailable(f"The {self.what} stopped ({exc}).") from None
        self.last_used = time.monotonic()
        try:
            return self.receive(timeout)
        finally:
            self.last_used = time.monotonic()

    def alive(self) -> bool:
        return self.popen.poll() is None if self.popen is not None else not self.ended.is_set()

    def idle_for(self) -> float:
        return time.monotonic() - self.last_used

    def stop(self) -> None:
        _live.discard(self)
        if self.popen is not None:
            try:
                self.popen.kill()
                self.popen.wait(timeout=5)
            except Exception:  # noqa: BLE001
                pass
            return
        try:
            self.spawner.request({"op": "kill", "pid": self.pid})
        except Exception:  # noqa: BLE001 - it may be gone already
            pass
        try:
            self.stdin.close()
        except OSError:
            pass


def lock_down(read: list[str], what: str) -> bool:
    """For the worker side: Landlock and seccomp, before anything parses untrusted input. When the kernel
    can't, the worker says so in its first line and doesn't start, like a plugin."""
    from . import sandbox

    try:
        sandbox.lock_down(read, [], close_network=True, forbidden=[])
        return True
    except (sandbox.SandboxError, OSError) as exc:
        respond({"error": f"the {what} can't lock itself down, so it doesn't start: {exc} "
                          "(plugin_sandbox: false in doorman.yaml runs helpers and plugins without the sandbox)"})
        return False


def respond(message: dict) -> None:
    """For the worker side: one answer line on the real stdout."""
    sys.__stdout__.write(json.dumps(message) + "\n")
    sys.__stdout__.flush()
