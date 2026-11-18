"""doorman-activity: a Hermes plugin that tells Doorman when each tool call starts and ends (POST
/v1/activity), so Doorman's network log can say which call made a connection. Standard library only.

It never holds up or breaks a tool call: the hooks only put a line on a queue, one daemon thread posts them
in order (a start before its end) with a 2 s timeout, and anything that goes wrong is logged and dropped.
Settings: DOORMAN_URL and DOORMAN_TOKEN, as for the `doorman` command; the session is DOORMAN_SESSION or
the one `doorman claim` saved, so the calls count towards the claimed task.
"""

import hashlib
import json
import logging
import os
import queue
import threading
import urllib.request
from pathlib import Path

TIMEOUT = 2  # seconds per post
SUMMARY_CHARS = 300  # a summary made from the arguments (JSON)
COMMAND_CHARS = 500  # a command as the summary: Doorman keeps this many characters
BACKLOG = 1000  # lines waiting to be posted; beyond that new ones are dropped

log = logging.getLogger("doorman-activity")
_queue: "queue.Queue[dict]" = queue.Queue(BACKLOG)
_worker: threading.Thread | None = None
_lock = threading.Lock()


def register(ctx) -> None:
    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("post_tool_call", post_tool_call)


def pre_tool_call(**kwargs) -> None:
    _send("start", kwargs)


def post_tool_call(**kwargs) -> None:
    _send("end", kwargs)


def summary(args) -> str:
    """The command when there is one, else the arguments as compact JSON."""
    if isinstance(args, dict) and isinstance(args.get("command"), str):
        return args["command"][:COMMAND_CHARS]
    return json.dumps(args, ensure_ascii=False, separators=(",", ":"), default=str)[:SUMMARY_CHARS]


def _send(phase: str, kwargs: dict) -> None:
    try:
        tool = str(kwargs.get("tool_name") or "unknown")[:100]
        args = kwargs.get("args")
        call_id = kwargs.get("tool_call_id") or hashlib.sha256(
            json.dumps([tool, args], sort_keys=True, default=str).encode()).hexdigest()[:24]
        body = {"phase": phase, "call_id": str(call_id)[:100], "tool": tool, "summary": summary(args)}
        if phase == "end" and kwargs.get("status") is not None:
            body["status"] = str(kwargs["status"])[:40]
        _queue.put_nowait(body)
        _start_worker()
    except Exception as exc:  # a hook never raises
        log.warning("doorman-activity: %s", exc)


def _start_worker() -> None:
    global _worker
    with _lock:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_run, name="doorman-activity", daemon=True)
            _worker.start()


def _run() -> None:
    while True:
        body = _queue.get()
        try:
            _post(body)
        except Exception as exc:
            log.warning("doorman-activity: couldn't tell Doorman (%s)", exc)
        finally:
            _queue.task_done()


def _session(token: str) -> str | None:
    """DOORMAN_SESSION, else the session the `doorman` command saved for this key."""
    if os.environ.get("DOORMAN_SESSION"):
        return os.environ["DOORMAN_SESSION"]
    name = hashlib.sha256(token.encode()).hexdigest()[:12]
    path = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "doorman" / f"session-{name}"
    try:
        return path.read_text().strip() or None
    except OSError:
        return None


def _post(body: dict) -> None:
    base, token = os.environ.get("DOORMAN_URL", "").rstrip("/"), os.environ.get("DOORMAN_TOKEN", "")
    if not base or not token:
        return
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    session = _session(token)
    if session:
        headers["X-Doorman-Session"] = session
    request = urllib.request.Request(f"{base}/v1/activity", data=json.dumps(body).encode(), headers=headers,
                                     method="POST")
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        response.read()


def flush(timeout: float = 5) -> bool:
    """Wait until every queued line was posted (or given up on); for tests and shutdown."""
    done = threading.Event()

    def join():
        _queue.join()
        done.set()

    threading.Thread(target=join, daemon=True).start()
    return done.wait(timeout)
