"""Doorman's side of text extraction: the extractor process (extract_worker.py) and the call plugins make.

Plugins hand over a document's bytes (ctx.extract, over the plugin wire when they run in their own process)
and get its text back. The extractor starts on first use and stops after `idle_minutes` without one; with
OCR loaded it takes about 600 MB. If it can't run, the caller gets empty text and a note, never a parse in
Doorman's own process.
"""

from __future__ import annotations

import base64
import logging
import threading
import time
from typing import Any

from .extract import check_mode
from .worker_process import Worker, WorkerUnavailable

log = logging.getLogger("doorman.extractor")

# memory_mb: the process's address space (RLIMIT_AS; virtual, so well above the ~600 MB it uses), 0: none
DEFAULTS = {"ocr": True, "dpi": 200, "ocr_max_pages": 20, "idle_minutes": 10, "max_mb": 50, "memory_mb": 2048}
# background work (a mail archive's backfill) waits until the agent hasn't needed the extractor for this
# long: a few seconds for text layers, a minute before an OCR run that can hold it for minutes
QUIET_SECONDS = {"text": 5.0, "ocr": 60.0}
BACKGROUND_WAIT = 120.0


class Extractor:
    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()
        self.worker: Worker | None = None
        self.last_error: str | None = None
        self.waiting = 0                      # interactive calls waiting for the lock
        self.last_interactive = -1e9          # time.monotonic() of the last interactive call
        self.make_room = None                 # stops the embedding model if idle (engine.py)

    def setting(self, name: str) -> Any:
        return (self.config.get("extract") or {}).get(name, DEFAULTS[name])

    def _worker(self, background: bool = False) -> Worker:
        if self.worker and self.worker.alive():
            return self.worker
        if background and self.make_room:
            self.make_room()
        args = [str(int(self.setting("dpi"))), str(int(self.setting("ocr_max_pages")))]
        sandboxed = bool(self.config.get("plugin_sandbox", True))
        if sandboxed:
            args.append("sandbox")
        args.append(f"mem={int(self.setting('memory_mb'))}")
        self.worker = Worker("doorman.extract_worker", args, "text extractor", own_user=sandboxed).start(timeout=60)
        return self.worker

    def _wait_quiet(self, ocr: bool) -> bool:
        """Background work goes only when no agent read waits or ran just now. False: still busy."""
        quiet = QUIET_SECONDS["ocr" if ocr else "text"]
        deadline = time.monotonic() + BACKGROUND_WAIT
        while time.monotonic() < deadline:
            if not self.waiting and time.monotonic() - self.last_interactive >= quiet and not self.lock.locked():
                return True
            time.sleep(0.5)
        return False

    def extract(self, name: str, content: bytes, content_type: str | None = None, ocr: bool = True,
                limit: int = 2_000_000, check_pdf: bool | str = True, background: bool = False) -> dict:
        """{text, report, pages?, ocr_pages?, note?} for one document (see extract.extract). `background`:
        work nobody waits for, which steps aside for the agent's reads (and answers busy=True if it had to
        wait too long)."""
        if len(content) > float(self.setting("max_mb")) * 1024 * 1024:
            return {"text": "", "report": {}, "note": f"larger than {self.setting('max_mb')} MB; not read"}
        ocr = bool(ocr and self.setting("ocr"))
        message = {"name": name, "content": base64.b64encode(content).decode(), "content_type": content_type,
                   "ocr": ocr, "limit": int(limit), "check_pdf": check_mode(check_pdf)}
        # a page of OCR takes ~10 s on a small VPS; a long text-only PDF a few seconds
        budget = 60 + 15 * int(self.setting("ocr_max_pages"))
        if background:
            if not self._wait_quiet(ocr):
                return {"text": "", "report": {}, "busy": True, "note": "the extractor is busy; try later"}
            return self._run(name, message, budget, background=True)
        self.waiting += 1
        try:
            self.lock.acquire()
        finally:
            self.waiting -= 1
        self.last_interactive = time.monotonic()
        try:
            return self._run(name, message, budget, locked=True)
        finally:
            self.last_interactive = time.monotonic()

    def _run(self, name: str, message: dict, budget: float, locked: bool = False, background: bool = False) -> dict:
        if not locked:
            self.lock.acquire()
        try:
            try:
                out = self._worker(background).call(message, timeout=budget)
                self.last_error = None
                return out
            except WorkerUnavailable as exc:
                self.last_error = str(exc)
                log.warning("extracting %s failed: %s", name, exc)
                return {"text": "", "report": {}, "note": f"couldn't extract text: {exc}"}
        finally:
            self.lock.release()

    def stop_if_idle(self) -> None:
        worker = self.worker
        if worker and worker.alive() and not self.lock.locked() and \
                worker.idle_for() > float(self.setting("idle_minutes")) * 60:
            with self.lock:
                worker.stop()
                self.worker = None

    def stop_if_unused(self) -> None:
        """Make room for another model: stop now if nothing is being read."""
        if self.worker and self.lock.acquire(blocking=False):
            try:
                if self.worker:
                    self.worker.stop()
                    self.worker = None
            finally:
                self.lock.release()

    def stop(self) -> None:
        with self.lock:
            if self.worker:
                self.worker.stop()
                self.worker = None
