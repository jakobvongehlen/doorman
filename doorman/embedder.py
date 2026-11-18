"""Semantic search: Doorman's side of the embedding model (embed_worker.py).

Off by default. Switched on in the app (More → Semantic search) or with `semantic: {enabled: true}` in
doorman.yaml; switching it on downloads the model (pinned revision, sha256 checked) if it isn't there yet.
Plugins ask for vectors through ctx.embed (over the plugin wire when they run in their own process): a mail
archive embeds its messages in the background, newest first, and embeds each search query. Background work
steps aside while the agent searches, and the model's process stops when idle.
"""

from __future__ import annotations

import base64
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .models import ModelFiles
from .plugin_api import Denied
from .worker_process import Worker, WorkerUnavailable

log = logging.getLogger("doorman.embedder")

# IBM's Granite Embedding 107M multilingual (r1) as a uint8 ONNX file built for AVX2 CPUs (gety-ai's export of
# IBM's model, Apache-2.0). Measured on this box (Nov 2026, 419 documents and 80 queries in German, Dutch and
# English, tests/embedding_eval): the right document first for 80% of queries (MRR 0.86, across languages
# 0.87), against 47% for the int8 build of Granite r2 used before, whose signed int8 weights lose too much on
# CPUs without VNNI; about 0.08 s per 200-token chunk on one core; about 500 MB while it runs. Its vectors
# match IBM's own fp32 model's at cosine 0.99 and its tokenizer IBM's token for token.
MODEL = {
    "name": "Granite Embedding 107M multilingual (uint8)",
    "repo": "gety-ai/granite-embedding-107m-multilingual-onnx",
    "revision": "4713bc4053d578f45e263e5857262b69f1f4296f",
    "license": "Apache-2.0",
    "files": {
        "model.onnx": ("onnx/model_quint8_avx2.onnx",
                       "d05faecfadb826e7674c1588917db966aac32b362c8dabe71dd06ef6c3d1b688", 107310611),
        "tokenizer.json": ("tokenizer.json",
                           "14917dd757b81bc44d4af6b028367351702656670c1954e055dabdfcf21593cf", 17082798),
        "config.json": ("config.json",
                        "c3706f9fcb0809d6de6af9805cf8849603929b8fa849cf1b398c80445d660b66", 726),
    },
}
MODEL_ID = f"granite-embedding-107m-multilingual-quint8@{MODEL['revision'][:12]}"
DIM = 384
DEFAULTS = {"enabled": False, "idle_minutes": 10, "max_tokens": 512}
QUIET_SECONDS = 5.0       # background embedding waits this long after the agent's last search
BACKGROUND_WAIT = 60.0


class Embedder:
    # tests put a stand-in here (texts -> list of float vectors) instead of the model
    backend: Callable[[list[str]], list[list[float]]] | None = None

    def __init__(self, config, db):
        self.config = config
        self.db = db
        self.files = ModelFiles(MODEL, Path(config.data_dir) / "models" / MODEL_ID)
        self.lock = threading.Lock()
        self.worker: Worker | None = None
        self.last_error: str | None = None
        self.waiting = 0
        self.last_interactive = -1e9
        self.make_room: Callable[[], None] | None = None   # stops the extractor if idle (engine.py)

    # ------------------------------------------------------------------ settings

    def _yaml(self) -> dict:
        return dict(self.config.get("semantic") or {})

    def locked(self) -> list[str]:
        return ["enabled"] if "enabled" in self._yaml() else []

    def setting(self, name: str) -> Any:
        block = self._yaml()
        if name in block:
            return block[name]
        if name == "enabled":
            stored = self.db.get_setting("semantic_enabled")
            if stored is not None:
                return stored == "1"
        return DEFAULTS[name]

    @property
    def enabled(self) -> bool:
        return bool(self.setting("enabled"))

    def ready(self) -> bool:
        return self.backend is not None or self.files.ready()

    def save(self, enabled: Any) -> dict:
        if not isinstance(enabled, bool):
            raise Denied("enabled is true or false", "invalid")
        if self.locked():
            raise Denied("doorman.yaml sets semantic.enabled; change it there", "locked")
        self.db.set_setting("semantic_enabled", "1" if enabled else "0")
        if enabled and not self.ready():
            self.files.fetch()
        if not enabled:
            self.stop()
        return self.status()

    def fetch(self, wait: bool = False, base_url: str = "https://huggingface.co") -> dict:
        self.files.fetch(wait=wait, base_url=base_url)
        return self.status()

    def status(self) -> dict:
        if not self.enabled:
            state = "off"
        elif self.files.download["state"] == "downloading":
            state = "downloading"
        elif not self.ready():
            state = "missing"
        elif self.last_error:
            state = "broken"
        else:
            state = "ready"
        return {"enabled": self.enabled, "locked": self.locked(), "state": state, "error": self.last_error,
                "model": self.files.card(), "model_id": MODEL_ID, "download": dict(self.files.download),
                "running": bool(self.worker and self.worker.alive())}

    def ensure_downloaded(self) -> None:
        """On start, and hourly: switched on but no model (a fresh install, a failed download): fetch it."""
        if self.enabled and not self.ready() and self.files.download["state"] in ("idle", "failed"):
            self.files.fetch()

    # ------------------------------------------------------------------ embedding

    def _worker(self, background: bool) -> Worker:
        if self.worker and self.worker.alive():
            return self.worker
        if background and self.make_room:
            self.make_room()  # the OCR model and this one don't both need to sit in memory
        args = [str(self.files.model_dir), str(int(self.setting("max_tokens")))]
        sandboxed = bool(self.config.get("plugin_sandbox", True))
        if sandboxed:
            args.append("sandbox")
        self.worker = Worker("doorman.embed_worker", args, "embedding model", own_user=sandboxed,
                             shared=self.files.model_dir).start(timeout=180)
        return self.worker

    def _wait_quiet(self) -> bool:
        deadline = time.monotonic() + BACKGROUND_WAIT
        while time.monotonic() < deadline:
            if not self.waiting and time.monotonic() - self.last_interactive >= QUIET_SECONDS and not self.lock.locked():
                return True
            time.sleep(0.25)
        return False

    def embed(self, texts: list[str], background: bool = False) -> dict:
        """{"model", "dim", "vectors": bytes (float16, normalized, one row per text)}; {"off": True} when
        semantic search is off or the model isn't there yet; {"busy": True} when background work gave way."""
        if not self.enabled or not self.ready():
            return {"off": True, "state": self.status()["state"]}
        texts = [str(t)[:20000] for t in texts]
        if not texts:  # a probe: is it on, and with which model (doesn't start the model)
            return {"model": "test-backend" if self.backend is not None else MODEL_ID, "dim": DIM, "vectors": b""}
        if background:
            if not self._wait_quiet():
                return {"busy": True}
            with self.lock:
                return self._run(texts, True)
        self.waiting += 1
        try:
            self.lock.acquire()
        finally:
            self.waiting -= 1
        try:
            return self._run(texts, False)
        finally:
            self.lock.release()
            self.last_interactive = time.monotonic()

    def _run(self, texts: list[str], background: bool) -> dict:
        import numpy as np

        if self.backend is not None:
            vectors = np.array(self.backend(texts), dtype=np.float32).reshape(len(texts), DIM)
            norms = np.linalg.norm(vectors, axis=1, keepdims=True)
            norms[norms == 0] = 1
            return {"model": "test-backend", "dim": DIM, "vectors": (vectors / norms).astype("<f2").tobytes()}
        try:
            worker = self._worker(background)
            # ~1 s per 512 tokens (about 1,500 characters) on one core, with room to spare
            budget = 120 + sum(min(len(t), 2000) for t in texts) / 300
            out = worker.call({"texts": texts}, timeout=budget)
            self.last_error = None
            return {"model": MODEL_ID, "dim": int(out.get("dim", DIM)), "vectors": base64.b64decode(out["vectors"])}
        except WorkerUnavailable as exc:
            self.last_error = str(exc)
            log.warning("embedding failed: %s", exc)
            return {"off": True, "state": "broken", "error": str(exc)}

    def stop_if_idle(self) -> None:
        worker = self.worker
        if worker and worker.alive() and not self.lock.locked() and \
                worker.idle_for() > float(self.setting("idle_minutes")) * 60:
            with self.lock:
                worker.stop()
                self.worker = None

    def stop_if_unused(self) -> None:
        """Make room for another model: stop now if nothing is embedding."""
        if self.worker and not self.lock.locked() and self.lock.acquire(blocking=False):
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
