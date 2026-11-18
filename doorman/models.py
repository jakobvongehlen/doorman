"""Pinned model downloads: files from a Hugging Face repository at a fixed revision, each checked against its
sha256 before it is used. Used by semantic search (embedder.py); the guard has its own copy of this logic."""

from __future__ import annotations

import hashlib
import logging
import threading
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("doorman.models")


class ModelFiles:
    def __init__(self, spec: dict, model_dir: Path, on_done: Callable[[], None] | None = None):
        """spec: {name, repo, revision, license, files: {local name: (path in the repo, sha256, size)}}."""
        self.spec = spec
        self.model_dir = Path(model_dir)
        self.on_done = on_done
        self.download: dict[str, Any] = {"state": "idle", "done": 0, "total": 0, "error": None}
        self._lock = threading.Lock()

    @property
    def size(self) -> int:
        return sum(size for _, _, size in self.spec["files"].values())

    def ready(self) -> bool:
        return all((self.model_dir / name).is_file() and (self.model_dir / name).stat().st_size == size
                   for name, (_, _, size) in self.spec["files"].items())

    def card(self) -> dict:
        return {"name": self.spec["name"], "repo": self.spec["repo"], "revision": self.spec["revision"],
                "license": self.spec["license"], "ready": self.ready(), "size": self.size}

    def fetch(self, wait: bool = False, base_url: str = "https://huggingface.co") -> dict:
        """Download in the background (or now, with `wait`); `download` shows the progress."""
        with self._lock:
            if self.download["state"] == "downloading":
                return dict(self.download)
            self.download = {"state": "downloading", "done": 0, "total": self.size, "error": None}
        if wait:
            self._fetch(base_url)
        else:
            threading.Thread(target=self._fetch, args=(base_url,), daemon=True,
                             name=f"fetch-{self.model_dir.name[:20]}").start()
        return dict(self.download)

    def _fetch(self, base_url: str) -> None:
        import httpx

        tmp = self.model_dir.with_name(self.model_dir.name + ".part")
        try:
            tmp.mkdir(parents=True, exist_ok=True)
            done = 0
            for name, (path, sha, size) in self.spec["files"].items():
                target = self.model_dir / name
                if target.is_file() and target.stat().st_size == size:
                    done += size
                    self.download["done"] = done
                    continue
                url = f"{base_url.rstrip('/')}/{self.spec['repo']}/resolve/{self.spec['revision']}/{path}"
                digest = hashlib.sha256()
                part = tmp / name
                with httpx.stream("GET", url, follow_redirects=True, timeout=60) as response, open(part, "wb") as out:
                    response.raise_for_status()
                    for chunk in response.iter_bytes(1 << 20):
                        out.write(chunk)
                        digest.update(chunk)
                        done += len(chunk)
                        self.download["done"] = done
                if digest.hexdigest() != sha:
                    part.unlink(missing_ok=True)
                    raise ValueError(f"{name} doesn't match its pinned sha256; not used")
                self.model_dir.mkdir(parents=True, exist_ok=True)
                part.replace(target)
            self.download = {**self.download, "state": "done", "done": self.download["total"]}
            log.info("%s downloaded to %s", self.spec["name"], self.model_dir)
            if self.on_done:
                self.on_done()
        except Exception as exc:  # noqa: BLE001 - shown in the app
            log.warning("downloading %s failed: %s", self.spec["name"], exc)
            self.download = {**self.download, "state": "failed", "error": f"{type(exc).__name__}: {exc}"}
        finally:
            try:
                for leftover in tmp.iterdir():
                    leftover.unlink()
                tmp.rmdir()
            except OSError:
                pass
