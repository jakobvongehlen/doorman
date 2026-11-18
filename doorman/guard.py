"""The injection guard: every third-party read is scanned for prompt injection before an agent gets it.
Optional, off unless the owner switches it on (More → Injection guard, or `guard: {enabled: true}` in
doorman.yaml): it wants the model's download and about 800 MB of memory while it scans.

The scanner is Wolf Defender Small v2, a 141M-parameter classifier (Apache 2.0) that scores text as
benign or injection. It runs in a process of its own (guard_worker.py), started on the first scan and
stopped after `idle_minutes` without one.

What happens with a score at or over the threshold is the engine's business (engine._scan): a single item
is refused, an item in a list is masked. Here: settings, the model download, the scan cache, and the
quarantine table, where each flagged text waits for the owner to release it (by its sha256: the same text
passes from then on, changed text is scanned again) or keep it blocked.

Switched on, if the scanner can't run (model not downloaded, worker crashed) reads go through unscanned, and
Needs attention says so. The owner chose that over blocking every third-party read until it's fixed.

Measured on this hardware (Nov 2026): the FP16 build takes ~1.3 s per 512-token window and ~800 MB while
running; with the threads it gets now (`threads`, guard_worker.py), 0.5-0.9 s per 1,000 characters.

An agent's call doesn't wait for a long scan past `answer_seconds` (answer_within): an MCP client gives up
on a call after 120 s, and Hermes's did, 5 s before a 61,000-character course outline was through. The scan
goes on in a thread of its own and keeps its result in the cache, and the agent gets GuardBusy (`busy`,
HTTP 429 with Retry-After): ask again in so many seconds. The text is held back meanwhile, not let through. The smaller INT8 builds in the same repository score every text ~0.96 with onnxruntime 1.31, so
they aren't used. The model misses some injections (it caught 524 of 629 buried ones in its authors' test,
and missed a short German one here); it is a filter in front of the approvals, not a replacement for them.
"""

from __future__ import annotations

import concurrent.futures
import contextvars
import hashlib
import logging
import math
import os
import re
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from . import clock
from .plugin_api import Denied
from .worker_process import Worker, WorkerUnavailable

log = logging.getLogger("doorman.guard")

MODEL = {
    "name": "Wolf Defender Small v2 (FP16)",
    "repo": "patronus-studio/wolf-defender-prompt-injection-small",
    "revision": "e311bc5648fa2c86ca637e6db819e68fc0bb5ccd",
    "license": "Apache-2.0",
    # local name: (path in the repository, sha256, size)
    "files": {
        "model.onnx": ("onnx/onnx_fp16/model_fp16.onnx",
                       "f81eccd747b4fe9b077fb37c7ddbe0571c5b21e544e84fa95cc8bcbff9cd1332", 281826832),
        "tokenizer.json": ("tokenizer.json",
                           "7e426c3929b44e6ab4c931770b5f22b913280633f5a1c67c81e9ad64decef55c", 34363287),
        "config.json": ("config.json",
                        "b5bfba7b100b4b1aa361e8160e5593695164d81ca09b47f3b26561332b520218", 2084),
    },
}
MODEL_ID = f"wolf-defender-small-v2-fp16@{MODEL['revision'][:12]}"
DEFAULTS = {"enabled": False, "threshold": 0.5, "window_tokens": 512, "overlap_tokens": 64, "idle_minutes": 10,
            # 0: half the CPUs this process may use, at most 4 (guard_worker.py has the measurements)
            "threads": 0,
            # an agent's call waits this long for its scans, then gets `busy`; MCP clients give up at 120 s,
            # and the plugin's own fetch comes out of the same time
            "answer_seconds": 80}
EXCERPT_CHARS = 3000
REASON = "possible prompt injection"
# for the "ask again in" estimate: slower than measured (0.5-0.9 s), as a second ask that's busy too costs more
SECONDS_PER_1000_CHARS = 1.0

# when the agent's call that's running in this context has to answer by (time.monotonic()); None: no limit
_answer_by: contextvars.ContextVar[float | None] = contextvars.ContextVar("guard_answer_by", default=None)


class GuardUnavailable(WorkerUnavailable):
    """The scanner can't run right now; the text goes through unscanned. `verdicts`, when check() sets it:
    the items it could decide without the model (already held, or flagged by sanitize.py)."""

    verdicts: list | None = None


class GuardBusy(Denied):
    """An agent's call ran out of time before its scans were done (answer_within). Unlike GuardUnavailable,
    the text doesn't go through: the scan goes on, and the same read a little later gets it from the cache."""

    def __init__(self, retry_after: int):
        super().__init__(f"still scanning this for prompt injection: it's long, and new to the scanner. Ask again "
                         f"in about {retry_after} s; the scan goes on meanwhile, and the same read then answers "
                         "at once", "busy")
        self.retry_after = retry_after


class _Scan(concurrent.futures.Future):
    """One scan running in its thread: {sha256: {score, start, end}} when it's done."""

    def __init__(self, chars: int):
        super().__init__()
        self.chars = chars
        self.started = time.monotonic()

    def seconds_left(self) -> float:
        return self.chars / 1000 * SECONDS_PER_1000_CHARS - (time.monotonic() - self.started)


LINK = re.compile(r"https?://[^\s<>\"'()\[\]{}]+")
LINK_PIECE = re.compile(r"[^/?&=#;]+")
WORDLIKE = re.compile(r"(?:[A-Z]?[a-z]+)+|[A-Z]+|\d+")


def _opaque(piece: str) -> bool:
    """A piece of a link nobody wrote words into: 16 characters or more, less than half of them words
    (lowercase, Capitalized or camelCase, ALL CAPS) or plain numbers. eJwUzLFuwyAQANCvgc0I7mx… is one,
    6a30303cc97c1_d429d20173937 too; ignore-all-previous-instructions and 2026-11-annual-report aren't."""
    if len(piece) < 16:
        return False
    words = sum(len(w) for w in re.split(r"[-_.+%~:,]", piece) if WORDLIKE.fullmatch(w))
    return words * 2 < len(piece)


def quiet_links(text: str) -> str:
    """The text as the model scans it: in every link, the pieces nobody wrote words into (a mail's click
    tracking, session tokens, a document's ID) become …. The model takes long random strings for encoded
    instructions: a FeedbackFruits notice scored 0.74 with its tracking link, 0.00 with links left out and
    0.02 with them cut short; the link alone scored 0.85. Words in a link (its host, a path, a query
    someone typed) stay in. The agent gets the link as it was."""
    def quiet(m: re.Match) -> str:
        return LINK_PIECE.sub(lambda p: "…" if _opaque(p.group(0)) else p.group(0), m.group(0))
    return LINK.sub(quiet, text)


def text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


class Guard:
    # tests put a fake scorer here (texts -> [{score, start, end}]) instead of the model
    backend: Callable[[list[str]], list[dict]] | None = None

    def __init__(self, config, db, attention: Callable[..., bool], resolve_attention: Callable[..., bool]):
        self.config = config
        self.db = db
        self.attention = attention
        self.resolve_attention = resolve_attention
        self.model_dir = Path(config.data_dir) / "models" / MODEL_ID
        self.lock = threading.Lock()          # the worker: one request at a time
        self.worker: Worker | None = None
        self._running: dict[str, _Scan] = {}  # sha256 -> the scan that has it, while it runs
        self._running_lock = threading.Lock()
        self.last_error: str | None = None
        self.download: dict[str, Any] = {"state": "idle", "done": 0, "total": 0, "error": None}
        self._download_lock = threading.Lock()

    # ------------------------------------------------------------------ settings

    def _yaml(self) -> dict:
        return dict(self.config.get("guard") or {})

    def locked(self) -> list[str]:
        """Settings doorman.yaml sets: they win, and the app shows them read-only."""
        return [k for k in ("enabled", "threshold") if k in self._yaml()]

    def setting(self, name: str) -> Any:
        block = self._yaml()
        if name in block:
            return block[name]
        stored = self.db.get_setting(f"guard_{name}") if name in ("enabled", "threshold") else None
        if stored is not None:
            return stored == "1" if name == "enabled" else float(stored)
        return DEFAULTS[name]

    @property
    def enabled(self) -> bool:
        return bool(self.setting("enabled"))

    @property
    def threshold(self) -> float:
        return float(self.setting("threshold"))

    def settings(self) -> dict:
        return {"enabled": self.enabled, "threshold": self.threshold, "locked": self.locked()}

    @staticmethod
    def check_threshold(value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0.05 <= float(value) <= 0.99:
            raise Denied("threshold is a number from 0.05 to 0.99", "invalid")
        return round(float(value), 3)

    def loosens(self, enabled: Any = None, threshold: Any = None) -> bool:
        """Switching off or raising the threshold lets more through: that needs a fresh passkey check."""
        return enabled is False or (threshold is not None and isinstance(threshold, (int, float))
                                    and not isinstance(threshold, bool) and float(threshold) > self.threshold)

    def save(self, enabled: Any = None, threshold: Any = None) -> tuple[dict, dict]:
        changing = [k for k, v in (("enabled", enabled), ("threshold", threshold)) if v is not None]
        fixed = [k for k in changing if k in self.locked()]
        if fixed:
            raise Denied(f"doorman.yaml sets guard {', '.join(fixed)}; change it there", "locked")
        if enabled is not None and not isinstance(enabled, bool):
            raise Denied("enabled is true or false", "invalid")
        value = self.check_threshold(threshold) if threshold is not None else None
        before = self.settings()
        if enabled is not None:
            self.db.set_setting("guard_enabled", "1" if enabled else "0")
        if value is not None:
            self.db.set_setting("guard_threshold", str(value))
        if enabled is False:
            self.resolve_attention("guard", "scanner")  # off on purpose: nothing broken to report
        return before, self.settings()

    # ------------------------------------------------------------------ the model

    def model_ready(self) -> bool:
        return all((self.model_dir / name).is_file() and (self.model_dir / name).stat().st_size == size
                   for name, (_, _, size) in MODEL["files"].items())

    def fetch(self, wait: bool = False, base_url: str = "https://huggingface.co") -> dict:
        """Download the pinned model files into data_dir/models and check each sha256. In the background
        unless `wait`; status() shows the progress."""
        with self._download_lock:
            if self.download["state"] == "downloading":
                return self.status()
            total = sum(size for _, _, size in MODEL["files"].values())
            self.download = {"state": "downloading", "done": 0, "total": total, "error": None}
        if wait:
            self._fetch(base_url)
        else:
            threading.Thread(target=self._fetch, args=(base_url,), daemon=True, name="guard-fetch").start()
        return self.status()

    def _fetch(self, base_url: str) -> None:
        import httpx

        tmp = self.model_dir.with_name(self.model_dir.name + ".part")
        try:
            tmp.mkdir(parents=True, exist_ok=True)
            done = 0
            for name, (path, sha, size) in MODEL["files"].items():
                target = self.model_dir / name
                if target.is_file() and target.stat().st_size == size:
                    done += size
                    self.download["done"] = done
                    continue
                url = f"{base_url.rstrip('/')}/{MODEL['repo']}/resolve/{MODEL['revision']}/{path}"
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
                    raise GuardUnavailable(f"{name} doesn't match its pinned sha256; not used")
                self.model_dir.mkdir(parents=True, exist_ok=True)
                part.replace(target)
            self.download = {**self.download, "state": "done", "done": self.download["total"]}
            self.last_error = None
            self.resolve_attention("guard", "scanner")
            log.info("guard model downloaded to %s", self.model_dir)
        except Exception as exc:  # noqa: BLE001 - shown on the Guard screen
            log.exception("guard model download failed")
            self.download = {**self.download, "state": "failed", "error": f"{type(exc).__name__}: {exc}"}
        finally:
            try:
                for leftover in tmp.iterdir():
                    leftover.unlink()
                tmp.rmdir()
            except OSError:
                pass

    # ------------------------------------------------------------------ scanning

    def threads(self) -> int:
        """The scanner's threads: guard.threads, or half the CPUs this process may use, at most 4."""
        wanted = int(self.setting("threads") or 0)
        if wanted > 0:
            return wanted
        try:
            cpus = len(os.sched_getaffinity(0))
        except (AttributeError, OSError):
            cpus = os.cpu_count() or 1
        return max(1, min(4, cpus // 2))

    @contextmanager
    def answer_within(self, seconds: float | None = None) -> Iterator[None]:
        """Around an agent's call: scans it needs that aren't done `seconds` (guard.answer_seconds) from now
        raise GuardBusy instead of holding the call. Inside another one, the outer time holds. Elsewhere (the
        owner's app, doorman-admin, background jobs) scans are waited for, however long they take."""
        if _answer_by.get() is not None:
            yield
            return
        limit = float(self.setting("answer_seconds")) if seconds is None else seconds
        token = _answer_by.set(time.monotonic() + max(0.0, limit))
        try:
            yield
        finally:
            _answer_by.reset(token)

    def _worker(self) -> Worker:
        if self.worker and self.worker.alive():
            return self.worker
        if not self.model_ready():
            raise GuardUnavailable("The scanner model isn't downloaded yet: More → Injection guard → Download model.")
        args = [str(self.model_dir), str(int(self.setting("window_tokens"))), str(int(self.setting("overlap_tokens"))),
                str(self.threads())]
        sandboxed = bool(self.config.get("plugin_sandbox", True))
        if sandboxed:
            args.append("sandbox")
        try:
            self.worker = Worker("doorman.guard_worker", args, "scanner", own_user=sandboxed,
                                 shared=self.model_dir).start(timeout=180)
        except WorkerUnavailable as exc:
            raise GuardUnavailable(str(exc)) from None
        return self.worker

    def _score(self, texts: list[str]) -> list[dict]:
        if self.backend is not None:
            return self.backend(texts)
        with self.lock:
            worker = self._worker()
            # ~1.3 s per 512-token window (~1,500 characters) on a small VPS, with a lot of room
            budget = 60 + sum(len(t) for t in texts) / 100
            try:
                return worker.call({"texts": texts}, timeout=min(budget, 1800))["results"]
            except WorkerUnavailable as exc:
                raise GuardUnavailable(str(exc)) from None

    def scores(self, texts: list[str]) -> list[dict]:
        """{score, start, end} per text, from the cache where possible. Raises GuardUnavailable when the scanner
        can't run, and GuardBusy when an agent's call (answer_within) runs out of time first."""
        hashes = [text_hash(t) for t in texts]
        cached = {}
        for i in range(0, len(hashes), 500):
            chunk = hashes[i:i + 500]
            rows = self.db.all(f"SELECT * FROM scans WHERE model=? AND sha256 IN ({','.join('?' * len(chunk))})",
                               (MODEL_ID, *chunk))
            cached.update({r["sha256"]: r for r in rows})
        missing = list(dict.fromkeys(h for h in hashes if h not in cached))
        if missing:
            answer_by = _answer_by.get()
            scans = self._scans_for(missing, dict(zip(hashes, texts)))
            for scan in scans:
                left = None if answer_by is None else max(0.0, answer_by - time.monotonic())
                try:
                    cached.update(scan.result(timeout=left))
                except concurrent.futures.TimeoutError:
                    left = max((s.seconds_left() for s in scans if not s.done()), default=0)
                    raise GuardBusy(max(10, math.ceil(left / 10) * 10)) from None
                except GuardUnavailable as exc:  # one of its own: check() writes on it, and others wait on this scan
                    raise GuardUnavailable(str(exc)) from exc
        return [{k: cached[h][k] for k in ("score", "start", "end")} for h in hashes]

    def _scans_for(self, missing: list[str], by_hash: dict[str, str]) -> list[_Scan]:
        """The scans that answer `missing`: one already running for some of them (another read asked first)
        and a new one for the rest, in a thread of its own, so a caller who stops waiting doesn't stop it."""
        with self._running_lock:
            scans = {id(s): s for s in (self._running.get(h) for h in missing) if s is not None}
            new = [h for h in missing if h not in self._running]
            if new:
                scan = _Scan(sum(len(by_hash[h]) for h in new))
                for h in new:
                    self._running[h] = scan
                threading.Thread(target=self._run_scan, args=(scan, new, [by_hash[h] for h in new]),
                                 name="guard-scan", daemon=True).start()
                scans[id(scan)] = scan
        return list(scans.values())

    def _run_scan(self, scan: _Scan, hashes: list[str], texts: list[str]) -> None:
        try:
            try:
                results = self._score(texts)
            except GuardUnavailable as exc:
                self._broken(str(exc))
                raise
            except Exception as exc:  # noqa: BLE001 - a scanner bug must not break reads
                log.exception("guard scan failed")
                self._broken(f"{type(exc).__name__}: {exc}")
                raise GuardUnavailable(str(exc)) from exc
            scan.set_result(self._keep(hashes, results))
        except Exception as exc:  # noqa: BLE001 - whoever waits on the scan gets it
            scan.set_exception(exc)
        finally:
            with self._running_lock:
                for h in hashes:
                    if self._running.get(h) is scan:
                        del self._running[h]

    def _keep(self, hashes: list[str], results: list[dict]) -> dict[str, dict]:
        """Into the cache, so the next read of the same text needn't wait, whoever asked for the scan."""
        kept, now = {}, clock.iso()
        with self.db.tx() as conn:
            for h, result in zip(hashes, results):
                kept[h] = {"score": float(result["score"]), "start": int(result.get("start", 0)),
                           "end": int(result.get("end", 0))}
                conn.execute("INSERT OR REPLACE INTO scans(sha256, model, score, start, end, ts) VALUES(?,?,?,?,?,?)",
                             (h, MODEL_ID, kept[h]["score"], kept[h]["start"], kept[h]["end"], now))
        if self.last_error:
            self.last_error = None
            self.resolve_attention("guard", "scanner")
        return kept

    def _broken(self, error: str) -> None:
        self.last_error = error
        self.attention("guard", "scanner", "The injection scanner isn't working",
                       f"Third-party text reaches agents unscanned until it works again. {error}",
                       url=f"{self.config['public_url'].rstrip('/')}/app/#/guard", priority=4)

    def check(self, items: list[dict]) -> list[dict | None]:
        """items: {text, source, ref, label, sender}. Returns, per item, None (it may pass) or its quarantine
        row. Raises GuardUnavailable when the scanner can't run (the caller lets the text through)."""
        if not items:
            return []
        items = [{**i, "text": quiet_links(i["text"])} for i in items]  # what the model scans, hashed and shown
        hashes = [text_hash(i["text"]) for i in items]
        rows = {}
        for i in range(0, len(hashes), 500):
            chunk = hashes[i:i + 500]
            rows.update({r["sha256"]: r for r in self.db.all(
                f"SELECT * FROM quarantine WHERE sha256 IN ({','.join('?' * len(chunk))})", tuple(chunk))})
        verdicts: list[dict | None] = [None] * len(items)
        pending = []
        for n, (item, h) in enumerate(zip(items, hashes)):
            row = rows.get(h)
            if row is None and item.get("flag"):
                # hidden text found in code (sanitize.py): held back without asking the model
                verdicts[n] = self._quarantine(item, h, {"score": 1.0, "start": 0, "end": 0}, item["flag"])
            elif row is None:
                pending.append(n)
            elif row["status"] != "released":
                verdicts[n] = row
        if not pending:
            return verdicts
        threshold = self.threshold
        try:
            scores = self.scores([items[n]["text"] for n in pending])
        except GuardUnavailable as exc:
            exc.verdicts = verdicts  # what's already held (or flagged) stays held while the scanner is down
            raise
        for n, result in zip(pending, scores):
            if result["score"] >= threshold:
                verdicts[n] = self._quarantine(items[n], hashes[n], result)
        return verdicts

    def _quarantine(self, item: dict, sha: str, result: dict, reason: str | None = None) -> dict:
        text = item["text"]
        excerpt = text[result["start"]:result["end"]] or text
        with self.db.tx() as conn:
            existing = conn.execute("SELECT * FROM quarantine WHERE sha256=?", (sha,)).fetchone()
            if existing:
                return dict(existing)
            qid = conn.execute(
                "INSERT INTO quarantine(sha256, source, ref, label, sender, score, excerpt, status, created, reason) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (sha, item.get("source"), _cut(item.get("ref"), 500), _cut(item.get("label"), 200),
                 _cut(item.get("sender"), 200), round(float(result["score"]), 4), excerpt[:EXCERPT_CHARS],
                 "held", clock.iso(), _cut(reason, 300))).lastrowid
        row = self.quarantined(qid)
        where = " · ".join(x for x in (item.get("source"), _cut(item.get("sender"), 80)) if x)
        why = f"({reason})" if reason else f"(score {row['score']:.2f})"
        self.attention("quarantine", qid, f"Held back: {reason or REASON}",
                       f"{where}: {_cut(item.get('label'), 120) or 'an item'} {why}. "
                       "No agent got it. Release it if it's harmless.",
                       url=f"{self.config['public_url'].rstrip('/')}/app/#/quarantine/{qid}", priority=2,
                       # Keep acts on the push; Release opens the item, where the app asks once more
                       ask={"kind": "quarantine", "id": qid, "accept": "app"})
        return row

    # ------------------------------------------------------------------ quarantine

    def quarantined(self, qid: int) -> dict | None:
        return self.db.one("SELECT * FROM quarantine WHERE id=?", (qid,))

    def list(self, status: str | None = None, limit: int = 100) -> list[dict]:
        """Newest first; without a status, what's still held back comes before everything decided, so a page
        of it (the Guard screen's) never leaves out an item agents still get held back."""
        if status:
            return self.db.all("SELECT * FROM quarantine WHERE status=? ORDER BY id DESC LIMIT ?", (status, limit))
        return self.db.all("SELECT * FROM quarantine ORDER BY status='held' DESC, id DESC LIMIT ?", (limit,))

    def held_refs(self, refs: list[str]) -> set[str]:
        refs = [r for r in refs if r]
        if not refs:
            return set()
        rows = self.db.all(f"SELECT ref FROM quarantine WHERE status!='released' AND ref IN "
                           f"({','.join('?' * len(refs))})", tuple(refs))
        return {r["ref"] for r in rows}

    def decide(self, qid: int, release: bool) -> dict:
        row = self.quarantined(qid)
        if row is None:
            raise Denied("nothing quarantined with that id", "not_found")
        status = "released" if release else "kept"
        self.db.exec("UPDATE quarantine SET status=?, decided=? WHERE id=?", (status, clock.iso(), qid))
        self.resolve_attention("quarantine", qid)
        return self.quarantined(qid)

    # ------------------------------------------------------------------ status and upkeep

    def status(self) -> dict:
        running = bool(self.worker and self.worker.alive())
        if not self.enabled:
            state = "off"
        elif self.download["state"] == "downloading":
            state = "downloading"
        elif not self.model_ready() and self.backend is None:
            state = "missing"
        elif self.last_error:
            state = "broken"
        else:
            state = "ready"
        count = lambda sql: self.db.one(sql)["n"]  # noqa: E731
        return {
            **self.settings(),
            "state": state,
            "error": self.last_error,
            "model": {"name": MODEL["name"], "repo": MODEL["repo"], "revision": MODEL["revision"],
                      "license": MODEL["license"], "ready": self.model_ready(),
                      "size": sum(size for _, _, size in MODEL["files"].values())},
            "download": dict(self.download),
            "running": running,
            "held": count("SELECT COUNT(*) AS n FROM quarantine WHERE status='held'"),
            "kept": count("SELECT COUNT(*) AS n FROM quarantine WHERE status='kept'"),
            "released": count("SELECT COUNT(*) AS n FROM quarantine WHERE status='released'"),
            "scanned": count("SELECT COUNT(*) AS n FROM scans"),
        }

    def stop_if_idle(self) -> None:
        worker = self.worker
        if worker and worker.alive() and not self.lock.locked() and \
                worker.idle_for() > float(self.setting("idle_minutes")) * 60:
            with self.lock:
                worker.stop()
                self.worker = None
            log.info("guard scanner stopped after being idle")

    def stop(self) -> None:
        with self.lock:
            if self.worker:
                self.worker.stop()
                self.worker = None


def _cut(value: Any, n: int) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split())
    return text if len(text) <= n else text[: n - 1] + "…"


def held_row(item: Any, held: dict | None = None) -> dict:
    """A list row the guard held back: no text, but the keys a pipeline goes by (id, ref, plugin) and
    `held: true`, so `select(.held | not)` or `.held // false` sorts it out instead of a missing field
    breaking the filter. `quarantined` stays for what reads it already."""
    out = {"quarantined": True, "held": True, "reason": (held or {}).get("reason") or REASON}
    if isinstance(item, dict):
        for key in ("id", "ref", "plugin"):
            if item.get(key) is not None:
                out[key] = str(item[key])[:200]
        if "plugin" not in out and ":" in out.get("ref", ""):
            out["plugin"] = out["ref"].split(":", 1)[0]
    return out
