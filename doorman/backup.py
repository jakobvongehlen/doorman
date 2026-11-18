"""Backups: everything undo needs, copied consistently, never the vault key.

A backup is a directory `doorman-YYYYmmdd-HHMMSS` with:

    doorman.yaml          the configuration
    data/doorman.db       journal, approvals, tasks... (SQLite backup API, so a running doorman is fine)
    data/vault.enc       the encrypted credentials (useless without the key, which is never copied)
    data/plugins/...     plugin data: notes, the files index (SQLite files again through the backup API)
    extra/<name>/...     backup.extra_paths, e.g. the WhatsApp sidecar's session
    manifest.json        every file with its SHA-256, checked before a restore

It is written as `<name>.partial` and renamed when complete, so a half-written backup never counts.
The oldest are deleted beyond `keep`. Copy the directory to another host (rsync, rclone, a mounted
disk; rsync -H keeps the hard links); a backup on Doorman's own disk doesn't survive that disk.
`copy_off_host` runs the owner's command for that (backup.copy_command); upkeep.py runs both nightly.

Two markers a plugin can put in a folder of its own:

    .no-backup     the folder is left out: it can be rebuilt (a search index). A restore deletes it, so it
                   is rebuilt from the restored data rather than kept from what was there before
    .immutable     files below never change once written (a mail archive's originals, named by their
                   hash), so a file the previous backup has at the same path and size is hard-linked
                   from there instead of copied: fourteen backups of 10 GB of mail take 10 GB
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from . import __version__, clock

SQLITE_MAGIC = b"SQLite format 3\x00"
NEVER = {"vault.key"}                       # the key stays out of every backup
SKIP_SUFFIXES = ("-wal", "-shm", "-journal", ".tmp", ".partial")


class BackupError(Exception):
    pass


TIME_RE = re.compile(r"^([01]?\d|2[0-3]):([0-5]\d)$")
# environment variables a copy command never gets, whatever backup.copy_env says
NEVER_ENV = {"ANTHROPIC_API_KEY", "READER_API_KEY", "READER_DOORMAN_TOKEN", "SIDECAR_TOKEN"}


def schedule_time(schedule: str | int) -> str:
    """backup.schedule as HH:MM. YAML 1.1 reads an unquoted 13:30 as 810 (base 60), so that counts too."""
    if isinstance(schedule, int) and not isinstance(schedule, bool) and 0 <= schedule < 24 * 60:
        return f"{schedule // 60:02d}:{schedule % 60:02d}"
    match = TIME_RE.match(str(schedule or "").strip())
    if not match:
        raise BackupError(f"backup.schedule must be a time of day like 03:30, not {schedule!r}")
    return f"{int(match.group(1)):02d}:{match.group(2)}"


def next_run(schedule: str | int, zone: ZoneInfo, after: datetime) -> datetime:
    """The first time `schedule` (HH:MM on the owner's clock) comes after `after`. A time a DST change
    skips runs an hour later that day; one it repeats runs the first time."""
    hour, minute = (int(part) for part in schedule_time(schedule).split(":"))
    day = after.astimezone(zone).date()
    while True:
        wall = datetime(day.year, day.month, day.day, hour, minute)
        at = wall.replace(tzinfo=zone)
        if at.astimezone(timezone.utc).astimezone(zone).replace(tzinfo=None) != wall:  # skipped by DST
            at = (wall + timedelta(hours=1)).replace(tzinfo=zone)
        if at > after:
            return at
        day += timedelta(days=1)


def copy_command_args(command: str | list, backup: Path) -> list[str]:
    """The copy command as arguments. A string is split as a shell would split it, but no shell runs it.
    {path} (the backup directory), {name} (its name) and {dir} (backup.dir) are filled in afterwards, each
    inside the one argument it stands in, so a path can't add arguments or commands."""
    try:
        parts = shlex.split(command) if isinstance(command, str) else [str(p) for p in command]
    except ValueError as exc:
        raise BackupError(f"backup.copy_command can't be split into arguments: {exc}") from None
    if not parts:
        raise BackupError("backup.copy_command is empty")
    values = {"{path}": str(backup), "{name}": backup.name, "{dir}": str(backup.parent)}
    out = []
    for part in parts:
        for key, value in values.items():
            part = part.replace(key, value)
        out.append(part)
    return out


def copy_off_host(backup: Path, command: str | list, timeout: float, env_names: list[str] | None = None) -> str:
    """Runs backup.copy_command for one finished backup, e.g. `rclone copy {path} remote:doorman/{name}` or
    `restic backup {path}`. It gets what a helper process gets of Doorman's environment (no vault key, no API
    keys), plus the variables backup.copy_env names (RESTIC_REPOSITORY, RCLONE_CONFIG...). On a timeout its
    whole process group is killed. Returns the end of its output; raises BackupError when it fails."""
    from .worker_process import clean_env

    backup = Path(backup)
    args = copy_command_args(command, backup)
    env = clean_env()
    env.pop("OMP_NUM_THREADS", None)  # that one is for the OCR and guard workers
    for name in env_names or []:
        if name in NEVER_ENV or name.startswith("DOORMAN_"):
            raise BackupError(f"backup.copy_env: {name} is never passed to a copy command")
        if name in os.environ:
            env[name] = os.environ[name]
    try:
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                cwd=backup.parent, env=env, start_new_session=True)
    except OSError as exc:
        raise BackupError(f"couldn't start {args[0]}: {exc.strerror or exc}") from None
    try:
        output, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)  # rclone's or restic's own children too
        except ProcessLookupError:
            pass
        proc.communicate()
        raise BackupError(f"{args[0]} took longer than {timeout:g} seconds and was stopped") from None
    tail = output.decode("utf-8", "replace").strip()[-500:]
    if proc.returncode != 0:
        raise BackupError(f"{args[0]} exited with {proc.returncode}" + (f": {tail}" if tail else ""))
    return tail


def _is_sqlite(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(16) == SQLITE_MAGIC
    except OSError:
        return False


def _copy_sqlite(source: Path, target: Path) -> None:
    """A consistent copy of a live database, including what's still in its write-ahead log."""
    target.parent.mkdir(parents=True, exist_ok=True)
    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    dst = sqlite3.connect(target)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()


def _walk(source: Path):
    """(path, immutable) for each file to back up below source, leaving out .no-backup folders."""
    def visit(folder: Path, immutable: bool):
        if (folder / ".no-backup").exists():
            return
        immutable = immutable or (folder / ".immutable").exists()
        for path in sorted(folder.iterdir()):
            if path.is_symlink():
                continue
            if path.is_dir():
                yield from visit(path, immutable)
            elif path.is_file():
                yield path, immutable
    yield from visit(source, False)


def _copy_tree(source: Path, target: Path, previous: Path | None = None, work: Path | None = None,
               known: dict[str, str] | None = None, linked: dict[str, str] | None = None) -> None:
    """Copy source to target. Files in an .immutable folder come as hard links from `previous` (the last
    backup) when it has them at the same path and size; their hashes go to `linked`, from `known`."""
    for path, immutable in _walk(source):
        if path.name in NEVER or path.name.endswith(SKIP_SUFFIXES):
            continue
        dest = target / path.relative_to(source)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if immutable and previous is not None and work is not None:
            rel = str(dest.relative_to(work))
            old = previous / rel
            try:
                if rel in (known or {}) and old.stat().st_size == path.stat().st_size:
                    os.link(old, dest)
                    if linked is not None:
                        linked[rel] = known[rel]
                    continue
            except OSError:  # gone, another file system: copy it
                pass
        if _is_sqlite(path):
            _copy_sqlite(path, dest)
        else:
            shutil.copy2(path, dest)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def make_backup(data_dir: Path, config_path: Path | None, dest_root: Path, keep: int = 14,
                extra_paths: list[str] | None = None) -> Path:
    data_dir, dest_root = Path(data_dir), Path(dest_root)
    if not (data_dir / "doorman.db").exists():
        raise BackupError(f"no doorman.db in {data_dir}")
    dest_root.mkdir(parents=True, exist_ok=True)
    name = f"doorman-{clock.now().strftime('%Y%m%d-%H%M%S')}"
    final = dest_root / name
    if final.exists():
        raise BackupError(f"{final} exists already")
    work = dest_root / f"{name}.partial"
    shutil.rmtree(work, ignore_errors=True)
    earlier = list_backups(dest_root)
    previous = earlier[-1] if earlier else None
    try:
        known = json.loads((previous / "manifest.json").read_text())["files"] if previous else {}
    except (OSError, ValueError, KeyError):
        previous, known = None, {}
    linked: dict[str, str] = {}
    try:
        _copy_sqlite(data_dir / "doorman.db", work / "data" / "doorman.db")
        if (data_dir / "vault.enc").exists():
            shutil.copy2(data_dir / "vault.enc", work / "data" / "vault.enc")
        if (data_dir / "plugins").is_dir():
            _copy_tree(data_dir / "plugins", work / "data" / "plugins", previous, work, known, linked)
        if config_path and Path(config_path).exists():
            shutil.copy2(config_path, work / "doorman.yaml")
        for extra in extra_paths or []:
            source = Path(extra)
            if not source.exists():
                raise BackupError(f"backup.extra_paths: {source} doesn't exist")
            target = work / "extra" / source.name
            if source.is_dir():
                _copy_tree(source, target)
            elif _is_sqlite(source):
                _copy_sqlite(source, target)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        # a hard-linked file is the previous backup's, whose hash that manifest has
        files = {rel: linked.get(rel) or _sha256(work / rel)
                 for rel in (str(p.relative_to(work)) for p in sorted(work.rglob("*")) if p.is_file())}
        if any(Path(f).name in NEVER for f in files):
            raise BackupError("the vault key ended up in the backup; aborting")
        (work / "manifest.json").write_text(json.dumps(
            {"created": clock.iso(), "version": __version__, "extra": [Path(e).name for e in extra_paths or []],
             "extra_paths": {Path(e).name: str(Path(e).resolve()) for e in extra_paths or []},
             "files": files}, indent=1))
        work.rename(final)
    except BaseException:
        shutil.rmtree(work, ignore_errors=True)
        raise
    prune(dest_root, keep)
    return final


def list_backups(dest_root: Path) -> list[Path]:
    return sorted(p for p in Path(dest_root).glob("doorman-*") if p.is_dir() and not p.name.endswith(".partial"))


def prune(dest_root: Path, keep: int) -> list[Path]:
    backups = list_backups(dest_root)
    gone = backups[:-keep] if keep > 0 else []
    for path in gone:
        shutil.rmtree(path)
    return gone


def verify(backup: Path) -> dict:
    backup = Path(backup)
    try:
        manifest = json.loads((backup / "manifest.json").read_text())
    except (OSError, ValueError) as exc:
        raise BackupError(f"{backup} has no readable manifest.json: {exc}") from None
    for rel, digest in manifest["files"].items():
        path = backup / rel
        if not path.is_file() or _sha256(path) != digest:
            raise BackupError(f"{rel} is missing or changed since the backup was made")
    return manifest


def _put_back(source: Path, dest: Path) -> None:
    """Copy one file into place. A restored SQLite file must not meet the old one's WAL or journal,
    which SQLite would otherwise replay over it."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if _is_sqlite(source):
        for suffix in ("-wal", "-shm", "-journal"):
            dest.with_name(dest.name + suffix).unlink(missing_ok=True)
    shutil.copy2(source, dest)


def clear_derived(root: Path) -> list[Path]:
    """Deletes every .no-backup folder below root: what was built from data the restore is about to replace
    (the search index and its vectors, a course download) would point at items that aren't there, or miss
    ones that are. Gone, it is rebuilt from the restored data, as after any lost index."""
    cleared = []
    if not root.is_dir():
        return cleared
    for folder, dirs, files in os.walk(root):  # doesn't follow links: a planted one can't send rmtree elsewhere
        if ".no-backup" in files:
            shutil.rmtree(folder)
            cleared.append(Path(folder))
            dirs.clear()
    return cleared


def restore(backup: Path, data_dir: Path, config_path: Path | None = None, force: bool = False,
            extra_paths: list[str] | None = None) -> dict:
    """Put a backup back. Doorman must be stopped. The vault key isn't in the backup: it comes from
    DOORMAN_VAULT_KEY or the vault.key you kept elsewhere. Derived folders (.no-backup) are deleted first.

    Extras (backup.extra_paths, e.g. the WhatsApp session) go back where they were backed up from, or to
    the path in `extra_paths` with the same last component when the layout changed."""
    backup, data_dir = Path(backup), Path(data_dir)
    manifest = verify(backup)
    if (data_dir / "doorman.db").exists() and not force:
        raise BackupError(f"{data_dir} already has a doorman.db; stop Doorman and pass --force to replace it")
    targets = dict(manifest.get("extra_paths") or {})
    targets.update({Path(e).name: str(Path(e)) for e in extra_paths or []})
    extras = sorted(p for p in (backup / "extra").iterdir()) if (backup / "extra").is_dir() else []
    missing = [p.name for p in extras if p.name not in targets]
    if missing:
        raise BackupError(f"don't know where to put back {', '.join(missing)}: set backup.extra_paths")
    for extra in extras:
        dest = Path(targets[extra.name])
        if dest.exists() and not force:
            raise BackupError(f"{dest} exists; stop what uses it and pass --force to replace it")
    data_dir.mkdir(parents=True, exist_ok=True)
    clear_derived(data_dir / "plugins")
    clear_derived(data_dir / "search")  # Doorman's search index: the plugins feed it again from the start
    for path in sorted((backup / "data").rglob("*")):
        if path.is_file():
            _put_back(path, data_dir / path.relative_to(backup / "data"))
    for extra in extras:
        dest = Path(targets[extra.name])
        if extra.is_dir():
            if dest.exists():
                shutil.rmtree(dest) if dest.is_dir() else dest.unlink()
            for path in sorted(extra.rglob("*")):
                if path.is_file():
                    _put_back(path, dest / path.relative_to(extra))
        else:
            _put_back(extra, dest)
    if config_path and (backup / "doorman.yaml").exists():
        shutil.copy2(backup / "doorman.yaml", config_path)
    return manifest
