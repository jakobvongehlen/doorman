"""What the worker does so that nobody has to remember it: the nightly backup, copied off the host, and a
dead-man ping that lets an outside service alert the owner when Doorman stops.

Both run from server._worker as background jobs, so neither holds up the tick. A Doorman that is down
can't push that it is down; the ping can only stop, and the service it goes to (healthchecks.io or the
like) mails the owner when it does.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from zoneinfo import ZoneInfo

import httpx

from . import backup, clock
from .util import dumps, loads

log = logging.getLogger("doorman.upkeep")

STATE = "backup_state"   # settings key: the last backup run, scheduled or by hand (JSON)
SCHEDULED_WARN_HOURS = 36  # a nightly backup missed once is fine; missed twice, the owner hears of it
PING_EVERY = 300           # seconds between dead-man pings
PING_TIMEOUT = 10          # seconds; the ping runs beside the tick, never in it


def settings(engine) -> dict:
    return dict(engine.config.get("backup") or {})


def scheduled(engine) -> bool:
    """The worker makes backups once there is somewhere to put them and a time of day for it."""
    s = settings(engine)
    return bool(s.get("dir") and s.get("schedule"))


def schedule_label(engine) -> str:
    """backup.schedule as the owner reads it (03:30), or as written when it isn't a time."""
    try:
        return backup.schedule_time(settings(engine).get("schedule"))
    except backup.BackupError:
        return str(settings(engine).get("schedule"))


def last_run(engine) -> dict | None:
    return loads(engine.db.get_setting(STATE) or "null")


def next_backup(engine) -> datetime | None:
    """When the worker makes the next backup: the schedule's next time after the last run. A Doorman that
    never made one counts from its first start, so after an upgrade the first backup comes right away."""
    if not scheduled(engine):
        return None
    run = last_run(engine) or {}
    since = run.get("started") or engine.db.get_setting("last_backup") or engine.db.get_setting("first_start")
    zone = ZoneInfo(engine.config.get("timezone") or "UTC")
    return backup.next_run(settings(engine)["schedule"], zone, clock.parse(since) if since else clock.now())


def due(engine) -> bool:
    try:
        at = next_backup(engine)
    except backup.BackupError as exc:
        engine.attention("backup_schedule", "schedule", "Backups don't run on their own", str(exc),
                         url=f"{engine.public_url}/app/#/status")
        return False
    engine.resolve_attention("backup_schedule", "schedule")
    return at is not None and at <= clock.now()


def _save(engine, state: dict) -> None:
    engine.db.set_setting(STATE, dumps(state))


def run_backup(engine, dest: str | Path | None = None, keep: int | None = None,
               config_path: Path | None = None) -> dict:
    """One backup into backup.dir (or dest), then backup.copy_command when set. Each failure goes to Needs
    attention; a later success clears it. Returns the run as kept in the settings (last_run)."""
    s = settings(engine)
    dest = dest or s.get("dir")
    if not dest:
        raise backup.BackupError("where to? pass a directory or set backup.dir in doorman.yaml")
    keep = keep if keep is not None else int(s.get("keep", 14))
    status_url = f"{engine.public_url}/app/#/status"
    state = {"started": clock.iso(), "finished": None, "ok": False, "path": None, "error": None, "copy": None}
    _save(engine, state)  # a run that dies half-way still counts, so the worker doesn't start it again at once
    try:
        path = backup.make_backup(engine.config.data_dir, config_path or engine.config.path, Path(dest),
                                  keep=keep, extra_paths=s.get("extra_paths") or [])
    except Exception as exc:  # noqa: BLE001 - every failure is reported to the owner
        log.warning("backup failed: %s", exc)
        state.update(finished=clock.iso(), error=str(exc)[:500])
        _save(engine, state)
        engine.attention("backup_failed", clock.now().strftime("%Y-%m-%d"), "The backup failed", str(exc),
                         url=status_url)
        return state
    engine.db.set_setting("last_backup", clock.iso())
    for item in engine.attention_list():
        if item["kind"] == "backup_failed":
            engine.resolve_attention("backup_failed", item["ref"])
    state.update(ok=True, path=str(path))
    command = s.get("copy_command")
    if command:
        try:
            backup.copy_off_host(path, command, 60 * float(s.get("copy_timeout_minutes") or 120),
                                 s.get("copy_env") or [])
            state["copy"] = {"ok": True, "error": None}
            engine.resolve_attention("backup_copy", "copy")
        except backup.BackupError as exc:
            log.warning("copying the backup off the host failed: %s", exc)
            state["copy"] = {"ok": False, "error": str(exc)[:500]}
            engine.attention("backup_copy", "copy", "The backup wasn't copied off the host",
                             f"{exc}. The backup itself is in {path}.", url=status_url)
    state["finished"] = clock.iso()
    _save(engine, state)
    return state


def warn_hours(engine) -> float:
    """How old the last good backup may get before Needs attention lists it (0: never)."""
    if scheduled(engine):
        return SCHEDULED_WARN_HOURS
    return 24 * float(engine.config.get("backup_warn_days", 7))


def check_backup(engine, now: datetime) -> bool:
    """For check_silence: lists a backup that is too old, and clears it (and a copy failure whose command
    is gone from the settings) once that's no longer so. True while it is listed."""
    if not settings(engine).get("copy_command"):
        engine.resolve_attention("backup_copy", "copy")
    hours = warn_hours(engine)
    last = engine.db.get_setting("last_backup")
    since = last or engine.db.get_setting("first_start")
    if not (hours and since and clock.parse(since) < now - timedelta(hours=hours)):
        engine.resolve_attention("backup_old", "backup")
        return False
    span = f"{int(hours // 24)} days" if hours % 24 == 0 else f"{hours:g} hours"
    if scheduled(engine):
        detail = (f"The last backup was on {last[:10]}. " if last else "") + \
                 f"The nightly backup at {schedule_label(engine)} didn't work; doorman-admin backup status says why."
    else:
        detail = f"The last backup was on {last[:10]}." if last else \
                 "Set backup.dir in doorman.yaml and the worker makes one every night, or run doorman-admin backup."
    engine.attention("backup_old", "backup", f"No backup for {span}" if last else "No backup yet", detail,
                     url=f"{engine.public_url}/app/#/status")
    return True


def backup_row(engine, last_backup: str | None, problems: dict) -> dict:
    """The backup's line on the status page: the last good one, the last run's result and the next."""
    run = last_run(engine) or {}
    problem = problems.get(("backup_old", "backup")) or problems.get(("backup_copy", "copy")) \
        or next((item for (kind, _), item in problems.items() if kind in ("backup_failed", "backup_schedule")), None)
    try:
        upcoming = next_backup(engine)
    except backup.BackupError:
        upcoming = None
    copy = run.get("copy") if run.get("ok") else None
    failed = bool(run.get("finished")) and (not run.get("ok") or (copy is not None and not copy["ok"]))
    return {"last": last_backup, "problem": problem["title"] if problem else None, "failed": failed,
            "copied": copy["ok"] if copy else None, "offsite": bool(settings(engine).get("copy_command")),
            "next": clock.iso(upcoming) if upcoming else None}


def _fail_url(url: str) -> str:
    """healthchecks.io's convention: the same URL with /fail at the end of its path says "up, but unwell"."""
    parts = urlsplit(url)
    return urlunsplit(parts._replace(path=parts.path.rstrip("/") + "/fail"))


def ping(engine, transport: httpx.BaseTransport | None = None) -> dict | None:
    """One dead-man ping: GET health.ping_url, or ping_url/fail while /health would answer unhealthy.
    Errors are logged and dropped: a missed ping is exactly what the service alerts on."""
    url = (engine.config.get("health") or {}).get("ping_url")
    if not url:
        return None
    ok, _ = engine.health()
    target = url if ok else _fail_url(url)
    try:
        with httpx.Client(transport=transport, timeout=PING_TIMEOUT, follow_redirects=False) as client:
            response = client.get(target)
        return {"at": clock.iso(), "healthy": ok, "status": response.status_code}
    except httpx.HTTPError as exc:
        # the URL holds the check's secret id: say only where it went
        log.warning("dead-man ping to %s failed: %s", urlsplit(url).hostname, type(exc).__name__)
        return {"at": clock.iso(), "healthy": ok, "error": type(exc).__name__}
