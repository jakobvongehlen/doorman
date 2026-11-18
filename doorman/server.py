"""Runs the agent API, the owner API and the background worker in one process."""

import asyncio
import ipaddress
import logging
import time

import uvicorn

from . import upkeep
from .api.agent import create_agent_app
from .api.owner import create_owner_app
from .engine import Engine

log = logging.getLogger("doorman.server")


def _host_port(value: str) -> tuple[str, int]:
    host, _, port = value.rpartition(":")
    return host or "127.0.0.1", int(port)


def forwarded_from(config: dict) -> str:
    """Whose X-Forwarded-For the agent API believes: 127.0.0.1 and `agent_forwarded_from` (single addresses,
    the relay of an agent on a Docker of its own). Anything else that isn't an address is left out."""
    out = ["127.0.0.1"]
    for value in config.get("agent_forwarded_from") or []:
        try:
            address = ipaddress.ip_address(str(value).strip())
        except ValueError:
            log.warning("agent_forwarded_from: %r isn't an address; left out", value)
            continue
        out.append(str(address))
    return ",".join(dict.fromkeys(out))


async def _maintain(engine: Engine, name: str) -> None:
    try:
        await asyncio.to_thread(engine.registry.instance(name).maintenance)
    except Exception:  # noqa: BLE001 - maintenance must not stop the worker
        log.exception("maintenance of %s", name)


def start_maintenance(engine: Engine, every: float, last: dict[str, float],
                      running: dict[str, asyncio.Task]) -> list[str]:
    """Start due maintenance (e.g. rebuilding the files index) as background jobs, at most one per
    plugin, so a long run never holds up the worker's tick: approvals, leases, routines and /health."""
    started = []
    for plugin in engine.registry.list():
        name = plugin["name"]
        if not plugin["enabled"] or name in running or time.monotonic() - last.get(name, -1e9) < every:
            continue
        last[name] = time.monotonic()
        job = asyncio.create_task(_maintain(engine, name))
        running[name] = job
        job.add_done_callback(lambda _, n=name: running.pop(n, None))
        started.append(name)
    return started


async def _job(engine: Engine, name: str, job: dict, last: dict[tuple, float]) -> None:
    budget = float(job.get("budget_seconds", 120))
    try:
        status = await asyncio.to_thread(engine.registry.instance(name).run_job, job["name"], budget)
        # events the run found: into the feed and to the triggers
        status = await asyncio.to_thread(engine.job_events, name, job["name"], status)
        # e.g. files the plugin downloaded: copied into the files archive, which indexes it
        archived = await asyncio.to_thread(engine.copy_to_archive, name, job["name"])
        if archived and archived["copied"]:
            status = {**(status or (engine.job_status(name).get(job["name"]) or {}).get("status") or {}),
                      "archived": archived}
        engine.job_done(name, job["name"], status)
        # what the run brought in (new mail, a downloaded file) goes to the search index now
        await asyncio.to_thread(engine.search.pull, name)
        for target in dict.fromkeys(str(t).split(":", 1)[0] for t in (archived or {}).get("into") or []
                                    if archived["copied"]):
            await asyncio.to_thread(engine.search.pull, target)
        if isinstance(status, dict) and status.get("more"):
            # more to do (a first download): again in half a minute, not in every_minutes
            last[(name, job["name"])] = time.monotonic() - 60 * float(job.get("every_minutes", 5)) + 30
    except Exception as exc:  # noqa: BLE001 - a job must not stop the worker
        log.warning("job %s.%s failed: %s", name, job["name"], exc)
        engine.job_done(name, job["name"], None, str(exc))


def start_jobs(engine: Engine, last: dict[tuple, float], running: dict[tuple, asyncio.Task]) -> list[str]:
    """Background jobs plugins declare (`jobs:` in the manifest, e.g. a mail archive's sync), each every
    every_minutes, one run at a time per job, each run a slice of budget_seconds."""
    started = []
    for plugin in engine.registry.list():
        if not plugin["enabled"]:
            continue
        for job in plugin.get("jobs") or []:
            off = job.get("off_when") or {}
            if any(str((plugin.get("config") or {}).get(k, "")).lower() == str(v).lower() for k, v in off.items()):
                continue  # e.g. archive: off
            key = (plugin["name"], job["name"])
            every = 60 * float(job.get("every_minutes", 5))
            if key in running or time.monotonic() - last.get(key, -1e9) < every:
                continue
            last[key] = time.monotonic()
            task = asyncio.create_task(_job(engine, plugin["name"], job, last))
            running[key] = task
            task.add_done_callback(lambda _, k=key: running.pop(k, None))
            started.append(f"{key[0]}.{key[1]}")
    return started


def library_round(engine: Engine, last: dict[str, float]) -> dict:
    """One round of the search index's upkeep: each indexed plugin whose feed is due is asked for what
    changed, then stems and vectors for what came in, for the rest of the round's budget."""
    started = time.monotonic()
    if "_checked" not in last:  # once after start: a full look at the index files (damage is made anew)
        last["_checked"] = started
        engine.library.check()
    engine.search.tidy()
    pulled = {}
    for name in engine.search.due(started, last):
        last[name] = time.monotonic()
        pulled[name] = engine.search.pull(name, 60)
    budget = float((engine.config.get("search_index") or {}).get("upkeep_seconds", 100))
    status = engine.library.run(started + budget)
    return {"pulled": pulled, **status}


def start_library(engine: Engine, last: dict[str, float], running: dict[str, asyncio.Task]) -> bool:
    """The search index's round (library_round) every upkeep_minutes, one at a time, in the background; again
    in half a minute while there's more to embed."""
    every = 60 * float((engine.config.get("search_index") or {}).get("upkeep_minutes", 2))
    if "library" in running or time.monotonic() - last.get("_round", -1e9) < every:
        return False
    last["_round"] = time.monotonic()

    def round_():
        status = library_round(engine, last)
        if status.get("more"):
            last["_round"] = time.monotonic() - every + 30
    _in_background(running, "library", round_)
    return True


def _in_background(running: dict, key: str, fn, *args) -> asyncio.Task:
    """fn(*args) in a thread as a background job, at most one per key; errors are logged, never raised."""
    async def run():
        try:
            await asyncio.to_thread(fn, *args)
        except Exception:  # noqa: BLE001 - must not stop the worker
            log.exception("%s", key)
    task = asyncio.create_task(run())
    running[key] = task
    task.add_done_callback(lambda _: running.pop(key, None))
    return task


def start_backup(engine: Engine, last: dict[str, float], running: dict[str, asyncio.Task]) -> bool:
    """The nightly backup (backup.schedule), as a background job: it can take minutes. Whether it's due is
    looked at once a minute."""
    if "backup" in running or time.monotonic() - last.get("backup", -1e9) < 60:
        return False
    last["backup"] = time.monotonic()
    if not upkeep.due(engine):
        return False
    _in_background(running, "backup", upkeep.run_backup, engine)
    return True


def start_ping(engine: Engine, last: dict[str, float], running: dict[str, asyncio.Task]) -> bool:
    """The dead-man ping (health.ping_url) every PING_EVERY seconds, beside the tick: a slow ping service
    holds up nothing, and a stuck tick stops the pings, which is what the service alerts on."""
    if not (engine.config.get("health") or {}).get("ping_url") or "ping" in running \
            or time.monotonic() - last.get("ping", -1e9) < upkeep.PING_EVERY:
        return False
    last["ping"] = time.monotonic()
    _in_background(running, "ping", upkeep.ping, engine)
    return True


async def _worker(engine: Engine, interval: float) -> None:
    maintenance_every = 60 * float(engine.config.get("maintenance_interval_minutes", 60))
    last_maintenance: dict[str, float] = {}
    running: dict[str, asyncio.Task] = {}
    last_job: dict[tuple, float] = {}
    jobs: dict[tuple, asyncio.Task] = {}
    upkeep_running: dict[str, asyncio.Task] = {}
    last_upkeep: dict[str, float] = {}
    last_library: dict[str, float] = {}
    while True:
        await asyncio.to_thread(engine.tick)
        start_maintenance(engine, maintenance_every, last_maintenance, running)
        start_jobs(engine, last_job, jobs)
        start_library(engine, last_library, upkeep_running)
        start_backup(engine, last_upkeep, upkeep_running)
        start_ping(engine, last_upkeep, upkeep_running)
        await asyncio.sleep(interval)


async def serve(engine: Engine) -> None:
    recovered = engine.recover_interrupted()
    if recovered["sends"] or recovered["writes"] or recovered["approved"]:
        log.warning("cut off by the last stop: sends %s (now 'unknown'), writes %s (now failed), approved "
                    "but not started %s (the worker sends them)", recovered["sends"], recovered["writes"],
                    recovered["approved"])
    servers = []
    for app, listen, forwarded in ((create_agent_app(engine), engine.config["agent_listen"],
                                    forwarded_from(engine.config)),
                                   (create_owner_app(engine), engine.config["owner_listen"], "127.0.0.1")):
        host, port = _host_port(listen)
        servers.append(uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="info",
                                                     proxy_headers=True, forwarded_allow_ips=forwarded)))
    worker = asyncio.create_task(_worker(engine, float(engine.config["worker_interval_seconds"])))
    log.info("agent API on %s, owner app on %s", engine.config["agent_listen"], engine.config["owner_listen"])
    try:
        await asyncio.gather(*(server.serve() for server in servers))
    finally:
        worker.cancel()
        from .plugin_host import stop_all

        await asyncio.to_thread(stop_all)  # each plugin's process gets a friendly exit
        await asyncio.to_thread(engine.guard.stop)
        await asyncio.to_thread(engine.extractor.stop)
