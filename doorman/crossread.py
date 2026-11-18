"""What Doorman's reads across plugins share: `doorman agenda` and `doorman recent`, and the owner app's
contact list for "Trust a contact" (`contacts: search`, asked through for_owner below). (`doorman search`
doesn't ask plugins: it searches the index they feed, library.py.)

Each finds the plugins whose manifest names one of their reads for it (`agenda: events`, `recent: recent`),
asks them in parallel, and merges the answers its own way. Each part is
an ordinary read of that plugin (engine.read), so switches, the actor rule, cleaning, the guard,
placeholders and the read log apply as if the agent had asked that plugin itself. A source that fails or
is refused is reported and leaves the others standing."""

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .plugin_api import Denied


def sources(engine, key: str, role: str | None = None) -> list[dict]:
    """Switched-on plugins whose manifest names a read under `key`, with that read on: {name, read, type,
    raw, params}. With `role` actor and the reader/actor split on, a raw read is left out, as the actor
    couldn't read it (what capabilities list). Without a role every source counts, and an actor asking one
    gets it reported as skipped."""
    out = []
    for plugin in engine.registry.list():
        if not plugin["enabled"]:
            continue
        short = engine.registry.manifest(plugin["name"]).get(key)
        if not short or short in plugin["disabled_tools"]:
            continue
        spec = next((r for r in plugin["reads"] if r["name"] == f"{plugin['name']}.{short}"), None)
        if spec is None or (role == "actor" and engine.config["reader_actor_split"] and spec["raw"]):
            continue
        out.append({"name": plugin["name"], "read": spec["name"], "type": plugin["type"], "raw": spec["raw"],
                    "params": spec.get("params") or {}})
    return out


def chosen(found: list[dict], wanted: list[str] | None, unknown: str) -> list[dict]:
    """The sources the agent named (`sources: [...]`), or all of them. `unknown` says what's wrong with
    names that aren't among them ({} takes the names)."""
    if not wanted:
        return found
    missing = set(wanted) - {s["name"] for s in found}
    if missing:
        raise Denied(unknown.format(", ".join(sorted(missing))), "invalid")
    return [s for s in found if s["name"] in set(wanted)]


def fan_out(engine, session: dict, key: dict, jobs: list[tuple[dict, dict]]) -> list[tuple[dict, Any, dict | None]]:
    """Ask each (source, params) at once, at most four at a time. Returns (source, data, problem) in the
    order given; problem is {"skipped": why} for a refusal (switched off, the actor rule, held back) or
    {"error": ...} for a failure, and data is then None."""
    def one(job):
        source, params = job
        try:
            return source, engine.read(session, key, source["read"], dict(params)), None
        except Denied as exc:
            return source, None, {"skipped": exc.reason}
        except Exception as exc:  # noqa: BLE001 - one source failing leaves the others
            return source, None, {"error": str(exc)[:300]}

    with ThreadPoolExecutor(max_workers=max(1, min(4, len(jobs)))) as pool:
        return list(pool.map(one, jobs))


def for_owner(engine, key: str, params: dict) -> list[tuple[dict, Any, dict | None]]:
    """The same sources for the owner app (the "Trust a contact" list): each read is run directly, without
    the read log, the guard or placeholders, which are there for agents; the owner sees their own data. A
    source that fails is reported as {"error": ...} and leaves the others."""
    out = []
    for source in sources(engine, key):
        try:
            _, plugin, spec = engine.registry.find_read(source["read"])
            engine._validate(spec.get("params"), params, "parameters")
            out.append((source, plugin.run_read(spec["name"], dict(params)), None))
        except Exception as exc:  # noqa: BLE001 - one source failing leaves the others
            out.append((source, None, {"error": str(exc)[:300]}))
    return out
