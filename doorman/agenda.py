"""One agenda over every calendar (`doorman agenda`, /v1/read/agenda).

Doorman asks every plugin whose manifest names an agenda read (`agenda: events`) for the same time range,
in parallel, and merges the answers into one list sorted by start. Each part is an ordinary read of that
plugin, as with the common search: the session's plugin list, switched-off plugins and reads, the actor rule,
cleaning, the injection guard, placeholders and the read log apply as if the agent had asked it directly. A
source that fails or is refused is reported under `sources` and leaves the rest standing.

Only the entries, as the calendars have them: no free slots or other computed answers. Two things are
normalised so every calendar reads alike: an `end` that is a date includes that whole day (`--to 2026-11-09`
has the 9th), and every time comes in the owner's zone with its offset (a feed's floating times too)."""

from datetime import date, datetime, time, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from . import crossread
from .plugin_api import Denied

AGENDA_SCHEMA = {
    "type": "object",
    "properties": {
        "start": {"type": "string", "minLength": 10, "maxLength": 40, "description": "ISO date or date-time"},
        "end": {"type": "string", "minLength": 10, "maxLength": 40,
                "description": "ISO date (that day included) or date-time (up to that moment)"},
        "sources": {"type": "array", "items": {"type": "string"}, "description": "only these calendars (plugin names)"},
        "invitations": {"type": "boolean",
                        "description": "only invitations the owner hasn't answered yet (response needs-action)"},
    },
    "required": ["start", "end"],
    "additionalProperties": False,
}
LATEST = datetime.max.replace(tzinfo=timezone.utc)


def instant(value: Any, zone: ZoneInfo) -> datetime:
    """When an entry starts, for sorting: a date is midnight in Doorman's zone, a time without an offset too."""
    if not isinstance(value, str) or not value:
        return LATEST
    try:
        if len(value) == 10:
            return datetime.combine(date.fromisoformat(value), time(), zone).astimezone(timezone.utc)
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return LATEST
    return (moment if moment.tzinfo else moment.replace(tzinfo=zone)).astimezone(timezone.utc)


def local(value: Any, zone: ZoneInfo) -> Any:
    """A date-time in the owner's zone with its offset ("2026-11-09T10:00:00+01:00"), whatever zone the calendar
    gave it in; one without an offset (a feed's floating time) is taken to be in the owner's zone. A date, or
    anything that isn't a time, stays as it is."""
    if not isinstance(value, str) or len(value) <= 10:
        return value
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    return (moment if moment.tzinfo else moment.replace(tzinfo=zone)).astimezone(zone).isoformat()


def bounds(params: dict, zone: ZoneInfo) -> tuple[str, str]:
    """The range as every calendar gets it: a date becomes midnight in the owner's zone, and an end date
    includes its day (midnight after it), so calendars that read an end date differently agree."""
    def moment(value: str, day_after: bool) -> str:
        value = value.strip()
        if len(value) != 10:
            return value
        try:
            day = date.fromisoformat(value) + timedelta(days=1 if day_after else 0)
        except ValueError:
            raise Denied(f"{value} isn't an ISO date (2026-11-09) or date-time", "invalid") from None
        return datetime.combine(day, time(), zone).isoformat()
    return moment(params["start"], False), moment(params["end"], True)


def entry(source: str, item: dict, zone: ZoneInfo = ZoneInfo("UTC")) -> dict:
    """One calendar entry in the agenda's shape, whichever plugin it came from. `ref`, and `id` or `uid` as the
    plugin's own tools name it (update_event id=... or uid=...), lead back to the plugin; a feed's entries have
    none of them, as a feed can't be changed. An invitation also has `organizer` and `response` (the owner's
    answer: needs-action until they answer)."""
    out = {"start": local(item.get("start"), zone), "end": local(item.get("end"), zone),
           "all_day": bool(item.get("all_day")),
           "title": item.get("summary") if "summary" in item else item.get("title"),
           "location": item.get("location") or "", "calendar": item.get("calendar") or item.get("feed") or source,
           "plugin": source}
    for key in ("ref", "id", "uid"):
        if item.get(key):
            out[key] = item[key]
    for key in ("attendees", "organizer", "response"):
        if item.get(key):
            out[key] = item[key]
    for flag in ("cancelled", "stale", "recurring"):
        if item.get(flag):
            out[flag] = True
    if item.get("recurring_event_id"):
        out["recurring"] = True
    return out


def run(engine, session: dict, key: dict, params: dict) -> dict:
    engine._guard(session, None, write=False)
    engine._validate(AGENDA_SCHEMA, params, "parameters")
    zone = ZoneInfo(engine.config.get("timezone") or "UTC")
    found = crossread.chosen(crossread.sources(engine, "agenda"), params.get("sources"),
                             "no calendar here named {}; doorman caps lists them under agenda")
    start, end = bounds(params, zone)
    sub = {"start": start, "end": end}
    entries, held, report = [], [], {}
    for source, data, problem in crossread.fan_out(engine, session, key, [(s, sub) for s in found]):
        if problem:
            report[source["name"]] = problem
            continue
        items = [i for i in (data if isinstance(data, list) else []) if isinstance(i, dict)]
        kept = 0
        for item in items:
            if item.get("quarantined"):  # held back by the guard: no times to sort by; it counts, as it's there
                held.append({"plugin": source["name"], **item})
                kept += 1
            elif not params.get("invitations") or (item.get("response") == "needs-action"
                                                   and not item.get("cancelled")):
                entries.append(entry(source["name"], item, zone))
                kept += 1
        report[source["name"]] = {"count": kept}
    entries.sort(key=lambda e: (instant(e["start"], zone), not e["all_day"], str(e["title"] or "")))
    out = {"entries": entries, "sources": report, "timezone": str(zone)}
    if held:
        out["held_back"] = held
    return out
