"""What the calendar plugins (caldav, google_calendar, ics) hand to Doorman's search index (library.py).

Each plugin feeds every entry of a window, from `search_past_months` (config, default 24) back to 12 months
ahead, so "when did I last see the dentist" and "the seminar next month" are both found; the whole window
every time (`complete`), so an entry deleted or moved out of the window leaves search at the next feed.

One item per event series, not per occurrence: a weekly lecture is one hit, not a hundred. The plugin
expands the occurrences in the window (its events read does the same) and passes them here as plain dicts,
each with the item `key` of its series; `event_items` groups them. The item's date is the series' next
occurrence from now (or the one under way), else its latest past one; its fields carry that occurrence's
start and end, whether it recurs, and how many occurrences fall in the window.

An occurrence: {"key", "ref", "uid"?, "summary", "start", "end"?, "all_day", "location"?, "description"?,
"attendees"?: [address], "organizer"?: address, "organizer_name"?, "calendar": what the owner calls it,
"recurring"?: the plugin knows it belongs to a series, "extra"?: {field: value} for the hit (status...)}.

A feed that runs out of its budget doesn't block: it hands over what it has read so far without
`complete` (so nothing is removed on a partial look) and begins with the calendar it didn't reach next
time (`rotated`)."""

from __future__ import annotations

import calendar
import json
from datetime import date, datetime, time, timezone, tzinfo
from typing import Iterable

from . import clock

PAST_MONTHS = 24          # default of the plugins' search_past_months
AHEAD_MONTHS = 12
MAX_PAST_MONTHS = 240
EARLIEST = datetime.min.replace(tzinfo=timezone.utc)


def months_from(moment: datetime, months: int) -> datetime:
    """`moment` moved by whole months (back for a negative number); a day the month lacks becomes its last
    (31 March less a month: 28 or 29 February)."""
    total = moment.year * 12 + moment.month - 1 + months
    year, month = divmod(total, 12)
    return moment.replace(year=year, month=month + 1, day=min(moment.day, calendar.monthrange(year, month + 1)[1]))


def window(config: dict, now: datetime | None = None) -> tuple[datetime, datetime]:
    """(start, end) of what a calendar feeds: search_past_months back (a bad value: the default), 12 months
    ahead."""
    try:
        past = int(config.get("search_past_months", PAST_MONTHS))
    except (TypeError, ValueError):
        past = PAST_MONTHS
    now = now or clock.now()
    return months_from(now, -min(max(past, 0), MAX_PAST_MONTHS)), months_from(now, AHEAD_MONTHS)


def moment(value: str | None, zone: tzinfo | None = None) -> datetime | None:
    """An ISO date or date-time as an aware datetime: a date is its midnight, a time without an offset is in
    `zone` (UTC without one). None for nothing or something else."""
    if not value:
        return None
    try:
        if len(value) == 10:
            return datetime.combine(date.fromisoformat(value), time(), zone or timezone.utc)
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=zone or timezone.utc)


def rotated(names: list[str], cursor: str | None) -> list[str]:
    """The calendars to read, beginning with the one a partial feed didn't reach (the cursor's `first`)."""
    try:
        first = (json.loads(cursor) or {}).get("first") if cursor else None
    except (ValueError, AttributeError):
        first = None
    if first not in names:
        return list(names)
    at = names.index(first)
    return names[at:] + names[:at]


def answer(items: list[dict], stopped_at: str | None = None) -> dict:
    """A feed's answer: everything (`complete`), or, when the budget ran out before calendar `stopped_at`, what
    was read so far, with nothing removed and that calendar first next time."""
    if stopped_at is None:
        return {"items": items, "complete": True, "cursor": None}
    return {"items": items, "more": True, "cursor": json.dumps({"first": stopped_at})}


def event_items(occurrences: Iterable[dict], zone: tzinfo | None = None, now: datetime | None = None) -> list[dict]:
    """One search index item per series (the occurrences' `key`)."""
    now = now or clock.now()
    series: dict[str, list[dict]] = {}
    for occurrence in occurrences:
        series.setdefault(occurrence["key"], []).append(occurrence)
    return [_item(group, zone, now) for group in series.values()]


def _item(group: list[dict], zone: tzinfo | None, now: datetime) -> dict:
    def start(o: dict) -> datetime:
        return moment(o.get("start"), zone) or EARLIEST

    group.sort(key=start)
    ahead = [o for o in group if (moment(o.get("end"), zone) or start(o)) > now]  # to come, or under way
    shown = ahead[0] if ahead else group[-1]
    recurring = len(group) > 1 or any(o.get("recurring") for o in group)
    organizer, name = shown.get("organizer"), shown.get("organizer_name")
    fields = {"summary": shown.get("summary") or "", "start": shown.get("start"), "end": shown.get("end"),
              "all_day": bool(shown.get("all_day")), "location": shown.get("location"),
              "calendar": shown.get("calendar"), "organizer": organizer, "recurring": recurring}
    if recurring:
        fields["occurrences"] = len(group)
    fields.update(shown.get("extra") or {})
    text = "\n".join(part for part in (shown.get("description"), shown.get("location"),
                                       ", ".join(shown.get("attendees") or [])) if part)
    item = {"key": shown["key"], "ref": shown["ref"], "kind": "event", "title": shown.get("summary") or "",
            "date": shown.get("start"), "in": shown.get("calendar"),
            "from": f"{name} <{organizer}>" if name and organizer else organizer, "text": text,
            # a hit is kept short: what's empty stays out
            "fields": {k: v for k, v in fields.items() if v not in (None, "")}}
    if shown.get("uid"):
        item["same"] = f"uid:{shown['uid']}"  # the same event in two calendars (or two plugins) comes once
    return item
