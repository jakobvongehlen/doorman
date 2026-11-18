"""What's new across mail and chats in one list (`doorman recent`, /v1/read/recent).

Doorman asks every plugin whose manifest names a recent read (`recent: recent`) for what came in since a
moment, in parallel, and merges the answers into one list, newest first, as the agenda merges calendars. A
mailbox gives its newest messages, a chat service each chat's newest message. Each part is an ordinary read
of that plugin: the session's plugin list, switched-off plugins and reads, the actor rule, cleaning, the
injection guard, placeholders and the read log apply as if the agent had asked it directly. A source that
fails or is refused is reported under `sources` and leaves the rest standing.

Only what the sources have: no ranking, no "important" flag."""

from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

from . import crossread
from .agenda import instant, local
from .plugin_api import Denied

RECENT_SCHEMA = {
    "type": "object",
    "properties": {
        "since": {"type": "string", "minLength": 10, "maxLength": 40,
                  "description": "ISO date or date-time: what came in from then on"},
        "sources": {"type": "array", "items": {"type": "string"}, "description": "only these plugins"},
        "limit": {"type": "integer", "minimum": 1, "maximum": 50,
                  "description": "at most this many items per source (default 20)"},
    },
    "required": ["since"],
    "additionalProperties": False,
}
EARLIEST = datetime.min.replace(tzinfo=timezone.utc)


def _who(value: Any) -> str | None:
    """A sender as one string: a mailbox's list of addresses is joined."""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value if v) or None
    return str(value) if value else None


def item(source: str, row: dict, zone: ZoneInfo = ZoneInfo("UTC")) -> dict:
    """One row in the merged shape, whichever plugin it came from: when (`sent`, in the owner's zone with its
    offset), where (`plugin`, and the chat or folder in `in`), who (`from`, `mine` when the owner wrote it),
    `text` (a chat message's start, a mail's subject), `ref` (doorman meta, doorman ask), and what the
    plugin's own reads take for the whole thing: `chat_id` (a chat's messages) or `id` (one mail).

    A mail row is shaped like a `mail.search` row as well, so one jq expression reads both: `subject`, and
    `from` as the list of addresses (a chat row's `from` is the sender's name). It also has `snippet` (its
    text's start), `attachments` (names) and `bulk` (a mailing list or newsletter) when its plugin gives
    them."""
    mail = "subject" in row and "text" not in row
    out = {"sent": local(row.get("sent") or row.get("date"), zone), "plugin": source,
           "in": row.get("chat") or row.get("folder"),
           "from": _addresses(row.get("from")) if mail else _who(row.get("from")),
           "text": row.get("subject") if mail else row.get("text")}
    if mail:
        out["subject"] = row.get("subject")
    for flag in ("mine", "unread", "bulk"):
        if row.get(flag):
            out[flag] = True
    for key in ("ref", "chat_id", "id", "snippet"):
        if row.get(key):
            out[key] = row[key]
    if isinstance(row.get("attachments"), list):  # a mail's attachment names, [] for none
        out["attachments"] = row["attachments"]
    return out


def _addresses(value: Any) -> list[str]:
    """A mail's senders as mail.search gives them: a list (a plugin that joined them is split again)."""
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return [part.strip() for part in str(value).split(",") if part.strip()] if value else []


def run(engine, session: dict, key: dict, params: dict) -> dict:
    engine._guard(session, None, write=False)
    engine._validate(RECENT_SCHEMA, params, "parameters")
    zone = ZoneInfo(engine.config.get("timezone") or "UTC")
    since = instant(params["since"], zone)
    if since.year == 9999:  # agenda.instant's answer for something that isn't a date
        raise Denied(f"since={params['since']} isn't an ISO date or date-time (2026-11-01, 2026-11-01T08:00Z)",
                     "invalid")
    found = crossread.chosen(crossread.sources(engine, "recent"), params.get("sources"),
                             "no source here named {}; doorman caps lists them under recent")
    # the sources get the moment as UTC, so each compares it its own way without knowing Doorman's zone
    sub = {"since": since.strftime("%Y-%m-%dT%H:%M:%SZ"), "limit": params.get("limit", 20)}
    items, held, report = [], [], {}
    for source, data, problem in crossread.fan_out(engine, session, key, [(s, sub) for s in found]):
        if problem:
            report[source["name"]] = problem
            continue
        rows = [r for r in (data if isinstance(data, list) else []) if isinstance(r, dict)]
        kept = 0
        for row in rows:
            if row.get("quarantined"):  # held back by the guard
                held.append({"plugin": source["name"], **row})
                continue
            entry = item(source["name"], row, zone)
            moment = instant(entry["sent"], zone)
            if moment.year == 9999:
                moment = EARLIEST
            if moment < since:  # a source may filter by day only (IMAP SINCE)
                continue
            items.append((moment, entry))
            kept += 1
        report[source["name"]] = {"count": kept}
    items.sort(key=lambda pair: pair[0], reverse=True)
    out = {"items": [entry for _, entry in items], "sources": report, "since": sub["since"]}
    if held:
        out["held_back"] = held
    return out
