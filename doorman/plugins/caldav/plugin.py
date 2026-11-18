"""Calendars (VEVENT) and to-do lists (VTODO) over CalDAV, with one login. A collection can hold both
(Nextcloud's "Personal" does), so it may show up as a calendar and as a task list.

Every quiet write is undoable: undo puts back the item's full iCalendar text from the snapshot, or only the
fields the action changed when someone edited the item since. Writes that reach other people are sends and
wait for the owner (calendar_tools has the rules): events with outside guests, someone else's invitation
deleted or answered, and any write, events and tasks alike, to a collection that is shared (see is_shared)."""

import json
import logging
import threading
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from urllib.parse import unquote, urlparse
from zoneinfo import ZoneInfo

import caldav
from caldav.lib.error import NotFoundError
from icalendar import Calendar as ICalendar
from icalendar import Event as IEvent
from icalendar import Todo as ITodo
from icalendar import vCalAddress

from doorman import calendar_feed, clock
from doorman.calendar_tools import ANSWERS, QUIET, SEND, CreateRules, DeleteRules, RespondRules, UpdateRules
from doorman.plugin_api import (BasePlugin, Denied, ExecResult, NotSent, PluginError, Tool, calendar_cursor,
                                soon_minutes, starting_soon)

log = logging.getLogger(__name__)

EVENT_FIELDS = ("summary", "location", "description", "start", "end", "attendees")
TASK_FIELDS = ("summary", "description", "due", "priority", "tags", "done")


def parse_time(value: str, zone=None):
    """ISO date or date-time. Aware times are converted to the configured zone (or UTC), because a
    bare UTC offset can't be written as a TZID and would become floating time; naive ones are in `zone`."""
    value = value.strip()
    if len(value) == 10:
        return date.fromisoformat(value)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=zone) if zone else parsed
    return parsed.astimezone(zone or timezone.utc)


def _iso(prop) -> str | None:
    return prop.dt.isoformat() if prop is not None else None


def _addresses(prop) -> list[str]:
    if prop is None:
        return []
    items = prop if isinstance(prop, list) else [prop]
    return sorted(str(item).lower().replace("mailto:", "", 1) for item in items)


def _tags(component) -> list[str]:
    prop = component.get("categories")
    if prop is None:
        return []
    props = prop if isinstance(prop, list) else [prop]
    return sorted(str(c) for p in props for c in (getattr(p, "cats", None) or []))


def _before(due_iso: str, limit) -> bool:
    due = date.fromisoformat(due_iso) if len(due_iso) == 10 else datetime.fromisoformat(due_iso)
    if isinstance(limit, datetime) and not isinstance(due, datetime):
        return due <= limit.date()
    if isinstance(due, datetime) and not isinstance(limit, datetime):
        return due.date() <= limit
    if isinstance(due, datetime) and isinstance(limit, datetime) and (due.tzinfo is None) != (limit.tzinfo is None):
        return due.replace(tzinfo=None) <= limit.replace(tzinfo=None)
    return due <= limit


def _attendee_props(component) -> list:
    prop = component.get("attendee")
    return [] if prop is None else prop if isinstance(prop, list) else [prop]


def _response(component, me: set[str]) -> str | None:
    """The owner's answer to the event (needs-action, accepted, declined, tentative), None when they aren't
    among its guests."""
    for attendee in _attendee_props(component):
        if str(attendee).lower().replace("mailto:", "", 1) in me:
            return str(attendee.params.get("PARTSTAT", "NEEDS-ACTION")).lower()
    return None


def _name(prop) -> str | None:
    """The CN of an ORGANIZER line: "Dr. Jansen" for an approval that says who is told."""
    prop = prop[0] if isinstance(prop, list) and prop else prop
    return str(prop.params.get("CN") or "") or None if prop is not None and hasattr(prop, "params") else None


def event_state(calendar_name: str, component, ics: str, me: set[str] = frozenset()) -> dict:
    start = component.get("dtstart")
    organizer = component.get("organizer")
    return {
        "uid": str(component.get("uid")),
        "calendar": calendar_name,
        "summary": str(component.get("summary", "")),
        "start": _iso(start),
        "end": _iso(component.get("dtend")),
        "all_day": bool(start is not None and not isinstance(start.dt, datetime)),
        "location": str(component.get("location", "")),
        "description": str(component.get("description", "")),
        "attendees": _addresses(component.get("attendee")),
        "organizer": _addresses(component.get("organizer"))[0] if component.get("organizer") else None,
        "recurring": component.get("rrule") is not None,
        "response": _response(component, me),
        "_organizer_name": _name(organizer),
        "_ics": ics,
    }


def task_state(list_name: str, component, ics: str) -> dict:
    status = str(component.get("status", "NEEDS-ACTION")).upper()
    priority = int(component.get("priority", 0) or 0)
    return {
        "uid": str(component.get("uid")),
        "list": list_name,
        "summary": str(component.get("summary", "")),
        "description": str(component.get("description", "")),
        "due": _iso(component.get("due")),
        "priority": priority or None,
        "tags": _tags(component),
        "done": status == "COMPLETED",
        "completed_at": _iso(component.get("completed")),
        "_ics": ics,
    }


# sharing: what Nextcloud (ownCloud's properties) and CalendarServer-style servers (iCloud, Fastmail) say
OC, NC, CS = "{http://owncloud.org/ns}", "{http://nextcloud.com/ns}", "{http://calendarserver.org/ns/}"
SHARING_QUERY = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.com/ns" '
    'xmlns:cs="http://calendarserver.org/ns/"><d:prop><oc:owner-principal/><nc:owner-principal/><oc:invite/>'
    '<cs:invite/><cs:publish-url/><d:resourcetype/></d:prop></d:propfind>')
NOT_SHARED_ANY_MORE = {"invite-declined", "invite-deleted", "invite-invalid"}


def _local(tag) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _is_me(href: str, principal_path: str, emails: set[str]) -> bool:
    """Whether a principal named in a sharing property is the owner: their address, or their principal URL
    (Nextcloud writes it relative, "principal:principals/users/sam" or "principals/users/sam")."""
    value = unquote(href.strip())
    if value.lower().startswith("mailto:"):
        return value[7:].lower() in emails
    path = urlparse(value.removeprefix("principal:")).path.strip("/")
    if not path or not principal_path:
        return not path  # an empty name says nothing
    return path == principal_path or principal_path.endswith("/" + path) or path.endswith("/" + principal_path)


def sharing_of(tree, principal_path: str, emails: set[str]) -> bool:
    """True when a PROPFIND answer (SHARING_QUERY) shows evidence that others see the collection:
    - its owner is someone else (Nextcloud's owner-principal): shared with the owner;
    - its invite lists someone other than the owner who hasn't declined (Nextcloud's or CalendarServer's):
      the owner shares it, or (an organizer who isn't the owner) it is shared with them;
    - it is published as a public link (publish-url), or the server marks it shared (resourcetype).
    Properties the server doesn't know come back empty or as 404, which is no evidence either way."""
    for element in tree.iter():
        tag = element.tag if isinstance(element.tag, str) else ""
        if tag in (OC + "owner-principal", NC + "owner-principal"):
            if (element.text or "").strip() and not _is_me(element.text, principal_path, emails):
                return True
        elif tag in (OC + "invite", CS + "invite"):
            for person in element:
                if _local(person.tag) not in ("user", "organizer"):
                    continue
                if any(_local(flag.tag) in NOT_SHARED_ANY_MORE for flag in person):
                    continue
                href = person.find("{DAV:}href")
                if href is not None and (href.text or "").strip() and not _is_me(href.text, principal_path, emails):
                    return True
        elif tag == CS + "publish-url":
            if (element.text or "").strip() or any((child.text or "").strip() for child in element):
                return True
        elif tag == "{DAV:}resourcetype":
            if any(child.tag in (CS + "shared", CS + "shared-owner") for child in element):
                return True
    return False


# events


class EventTool(Tool):
    """The send rules (calendar_tools) need calendar_of, existing and invitation_from; the rest is CalDAV's."""

    def current(self, object_ref):
        found = self.plugin.find_event(object_ref)
        return found[2] if found else None

    def undo(self, object_ref, before, after):
        self.plugin.restore_event(object_ref, before)

    def undo_fields(self, object_ref, fields, now):
        """Put back the fields this action changed; what others changed meanwhile stays."""
        found = self.plugin.find_event(object_ref)
        if found is None:
            raise PluginError(f"no event with uid {object_ref}")
        changes = {k: v for k, v in fields.items() if k in EVENT_FIELDS}
        unknown = set(fields) - set(changes) - {"all_day", "response"}  # these follow start, end and attendees
        if unknown:
            raise PluginError(f"can't put back {', '.join(sorted(unknown))}")
        self.plugin.apply_event_changes(found[1], changes)

    def render_diff(self, before, after, args):
        hide = {"uid", "calendar", "recurring", "organizer"}
        strip = (lambda s: {k: v for k, v in s.items() if k not in hide} if s else None)
        return super().render_diff(strip(before), strip(after), args)

    def ref_for(self, args):
        return args["uid"]

    def existing(self, args) -> dict:
        found = self.plugin.find_event(args["uid"])
        if found is None:
            raise PluginError(f"no event with uid {args['uid']}")
        return found[2]

    def calendar_of(self, args) -> str:
        return self.existing(args)["calendar"]

    def shared_note(self, args) -> str:
        """" on shared calendar X" for a summary; nothing when the event is gone (a summary after a delete)."""
        try:
            return self.where(self.calendar_of(args))
        except (PluginError, Denied):
            return ""

    def invitation_from(self, state: dict) -> str | None:
        """The organizer, when the event is someone else's invitation."""
        organizer = state.get("organizer")
        return organizer if organizer and organizer not in self.plugin.owner_emails else None


def default_end(start: str) -> str:
    """No end given: an hour after a time, the next day after a date (all day), written like the start."""
    start = start.strip()
    if len(start) == 10:
        return (date.fromisoformat(start) + timedelta(days=1)).isoformat()
    text = (datetime.fromisoformat(start.replace("Z", "+00:00")) + timedelta(hours=1)).isoformat()
    return text[:-6] + "Z" if start.endswith("Z") else text


class CreateEvent(CreateRules, EventTool):
    def ref_for(self, args):
        return None

    def calendar_of(self, args):
        """None when there is no such calendar: the write then fails in execute and says so."""
        try:
            return self.plugin.calendar_name(args.get("calendar"))
        except PluginError:
            return None

    @staticmethod
    def end(args) -> str:
        return args.get("end") or default_end(args["start"])

    def preview(self, args, before):
        return {"summary": args["summary"], "start": args["start"], "end": self.end(args),
                "location": args.get("location", ""), "description": args.get("description", ""),
                "attendees": sorted(a.lower() for a in args.get("attendees", []))}

    def execute(self, args, before):
        calendar = self.plugin.calendar(args.get("calendar"))
        uid = f"{uuid.uuid4()}@doorman"
        ical = ICalendar()
        ical.add("prodid", "-//doorman//EN")
        ical.add("version", "2.0")
        event = IEvent()
        event.add("uid", uid)
        event.add("dtstamp", datetime.now(timezone.utc))
        event.add("summary", args["summary"])
        event.add("dtstart", parse_time(args["start"], self.plugin.zone))
        event.add("dtend", parse_time(self.end(args), self.plugin.zone))
        for field in ("location", "description"):
            if args.get(field):
                event.add(field, args[field])
        attendees = args.get("attendees", [])
        if attendees and self.plugin.owner_emails:
            event.add("organizer", vCalAddress(f"mailto:{sorted(self.plugin.owner_emails)[0]}"))
        for address in attendees:
            attendee = vCalAddress(f"mailto:{address}")
            attendee.params["ROLE"] = "REQ-PARTICIPANT"
            attendee.params["RSVP"] = "TRUE"
            event.add("attendee", attendee)
        ical.add_component(event)
        if hasattr(ical, "add_missing_timezones"):
            ical.add_missing_timezones()
        calendar.add_event(ical.to_ical().decode())
        _, _, state = self.plugin.find_event(uid)
        result = {"uid": uid}
        if not args.get("end"):
            result.update(end=self.end(args), note="no end given: " + (
                "all day" if len(args["start"].strip()) == 10 else "one hour") + "; update_event changes it")
        return ExecResult(result=result, after=state, object_ref=uid,
                          summary=f"Created “{args['summary']}” {args['start']} to {self.end(args)}")

    def describe(self, args):
        who = f" with {', '.join(args['attendees'])}" if args.get("attendees") else ""
        return f"Create “{args.get('summary')}” at {args.get('start')}{who}{self.where(self.calendar_of(args))}"

    def follow_up(self, args, result):
        if not args.get("attendees"):
            return "Everyone who shares the calendar sees it. Delete the event to take it away."
        return "Invitations went out. Delete the event to send a cancellation."


class UpdateEvent(UpdateRules, EventTool):
    def existing(self, args):
        state = super().existing(args)
        organizer = self.invitation_from(state)
        if organizer and type(self) is UpdateEvent:
            raise Denied(f"this is {organizer}'s invitation: its time, title and guests are theirs to change", "invalid")
        return state

    def snapshot(self, args):
        return self.existing(args)

    def preview(self, args, before):
        changes = dict(args["changes"])
        if "attendees" in changes:
            changes["attendees"] = sorted(a.lower() for a in changes["attendees"])
        return {**{k: v for k, v in before.items() if not k.startswith("_")}, **changes}

    def execute(self, args, before):
        self.plugin.apply_event_changes(self.plugin.find_event(args["uid"])[1], args["changes"])
        state = self.plugin.find_event(args["uid"])[2]
        return ExecResult(result={"uid": args["uid"]}, after=state, object_ref=args["uid"],
                          summary=f"Changed “{state['summary']}”")

    def describe(self, args):
        return f"Change event {args.get('uid')}: {', '.join(sorted(args.get('changes', {})))}{self.shared_note(args)}"

    def follow_up(self, args, result):
        return "Attendees were notified of the change. Change it back to send another update."


class DeleteEvent(DeleteRules, UpdateEvent):
    def preview(self, args, before):
        return None

    def execute(self, args, before):
        self.plugin.find_event(args["uid"])[1].delete()
        return ExecResult(result={"uid": args["uid"]}, after=None, object_ref=args["uid"],
                          summary=f"Deleted “{before['summary']}”")

    def describe(self, args):
        return f"Delete event {args.get('uid')}{self.shared_note(args)}"

    def follow_up(self, args, result):
        return "Attendees got a cancellation. Re-create the event to invite them again."


class RespondEvent(RespondRules, EventTool):
    """An iTIP REPLY the CalDAV way (RFC 6638): the owner's ATTENDEE line on their copy gets the new PARTSTAT,
    and a server that does scheduling (Nextcloud, iCloud, Fastmail) sends the reply to the organizer. Every
    occurrence of a series is answered. No comment: Nextcloud's scheduling (sabre/vobject) builds the REPLY
    from the attendee line and leaves a COMMENT out, so the organizer wouldn't see it."""

    def zone_name(self):
        return self.plugin.config.get("timezone")

    def execute(self, args, before):
        found = self.plugin.find_event(args["uid"])
        if found is None:
            raise NotSent(f"no event with uid {args['uid']} any more; nothing was sent")
        organizer = self.invitation_from(found[2])
        if organizer != args["to"]:
            raise NotSent(f"the invitation's organizer is now {organizer or 'you'}, not {args['to']}; nothing was "
                          "sent, ask again")
        if not self.plugin.answer_invitation(found[1], PARTSTAT[args["response"]]):
            raise NotSent("you're no longer among the event's guests; nothing was sent")
        state = self.plugin.find_event(args["uid"])[2]
        return ExecResult(result={"uid": args["uid"], "response": state["response"]}, after=state,
                          object_ref=args["uid"], summary=f"Told {args['to']} you {ANSWERS[args['response']][0]}")


PARTSTAT = {"accept": "ACCEPTED", "decline": "DECLINED", "tentative": "TENTATIVE"}

# tasks


class TaskTool(Tool):
    IGNORE_FIELDS = frozenset({"completed_at"})

    def current(self, object_ref):
        found = self.plugin.find_task(object_ref)
        return found[2] if found else None

    def undo(self, object_ref, before, after):
        self.plugin.restore_task(object_ref, before)

    def undo_fields(self, object_ref, fields, now):
        found = self.plugin.find_task(object_ref)
        if found is None:
            raise PluginError(f"no task with uid {object_ref}")
        unknown = set(fields) - set(TASK_FIELDS)
        if unknown:
            raise PluginError(f"can't put back {', '.join(sorted(unknown))}")
        self.plugin.apply_task_changes(found[1], fields)

    def render_diff(self, before, after, args):
        hide = {"uid", "list", "completed_at"}
        strip = (lambda s: {k: v for k, v in s.items() if k not in hide} if s else None)
        return super().render_diff(strip(before), strip(after), args)

    def ref_for(self, args):
        return args.get("uid")

    def existing(self, args) -> dict:
        found = self.plugin.find_task(args["uid"])
        if found is None:
            raise PluginError(f"no task with uid {args['uid']}")
        return found[2]

    def snapshot(self, args):
        return self.existing(args)

    def list_of(self, args) -> str:
        return self.existing(args)["list"]

    def tier(self, args):
        """On a shared list (the flat's shopping list, a group project's to-dos) others see it at once: a send."""
        return SEND if self.plugin.is_shared(self.list_of(args)) else QUIET

    def describe(self, args):
        try:
            shared = self.plugin.is_shared(self.list_of(args))
        except (PluginError, Denied):  # gone already: the summary after a delete
            shared = False
        return self.what(args) + (" on a shared list" if shared else "")

    def what(self, args) -> str:
        return self.spec["name"]

    def follow_up(self, args, result):
        return "Everyone who shares the list sees it. Change it again to correct it."


class CreateTask(TaskTool):
    def ref_for(self, args):
        return None

    def snapshot(self, args):
        return None

    def list_of(self, args):
        try:
            return self.plugin.tasklist(args.get("list"))[0]
        except PluginError:  # no such list: execute fails and says so
            return None

    def preview(self, args, before):
        return {"summary": args["summary"], "description": args.get("description", ""), "due": args.get("due"),
                "priority": args.get("priority"), "tags": sorted(args.get("tags", [])), "done": False}

    def execute(self, args, before):
        name, tasklist = self.plugin.tasklist(args.get("list"))
        uid = f"{uuid.uuid4()}@doorman"
        ical = ICalendar()
        ical.add("prodid", "-//doorman//EN")
        ical.add("version", "2.0")
        todo = ITodo()
        todo.add("uid", uid)
        todo.add("dtstamp", datetime.now(timezone.utc))
        todo.add("summary", args["summary"])
        todo.add("status", "NEEDS-ACTION")
        ical.add_component(todo)
        tasklist.save_todo(ical.to_ical().decode())
        found = self.plugin.find_task(uid)
        fields = {k: args[k] for k in ("description", "due", "priority", "tags") if args.get(k) is not None}
        if fields:
            self.plugin.apply_task_changes(found[1], fields)
            found = self.plugin.find_task(uid)
        return ExecResult(result={"uid": uid, "list": name}, after=found[2], object_ref=uid,
                          summary=f"Added task “{args['summary']}”" + (f", due {args['due']}" if args.get("due") else ""))

    def what(self, args):
        return f"Add task “{args.get('summary')}”"


class UpdateTask(TaskTool):
    def preview(self, args, before):
        return {**{k: v for k, v in before.items() if not k.startswith("_")}, **args["changes"]}

    def execute(self, args, before):
        self.plugin.apply_task_changes(self.plugin.find_task(args["uid"])[1], args["changes"])
        state = self.plugin.find_task(args["uid"])[2]
        return ExecResult(result={"uid": args["uid"]}, after=state, object_ref=args["uid"],
                          summary=f"Changed task “{state['summary']}”")

    def what(self, args):
        return f"Change task {args.get('uid')}: {', '.join(sorted(args.get('changes', {})))}"


class CompleteTask(TaskTool):
    def preview(self, args, before):
        return {**{k: v for k, v in before.items() if not k.startswith("_")}, "done": args.get("done", True)}

    def execute(self, args, before):
        done = args.get("done", True)
        self.plugin.apply_task_changes(self.plugin.find_task(args["uid"])[1], {"done": done})
        state = self.plugin.find_task(args["uid"])[2]
        return ExecResult(result={"uid": args["uid"], "done": state["done"]}, after=state, object_ref=args["uid"],
                          summary=f"{'Ticked off' if done else 'Reopened'} “{state['summary']}”")

    def what(self, args):
        return f"{'Tick off' if args.get('done', True) else 'Reopen'} task {args.get('uid')}"


class DeleteTask(TaskTool):
    def execute(self, args, before):
        self.plugin.find_task(args["uid"])[1].delete()
        return ExecResult(result={"uid": args["uid"]}, after=None, object_ref=args["uid"],
                          summary=f"Deleted task “{before['summary']}”")

    def what(self, args):
        return f"Delete task {args.get('uid')}"


class Plugin(BasePlugin):
    TOOLS = {"create_event": CreateEvent, "update_event": UpdateEvent, "delete_event": DeleteEvent,
             "respond": RespondEvent, "create_task": CreateTask, "update_task": UpdateTask,
             "complete_task": CompleteTask, "delete_task": DeleteTask}
    READS = {"calendars": "read_calendars", "events": "read_events", "lists": "read_lists", "tasks": "read_tasks"}

    def __init__(self, ctx, manifest):
        super().__init__(ctx, manifest)
        self.owner_emails = {e.lower() for e in self.config.get("owner_emails", [])} | ctx.owner_identities
        self._client = None
        self._collections = None
        self._principal_path = ""
        self._first = threading.Lock()
        self._sharing: dict[str, tuple[bool, float]] = {}  # collection URL: (shared, good until)
        self.zone = ZoneInfo(self.config["timezone"]) if self.config.get("timezone") else None

    # connection and collections

    def client(self) -> caldav.DAVClient:
        if self._client is None:
            url = self.config.get("url")
            if not url:
                raise PluginError(f"{self.ctx.instance}: set config.url")
            self._client = caldav.DAVClient(
                url=url, username=self.credentials.get("username"), password=self.credentials.get("password"),
                require_tls=url.startswith("https://") or not self.config.get("allow_http", False))
        return self._client

    def collections(self) -> list[tuple[str, object, list[str]]]:
        """Every collection on the server: (name, collection, the components it takes). One thread at a time:
        the first request negotiates the login, and the client isn't thread-safe while it does (a second
        request at that moment, the worker's poll next to an agent's read, gets a 401)."""
        with self._first:
            if self._collections is None:
                found = []
                principal = self.client().principal()
                self._principal_path = urlparse(str(principal.url)).path.strip("/")
                for collection in principal.calendars():
                    try:
                        components = collection.get_supported_components()
                    except Exception:  # noqa: BLE001 - servers that don't say: assume both
                        components = ["VEVENT", "VTODO"]
                    name = collection.get_display_name() or str(collection.url).rstrip("/").rsplit("/", 1)[-1]
                    found.append((name, collection, components))
                self._collections = found
            return self._collections

    def _pick(self, component: str, config_key: str) -> dict:
        wanted = self.config.get(config_key)  # None: all of them; []: none
        if isinstance(wanted, str):  # one name, typed without brackets
            wanted = [wanted]
        return {name: c for name, c, components in self.collections()
                if component in components and (wanted is None or name in wanted)}

    def calendars(self) -> dict:
        return self._pick("VEVENT", "calendars")

    def lists(self) -> dict:
        return self._pick("VTODO", "lists")

    def check(self):
        self._collections = None  # pick up calendars and lists made since
        self._sharing = {}
        try:
            names = {name for name, _, _ in self.collections()}
        except Exception as exc:  # noqa: BLE001 - login refused, server gone
            self._client, self._collections = None, None
            return f"CalDAV login failed: {exc}"
        named = [self.config.get(key) or [] for key in ("calendars", "lists")]
        missing = [n for group in named for n in ([group] if isinstance(group, str) else group) if n not in names]
        return f"not on the server: {', '.join(missing)}" if missing else None

    def calendar_name(self, name: str | None) -> str:
        calendars = self.calendars()
        if not calendars:
            raise PluginError("no calendars to use (none on the server, or config.calendars leaves none)")
        name = name or self.config.get("default_calendar") or next(iter(calendars))
        if name not in calendars:
            raise PluginError(f"no calendar named {name}")
        return name

    def calendar(self, name: str | None):
        return self.calendars()[self.calendar_name(name)]

    def outside(self, attendees: list[str]) -> list[str]:
        return [a for a in attendees if a.lower() not in self.owner_emails]

    # sharing

    SHARING_TTL = 3600  # a collection's sharing rarely changes; check() forgets it at once
    SHARING_RETRY = 60  # after a failed lookup: one write asks once, the next minute's ask again

    def is_shared(self, name: str) -> bool:
        """Whether others see the collection called `name` (a calendar or a task list), so that writing to it
        reaches them. From config.shared_collections, or from what the server says (sharing_of)."""
        if name in (self.config.get("shared_collections") or []):
            return True
        return any(self._collection_shared(collection) for n, collection, _ in self.collections() if n == name)

    def _collection_shared(self, collection) -> bool:
        url = str(collection.url)
        cached = self._sharing.get(url)
        if cached and self._now() < cached[1]:
            return cached[0]
        if "_shared_by_" in urlparse(url).path.rstrip("/").rsplit("/", 1)[-1]:
            shared = True  # Nextcloud's own name for someone else's calendar in yours
        else:
            try:
                response = self.client().propfind(url, SHARING_QUERY, 0)
            except Exception as exc:  # noqa: BLE001 - the server's trouble, not a sign of sharing
                # No answer is no evidence of sharing: the write stays quiet (and undoable) rather than every
                # write asking because a request failed. The server most likely refuses the write too.
                log.warning("%s: couldn't read the sharing of %s (%s); treating it as not shared",
                            self.ctx.instance, url, exc)
                self._sharing[url] = (False, self._now() + self.SHARING_RETRY)
                return False
            shared = (response.status in (200, 207) and response.tree is not None
                      and sharing_of(response.tree, self._principal_path, self.owner_emails))
        self._sharing[url] = (shared, self._now() + self.SHARING_TTL)
        return shared

    @staticmethod
    def _now() -> float:
        return time.monotonic()

    def tasklist(self, name: str | None):
        lists = self.lists()
        if not lists:
            raise PluginError("no task lists to use (none on the server, or config.lists leaves none)")
        name = name or self.config.get("default_list") or next(iter(lists))
        if name not in lists:
            raise PluginError(f"no task list named {name}")
        return name, lists[name]

    # events

    def find_event(self, uid: str):
        """(calendar name, resource, state) or None."""
        for name, calendar in self.calendars().items():
            try:
                resource = calendar.event_by_uid(uid)
            except NotFoundError:
                continue
            resource.load()
            return name, resource, event_state(name, resource.icalendar_component, resource.data, self.owner_emails)
        return None

    def answer_invitation(self, resource, partstat: str) -> bool:
        """Set the owner's PARTSTAT on every occurrence (the series and the ones moved on their own) and save:
        a scheduling server sends the organizer an iTIP REPLY from it. False when the owner isn't a guest."""
        answered = False
        with resource.edit_icalendar_instance() as ical:
            for component in ical.walk("VEVENT"):
                mine = [a for a in _attendee_props(component)
                        if str(a).lower().replace("mailto:", "", 1) in self.owner_emails]
                for attendee in mine:
                    attendee.params["PARTSTAT"] = partstat
                    attendee.params.pop("RSVP", None)  # answered: no reply is asked for any more
                if mine:
                    answered = True
                    component.pop("dtstamp", None)
                    component.add("dtstamp", datetime.now(timezone.utc))
        if answered:
            resource.save()
        return answered

    def apply_event_changes(self, resource, changes: dict) -> None:
        component = resource.icalendar_component
        for field in ("summary", "location", "description"):
            if field in changes:
                component.pop(field, None)
                if changes[field]:
                    component.add(field, changes[field])
        for field, prop in (("start", "dtstart"), ("end", "dtend")):
            if field in changes:
                component.pop(prop, None)
                if changes[field]:
                    component.add(prop, parse_time(changes[field], self.zone))
        if "attendees" in changes:
            component.pop("attendee", None)
            for address in changes["attendees"] or []:
                component.add("attendee", vCalAddress(f"mailto:{address}"))
        component.pop("dtstamp", None)
        component.add("dtstamp", datetime.now(timezone.utc))
        resource.save()

    def restore_event(self, uid: str, state: dict | None) -> None:
        """Make the event look like `state` again (None = it should not exist)."""
        found = self.find_event(uid)
        if state is None:
            if found:
                found[1].delete()
            return
        if found:
            found[1].data = state["_ics"]
            found[1].save()
        else:
            self.calendar(state["calendar"]).add_event(state["_ics"])

    # tasks

    def find_task(self, uid: str):
        """(list name, resource, state) or None."""
        for name, tasklist in self.lists().items():
            try:
                resource = tasklist.todo_by_uid(uid)
            except NotFoundError:
                continue
            resource.load()
            return name, resource, task_state(name, resource.icalendar_component, resource.data)
        return None

    def apply_task_changes(self, resource, changes: dict) -> None:
        component = resource.icalendar_component
        for field in ("summary", "description"):
            if field in changes:
                component.pop(field, None)
                if changes[field]:
                    component.add(field, changes[field])
        if "due" in changes:
            component.pop("due", None)
            if changes["due"]:
                component.add("due", parse_time(changes["due"], self.zone))
        if "priority" in changes:
            component.pop("priority", None)
            if changes["priority"]:
                component.add("priority", int(changes["priority"]))
        if "tags" in changes:
            component.pop("categories", None)
            if changes["tags"]:
                component.add("categories", list(changes["tags"]))
        if "done" in changes:
            for prop in ("status", "completed", "percent-complete"):
                component.pop(prop, None)
            if changes["done"]:
                component.add("status", "COMPLETED")
                component.add("completed", datetime.now(timezone.utc))
                component.add("percent-complete", 100)
            else:
                component.add("status", "NEEDS-ACTION")
        for prop in ("dtstamp", "last-modified"):
            component.pop(prop, None)
        component.add("dtstamp", datetime.now(timezone.utc))
        component.add("last-modified", datetime.now(timezone.utc))
        resource.save()

    def restore_task(self, uid: str, state: dict | None) -> None:
        """Make the task look like `state` again (None = it should not exist)."""
        found = self.find_task(uid)
        if state is None:
            if found:
                found[1].delete()
            return
        if found:
            found[1].data = state["_ics"]
            found[1].save()
        else:
            self.tasklist(state["list"])[1].save_todo(state["_ics"])

    # reads

    def read_calendars(self, params):
        return [{"name": name, "shared": self.is_shared(name)} for name in self.calendars()]

    def occurrences(self, name: str, start, end) -> list:
        """The VEVENTs of one calendar between start and end, recurring ones expanded (one per occurrence)."""
        return [component for resource in self.calendar(name).search(start=start, end=end, event=True, expand=True)
                for component in resource.icalendar_instance.walk("VEVENT")]

    def read_events(self, params):
        start, end = parse_time(params["start"], self.zone), parse_time(params["end"], self.zone)
        names = [params["calendar"]] if params.get("calendar") else list(self.calendars())
        events = []
        for name in names:
            for component in self.occurrences(name, start, end):
                state = event_state(name, component, "", self.owner_emails)
                state = {k: v for k, v in state.items() if not k.startswith("_")}
                state["ref"] = f"{self.ctx.instance}:{state['uid']}"
                events.append(state)
        return sorted(events, key=lambda e: e["start"] or "")

    def read_lists(self, params):
        return [{"name": name, "shared": self.is_shared(name)} for name in self.lists()]

    def read_tasks(self, params):
        names = [params["list"]] if params.get("list") else list(self.lists())
        include = bool(params.get("include_completed"))
        limit = parse_time(params["due_before"], self.zone) if params.get("due_before") else None
        out = []
        for name in names:
            for resource in self.tasklist(name)[1].todos(include_completed=include):
                for component in resource.icalendar_instance.walk("VTODO"):
                    state = task_state(name, component, "")
                    state.pop("_ics")
                    if limit is not None and (not state["due"] or not _before(state["due"], limit)):
                        continue
                    state["ref"] = f"{self.ctx.instance}:{state['uid']}"
                    out.append(state)
        return sorted(out, key=lambda t: (t["due"] is None, t["due"] or "", t["priority"] or 10))

    # Doorman's search index (calendar_feed.py has the rules)

    def index_feed(self, cursor, budget):
        """Every event series and task of the window (calendar_feed.window), each calendar and list read whole,
        one at a time until the budget is spent. A series' item has the ref the events read gives (what
        update_event, delete_event and respond take); key and ref alike for tasks."""
        deadline = time.monotonic() + float(budget)
        start, end = calendar_feed.window(self.config)
        todo = calendar_feed.rotated([f"event:{n}" for n in self.calendars()] + [f"task:{n}" for n in self.lists()],
                                     cursor)
        occurrences, tasks = [], []
        for i, which in enumerate(todo):
            if i and time.monotonic() >= deadline:
                return calendar_feed.answer(calendar_feed.event_items(occurrences, self.zone) + tasks, which)
            kind, name = which.split(":", 1)
            if kind == "event":
                occurrences += [self._occurrence(name, c) for c in self.occurrences(name, start, end)]
            else:
                tasks += self._task_items(name, start)
        return calendar_feed.answer(calendar_feed.event_items(occurrences, self.zone) + tasks)

    def _occurrence(self, calendar_name: str, component) -> dict:
        state = event_state(calendar_name, component, "", self.owner_emails)
        status = str(component.get("status") or "").lower()
        return {**state, "key": f"{calendar_name}/{state['uid']}", "ref": f"{self.ctx.instance}:{state['uid']}",
                "organizer_name": state["_organizer_name"],
                "recurring": state["recurring"] or component.get("recurrence-id") is not None,
                "extra": {"status": status} if status and status != "confirmed" else {}}

    def _task_items(self, list_name: str, since) -> list[dict]:
        """A list's open tasks, and its completed ones of the window. date: due, or when it was made."""
        out = []
        for resource in self.tasklist(list_name)[1].todos(include_completed=True):
            for component in resource.icalendar_instance.walk("VTODO"):
                state = task_state(list_name, component, "")
                made = _iso(component.get("created")) or _iso(component.get("dtstamp"))
                when = [calendar_feed.moment(v, self.zone) for v in (state["completed_at"], state["due"], made)]
                if state["done"] and not any(w and w >= since for w in when):
                    continue
                fields = {"list": list_name, "due": state["due"], "priority": state["priority"],
                          "completed": state["completed_at"] or state["done"]}
                out.append({"key": f"{list_name}/{state['uid']}", "ref": f"{self.ctx.instance}:{state['uid']}",
                            "kind": "task", "title": state["summary"], "date": state["due"] or made,
                            "in": list_name, "text": state["description"], "same": f"uid:{state['uid']}",
                            "fields": {k: v for k, v in fields.items() if v is not None}})
        return out

    def poll_events(self, cursor):
        """New events organized by someone else (invitations) since the last poll, and entries starting
        within soon_minutes (default 30), once per occurrence."""
        if not self.calendars():
            return [], cursor
        state = calendar_cursor(cursor)
        seen = set(state["invites"])
        now = clock.now()
        today = now.astimezone(self.zone).date() if self.zone else now.date()
        entries = self.read_events({"start": today.isoformat(), "end": (today + timedelta(days=90)).isoformat()})
        events, current = [], set()
        for event in entries:
            current.add(event["uid"])
            organizer = event.get("organizer")
            if event["uid"] not in seen and organizer and organizer not in self.owner_emails and cursor is not None:
                events.append({"type": "invite_received", "ref": event["ref"], "from": organizer,
                               "summary": event["summary"], "start": event["start"]})
        soon, announced = starting_soon(entries, state["soon"], soon_minutes(self.config), now,
                                        self.zone)
        return events + soon, json.dumps({"invites": sorted(current), "soon": announced})
