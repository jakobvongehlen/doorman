"""The send rules both calendar plugins (caldav, google_calendar) share: which event writes reach other people,
and so wait for the owner, and whom they reach. They were written twice and had drifted (only Google knew
shared calendars); now each plugin's event tools mix these in before `Tool` and supply the hooks:

- `calendar_of(args)`: the calendar the write lands on (an id or a name, whatever `plugin.is_shared` takes);
- `existing(args)`: the event as it is now (update, delete, respond);
- `invitation_from(state)`: the organizer, when the event is someone else's invitation;
- `plugin.outside(attendees)`: the attendees who aren't the owner;
- `plugin.is_shared(calendar)`: whether others can see the calendar.

Each plugin keeps `execute`, `undo` and how it reads and writes events."""

from datetime import date, datetime
from zoneinfo import ZoneInfo

from doorman.plugin_api import Denied

SEND, QUIET = "irreversible", "reversible"

# respond's `response` → (what the owner is told it does, the state's `response` afterwards)
ANSWERS = {"accept": ("accept", "accepted"), "decline": ("decline", "declined"),
           "tentative": ("tentatively accept", "tentative")}


class EventRules:
    def is_send(self, calendar, attendees: list[str]) -> bool:
        """A write reaches others when the event has guests other than the owner (before or after the change)
        or when the calendar is shared: they see it at once."""
        return bool(self.plugin.outside(attendees)) or self.plugin.is_shared(calendar)

    def where(self, calendar) -> str:
        return f" on shared calendar {calendar}" if self.plugin.is_shared(calendar) else ""


class CreateRules(EventRules):
    def tier(self, args):
        return SEND if self.is_send(self.calendar_of(args), args.get("attendees", [])) else QUIET


class UpdateRules(EventRules):
    def tier(self, args):
        existing = self.existing(args)
        attendees = existing["attendees"] + args["changes"].get("attendees", [])
        return SEND if self.is_send(self.calendar_of(args), attendees) else QUIET

    def destinations(self, args):
        found = super().destinations(args)
        return found + [("email", a) for a in self.plugin.outside(self.existing(args)["attendees"])]


class DeleteRules(EventRules):
    """Deleting someone else's invitation declines it (the server or Google tells the organizer): a send."""

    def tier(self, args):
        existing = self.existing(args)
        send = self.is_send(self.calendar_of(args), existing["attendees"]) or self.invitation_from(existing)
        return SEND if send else QUIET

    def destinations(self, args):
        existing = self.existing(args)
        found = self.plugin.outside(existing["attendees"])
        organizer = self.invitation_from(existing)
        if organizer and organizer not in found:
            found.append(organizer)
        return [("email", a) for a in found]


class RespondRules(EventRules):
    """Accept, decline or tentatively accept an invitation. Always a send (the manifest's tier): the organizer
    is told. prepare() puts the organizer into the arguments as `to`, so the approval, the push and the payload
    hash name who hears it; the manifest's destination reads it from there. The organizer is trusted by
    context, as a mail's sender is for a reply: they put the invitation into the owner's calendar."""

    def answerable(self, args) -> tuple[dict, str]:
        """The event and its organizer, or Denied when there is nothing to answer."""
        state = self.existing(args)
        organizer = self.invitation_from(state)
        if not organizer:
            raise Denied("this is your own event, not an invitation: there is nothing to answer", "invalid")
        if state.get("response") is None:
            raise Denied("you aren't among this event's guests, so there is no invitation of yours to answer "
                         "(if you are, add the address it uses to owner_emails)", "invalid")
        return state, organizer

    def prepare(self, args):
        _, organizer = self.answerable(args)
        return {**args, "to": organizer}

    def trusted_destinations(self, args):
        return {args["to"]} if args.get("to") else set()

    def snapshot(self, args):
        return self.existing(args)

    def describe(self, args):
        # addresses only: the event's title is the organizer's text, and agents see summaries
        verb = ANSWERS.get(args.get("response"), (args.get("response"),))[0]
        return f"Tell {args.get('to') or 'the organizer'} you {verb} their invitation"

    def outgoing(self, args):
        """What the organizer hears, in a sentence for the approval: "Tells Dr. Jansen (…) you accept
        “Thesis meeting”, Tue 10 Nov, 10:00." Read again when the approval is shown."""
        state = self.existing(args)
        title = state.get("summary") or "(no title)"
        when = when_text(state.get("start"), self.zone_name())
        name = self.organizer_name(state)
        who = f"{name} ({args.get('to')})" if name and name.lower() != str(args.get("to")).lower() else args.get("to")
        verb = ANSWERS.get(args.get("response"), (args.get("response"),))[0]
        text = f"Tells {who} you {verb} “{title}”{', ' + when if when else ''}{self.scope(state)}."
        if args.get("comment"):
            text += f"\nYour comment: {args['comment']}"
        return {"label": "Your answer to the invitation", "title": f"{title}{', ' + when if when else ''}",
                "text": text}

    def follow_up(self, args, result):
        return "The organizer has your answer. Answer again to change it."

    def organizer_name(self, state: dict) -> str | None:
        return state.get("_organizer_name")

    def zone_name(self) -> str | None:
        return None

    def scope(self, state: dict) -> str:
        return " (the whole series)" if state.get("recurring") else ""


def when_text(value: str | None, zone: str | None = None) -> str:
    """"Tue 10 Nov, 10:00" (in `zone` when given), "Tue 10 Nov" for a whole day."""
    if not value:
        return ""
    try:
        if len(value) == 10:
            day = date.fromisoformat(value)
            return f"{day:%a} {day.day} {day:%b}"
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    if zone and moment.tzinfo is not None:
        try:
            moment = moment.astimezone(ZoneInfo(zone))
        except (KeyError, ValueError):
            pass
    return f"{moment:%a} {moment.day} {moment:%b}, {moment:%H:%M}"
