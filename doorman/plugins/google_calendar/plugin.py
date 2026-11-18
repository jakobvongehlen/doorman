"""Google Calendar through the Calendar API v3. Not tested against Google; tests use a fake API.

Login is OAuth 2.0 for a "Desktop app" client: authorization code with PKCE and a loopback redirect
(http://127.0.0.1:<port>/). Doorman usually runs on a server, so the browser that logs in can't
reach that loopback address: Google's redirect then shows an error page, and you paste that page's
address back (into the owner app or the `doorman-admin login` prompt). When the browser runs on the
doorman's own machine, `doorman-admin login` catches the redirect itself.

Writes that notify nobody run with sendUpdates=none and are undoable. A write is a send (approval,
sendUpdates=all) when the event has attendees other than you, before or after the change, or when the
calendar is shared: someone else's calendar you may write to, or one of yours whose sharing settings
give anyone else access. Answering an invitation (respond) is always a send. The rules are shared with
the caldav plugin (doorman/calendar_tools.py).
"""

import base64
import hashlib
import json
import os
import secrets
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode, urlparse
from zoneinfo import ZoneInfo

import httpx

from doorman import calendar_feed, clock
from doorman.calendar_tools import ANSWERS, CreateRules, DeleteRules, RespondRules, UpdateRules
from doorman.plugin_api import (BasePlugin, Denied, ExecResult, NotSent, PluginError, Tool, calendar_cursor,
                                http_json, soon_minutes, starting_soon)

API = "https://www.googleapis.com/calendar/v3"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
SCOPES = [
    "https://www.googleapis.com/auth/calendar.events",              # read and write events
    "https://www.googleapis.com/auth/calendar.calendarlist.readonly",  # which calendars exist
    "https://www.googleapis.com/auth/calendar.acls.readonly",       # whether a calendar is shared
]
LOGIN_TTL = 15 * 60
# fields of an event resource that may be written back when undoing
WRITABLE = ("summary", "description", "location", "start", "end", "attendees", "recurrence", "reminders",
            "colorId", "transparency", "visibility", "status", "extendedProperties", "guestsCanModify",
            "guestsCanInviteOthers", "guestsCanSeeOtherGuests", "source", "eventType")


def q(value: str) -> str:
    """Quote an id for a URL path, so it can't add path segments, queries or fragments."""
    return quote(str(value), safe="")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def time_field(value: str, zone: str | None) -> dict:
    """ISO date → all-day; date-time with offset → as given; without offset → in `zone`."""
    value = value.strip()
    if len(value) == 10:
        return {"date": date.fromisoformat(value).isoformat()}
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is not None:
        return {"dateTime": parsed.isoformat()}
    if not zone:
        raise PluginError(f"{value} has no UTC offset and no timezone is configured")
    return {"dateTime": parsed.isoformat(), "timeZone": zone}


def _when(field: dict | None) -> str | None:
    if not field:
        return None
    return field.get("dateTime") or field.get("date")


def ref_of(calendar: str, event_id: str) -> str:
    return f"{calendar}/{event_id}"


def split_ref(ref: str) -> tuple[str, str]:
    calendar, _, event_id = ref.rpartition("/")
    if not calendar or not event_id:
        raise PluginError(f"bad event reference {ref}")
    return calendar, event_id


GENERATED = "@group.v.calendar.google.com"  # Google's own calendars: week numbers, holidays, birthdays

class GoogleTool(Tool):
    def current(self, object_ref):
        calendar, event_id = split_ref(object_ref)
        return self.plugin.event_state(calendar, event_id)

    def undo(self, object_ref, before, after):
        self.plugin.restore(object_ref, before)

    def undo_fields(self, object_ref, fields, now):
        """Put back the fields this action changed; what others changed meanwhile stays."""
        calendar, event_id = split_ref(object_ref)
        body = {}
        for field, value in fields.items():
            if field in ("summary", "location", "description"):
                body[field] = value or ""
            elif field in ("start", "end"):
                body[field] = {"date": value} if value and len(value) == 10 else {"dateTime": value}
            elif field == "attendees":
                body[field] = [{"email": a} for a in value or []]
            elif field not in ("all_day", "response"):  # these follow start, end and attendees
                raise PluginError(f"can't put back {field}")
        self.plugin.request("PATCH", f"/calendars/{q(calendar)}/events/{q(event_id)}", json=body,
                            params={"sendUpdates": "none"})

    def render_diff(self, before, after, args):
        hide = {"id", "calendar", "organizer", "recurring_event_id", "link"}
        strip = (lambda s: {k: v for k, v in s.items() if k not in hide} if s else None)
        return super().render_diff(strip(before), strip(after), args)

    def calendar_id(self, args) -> str:
        return self.plugin.resolve_calendar(args.get("calendar"))

    def existing(self, args) -> dict:
        state = self.plugin.event_state(self.calendar_id(args), args["id"])
        if state is None:
            raise PluginError(f"no event {args['id']}")
        return state

    def calendar_of(self, args) -> str:
        return self.calendar_id(args)

    @staticmethod
    def invitation_from(state: dict) -> str | None:
        """The organizer, when the event is someone else's invitation."""
        return state["organizer"] if state.get("_invited") else None


class CreateEvent(CreateRules, GoogleTool):
    def preview(self, args, before):
        return {"summary": args["summary"], "start": args["start"], "end": args["end"],
                "location": args.get("location", ""), "description": args.get("description", ""),
                "attendees": sorted(a.lower() for a in args.get("attendees", []))}

    def execute(self, args, before):
        calendar = self.calendar_id(args)
        zone = self.plugin.zone_for(calendar)
        body = {"summary": args["summary"], "start": time_field(args["start"], zone),
                "end": time_field(args["end"], zone)}
        for field in ("location", "description"):
            if args.get(field):
                body[field] = args[field]
        if args.get("attendees"):
            body["attendees"] = [{"email": a} for a in args["attendees"]]
        send = self.is_send(calendar, args.get("attendees", []))
        event = self.plugin.request("POST", f"/calendars/{q(calendar)}/events", json=body,
                                    params={"sendUpdates": "all" if send else "none"})
        state = self.plugin.state_from(calendar, event)
        return ExecResult(result={"id": event["id"], "calendar": calendar, "link": event.get("htmlLink")},
                          after=state, object_ref=ref_of(calendar, event["id"]),
                          summary=f"Created “{args['summary']}” {args['start']}")

    def describe(self, args):
        who = f" with {', '.join(args['attendees'])}" if args.get("attendees") else ""
        return f"Create “{args.get('summary')}” at {args.get('start')}{who}{self.where(self.calendar_id(args))}"

    def follow_up(self, args, result):
        return "Invitations went out. Delete the event to send a cancellation."


class UpdateEvent(UpdateRules, GoogleTool):
    def ref_for(self, args):
        return ref_of(self.calendar_id(args), args["id"])

    def existing(self, args) -> dict:
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
        calendar = self.calendar_id(args)
        zone = self.plugin.zone_for(calendar)
        changes, body = args["changes"], {}
        for field in ("summary", "location", "description"):
            if field in changes:
                body[field] = changes[field]
        for field in ("start", "end"):
            if field in changes:
                body[field] = time_field(changes[field], zone)
        if "attendees" in changes:
            body["attendees"] = [{"email": a} for a in changes["attendees"]]
        send = self.is_send(calendar, before["attendees"] + changes.get("attendees", []))
        event = self.plugin.request("PATCH", f"/calendars/{q(calendar)}/events/{q(args['id'])}", json=body,
                                    params={"sendUpdates": "all" if send else "none"})
        state = self.plugin.state_from(calendar, event)
        return ExecResult(result={"id": args["id"], "calendar": calendar}, after=state,
                          object_ref=ref_of(calendar, args["id"]), summary=f"Changed “{state['summary']}”")

    def describe(self, args):
        return (f"Change event {args.get('id')}: {', '.join(sorted(args.get('changes', {})))}"
                f"{self.where(self.calendar_id(args))}")

    def follow_up(self, args, result):
        return "Attendees were notified of the change. Change it back to send another update."


class DeleteEvent(DeleteRules, UpdateEvent):
    def preview(self, args, before):
        return None

    def execute(self, args, before):
        calendar = self.calendar_id(args)
        send = self.is_send(calendar, before["attendees"]) or bool(self.invitation_from(before))
        self.plugin.request("DELETE", f"/calendars/{q(calendar)}/events/{q(args['id'])}",
                            params={"sendUpdates": "all" if send else "none"})
        return ExecResult(result={"id": args["id"], "calendar": calendar}, after=None,
                          object_ref=ref_of(calendar, args["id"]), summary=f"Deleted “{before['summary']}”")

    def describe(self, args):
        return f"Delete event {args.get('id')}{self.where(self.calendar_id(args))}"

    def follow_up(self, args, result):
        return "Attendees got a cancellation. Re-create the event to invite them again."


class RespondEvent(RespondRules, GoogleTool):
    """Sets the owner's responseStatus (and comment) on the event; Google tells the organizer. An occurrence's
    id answers that occurrence, the series' id (recurring_event_id) all of them."""

    def ref_for(self, args):
        return ref_of(self.calendar_id(args), args["id"])

    def zone_name(self):
        return self.plugin.zone

    def scope(self, state):
        if state.get("recurring_event_id"):
            return " (this occurrence only)"
        return " (the whole series)" if (state.get("_raw") or {}).get("recurrence") else ""

    def execute(self, args, before):
        calendar = self.calendar_id(args)
        path = f"/calendars/{q(calendar)}/events/{q(args['id'])}"
        event = self.plugin.request("GET", path, allow=(404, 410))
        if event is None or event.get("status") == "cancelled":
            raise NotSent(f"event {args['id']} is gone; nothing was sent")
        organizer = self.invitation_from(self.plugin.state_from(calendar, event))
        if organizer != args["to"]:
            raise NotSent(f"the invitation's organizer is now {organizer or 'you'}, not {args['to']}; nothing was "
                          "sent, ask again")
        attendees = [dict(a) for a in event.get("attendees", [])]
        mine = [a for a in attendees if self.plugin.is_me(a)]
        if not mine:
            raise NotSent("you're no longer among the event's guests; nothing was sent")
        for attendee in mine:
            attendee["responseStatus"] = GOOGLE_ANSWER[args["response"]]
            if args.get("comment"):
                attendee["comment"] = args["comment"]
        updated = self.plugin.request("PATCH", path, json={"attendees": attendees}, params={"sendUpdates": "all"})
        state = self.plugin.state_from(calendar, updated)
        return ExecResult(result={"id": args["id"], "calendar": calendar, "response": state["response"]},
                          after=state, object_ref=ref_of(calendar, args["id"]),
                          summary=f"Told {args['to']} you {ANSWERS[args['response']][0]}")


GOOGLE_ANSWER = {"accept": "accepted", "decline": "declined", "tentative": "tentative"}
STATE_ANSWER = {"needsAction": "needs-action", "accepted": "accepted", "declined": "declined",
                "tentative": "tentative"}


class Plugin(BasePlugin):
    TOOLS = {"create_event": CreateEvent, "update_event": UpdateEvent, "delete_event": DeleteEvent,
             "respond": RespondEvent}
    READS = {"calendars": "read_calendars", "events": "read_events"}
    transport: httpx.BaseTransport | None = None  # tests inject a fake Google here
    SHARED_TTL = 3600

    def __init__(self, ctx, manifest):
        super().__init__(ctx, manifest)
        self.owner_emails = {e.lower() for e in self.config.get("owner_emails", [])} | ctx.owner_identities
        self.zone = self.config.get("timezone")
        if self.zone:
            ZoneInfo(self.zone)  # fail early on a typo
        self._token: str | None = None
        self._expires = 0.0
        self._calendars: dict[str, dict] | None = None
        self._shared: dict[str, tuple[bool, float]] = {}

    # ---------------------------------------------------------------- OAuth

    @property
    def client_id(self) -> str:
        client_id = self.config.get("client_id")
        if not client_id:
            raise PluginError(f"{self.ctx.instance}: set config.client_id (an OAuth client of type Desktop app)")
        return client_id

    def _client_secret(self) -> str:
        secret = self.credentials.get("client_secret")
        if not secret:
            raise PluginError(f"{self.ctx.instance}: store the client secret first (Plugins → "
                              f"{self.ctx.instance} → Settings and credentials, or "
                              f"doorman-admin vault set {self.ctx.instance} client_secret)")
        return secret

    def _token_request(self, data: dict) -> dict:
        data = {"client_id": self.client_id, "client_secret": self._client_secret(), **data}
        try:
            with httpx.Client(transport=self.transport, timeout=30) as client:
                response = client.post(TOKEN_URL, data=data)
        except httpx.HTTPError as exc:
            raise PluginError(f"Google login unreachable: {exc}") from exc
        try:
            body = response.json()
        except ValueError:
            body = {}
        if response.status_code >= 400 or "access_token" not in body:
            error = body.get("error_description") or body.get("error") or f"HTTP {response.status_code}"
            if body.get("error") == "invalid_grant":
                error += " (the Google login expired or was revoked; connect the account again)"
            raise PluginError(f"Google token request failed: {error}")
        return body

    @property
    def _pending_path(self) -> Path:
        return self.ctx.data_dir / "login_pending.json"

    def login_status(self) -> dict:
        missing = [what for what, have in (("client_id", self.config.get("client_id")),
                                           ("client_secret", self.credentials.get("client_secret"))) if not have]
        return {"connected": bool(self.credentials.get("refresh_token")),
                "account": self.credentials.get("account"), "ready": not missing,
                **({"error": f"Not set up yet: {' and '.join(missing)} missing. Follow the steps below."}
                   if missing else {})}

    def login_start(self, redirect_uri: str | None = None) -> dict:
        """Begin an OAuth login. Returns the URL to open in a browser."""
        self._client_secret()
        redirect_uri = redirect_uri or f"http://127.0.0.1:{int(self.config.get('redirect_port', 8799))}/"
        if not redirect_uri.startswith(("http://127.0.0.1:", "http://localhost:")):
            raise PluginError("the redirect must be a loopback address for a Desktop app client")
        verifier = _b64(secrets.token_bytes(48))
        state = _b64(secrets.token_bytes(24))
        pending = {"state": state, "verifier": verifier, "redirect_uri": redirect_uri, "created": time.time()}
        tmp = self._pending_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(pending))
        os.chmod(tmp, 0o600)
        tmp.replace(self._pending_path)
        query = {
            "client_id": self.client_id, "redirect_uri": redirect_uri, "response_type": "code",
            "scope": " ".join(SCOPES), "access_type": "offline", "prompt": "consent",
            "include_granted_scopes": "true", "state": state,
            "code_challenge": _b64(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256",
        }
        return {"auth_url": f"{AUTH_URL}?{urlencode(query)}", "redirect_uri": redirect_uri, "expires_in": LOGIN_TTL}

    def login_finish(self, response_url: str) -> dict:
        """Finish the login with the address Google redirected the browser to."""
        try:
            pending = json.loads(self._pending_path.read_text())
        except (OSError, ValueError):
            raise Denied("no login in progress; start again", "login") from None
        if time.time() - pending["created"] > LOGIN_TTL:
            self._pending_path.unlink(missing_ok=True)
            raise Denied("the login took too long; start again", "login")
        params = parse_qs(urlparse(response_url.strip()).query)
        if params.get("error"):
            self._pending_path.unlink(missing_ok=True)
            raise Denied(f"Google says: {params['error'][0]}", "login")
        code, state = (params.get("code") or [None])[0], (params.get("state") or [None])[0]
        if not code:
            raise Denied("that address has no code in it; paste the whole address of the page Google sent you to",
                         "login")
        if not state or not secrets.compare_digest(state, pending["state"]):
            raise Denied("that address belongs to a different login attempt; start again", "login")
        self._pending_path.unlink(missing_ok=True)
        body = self._token_request({"grant_type": "authorization_code", "code": code,
                                    "redirect_uri": pending["redirect_uri"], "code_verifier": pending["verifier"]})
        if not body.get("refresh_token"):
            raise PluginError("Google sent no refresh token; remove the app's access at "
                              "myaccount.google.com/permissions and connect again")
        granted = set((body.get("scope") or "").split())
        missing = [s.rsplit("/", 1)[-1] for s in SCOPES if granted and s not in granted]
        if missing:
            raise Denied(f"Google login is missing permissions: {', '.join(missing)}; allow all of them", "login")
        self._store("refresh_token", body["refresh_token"])
        self._token, self._expires = body["access_token"], time.monotonic() + int(body.get("expires_in", 3600))
        self._calendars = None
        try:
            account = self._primary_id()
        except PluginError:
            account = None
        if account:
            self._store("account", account)
        return {"connected": True, "account": account}

    def logout(self) -> dict:
        token = self.credentials.get("refresh_token")
        if token:
            try:
                with httpx.Client(transport=self.transport, timeout=30) as client:
                    client.post(REVOKE_URL, data={"token": token})
            except httpx.HTTPError:
                self.ctx.log.warning("revoking the Google token failed; it is forgotten here anyway")
        for key in ("refresh_token", "account"):
            self._store(key, None)
        self._token = None
        return {"connected": False}

    def _store(self, key: str, value: str | None) -> None:
        if value is None:
            self.credentials.pop(key, None)
        else:
            self.credentials[key] = value
        self.ctx.save_credential(key, value)

    def interactive_login(self, say, read_line=input, finish=None) -> None:
        """doorman-admin login: catch the redirect on loopback, or take the pasted address.
        `finish` defaults to login_finish; the admin passes the engine's, which also journals it."""
        import select
        import sys
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        caught: dict = {}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - http.server API
                caught["url"] = self.path
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write("Done. You can close this tab and go back to the terminal.".encode())

            def log_message(self, *args):
                pass

        server = None
        try:
            server = HTTPServer(("127.0.0.1", int(self.config.get("redirect_port", 8799))), Handler)
            threading.Thread(target=server.handle_request, daemon=True).start()
        except OSError:
            say("(the loopback port is busy; paste the address instead)")
        start = self.login_start()
        say("Open this address in a browser and allow access:\n")
        say(start["auth_url"] + "\n")
        say("If the browser runs on another machine, Google ends on a page that doesn't load.\n"
            "Copy that page's whole address and paste it here.")
        url = None
        while url is None:
            if caught.get("url"):
                url = "http://127.0.0.1" + caught["url"]
                break
            if read_line is input and sys.stdin.isatty():
                ready, _, _ = select.select([sys.stdin], [], [], 0.5)
                if ready:
                    line = sys.stdin.readline().strip()
                    url = line or None
            else:
                url = read_line("> ").strip() or None
        if server:
            server.server_close()
        result = (finish or self.login_finish)(url)
        say(f"Connected {result.get('account') or 'the Google account'}.")

    def check(self):
        """A fresh token from the refresh token: catches a revoked or expired Google login."""
        if not self.credentials.get("refresh_token"):
            return "not connected: connect it under Plugins"
        self._token = None
        try:
            self.access_token()
        except PluginError as exc:
            return str(exc)
        return None

    def access_token(self) -> str:
        if self._token and time.monotonic() < self._expires - 60:
            return self._token
        refresh = self.credentials.get("refresh_token")
        if not refresh:
            raise PluginError(f"{self.ctx.instance} isn't connected to Google: connect it in the app "
                              f"(Plugins) or run doorman-admin login {self.ctx.instance}")
        body = self._token_request({"grant_type": "refresh_token", "refresh_token": refresh})
        self._token, self._expires = body["access_token"], time.monotonic() + int(body.get("expires_in", 3600))
        return self._token

    # ---------------------------------------------------------------- API

    def request(self, method: str, path: str, params: dict | None = None, json: dict | None = None,
                allow: tuple[int, ...] = ()) -> dict | None:
        """A Calendar API call (plugin_api.http_json). An expired login or no connection is NotSent, and so
        is a 4xx: Google refused the request and did nothing."""
        return http_json("Google Calendar", method, API + path, token=self.access_token, transport=self.transport,
                         params=params, json=json, allow=allow)

    def _pages(self, path: str, params: dict) -> list[dict]:
        items, token = [], None
        for _ in range(50):
            page = self.request("GET", path, params={**params, **({"pageToken": token} if token else {})})
            items += page.get("items", [])
            token = page.get("nextPageToken")
            if not token:
                break
        return items

    def calendars(self) -> dict[str, dict]:
        if self._calendars is None:
            wanted = self.config.get("calendars")
            found = {}
            for item in self._pages("/users/me/calendarList", {"minAccessRole": "reader"}):
                if item.get("deleted") or item.get("hidden"):
                    continue
                ids = {item["id"], "primary"} if item.get("primary") else {item["id"]}
                if not wanted or ids & set(wanted):
                    found[item["id"]] = item
            if not found:
                raise PluginError(f"{self.ctx.instance}: no matching calendars")
            self._calendars = found
            primary = self._primary_id()
            if primary:
                self.owner_emails.add(primary.lower())
        return self._calendars

    def _primary_id(self) -> str | None:
        calendars = self._calendars if self._calendars is not None else self.calendars()
        return next((cid for cid, item in calendars.items() if item.get("primary")), None)

    def resolve_calendar(self, name: str | None) -> str:
        """A calendar id the agent may use: an id, its name, 'primary', or the default."""
        calendars = self.calendars()
        name = name or self.config.get("default_calendar") or "primary"
        if name == "primary":
            primary = self._primary_id()
            if primary:
                return primary
            raise PluginError("the primary calendar isn't among the configured calendars")
        if name in calendars:
            return name
        matches = [cid for cid, item in calendars.items() if item.get("summary") == name]
        if len(matches) == 1:
            return matches[0]
        raise Denied(f"no calendar {name}", "invalid")

    def zone_for(self, calendar: str) -> str | None:
        return self.zone or self.calendars().get(calendar, {}).get("timeZone")

    def is_shared(self, calendar: str) -> bool:
        """Writes to a calendar others can see reach them, so they count as sends."""
        if calendar in (self.config.get("shared_calendars") or []):
            return True
        cached = self._shared.get(calendar)
        if cached and time.monotonic() - cached[1] < self.SHARED_TTL:
            return cached[0]
        item = self.calendars().get(calendar, {})
        if item.get("accessRole") != "owner":
            shared = True  # someone else's calendar
        else:
            rules = self.request("GET", f"/calendars/{q(calendar)}/acl", allow=(403, 404))
            if rules is None:
                shared = True  # can't tell, so be careful
            else:
                shared = False
                for rule in rules.get("items", []):
                    scope, role = rule.get("scope", {}), rule.get("role")
                    if role == "none":
                        continue
                    if scope.get("type") == "user" and scope.get("value", "").lower() in self.owner_emails | {
                            calendar.lower()}:
                        continue
                    if role == "freeBusyReader":
                        continue  # others see only busy blocks, no titles
                    shared = True
                    break
        self._shared[calendar] = (shared, time.monotonic())
        return shared

    def outside(self, attendees: list[str]) -> list[str]:
        return [a for a in attendees if a.lower() not in self.owner_emails]

    def is_me(self, attendee: dict) -> bool:
        """The owner among an event's attendees, by address. Not Google's `self`: on someone else's calendar
        the owner may write to, that marks the calendar's owner, and answering for them isn't the owner's."""
        return (attendee.get("email") or "").lower() in self.owner_emails

    def state_from(self, calendar: str, event: dict) -> dict:
        start = event.get("start") or {}
        attendees = sorted(a["email"].lower() for a in event.get("attendees", [])
                           if a.get("email") and not a.get("resource"))
        raw = {k: event[k] for k in WRITABLE if k in event}
        mine = [a for a in event.get("attendees", []) if self.is_me(a)]
        organizer = event.get("organizer") or {}
        return {
            "id": event["id"],
            "calendar": calendar,
            "summary": event.get("summary", ""),
            "start": _when(start),
            "end": _when(event.get("end")),
            "all_day": "date" in start,
            "location": event.get("location", ""),
            "description": event.get("description", ""),
            "attendees": attendees,
            "organizer": organizer.get("email"),
            "recurring_event_id": event.get("recurringEventId"),
            "link": event.get("htmlLink"),
            "response": STATE_ANSWER.get(mine[0].get("responseStatus"), "needs-action") if mine else None,
            "_invited": self._invited(calendar, event),
            "_organizer_name": organizer.get("displayName"),
            "_raw": raw,
        }

    def _invited(self, calendar: str, event: dict) -> bool:
        """Organized by someone else: an event made on one of your calendars has that calendar (or you) as
        organizer, or Google marks it self."""
        organizer = event.get("organizer") or {}
        email = (organizer.get("email") or "").lower()
        if not email or organizer.get("self"):
            return False
        return email not in self.owner_emails | {calendar.lower()}

    def event_state(self, calendar: str, event_id: str) -> dict | None:
        event = self.request("GET", f"/calendars/{q(calendar)}/events/{q(event_id)}", allow=(404, 410))
        if event is None or event.get("status") == "cancelled":
            return None
        return self.state_from(calendar, event)

    def restore(self, ref: str, state: dict | None) -> None:
        """Make the event look like `state` again (None = it should not exist). Notifies nobody: only
        reversible changes are undone, and those never had outside attendees."""
        calendar, event_id = split_ref(ref)
        path = f"/calendars/{q(calendar)}/events/{q(event_id)}"
        if state is None:
            self.request("DELETE", path, params={"sendUpdates": "none"}, allow=(404, 410))
            return
        body = {**state["_raw"], "status": "confirmed"}
        # PUT also brings back a deleted event: Google keeps it, cancelled, under the same id
        if self.request("PUT", path, json=body, params={"sendUpdates": "none"}, allow=(404, 410)) is None:
            self.request("POST", f"/calendars/{q(calendar)}/events", json=body, params={"sendUpdates": "none"})

    # ---------------------------------------------------------------- reads

    def read_calendars(self, params):
        return [{"id": cid, "name": item.get("summary", cid), "primary": bool(item.get("primary")),
                 "access": item.get("accessRole"), "time_zone": item.get("timeZone"),
                 "shared": self.is_shared(cid)} for cid, item in self.calendars().items()]

    def _bound(self, value: str, calendar: str) -> str:
        field = time_field(value, self.zone_for(calendar) or "UTC")
        if "date" in field:
            return datetime.fromisoformat(field["date"]).replace(
                tzinfo=ZoneInfo(self.zone_for(calendar) or "UTC")).isoformat()
        parsed = datetime.fromisoformat(field["dateTime"])
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=ZoneInfo(field["timeZone"]))
        return parsed.isoformat()

    def read_events(self, params):
        ids = [self.resolve_calendar(params["calendar"])] if params.get("calendar") else list(self.calendars())
        events = []
        for calendar in ids:
            query = {"timeMin": self._bound(params["start"], calendar), "timeMax": self._bound(params["end"], calendar),
                     "singleEvents": "true", "orderBy": "startTime", "maxResults": 250}
            if params.get("query"):
                query["q"] = params["query"]
            for event in self._pages(f"/calendars/{q(calendar)}/events", query):
                if event.get("status") == "cancelled":
                    continue
                state = self.state_from(calendar, event)
                state.pop("_raw")
                state["ref"] = f"{self.ctx.instance}:{ref_of(calendar, event['id'])}"
                events.append(state)
        return sorted(events, key=lambda e: e["start"] or "")

    def poll_events(self, cursor):
        """New events organized by someone else (invitations) since the last poll, and entries starting
        within soon_minutes (default 30), once per occurrence."""
        state = calendar_cursor(cursor)
        seen = set(state["invites"])
        now = clock.now()
        entries = self.read_events({"start": now.isoformat(), "end": (now + timedelta(days=90)).isoformat()})
        events, current = [], set()
        for event in entries:
            # a recurring invitation counts once, not once per occurrence
            key = ref_of(event["calendar"], event.get("recurring_event_id") or event["id"])
            new = key not in seen and key not in current
            current.add(key)
            organizer = (event.get("organizer") or "").lower()
            if new and organizer and organizer not in self.owner_emails and cursor is not None:
                events.append({"type": "invite_received", "ref": event["ref"], "from": organizer,
                               "summary": event["summary"], "start": event["start"]})
        soon, announced = starting_soon(entries, state["soon"], soon_minutes(self.config), now)
        return events + soon, json.dumps({"invites": sorted(current), "soon": announced})

    # ---------------------------------------------------------------- Doorman's search index

    def index_feed(self, cursor, budget):
        """Every event series of the window (calendar_feed.window), one calendar at a time until the budget is
        spent. A series' key and ref name the series (its recurring_event_id): update_event, delete_event and
        respond take it for the whole series."""
        deadline = time.monotonic() + float(budget)
        start, end = calendar_feed.window(self.config)
        # Google's own generated calendars (week numbers, holidays, contacts' birthdays) aren't the owner's
        # entries: a "Kalenderwoche 45" for every week of three years would crowd every search
        calendars = {cid: item for cid, item in self.calendars().items() if not cid.endswith(GENERATED)}
        todo = calendar_feed.rotated(list(calendars), cursor)
        zone = ZoneInfo(self.zone) if self.zone else None  # where an all-day entry's day begins
        occurrences = []
        for i, calendar in enumerate(todo):
            if i and time.monotonic() >= deadline:
                return calendar_feed.answer(calendar_feed.event_items(occurrences, zone), calendar)
            name = calendars[calendar].get("summary") or calendar
            query = {"timeMin": start.isoformat(), "timeMax": end.isoformat(), "singleEvents": "true",
                     "orderBy": "startTime", "maxResults": 2500}
            for event in self._pages(f"/calendars/{q(calendar)}/events", query):
                if event.get("status") == "cancelled":
                    continue
                state = self.state_from(calendar, event)
                series = ref_of(calendar, event.get("recurringEventId") or event["id"])
                occurrences.append({
                    **state, "key": series, "ref": f"{self.ctx.instance}:{series}", "uid": event.get("iCalUID"),
                    "calendar": name, "organizer_name": state["_organizer_name"],
                    "recurring": bool(event.get("recurringEventId")),
                    "extra": {"status": event["status"]} if event.get("status") not in (None, "confirmed") else {}})
        return calendar_feed.answer(calendar_feed.event_items(occurrences, zone))
