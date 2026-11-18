"""Google Calendar plugin against a fake of Google's OAuth endpoints and Calendar API v3."""

import base64
import hashlib
import itertools
import json
from datetime import timedelta
from urllib.parse import parse_qs, unquote, urlparse
from zoneinfo import ZoneInfo

import httpx
import pytest
from fastapi.testclient import TestClient

from doorman import clock
from doorman.api.owner import create_owner_app
from doorman.approvals_util import notice_text, notice_title
from doorman.guard import Guard
from doorman.plugin_api import Denied, PluginError
from conftest import Agent, fake_scorer, make_engine

ME = "kim@gmail.example"
FAMILY = "family123@group.calendar.google.com"
WORK = "boss@company.example"  # someone else's calendar Kim may write to


class FakeGoogle:
    def __init__(self):
        self.ids = itertools.count(1)
        self.calendars = {
            ME: {"id": ME, "summary": ME, "primary": True, "accessRole": "owner", "timeZone": "Europe/Berlin"},
            FAMILY: {"id": FAMILY, "summary": "Family", "accessRole": "owner", "timeZone": "Europe/Berlin"},
            WORK: {"id": WORK, "summary": "Boss", "accessRole": "writer", "timeZone": "Europe/Berlin"},
        }
        self.acl = {
            ME: [{"scope": {"type": "user", "value": ME}, "role": "owner"},
                 {"scope": {"type": "default"}, "role": "none"}],
            FAMILY: [{"scope": {"type": "user", "value": ME}, "role": "owner"},
                     {"scope": {"type": "user", "value": "partner@example.org"}, "role": "writer"}],
        }
        self.events = {cid: {} for cid in self.calendars}
        self.writes = []  # (method, calendar, event id, sendUpdates)
        self.challenge = None
        self.codes = {"good-code"}
        self.refresh_tokens = {"rt-1"}
        self.revoked = []
        self.token_calls = 0

    def add(self, calendar, summary, start, end, attendees=(), organizer=ME, **extra):
        event_id = f"ev{next(self.ids)}"
        event = {"id": event_id, "status": "confirmed", "summary": summary, "start": {"dateTime": start},
                 "end": {"dateTime": end}, "organizer": {"email": organizer},
                 "htmlLink": f"https://calendar.example/{event_id}", "etag": "1", **extra}
        if attendees:
            event["attendees"] = [{"email": a} for a in attendees]
        self.events[calendar][event_id] = event
        return event_id

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.host == "oauth2.googleapis.com":
            return self.oauth(request)
        assert request.headers["Authorization"].startswith("Bearer at-"), "missing access token"
        path = unquote(url.raw_path.decode().split("?")[0]).removeprefix("/calendar/v3")
        params = dict(url.params)
        body = json.loads(request.content) if request.content else None
        if path == "/users/me/calendarList":
            return httpx.Response(200, json={"items": list(self.calendars.values())})
        parts = path.split("/")
        calendar = parts[2]
        if calendar not in self.calendars:
            return httpx.Response(404, json={"error": {"message": "Not Found"}})
        if parts[3] == "acl":
            if self.calendars[calendar]["accessRole"] != "owner":
                return httpx.Response(403, json={"error": {"message": "Forbidden"}})
            return httpx.Response(200, json={"items": self.acl.get(calendar, [])})
        events = self.events[calendar]
        if len(parts) == 4:
            if request.method == "POST":
                event_id = f"ev{next(self.ids)}"
                event = {"id": event_id, "status": "confirmed", "organizer": {"email": ME},
                         "htmlLink": f"https://calendar.example/{event_id}", **body}
                events[event_id] = event
                self.writes.append(("POST", calendar, event_id, params.get("sendUpdates")))
                return httpx.Response(200, json=event)
            items = [e for e in events.values() if e["status"] != "cancelled"
                     and params["timeMin"][:10] <= e["start"].get("dateTime", e["start"].get("date"))[:10]
                     < params["timeMax"][:10]]
            if params.get("q"):
                items = [e for e in items if params["q"].lower() in e.get("summary", "").lower()]
            return httpx.Response(200, json={"items": items})
        event_id = parts[4]
        event = events.get(event_id)
        if event is None:
            return httpx.Response(404, json={"error": {"message": "Not Found"}})
        if request.method == "GET":
            return httpx.Response(200, json=event)
        self.writes.append((request.method, calendar, event_id, params.get("sendUpdates")))
        if request.method == "DELETE":
            if event["status"] == "cancelled":
                return httpx.Response(410, json={"error": {"message": "Resource has been deleted"}})
            event["status"] = "cancelled"
            return httpx.Response(204)
        if request.method == "PATCH":
            event.update(body)
        elif request.method == "PUT":
            keep = {k: event[k] for k in ("id", "organizer", "htmlLink")}
            event.clear()
            event.update({"status": "confirmed", **body, **keep})
        return httpx.Response(200, json=event)

    def oauth(self, request):
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        if request.url.path == "/revoke":
            self.revoked.append(form["token"])
            self.refresh_tokens.discard(form["token"])
            return httpx.Response(200)
        assert form["client_id"] == "client.apps.example" and form["client_secret"] == "s3cret"
        self.token_calls += 1
        if form["grant_type"] == "authorization_code":
            verifier = form["code_verifier"]
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            if form["code"] not in self.codes or challenge != self.challenge:
                return httpx.Response(400, json={"error": "invalid_grant"})
            self.codes.discard(form["code"])
            return httpx.Response(200, json={"access_token": "at-new", "expires_in": 3599, "refresh_token": "rt-new",
                                             "scope": " ".join(scopes()), "token_type": "Bearer"})
        if form["refresh_token"] not in self.refresh_tokens and form["refresh_token"] != "rt-new":
            return httpx.Response(400, json={"error": "invalid_grant", "error_description": "Token has been revoked."})
        return httpx.Response(200, json={"access_token": "at-refreshed", "expires_in": 3599})


def scopes():
    return ["https://www.googleapis.com/auth/calendar.events",
            "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
            "https://www.googleapis.com/auth/calendar.acls.readonly"]


def make(tmp_path, connected=True, **config):
    engine = make_engine(tmp_path, plugins={
        "gcal": {"type": "google_calendar", "enabled": True,
                 "config": {"client_id": "client.apps.example", "timezone": "Europe/Berlin", **config}},
        "notes": {"enabled": True}})
    engine.vault.set("gcal", "client_secret", "s3cret")
    if connected:
        engine.vault.set("gcal", "refresh_token", "rt-1")
    google = FakeGoogle()
    plugin = engine.registry.instance("gcal")
    type(plugin).transport = httpx.MockTransport(google)  # class-level: survives rebuilt instances
    return engine, google


@pytest.fixture
def gcal(tmp_path):
    engine, google = make(tmp_path)
    return engine, Agent(engine), google


# ---------------------------------------------------------------- reads


def test_calendars_and_sharing(gcal):
    engine, agent, google = gcal
    calendars = {c["name"]: c for c in agent.read("gcal.calendars")}
    assert calendars[ME]["primary"] and not calendars[ME]["shared"]
    assert calendars["Family"]["shared"]          # the partner can write to it
    assert calendars["Boss"]["shared"]            # someone else's calendar


def test_events_read_expands_and_searches(gcal):
    engine, agent, google = gcal
    google.add(ME, "Haircut", "2026-11-10T09:00:00+01:00", "2026-11-10T10:00:00+01:00")
    google.add(ME, "Gym", "2026-11-11T18:00:00+01:00", "2026-11-11T19:00:00+01:00",
               recurringEventId="gymseries")
    events = agent.read("gcal.events", {"start": "2026-11-09", "end": "2026-11-16", "calendar": "primary"})
    assert [e["summary"] for e in events] == ["Haircut", "Gym"]
    assert events[1]["recurring_event_id"] == "gymseries"
    assert events[0]["ref"] == f"gcal:{ME}/{events[0]['id']}"
    found = agent.read("gcal.events", {"start": "2026-11-09", "end": "2026-11-16", "query": "hair"})
    assert [e["summary"] for e in found] == ["Haircut"]


def test_the_guard_scans_an_event_without_its_ids(gcal, monkeypatch):
    # not_scanned in the manifest: a secondary calendar's 64-character ID, the event ID and the base64 link
    # made a harmless three-word title score 0.67 with the real model
    engine, agent, google = gcal
    scanned = []

    def scorer(texts):
        scanned.extend(texts)
        return fake_scorer(texts)

    monkeypatch.setattr(Guard, "backend", staticmethod(scorer))
    google.add(FAMILY, "Draft: weekend trip", "2026-11-12T09:00:00+01:00", "2026-11-12T10:00:00+01:00",
               organizer="anna@uni.example")
    (event,) = agent.read("gcal.events", {"start": "2026-11-12", "end": "2026-11-13"})
    assert event["id"] and event["calendar"] == FAMILY and event["link"] and event["ref"]  # the agent still gets them
    (text,) = scanned
    fields = {line.split(":", 1)[0] for line in text.splitlines()}
    assert {"summary", "start", "organizer"} <= fields
    assert not fields & {"id", "calendar", "link", "ref"}
    assert "organizer: anna@uni.example" in text  # anyone picks that address on an invitation


def test_a_dentist_appointment_reaches_the_agent_as_a_placeholder(gcal):
    engine, agent, google = gcal
    google.add(ME, "Dentist", "2026-11-12T09:00:00+01:00", "2026-11-12T10:00:00+01:00")
    event = agent.read("gcal.events", {"start": "2026-11-12", "end": "2026-11-13"})[0]
    assert event["summary"].startswith("[Gesundheit PSN-")
    assert event["start"].startswith("2026-11-12T09:00") and event["id"]
    # the agent can move it without knowing what it is; the title stays "Dentist" at Google
    out = agent.call("gcal.update_event", {"id": event["id"], "changes": {
        "start": "2026-11-12T11:00:00+01:00", "end": "2026-11-12T12:00:00+01:00", "summary": event["summary"]}})
    assert out["status"] == "done", out
    stored = next(e for e in google.events[ME].values() if e["id"] == event["id"])
    assert stored["summary"] == "Dentist"


# ---------------------------------------------------------------- writes and tiers


def test_private_create_runs_silently_and_reverts(gcal):
    engine, agent, google = gcal
    out = agent.call("gcal.create_event", {"summary": "Focus", "start": "2026-11-12T09:00:00",
                                           "end": "2026-11-12T11:00:00"})
    assert out["status"] == "done", out
    event_id = out["result"]["id"]
    event = google.events[ME][event_id]
    assert event["start"] == {"dateTime": "2026-11-12T09:00:00", "timeZone": "Europe/Berlin"}
    assert google.writes[-1] == ("POST", ME, event_id, "none")
    engine.revert_entry(out["entry_id"])
    assert google.events[ME][event_id]["status"] == "cancelled"
    assert google.writes[-1] == ("DELETE", ME, event_id, "none")


def test_all_day_event(gcal):
    engine, agent, google = gcal
    out = agent.call("gcal.create_event", {"summary": "Trip", "start": "2026-11-20", "end": "2026-11-22"})
    assert google.events[ME][out["result"]["id"]]["start"] == {"date": "2026-11-20"}


def test_outside_attendees_need_approval_and_notify(gcal):
    engine, agent, google = gcal
    out = agent.call("gcal.create_event", {"summary": "Lunch", "start": "2026-11-12T12:00:00",
                                           "end": "2026-11-12T13:00:00", "attendees": ["anna@example.org"]})
    assert out["status"] == "waiting_approval"
    assert "anna@example.org" in out["warnings"][0]
    assert google.writes == []
    result = engine.approvals.decide(out["approval_id"], approve=True)["results"][0]
    assert result["status"] == "done"
    assert google.writes[-1][3] == "all"


def test_own_address_as_attendee_is_not_outside(gcal):
    engine, agent, google = gcal
    out = agent.call("gcal.create_event", {"summary": "Me", "start": "2026-11-12T12:00:00",
                                           "end": "2026-11-12T13:00:00", "attendees": [ME]})
    assert out["status"] == "done", out


def test_shared_calendar_write_is_a_send(gcal):
    engine, agent, google = gcal
    family = agent.call("gcal.create_event", {"calendar": "Family", "summary": "Dinner",
                                              "start": "2026-11-12T19:00:00", "end": "2026-11-12T21:00:00"})
    assert family["status"] == "waiting_approval"
    boss = agent.call("gcal.create_event", {"calendar": WORK, "summary": "Prep",
                                            "start": "2026-11-12T08:00:00", "end": "2026-11-12T09:00:00"})
    assert boss["status"] == "waiting_approval"
    assert "shared calendar" in engine.journal.get(boss["entry_id"])["summary"]
    assert google.writes == []


def test_shared_calendars_from_config(tmp_path):
    engine, google = make(tmp_path, shared_calendars=[ME])
    out = Agent(engine).call("gcal.create_event", {"summary": "x", "start": "2026-11-12T08:00:00",
                                                   "end": "2026-11-12T09:00:00"})
    assert out["status"] == "waiting_approval"


def test_update_single_occurrence_and_revert(gcal):
    engine, agent, google = gcal
    event_id = google.add(ME, "Gym", "2026-11-11T18:00:00+01:00", "2026-11-11T19:00:00+01:00",
                          recurringEventId="gymseries")
    out = agent.call("gcal.update_event", {"id": event_id, "changes": {"start": "2026-11-11T19:00:00+01:00",
                                                                        "end": "2026-11-11T20:00:00+01:00"}})
    assert out["status"] == "done", out
    assert google.events[ME][event_id]["start"]["dateTime"] == "2026-11-11T19:00:00+01:00"
    diff = engine.entry_view(engine.journal.get(out["entry_id"]))["diff"]
    assert {"sign": "-", "field": "start", "value": "2026-11-11T18:00:00+01:00"} in diff
    engine.revert_entry(out["entry_id"])
    assert google.events[ME][event_id]["start"]["dateTime"] == "2026-11-11T18:00:00+01:00"
    assert google.writes[-1] == ("PUT", ME, event_id, "none")


def test_invitation_from_someone_else(gcal):
    """Its shared fields are the organizer's; deleting it declines it, so that's a send to the organizer."""
    engine, agent, google = gcal
    # the organizer isn't even in the attendee list here, so only the organizer check catches it
    event_id = google.add(ME, "Team", "2026-11-11T10:00:00+01:00", "2026-11-11T11:00:00+01:00",
                          organizer="lead@company.example")
    with pytest.raises(Denied, match="lead@company.example's invitation"):
        agent.call("gcal.update_event", {"id": event_id, "changes": {"summary": "Team (moved)"}})
    deleted = agent.call("gcal.delete_event", {"id": event_id})
    assert deleted["status"] == "waiting_approval"
    assert "lead@company.example" in deleted["warnings"][0]
    assert google.writes == []
    engine.approvals.decide(deleted["approval_id"], approve=True)
    assert google.writes[-1] == ("DELETE", ME, event_id, "all")


def test_events_on_secondary_calendars_are_not_invitations(gcal):
    """Events made on a secondary calendar have that calendar as organizer."""
    engine, agent, google = gcal
    google.acl[FAMILY] = google.acl[ME]  # unshare it, so only the organizer rule could make it a send
    event_id = google.add(FAMILY, "Birthday", "2026-11-11T10:00:00+01:00", "2026-11-11T11:00:00+01:00",
                          organizer=FAMILY)
    out = agent.call("gcal.delete_event", {"calendar": FAMILY, "id": event_id})
    assert out["status"] == "done", out


def test_delete_and_restore(gcal):
    engine, agent, google = gcal
    event_id = google.add(ME, "Haircut", "2026-11-13T15:00:00+01:00", "2026-11-13T16:00:00+01:00",
                          location="Salon")
    out = agent.call("gcal.delete_event", {"id": event_id})
    assert out["status"] == "done"
    assert google.events[ME][event_id]["status"] == "cancelled"
    assert google.writes[-1] == ("DELETE", ME, event_id, "none")
    engine.revert_entry(out["entry_id"])
    restored = google.events[ME][event_id]
    assert restored["status"] == "confirmed" and restored["location"] == "Salon"


def test_revert_refuses_after_someone_changed_the_event(gcal):
    engine, agent, google = gcal
    out = agent.call("gcal.create_event", {"summary": "Focus", "start": "2026-11-12T09:00:00",
                                           "end": "2026-11-12T11:00:00"})
    google.events[ME][out["result"]["id"]]["summary"] = "Focus (edited on the phone)"
    result = engine.revert_entry(out["entry_id"])
    assert result["conflicts"] and not result["reverted"]


def test_unknown_calendar_is_denied(gcal):
    engine, agent, google = gcal
    with pytest.raises(Denied):
        agent.call("gcal.create_event", {"calendar": "nope", "summary": "x", "start": "2026-11-12T09:00:00",
                                         "end": "2026-11-12T10:00:00"})


def test_invitation_trigger_counts_a_series_once(gcal):
    engine, agent, google = gcal
    plugin = engine.registry.instance("gcal")
    _, cursor = plugin.poll_events(None)
    for day in (20, 27):
        google.add(ME, "Standup", f"2026-11-{day}T09:00:00+01:00", f"2026-11-{day}T09:15:00+01:00",
                   attendees=[ME, "lead@company.example"], organizer="lead@company.example",
                   recurringEventId="standup")
    events, cursor = plugin.poll_events(cursor)
    assert [e["summary"] for e in events] == ["Standup"]
    events, _ = plugin.poll_events(cursor)
    assert events == []


# ---------------------------------------------------------------- login


def test_login_flow_with_pasted_address(tmp_path):
    engine, google = make(tmp_path, connected=False)
    status = engine.plugin_setup.login_status("gcal")
    assert status == {"connected": False, "account": None, "ready": True}
    with pytest.raises(PluginError, match="isn't connected"):
        Agent(engine).read("gcal.calendars")

    start = engine.plugin_setup.login_start("gcal")
    query = parse_qs(urlparse(start["auth_url"]).query)
    assert query["redirect_uri"] == ["http://127.0.0.1:8799/"]
    assert query["code_challenge_method"] == ["S256"] and query["access_type"] == ["offline"]
    assert "calendar.events" in query["scope"][0]
    google.challenge = query["code_challenge"][0]

    with pytest.raises(Denied, match="different login"):
        engine.plugin_setup.login_finish("gcal", "http://127.0.0.1:8799/?state=forged&code=good-code")
    result = engine.plugin_setup.login_finish(
        "gcal", f"http://127.0.0.1:8799/?state={query['state'][0]}&code=good-code&scope=x")
    assert result == {"connected": True, "account": ME}
    assert engine.vault.get("gcal")["refresh_token"] == "rt-new"
    assert engine.plugin_setup.login_status("gcal")["connected"]
    assert "Connected gcal" in engine.journal.list(limit=1, include_denied=True)[0]["summary"]
    # the pending login is used up
    with pytest.raises(Denied, match="no login in progress"):
        engine.plugin_setup.login_finish("gcal", f"http://127.0.0.1:8799/?state={query['state'][0]}&code=good-code")
    assert Agent(engine).read("gcal.calendars")


def test_login_error_and_logout(tmp_path):
    engine, google = make(tmp_path, connected=False)
    engine.plugin_setup.login_start("gcal")
    with pytest.raises(Denied, match="access_denied"):
        engine.plugin_setup.login_finish("gcal", "http://127.0.0.1:8799/?error=access_denied")

    engine, google = make(tmp_path / "b")
    assert engine.plugin_setup.logout("gcal") == {"connected": False}
    assert google.revoked == ["rt-1"]
    assert "refresh_token" not in engine.vault.get("gcal")
    plugins = {p["name"]: p for p in engine.registry.list()}
    assert plugins["gcal"]["missing_credentials"] == ["refresh_token"] and plugins["gcal"]["login"] == "oauth"


def invite_anna(engine, agent):
    out = agent.call("gcal.create_event", {"summary": "Lunch", "start": "2026-11-12T12:00:00",
                                           "end": "2026-11-12T13:00:00", "attendees": ["anna@example.org"]})
    assert out["status"] == "waiting_approval"
    return out


def approved_entry(engine, out):
    engine.approvals.decide(out["approval_id"], approve=True)
    entry = engine.journal.get(out["entry_id"])
    kinds = {a["kind"] for a in engine.attention_list() if a["ref"] == str(out["entry_id"])}
    return entry, kinds


def failing_google(google, error, when=lambda request: True):
    def handler(request):
        if request.url.host == "www.googleapis.com" and when(request):
            raise error("boom", request=request)
        return google(request)
    return httpx.MockTransport(handler)


def test_an_invitation_approved_after_the_login_expired_failed_and_says_to_reconnect(gcal):
    engine, agent, google = gcal
    out = invite_anna(engine, agent)
    google.refresh_tokens.clear()
    engine.registry.instance("gcal")._token = None  # the hour-long access token ran out as well
    entry, kinds = approved_entry(engine, out)
    assert entry["status"] == "failed" and "connect the account again" in entry["error"], entry
    assert kinds == {"send_failed"} and google.writes == []


def test_an_invitation_that_never_reached_google_failed(gcal, monkeypatch):
    engine, agent, google = gcal
    out = invite_anna(engine, agent)
    plugin = engine.registry.instance("gcal")
    monkeypatch.setattr(type(plugin), "transport", failing_google(google, httpx.ConnectError))
    entry, kinds = approved_entry(engine, out)
    assert entry["status"] == "failed" and "Google Calendar unreachable" in entry["error"], entry
    assert kinds == {"send_failed"}


def test_an_invitation_whose_answer_timed_out_is_unknown(gcal, monkeypatch):
    engine, agent, google = gcal
    out = invite_anna(engine, agent)
    plugin = engine.registry.instance("gcal")
    monkeypatch.setattr(type(plugin), "transport", failing_google(google, httpx.ReadTimeout,
                                                                  lambda request: request.method == "POST"))
    entry, kinds = approved_entry(engine, out)
    assert entry["status"] == "unknown" and "may have gone out" in entry["error"], entry
    assert kinds == {"send_unknown"}


def test_revoked_refresh_token_says_to_reconnect(gcal):
    engine, agent, google = gcal
    google.refresh_tokens.clear()
    with pytest.raises(PluginError, match="connect the account again"):
        agent.read("gcal.calendars")


def test_not_set_up_without_client_secret(tmp_path):
    engine = make_engine(tmp_path, plugins={"gcal": {"type": "google_calendar", "enabled": True,
                                                     "config": {"client_id": "x"}}})
    assert engine.plugin_setup.login_status("gcal")["ready"] is False
    with pytest.raises(PluginError, match="client secret"):
        engine.plugin_setup.login_start("gcal")


def test_cli_login_from_another_process_reaches_the_running_doorman(tmp_path):
    """doorman-admin login writes the vault from another process; the server's instance must notice."""
    engine, google = make(tmp_path, connected=False)
    with pytest.raises(PluginError):
        Agent(engine).read("gcal.calendars")
    other = make_engine(tmp_path, plugins={})  # same data dir: the same vault, and gcal in the database
    other.vault.set("gcal", "refresh_token", "rt-1")
    assert Agent(engine).read("gcal.calendars")


def test_interactive_login_takes_a_pasted_address(tmp_path):
    engine, google = make(tmp_path, connected=False)
    plugin = engine.registry.instance("gcal")
    said = []

    def paste(_prompt):
        url = next(line for line in said if line.startswith("https://accounts.google.com"))
        query = parse_qs(urlparse(url.strip()).query)
        google.challenge = query["code_challenge"][0]
        return f"http://127.0.0.1:8799/?state={query['state'][0]}&code=good-code"

    plugin.config["redirect_port"] = 0  # don't hold a fixed port in tests
    plugin.interactive_login(said.append, read_line=paste,
                             finish=lambda url: engine.plugin_setup.login_finish("gcal", url))
    assert said[-1] == f"Connected {ME}."


def test_owner_api_login_endpoints(tmp_path):
    engine, google = make(tmp_path, connected=False)
    engine.config["dev_owner_token"] = "dev"
    owner = TestClient(create_owner_app(engine), headers={"Authorization": "Bearer dev"})
    assert owner.get("/owner/plugins/gcal/login").json()["ready"] is True
    start = owner.post("/owner/plugins/gcal/login/start").json()
    query = parse_qs(urlparse(start["auth_url"]).query)
    google.challenge = query["code_challenge"][0]
    empty = owner.post("/owner/plugins/gcal/login/finish", json={"url": " "})
    assert empty.status_code == 403
    done = owner.post("/owner/plugins/gcal/login/finish",
                      json={"url": f"http://127.0.0.1:8799/?state={query['state'][0]}&code=good-code"})
    assert done.status_code == 200 and done.json()["account"] == ME
    assert owner.post("/owner/plugins/notes/login/start").status_code == 403
    assert owner.post("/owner/plugins/gcal/logout").json() == {"connected": False}


def test_revert_keeps_what_the_owner_changed_since(gcal):
    engine, agent, google = gcal
    event_id = google.add(ME, "Dentist", "2026-11-10T09:00:00+01:00", "2026-11-10T10:00:00+01:00")
    out = agent.call("gcal.update_event", {"id": event_id, "changes": {"start": "2026-11-10T11:00:00+01:00",
                                                                        "end": "2026-11-10T12:00:00+01:00"}})
    google.events[ME][event_id]["summary"] = "Dentist (bring card)"  # the owner, on the phone
    result = engine.revert_entry(out["entry_id"])
    assert result["reverted"] == [out["entry_id"]], result
    event = google.events[ME][event_id]
    assert event["start"]["dateTime"] == "2026-11-10T09:00:00+01:00" and event["summary"] == "Dentist (bring card)"
    assert google.writes[-1] == ("PATCH", ME, event_id, "none")


def test_revoked_google_login_needs_attention(gcal):
    engine, agent, google = gcal
    assert engine.check_plugins(force=True)["gcal"] is None
    google.refresh_tokens.clear()  # the owner removed the app's access in their Google account
    problem = engine.check_plugins(force=True)["gcal"]
    assert "connect the account again" in problem
    assert [i["title"] for i in engine.attention_list()] == ["gcal isn't working"]


def test_unconnected_google_needs_attention(tmp_path):
    engine, google = make(tmp_path, connected=False)
    assert engine.check_plugins(force=True)["gcal"] == "not connected: connect it under Plugins"


# ---------------------------------------------------------------- answering invitations


def thesis(google, **extra):
    """Dr. Jansen's invitation with Kim and Anna as guests, as Google lists it on Kim's calendar."""
    event_id = google.add(ME, "Thesis meeting", "2026-11-10T10:00:00+01:00", "2026-11-10T11:00:00+01:00",
                          organizer="jansen@uni.example", **extra)
    event = google.events[ME][event_id]
    event["organizer"]["displayName"] = "Dr. Jansen"
    event["attendees"] = [{"email": "jansen@uni.example", "organizer": True, "responseStatus": "accepted"},
                          {"email": ME, "self": True, "responseStatus": "needsAction"},
                          {"email": "anna@example.com", "responseStatus": "needsAction"}]
    return event_id


def test_respond_waits_and_tells_the_organizer(gcal):
    engine, agent, google = gcal
    event_id = thesis(google)
    [listed] = agent.read("gcal.events", {"start": "2026-11-10", "end": "2026-11-11"})
    assert listed["response"] == "needs-action"
    out = agent.call("gcal.respond", {"id": event_id, "response": "accept", "comment": "See you there"})
    assert out["status"] == "waiting_approval"
    assert out["warnings"] == []  # answering the organizer is no new recipient
    assert google.writes == []
    approval = engine.approvals.get(out["approval_id"])
    [entry] = approval["entries"]
    assert entry["args"]["to"] == "jansen@uni.example" and entry["editable"] == ["comment"]
    assert entry["summary"] == "Tell jansen@uni.example you accept their invitation"
    assert entry["outgoing"] == {
        "label": "Your answer to the invitation", "title": "Thesis meeting, Tue 10 Nov, 10:00",
        "text": "Tells Dr. Jansen (jansen@uni.example) you accept “Thesis meeting”, Tue 10 Nov, 10:00.\n"
                "Your comment: See you there"}
    assert notice_title([entry]) == "Send to jansen@uni.example"
    assert "Tells Dr. Jansen (jansen@uni.example) you accept" in notice_text([entry])

    # the owner rewrites the comment, then approves
    edited = engine.approvals.edit(out["approval_id"], out["entry_id"], {"comment": "See you at 10"},
                                  approval["payload_hash"])
    engine.approvals.decide(edited["approval_id"], approve=True)
    assert google.writes == [("PATCH", ME, event_id, "all")]
    attendees = {a["email"]: a for a in google.events[ME][event_id]["attendees"]}
    assert attendees[ME]["responseStatus"] == "accepted" and attendees[ME]["comment"] == "See you at 10"
    assert attendees["anna@example.com"] == {"email": "anna@example.com", "responseStatus": "needsAction"}
    done = engine.journal.get(edited["entry_id"])
    assert done["status"] == "done" and done["result"]["response"] == "accepted"
    assert done["summary"] == "Told jansen@uni.example you accept"


def test_respond_to_one_occurrence_or_the_series(gcal):
    engine, agent, google = gcal
    occurrence = thesis(google, recurringEventId="thesisseries")
    out = agent.call("gcal.respond", {"id": occurrence, "response": "tentative"})
    text = engine.approvals.get(out["approval_id"])["entries"][0]["outgoing"]["text"]
    assert text.startswith("Tells Dr. Jansen (jansen@uni.example) you tentatively accept")
    assert text.endswith("(this occurrence only).")
    series = thesis(google, recurrence=["RRULE:FREQ=WEEKLY"])
    out = agent.call("gcal.respond", {"id": series, "response": "decline"})
    assert engine.approvals.get(out["approval_id"])["entries"][0]["outgoing"]["text"].endswith("(the whole series).")


def test_respond_needs_someone_elses_invitation_with_you_as_guest(gcal):
    engine, agent, google = gcal
    own = google.add(ME, "Focus", "2026-11-10T09:00:00+01:00", "2026-11-10T10:00:00+01:00")
    with pytest.raises(Denied, match="your own event"):
        agent.call("gcal.respond", {"id": own, "response": "accept"})
    told = google.add(ME, "Team", "2026-11-11T10:00:00+01:00", "2026-11-11T11:00:00+01:00",
                      organizer="lead@company.example")  # on the calendar, but not on the guest list
    with pytest.raises(Denied, match="aren't among this event's guests"):
        agent.call("gcal.respond", {"id": told, "response": "accept"})
    # on the boss's calendar Google marks the boss as `self`: answering for them isn't Kim's to do
    boss = google.add(WORK, "Board", "2026-11-11T14:00:00+01:00", "2026-11-11T15:00:00+01:00",
                      organizer="ceo@company.example")
    google.events[WORK][boss]["attendees"] = [{"email": WORK, "self": True, "responseStatus": "needsAction"}]
    with pytest.raises(Denied, match="aren't among this event's guests"):
        agent.call("gcal.respond", {"calendar": WORK, "id": boss, "response": "accept"})
    assert google.writes == []


def test_respond_fails_cleanly_when_the_organizer_changed(gcal):
    engine, agent, google = gcal
    event_id = thesis(google)
    out = agent.call("gcal.respond", {"id": event_id, "response": "decline"})
    google.events[ME][event_id]["organizer"] = {"email": "someone@else.example"}
    # what the approval showed (whom the answer goes to) isn't so any more: it no longer matches
    with pytest.raises(Denied) as exc:
        engine.approvals.decide(out["approval_id"], approve=True)
    assert exc.value.code == "payload_changed"
    assert engine.journal.get(out["entry_id"])["status"] == "rejected"
    assert google.writes == []


# ---------------------------------------------------------------- doorman search (calendar_feed.py)


_NOW: list = []  # this test's "now", taken once: on a busy machine a second passes between two at() calls


@pytest.fixture(autouse=True)
def _one_now():
    _NOW[:] = [clock.now().replace(microsecond=0)]
    yield
    _NOW.clear()


def at(days, hours=0):
    """A time `days` from this test's now in Berlin, as Google writes it."""
    moment = (_NOW[0] if _NOW else clock.now().replace(microsecond=0)) + timedelta(days=days, hours=hours)
    return moment.astimezone(ZoneInfo("Europe/Berlin")).isoformat()


def find(agent, **params):
    return agent.engine.search.any_word(agent.session, agent.key, params)


@pytest.fixture
def filled(gcal):
    """A weekly gym series (last week, tomorrow, next week), a haircut two months ago, the family's summer party
    in six weeks, and a trip three years ago (out of the window)."""
    engine, agent, google = gcal
    for days in (-7, 1, 8):
        google.add(ME, "Gym", at(days), at(days, 1), recurringEventId="gymseries", iCalUID="gym@google.com")
    haircut = google.add(ME, "Haircut", at(-60), at(-60, 1))
    party = google.add(FAMILY, "Sommerfest", at(40), at(40, 5), location="Kleingarten Nord",
                       description="Bitte Salat mitbringen", attendees=[ME, "oma@example.org"],
                       organizer="oma@example.org")
    google.events[FAMILY][party]["organizer"]["displayName"] = "Oma"
    google.add(ME, "Trip to Rome", at(-3 * 365), at(-3 * 365, 2))
    return engine, agent, google, haircut, party


def test_the_feed_has_one_item_per_series_dated_by_its_next_occurrence(filled):
    engine, agent, google, haircut, party = filled
    assert engine.search.pull("gcal")["changed"] == 3
    assert engine.library.keys("gcal") == {f"{ME}/gymseries", f"{ME}/{haircut}", f"{FAMILY}/{party}"}
    gym = engine.library.get("gcal", f"{ME}/gymseries")
    assert (gym["kind"], gym["ref"], gym["title"], gym["date"], gym["place"], gym["same"].split("|")[0]) == (
        "event", f"gcal:{ME}/gymseries", "Gym", at(1), ME, "uid:gym@google.com")  # with a hash of what it says
    assert gym["fields"] == {"summary": "Gym", "start": at(1), "end": at(1, 1), "all_day": False, "calendar": ME,
                             "organizer": ME, "recurring": True, "occurrences": 3}
    summer = engine.library.get("gcal", f"{FAMILY}/{party}")
    assert (summer["ref"], summer["place"], summer["sender"]) == (f"gcal:{FAMILY}/{party}", "Family",
                                                                  "oma <oma@example.org>")
    assert summer["parts"][0]["text"] == f"Bitte Salat mitbringen\nKleingarten Nord\n{ME}, oma@example.org"
    assert engine.library.get("gcal", f"{ME}/{haircut}")["date"] == at(-60)  # no next one: its last
    # the series is what its ref names: the tools take it for every occurrence
    assert agent.read("gcal.events", {"start": at(0), "end": at(2)})[0]["recurring_event_id"] == "gymseries"
    del google.events[ME][haircut]
    assert engine.search.pull("gcal")["removed"] == 1


def test_search_finds_events_by_words_place_and_time(filled):
    engine, agent, google, haircut, party = filled
    engine.search.pull("gcal")
    [hit] = find(agent, query="Salat")["results"]
    assert (hit["source"], hit["kind"], hit["title"], hit["calendar"], hit["location"]) == (
        "gcal", "event", "Sommerfest", "Family", "Kleingarten Nord")
    assert hit["passage"] == f"Bitte Salat mitbringen Kleingarten Nord {ME}, oma@example.org"
    assert [h["title"] for h in find(agent, kind="event", **{"in": "family"})["results"]] == ["Sommerfest"]
    assert [h["title"] for h in find(agent, kind="event", since=at(0)[:10])["results"]] == ["Sommerfest", "Gym"]
    assert [h["title"] for h in find(agent, query="haircut", until=at(-30)[:10])["results"]] == ["Haircut"]
    assert [h["title"] for h in find(agent, **{"from": "oma"})["results"]] == ["Sommerfest"]
    assert find(agent, query="Rome")["results"] == []  # out of the window


def test_the_same_event_in_two_calendars_comes_once(gcal):
    engine, agent, google = gcal
    start, end = at(3), at(3, 3)  # once: a second can pass between two at() calls on a busy machine
    refs = {f"gcal:{calendar}/{google.add(calendar, 'Lena’s birthday party', start, end, iCalUID='party@x')}"
            for calendar in (ME, FAMILY)}
    engine.search.pull("gcal")
    [hit] = find(agent, query="birthday")["results"]
    [also] = hit["also"]
    assert {hit["ref"], also["ref"]} == refs
    assert also == {"source": "gcal", "ref": also["ref"], "title": "Lena’s birthday party", "date": start}


def test_pseudonyms_hide_a_dentist_appointment_in_search(gcal):
    engine, agent, google = gcal
    google.add(ME, "Zahnarzt Dr. Weber", at(2), at(2, 1), description="Kontrolle, danach Pizza")
    engine.search.pull("gcal")
    assert find(agent, query="Pizza")["results"] == []  # found only by what the placeholders hide
    [hit] = find(agent, kind="event", since=at(1)[:10], until=at(3)[:10])["results"]
    assert "Zahnarzt" not in str(hit) and "Weber" not in str(hit)
    assert hit["title"].startswith("[Gesundheit PSN-") and hit["summary"].startswith("[Gesundheit PSN-")
    assert hit["passage"].startswith("[Gesundheit PSN-") and hit["start"] == at(2) and hit["source"] == "gcal"


def test_googles_own_generated_calendars_stay_out_of_search(filled):
    """Week numbers, holidays and birthdays are calendars Google makes, not the owner's entries."""
    engine, agent, google, _, _ = filled
    weeks = "e_2_de#weeknum@group.v.calendar.google.com"
    google.calendars[weeks] = {"id": weeks, "summary": "Kalenderwochen", "accessRole": "reader"}
    google.events[weeks] = {}
    google.add(weeks, "Kalenderwoche 46", at(2), at(3))
    engine.search.pull("gcal")
    assert not any(k.startswith(weeks) for k in engine.library.keys("gcal"))
    assert any(e["summary"] == "Kalenderwoche 46" for e in agent.read("gcal.events", {"start": at(0), "end": at(5)}))
