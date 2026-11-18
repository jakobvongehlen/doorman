"""The caldav plugin (calendars and task lists, one login) against a real Radicale server."""

import importlib.util
import json
import time
from datetime import timedelta, timezone
from pathlib import Path

import caldav
import pytest

import doorman
from doorman import clock
from doorman.plugin_api import Denied, PluginError
from conftest import Agent, make_engine

pytestmark = pytest.mark.integration


@pytest.fixture
def radicale(radicale_server):
    """A user of its own on the session's Radicale (conftest.py), so a fresh set of collections: Personal
    (events and tasks, like Nextcloud's), Todo (tasks only) and Events (events only)."""
    dav = radicale_server.new_user()
    principal = caldav.DAVClient(url=dav.url, username=dav.user, password="x", require_tls=False).principal()
    principal.make_calendar(name="Personal")
    principal.make_calendar(name="Todo", supported_calendar_component_set=["VTODO"])
    principal.make_calendar(name="Events", supported_calendar_component_set=["VEVENT"])
    return dav


def setup(tmp_path, dav, **config):
    engine = make_engine(tmp_path, plugins={"caldav": {"enabled": True, "config": {
        "url": dav.url, "allow_http": True, "owner_emails": ["me@example.com"], "timezone": "Europe/Berlin",
        **config}}})
    engine.vault.set("caldav", "username", dav.user)
    engine.vault.set("caldav", "password", "x")
    return engine, Agent(engine)


@pytest.fixture
def cal(tmp_path, radicale):
    return setup(tmp_path, radicale, default_calendar="Personal", default_list="Todo")


def gym(agent):
    return agent.call("caldav.create_event", {"summary": "Gym", "start": "2026-11-05T08:00:00+01:00",
                                              "end": "2026-11-05T09:00:00+01:00"})


def week(agent):
    return agent.read("caldav.events", {"start": "2026-11-01", "end": "2026-11-10"})


# one plugin, one login, both kinds of collection


def test_collections_are_sorted_by_what_they_hold(cal):
    engine, agent = cal
    assert sorted(c["name"] for c in agent.read("caldav.calendars")) == ["Events", "Personal"]
    assert sorted(c["name"] for c in agent.read("caldav.lists")) == ["Personal", "Todo"]


def test_config_picks_collections_and_an_empty_list_turns_a_kind_off(tmp_path, radicale):
    engine, agent = setup(tmp_path, radicale, calendars=[], lists="Todo")  # "Todo": typed without brackets
    assert agent.read("caldav.calendars") == []
    assert agent.read("caldav.lists") == [{"name": "Todo", "shared": False}]
    out = agent.call("caldav.create_event", {"summary": "x", "start": "2026-11-05", "end": "2026-11-06"})
    assert out["status"] == "failed" and "no calendars to use" in out["error"]
    assert agent.call("caldav.create_task", {"summary": "Buy ink"})["status"] == "done"
    plugin = engine.registry.instance("caldav")
    assert plugin.poll_events(None) == ([], None)  # no calendars: nothing to poll, no error
    assert plugin.check() is None


def test_check_reports_named_collections_the_server_lacks(tmp_path, radicale):
    engine, _ = setup(tmp_path, radicale, calendars=["Personal", "Work"], lists=["Shopping"])
    assert engine.registry.instance("caldav").check() == "not on the server: Work, Shopping"


# events


def test_create_read_update_revert(cal):
    engine, agent = cal
    created = gym(agent)
    assert created["status"] == "done", created
    uid = created["result"]["uid"]
    events = week(agent)
    assert [(e["summary"], e["calendar"]) for e in events] == [("Gym", "Personal")]
    assert events[0]["ref"] == f"caldav:{uid}"

    moved = agent.call("caldav.update_event", {"uid": uid, "changes": {
        "start": "2026-11-06T08:00:00+01:00", "end": "2026-11-06T09:00:00+01:00"}})
    assert moved["status"] == "done", moved
    diff = engine.entry_view(engine.journal.get(moved["entry_id"]))["diff"]
    assert {"sign": "-", "field": "start", "value": "2026-11-05T08:00:00+01:00"} in diff
    assert {"sign": "+", "field": "start", "value": "2026-11-06T08:00:00+01:00"} in diff

    assert engine.revert_entry(moved["entry_id"])["reverted"] == [moved["entry_id"]]
    assert week(agent)[0]["start"] == "2026-11-05T08:00:00+01:00"


def test_an_event_without_an_end_takes_an_hour_and_says_so(cal):
    engine, agent = cal
    out = agent.call("caldav.create_event", {"summary": "Group meeting", "start": "2026-11-09T14:00:00+01:00"})
    assert out["status"] == "done", out
    assert out["result"]["end"] == "2026-11-09T15:00:00+01:00" and "one hour" in out["result"]["note"]
    [event] = [e for e in week(agent) if e["summary"] == "Group meeting"]
    assert event["end"].startswith("2026-11-09T15:00")
    day = agent.call("caldav.create_event", {"summary": "Trip", "start": "2026-11-07"})
    assert day["result"]["end"] == "2026-11-08" and "all day" in day["result"]["note"]
    assert "note" not in gym(agent)["result"]  # an end given: nothing to say


def test_delete_and_revert_recreates_same_uid(cal):
    engine, agent = cal
    uid = gym(agent)["result"]["uid"]
    deleted = agent.call("caldav.delete_event", {"uid": uid})
    assert week(agent) == []
    engine.revert_entry(deleted["entry_id"])
    assert [e["uid"] for e in week(agent)] == [uid]


def test_drift_is_detected(cal):
    engine, agent = cal
    uid = gym(agent)["result"]["uid"]
    renamed = agent.call("caldav.update_event", {"uid": uid, "changes": {"summary": "Gym (short)"}})
    # the owner edits the event in another app
    resource = engine.registry.instance("caldav").find_event(uid)[1]
    component = resource.icalendar_component
    component.pop("summary")
    component.add("summary", "Gym with Anna")
    resource.save()
    result = engine.revert_entry(renamed["entry_id"])
    assert result["conflicts"][0]["now"]["summary"] == "Gym with Anna"


def test_outside_attendees_make_it_a_send(cal):
    engine, agent = cal
    out = agent.call("caldav.create_event", {"summary": "Sync", "start": "2026-11-05T10:00:00+01:00",
                                             "end": "2026-11-05T10:30:00+01:00",
                                             "attendees": ["me@example.com", "anna@example.com"]})
    assert out["status"] == "waiting_approval"
    assert "anna@example.com" in out["warnings"][0]
    engine.approvals.decide(out["approval_id"], approve=True)
    events = week(agent)
    assert events[0]["attendees"] == ["anna@example.com", "me@example.com"]
    # changing that event later is also a send
    change = agent.call("caldav.update_event", {"uid": events[0]["uid"], "changes": {"summary": "Sync!"}})
    assert change["status"] == "waiting_approval"


def test_invitation_from_someone_else(cal):
    """An event organized by someone else: deleting declines it (a send), editing is refused."""
    engine, agent = cal
    plugin = engine.registry.instance("caldav")
    ics = (
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:invite-1@company.example\r\n"
        "DTSTAMP:20261101T080000Z\r\nDTSTART:20261106T090000Z\r\nDTEND:20261106T100000Z\r\nSUMMARY:Review\r\n"
        "ORGANIZER:mailto:lead@company.example\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
    plugin.calendar(None).add_event(ics)
    with pytest.raises(Denied, match="lead@company.example's invitation"):
        agent.call("caldav.update_event", {"uid": "invite-1@company.example", "changes": {"summary": "x"}})
    out = agent.call("caldav.delete_event", {"uid": "invite-1@company.example"})
    assert out["status"] == "waiting_approval"
    assert "lead@company.example" in out["warnings"][0]


def test_revert_keeps_what_the_owner_changed_since(cal):
    engine, agent = cal
    uid = gym(agent)["result"]["uid"]
    moved = agent.call("caldav.update_event", {"uid": uid, "changes": {
        "start": "2026-11-05T18:00:00+01:00", "end": "2026-11-05T19:00:00+01:00"}})
    resource = engine.registry.instance("caldav").find_event(uid)[1]
    resource.icalendar_component.add("location", "New gym")  # the owner, in another app
    resource.save()
    result = engine.revert_entry(moved["entry_id"])
    assert result["reverted"] == [moved["entry_id"]], result
    event = week(agent)[0]
    assert event["start"] == "2026-11-05T08:00:00+01:00" and event["location"] == "New gym"


# tasks


def test_create_update_complete_and_revert_a_task(cal):
    engine, agent = cal
    made = agent.call("caldav.create_task", {"summary": "Hand in thesis draft", "due": "2026-11-20",
                                             "priority": 1, "tags": ["thesis"]})
    assert made["status"] == "done", made
    uid = made["result"]["uid"]
    [task] = agent.read("caldav.tasks")
    assert task | {"ref": None} == {"uid": uid, "list": "Todo", "summary": "Hand in thesis draft", "description": "",
                                    "due": "2026-11-20", "priority": 1, "tags": ["thesis"], "done": False,
                                    "completed_at": None, "ref": None}

    moved = agent.call("caldav.update_task", {"uid": uid, "changes": {"due": "2026-11-27T12:00:00", "priority": None}})
    assert moved["status"] == "done", moved
    diff = engine.entry_view(engine.journal.get(moved["entry_id"]))["diff"]
    assert {"sign": "+", "field": "due", "value": "2026-11-27T12:00:00+01:00"} in diff

    ticked = agent.call("caldav.complete_task", {"uid": uid})
    assert ticked["result"]["done"] is True
    assert agent.read("caldav.tasks") == []
    assert agent.read("caldav.tasks", {"include_completed": True})[0]["done"] is True

    # undo in reverse: open again, then the old due date and priority
    assert engine.revert_entry(ticked["entry_id"])["reverted"] == [ticked["entry_id"]]
    assert engine.revert_entry(moved["entry_id"])["reverted"] == [moved["entry_id"]]
    [task] = agent.read("caldav.tasks")
    assert (task["done"], task["due"], task["priority"]) == (False, "2026-11-20", 1)


def test_delete_and_revert_brings_back_the_same_task(cal):
    engine, agent = cal
    uid = agent.call("caldav.create_task", {"summary": "Buy ink"})["result"]["uid"]
    deleted = agent.call("caldav.delete_task", {"uid": uid})
    assert agent.read("caldav.tasks") == []
    engine.revert_entry(deleted["entry_id"])
    assert [t["uid"] for t in agent.read("caldav.tasks")] == [uid]


def test_due_before_filters(cal):
    engine, agent = cal
    agent.call("caldav.create_task", {"summary": "Soon", "due": "2026-11-06"})
    agent.call("caldav.create_task", {"summary": "Later", "due": "2026-12-24T10:00:00"})
    agent.call("caldav.create_task", {"summary": "Someday"})
    assert [t["summary"] for t in agent.read("caldav.tasks")] == ["Soon", "Later", "Someday"]
    assert [t["summary"] for t in agent.read("caldav.tasks", {"due_before": "2026-11-30"})] == ["Soon"]


def test_an_agents_undo_says_what_it_put_back(cal):
    engine, agent = cal
    uid = agent.call("caldav.create_task", {"summary": "Call the bank", "due": "2026-11-20"})["result"]["uid"]
    moved = agent.call("caldav.update_task", {"uid": uid, "changes": {"due": "2026-11-25"}})
    out = engine.agent_undo(agent.session, agent.key, entry_id=moved["entry_id"])
    assert out["reverted"][0]["undone"].endswith(": undone, due back to 2026-11-20"), out
    made = engine.journal.list(kinds=("action",), limit=10)[-1]
    assert engine.agent_undo(agent.session, agent.key, entry_id=made["id"])["reverted"][0]["undone"].endswith(
        ": undone, removed again")


def test_revert_after_the_owner_edited_another_field(cal):
    engine, agent = cal
    uid = agent.call("caldav.create_task", {"summary": "Call the bank"})["result"]["uid"]
    renamed = agent.call("caldav.update_task", {"uid": uid, "changes": {"summary": "Call the bank about the card"}})
    plugin = engine.registry.instance("caldav")
    plugin.apply_task_changes(plugin.find_task(uid)[1], {"due": "2026-11-09"})  # the owner, in the Tasks app
    result = engine.revert_entry(renamed["entry_id"])
    assert result["reverted"] == [renamed["entry_id"]], result
    [task] = agent.read("caldav.tasks")
    assert (task["summary"], task["due"]) == ("Call the bank", "2026-11-09")


def test_events_and_tasks_in_one_collection_stay_apart(cal):
    """Personal holds both: an event's uid isn't a task, and the other way round."""
    engine, agent = cal
    event = gym(agent)["result"]["uid"]
    task = agent.call("caldav.create_task", {"summary": "Pack gym bag", "list": "Personal"})["result"]["uid"]
    assert [t["uid"] for t in agent.read("caldav.tasks", {"list": "Personal"})] == [task]
    assert [e["uid"] for e in week(agent)] == [event]
    with pytest.raises(PluginError, match="no task with uid"):
        agent.call("caldav.complete_task", {"uid": event})
    with pytest.raises(PluginError, match="no event with uid"):
        agent.call("caldav.delete_event", {"uid": task})


# shared collections: writes others see at once are sends

OWNED_BY = ('<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:" xmlns:nc="http://nextcloud.com/ns"><d:set><d:prop>'
            '<nc:owner-principal>{}</nc:owner-principal></d:prop></d:set></d:propertyupdate>')


def owned_by(dav, name, principal):
    """Make a collection look like Nextcloud's view of someone else's calendar shared with the owner. Radicale
    keeps properties it doesn't know (as text), so nc:owner-principal comes back as Nextcloud would send it."""
    client = caldav.DAVClient(url=dav.url, username=dav.user, password="x", require_tls=False)
    collection = next(c for c in client.principal().calendars() if c.get_display_name() == name)
    assert client.proppatch(str(collection.url), OWNED_BY.format(principal)).status == 207


def test_writes_to_a_shared_collection_wait_for_approval(tmp_path, radicale):
    principal = caldav.DAVClient(url=radicale.url, username=radicale.user, password="x", require_tls=False).principal()
    principal.make_calendar(name="Flat", supported_calendar_component_set=["VEVENT", "VTODO"])
    owned_by(radicale, "Flat", "principals/users/lena")
    owned_by(radicale, "Todo", f"principals/users/{radicale.user}")  # the owner's own: not shared
    engine, agent = setup(tmp_path, radicale, default_calendar="Personal", default_list="Todo")
    assert {c["name"]: c["shared"] for c in agent.read("caldav.calendars")} == {
        "Personal": False, "Events": False, "Flat": True}
    assert {c["name"]: c["shared"] for c in agent.read("caldav.lists")}["Flat"] is True

    event = agent.call("caldav.create_event", {"calendar": "Flat", "summary": "Flat meeting",
                                               "start": "2026-11-05T19:00:00+01:00", "end": "2026-11-05T20:00:00+01:00"})
    assert event["status"] == "waiting_approval"
    assert engine.journal.get(event["entry_id"])["summary"].endswith("on shared calendar Flat")
    task = agent.call("caldav.create_task", {"summary": "Buy dish soap", "list": "Flat"})
    assert task["status"] == "waiting_approval"
    assert engine.journal.get(task["entry_id"])["summary"] == "Add task “Buy dish soap” on a shared list"
    assert agent.read("caldav.tasks", {"list": "Flat"}) == []  # nothing until the owner says yes

    engine.approvals.decide(task["approval_id"], approve=True)
    [soap] = agent.read("caldav.tasks", {"list": "Flat"})
    # the flatmates saw it: no undo, but the refusal names the call that takes it away again
    with pytest.raises(Denied) as refused:
        engine.agent_undo(agent.session, agent.key, entry_id=task["entry_id"])
    assert refused.value.code == "irreversible"
    assert f"`doorman call caldav.delete_task uid={soap['uid']}`" in refused.value.reason
    for name, args in (("caldav.complete_task", {"uid": soap["uid"]}),
                       ("caldav.update_task", {"uid": soap["uid"], "changes": {"summary": "Soap"}}),
                       ("caldav.delete_task", {"uid": soap["uid"]})):
        assert agent.call(name, args)["status"] == "waiting_approval", name
    # the owner's own lists and calendars stay quiet, undoable writes
    assert agent.call("caldav.create_task", {"summary": "Buy ink"})["status"] == "done"
    assert gym(agent)["status"] == "done"


def test_shared_collections_from_config(tmp_path, radicale):
    engine, agent = setup(tmp_path, radicale, default_list="Todo", shared_collections=["Todo"])
    assert agent.call("caldav.create_task", {"summary": "Buy ink"})["status"] == "waiting_approval"


def test_nextcloud_names_a_calendar_shared_with_you(tmp_path, radicale):
    """Nextcloud puts someone else's calendar into yours as <id>_shared_by_<user>: evidence without asking."""
    principal = caldav.DAVClient(url=radicale.url, username=radicale.user, password="x", require_tls=False).principal()
    principal.make_calendar(name="Group project", cal_id="project_shared_by_priya",
                            supported_calendar_component_set=["VTODO"])
    engine, agent = setup(tmp_path, radicale)
    asked = watch_sharing_lookups(engine)
    assert agent.call("caldav.create_task", {"summary": "Slides", "list": "Group project"})["status"] == "waiting_approval"
    assert asked == []  # no request needed: the name says it


def watch_sharing_lookups(engine, fail=None):
    """Count the plugin's sharing PROPFINDs (and fail them while fail["on"]); the library's own pass through."""
    client = engine.registry.instance("caldav").client()
    real, asked = client.propfind, []

    def propfind(url=None, props=None, depth=0):
        if isinstance(props, str) and "owner-principal" in props:
            asked.append(url)
            if fail and fail["on"]:
                raise caldav.lib.error.DAVError("server busy")
        return real(url, props, depth)

    client.propfind = propfind
    return asked


def test_sharing_is_cached_and_a_failed_lookup_is_no_evidence(cal):
    engine, agent = cal
    plugin = engine.registry.instance("caldav")
    later = {"seconds": 0}
    plugin._now = lambda: time.monotonic() + later["seconds"]
    fail = {"on": True}
    asked = watch_sharing_lookups(engine, fail)
    # no answer, no evidence of sharing: the write stays a quiet one, and the failure is kept only briefly
    assert agent.call("caldav.create_task", {"summary": "Buy ink"})["status"] == "done"
    assert len(asked) == 1
    fail["on"] = False
    later["seconds"] = plugin.SHARING_RETRY + 1
    agent.call("caldav.create_task", {"summary": "Buy stamps"})
    agent.call("caldav.create_task", {"summary": "Buy tea"})
    assert len(asked) == 2  # asked once more, then from the cache
    plugin.check()  # the owner's "check" (and Doorman's periodic one) forgets it
    agent.call("caldav.create_task", {"summary": "Buy milk"})
    assert len(asked) == 3


ME_PATH = "remote.php/dav/principals/users/sam"
EMAILS = {"sam@example.com"}


def props(*inner: str):
    from lxml import etree
    return etree.fromstring(
        '<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.com/ns" '
        'xmlns:cs="http://calendarserver.org/ns/"><d:response><d:href>/c/</d:href><d:propstat><d:prop>'
        + "".join(inner) + '</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>')


@pytest.mark.parametrize("inner, shared", [
    # Nextcloud, the owner's own calendar, not shared
    (['<oc:owner-principal>principals/users/sam</oc:owner-principal>', '<oc:invite/>'], False),
    # Nextcloud, the owner shares it with Bob
    (['<oc:owner-principal>principals/users/sam</oc:owner-principal>',
      '<oc:invite><oc:user><d:href>principal:principals/users/bob</d:href><oc:common-name>Bob</oc:common-name>'
      '<oc:invite-accepted/><oc:access><oc:read-write/></oc:access></oc:user></oc:invite>'], True),
    # Nextcloud, Lena's calendar shared with the owner
    (['<nc:owner-principal>principals/users/lena</nc:owner-principal>'], True),
    # CalendarServer (iCloud): the owner shares it; the only invitee declined
    (['<cs:invite><cs:organizer><d:href>mailto:sam@example.com</d:href></cs:organizer><cs:user>'
      '<d:href>mailto:tom@example.org</d:href><cs:invite-declined/></cs:user></cs:invite>'], False),
    # CalendarServer: someone else shares it; the owner is one of its users
    (['<cs:invite><cs:organizer><d:href>mailto:lena@example.org</d:href></cs:organizer><cs:user>'
      '<d:href>mailto:sam@example.com</d:href><cs:invite-accepted/></cs:user></cs:invite>'], True),
    # published as a public link
    (['<cs:publish-url><d:href>https://cloud.example/public/abc</d:href></cs:publish-url>'], True),
    (['<d:resourcetype><d:collection/><cs:shared-owner/></d:resourcetype>'], True),
    # a server that knows none of it
    (['<d:resourcetype><d:collection/></d:resourcetype>', '<cs:publish-url/>'], False),
])
def test_sharing_of(inner, shared):
    spec = importlib.util.spec_from_file_location("caldav_plugin", Path(doorman.__file__).parent / "plugins/caldav/plugin.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.sharing_of(props(*inner), ME_PATH, EMAILS) is shared


# answering invitations

INVITE = (
    "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:thesis-1@uni.example\r\n"
    "DTSTAMP:20261101T080000Z\r\nDTSTART:20261106T090000Z\r\nDTEND:20261106T100000Z\r\nSUMMARY:Thesis meeting\r\n"
    "{extra}ORGANIZER;CN=Dr. Jansen:mailto:jansen@uni.example\r\n"
    "ATTENDEE;CN=Dr. Jansen;PARTSTAT=ACCEPTED:mailto:jansen@uni.example\r\n"
    "ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:me@example.com\r\n"
    "ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:anna@example.com\r\nEND:VEVENT\r\n{more}END:VCALENDAR\r\n")


def invite(engine, extra="", more=""):
    engine.registry.instance("caldav").calendar(None).add_event(INVITE.format(extra=extra, more=more))
    return "thesis-1@uni.example"


def test_respond_tells_the_organizer_after_approval(cal):
    engine, agent = cal
    uid = invite(engine)
    assert week(agent)[0]["response"] == "needs-action"
    out = agent.call("caldav.respond", {"uid": uid, "response": "accept"})
    assert out["status"] == "waiting_approval"
    assert out["warnings"] == []  # the organizer asked: answering them is no new recipient
    view = engine.entry_view(engine.journal.get(out["entry_id"]))
    assert view["args"]["to"] == "jansen@uni.example"
    assert view["summary"] == "Tell jansen@uni.example you accept their invitation"
    assert view["outgoing"]["text"] == ("Tells Dr. Jansen (jansen@uni.example) you accept “Thesis meeting”, "
                                        "Fri 6 Nov, 10:00.")
    assert week(agent)[0]["response"] == "needs-action"  # nothing yet

    engine.approvals.decide(out["approval_id"], approve=True)
    entry = engine.journal.get(out["entry_id"])
    assert entry["status"] == "done" and entry["result"]["response"] == "accepted"
    resource = engine.registry.instance("caldav").find_event(uid)[1]
    lines = {str(a).replace("mailto:", ""): dict(a.params) for a in resource.icalendar_component.get("attendee")}
    assert lines["me@example.com"] == {"PARTSTAT": "ACCEPTED"}  # what a scheduling server turns into a REPLY
    assert lines["anna@example.com"]["PARTSTAT"] == "NEEDS-ACTION"  # the other guests' lines stay theirs
    assert week(agent)[0]["response"] == "accepted"
    assert not engine.entry_view(entry)["revertable"]  # it left: answer again to change it


def test_respond_answers_every_occurrence_of_a_series(cal):
    engine, agent = cal
    moved = (
        "BEGIN:VEVENT\r\nUID:thesis-1@uni.example\r\nRECURRENCE-ID:20261113T090000Z\r\nDTSTAMP:20261101T080000Z\r\n"
        "DTSTART:20261113T130000Z\r\nDTEND:20261113T140000Z\r\nSUMMARY:Thesis meeting (moved)\r\n"
        "ORGANIZER;CN=Dr. Jansen:mailto:jansen@uni.example\r\n"
        "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:me@example.com\r\nEND:VEVENT\r\n")
    uid = invite(engine, extra="RRULE:FREQ=WEEKLY;COUNT=4\r\n", more=moved)
    out = agent.call("caldav.respond", {"uid": uid, "response": "decline"})
    assert "(the whole series)" in engine.entry_view(engine.journal.get(out["entry_id"]))["outgoing"]["text"]
    engine.approvals.decide(out["approval_id"], approve=True)
    events = agent.read("caldav.events", {"start": "2026-11-01", "end": "2026-12-01"})
    assert len(events) == 4 and {e["response"] for e in events} == {"declined"}


def test_respond_needs_an_invitation_with_you_as_guest(cal):
    engine, agent = cal
    own = gym(agent)["result"]["uid"]
    with pytest.raises(Denied, match="your own event"):
        agent.call("caldav.respond", {"uid": own, "response": "accept"})
    without_me = INVITE.replace("ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:me@example.com\r\n", "")
    engine.registry.instance("caldav").calendar(None).add_event(without_me.format(extra="", more=""))
    with pytest.raises(Denied, match="aren't among this event's guests"):
        agent.call("caldav.respond", {"uid": "thesis-1@uni.example", "response": "accept"})
    with pytest.raises(Denied):  # no comment here: Nextcloud's scheduling wouldn't pass it on
        agent.call("caldav.respond", {"uid": "thesis-1@uni.example", "response": "accept", "comment": "Hi"})


def test_respond_refuses_when_the_organizer_changed_before_approval(cal):
    engine, agent = cal
    uid = invite(engine)
    out = agent.call("caldav.respond", {"uid": uid, "response": "accept"})
    resource = engine.registry.instance("caldav").find_event(uid)[1]
    with resource.edit_icalendar_instance() as ical:
        component = ical.walk("VEVENT")[0]
        component.pop("organizer")
        component.add("organizer", "mailto:someone@else.example")
    resource.save()
    # the approval showed whom the answer goes to ("Tells Dr. Jansen ... you accept"): that isn't so any more,
    # so it no longer matches (the approval hash covers what a send points at), and nothing goes out
    with pytest.raises(Denied) as exc:
        engine.approvals.decide(out["approval_id"], approve=True)
    assert exc.value.code == "payload_changed"
    assert engine.journal.get(out["entry_id"])["status"] == "rejected"
    assert week(agent)[0]["response"] == "needs-action"


# doorman search: the plugin feeds Doorman's search index (calendar_feed.py), one item per series


def stamp(moment):
    return moment.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def vevent(uid, summary, start, minutes=60, extra=""):
    return ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\n"
            f"UID:{uid}\r\nDTSTAMP:20261101T080000Z\r\nDTSTART:{stamp(start)}\r\n"
            f"DTEND:{stamp(start + timedelta(minutes=minutes))}\r\nSUMMARY:{summary}\r\n{extra}END:VEVENT\r\n"
            "END:VCALENDAR\r\n")


def vtodo(uid, summary, extra=""):
    return ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VTODO\r\n"
            f"UID:{uid}\r\nDTSTAMP:20261101T080000Z\r\nSUMMARY:{summary}\r\n{extra}END:VTODO\r\nEND:VCALENDAR\r\n")


def find(agent, **params):
    return agent.engine.search.any_word(agent.session, agent.key, params)


@pytest.fixture
def filled(cal):
    """A weekly seminar (three past weeks, this week's an hour ago, six to come), a haircut five months ago,
    a dinner three years ago (out of the window), and three tasks."""
    engine, agent = cal
    plugin = engine.registry.instance("caldav")
    now = clock.now().replace(second=0, microsecond=0)
    seminar = now - timedelta(days=21, hours=1)
    plugin.calendar("Personal").add_event(vevent(
        "seminar@uni.example", "Seminar Datenbanken", seminar, 30,
        "RRULE:FREQ=WEEKLY;COUNT=10\r\nLOCATION:BBG 1.15\r\nDESCRIPTION:Normalformen und Transaktionen\r\n"
        "ORGANIZER;CN=Dr. Jansen:mailto:jansen@uni.example\r\nATTENDEE:mailto:me@example.com\r\n"))
    plugin.calendar("Personal").add_event(vevent("haircut@x", "Haircut", now - timedelta(days=150)))
    plugin.calendar("Events").add_event(vevent("dinner@x", "Dinner with Anna", now - timedelta(days=3 * 365)))
    todo = plugin.tasklist("Todo")[1]
    todo.save_todo(vtodo("thesis@x", "Hand in thesis draft", "DUE;VALUE=DATE:20991231\r\nPRIORITY:1\r\n"
                                                             "DESCRIPTION:Chapter 3 and the appendix\r\n"))
    todo.save_todo(vtodo("ink@x", "Buy ink", f"STATUS:COMPLETED\r\nCOMPLETED:{stamp(now - timedelta(days=2))}\r\n"))
    todo.save_todo(vtodo("old@x", "Renew passport", "STATUS:COMPLETED\r\nCOMPLETED:20200101T100000Z\r\n"
                                                    "CREATED:20191201T100000Z\r\nDUE;VALUE=DATE:20200115\r\n"))
    return engine, agent, seminar


def test_the_feed_has_one_item_per_series_dated_by_its_next_occurrence(filled):
    engine, agent, seminar = filled
    assert engine.search.pull("caldav")["changed"] == 4
    assert engine.library.keys("caldav") == {"Personal/seminar@uni.example", "Personal/haircut@x",
                                             "Todo/thesis@x", "Todo/ink@x"}   # the dinner and the passport: too old
    item = engine.library.get("caldav", "Personal/seminar@uni.example")
    nxt = seminar + timedelta(days=28)  # this week's ended half an hour ago: the next is in a week
    assert (item["kind"], item["ref"], item["title"], item["date"]) == (
        "event", "caldav:seminar@uni.example", "Seminar Datenbanken", nxt.isoformat())
    assert (item["place"], item["sender"], item["same"].split("|")[0]) == (
        "Personal", "dr. jansen <jansen@uni.example>", "uid:seminar@uni.example")  # with a hash of what it says
    assert item["fields"] == {"summary": "Seminar Datenbanken", "start": nxt.isoformat(),
                              "end": (nxt + timedelta(minutes=30)).isoformat(), "all_day": False,
                              "location": "BBG 1.15", "calendar": "Personal", "organizer": "jansen@uni.example",
                              "recurring": True, "occurrences": 10}
    assert item["parts"][0]["text"] == "Normalformen und Transaktionen\nBBG 1.15\nme@example.com"
    haircut = engine.library.get("caldav", "Personal/haircut@x")
    assert haircut["fields"]["recurring"] is False and "occurrences" not in haircut["fields"]  # its one, past
    thesis = engine.library.get("caldav", "Todo/thesis@x")
    assert (thesis["kind"], thesis["ref"], thesis["date"], thesis["place"]) == ("task", "caldav:thesis@x",
                                                                               "2099-12-31", "Todo")
    assert thesis["fields"] == {"list": "Todo", "due": "2099-12-31", "priority": 1, "completed": False}
    assert engine.library.get("caldav", "Todo/ink@x")["fields"]["completed"].startswith(
        str((clock.now() - timedelta(days=2)).date()))
    # a deleted event leaves at the next feed: each one is the whole window
    engine.registry.instance("caldav").find_event("haircut@x")[1].delete()
    assert engine.search.pull("caldav")["removed"] == 1 and "Personal/haircut@x" not in engine.library.keys("caldav")


def test_the_window_reaches_as_far_back_as_configured(tmp_path, radicale):
    engine, agent = setup(tmp_path, radicale, search_past_months=48)
    engine.registry.instance("caldav").calendar("Events").add_event(
        vevent("dinner@x", "Dinner with Anna", clock.now() - timedelta(days=3 * 365)))
    engine.registry.instance("caldav").calendar("Events").add_event(
        vevent("trip@x", "Trip to Lisbon", clock.now() + timedelta(days=400)))  # past the 12 months ahead
    engine.search.pull("caldav")
    assert engine.library.keys("caldav") == {"Events/dinner@x"}


def test_search_finds_events_and_tasks_with_their_passage(filled):
    engine, agent, seminar = filled
    engine.search.pull("caldav")
    [hit] = find(agent, query="Transaktionen")["results"]
    assert (hit["source"], hit["kind"], hit["ref"], hit["title"], hit["calendar"]) == (
        "caldav", "event", "caldav:seminar@uni.example", "Seminar Datenbanken", "Personal")
    assert hit["passage"] == "Normalformen und Transaktionen BBG 1.15 me@example.com"
    assert hit["recurring"] is True and hit["occurrences"] == 10
    assert [h["ref"] for h in find(agent, query="appendix")["results"]] == ["caldav:thesis@x"]
    assert [h["title"] for h in find(agent, kind="task")["results"]] == ["Hand in thesis draft", "Buy ink"]
    assert [h["title"] for h in find(agent, kind="event", **{"in": "personal"})["results"]] == [
        "Seminar Datenbanken", "Haircut"]
    since = str((clock.now() - timedelta(days=30)).date())
    assert [h["title"] for h in find(agent, kind="event", since=since)["results"]] == ["Seminar Datenbanken"]
    assert [h["title"] for h in find(agent, query="haircut", until=since)["results"]] == ["Haircut"]
    assert [h["title"] for h in find(agent, **{"from": "jansen"})["results"]] == ["Seminar Datenbanken"]


def test_the_same_event_in_two_calendars_comes_once(cal):
    engine, agent = cal
    plugin = engine.registry.instance("caldav")
    start = clock.now() + timedelta(days=3)
    for name in ("Personal", "Events"):
        plugin.calendar(name).add_event(vevent("party@x", "Lena's birthday party", start))
    engine.search.pull("caldav")
    assert engine.library.keys("caldav") == {"Personal/party@x", "Events/party@x"}
    [hit] = find(agent, query="birthday")["results"]
    assert hit["ref"] == "caldav:party@x" and hit["calendar"] in ("Personal", "Events")
    assert hit["also"] == [{"source": "caldav", "ref": "caldav:party@x", "title": "Lena's birthday party",
                            "date": hit["date"]}]


def test_pseudonyms_hide_a_dentist_appointment_in_search(cal):
    engine, agent = cal
    start = (clock.now() + timedelta(days=2)).replace(second=0, microsecond=0)
    engine.registry.instance("caldav").calendar("Personal").add_event(
        vevent("dentist@x", "Zahnarzt Dr. Weber", start, extra="DESCRIPTION:Kontrolle, danach Pizza\r\n"))
    engine.search.pull("caldav")
    assert find(agent, query="Pizza")["results"] == []  # found only by what the placeholders hide
    [hit] = [h for h in find(agent, kind="event", since=start.date().isoformat())["results"]
             if h["ref"] == "caldav:dentist@x"]
    assert "Zahnarzt" not in str(hit) and "Weber" not in str(hit)
    assert hit["title"].startswith("[Gesundheit PSN-") and hit["summary"].startswith("[Gesundheit PSN-")
    assert hit["passage"].startswith("[Gesundheit PSN-")
    assert hit["start"] == start.isoformat() and hit["ref"] == "caldav:dentist@x" and hit["calendar"] == "Personal"
    assert hit["source"] == "caldav", hit


def test_a_feed_out_of_time_hands_over_what_it_has(filled):
    engine, agent, _ = filled
    plugin = engine.registry.instance("caldav")
    order = [f"event:{n}" for n in plugin.calendars()] + [f"task:{n}" for n in plugin.lists()]
    keys = {"event:Personal": {"Personal/seminar@uni.example", "Personal/haircut@x"}, "event:Events": set(),
            "task:Personal": set(), "task:Todo": {"Todo/thesis@x", "Todo/ink@x"}}
    part = plugin.index_feed(None, 0)  # no time at all: one collection, then it stops
    assert "complete" not in part and part["more"] is True
    assert json.loads(part["cursor"]) == {"first": order[1]}
    assert {i["key"] for i in part["items"]} == keys[order[0]]
    rest = plugin.index_feed(part["cursor"], 0)  # the next one begins where it stopped
    assert json.loads(rest["cursor"]) == {"first": order[2]} and {i["key"] for i in rest["items"]} == keys[order[1]]
    whole = plugin.index_feed(None, 60)
    assert whole["complete"] is True and len(whole["items"]) == 4
