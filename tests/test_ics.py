from datetime import datetime, timezone

import httpx
import pytest

from doorman import clock
from doorman.plugin_api import PluginError
from conftest import Agent, make_engine

FEED = b"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//MyTimetable//EN
X-WR-CALNAME:UU timetable
BEGIN:VTIMEZONE
TZID:Europe/Amsterdam
BEGIN:STANDARD
DTSTART:19701025T030000
RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU
TZOFFSETFROM:+0200
TZOFFSETTO:+0100
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700329T020000
RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU
TZOFFSETFROM:+0100
TZOFFSETTO:+0200
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
UID:lecture-1@mytimetable
DTSTART;TZID=Europe/Amsterdam:20261102T110000
DTEND;TZID=Europe/Amsterdam:20261102T124500
RRULE:FREQ=WEEKLY;COUNT=8
EXDATE;TZID=Europe/Amsterdam:20261109T110000
SUMMARY:INFOMDM Lecture
LOCATION:Educatorium Alfa
END:VEVENT
BEGIN:VEVENT
UID:werkcollege@mytimetable
DTSTART;TZID=Europe/Amsterdam:20261104T090000
DTEND;TZID=Europe/Amsterdam:20261104T104500
SUMMARY:INFOMDM Werkcollege
LOCATION:BBG 1.15
STATUS:CANCELLED
END:VEVENT
BEGIN:VEVENT
UID:deadline@brightspace
DTSTART;VALUE=DATE:20261106
DTEND;VALUE=DATE:20261107
SUMMARY:Assignment 2 due
DESCRIPTION:Hand in via Brightspace
END:VEVENT
END:VCALENDAR
"""


class FakeFeed:
    def __init__(self):
        self.body, self.status, self.hits = FEED, 200, 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.hits += 1
        assert request.url == "https://mytimetable.uni.example/ical?token=s3cret"
        return httpx.Response(self.status, content=self.body, headers={"Content-Type": "text/calendar"})


@pytest.fixture
def feed(tmp_path):
    engine = make_engine(tmp_path, plugins={"timetable": {"type": "ics", "enabled": True,
                                                          "config": {"label": "UU timetable", "timezone": "Europe/Amsterdam"}}})
    engine.vault.set("timetable", "url", "webcal://mytimetable.uni.example/ical?token=s3cret")
    fake = FakeFeed()
    engine.registry.instance("timetable").transport = httpx.MockTransport(fake)
    return engine, Agent(engine), fake


def test_week_view_expands_recurring_lectures(feed):
    engine, agent, fake = feed
    week = agent.read("timetable.events", {"start": "2026-11-02", "end": "2026-11-08"})
    assert [(e["title"], e["start"]) for e in week] == [
        ("INFOMDM Lecture", "2026-11-02T11:00:00+01:00"),
        ("INFOMDM Werkcollege", "2026-11-04T09:00:00+01:00"),
        ("Assignment 2 due", "2026-11-06")]  # the end date counts as a whole day
    assert week[1]["cancelled"] is True and week[2]["all_day"] is True
    assert week[0]["location"] == "Educatorium Alfa" and week[0]["feed"] == "UU timetable"
    # the 9th was cancelled with EXDATE; the series goes on after
    lectures = agent.read("timetable.events", {"start": "2026-11-09", "end": "2026-11-17", "query": "lecture"})
    assert [e["start"] for e in lectures] == ["2026-11-16T11:00:00+01:00"]


def test_feed_is_cached_and_survives_an_outage(feed):
    engine, agent, fake = feed
    agent.read("timetable.events", {"start": "2026-11-02", "end": "2026-11-03"})
    agent.read("timetable.events", {"start": "2026-11-02", "end": "2026-11-03"})
    assert fake.hits == 1  # reused within refresh_minutes
    fake.status = 503
    plugin = engine.registry.instance("timetable")
    assert "503" in plugin.check()
    clock.advance(31 * 60)  # past refresh_minutes: it tries again, fails, and answers from the last copy
    stale = agent.read("timetable.events", {"start": "2026-11-02", "end": "2026-11-03"})
    assert stale[0]["title"] == "INFOMDM Lecture" and stale[0]["stale"] is True
    assert agent.read("timetable.info")["stale"] is True


def test_info_and_bad_input(feed):
    engine, agent, fake = feed
    assert agent.read("timetable.info") | {"downloaded": None} == {
        "feed": "UU timetable", "name": "UU timetable", "events": 3, "downloaded": None, "stale": False}
    with pytest.raises(PluginError, match="at most"):
        agent.read("timetable.events", {"start": "2026-01-01", "end": "2028-01-01"})
    fake.body = b"<html>login page</html>"
    engine.vault.set("timetable", "url", "https://mytimetable.uni.example/ical?token=s3cret")
    engine.registry.invalidate("timetable")
    engine.registry.instance("timetable").transport = httpx.MockTransport(fake)
    assert "BEGIN:VCALENDAR" in engine.registry.instance("timetable").check()


def test_read_only_and_url_never_shown(feed):
    engine, agent, fake = feed
    caps = {p["name"]: p for p in engine.registry.list()}["timetable"]
    assert caps["tools"] == [] and caps["missing_credentials"] == []
    assert "s3cret" not in str(caps)
    events = agent.read("timetable.events", {"start": "2026-11-02", "end": "2026-11-08"})
    assert "s3cret" not in str(events)


FLOATING = FEED.replace(b"END:VCALENDAR", b"""BEGIN:VEVENT
UID:floating@mytimetable
DTSTART:20261110T090000
DTEND:20261110T104500
SUMMARY:INFOB3DS Lecture
END:VEVENT
END:VCALENDAR""")


def test_floating_times_get_the_feeds_zone_and_offset(feed):
    # timetable exports often leave the zone out: their "09:00" is local time, never UTC
    engine, agent, fake = feed
    fake.body = FLOATING
    entries = agent.read("timetable.events", {"start": "2026-11-10", "end": "2026-11-10"})
    assert [(e["title"], e["start"], e["end"]) for e in entries] == [
        ("INFOB3DS Lecture", "2026-11-10T09:00:00+01:00", "2026-11-10T10:45:00+01:00")]


# ---------------------------------------------------------------- doorman search (calendar_feed.py)


def event(uid, summary, start, end, extra=""):
    return (f"BEGIN:VEVENT\nUID:{uid}\nDTSTART:{start}\nDTEND:{end}\nSUMMARY:{summary}\n{extra}END:VEVENT\n"
            "END:VCALENDAR\n").encode()


def find(agent, **params):
    return agent.engine.search.any_word(agent.session, agent.key, params)


def to_tuesday_noon():
    """The feed's week, seen on Tuesday 10 November 2026 at noon (make_engine sets the clock back)."""
    clock.advance((datetime(2026, 11, 10, 11, tzinfo=timezone.utc) - clock.now()).total_seconds())


@pytest.fixture
def tuesday(feed):
    to_tuesday_noon()
    yield feed
    clock.reset()


def test_the_feed_has_one_item_per_series_dated_by_its_next_occurrence(tuesday):
    engine, agent, fake = tuesday
    assert engine.search.pull("timetable")["changed"] == 3
    lecture = engine.library.get("timetable", "lecture-1@mytimetable")
    assert (lecture["kind"], lecture["ref"], lecture["title"], lecture["date"], lecture["place"],
            lecture["same"].split("|")[0]) == (
        "event", "timetable:lecture-1@mytimetable", "INFOMDM Lecture", "2026-11-16T11:00:00+01:00", "UU timetable",
        "uid:lecture-1@mytimetable")  # the 2nd is past, the 9th cancelled (EXDATE)
    assert lecture["fields"] == {"summary": "INFOMDM Lecture", "start": "2026-11-16T11:00:00+01:00",
                                 "end": "2026-11-16T12:45:00+01:00", "all_day": False, "location": "Educatorium Alfa",
                                 "calendar": "UU timetable", "recurring": True, "occurrences": 7}
    cancelled = engine.library.get("timetable", "werkcollege@mytimetable")
    assert cancelled["date"] == "2026-11-04T09:00:00+01:00" and cancelled["fields"]["cancelled"] is True
    deadline = engine.library.get("timetable", "deadline@brightspace")
    assert (deadline["date"], deadline["fields"]["all_day"], deadline["parts"][0]["text"]) == (
        "2026-11-06", True, "Hand in via Brightspace")
    # the feed changes: what's gone from it leaves search
    fake.body = FEED.replace(b"BEGIN:VEVENT\nUID:werkcollege", b"BEGIN:VEVENT\nUID:werkcollege-moved")
    engine.registry.instance("timetable").feed(fresh=True)
    assert engine.search.pull("timetable")["removed"] == 1
    assert "werkcollege@mytimetable" not in engine.library.keys("timetable")


def test_the_window_reaches_as_far_back_as_configured(tuesday):
    engine, agent, fake = tuesday
    fake.body = FEED.replace(b"END:VCALENDAR\n", event("exam@uu", "Exam Logic", "20231110T090000Z", "20231110T110000Z")
                             ).replace(b"END:VCALENDAR\n", event("far@uu", "Graduation", "20271215T090000Z",
                                                                 "20271215T110000Z"))
    engine.search.pull("timetable")
    assert {"exam@uu", "far@uu"} & engine.library.keys("timetable") == set()  # 3 years back, 13 months ahead
    engine.registry.instance("timetable").config["search_past_months"] = 48
    engine.search.pull("timetable")
    assert "exam@uu" in engine.library.keys("timetable") and "far@uu" not in engine.library.keys("timetable")


def test_search_finds_the_feeds_events(tuesday):
    engine, agent, fake = tuesday
    engine.search.pull("timetable")
    [hit] = find(agent, query="Educatorium")["results"]
    assert (hit["source"], hit["kind"], hit["ref"], hit["title"], hit["passage"], hit["calendar"]) == (
        "timetable", "event", "timetable:lecture-1@mytimetable", "INFOMDM Lecture", "Educatorium Alfa", "UU timetable")
    assert hit["start"] == "2026-11-16T11:00:00+01:00" and hit["occurrences"] == 7
    assert [h["title"] for h in find(agent, kind="event", **{"in": "uu time"})["results"]] == [
        "INFOMDM Lecture", "Assignment 2 due", "INFOMDM Werkcollege"]
    assert [h["title"] for h in find(agent, kind="event", since="2026-11-10")["results"]] == ["INFOMDM Lecture"]
    assert [h["title"] for h in find(agent, query="Brightspace", until="2026-11-06")["results"]] == ["Assignment 2 due"]
    assert find(agent, kind="note")["results"] == []


def test_the_same_event_in_two_feeds_comes_once(tmp_path):
    engine = make_engine(tmp_path, plugins={
        "timetable": {"type": "ics", "enabled": True, "config": {"label": "UU timetable"}},
        "brightspace": {"type": "ics", "enabled": True, "config": {"label": "Brightspace"}}})
    to_tuesday_noon()
    agent = Agent(engine)
    other = FEED.split(b"BEGIN:VEVENT")[0] + b"BEGIN:VEVENT" + FEED.split(b"BEGIN:VEVENT")[-1]  # the deadline alone
    for name in ("timetable", "brightspace"):
        engine.vault.set(name, "url", f"https://{name}.example/feed.ics")
    for name, body in (("timetable", FEED), ("brightspace", other)):
        engine.registry.instance(name).transport = httpx.MockTransport(
            lambda request, body=body: httpx.Response(200, content=body))
    assert engine.search.pull("timetable")["changed"] == 3 and engine.search.pull("brightspace")["changed"] == 1
    [hit] = find(agent, query="Brightspace")["results"]
    [also] = hit["also"]
    assert {hit["source"], also["source"]} == {"timetable", "brightspace"}
    assert also == {"source": also["source"], "ref": f"{also['source']}:deadline@brightspace",
                    "title": "Assignment 2 due", "date": "2026-11-06"}
    clock.reset()


def test_pseudonyms_hide_a_dentist_appointment_in_search(tuesday):
    engine, agent, fake = tuesday
    fake.body = FEED.replace(b"END:VCALENDAR\n", event("dentist@x", "Zahnarzt Dr. Weber", "20261112T090000Z",
                                                       "20261112T093000Z", "DESCRIPTION:Kontrolle, danach Pizza\n"))
    engine.search.pull("timetable")
    assert find(agent, query="Pizza")["results"] == []  # found only by what the placeholders hide
    [hit] = find(agent, kind="event", since="2026-11-12", until="2026-11-12")["results"]
    assert "Zahnarzt" not in str(hit) and "Weber" not in str(hit)
    assert hit["title"].startswith("[Gesundheit PSN-") and hit["summary"].startswith("[Gesundheit PSN-")
    assert hit["passage"].startswith("[Gesundheit PSN-") and hit["start"] == "2026-11-12T09:00:00+00:00"
    assert hit["source"] == "timetable" and hit["calendar"] == "UU timetable"
