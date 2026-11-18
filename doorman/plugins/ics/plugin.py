"""A subscribed calendar feed (iCal/ICS), read-only. One plugin instance per feed: the feed URL is in
the vault, because anyone who has it can read the calendar. The feed is downloaded at most every
refresh_minutes and kept in the plugin's data directory, so a feed that is briefly down still answers."""

import hashlib
import json
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import httpx
import recurring_ical_events
from icalendar import Calendar

from doorman import calendar_feed, clock
from doorman.plugin_api import BasePlugin, PluginError

MAX_BYTES = 20 * 1024 * 1024
MAX_DAYS = 400  # one read covers at most this range, so a typo can't expand years of a weekly lecture


def _parse(value: str, zone) -> datetime:
    value = value.strip()
    if len(value) == 10:
        return datetime.combine(date.fromisoformat(value), datetime.min.time(), zone)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=zone)


def _iso(value, zone=None) -> str | None:
    """A DTSTART/DTEND as ISO text. A floating time (no zone, as timetable exports often have) gets the feed's
    `timezone` and its offset, so "09:00" can't be read as UTC; without a configured zone it stays floating
    (Doorman's agenda then takes it to be in the owner's zone)."""
    if value is None:
        return None
    value = value.dt
    if isinstance(value, datetime) and value.tzinfo is None and zone is not None:
        value = value.replace(tzinfo=zone)
    return value.isoformat()


class Plugin(BasePlugin):
    TOOLS = {}
    READS = {"events": "read_events", "info": "read_info"}
    transport: httpx.BaseTransport | None = None  # tests inject a fake server here

    @property
    def zone(self):
        return ZoneInfo(self.config["timezone"]) if self.config.get("timezone") else timezone.utc

    @property
    def _cache(self):
        return self.ctx.data_dir / "feed.ics", self.ctx.data_dir / "feed.json"

    def _url(self) -> str:
        url = (self.credentials.get("url") or "").strip()
        if not url:
            raise PluginError(f"{self.ctx.instance}: store the feed address first (credential url)")
        if url.startswith("webcal://"):
            url = "https://" + url[len("webcal://"):]
        if not url.startswith("https://") and not self.config.get("allow_http"):
            raise PluginError(f"{self.ctx.instance}: the feed address must start with https:// or webcal://")
        return url

    def _download(self) -> bytes:
        try:
            with httpx.Client(transport=self.transport, timeout=30, follow_redirects=True) as client:
                with client.stream("GET", self._url(), headers={"Accept": "text/calendar"}) as response:
                    if response.status_code >= 400:
                        raise PluginError(f"the feed answered {response.status_code}; is the address still valid?")
                    body = b""
                    for chunk in response.iter_bytes():
                        body += chunk
                        if len(body) > MAX_BYTES:
                            raise PluginError("the feed is larger than 20 MB")
        except httpx.HTTPError as exc:
            raise PluginError(f"the feed is unreachable: {exc}") from exc
        if b"BEGIN:VCALENDAR" not in body[:2048]:
            raise PluginError("that address doesn't return a calendar (no BEGIN:VCALENDAR)")
        return body

    def feed(self, fresh: bool = False) -> tuple[Calendar, dict]:
        data_path, meta_path = self._cache
        meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        age = clock.now().timestamp() - meta.get("fetched", 0)
        if fresh or not data_path.exists() or age > 60 * float(self.config.get("refresh_minutes", 30)):
            try:
                body = self._download()
            except PluginError:
                if not data_path.exists():
                    raise
                meta["stale"] = True  # keep answering from the last good copy
            else:
                data_path.write_bytes(body)
                meta = {"fetched": clock.now().timestamp(), "stale": False}
                meta_path.write_text(json.dumps(meta))
        try:
            return Calendar.from_ical(data_path.read_bytes()), meta
        except ValueError as exc:
            raise PluginError(f"the feed isn't valid iCalendar: {exc}") from exc

    def check(self):
        """Download the feed now. Reads keep answering from the last good copy, but Needs attention should
        say that the feed itself is broken (an expired token, a changed address)."""
        try:
            Calendar.from_ical(self._download())
        except (PluginError, ValueError) as exc:
            return str(exc)
        return None

    @property
    def label(self) -> str:
        return self.config.get("label") or self.ctx.instance

    def entries(self, calendar: Calendar, start: datetime, end: datetime) -> list[tuple[str, dict]]:
        """(uid, entry) for each occurrence between start and end, recurring ones expanded."""
        floating = self.zone if self.config.get("timezone") else None
        out = []
        for event in recurring_ical_events.of(calendar).between(start, end):
            item = {"title": str(event.get("summary", "")), "start": _iso(event.get("dtstart"), floating),
                    "end": _iso(event.get("dtend"), floating), "location": str(event.get("location", "")),
                    "description": str(event.get("description", ""))[:2000],
                    "all_day": not isinstance(event.get("dtstart").dt, datetime) if event.get("dtstart") else False,
                    "cancelled": str(event.get("status", "")).upper() == "CANCELLED", "feed": self.label}
            out.append((str(event.get("uid") or ""), item))
        return out

    def read_events(self, params):
        start, end = _parse(params["start"], self.zone), _parse(params["end"], self.zone)
        if len(params["end"].strip()) == 10:
            end += timedelta(days=1)  # an end date includes that whole day
        if end <= start:
            raise PluginError("end must be after start")
        if end - start > timedelta(days=MAX_DAYS):
            raise PluginError(f"ask for at most {MAX_DAYS} days at a time")
        calendar, meta = self.feed()
        words = (params.get("query") or "").lower().split()
        out = []
        for _, item in self.entries(calendar, start, end):
            text = f"{item['title']}\n{item['location']}\n{item['description']}".lower()
            if any(w not in text for w in words):
                continue
            out.append(item)
        out.sort(key=lambda e: e["start"] or "")
        if meta.get("stale"):
            for item in out:
                item["stale"] = True  # the feed couldn't be refreshed; this is the last good copy
        return out

    def index_feed(self, cursor, budget):
        """Every event series of the window (calendar_feed.window) for Doorman's search index: the feed's own
        window, not MAX_DAYS, as only Doorman asks. A feed can't be changed, so its ref is no tool's; it names
        the series (<instance>:<UID>), and an entry without a UID (which iCalendar forbids, but feeds have) gets
        a key from its title and start. One download and one expansion: there is nothing to split."""
        calendar, _ = self.feed()
        start, end = calendar_feed.window(self.config)
        series = {str(c.get("uid")) for c in calendar.walk("VEVENT")
                  if c.get("rrule") is not None or c.get("rdate") is not None or c.get("recurrence-id") is not None}
        occurrences = []
        for uid, item in self.entries(calendar, start, end):
            key = uid or "made-" + hashlib.sha256(f"{item['title']}|{item['start']}".encode()).hexdigest()[:16]
            occurrences.append({**item, "summary": item["title"], "key": key, "ref": f"{self.ctx.instance}:{key}",
                                "uid": uid or None, "calendar": self.label, "recurring": uid in series,
                                "extra": {"cancelled": True} if item["cancelled"] else {}})
        return calendar_feed.answer(calendar_feed.event_items(occurrences, self.zone))

    def read_info(self, params):
        calendar, meta = self.feed()
        return {"feed": self.label,
                "name": str(calendar.get("x-wr-calname", "")) or None,
                "events": len(calendar.walk("VEVENT")),
                "downloaded": datetime.fromtimestamp(meta.get("fetched", 0), timezone.utc).isoformat()
                if meta.get("fetched") else None,
                "stale": bool(meta.get("stale"))}
