"""WhatsApp in doorman search: the plugin feeds Doorman's search index one chat-day at a time, the whole
history first, then only the days wacli's change log names. Against a fake sidecar that answers /chats,
/messages (before/after, newest first) and /changes the way sidecars/whatsapp/shim.py does over wacli;
test_whatsapp_wacli.py runs the same through the real shim and wacli when a wacli binary is there."""

import json
from datetime import datetime, timezone

import httpx
import pytest

from doorman import clock
from doorman.demo import fakes, seed
from doorman.plugin_api import PluginError
from conftest import Agent, free_port, make_engine

FAMILY, MUM, DOC = "120363000@g.us", "4915100000000@s.whatsapp.net", "4930123456@s.whatsapp.net"
BERLIN_NOON = datetime(2026, 11, 10, 11, tzinfo=timezone.utc)  # Tuesday 10 November, 12:00 in Berlin


def utc(day, hh, mm=0):
    """A time on a November 2026 day, in UTC, as wacli writes it."""
    return datetime(2026, 11, day, hh, mm, tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Sidecar:
    """wacli's store as the sidecar shows it: chats, messages, and the change log, where a checkpoint is a
    position."""

    def __init__(self):
        self.names = {FAMILY: "Family", MUM: "Mum", DOC: "Zahnarztpraxis Weber"}
        self.messages: dict[tuple[str, str], dict] = {}
        self.log: list[dict] = []
        self.asked: list[tuple[str, dict]] = []
        self.oldest = 0  # checkpoints before this one have expired

    def add(self, chat, msg_id, text, when, who="Mum", **extra):
        mine = who == "me"
        message = {"ChatJID": chat, "ChatName": self.names[chat], "MsgID": msg_id, "Text": text, "Timestamp": when,
                   "SenderJID": "me@s.whatsapp.net" if mine else MUM, "SenderName": "" if mine else who,
                   "FromMe": mine, **extra}
        self.messages[(chat, msg_id)] = message
        self.log.append({"operation": "upsert", "chat_jid": chat, "msg_id": msg_id, "message_time": when})

    def delete(self, chat, msg_id):
        gone = self.messages.pop((chat, msg_id))
        self.log.append({"operation": "delete", "chat_jid": chat, "msg_id": msg_id,
                         "message_time": gone["Timestamp"]})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        self.asked.append((request.url.path, params))
        if request.url.path == "/chats":
            last = {c: max((m["Timestamp"] for (k, _), m in self.messages.items() if k == c), default="")
                    for c in self.names}
            return httpx.Response(200, json=[{"jid": c, "name": n, "last_message_ts": last[c]} for c, n in
                                             sorted(self.names.items(), key=lambda p: last[p[0]], reverse=True)])
        if request.url.path == "/changes":
            if "since" not in params:
                return httpx.Response(200, json={"changes": [], "has_more": False, "next_checkpoint": str(len(self.log))})
            start, limit = int(params["since"]), int(params.get("limit", 50))
            if start < self.oldest:
                return httpx.Response(502, json={"error": "expired checkpoint; take a new one"})
            page = self.log[start:start + limit]
            return httpx.Response(200, json={"changes": page, "has_more": start + len(page) < len(self.log),
                                             "next_checkpoint": str(start + len(page))})
        assert request.url.path == "/messages"
        after, before = params.get("after"), params.get("before")
        found = [m for (chat, _), m in self.messages.items() if chat == params["chat"]
                 and (not after or m["Timestamp"] > after) and (not before or m["Timestamp"] < before)]
        oldest_first = bool(after and not before)
        return httpx.Response(200, json=sorted(found, key=lambda m: m["Timestamp"],
                                               reverse=not oldest_first)[:int(params.get("limit", 30))])


def filled(sidecar):
    """Three days of the family chat, Mum's Sunday, and the dentist's reminder."""
    add = sidecar.add
    add(FAMILY, "F1", "Wer bringt den Kuchen mit?", utc(7, 17, 5))
    add(FAMILY, "F2", "Ich!", utc(7, 17, 9), who="me")
    add(FAMILY, "F3", "", utc(7, 17, 10), ReactionToID="F2", ReactionEmoji="👍")  # a reaction: not a line
    add(FAMILY, "F4", "", utc(7, 18, 0), Revoked=True)                           # deleted for everyone
    add(FAMILY, "F5", "Look!", utc(7, 23, 30), who="Lena", MediaType="image", Filename="cake.jpg")  # 00:30 on the 8th
    add(FAMILY, "F6", "Danke für gestern", utc(8, 9, 0), who="Lena")
    add(FAMILY, "F7", "Zug fährt um 8", utc(10, 6, 0))
    add(MUM, "M1", "Kommst du Sonntag zum Essen?", utc(8, 10, 0))
    add(MUM, "M2", "Papa macht Lasagne", utc(8, 10, 1))
    add(DOC, "D1", "Erinnerung: Kontrolle am Donnerstag", utc(9, 8, 0), who="Praxis")


@pytest.fixture
def world(tmp_path):
    engine = make_engine(tmp_path, plugins={"whatsapp": {"enabled": True, "config": {"timezone": "Europe/Berlin"}}})
    engine.vault.set("whatsapp", "sidecar_token", "tok")
    clock.advance((BERLIN_NOON - clock.now()).total_seconds())
    sidecar = Sidecar()
    filled(sidecar)
    engine.registry.instance("whatsapp").transport = httpx.MockTransport(sidecar)
    yield engine, Agent(engine), sidecar
    clock.reset()


def find(agent, **params):
    return agent.engine.search.any_word(agent.session, agent.key, params)


def test_the_first_feed_reads_every_chat_a_day_at_a_time(world):
    engine, agent, sidecar = world
    out = engine.search.pull("whatsapp")
    assert out["changed"] == 5 and not out["more"]
    assert engine.library.keys("whatsapp") == {f"{FAMILY}/2026-11-07", f"{FAMILY}/2026-11-08", f"{FAMILY}/2026-11-10",
                                               f"{MUM}/2026-11-08", f"{DOC}/2026-11-09"}
    day = engine.library.get("whatsapp", f"{FAMILY}/2026-11-08")  # the photo at 00:30 Berlin time is the 8th's
    assert (day["kind"], day["ref"], day["title"], day["place"], day["sender"], day["date"]) == (
        "chat", f"whatsapp:{FAMILY}/F5", "Family", "Family", "lena", "2026-11-08T10:00:00+01:00")
    assert day["parts"][0]["text"] == "00:30 Lena: [image: cake.jpg] Look!\n10:00 Lena: Danke für gestern"
    assert day["fields"] == {"chat": "Family", "chat_id": FAMILY, "day": "2026-11-08", "messages": 2}
    first = engine.library.get("whatsapp", f"{FAMILY}/2026-11-07")  # the reaction and the deleted one: no lines
    assert first["parts"][0]["text"] == "18:05 Mum: Wer bringt den Kuchen mit?\n18:09 me: Ich!"
    assert (first["sender"], first["fields"]["messages"]) == ("mum, me", 2)


def test_history_comes_in_pages_and_a_day_is_never_cut(world, monkeypatch):
    engine, agent, sidecar = world
    plugin = engine.registry.instance("whatsapp")
    monkeypatch.setitem(type(plugin).index_feed.__globals__, "PAGE", 2)  # the plugin module's
    for n in range(5):  # the 9th has five messages: more than a page of two
        sidecar.add(FAMILY, f"N{n}", f"Nachricht {n}", utc(9, 12, n))
    whole = plugin.index_feed(None, 60)
    assert whole["more"] is False
    days = {i["key"]: i["fields"]["messages"] for i in whole["items"]}
    assert days[f"{FAMILY}/2026-11-08"] == 2 and days[f"{FAMILY}/2026-11-07"] == 2
    assert days[f"{FAMILY}/2026-11-09"] == 5  # longer than a page: read on to the day's start
    # with no time at all, one page per call; together the same items
    cursor, items, calls = None, {}, 0
    while True:
        part = plugin.index_feed(cursor, 0)
        items.update({i["key"]: i for i in part["items"]})
        cursor, calls = part["cursor"], calls + 1
        if not part["more"]:
            break
    assert calls > 5 and items == {i["key"]: i for i in whole["items"]}


def test_later_feeds_send_only_the_chat_days_that_changed(world):
    engine, agent, sidecar = world
    engine.search.pull("whatsapp")
    sidecar.asked.clear()
    assert engine.search.pull("whatsapp")["changed"] == 0
    assert [path for path, _ in sidecar.asked] == ["/changes"]  # nothing new: one question
    sidecar.add(FAMILY, "F8", "Bin gleich da", utc(10, 10, 30))           # today: a new line
    sidecar.add(FAMILY, "F1", "Wer bringt den Käsekuchen mit?", utc(7, 17, 5), Edited=True)  # an edit, last week
    sidecar.delete(DOC, "D1")                                              # the reminder's day has nothing left
    sidecar.asked.clear()
    out = engine.search.pull("whatsapp")
    assert (out["changed"], out["removed"]) == (2, 1)
    days = sorted((p["after"], p["before"]) for path, p in sidecar.asked if path == "/messages")
    assert days == [("2026-11-06T22:59:59Z", "2026-11-07T23:00:00Z"), ("2026-11-08T22:59:59Z", "2026-11-09T23:00:00Z"),
                    ("2026-11-09T22:59:59Z", "2026-11-10T23:00:00Z")]  # Berlin's days, in UTC
    assert "Käsekuchen" in engine.library.get("whatsapp", f"{FAMILY}/2026-11-07")["parts"][0]["text"]
    assert engine.library.get("whatsapp", f"{FAMILY}/2026-11-10")["fields"]["messages"] == 2
    assert f"{DOC}/2026-11-09" not in engine.library.keys("whatsapp")


def test_an_expired_checkpoint_reads_the_history_again(world):
    engine, agent, sidecar = world
    engine.search.pull("whatsapp")
    sidecar.messages[(MUM, "M2")]["Text"] = "Papa macht Pizza"  # changed while Doorman wasn't looking
    sidecar.oldest = len(sidecar.log) + 1                       # and the log forgot where it was
    sidecar.asked.clear()
    out = engine.search.pull("whatsapp")
    assert out["changed"] == 1 and "error" not in out and not out["more"]
    assert ("/chats", {"limit": "1000"}) in sidecar.asked
    assert "Pizza" in engine.library.get("whatsapp", f"{MUM}/2026-11-08")["parts"][0]["text"]
    # a sidecar that refuses even its new checkpoint: one reading of the history per feed, not again and again
    sidecar.oldest = 10**9
    sidecar.asked.clear()
    assert "error" not in engine.search.pull("whatsapp")
    assert len([p for path, p in sidecar.asked if path == "/changes" and "since" in p]) == 2


def test_search_finds_chat_days_through_the_engine(world):
    engine, agent, sidecar = world
    engine.search.pull("whatsapp")
    [hit] = find(agent, query="Kuchen")["results"]
    assert (hit["source"], hit["kind"], hit["ref"], hit["title"], hit["chat"], hit["chat_id"], hit["day"]) == (
        "whatsapp", "chat", f"whatsapp:{FAMILY}/F1", "Family", "Family", FAMILY, "2026-11-07")
    assert hit["passage"] == "18:05 Mum: Wer bringt den Kuchen mit? 18:09 me: Ich!" and hit["messages"] == 2
    # the ref is the day's first message: what doorman meta and the message read take
    assert engine.meta(agent.session, agent.key, hit["ref"])["sender"] == MUM
    assert [h["day"] for h in find(agent, kind="chat", **{"in": "family"})["results"]] == [
        "2026-11-10", "2026-11-08", "2026-11-07"]
    assert [h["chat"] for h in find(agent, **{"from": "lena"})["results"]] == ["Family"]
    assert [h["day"] for h in find(agent, query="Lasagne", since="2026-11-08", until="2026-11-08")["results"]] == [
        "2026-11-08"]
    assert find(agent, query="Lasagne", since="2026-11-09")["results"] == []
    assert find(agent, query="Kuchen", kind="event")["results"] == []


def test_the_message_read_gates_whatsapp_in_search(world):
    engine, agent, sidecar = world
    engine.search.pull("whatsapp")
    state = engine.registry.state("whatsapp")
    engine.registry.set_state("whatsapp", {**state, "disabled_tools": ["message"]})
    assert find(agent, query="Kuchen")["results"] == [] and "whatsapp" not in find(agent, query="Kuchen")["sources"]
    engine.registry.set_state("whatsapp", state)
    assert len(find(agent, query="Kuchen")["results"]) == 1


def test_a_chats_day_needs_the_messages_read_too_and_a_held_message_holds_it(world):
    """A chat's day is what whatsapp.messages returns: with that read off it doesn't show. A message the guard
    holds back holds back the day it is in, whichever message the day's ref names."""
    engine, agent, sidecar = world
    engine.search.pull("whatsapp")
    engine.plugin_setup.switch("whatsapp", tool="messages", mode="off")
    assert find(agent, query="Kuchen")["results"] == []
    engine.plugin_setup.switch("whatsapp", tool="messages", mode="auto")
    [day] = find(agent, query="Kuchen")["results"]
    item = engine.library.get("whatsapp", f"{day['chat_id']}/{day['day']}")
    assert day["ref"] in item["refs"] and all(r.startswith(f"whatsapp:{day['chat_id']}/") for r in item["refs"])
    later = item["refs"][-1]
    engine.db.exec("INSERT INTO quarantine(sha256, source, ref, label, score, excerpt, status, created) "
                   "VALUES('x', 'whatsapp.message', ?, 'x', 0.97, 'x', 'held', '2026-11-09')", (later,))
    [held] = find(agent, query="Kuchen")["results"]
    assert held["held"] and "Kuchen" not in str(held)


def test_pseudonyms_hide_a_chat_with_the_doctors_practice(world):
    engine, agent, sidecar = world
    engine.search.pull("whatsapp")
    assert find(agent, query="Kontrolle")["results"] == []  # found only by what the placeholders hide
    [hit] = [h for h in find(agent, kind="chat", since="2026-11-09")["results"] if h["chat_id"] == DOC]
    assert "Zahnarzt" not in str(hit) and hit["title"].startswith("[Gesundheit PSN-")
    assert hit["passage"].startswith("[Gesundheit PSN-") and hit["chat"].startswith("[Gesundheit PSN-")
    assert (hit["source"], hit["chat_id"], hit["day"], hit["ref"]) == ("whatsapp", DOC, "2026-11-09", f"whatsapp:{DOC}/D1")


def test_a_sidecar_error_after_some_progress_keeps_what_came(world):
    engine, agent, sidecar = world
    plugin = engine.registry.instance("whatsapp")
    first = plugin.index_feed(None, 60)
    real = sidecar.__call__

    def down_for_the_family(request):
        if request.url.path == "/messages" and request.url.params.get("chat") == FAMILY:
            return httpx.Response(503, json={"error": "busy"})
        return real(request)

    sidecar.add(FAMILY, "F9", "Neu", utc(10, 11, 0))
    sidecar.add(MUM, "M3", "Ruf mal an", utc(10, 11, 5))
    plugin.transport = httpx.MockTransport(down_for_the_family)
    part = plugin.index_feed(first["cursor"], 60)  # Mum's day first (newest days first, then by chat), then a 503
    assert [i["key"] for i in part["items"]] == [f"{MUM}/2026-11-10"] and part["more"] is True
    plugin.transport = httpx.MockTransport(sidecar)
    rest = plugin.index_feed(part["cursor"], 60)
    assert [i["key"] for i in rest["items"]] == [f"{FAMILY}/2026-11-10"] and rest["more"] is False
    plugin.transport = httpx.MockTransport(lambda request: httpx.Response(503, json={"error": "busy"}))
    with pytest.raises(PluginError, match="503"):  # nothing came at all: the feed fails, its cursor stays
        plugin.index_feed(rest["cursor"], 60)


def test_the_demos_fake_sidecar_feeds_search_too(tmp_path):
    """doorman-admin demo's WhatsApp (doorman/demo/fakes.py) answers what the feed asks, as the shim does."""
    state = tmp_path / "whatsapp.json"
    state.write_text(json.dumps(seed.whatsapp(datetime.now(seed.ZONE))))
    chats = fakes.WhatsAppState(state)
    port = free_port()
    server = fakes.start_http(port, tmp_path / "none.ics", chats, "demo-token")
    try:
        engine = make_engine(tmp_path / "doorman", plugins={"whatsapp": {"enabled": True, "config": {
            "sidecar_url": f"http://127.0.0.1:{port}", "timezone": "Europe/Amsterdam"}}})
        engine.vault.set("whatsapp", "sidecar_token", "demo-token")
        agent = Agent(engine)
        assert engine.search.pull("whatsapp")["changed"] >= 3 and not engine.library.feed_state("whatsapp")["error"]
        [hit] = find(agent, query="lasagne")["results"]
        assert hit["chat"] == "Mama" and hit["passage"].endswith("Mama: Kom je zondag eten? Papa maakt lasagne 🍝")
        chats.send(seed.GROUP, "I'll bring the slides")  # what the agent sends shows up after the next feed
        assert engine.search.pull("whatsapp")["changed"] == 1
        assert [h["chat"] for h in find(agent, query="slides bring")["results"]][:1] == ["INFOB3 group 7"]
    finally:
        server.shutdown()
        server.server_close()
