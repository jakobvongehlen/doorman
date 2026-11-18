"""`doorman recent`: what's new across mail and chats in one list, newest first, each part an ordinary read."""

import importlib.util
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx
import pytest
from fastapi.testclient import TestClient

from doorman import crossread, recent
from doorman.api.agent import create_agent_app
from doorman.plugin_api import Denied
from conftest import Agent, make_engine
from test_teams import FakeGraph, connect

FAMILY, MUM = "120363000@g.us", "4915100000000@s.whatsapp.net"


class FakeSidecar:
    def __init__(self):
        self.down = False
        self.asked: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            return httpx.Response(503, json={"error": "sync not running"})
        if request.url.path == "/chats":
            return httpx.Response(200, json=[
                {"jid": FAMILY, "kind": "group", "name": "Family", "last_message_ts": "2026-11-06T10:00:00Z",
                 "unread_count": 2},
                {"jid": MUM, "kind": "dm", "name": "Mum", "last_message_ts": "2026-10-01T08:00:00Z"}])
        assert request.url.path == "/messages" and request.url.params["limit"] == "1"
        chat = request.url.params["chat"]
        self.asked.append(chat)
        return httpx.Response(200, json=[{"MsgID": "M9" if chat == FAMILY else "M1", "SenderJID": MUM,
                                          "SenderName": "Mum", "Text": "Are   you\ncoming?",
                                          "Timestamp": "2026-11-06T10:00:00Z" if chat == FAMILY
                                          else "2026-10-01T08:00:00Z"}])


@pytest.fixture
def world(tmp_path):
    engine = make_engine(tmp_path, timezone="Europe/Amsterdam", plugins={
        "teams": {"enabled": True, "config": {"client_id": "app-id", "tenant": "uni.example"}},
        "whatsapp": {"enabled": True}, "notes": {"enabled": True}})
    engine.vault.set("whatsapp", "sidecar_token", "tok")  # first: it makes new plugin instances, without the fakes
    graph = FakeGraph()
    engine.registry.instance("teams").transport = httpx.MockTransport(graph)
    connect(engine)
    sidecar = FakeSidecar()
    engine.registry.instance("whatsapp").transport = httpx.MockTransport(sidecar)
    return engine, Agent(engine), sidecar


def test_one_list_newest_first_from_every_chat_service(world):
    engine, agent, sidecar = world
    out = recent.run(engine, agent.session, agent.key, {"since": "2026-11-01"})
    # times in the owner's zone with the offset, whatever zone the service gave them in
    assert [(i["plugin"], i["in"], i["sent"]) for i in out["items"]] == [
        ("whatsapp", "Family", "2026-11-06T11:00:00+01:00"), ("teams", "Anna Berg", "2026-11-05T10:00:00+01:00")]
    family, anna = out["items"]
    assert family == {"sent": "2026-11-06T11:00:00+01:00", "plugin": "whatsapp", "in": "Family", "from": "Mum",
                      "text": "Are you coming?", "unread": True, "ref": f"whatsapp:{FAMILY}/M9", "chat_id": FAMILY}
    assert anna["ref"] == "teams:19:chat-anna/2" and anna["chat_id"] == "19:chat-anna" and "mine" not in anna
    assert out["sources"] == {"teams": {"count": 1}, "whatsapp": {"count": 1}} and "notes" not in out["sources"]
    assert sidecar.asked == [FAMILY]  # Mum's chat is older than since: no message fetched for it
    # since is a moment in Doorman's zone; earlier, the owner's own message in the group chat comes too
    older = recent.run(engine, agent.session, agent.key, {"since": "2026-10-20T16:00:00"})  # summer time: 14:00 UTC
    assert [(i["in"], i.get("mine")) for i in older["items"]] == [("Family", None), ("Anna Berg", None),
                                                                   ("Thesis", True)]
    assert older["since"] == "2026-10-20T14:00:00Z"
    later = recent.run(engine, agent.session, agent.key, {"since": "2026-10-20T16:00:01"})
    assert [i["in"] for i in later["items"]] == ["Family", "Anna Berg"]


def test_sources_limit_and_bad_input(world):
    engine, agent, _ = world
    only = recent.run(engine, agent.session, agent.key, {"since": "2026-10-01", "sources": ["teams"], "limit": 1})
    assert [i["in"] for i in only["items"]] == ["Anna Berg"] and list(only["sources"]) == ["teams"]
    with pytest.raises(Denied) as err:
        recent.run(engine, agent.session, agent.key, {"since": "2026-11-01", "sources": ["mail"]})
    assert "no source here named mail" in err.value.reason
    with pytest.raises(Denied) as err:
        recent.run(engine, agent.session, agent.key, {"since": "yesterday!!"})
    assert "ISO date" in err.value.reason
    with pytest.raises(Denied):
        recent.run(engine, agent.session, agent.key, {})  # since is required; the CLI fills in yesterday


def test_a_failing_source_is_reported_and_leaves_the_rest(world):
    engine, agent, sidecar = world
    sidecar.down = True
    out = recent.run(engine, agent.session, agent.key, {"since": "2026-11-01"})
    assert [i["plugin"] for i in out["items"]] == ["teams"] and "error" in out["sources"]["whatsapp"]
    engine.plugin_setup.switch("teams", tool="recent", mode="off")  # a read switched off: not a source any more
    assert [s["name"] for s in crossread.sources(engine, "recent")] == ["whatsapp"]


def test_api_caps_help_and_the_actor(world):
    engine, agent, _ = world
    client = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {agent.token}"})
    body = client.post("/v1/read/recent", json={"params": {"since": "2026-11-01"}}).json()
    assert body["spotlight"]["tag"] and [i["in"] for i in body["data"]["items"]] == ["Family", "AnnaˆBerg"]
    assert body["data"]["items"][0]["text"] == "Areˆyouˆcoming?"  # datamarked like any third-party read
    assert client.get("/v1/capabilities", params={"brief": "true"}).json()["recent"] == ["teams", "whatsapp"]
    assert "since" in client.get("/v1/capabilities/recent").json()["params"]["properties"]
    actor = Agent(engine, "actor")  # message text is raw third-party content: not for an actor
    as_actor = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {actor.token}"})
    assert as_actor.get("/v1/capabilities").json()["recent"] == {"sources": []}
    out = recent.run(engine, actor.session, actor.key, {"since": "2026-11-01"})
    assert out["items"] == [] and all("skipped" in s for s in out["sources"].values())


def test_a_mail_row_is_shaped_like_mail_search():
    # one jq expression for both: subject, and from as the list of addresses
    row = {"ref": "mail:m1", "id": "m1", "sent": "2026-11-06T19:10:54Z", "folder": "INBOX",
           "from": ["tom@mail.example"], "subject": "Slides?", "unread": True, "attachments": []}
    out = recent.item("mail", row, ZoneInfo("Europe/Amsterdam"))
    assert out["subject"] == out["text"] == "Slides?" and out["from"] == ["tom@mail.example"]
    assert out["sent"] == "2026-11-06T20:10:54+01:00"
    joined = recent.item("mail", {**row, "from": "a@x.example, b@x.example"})  # a plugin that joined them
    assert joined["from"] == ["a@x.example", "b@x.example"]


def load_cli():
    spec = importlib.util.spec_from_file_location(
        "doorman_cli", Path(__file__).resolve().parent.parent / "doorman/agent_skill/scripts/doorman.py")
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    return cli


def test_text_mode_prints_one_line_per_mail_message_and_hit():
    cli = load_cli()
    mail = {"id": "m1", "ref": "mail:m1", "date": "2026-11-06T20:10:54+01:00", "from": ["tom@mail.example"],
            "subject": "Slidesˆfor Thursday?", "unread": True, "attachments": ["a.pdf"], "bulk": True,
            "snippet": "Hey, do you still have the slides"}
    held = {"id": "m2", "ref": "mail:m2", "plugin": "mail", "held": True, "quarantined": True, "reason": "x"}
    assert cli.is_mail_list([mail, held]) and not cli.is_mail_list([{"path": "a.md"}]) and not cli.is_mail_list([])
    assert cli.mail_rows([mail, held]).splitlines() == [
        "Fri 2026-11-06 20:10+01:00  tom@mail.example  “Slidesˆfor Thursday?”  unread 📎1 bulk  id=m1",
        "HELD  mail  held back by the guard, no text  id=m2"]
    chat = {"sent": "2026-11-07T05:06:53+01:00", "plugin": "whatsapp", "in": "Mama", "from": "Mama",
            "text": "Kom je zondag eten?", "unread": True, "chat_id": "316@s.whatsapp.net"}
    rows = cli.recent_rows({"items": [chat, {**mail, "plugin": "mail", "sent": mail["date"]}],
                            "held_back": [held], "sources": {"mail": {"count": 1}, "whatsapp": {"error": "down"}}})
    assert rows.splitlines() == [
        "whatsapp/Mama  Sat 2026-11-07 05:06+01:00  Mama: Kom je zondag eten?  unread  chat=316@s.whatsapp.net",
        "mail  Fri 2026-11-06 20:10+01:00  tom@mail.example  “Slidesˆfor Thursday?”  unread 📎1 bulk  id=m1",
        "HELD  mail  held back by the guard, no text  id=m2",
        "sources: mail 1, whatsapp failed: down"]
    hits = cli.search_rows({"results": [
        {**mail, "source": "mail", "kind": "mail", "title": mail["subject"], "where": "a.pdf",
         "passage": "Die  Folien\nfür Donnerstag", "also": [{"source": "files", "ref": "files:Uni/a.pdf", "path": "Uni/a.pdf"}]},
        {"source": "files", "kind": "file", "title": "project-proposal.md", "path": "Courses/INFOMDM/project-proposal.md",
         "ref": "files:Courses/x.md", "date": "2026-11-07T04:46:53+00:00", "made_by": "hermes",
         "based_on": ["mail:m1"]},
        {"source": "uni", "kind": "event", "title": "Seminar", "date": "2026-11-12T10:00:00+01:00", "ref": "uni:e1",
         "start": "2026-11-12T10:00:00+01:00", "location": "Minnaert 2.02", "calendar": "Uni", "recurring": True,
         "by_meaning": True},
        {"source": "whatsapp", "kind": "chat", "title": "Mama", "chat": "Mama", "date": "2026-11-07T05:06:53+01:00",
         "ref": "whatsapp:m9", "passage": "05:06 Mama: Kom je zondag eten?"}],
        "sources": {"mail": {"count": 1}, "files": {"count": 1}, "chat": {"skipped": "can't filter by from"}},
        "matched": "any_word"})
    assert hits.splitlines() == [
        "mail  Fri 2026-11-06 20:10+01:00  tom@mail.example  “Slidesˆfor Thursday?”  unread 📎1 bulk  id=m1  in: a.pdf",
        "    Die Folien für Donnerstag",
        "    also: files files:Uni/a.pdf “Uni/a.pdf”",
        "files  file  Sat 2026-11-07 04:46+00:00  “Courses/INFOMDM/project-proposal.md”  ref=files:Courses/x.md  made by hermes",
        "    based on: mail:m1",
        "uni  event  Thu 2026-11-12 10:00+01:00  “Seminar”  Minnaert 2.02 · Uni  recurring  by meaning  ref=uni:e1",
        "whatsapp  chat  Sat 2026-11-07 05:06+01:00  “Mama”  Mama  ref=whatsapp:m9",
        "    05:06 Mama: Kom je zondag eten?",
        "sources: mail 1, files 1, chat skipped: can't filter by from; matched: any_word"]
    assert cli.short_time("2026-11-09T09:00:00") == "Mon 2026-11-09 09:00 (no zone)" and cli.short_time("2026-11-09") \
        == "Mon 2026-11-09"
