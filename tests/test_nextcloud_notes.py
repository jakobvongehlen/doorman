import base64
import itertools
import json

import httpx
import pytest

from conftest import Agent, make_engine

PREFIX = "/index.php/apps/notes/api/v1"


class FakeNotes:
    """The Notes app's API as far as the plugin uses it: basic auth, ETags on PUT, 404s."""

    def __init__(self):
        self.notes: dict[int, dict] = {}
        self.ids = itertools.count(100)
        self.clock = itertools.count(1_700_000_000, 60)
        self.listed: list[dict] = []  # each GET /notes: its parameters and how long the client waits

    def add(self, title, content="", category=""):
        note_id = next(self.ids)
        self.notes[note_id] = {"id": note_id, "title": title, "content": content, "category": category,
                               "favorite": False, "modified": next(self.clock), "etag": f"e{note_id}-0", "readonly": False}
        return note_id

    def __call__(self, request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        if auth != "Basic " + base64.b64encode(b"robin:app-pw").decode():
            return httpx.Response(401)
        path = request.url.path.removeprefix(PREFIX)
        if path == "/notes" and request.method == "GET":
            self.listed.append({**request.url.params, "timeout": request.extensions["timeout"]["read"]})
            notes = [dict(n) for n in self.notes.values()]
            if request.url.params.get("exclude") == "content":
                for n in notes:
                    n.pop("content")
            return httpx.Response(200, json=notes)
        if path == "/notes" and request.method == "POST":
            body = json.loads(request.content)
            note_id = self.add(body["title"], body.get("content", ""), body.get("category", ""))
            self.notes[note_id]["favorite"] = bool(body.get("favorite"))
            return httpx.Response(200, json=self.notes[note_id])
        note_id = int(path.rsplit("/", 1)[1])
        note = self.notes.get(note_id)
        if note is None:
            return httpx.Response(404, json={})
        if request.method == "GET":
            return httpx.Response(200, json=note)
        if request.method == "PUT":
            if request.headers.get("If-Match") not in (None, f'"{note["etag"]}"'):
                return httpx.Response(412)
            note.update(json.loads(request.content))
            version = int(note["etag"].rsplit("-", 1)[1]) + 1
            note["etag"], note["modified"] = f"e{note_id}-{version}", next(self.clock)
            return httpx.Response(200, json=note)
        if request.method == "DELETE":
            del self.notes[note_id]
            return httpx.Response(200, json={})
        return httpx.Response(405)


@pytest.fixture
def nc(tmp_path):
    engine = make_engine(tmp_path, plugins={"ncnotes": {"type": "nextcloud_notes", "enabled": True,
                                                        "config": {"url": "https://cloud.example.com"}}})
    engine.vault.set("ncnotes", "username", "robin")
    engine.vault.set("ncnotes", "password", "app-pw")
    fake = FakeNotes()
    engine.registry.instance("ncnotes").transport = httpx.MockTransport(fake)
    return engine, Agent(engine), fake


def test_read_list_and_categories(nc):
    engine, agent, fake = nc
    fake.add("Groceries", "oat milk\ncoffee", "Home")
    fake.add("Thesis outline", "1. Background\n2. Method", "Uni")
    assert [n["title"] for n in agent.read("ncnotes.list")] == ["Thesis outline", "Groceries"]
    assert [n["title"] for n in agent.read("ncnotes.list", {"category": "Uni"})] == ["Thesis outline"]
    assert all(call["exclude"] == "content" for call in fake.listed)  # a list needs no text
    assert agent.read("ncnotes.categories") == [{"category": "Home", "notes": 1}, {"category": "Uni", "notes": 1}]
    note = agent.read("ncnotes.get", {"id": 101})
    assert note["content"] == "1. Background\n2. Method" and note["ref"] == "ncnotes:101"


def find(agent, **params):
    return agent.engine.search.any_word(agent.session, agent.key, params)


def test_every_note_feeds_doorman_search(nc):
    engine, agent, fake = nc
    groceries = fake.add("Groceries", "oat milk\ncoffee", "Home")
    thesis = fake.add("Thesis outline", "1. Background\n2. Method", "Uni")
    fake.notes[thesis]["favorite"] = True
    fake.add("Old todo", "buy ink", "Agent trash")  # deleted through Doorman: not searchable
    out = engine.registry.instance("ncnotes").index_feed(None, 7)
    assert out == {"complete": True, "items": [
        {"key": str(groceries), "kind": "note", "title": "Groceries", "text": "oat milk\ncoffee", "in": "Home",
         "date": "2023-11-14T22:13:20+00:00", "fields": {"category": "Home", "favorite": False}},
        {"key": str(thesis), "kind": "note", "title": "Thesis outline", "text": "1. Background\n2. Method",
         "in": "Uni", "date": "2023-11-14T22:14:20+00:00", "fields": {"category": "Uni", "favorite": True}}]}
    assert fake.listed[-1] == {"timeout": 7}  # one listing, with the text, waited for no longer than the budget

    engine.search.pull("ncnotes")
    [hit] = find(agent, query="coffee")["results"]
    assert hit["ref"] == f"ncnotes:{groceries}" and hit["title"] == "Groceries" and "coffee" in hit["passage"]
    assert hit["category"] == "Home" and hit["favorite"] is False and hit["kind"] == "note"
    assert [h["title"] for h in find(agent, **{"in": "uni"})["results"]] == ["Thesis outline"]
    assert find(agent, query="ink")["results"] == []
    # a note moved to the trash leaves search at the next pull; a change shows
    agent.call("ncnotes.delete", {"id": groceries})
    agent.call("ncnotes.append", {"id": thesis, "text": "3. Results"})
    engine.search.pull("ncnotes")
    assert find(agent, query="coffee")["results"] == [] and engine.library.keys("ncnotes") == {str(thesis)}
    assert [h["ref"] for h in find(agent, query="Results")["results"]] == [f"ncnotes:{thesis}"]
    # with its get read off, the notes' text isn't searchable at all
    engine.plugin_setup.switch("ncnotes", tool="get", mode="off")
    assert "ncnotes" not in find(agent, query="Results")["sources"]


def test_write_append_and_revert(nc):
    engine, agent, fake = nc
    made = agent.call("ncnotes.create", {"title": "Reading list", "content": "Pearl, Causality", "category": "Uni"})
    assert made["status"] == "done", made
    note_id = made["result"]["id"]
    added = agent.call("ncnotes.append", {"id": note_id, "text": "Hernán & Robins, What If"})
    assert fake.notes[note_id]["content"] == "Pearl, Causality\nHernán & Robins, What If"
    diff = engine.entry_view(engine.journal.get(added["entry_id"]))["diff"]
    assert {"sign": "+", "field": "content", "value": "Pearl, Causality\nHernán & Robins, What If"} in diff
    assert engine.revert_entry(added["entry_id"])["reverted"] == [added["entry_id"]]
    assert fake.notes[note_id]["content"] == "Pearl, Causality"
    assert engine.revert_entry(made["entry_id"])["reverted"] == [made["entry_id"]]
    assert note_id not in fake.notes


def test_delete_goes_to_agent_trash_and_back(nc):
    engine, agent, fake = nc
    note_id = fake.add("Old todo", "buy ink", "Home")
    deleted = agent.call("ncnotes.delete", {"id": note_id})
    assert fake.notes[note_id]["category"] == "Agent trash"
    assert agent.read("ncnotes.list") == []  # the trash is hidden from reads
    engine.revert_entry(deleted["entry_id"])
    assert fake.notes[note_id]["category"] == "Home"  # same id: later reverts keep working


def test_revert_keeps_what_the_owner_changed_since(nc):
    engine, agent, fake = nc
    note_id = fake.add("Plan", "draft", "")
    renamed = agent.call("ncnotes.update", {"id": note_id, "changes": {"title": "Trip plan"}})
    fake.notes[note_id]["content"] = "draft, edited on the phone"  # the owner, in the Notes app
    fake.notes[note_id]["etag"] = f"e{note_id}-7"
    result = engine.revert_entry(renamed["entry_id"])
    assert result["reverted"] == [renamed["entry_id"]], result
    assert (fake.notes[note_id]["title"], fake.notes[note_id]["content"]) == ("Plan", "draft, edited on the phone")


def test_wrong_password_shows_up_in_check(nc):
    engine, agent, fake = nc
    engine.vault.set("ncnotes", "password", "wrong")
    engine.registry.invalidate("ncnotes")
    engine.registry.instance("ncnotes").transport = httpx.MockTransport(fake)
    assert "app password" in engine.registry.instance("ncnotes").check()
