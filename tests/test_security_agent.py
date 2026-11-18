"""Security review fixes for the agent API, approvals and policy (9 Nov): what an agent can change about its own
checks, what its undo touches, where hidden text turns up again, records of switched-off plugins, and what a
send points at."""

from email.message import EmailMessage

import pytest

from doorman import manifest_check
from doorman.plugin_api import Denied
from conftest import Agent, make_engine


def setup_call(engine, agent, tool, args):
    return engine.setup.call(agent.session, agent.key, tool, args)


def warned(out):
    return any("new recipient" in w for w in out["warnings"])


# ------------------------------------------------------------------ which folder counts as Sent


def sent_mail(to: str, mid: str, sender: str = "me@example.com") -> bytes:
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = sender, to, "Project"
    message["Message-ID"], message["Date"] = f"<{mid}>", "Tue, 03 Nov 2026 10:00:00 +0000"
    message.set_content("See you Thursday.")
    return bytes(message)


@pytest.fixture
def mailbox(tmp_path):
    """A mailbox set up in the app (so agents may configure it) whose archive has a Sent folder and a folder
    holding a forged mail "from" the owner to an attacker."""
    engine = make_engine(tmp_path, owner={"identities": ["me@example.com"]})
    engine.plugin_setup.add("box", "mail_imap", {"imap_host": "127.0.0.1", "smtp_host": "127.0.0.1",
                                           "from_address": "me@example.com",
                                           "folders": {"sent": "Sent", "drafts": "Drafts"}})
    archive = engine.registry.instance("box").archive
    archive.store(sent_mail("x@evil.example", "forged@evil.example"), "Forged", 1, [])
    return engine, Agent(engine)


def test_an_agent_cant_choose_which_folder_counts_as_sent(mailbox):
    """`folders.sent` decides whose mail counts as "you wrote to them before". An agent that could point it at a
    folder holding a forged mail (From: the owner, To: an attacker) would make the attacker known: no new
    recipient warning, and a tool on Auto could send without asking."""
    engine, agent = mailbox
    note_id = agent.call("notes.create", {"title": "Gym", "body": "Tue 18:00"})["result"]["id"]
    assert warned(agent.call("notes.send_copy", {"id": note_id, "to": "x@evil.example"}))
    for args in ({"plugin": "box", "set": {"folders": {"sent": "Forged"}}},
                 {"plugin": "box", "set": {"folders": {"drafts": "Entwürfe", "sent": "Forged"}}},
                 {"plugin": "box", "set": {"folders": "{sent: Forged}"}}):
        with pytest.raises(Denied, match="folders.sent is the owner's") as exc:
            setup_call(engine, agent, "doorman.configure", args)
        assert exc.value.code == "setting"
    assert engine.registry.configured()["box"]["config"]["folders"] == {"sent": "Sent", "drafts": "Drafts"}
    assert warned(agent.call("notes.send_copy", {"id": note_id, "to": "x@evil.example"}))
    # the owner's own choice counts (which is why an agent mustn't make it)
    engine.plugin_setup.configure("box", {**engine.registry.configured()["box"]["config"], "folders": {"sent": "Forged"}})
    assert not warned(agent.call("notes.send_copy", {"id": note_id, "to": "x@evil.example"}))


def test_an_agent_still_sets_the_other_folder_names(mailbox):
    engine, agent = mailbox
    out = setup_call(engine, agent, "doorman.configure",
                     {"plugin": "box", "set": {"folders": {"drafts": "Entwürfe", "archive": "Archiv"}}})
    assert out["status"] == "done"
    folders = engine.registry.configured()["box"]["config"]["folders"]
    assert folders == {"sent": "Sent", "drafts": "Entwürfe", "archive": "Archiv"}  # merged over the owner's
    setup_call(engine, agent, "doorman.configure", {"plugin": "box", "set": {"folders": {"archive": None}}})
    assert engine.registry.configured()["box"]["config"]["folders"] == {"sent": "Sent", "drafts": "Entwürfe"}
    # unsetting takes out what agents may set; the owner's Sent stays
    setup_call(engine, agent, "doorman.configure", {"plugin": "box", "unset": ["folders"]})
    assert engine.registry.configured()["box"]["config"]["folders"] == {"sent": "Sent"}
    listed = {p["name"]: p for p in engine.setup.read(agent.session, agent.key, "doorman.plugins")}["box"]
    assert "folders.drafts" in listed["agent_settings"] and "folders.sent" not in listed["agent_settings"]
    assert "folders" not in listed["agent_settings"]


def test_microsoft_mail_has_the_same_limits():
    """mail_outlook extends mail_imap and takes its agent_settings: the same Sent folder rule."""
    from doorman.registry import BUILTIN_DIR, merged_manifest

    for name in ("mail_imap", "mail_outlook"):
        manifest = merged_manifest(BUILTIN_DIR / name)
        assert "folders" not in manifest["agent_settings"] and "folders.sent" not in manifest["agent_settings"]
        assert manifest["agent_add_only"] == ["archive_skip_folders"]


def test_manifest_check_takes_keys_of_a_mapping():
    base = {"name": "pin", "version": "1", "description": "x", "config": {"folders": "f", "skip": "s"}}
    assert manifest_check.check({**base, "agent_settings": ["folders.drafts", "skip"],
                                 "agent_add_only": ["skip"]})[0] == []
    errors = manifest_check.check({**base, "agent_settings": ["nope.drafts"], "agent_add_only": ["folders"]})[0]
    assert any("agent_settings: nope.drafts isn't one of the settings" in e for e in errors)
    assert any("agent_add_only: folders isn't one of the agent_settings" in e for e in errors)


# ------------------------------------------------------------------ lists agents may only narrow (or only add to)


def test_contact_books_only_narrow(tmp_path):
    """Which address books count decides who is "in your contacts" (no new recipient warning): an agent may
    leave one out, never add one back or clear the choice."""
    engine = make_engine(tmp_path)
    agent = Agent(engine)
    engine.plugin_setup.add("people", "contacts", {"url": "https://dav.example.com/", "books": ["Personal"]})
    for args in ({"plugin": "people", "set": {"books": ["Personal", "Work"]}},
                 {"plugin": "people", "unset": ["books"]},
                 {"plugin": "people", "set": {"books": ""}}):
        with pytest.raises(Denied, match="only narrow books") as exc:
            setup_call(engine, agent, "doorman.configure", args)
        assert exc.value.code == "setting", args
    assert engine.registry.configured()["people"]["config"]["books"] == ["Personal"]
    engine.plugin_setup.add("all_books", "contacts", {"url": "https://dav.example.com/"})  # every book: any choice narrows
    setup_call(engine, agent, "doorman.configure", {"plugin": "all_books", "set": {"books": ["Work"]}})
    assert engine.registry.configured()["all_books"]["config"]["books"] == ["Work"]


def test_folders_the_owner_kept_out_of_the_archive_stay_out(mailbox):
    engine, agent = mailbox
    engine.plugin_setup.configure("box", {**engine.registry.configured()["box"]["config"],
                                    "archive_skip_folders": ["Private"]})
    for args in ({"plugin": "box", "set": {"archive_skip_folders": ["Lists"]}},
                 {"plugin": "box", "unset": ["archive_skip_folders"]}):
        with pytest.raises(Denied, match="only add to archive_skip_folders") as exc:
            setup_call(engine, agent, "doorman.configure", args)
        assert exc.value.code == "setting", args
    setup_call(engine, agent, "doorman.configure", {"plugin": "box", "set": {"archive_skip_folders": ["Private", "Lists"]}})
    assert engine.registry.configured()["box"]["config"]["archive_skip_folders"] == ["Private", "Lists"]


# ------------------------------------------------------------------ an agent's undo and what it would take along


def test_an_agent_undo_doesnt_take_along_a_later_change_the_owner_approved(engine, agent):
    """revert_entry undoes later changes to the same item first. The agent may undo its Auto change A, but not
    B on the same note, which the owner approved: undoing A would undo B too, so nothing is undone."""
    notes = engine.registry.instance("notes")
    note_id = agent.call("notes.create", {"title": "Gym", "body": "Mon"})["result"]["id"]
    a = agent.call("notes.update", {"id": note_id, "body": "Tue"})
    engine.plugin_setup.switch("notes", tool="update", mode="ask")
    b = agent.call("notes.update", {"id": note_id, "body": "Wed"})
    assert b["status"] == "waiting_approval"
    assert engine.approvals.decide(b["approval_id"], approve=True)["results"][0]["status"] == "done"
    engine.plugin_setup.switch("notes", tool="update", mode="auto")  # A on its own would be the agent's to undo
    with pytest.raises(Denied, match=f"would also undo entry {b['entry_id']}") as exc:
        engine.agent_undo(agent.session, agent.key, entry_id=a["entry_id"])
    assert exc.value.code == "owner_only" and "approved" in exc.value.reason
    assert notes.load(note_id)["body"] == "Wed"
    assert engine.journal.get(a["entry_id"])["status"] == engine.journal.get(b["entry_id"])["status"] == "done"
    # the owner can: their revert takes both back
    engine.revert_entry(a["entry_id"])
    assert notes.load(note_id)["body"] == "Mon"


def test_an_agent_undo_of_a_task_reports_such_a_change_and_undoes_nothing_of_it(engine, agent):
    notes = engine.registry.instance("notes")
    task_id = engine.tasks.create("Gym notes")
    _, session = engine.tasks.claim(agent.key, task_id)
    worker = Agent.__new__(Agent)
    worker.engine, worker.key, worker.session_id = engine, agent.key, session["id"]
    note_id = worker.call("notes.create", {"title": "Gym", "body": "Mon"})["result"]["id"]
    a = worker.call("notes.update", {"id": note_id, "body": "Tue"})
    engine.plugin_setup.switch("notes", tool="update", mode="ask")
    b = worker.call("notes.update", {"id": note_id, "body": "Wed"})
    engine.approvals.decide(b["approval_id"], approve=True)
    engine.plugin_setup.switch("notes", tool="update", mode="auto")
    out = engine.agent_undo(worker.session, worker.key, task_id=task_id)
    assert out["status"] == "not_undone" and out["reverted"] == []
    assert a["entry_id"] in {p["entry_id"] for p in out["problems"]}
    assert notes.load(note_id)["body"] == "Wed"


def test_an_agent_undo_doesnt_take_along_a_change_whose_tool_is_now_ask_me(engine, agent):
    notes = engine.registry.instance("notes")
    made = agent.call("notes.create", {"title": "Gym", "body": "Mon"})
    agent.call("notes.update", {"id": made["result"]["id"], "body": "Tue"})
    engine.plugin_setup.switch("notes", tool="update", mode="ask")  # the owner wants to see updates first from now on
    with pytest.raises(Denied, match="set to Ask me") as exc:
        engine.agent_undo(agent.session, agent.key, entry_id=made["entry_id"])
    assert exc.value.code == "owner_only"
    assert notes.load(made["result"]["id"])["body"] == "Tue"


# ------------------------------------------------------------------ records follow the plugin's switches


@pytest.fixture
def records_world(tmp_path):
    from conftest import FAKE_PLUGINS

    engine = make_engine(tmp_path, plugin_paths=[FAKE_PLUGINS], plugins={
        "mail": {"type": "fake_mail", "enabled": True}, "notes": {"enabled": True}})
    reader = Agent(engine, "reader")
    for source, summary in (("mail:m1", "Invoice over 84,20 EUR."), ("notes:1", "A note's summary.")):
        engine.put_record(reader.session, reader.key, {"source": source, "category": "information",
                                                       "suggested_action": "review", "summary": summary})
    return engine, reader


@pytest.mark.parametrize("role", ["solo", "actor", "reader"])
def test_records_of_a_switched_off_plugin_or_read_are_left_out(records_world, role):
    """A reader's summary is as much the plugin's content as the item: with the plugin off, or its item read
    (mail.read) Off, its records are left out for every key, as its items and their search hits are."""
    engine, reader = records_world
    who = reader if role == "reader" else Agent(engine, role)
    refs = lambda: [r["ref"] for r in engine.list_records(who.session, who.key)]  # noqa: E731
    assert refs() == ["notes:1", "mail:m1"]
    engine.plugin_setup.switch("mail", tool="read", mode="off")
    assert refs() == ["notes:1"]
    assert engine.list_records(who.session, who.key, source="mail") == []
    engine.plugin_setup.switch("mail", tool="read", mode="auto")
    assert refs() == ["notes:1", "mail:m1"]
    engine.plugin_setup.switch("mail", enabled=False)
    assert refs() == ["notes:1"]


def test_records_of_a_removed_plugin_are_left_out(tmp_path):
    engine = make_engine(tmp_path)
    reader, actor = Agent(engine, "reader"), Agent(engine, "actor")
    engine.plugin_setup.add("box", "mail_imap", {"imap_host": "imap.example.com", "smtp_host": "smtp.example.com"})
    engine.put_record(reader.session, reader.key, {"source": "box:m1", "category": "information",
                                                   "suggested_action": "review", "summary": "Hello."})
    assert [r["ref"] for r in engine.list_records(actor.session, actor.key)] == ["box:m1"]
    engine.plugin_setup.remove("box")
    assert engine.list_records(actor.session, actor.key) == []


@pytest.mark.parametrize("role", ["solo", "actor"])
def test_only_reader_keys_file_records(engine, role):
    """Records are the reader's (doorman-reader); the actor reads them as such, so a solo or actor key can't
    plant one."""
    agent = Agent(engine, role)
    with pytest.raises(Denied, match="records come from the reader") as exc:
        engine.put_record(agent.session, agent.key, {"source": "notes:1", "category": "information",
                                                     "suggested_action": "review", "summary": "Planted."})
    assert exc.value.code == "role"
    assert engine.db.all("SELECT id FROM records") == []


# ------------------------------------------------------------------ what a send points at is part of the approval


def sent_copies(engine):
    path = engine.registry.instance("notes").ctx.data_dir / "sent.jsonl"
    return path.read_text().splitlines() if path.exists() else []


def test_editing_the_note_after_asking_makes_its_send_stale(engine, agent):
    """notes.send_copy {id, to} only points at a note; the owner approves the note's text the screen shows.
    An agent that edits the note afterwards (a reversible write, on Auto) mustn't get the new text out with
    the old approval: the tap's hash no longer matches, and nothing is sent."""
    from doorman import clock

    engine.db.exec("INSERT INTO trust(kind, value, label, created) VALUES('email','anna@example.com','Anna',?)",
                   (clock.iso(),))  # no warning on it, so Accept on its push approves in place
    note_id = agent.call("notes.create", {"title": "Plan", "body": "Lunch at noon"})["result"]["id"]
    asked = agent.call("notes.send_copy", {"id": note_id, "to": "anna@example.com"})
    shown = engine.approvals.get(asked["approval_id"])
    assert shown["entries"][0]["outgoing"]["text"] == "Lunch at noon"
    seen = shown["payload_hash"]
    assert engine.approvals.accept_from_notification(asked["approval_id"])  # Accept on the push would approve in place
    agent.call("notes.update", {"id": note_id, "body": "The door code is 4711"})
    with pytest.raises(Denied) as exc:
        engine.approvals.decide(asked["approval_id"], approve=True, seen_hash=seen, method="notification")
    assert exc.value.code == "payload_changed"
    assert engine.approvals.get(asked["approval_id"])["status"] == "failed"
    assert sent_copies(engine) == []
    # unchanged, it goes out as before
    again = agent.call("notes.send_copy", {"id": note_id, "to": "anna@example.com"})
    row = engine.approvals.get(again["approval_id"])
    assert engine.approvals.decide(again["approval_id"], approve=True, seen_hash=row["payload_hash"])[
        "results"][0]["status"] == "done"
    assert "4711" in sent_copies(engine)[0]


def test_a_note_changed_after_the_approval_isnt_sent(engine, agent):
    """Checked again right before the send: an approved entry that waits for its run (sends.py; after a
    restart, the worker sends it) fails when the note changed since it was asked for."""
    note_id = agent.call("notes.create", {"title": "Plan", "body": "Lunch at noon"})["result"]["id"]
    asked = agent.call("notes.send_copy", {"id": note_id, "to": "anna@example.com"})
    engine.journal.update(asked["entry_id"], status="approved")  # approved, not yet claimed by a run
    agent.call("notes.update", {"id": note_id, "body": "The door code is 4711"})
    out = engine.execute_entry(asked["entry_id"])
    assert out["status"] == "failed" and "changed after it was asked for" in out["error"]
    assert "Nothing went out" in engine.journal.get(asked["entry_id"])["error"]
    assert sent_copies(engine) == []


def test_an_owner_edit_keeps_the_send_sendable(engine, agent):
    note_id = agent.call("notes.create", {"title": "Plan", "body": "Lunch at noon"})["result"]["id"]
    asked = agent.call("notes.send_copy", {"id": note_id, "to": "anna@example.com", "message": "FYI"})
    row = engine.approvals.get(asked["approval_id"])
    editable = row["entries"][0]["editable"]
    if "message" not in editable:
        pytest.skip("send_copy's message isn't editable")
    edited = engine.approvals.edit(asked["approval_id"], asked["entry_id"], {"message": "See you"},
                                  row["payload_hash"])
    new = engine.approvals.get(edited["approval_id"])
    assert engine.approvals.decide(edited["approval_id"], approve=True, seen_hash=new["payload_hash"])[
        "results"][0]["status"] == "done"


# ------------------------------------------------------------------ hidden text stays hidden in another plugin


@pytest.fixture
def private(tmp_path):
    """A mailbox, the file archive and an agent on the HTTP API. The agent was shown a calendar entry
    "Dr. Müller" as a placeholder; "Dr." only hides in calendars, so in mail or a file the same words would
    pass."""
    from fastapi.testclient import TestClient

    from doorman.api.agent import create_agent_app
    from conftest import FAKE_PLUGINS

    root = tmp_path / "archive"
    root.mkdir()
    engine = make_engine(tmp_path, plugin_paths=[FAKE_PLUGINS], plugins={
        "mail": {"type": "fake_mail", "enabled": True}, "notes": {"enabled": True},
        "files": {"enabled": True, "config": {"root": str(root)}}})
    client = TestClient(create_agent_app(engine),
                        headers={"Authorization": f"Bearer {engine.auth.create_key('claude', 'solo')}"})
    [event], _ = engine.pseudonyms.hide([{"summary": "Dr. Müller", "start": "2026-11-12T11:15:00+01:00"}],
                                        "google_calendar")
    placeholder = event["summary"]
    token = placeholder.split()[-1].rstrip("]")
    assert token.startswith("PSN-") and engine.pseudonyms.text("Dr. Müller", "fake_mail") == "Dr. Müller"
    return engine, client, root, placeholder, token


def test_a_calendar_placeholder_in_a_mail_draft_stays_a_placeholder(private):
    import json

    engine, client, _, placeholder, token = private
    out = client.post("/v1/tools/mail.draft", json={"args": {
        "to": ["anna@example.com"], "subject": f"Re: {placeholder}", "body": f"About {placeholder} on Thursday."}}).json()
    assert out["status"] == "done", out
    assert "Müller" not in json.dumps(out) and token in out["summary"]
    # the real write carries the real text, and the owner sees it
    draft = engine.registry.instance("mail").message(out["result"]["id"])
    assert draft["subject"] == "Re: Dr. Müller" and draft["body"] == "About Dr. Müller on Thursday."
    assert "Dr. Müller" in engine.entry_view(engine.journal.get(out["entry_id"]))["summary"]
    # reading it back, the journal and doorman status: the placeholder
    read = client.post("/v1/read/mail.read", json={"id": out["result"]["id"]}).json()
    assert "Müller" not in json.dumps(read) and token in json.dumps(read)
    entries = client.get("/v1/journal").json()["entries"]
    assert "Müller" not in json.dumps(entries) and token in json.dumps(entries)
    # after a restart too
    from doorman.pseudonym import Pseudonymizer

    again = Pseudonymizer(engine.config, engine.db)
    assert again.text("Moved: Dr. Müller.", "fake_mail") == f"Moved: {placeholder}."
    assert again.text("Dr. Müllerstraße 3", "fake_mail") == "Dr. Müllerstraße 3"  # whole words only


def test_a_calendar_placeholder_kept_in_a_file_stays_a_placeholder(private):
    import json

    engine, client, root, placeholder, token = private
    out = client.post("/v1/tools/files.keep", json={"args": {
        "content": f"This week\n{placeholder} moved to Friday 10:00.\nGym on Monday.", "name": "week.md"}}).json()
    assert out["status"] == "done", out
    assert (root / "Agent" / "week.md").read_text().splitlines()[1] == "Dr. Müller moved to Friday 10:00."
    read = client.post("/v1/read/files.read", json={"path": "Agent/week.md"}).json()
    text = json.dumps(read)
    assert "Müller" not in text and token in text and "Gym" in text  # only the hidden words go


def test_changeset_previews_hide_with_each_actions_plugin(private):
    """A changeset's preview goes to the agent under its action's plugin's rules: "Dr." in a calendar's title
    is hidden there as it is in the calendar's reads."""
    import json

    from doorman.api.agent import _changeset_for_agent

    engine = private[0]
    engine.plugin_setup.add("cal", "google_calendar", {})
    cs = {"id": 1, "title": "This week", "comment": None, "status": "applied",
          "actions": [{"tool": "notes.create", "args": {}}, {"tool": "cal.update_event", "args": {}}],
          "preview": [{"index": 0, "tool": "notes.create", "summary": "Create note “Gym”", "tier": "reversible"},
                      {"index": 1, "tool": "cal.update_event", "summary": "Move “Dr. Jansen” to 17:00",
                       "tier": "reversible"}],
          "result": {"results": [{"index": 1, "status": "done", "summary": "Move “Dr. Jansen” to 17:00"}],
                     "approval_id": None}}
    out = _changeset_for_agent(cs, engine)
    assert "Jansen" not in json.dumps(out)
    assert out["preview"][0]["summary"] == "Create note “Gym”" and out["preview"][1]["tool"] == "cal.update_event"
    assert out["result"]["results"][0]["status"] == "done"
