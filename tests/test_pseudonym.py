"""Pseudonyms: agents get placeholders for doctor's appointments and other sensitive content."""

import pytest
from fastapi.testclient import TestClient

from doorman.api.agent import create_agent_app
from doorman.api.owner import create_owner_app
from doorman.db import Database
from doorman.plugin_api import Denied
from doorman.pseudonym import Pseudonymizer
from conftest import Agent, make_engine

OWNER_URL = "http://localhost:8711"
DOCTOR = {"id": "e1", "calendar": "primary", "summary": "Termin - Herr Dr. med. Hanno Sondermann",
          "start": "2026-11-12T11:15:00+01:00", "end": "2026-11-12T11:30:00+01:00",
          "location": "Vogt-Wells-Straße 14, 22529 Hamburg", "attendees": []}
LECTURE = {"id": "e2", "calendar": "uu", "summary": "INFOARM - Scientific research methods",
           "start": "2026-11-16T15:15:00+01:00", "end": "2026-11-16T17:00:00+01:00", "location": "BBG - 161"}


@pytest.fixture
def ps():
    return Pseudonymizer({}, Database(":memory:"))


def test_a_doctors_appointment_becomes_a_placeholder_with_its_time(ps):
    shown, hidden = ps.hide([DOCTOR, LECTURE], "google_calendar")
    assert hidden == [0]
    doctor = shown[0]
    assert doctor["summary"].startswith("[Gesundheit PSN-") and "Sondermann" not in str(doctor)
    assert "Hamburg" not in doctor["location"]
    assert (doctor["id"], doctor["start"], doctor["end"]) == ("e1", DOCTOR["start"], DOCTOR["end"])
    assert shown[1] == LECTURE
    # stable: the same text gets the same placeholder on every read
    assert ps.hide([DOCTOR], "google_calendar")[0][0]["summary"] == doctor["summary"]


def test_words_inside_words_and_other_languages(ps):
    for title in ("Zahnarzttermin", "Physiotherapie", "huisarts", "dentist check-up", "Hausärztin Müller"):
        assert ps.hide({"summary": title}, "google_calendar")[0]["summary"].startswith("[Gesundheit"), title
    for title in ("Praxisprojekt", "in der Praxis", "Doctoral defence", "Psychologie 101", "Data science"):
        assert ps.hide({"summary": title}, "google_calendar")[0]["summary"] == title, title


def test_dr_in_a_mail_signature_stays_but_a_doctors_sentence_goes(ps):
    mail = {"id": "m1", "subject": "Re: honours project", "from": ["e.vos@uni.example"],
            "body": "Dear Robin,\nI can't make Tuesday. I have a doctor appointment then. Wednesday works.\n"
                    "Dr. Ellen Vos"}
    shown, hidden = ps.hide(mail, "mail_imap")
    assert hidden == [0] and shown["subject"] == mail["subject"]
    assert "doctor" not in shown["body"] and "I can't make Tuesday. [Gesundheit PSN-" in shown["body"]
    assert shown["body"].endswith("Wednesday works.\nDr. Ellen Vos")
    # in a calendar title, "Dr." alone is enough
    assert ps.hide({"summary": "Meeting Dr. Ellen"}, "google_calendar")[0]["summary"].startswith("[Gesundheit")
    assert ps.hide({"subject": "Meeting Dr. Ellen"}, "mail_imap")[0]["subject"] == "Meeting Dr. Ellen"


def test_own_words_and_switching_off(ps):
    ps.save(True, ["Bewerbung", "*vertrag*"])
    assert ps.hide({"subject": "Bewerbung bei ACME"})[0]["subject"].startswith("[Privat PSN-")
    assert ps.hide({"title": "Mietvertrag 2026"})[0]["title"].startswith("[Privat PSN-")
    ps.save(False, [])
    assert ps.hide([DOCTOR], "google_calendar") == ([DOCTOR], [])


def test_restore(ps):
    placeholder = ps.hide({"summary": "Zahnarzt"})[0]["summary"]
    assert ps.restore({"summary": placeholder, "note": f"keep {placeholder} please"}) == \
        {"summary": "Zahnarzt", "note": "keep Zahnarzt please"}
    assert ps.tokens_in({"a": ["x", placeholder]}) == [placeholder.split()[-1].rstrip("]")]
    assert ps.restore("PSN-00000000 unknown") == "PSN-00000000 unknown"


# ------------------------------------------------------------------ through the engine and the APIs


def test_reads_hide_and_the_read_log_shows_the_owner_what(engine):
    agent = Agent(engine)
    agent.call("notes.create", {"title": "Zahnarzttermin Donnerstag", "body": "Versichertenkarte"})
    agent.call("notes.create", {"title": "Groceries", "body": "milk"})
    listed = agent.read("notes.list", {})
    titles = sorted(n["title"] for n in listed)
    assert titles[0] == "Groceries" and titles[1].startswith("[Gesundheit PSN-")
    row = engine.reads.list()[0]
    hidden = [i for i in row["labels"] if i.get("hidden")]
    assert [i["label"] for i in hidden] == ["Zahnarzttermin Donnerstag"]  # the owner sees the real title


def test_a_reversible_write_gets_the_original_back(engine):
    agent = Agent(engine)
    note_id = agent.call("notes.create", {"title": "Zahnarzttermin", "body": "x"})["result"]["id"]
    placeholder = agent.read("notes.get", {"id": note_id})["title"]
    out = agent.call("notes.update", {"id": note_id, "title": placeholder, "body": "moved to Friday"})
    assert out["status"] == "done"
    note = engine.registry.instance("notes").load(note_id)
    assert note["title"] == "Zahnarzttermin" and note["body"] == "moved to Friday"
    # the journal (owner side) has the real text
    assert engine.journal.get(out["entry_id"])["args"]


def test_a_send_with_a_placeholder_is_refused(engine):
    agent = Agent(engine)
    note_id = agent.call("notes.create", {"title": "Arzttermin", "body": "x"})["result"]["id"]
    placeholder = agent.read("notes.get", {"id": note_id})["title"]
    with pytest.raises(Denied) as exc:
        agent.call("notes.send_copy", {"id": note_id, "to": "anna@example.com",
                                       "message": f"FYI: {placeholder}"})
    assert exc.value.code == "pseudonym" and "Arzttermin" not in exc.value.reason
    with pytest.raises(Denied):
        engine.propose_changeset(agent.session, agent.key, "x", [
            {"tool": "notes.send_copy", "args": {"id": note_id, "to": "anna@example.com", "message": placeholder}}])


def test_agent_api_hides_results_journal_and_errors(tmp_path):
    engine = make_engine(tmp_path, public_url=OWNER_URL, dev_owner_token="dev")
    token = engine.auth.create_key("my-agent", "solo")
    agent = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL,
                       headers={"Authorization": "Bearer dev", "X-Requested-With": "doorman"})
    out = agent.post("/v1/tools/notes.create", json={"args": {"title": "Physiotherapie Montag"}}).json()
    assert "Physio" not in out["summary"] and "[Gesundheit PSN-" in out["summary"]
    journal = agent.get("/v1/journal").json()["entries"]
    assert "Physio" not in str(journal)
    # the owner sees it as it is
    assert "Physiotherapie Montag" in str(owner.get("/owner/journal").json()["entries"])

    # privacy settings: own words, preview, off
    saved = owner.post("/owner/privacy", json={"enabled": True, "extra_words": ["Bewerbung"]}).json()
    assert saved["extra_words"] == ["Bewerbung"] and saved["pseudonyms"] >= 1
    preview = owner.post("/owner/privacy/preview", json={"text": "Termin Dr. Sondermann"}).json()
    assert preview["as_title"].startswith("[Gesundheit") and preview["in_mail"] == "Termin Dr. Sondermann"
    assert "privacy.pseudonyms" in [e["tool"] for e in owner.get("/owner/journal").json()["entries"]]
    owner.post("/owner/privacy", json={"enabled": False, "extra_words": []})
    out = agent.post("/v1/tools/notes.create", json={"args": {"title": "Arzt"}}).json()
    assert "Arzt" in out["summary"]


def test_trigger_tasks_are_hidden_but_owner_tasks_are_not(tmp_path):
    engine = make_engine(tmp_path)
    token = engine.auth.create_key("my-agent", "solo")
    agent = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})
    engine.tasks.create("Move my Zahnarzt appointment to Friday")
    engine.tasks.create("New mail: Ihr Termin in der Zahnarztpraxis", origin="trigger:mail", trusted=False)
    texts = sorted(t["text"] for t in agent.get("/v1/tasks").json()["tasks"])
    assert texts[0] == "Move my Zahnarzt appointment to Friday"
    assert texts[1].startswith("New mail: [Gesundheit PSN-") or texts[1].startswith("[Gesundheit PSN-")


def test_a_journal_entry_hides_only_the_private_values(tmp_path):
    """The agent can still say what it did with a private item: when, with which tool, and what happened to
    the item, with only its title as a placeholder."""
    engine = make_engine(tmp_path)
    token = engine.auth.create_key("my-agent", "solo")
    agent = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})
    out = agent.post("/v1/tools/notes.create", json={"args": {"title": "Zahnarzt Donnerstag", "body": "x"}}).json()
    [entry] = agent.get("/v1/journal").json()["entries"]
    assert entry["tool"] == "notes.create" and entry["ts"].startswith("20") and entry["id"] == out["entry_id"]
    assert entry["summary"].startswith("Created note “[Gesundheit PSN-") and "Zahnarzt" not in str(entry)
    assert entry["undo"] == f"doorman undo {out['entry_id']}"


def test_summary_puts_placeholders_for_the_items_private_values(ps):
    state = {"summary": "Zahnarzt", "start": "2026-11-12T16:00:00+01:00", "list": "Health"}
    text = ps.summary("Moved “Zahnarzt” to Thu 17:00", [state, None])
    assert text.startswith("Moved “[Gesundheit PSN-") and text.endswith("” to Thu 17:00")
    assert ps.hide([state])[0][0]["list"] == "Health"  # a list's name is structure, like a calendar's
    assert ps.summary("Moved the Zahnarzt slot", []).startswith("[Gesundheit PSN-")  # free text: its sentence
