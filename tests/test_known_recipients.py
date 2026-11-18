"""Who the owner already knows counts as theirs in the recipient check (policy.Policy.known_destinations):
destinations they approved a send to before, and mail in their Sent folder. Contacts are in test_contacts.py,
against Radicale. A send that ran without asking never makes an address known; a payment's IBAN never is."""

import json
from email.message import EmailMessage

import pytest
from fastapi.testclient import TestClient

from doorman import clock
from doorman.api.owner import create_owner_app
from doorman.approvals_util import accept_in_place
from conftest import FAKE_PLUGINS, Agent, make_engine
from test_guard import CSRF, OWNER_URL, reauth


def note(agent):
    return agent.call("notes.create", {"title": "Gym", "body": "Tue 18:00"})["result"]["id"]


def warned(out):
    return any("new recipient" in w for w in out["warnings"])


def known(engine, out):
    return {d["value"]: d["source"] for d in engine.approvals.get(out["approval_id"])["entries"][0]["known_destinations"]}


# written to before: sends the owner approved


def test_an_address_the_owner_approved_a_send_to_is_known_next_time(engine, agent):
    note_id = note(agent)
    first = agent.call("notes.send_copy", {"id": note_id, "to": "anna.berg@uni.example"})
    assert warned(first)
    assert engine.approvals.decide(first["approval_id"], approve=True)["results"][0]["status"] == "done"

    again = agent.call("notes.send_copy", {"id": note_id, "to": "Anna.Berg@uni.example"})
    assert again["status"] == "waiting_approval" and again["warnings"] == []  # still asks, without the warning
    day = f"{clock.now().day} {clock.now():%b}"
    assert known(engine, again) == {"anna.berg@uni.example": f"you wrote to them before ({day})"}
    # so Accept on its push sends it, where the first one opened the app
    assert not accept_in_place(engine.approvals.get(first["approval_id"])["entries"], False)
    assert accept_in_place(engine.approvals.get(again["approval_id"])["entries"], False)
    # another agent, outside any task: the same, it's the owner's decision that counts
    assert Agent(engine).call("notes.send_copy", {"id": note_id, "to": "anna.berg@uni.example"})["warnings"] == []


def test_a_denied_or_unsent_send_makes_nobody_known(engine, agent):
    note_id = note(agent)
    denied = agent.call("notes.send_copy", {"id": note_id, "to": "x@evil.example"})
    engine.approvals.decide(denied["approval_id"], approve=False)
    waiting = agent.call("notes.send_copy", {"id": note_id, "to": "y@evil.example"})
    assert warned(agent.call("notes.send_copy", {"id": note_id, "to": "x@evil.example"}))
    assert warned(agent.call("notes.send_copy", {"id": note_id, "to": "y@evil.example"}))
    assert engine.journal.get(waiting["entry_id"])["status"] == "waiting_approval"


def test_a_send_that_ran_without_asking_makes_nobody_known(tmp_path):
    """Set to run without asking, a send to an address from the task goes out by itself. That is the task's
    trust, for that task: it must not turn into "written to before" for every later send."""
    engine = make_engine(tmp_path, plugins={"notes": {"enabled": True, "no_approval": True}})
    agent = Agent(engine)
    task_id = engine.tasks.create("Send the gym note to anna.berg@uni.example")
    note_id = note(agent)
    sent = agent.call("notes.send_copy", {"id": note_id, "to": "anna.berg@uni.example"}, task_id=task_id)
    assert sent["status"] == "done" and engine.journal.get(sent["entry_id"])["decision"] == "direct"

    outside = agent.call("notes.send_copy", {"id": note_id, "to": "anna.berg@uni.example"})
    assert outside["status"] == "waiting_approval" and warned(outside)


def test_with_written_before_off_the_warning_comes_back(tmp_path):
    engine = make_engine(tmp_path, trust={"written_before": False})
    agent = Agent(engine)
    note_id = note(agent)
    first = agent.call("notes.send_copy", {"id": note_id, "to": "anna.berg@uni.example"})
    engine.approvals.decide(first["approval_id"], approve=True)
    assert warned(agent.call("notes.send_copy", {"id": note_id, "to": "anna.berg@uni.example"}))
    assert engine.policy.known_settings() == {"contacts": True, "written_before": False,
                                              "locked": ["written_before"]}


def test_an_iban_is_never_known_by_an_earlier_payment(tmp_path):
    engine = make_engine(tmp_path, plugin_paths=[FAKE_PLUGINS], plugins={
        "bank": {"type": "fake_bank", "enabled": True, "config": {"iban": "DE00123456780000000000"}}})
    agent = Agent(engine)
    transfer = {"iban": "DE02 1203 0000 0000 2020 51", "name": "Stadtwerke", "amount": 20.0, "reference": "Okt"}
    first = agent.call("bank.prepare_transfer", transfer)
    assert warned(first)
    assert engine.approvals.decide(first["approval_id"], approve=True)["results"][0]["status"] == "done"
    assert warned(agent.call("bank.prepare_transfer", transfer))
    assert engine.policy.known_destinations([("iban", "DE02120300000000202051")]) == {}


def test_entries_from_before_targets_were_stored_still_count(engine, agent):
    """Sends approved before 7 Nov have only `destinations` (the values) in their checks."""
    note_id = note(agent)
    first = agent.call("notes.send_copy", {"id": note_id, "to": "anna.berg@uni.example"})
    engine.approvals.decide(first["approval_id"], approve=True)
    checks = engine.journal.get(first["entry_id"])["checks"]
    checks.pop("targets")
    engine.db.exec("UPDATE journal SET checks=? WHERE id=?", (json.dumps(checks), first["entry_id"]))
    assert agent.call("notes.send_copy", {"id": note_id, "to": "anna.berg@uni.example"})["warnings"] == []


# written to before: the owner's own Sent folder (the mail archive)


def sent_mail(to: str, mid: str, sender: str = "me@example.com") -> bytes:
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = sender, to, "Project"
    message["Message-ID"], message["Date"] = f"<{mid}>", "Tue, 03 Nov 2026 10:00:00 +0000"
    message.set_content("See you Thursday.")
    return bytes(message)


@pytest.fixture
def mailbox(tmp_path):
    """A mail_imap instance whose archive holds a Sent folder, filled without a server: `folders.sent` names
    it, so finding it needs no IMAP LIST."""
    engine = make_engine(tmp_path, owner={"identities": ["me@example.com"]}, plugins={
        "notes": {"enabled": True},
        "mail": {"type": "mail_imap", "enabled": True, "config": {
            "imap_host": "127.0.0.1", "smtp_host": "127.0.0.1", "from_address": "me@example.com",
            "folders": {"sent": "Sent"}}}})
    archive = engine.registry.instance("mail").archive
    return engine, Agent(engine), archive


def test_an_address_in_the_owners_sent_mail_is_known(mailbox):
    engine, agent, archive = mailbox
    archive.store(sent_mail("Tutor <tutor@uni.example>", "a1@example.com"), "Sent", 1, ["\\Seen"])
    out = agent.call("notes.send_copy", {"id": note(agent), "to": "tutor@uni.example"})
    assert out["warnings"] == []
    assert known(engine, out) == {"tutor@uni.example": "you wrote to them before (3 Nov)"}


def test_sent_mail_doorman_touched_or_not_from_the_owner_doesnt_count(mailbox):
    engine, agent, archive = mailbox
    # in Sent, but an agent moved it there (any action of Doorman's on that message counts)
    archive.store(sent_mail("x@evil.example", "forged@evil.example"), "Sent", 1, [])
    engine.journal.create(kind="action", plugin="mail", tool="mail.move", tier="reversible", decision="run",
                          status="done", object_ref="forged@evil.example", args={"id": "forged@evil.example"})
    # in Sent, but not from one of the owner's addresses
    archive.store(sent_mail("y@evil.example", "b1@example.com", sender="someone@else.example"), "Sent", 2, [])
    # from the owner, but in the inbox (a copy to themselves, or a forged From)
    archive.store(sent_mail("z@evil.example", "c1@example.com"), "INBOX", 1, [])
    note_id = note(agent)
    for address in ("x@evil.example", "y@evil.example", "z@evil.example"):
        assert warned(agent.call("notes.send_copy", {"id": note_id, "to": address})), address


def test_sent_mail_counts_only_with_written_before_on(mailbox):
    engine, agent, archive = mailbox
    archive.store(sent_mail("tutor@uni.example", "a1@example.com"), "Sent", 1, [])
    engine.policy.save_known_settings({"written_before": False})
    assert warned(agent.call("notes.send_copy", {"id": note(agent), "to": "tutor@uni.example"}))


# the switches in the owner app


def owner_app(tmp_path, **config):
    from soft_authenticator import SoftAuthenticator
    from test_api import register

    engine = make_engine(tmp_path, public_url=OWNER_URL, **config)
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL)
    passkey = SoftAuthenticator("localhost", OWNER_URL)
    register(engine, owner, passkey)
    return engine, owner, passkey


def test_owner_app_switches_are_journaled_and_switching_on_needs_a_fresh_passkey(tmp_path):
    engine, owner, passkey = owner_app(tmp_path)
    assert owner.get("/owner/trust").json()["known"] == {"contacts": True, "written_before": True, "locked": []}
    clock.advance(6 * 60)  # the passkey check at login is no longer fresh
    off = owner.post("/owner/trust/known", headers=CSRF, json={"contacts": False})  # stricter: no passkey
    assert off.status_code == 200 and off.json()["contacts"] is False
    assert engine.journal.list(limit=1)[0]["summary"] == "Trust: people in your contacts get the new recipient warning"
    stale = owner.post("/owner/trust/known", headers=CSRF, json={"contacts": True})
    assert stale.status_code == 403 and stale.json()["code"] == "reauth"
    reauth(owner, passkey)
    assert owner.post("/owner/trust/known", headers=CSRF, json={"contacts": True}).json()["contacts"] is True
    assert engine.journal.list(limit=1)[0]["summary"] == "Trust: people in your contacts count as yours"
    assert owner.post("/owner/trust/known", headers=CSRF, json={"contacts": "yes"}).json()["code"] == "invalid"


def test_a_setting_doorman_yaml_fixes_cant_be_switched_in_the_app(tmp_path):
    engine, owner, _ = owner_app(tmp_path, trust={"contacts": False})
    assert owner.get("/owner/trust").json()["known"]["locked"] == ["contacts"]
    out = owner.post("/owner/trust/known", headers=CSRF, json={"contacts": True})
    assert out.json()["code"] == "invalid" and "doorman.yaml" in out.json()["reason"]
    assert engine.policy.known_settings()["contacts"] is False
