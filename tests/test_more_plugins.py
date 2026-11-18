"""WhatsApp against a fake of the sidecar, and the payment tier against a stand-in bank."""

import json
from types import SimpleNamespace

import httpx
import pytest

from doorman.plugin_api import Denied
from conftest import FAKE_PLUGINS, Agent, make_engine


def test_whatsapp_send_policy(tmp_path):
    engine = make_engine(tmp_path, plugins={"whatsapp": {"enabled": True}})
    engine.vault.set("whatsapp", "sidecar_token", "tok")
    sent = []

    def sidecar(request: httpx.Request):
        assert request.headers["Authorization"] == "Bearer tok"
        if request.url.path == "/chats":
            return httpx.Response(200, json=[{"jid": "4915100000000@s.whatsapp.net", "kind": "dm", "name": "Mum"},
                                             {"jid": "120363000@g.us", "kind": "group", "name": "Family"}])
        if request.url.path == "/messages":
            return httpx.Response(200, json=[{"MsgID": "M1", "SenderJID": "4915100000000@s.whatsapp.net",
                                              "Text": "Are you coming?", "Timestamp": "2026-11-03T18:00:00Z"}])
        body = json.loads(request.content)
        if body["text"] == "queued too long":  # the sidecar says 4xx only when nothing went out
            return httpx.Response(409, json={"error": "request timed out in the send queue before dispatch; "
                                                      "it was not sent"})
        sent.append(body)
        return httpx.Response(200, json={"sent": True, "to": body["chat"], "id": "S1"})

    engine.registry.instance("whatsapp").transport = httpx.MockTransport(sidecar)
    engine.db.exec("INSERT INTO trust(kind, value, label, created) VALUES('chat','120363000@g.us','Family','x')")
    agent = Agent(engine)
    chats = agent.read("whatsapp.chats")
    assert chats[1]["name"] == "Family" and chats[1]["id"] == "120363000@g.us"
    assert agent.read("whatsapp.messages", {"chat": "120363000@g.us"})[0]["text"] == "Are you coming?"
    family = agent.call("whatsapp.send", {"chat": "120363000@g.us", "text": "20 minutes late"})
    assert family["status"] == "waiting_approval" and family["warnings"] == []
    assert "Family" in engine.journal.get(family["entry_id"])["summary"]
    other = agent.call("whatsapp.send", {"chat": "4915100000000@s.whatsapp.net", "text": "hi"})
    assert other["status"] == "waiting_approval" and other["warnings"]
    assert sent == []
    engine.approvals.decide(family["approval_id"], approve=True)
    engine.approvals.decide(other["approval_id"], approve=False)
    assert sent == [{"chat": "120363000@g.us", "text": "20 minutes late"}]
    assert engine.journal.get(family["entry_id"])["result"]["id"] == "S1"
    late = agent.call("whatsapp.send", {"chat": "120363000@g.us", "text": "queued too long"})
    engine.approvals.decide(late["approval_id"], approve=True)
    assert engine.journal.get(late["entry_id"])["status"] == "failed"  # NotSent: certainly not out
    with pytest.raises(Denied):
        agent.call("whatsapp.send", {"chat": "not-a-jid", "text": "x"})


def test_whatsapp_chats_by_name_or_number(tmp_path):
    engine = make_engine(tmp_path, plugins={"whatsapp": {"enabled": True}})
    engine.vault.set("whatsapp", "sidecar_token", "tok")
    asked = []

    def sidecar(request: httpx.Request):  # an older sidecar: ignores query, so the plugin filters too
        asked.append(dict(request.url.params))
        return httpx.Response(200, json=[{"jid": "4915100000000@s.whatsapp.net", "kind": "dm", "name": "Mum"},
                                         {"jid": "120363000@g.us", "kind": "group", "name": "Family"},
                                         {"jid": "31612345678@s.whatsapp.net", "kind": "dm", "name": "Sanne"}])

    engine.registry.instance("whatsapp").transport = httpx.MockTransport(sidecar)
    agent = Agent(engine)
    assert [c["name"] for c in agent.read("whatsapp.chats", {"query": "fam"})] == ["Family"]
    assert asked[-1] == {"query": "fam"}
    assert [c["name"] for c in agent.read("whatsapp.chats", {"query": "+49 151 0000"})] == ["Mum"]
    assert asked[-1] == {"query": "491510000"}
    assert [c["name"] for c in agent.read("whatsapp.chats", {"query": "0031 6 1234"})] == ["Sanne"]
    assert len(agent.read("whatsapp.chats", {"limit": 2})) == 2 and asked[-1] == {"limit": "2"}
    assert len(agent.read("whatsapp.chats")) == 3 and asked[-1] == {}


def test_payments_always_need_approval_and_respect_budget(tmp_path):
    """The payment tier, with a stand-in bank (tests/fakes/plugins/fake_bank): Doorman ships no bank plugin."""
    engine = make_engine(tmp_path, payments={"monthly_budget": 100.0}, plugin_paths=[FAKE_PLUGINS],
                         plugins={"bank": {"type": "fake_bank", "enabled": True,
                                           "config": {"iban": "DE00123456780000000000"}}})
    engine.db.exec("INSERT INTO trust(kind, value, label, created) VALUES('iban','DE02120300000000202051','power','x')")
    agent = Agent(engine)
    out = agent.call("bank.prepare_transfer", {"iban": "DE02 1203 0000 0000 2020 51", "name": "Stadtwerke",
                                               "amount": 84.20, "reference": "Oktober"})
    assert out["status"] == "waiting_approval" and out["warnings"] == []
    payment = [c for c in engine.journal.get(out["entry_id"])["checks"]["checks"] if c["name"] == "payment"]
    assert payment[0]["detail"].startswith("84.20 of 100.00 budget")
    result = engine.approvals.decide(out["approval_id"], approve=True)
    assert result["results"][0]["result"] == {"written_down": True}
    with pytest.raises(Denied) as exc:
        agent.call("bank.prepare_transfer", {"iban": "DE02120300000000202051", "name": "Stadtwerke", "amount": 20})
    assert exc.value.code == "budget"
    follow_up = engine.entry_view(engine.journal.get(out["entry_id"]))["follow_up"]
    assert "refund" in follow_up

    balance = agent.read("bank.balance")
    assert balance["amount"] == 1234.5
    assert agent.session["read_private"] == 1
