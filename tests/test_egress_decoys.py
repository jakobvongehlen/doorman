"""Decoy keys (egress/service.py): a file of fake API keys in the agent's container that it is told never to
touch. Reading it (the observer's tripwire) or using one of its keys (a proxy check, a tool call) stops the
agent: its keys are paused and the proxy cuts its address off (quarantine) until the owner lets it out.
Nothing the agent can read says "decoy" or "honeytoken"."""

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from doorman import clock, engine as engine_module
from doorman.api.agent import create_agent_app
from doorman.api.owner import create_owner_app
from doorman.egress import service
from doorman.plugin_api import Denied
from conftest import FAKE_PLUGINS, Agent, make_engine
from soft_authenticator import SoftAuthenticator
from test_api import CSRF, OWNER_URL, register

IP_A, IP_B = "172.32.0.3", "172.32.0.4"
ROOT = Path(__file__).resolve().parent.parent
SHAPES = {
    "ANTHROPIC_API_KEY": r"sk-ant-api03-[A-Za-z0-9_-]{93}-[A-Za-z0-9_-]{6}AA",
    "OPENAI_API_KEY": r"sk-proj-[A-Za-z0-9_-]{156}",
    "AWS_ACCESS_KEY_ID": r"AKIA[A-Z2-7]{16}",
    "AWS_SECRET_ACCESS_KEY": r"[A-Za-z0-9/+]{40}",
    "GITHUB_TOKEN": r"ghp_[A-Za-z0-9]{36}",
}


@pytest.fixture
def engine(tmp_path):
    eng = make_engine(tmp_path, plugin_paths=[FAKE_PLUGINS], honeytokens=["CANARY-7f3a9c2e"], plugins={
        "mail": {"type": "fake_mail", "enabled": True}, "notes": {"enabled": True}})
    eng._pushes = []
    eng.notifier.push = lambda title, message, **kw: eng._pushes.append((title, kw.get("priority", 3))) or 1
    yield eng
    clock.reset()


def values(engine):
    return [k["value"] for k in json.loads(engine.db.get_setting(service.DECOYS))["keys"]]


def parse(content):
    return dict(line.split("=", 1) for line in content.splitlines() if line and not line.startswith("#"))


def attention(engine, kind):
    return [a for a in engine.attention_list() if a["kind"] == kind]


def journal(engine, tool):
    return [e for e in engine.journal.list(limit=200) if e["tool"] == tool]


def quarantined(engine):
    return engine.egress.policy()["quarantine"]


def trip(engine, ip, event="open"):
    return engine.egress.tripwire({"client_ip": ip, "event": event,
                                   "path": "/opt/data/.config/secrets/api-keys.env", "ts": clock.now().timestamp()})


def seen(engine, ip, *agents):
    for agent in agents:
        engine.egress.client_seen(ip, agent.key["id"])


# ---------------------------------------------------------------- the keys


def test_decoy_file_shapes(engine, tmp_path):
    egress = engine.egress
    assert engine.db.get_setting(service.DECOYS) is None  # nothing until it's needed
    out = egress.decoys_file()
    assert set(out) == {"version", "filename", "content"} and out["filename"] == "api-keys.env"
    assert isinstance(out["version"], str) and out["version"] not in ("", "off")
    lines = out["content"].splitlines()
    assert lines[0] == "# API keys (backup, Oct 2026) - keep out of git"
    keys = parse(out["content"])
    assert list(keys) == list(SHAPES)
    for name, shape in SHAPES.items():
        assert re.fullmatch(shape, keys[name]), name
        assert "dmn_" not in keys[name].lower() and "dme_" not in keys[name].lower()
    stored = json.loads(engine.db.get_setting(service.DECOYS))
    assert set(stored) == {"version", "created", "filename", "keys"} and stored["version"] == out["version"]
    assert [k["name"] for k in stored["keys"]] == list(SHAPES)
    assert egress.decoys_file() == out  # the same set until it's rotated
    # another install gets keys of its own
    other = make_engine(tmp_path / "other", honeytokens=[])
    assert not set(parse(other.egress.decoys_file()["content"]).values()) & set(keys.values())


def test_made_with_the_proxy_token(engine):
    assert engine.db.get_setting(service.DECOYS) is None
    engine.egress.new_token()
    assert len(values(engine)) == 5
    assert engine.journal.list(limit=1)[0]["tool"] == "egress.token"


def test_off_removes_the_file(engine):
    engine.egress.save_settings({"decoys": {"enabled": False}})
    assert engine.egress.decoys_file() == {"version": "off", "filename": "api-keys.env", "content": None}
    engine.egress.save_settings({"decoys": {"enabled": True}})
    assert engine.egress.decoys_file()["content"]


def test_rotation_keeps_every_value_a_honeytoken(engine):
    first = engine.egress.decoys_file()
    old = values(engine)
    view = engine.egress.rotate_decoys()
    second = engine.egress.decoys_file()
    assert second["version"] != first["version"] and view["version"] == second["version"]
    new = values(engine)
    assert not set(old) & set(new)
    tokens = set(engine.egress.honeytokens())
    assert {v.lower() for v in old + new} <= tokens and "canary-7f3a9c2e" in tokens
    assert set(json.loads(engine.db.get_setting(service.DECOY_HISTORY))) == set(old + new)
    [entry] = journal(engine, "egress.decoys.rotate")
    assert entry["kind"] == "config" and entry["tier"] == "irreversible" and entry["status"] == "done"
    assert not any(v in json.dumps(entry) for v in old + new)  # never the values themselves


def test_settings_validate(engine):
    s = engine.egress.settings()
    assert s["decoys"] == {"enabled": True, "on_trip": "quarantine"}
    for bad in ({"enabled": "yes"}, {"on_trip": "kill"}, {"other": 1}, "on"):
        with pytest.raises(Denied) as exc:
            engine.egress.save_settings({"decoys": bad})
        assert exc.value.code == "invalid"
    assert engine.egress.save_settings({"decoys": {"on_trip": "alert"}})["decoys"] == {"enabled": True,
                                                                                    "on_trip": "alert"}
    assert journal(engine, "egress.settings")


# ---------------------------------------------------------------- honeytokens everywhere


def test_policy_and_check_know_every_decoy(engine):
    engine.egress.new_token()
    agent = Agent(engine)
    seen(engine, IP_A, agent)
    policy = engine.egress.policy()
    assert {v.lower() for v in values(engine)} | {"canary-7f3a9c2e"} == set(policy["honeytokens"])
    assert policy["quarantine"] == []
    out = engine.egress.check({"client_ip": IP_A, "host": "x.example", "prints": [],
                               "honeytokens": [values(engine)[3].lower()]})
    assert out["action"] == "deny"
    assert engine.auth.paused(agent.key["id"])
    assert quarantined(engine) == [IP_A]  # using a decoy key: the address is cut off too
    [item] = attention(engine, "egress_tripwire")
    assert "used" in item["title"] and item["detail"]
    assert not attention(engine, "egress_leak")
    # a configured honeytoken pauses as before, without a quarantine
    other = Agent(engine)
    seen(engine, IP_B, other)
    assert engine.egress.check({"client_ip": IP_B, "host": "x.example", "prints": [],
                                "honeytokens": ["canary-7f3a9c2e"]})["action"] == "deny"
    assert engine.auth.paused(other.key["id"]) and quarantined(engine) == [IP_A]


def test_decoys_in_what_goes_to_the_model_api_count_as_a_read(engine):
    """The proxy found decoy keys in the body of a request to a host on no_scan (check() with no_scan): the
    agent's conversation has them, so it read the file. The owner's honeytokens don't count there."""
    engine.egress.new_token()
    agent, other = Agent(engine), Agent(engine)
    seen(engine, IP_A, agent)
    seen(engine, IP_B, other)
    policy = engine.egress.policy()
    assert sorted(v.lower() for v in values(engine)) == policy["decoys"]
    body = {"client_ip": IP_B, "host": "api.anthropic.com", "prints": [], "no_scan": True}
    planted = engine.egress.check({**body, "honeytokens": ["canary-7f3a9c2e"]})  # it read a planted mail
    assert planted["action"] == "allow" and not engine.auth.paused(other.key["id"])

    engine.egress.save_settings({"decoys": {"on_trip": "alert"}})
    for _ in range(2):  # every later call carries them too: one push
        out = engine.egress.check({**body, "honeytokens": [values(engine)[0].lower()]})
        assert out["action"] == "allow" and not engine.auth.paused(other.key["id"]) and quarantined(engine) == []
    [item] = attention(engine, "egress_tripwire")
    assert item["title"] == "Your agent has the decoy keys" and "api.anthropic.com" in item["detail"]
    assert [p for t, p in engine._pushes if t == item["title"]] == [5]
    assert len(journal(engine, "egress.decoys_to_model")) == 1

    engine.egress.save_settings({"decoys": {"on_trip": "quarantine"}})
    out = engine.egress.check({**body, "client_ip": IP_A, "honeytokens": [values(engine)[1].lower()]})
    assert out["action"] == "deny" and engine.auth.paused(agent.key["id"]) and quarantined(engine) == [IP_A]


def test_the_owner_hears_when_the_decoy_keys_arent_watched(engine):
    egress = engine.egress
    egress.new_token()
    armed = {"reachable": True, "armed": True, "error": None}
    egress.proxy_status({"version": "2", "observer": armed})
    assert not attention(engine, "egress_tripwire_off")
    off = {"reachable": True, "armed": False, "error": "[Errno 2] No such file: '/proc/1/root/opt/data/x'"}
    egress.proxy_status({"version": "2", "observer": off})
    assert not attention(engine, "egress_tripwire_off")  # one status: maybe new keys being put in place
    clock.advance(60)
    egress.proxy_status({"version": "2", "observer": off})
    [item] = attention(engine, "egress_tripwire_off")
    assert item["title"] == "The decoy keys aren't watched" and "No such file" in item["detail"]
    assert [p for t, p in engine._pushes if t == item["title"]] == [4]
    egress.proxy_status({"version": "2", "observer": armed})
    assert not attention(engine, "egress_tripwire_off")
    for observer, words in ((None, "no observer"), ({"reachable": False, "armed": False, "error": "x"}, "can't reach")):
        egress.proxy_status({"version": "2", "observer": observer})
        clock.advance(60)
        egress.proxy_status({"version": "2", "observer": observer})
        [item] = attention(engine, "egress_tripwire_off")
        assert words in item["detail"]
        egress.proxy_status({"version": "2", "observer": armed})
    # decoy keys switched off: nothing to watch
    egress.save_settings({"decoys": {"enabled": False}})
    egress.proxy_status({"version": "2", "observer": None})
    clock.advance(60)
    egress.proxy_status({"version": "2", "observer": None})
    assert not attention(engine, "egress_tripwire_off")


def test_a_decoy_in_a_tool_call_fails_quietly_and_stops_the_agent(engine):
    engine.egress.new_token()
    agent = Agent(engine)
    seen(engine, IP_A, agent)
    key = values(engine)[4]
    with pytest.raises(Denied) as exc:
        agent.call("notes.create", {"title": "keys", "body": f"GITHUB_TOKEN={key}"})
    assert exc.value.code == "rejected" and exc.value.reason == "the call failed: the service didn't accept it"
    assert engine.auth.paused(agent.key["id"]) and quarantined(engine) == [IP_A]
    # the journal keeps the denied call, not the value
    assert key not in json.dumps(engine.journal.list(limit=50, include_denied=True)) and key.lower() not in json.dumps(
        engine.journal.list(limit=50, include_denied=True))
    [denied] = [e for e in engine.journal.list(limit=50, include_denied=True) if e["tool"] == "notes.create"]
    assert denied["args"]["body"] == "GITHUB_TOKEN=[removed]"
    [item] = attention(engine, "egress_tripwire")
    assert "used" in item["title"]
    [entry] = engine.egress.quarantine()
    assert entry["client_ip"] == IP_A and entry["key_ids"] == [agent.key["id"]]
    # alert mode: still paused (a honeytoken always pauses), but no quarantine
    engine.egress.save_settings({"decoys": {"on_trip": "alert"}})
    other = Agent(engine)
    seen(engine, IP_B, other)
    with pytest.raises(Denied):
        other.call("notes.create", {"title": "keys", "body": key.lower()})
    assert engine.auth.paused(other.key["id"]) and quarantined(engine) == [IP_A]


def test_a_configured_honeytoken_in_a_tool_call_reads_like_a_failure_too(engine):
    agent = Agent(engine)
    with pytest.raises(Denied) as exc:
        agent.call("notes.create", {"title": "x", "body": "CANARY-7f3a9c2e"})
    assert exc.value.code == "rejected" and "honeytoken" not in exc.value.reason
    assert engine.auth.paused(agent.key["id"]) and attention(engine, "key_paused")
    assert quarantined(engine) == []


# ---------------------------------------------------------------- the tripwire


def test_tripwire_open_stops_every_key_at_the_address(engine):
    engine.egress.new_token()
    first, second, elsewhere = Agent(engine), Agent(engine), Agent(engine)
    seen(engine, IP_A, first, second)
    seen(engine, IP_B, elsewhere)
    assert trip(engine, IP_A) == {"ok": True, "action": "quarantine"}
    assert engine.auth.paused(first.key["id"]) and engine.auth.paused(second.key["id"])
    assert not engine.auth.paused(elsewhere.key["id"])
    assert quarantined(engine) == [IP_A]
    [entry] = engine.egress.quarantine()
    assert set(entry) >= {"client_ip", "since", "reason", "key_ids"}
    assert sorted(entry["key_ids"]) == sorted([first.key["id"], second.key["id"]])
    [item] = attention(engine, "egress_tripwire")
    assert item["title"] == "Your agent read the decoy keys"
    assert ("Your agent read the decoy keys", 5) in engine._pushes
    [entry] = journal(engine, "egress.tripwire")
    assert (entry["kind"], entry["tier"], entry["decision"], entry["status"]) == ("config", "irreversible", "run",
                                                                                   "done")
    assert engine.egress.decoys_view()["last_trip"]["client_ip"] == IP_A
    # the agent hears only that its key is paused, in neutral words
    with pytest.raises(Denied) as exc:
        first.call("notes.create", {"title": "x"})
    assert exc.value.code == "key_paused" and exc.value.reason == engine_module.KEY_PAUSED


def test_tripwire_access_counts_like_open(engine):
    agent = Agent(engine)
    seen(engine, IP_A, agent)
    assert trip(engine, IP_A, "access")["action"] == "quarantine" and engine.auth.paused(agent.key["id"])


def test_tripwire_alert_only_tells(engine):
    engine.egress.save_settings({"decoys": {"on_trip": "alert"}})
    agent = Agent(engine)
    seen(engine, IP_A, agent)
    assert trip(engine, IP_A) == {"ok": True, "action": "alert"}
    assert not engine.auth.paused(agent.key["id"]) and quarantined(engine) == []
    assert attention(engine, "egress_tripwire") and any(p == 5 for _, p in engine._pushes)


def test_dir_open_is_noted(engine):
    agent = Agent(engine)
    seen(engine, IP_A, agent)
    assert trip(engine, IP_A, "dir_open") == {"ok": True, "action": "noted"}
    assert not engine.auth.paused(agent.key["id"]) and quarantined(engine) == []
    [item] = attention(engine, "egress_decoy_dir")
    assert any(t == item["title"] and p == 4 for t, p in engine._pushes)
    assert not attention(engine, "egress_tripwire")
    # a listing right before a read doesn't swallow the read's alarm
    assert trip(engine, IP_A)["action"] == "quarantine" and attention(engine, "egress_tripwire")


def test_repeated_events_within_a_minute_are_one_alarm(engine):
    agent = Agent(engine)
    seen(engine, IP_A, agent)
    trip(engine, IP_A, "open")
    trip(engine, IP_A, "access")
    trip(engine, IP_A, "open")
    assert len(journal(engine, "egress.tripwire")) == 1
    assert len([1 for t, _ in engine._pushes if t == "Your agent read the decoy keys"]) == 1
    clock.advance(61)
    trip(engine, IP_A, "open")
    assert len(journal(engine, "egress.tripwire")) == 2


def test_unknown_address_raises_the_alarm_and_pauses_the_proxys_keys(engine):
    engine.egress.new_token()
    behind_proxy, outside = Agent(engine), Agent(engine)
    seen(engine, IP_A, behind_proxy)
    seen(engine, "10.0.0.7", outside)  # calls Doorman, but never went through the proxy
    engine.egress.ingest([{"ts": clock.now().timestamp(), "client_ip": IP_A, "kind": "http", "host": "a.example",
                           "port": 443, "decision": "allow"}])
    for ip in (None, "172.32.0.99"):
        assert trip(engine, ip)["action"] == "quarantine"
    assert engine.auth.paused(behind_proxy.key["id"]) and not engine.auth.paused(outside.key["id"])
    assert quarantined(engine) == []  # nothing by address: it isn't known whose it is
    assert attention(engine, "egress_tripwire")


def test_bad_tripwire_bodies(engine):
    for bad in ("x", {"event": "close", "path": "/x"}, {"event": "open", "path": 3},
                {"event": "open", "path": "/x", "client_ip": 5}):
        with pytest.raises(Denied) as exc:
            engine.egress.tripwire(bad)
        assert exc.value.code == "invalid"


# ---------------------------------------------------------------- letting it out again


def test_lift_and_lift_on_resume(engine):
    first, second = Agent(engine), Agent(engine)
    seen(engine, IP_A, first)
    seen(engine, IP_B, second)
    trip(engine, IP_A)
    trip(engine, IP_B)
    assert quarantined(engine) == [IP_A, IP_B]
    engine.egress.lift_quarantine(IP_A)
    assert quarantined(engine) == [IP_B]
    assert engine.auth.paused(first.key["id"])  # lifting the address doesn't resume the key
    assert [e for e in journal(engine, "egress.quarantine.lift") if e["args"]["client_ip"] == IP_A]
    assert {a["ref"] for a in attention(engine, "egress_tripwire")} == {IP_B}
    with pytest.raises(Denied) as exc:
        engine.egress.lift_quarantine(IP_A)
    assert exc.value.code == "not_found"
    engine.resume_agent_key(second.key["id"])  # resuming a key lets its address out too
    assert quarantined(engine) == [] and attention(engine, "egress_tripwire") == []
    assert len(journal(engine, "egress.quarantine.lift")) == 2


# ---------------------------------------------------------------- silence towards the agent


def test_agent_facing_texts_are_neutral():
    skill = (ROOT / "doorman/agent_skill/SKILL.md").read_text()
    script = (ROOT / "doorman/agent_skill/scripts/doorman.py").read_text()
    for text in (engine_module.KEY_PAUSED, skill, script):
        assert "honeytoken" not in text.lower() and "decoy" not in text.lower()
    assert engine_module.KEY_PAUSED == ("the owner's Doorman paused your key; nothing more can be done until the "
                                        "owner resumes it. Stop and report.")
    assert "~/.config/secrets/" in skill


# ---------------------------------------------------------------- over HTTP


@pytest.fixture
def setup(tmp_path):
    engine = make_engine(tmp_path, public_url=OWNER_URL, plugin_paths=[FAKE_PLUGINS], honeytokens=["canary-0042"],
                         plugins={"notes": {"enabled": True}})
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL)
    token = engine.auth.create_key("claude", "solo")
    agent = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})
    passkey = SoftAuthenticator("localhost", OWNER_URL)
    register(engine, owner, passkey)
    yield engine, owner, agent, passkey
    clock.reset()


def reauth(owner, passkey):
    options = owner.post("/owner/auth/reauth/options", headers=CSRF).json()
    assert owner.post("/owner/auth/reauth/verify", headers=CSRF, json={
        "challenge_id": options["challenge_id"], "credential": passkey.get(options["options"])}).status_code == 200


def test_proxy_routes(setup):
    engine, _, agent, _ = setup
    nobody = TestClient(create_agent_app(engine))
    for client in (agent, nobody):  # before a token exists, too
        assert client.get("/v1/egress/proxy/decoys").status_code == 401
    token = engine.egress.new_token()
    proxy = TestClient(create_agent_app(engine), headers={"Authorization": f"Bearer {token}"})
    for client in (agent, nobody):
        out = client.get("/v1/egress/proxy/decoys")
        assert out.status_code == 401 and out.json()["code"] == "unauthenticated"
        out = client.post("/v1/egress/proxy/tripwire", json={"client_ip": None, "event": "open", "path": "/x",
                                                              "ts": 1.0})
        assert out.status_code == 401
    decoys = proxy.get("/v1/egress/proxy/decoys").json()
    assert set(decoys) == {"version", "filename", "content"} and decoys["filename"] == "api-keys.env"
    agent.get("/v1/capabilities")  # the key is seen from "testclient"
    out = proxy.post("/v1/egress/proxy/tripwire", json={"client_ip": "testclient", "event": "open",
                                                         "path": "/opt/data/.config/secrets/api-keys.env",
                                                         "ts": clock.now().timestamp()})
    assert out.json() == {"ok": True, "action": "quarantine"}
    assert proxy.get("/v1/egress/proxy/policy").json()["quarantine"] == ["testclient"]
    bad = proxy.post("/v1/egress/proxy/tripwire", json={"event": "nope", "path": "/x"})
    assert bad.status_code == 403 and bad.json()["code"] == "invalid"


def test_owner_view_lift_and_rotate(setup):
    engine, owner, agent, passkey = setup
    overview = owner.get("/owner/egress").json()
    assert overview["decoys"] == {"enabled": True, "on_trip": "quarantine", "version": None, "created": None,
                                  "last_trip": None}
    assert overview["quarantine"] == []
    engine.egress.new_token()
    agent.get("/v1/capabilities")
    engine.egress.tripwire({"client_ip": "testclient", "event": "open", "path": "/x", "ts": clock.now().timestamp()})
    overview = owner.get("/owner/egress").json()
    d = overview["decoys"]
    assert d["version"] and d["created"] and d["last_trip"]["client_ip"] == "testclient"
    [q] = overview["quarantine"]
    assert q["client_ip"] == "testclient" and q["key_ids"] and q["since"] and q["reason"]
    assert not any(v in json.dumps(overview) for v in values(engine))  # the owner app never gets the values
    clock.advance(6 * 60)
    for path, body in (("/owner/egress/quarantine/lift", {"client_ip": "testclient"}),
                       ("/owner/egress/decoys/rotate", {})):
        stale = owner.post(path, headers=CSRF, json=body)
        assert stale.status_code == 403 and stale.json()["code"] == "reauth", path
    reauth(owner, passkey)
    version = d["version"]
    rotated = owner.post("/owner/egress/decoys/rotate", headers=CSRF, json={}).json()
    assert rotated["version"] != version and not any(v in json.dumps(rotated) for v in values(engine))
    assert owner.post("/owner/egress/quarantine/lift", headers=CSRF, json={"client_ip": "testclient"}).json() == {
        "ok": True}
    assert owner.get("/owner/egress").json()["quarantine"] == []
    missing = owner.post("/owner/egress/quarantine/lift", headers=CSRF, json={"client_ip": "testclient"})
    assert missing.status_code == 403 and missing.json()["code"] == "not_found"


def test_the_agent_never_sees_a_decoy_value(setup):
    engine, _, agent, _ = setup
    engine.egress.new_token()
    secret = values(engine)
    seen_texts = [agent.get(p).text for p in ("/v1/capabilities", "/v1/status", "/v1/events", "/v1/egress/blocked")]
    out = agent.post("/v1/tools/notes.create", json={"args": {"title": "k", "body": secret[0]}})
    assert out.status_code == 403
    body = out.json()
    assert body["code"] == "rejected" and secret[0] not in body["reason"]
    seen_texts += [agent.get(p).text for p in ("/v1/capabilities", "/v1/status")]
    for text in seen_texts:
        assert not any(v in text or v.lower() in text for v in secret)
        assert "honeytoken" not in text.lower() and "decoy" not in text.lower()


def test_blocked_list_leaves_out_silent_blocks(setup):
    engine, _, agent, _ = setup
    agent.get("/v1/capabilities")
    rec = {"ts": clock.now().timestamp(), "client_ip": "testclient", "kind": "http", "host": "x.example",
           "port": 443, "decision": "deny"}
    engine.egress.ingest([{**rec, "rule": "honeytoken", "detail": "a honeytoken"},
                          {**rec, "rule": "quarantine", "detail": "quarantined"},
                          {**rec, "rule": "deny_list", "detail": "on the block list"}])
    assert [r["rule"] for r in agent.get("/v1/egress/blocked").json()["blocked"]] == ["deny_list"]
