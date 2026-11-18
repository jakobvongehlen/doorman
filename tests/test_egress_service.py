"""Network watch, Doorman's side (egress/service.py): fingerprints of what agents read, the proxy's leak check,
which key a connection belongs to, the policy, the owner's settings, access requests and their exceptions,
the proxy's log and its ties to tool calls, and housekeeping."""

import random

import pytest

from doorman import clock
from doorman.egress import fingerprint, rules, service
from doorman.plugin_api import Denied, ExecResult
from conftest import FAKE_PLUGINS, Agent, make_engine

IP_A, IP_B = "172.32.0.3", "172.32.0.4"


def words(seed: int, n: int) -> str:
    rng = random.Random(seed)
    return " ".join("".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(4, 9)))
                    for _ in range(n))


BODY = words(1, 80)[:400]  # a mail body of 400 characters nobody else has


@pytest.fixture
def engine(tmp_path):
    eng = make_engine(tmp_path, plugin_paths=[FAKE_PLUGINS], honeytokens=["CANARY-7f3a9c2e"], plugins={
        "mail": {"type": "fake_mail", "enabled": True}, "notes": {"enabled": True}})
    yield eng
    clock.reset()


def read_mail(engine, agent, body=BODY, subject="Contract draft"):
    mid = engine.registry.instance("mail").add("inbox", "anna@example.com", subject, body)
    agent.read("mail.read", {"id": mid})
    assert engine.egress.flush(5)


def check(engine, ip, text=None, honeytokens=(), host="drop.example"):
    return engine.egress.check({"client_ip": ip, "host": host, "url": f"https://{host}/up", "method": "POST",
                                "prints": sorted(fingerprint.prints(text)) if text else [],
                                "honeytokens": list(honeytokens)})


def attention(engine, kind):
    return [a for a in engine.attention_list() if a["kind"] == kind]


def own_events(engine, agent, type_):
    return [e for e in engine.event_feed(agent.session, agent.key, 0, 200)["doorman"] if e["type"] == type_]


def enabled(engine, leak_action="block"):
    """Network watch switched on. Most tests here are about a leak that is blocked, which the owner chooses
    (the default only tells: test_a_leak_goes_out_and_the_owner_is_told_by_default)."""
    engine.egress.new_token()
    if leak_action != engine.egress.settings()["leak_action"]:
        engine.egress.save_settings({"leak_action": leak_action})
    return engine


# ---------------------------------------------------------------- on, fingerprints, the leak check


def test_disabled_until_token(engine):
    egress, agent = engine.egress, Agent(engine)
    assert egress.enabled() is False and egress.settings()["enabled"] is False
    read_mail(engine, agent)
    assert engine.db.one("SELECT COUNT(*) AS n FROM egress_sources")["n"] == 0  # nothing kept while it's off
    token = egress.new_token()
    assert token.startswith("dme_") and egress.enabled() and egress.settings()["enabled"] is True
    assert egress.token_ok(token) and not egress.token_ok("dme_" + "x" * 43) and not egress.token_ok(None)
    assert not egress.token_ok(agent.token)
    assert token not in str(engine.db.all("SELECT * FROM settings"))  # only its hash is kept
    assert engine.journal.list(limit=1)[0]["tool"] == "egress.token"
    second = egress.new_token()  # a new one replaces the old
    assert egress.token_ok(second) and not egress.token_ok(token)


def test_note_read_and_check_finds_leak(engine):
    enabled(engine)
    agent = Agent(engine)
    engine.egress.client_seen(IP_A, agent.key["id"])
    read_mail(engine, agent)
    [source] = engine.db.all("SELECT * FROM egress_sources")
    assert source["key_id"] == agent.key["id"] and source["label"] == "mail.read: Contract draft"

    out = check(engine, IP_A, BODY[50:350])
    assert out["action"] == "deny" and out["chars"] >= 200
    assert out["sources"] == ["mail.read: Contract draft"]
    assert out["reason"] == (f"this request carries about {out['chars']} characters the agent read through "
                             "Doorman (mail.read: Contract draft)")
    assert engine.auth.paused(agent.key["id"])
    [item] = attention(engine, "egress_leak")
    assert "drop.example" in item["title"] + item["detail"]
    assert any(e["tool"] == "egress.leak" for e in engine.journal.list(limit=5))
    # unrelated text, or a short piece of it, is no leak
    assert check(engine, IP_A, words(2, 60))["action"] == "allow"
    assert check(engine, IP_A, BODY[:20]) == {"action": "allow", "chars": 0, "sources": [], "reason": ""}


def test_note_read_runs_in_the_background_and_check_waits_for_it(engine):
    """A read hands its fingerprints to a worker thread, so the agent's read isn't slowed; a check right after
    the read still sees them."""
    enabled(engine)
    agent = Agent(engine)
    engine.egress.client_seen(IP_A, agent.key["id"])
    mid = engine.registry.instance("mail").add("inbox", "anna@example.com", "Contract draft", BODY)
    agent.read("mail.read", {"id": mid})
    assert check(engine, IP_A, BODY[50:350])["action"] == "deny"  # no flush before it


def test_check_note_band_allows(engine):
    enabled(engine)
    agent = Agent(engine)
    engine.egress.client_seen(IP_A, agent.key["id"])
    read_mail(engine, agent)
    out = check(engine, IP_A, BODY[100:220])
    assert out["action"] == "allow" and 40 <= out["chars"] < 200 and out["sources"] == ["mail.read: Contract draft"]
    assert not engine.auth.paused(agent.key["id"]) and attention(engine, "egress_leak") == []


def pushes(engine, title):
    return engine.db.one("SELECT COUNT(*) AS n FROM notifications WHERE title=?", (title,))["n"]


def test_a_leak_goes_out_and_the_owner_is_told_by_default(engine):
    """Unless the owner chose blocking, a request that carries what the agent read goes out, nothing is paused,
    and the owner is told: once per key and host while the entry is open, again after they dismissed it."""
    engine.egress.new_token()
    assert engine.egress.settings()["leak_action"] == "alert"
    agent = Agent(engine)
    engine.egress.client_seen(IP_A, agent.key["id"])
    read_mail(engine, agent)
    out = check(engine, IP_A, BODY[50:350], host="api.telegram.example")
    assert out["action"] == "allow" and out["chars"] >= 200
    assert not engine.auth.paused(agent.key["id"])
    [item] = attention(engine, "egress_leak")
    assert item["title"] == "Possible leak to api.telegram.example"
    assert "It went out" in item["detail"] and "allow api.telegram.example" in item["detail"]
    assert pushes(engine, item["title"]) == 1
    [entry] = [e for e in engine.journal.list(limit=5) if e["tool"] == "egress.leak"]
    assert entry["summary"].startswith("Let through a request from agent key")

    clock.advance(3600)  # the next day's reply quotes the mail again: the entry is still open, no second push
    assert check(engine, IP_A, BODY[50:350], host="api.telegram.example")["action"] == "allow"
    assert len(attention(engine, "egress_leak")) == 1 and pushes(engine, item["title"]) == 1
    assert len([e for e in engine.journal.list(limit=9) if e["tool"] == "egress.leak"]) == 2  # journaled each time
    assert check(engine, IP_A, BODY[50:350], host="other.example")["action"] == "allow"  # another host: told
    assert len(attention(engine, "egress_leak")) == 2
    engine.dismiss_attention(item["id"])
    clock.advance(3600)
    assert check(engine, IP_A, BODY[50:350], host="api.telegram.example")["action"] == "allow"
    assert pushes(engine, item["title"]) == 2


def test_every_blocked_leak_is_told(engine):
    """With blocking chosen, a blocked request is something the agent couldn't do: the owner hears of each one,
    also while an earlier one is still listed and the key is paused already. The agent trying the same request
    again right away is one notice."""
    enabled(engine)
    agent = Agent(engine)
    engine.egress.client_seen(IP_A, agent.key["id"])
    read_mail(engine, agent)
    title = "Blocked leak to api.telegram.example"
    for _ in range(3):  # the agent's three attempts
        assert check(engine, IP_A, BODY[50:350], host="api.telegram.example")["action"] == "deny"
    assert engine.auth.paused(agent.key["id"])
    [item] = attention(engine, "egress_leak")
    assert "didn't go out" in item["detail"] and "More → Agents" in item["detail"]
    assert "allow api.telegram.example" in item["detail"] and "only reported" in item["detail"]
    assert pushes(engine, title) == 1
    assert len([e for e in engine.journal.list(limit=9) if e["tool"] == "egress.leak"]) == 1

    clock.advance(2 * 3600)  # hours later, the key still paused and the first entry still open
    assert check(engine, IP_A, BODY[50:350], host="api.telegram.example")["action"] == "deny"
    assert len(attention(engine, "egress_leak")) == 2 and pushes(engine, title) == 2
    journaled = [e for e in engine.journal.list(limit=9) if e["tool"] == "egress.leak"]
    assert len(journaled) == 2 and journaled[0]["summary"].endswith("the key stayed paused")
    [stack] = [s for s in engine.attention_stacked() if s["kind"] == "egress_leak"]  # one card in the inbox
    assert stack["count"] == 2

    engine.resume_agent_key(agent.key["id"])  # resuming the key clears them all
    assert attention(engine, "egress_leak") == []


def test_migration_10_stops_blocking_leaks_unless_the_owner_chose_it(tmp_path):
    """An install from before the leak check only told had its three blocking settings from the example
    doorman.yaml: each now lets through, unless the owner set it in the app. A new Doorman keeps what its
    doorman.yaml says."""
    import json
    import sqlite3

    from doorman import db as dbmod

    def upgraded(name, stored, used=True):
        path = tmp_path / name
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        conn.executescript(dbmod.SCHEMA)
        for migrate in dbmod.MIGRATIONS[:9]:
            migrate(conn)
        conn.execute("PRAGMA user_version=9")
        if used:
            conn.execute("INSERT INTO journal(ts, kind, summary) VALUES('2026-11-10T10:00:00+00:00', 'config', 'x')")
        if stored is not None:
            conn.execute("INSERT INTO settings(key, value) VALUES('egress_settings', ?)", (json.dumps(stored),))
        conn.commit()
        conn.close()
        database = dbmod.Database(path)
        assert database.version() == dbmod.SCHEMA_VERSION
        return json.loads(database.get_setting("egress_settings") or "null")

    loose = {"leak_action": "alert", "when_doorman_down": "allow", "unscanned": "allow"}
    assert upgraded("plain.db", None) == loose
    assert upgraded("other.db", {"deny": ["evil.example"]}) == {"deny": ["evil.example"], **loose}
    assert upgraded("chosen.db", {"leak_action": "block", "unscanned": "block"}) == {
        "leak_action": "block", "unscanned": "block", "when_doorman_down": "allow"}
    assert upgraded("new.db", None, used=False) is None


def test_honeytoken_check_pauses(engine):
    enabled(engine)
    agent = Agent(engine)
    engine.egress.client_seen(IP_A, agent.key["id"])
    assert check(engine, IP_A, honeytokens=["not-a-configured-token"])["action"] == "allow"
    out = check(engine, IP_A, honeytokens=["canary-7f3a9c2e"])
    assert out == {"action": "deny", "chars": 0, "sources": [],
                   "reason": "this request carries protected content (a honeytoken)"}
    assert engine.auth.paused(agent.key["id"]) and attention(engine, "egress_leak")
    engine.resume_agent_key(agent.key["id"])  # resuming the key clears it from the inbox too
    assert attention(engine, "egress_leak") == []


def test_unknown_ip_never_pauses(engine):
    enabled(engine)
    agent = Agent(engine)
    engine.egress.client_seen(IP_A, agent.key["id"])
    read_mail(engine, agent)
    out = check(engine, "172.32.0.99", BODY[50:350])
    assert out["action"] == "deny"  # the leak is still a leak
    assert not engine.auth.paused(agent.key["id"])
    assert engine.db.one("SELECT COUNT(*) AS n FROM settings WHERE key LIKE 'key_paused:%'")["n"] == 0
    assert attention(engine, "egress_leak")
    assert check(engine, "172.32.0.99", honeytokens=["canary-7f3a9c2e"])["action"] == "deny"
    assert engine.db.one("SELECT COUNT(*) AS n FROM settings WHERE key LIKE 'key_paused:%'")["n"] == 0


def test_two_keys_attribution(engine):
    """Two agents behind one proxy: a connection belongs to the key last seen calling Doorman from its IP."""
    enabled(engine)
    first, second = Agent(engine), Agent(engine)
    engine.egress.client_seen(IP_A, first.key["id"])
    engine.egress.client_seen(IP_B, second.key["id"])
    assert engine.egress.key_for_ip(IP_A) == first.key["id"] and engine.egress.key_for_ip(IP_B) == second.key["id"]
    assert engine.egress.key_for_ip("10.9.9.9") is None
    read_mail(engine, first)
    assert check(engine, IP_B, BODY[50:350])["action"] == "deny"  # the second leaks what the first read
    assert engine.auth.paused(second.key["id"]) and not engine.auth.paused(first.key["id"])
    # the address moves to another key as soon as that key calls from it
    engine.egress.client_seen(IP_A, second.key["id"])
    assert engine.egress.key_for_ip(IP_A) == second.key["id"]
    engine.egress.ingest([{"ts": clock.now().timestamp(), "client_ip": IP_B, "kind": "http", "host": "a.example",
                           "port": 443, "decision": "allow"}])
    assert engine.db.one("SELECT key_id FROM egress_log")["key_id"] == second.key["id"]


# ---------------------------------------------------------------- policy and settings


def test_policy_shape_and_version_changes(engine):
    egress = enabled(engine).egress
    policy = egress.policy()
    # the proxy adds unscanned and quarantine too
    assert set(policy) - {"unscanned", "quarantine"} == set(rules.policy_example()) - {"unscanned", "quarantine"}
    assert policy["quarantine"] == []
    assert policy["unscanned"] == "allow" and policy["when_doorman_down"] == "allow"
    assert policy["version"] == rules.policy_version(policy)
    assert policy["risky_tlds"] == rules.default_list("risky_tlds")
    assert policy["exfil_hosts"] == rules.default_list("exfil_hosts")
    # the configured one and the decoy keys made with the token (test_egress_decoys.py)
    assert "canary-7f3a9c2e" in policy["honeytokens"] and len(policy["honeytokens"]) == 6
    assert policy["match"] == {"k": 24, "w": 12, "note_chars": 40}
    assert {k: policy[k] for k in ("nonweb", "web_ports", "categories", "countries")} == {
        k: rules.policy_example()[k] for k in ("nonweb", "web_ports", "categories", "countries")}
    assert egress.policy()["version"] == policy["version"]  # nothing changed: the same version
    egress.save_settings({"deny": ["evil.example"], "risky_tlds": ["zip"]})
    changed = egress.policy()
    assert changed["version"] != policy["version"] and changed["deny"] == ["evil.example"]
    assert changed["risky_tlds"] == ["zip"]
    assert rules.decide(changed, rules.Conn("http", "a.evil.example", None, 443)).rule == "deny_list"


def test_save_settings_validates(engine):
    egress = engine.egress
    for bad in ({"allow": ["https://example.com"]}, {"deny": "example.com"}, {"countries": ["RUS"]},
                {"risky_tlds": ["foo.bar"]}, {"leak_chars": 5}, {"leak_action": "maybe"}, {"nonweb": "drop"},
                {"web_ports": [0]}, {"match_hours": 0}, {"categories": {"exfil_upload": "yes"}},
                {"categories": {"nope": True}}, {"surprise": 1}, {"note_chars": 300},
                {"when_doorman_down": "pray"}, {"exfil_hosts": ["paste bin"]}, {"unscanned": "sometimes"}):
        with pytest.raises(Denied) as exc:
            egress.save_settings(bad)
        assert exc.value.code == "invalid", bad
    out = egress.save_settings({"countries": ["ru", "CN"], "risky_tlds": [".zip", "Mov"], "allow": [" Example.org "],
                                "categories": {"countries": False}, "leak_chars": 500, "enabled": True})
    assert out["countries"] == ["RU", "CN"] and out["risky_tlds"] == ["zip", "mov"] and out["allow"] == ["example.org"]
    assert out["categories"]["countries"] is False and out["categories"]["exfil_upload"] is True
    assert out["leak_chars"] == 500 and out["enabled"] is False  # `enabled` follows the token, not the form
    entry = engine.journal.list(limit=1)[0]
    assert entry["tool"] == "egress.settings" and entry["kind"] == "config"
    assert "allow" in entry["summary"] and "countries" in entry["summary"]
    assert egress.save_settings({"risky_tlds": None})["risky_tlds"] is None  # back to the built-in list
    before = len(engine.journal.list(limit=100))
    egress.save_settings({"leak_chars": 500})  # nothing changed: nothing journaled
    assert len(engine.journal.list(limit=100)) == before


# ---------------------------------------------------------------- access requests


def test_request_flow_once_task_always_deny(engine):
    egress = enabled(engine).egress
    agent = Agent(engine)

    def ask(target, session=None):
        return egress.request_access(session or agent.session, agent.key,
                                     {"target": target, "reason": "the timetable is there"})

    once = ask("timetable.example")
    assert once["status"] == "open" and once["target"] == "timetable.example"
    note = engine.db.one("SELECT * FROM notifications ORDER BY id DESC LIMIT 1")
    assert note["title"] == "test-solo asks for network access"
    assert note["url"].endswith(f"/app/#/inbox/network/{once['id']}")
    done = egress.decide(once["id"], "once")
    assert done["status"] == "granted" and done["scope"] == "once"
    [exemption] = egress.policy()["exemptions"]
    assert exemption["target"] == "timetable.example"
    assert abs(exemption["expires"] - clock.now().timestamp() - 3600) < 5
    [event] = own_events(engine, agent, "egress_decided")
    assert event["request_id"] == once["id"] and event["status"] == "granted" and event["scope"] == "once"
    assert event["target"] == "timetable.example" and event["expires"]
    assert engine.journal.list(limit=1)[0]["tool"] == "egress.request.once"
    with pytest.raises(Denied):
        egress.decide(once["id"], "deny")  # decided already

    outside = ask("files.example")
    with pytest.raises(Denied) as exc:
        egress.decide(outside["id"], "task")  # it wasn't asked for a task
    assert exc.value.code == "invalid"
    always = egress.decide(outside["id"], "always")
    assert always["scope"] == "always" and "files.example" in egress.settings()["allow"]
    assert own_events(engine, agent, "egress_decided")[-1]["scope"] == "always"
    assert engine.journal.list(limit=1)[0]["tool"] == "egress.request.always"

    engine.tasks.create("Fetch the timetable")
    _, session = engine.tasks.claim(agent.key)
    in_task = ask("api.timetable.example", session)
    assert in_task["task_id"] == session["task_id"]
    assert egress.decide(in_task["id"], "task")["scope"] == "task"
    assert any(e["target"] == "api.timetable.example" for e in egress.policy()["exemptions"])

    no = ask("tracker.example", session)
    assert egress.decide(no["id"], "deny")["status"] == "denied"
    last = own_events(engine, agent, "egress_decided")[-1]
    assert last["status"] == "denied" and last["scope"] is None
    with pytest.raises(Denied):
        egress.decide(no["id"], "maybe")

    for bad in ({"target": "http://x.example/a", "reason": "why not"}, {"target": "x.example", "reason": "no"},
                {"target": "x.example"}, {"target": "x.example", "reason": "fine reason", "more": 1}):
        with pytest.raises(Denied) as exc:
            egress.request_access(session, agent.key, bad)
        assert exc.value.code == "invalid"
    for n in range(5):
        ask(f"site{n}.example", session)
    with pytest.raises(Denied) as exc:
        ask("one-more.example", session)
    assert exc.value.code == "too_many"
    reader = Agent(engine, "reader")
    with pytest.raises(Denied) as exc:
        egress.request_access(reader.session, reader.key, {"target": "x.example", "reason": "please let me"})
    assert exc.value.code == "role"
    assert [r["target"] for r in egress.my_requests(agent.session, agent.key)][:1] == ["site4.example"]
    with pytest.raises(Denied):
        egress.get_request(reader.session, reader.key, once["id"])  # someone else's


def test_task_exemption_ends_with_task(engine):
    """"For this task" ends when the task does: reported, closed by the owner, or its lease ran out."""
    egress = enabled(engine).egress
    agent = Agent(engine)

    def granted_in_task():
        task_id = engine.tasks.create("Look something up")
        _, session = engine.tasks.claim(agent.key, task_id)
        asked = egress.request_access(session, agent.key, {"target": "lookup.example", "reason": "for the task"})
        egress.decide(asked["id"], "task")
        assert [e["target"] for e in egress.policy()["exemptions"]] == ["lookup.example"]
        return task_id, session

    task_id, session = granted_in_task()
    engine.tasks.report(session, task_id, "done", "found it")
    assert egress.policy()["exemptions"] == []  # at once, not only at the next sweep
    egress.sweep(force=True)
    assert engine.db.all("SELECT * FROM egress_exemptions") == []

    task_id, _ = granted_in_task()
    engine.tasks.close(task_id)
    assert egress.policy()["exemptions"] == []

    task_id, _ = granted_in_task()
    clock.advance(31 * 60)
    assert engine.tasks.expire_leases() == [task_id]
    assert egress.policy()["exemptions"] == []
    egress.sweep(force=True)
    assert engine.db.all("SELECT * FROM egress_exemptions") == []


def test_once_expires_after_hour(engine):
    egress = enabled(engine).egress
    agent = Agent(engine)
    egress.client_seen("172.29.0.130", agent.key["id"])  # the exemption is for the asking agent's address
    asked = egress.request_access(agent.session, agent.key, {"target": "once.example", "reason": "just once"})
    egress.decide(asked["id"], "once")
    conn = rules.Conn("http", "once.example", None, 443, method="POST", client="172.29.0.130")
    other = rules.Conn("http", "once.example", None, 443, method="POST", client="172.29.0.131")
    assert rules.decide(egress.policy(), rules.Conn(**{**other.__dict__, "now": clock.now().timestamp()})).rule == "default"
    clock.advance(59 * 60)
    policy = egress.policy()
    assert rules.decide(policy, rules.Conn(**{**conn.__dict__, "now": clock.now().timestamp()})).rule == "exemption"
    assert [e["target"] for e in egress.exemptions()] == ["once.example"]
    clock.advance(2 * 60)
    policy = egress.policy()
    assert policy["exemptions"] == [] and egress.exemptions() == []
    assert rules.decide(policy, rules.Conn(**{**conn.__dict__, "now": clock.now().timestamp()})).rule == "default"
    egress.sweep(force=True)
    assert engine.db.all("SELECT * FROM egress_exemptions") == []


def test_revoke_exemption(engine):
    egress = enabled(engine).egress
    agent = Agent(engine)
    asked = egress.request_access(agent.session, agent.key, {"target": "once.example", "reason": "just once"})
    egress.decide(asked["id"], "once")
    [exemption] = egress.exemptions()
    assert exemption["agent"] == "test-solo" and exemption["scope"] == "once"
    egress.revoke_exemption(exemption["id"])
    assert egress.policy()["exemptions"] == [] and engine.journal.list(limit=1)[0]["tool"] == "egress.exemption.revoke"
    with pytest.raises(Denied):
        egress.revoke_exemption(exemption["id"])


def test_requests_expire(engine):
    egress = enabled(engine).egress
    agent = Agent(engine)
    asked = egress.request_access(agent.session, agent.key, {"target": "late.example", "reason": "nobody answers"})
    clock.advance(25 * 3600)
    egress.sweep(force=True)
    assert egress.get_request(agent.session, agent.key, asked["id"])["status"] == "expired"
    [event] = own_events(engine, agent, "egress_decided")
    assert event["status"] == "expired" and event["request_id"] == asked["id"]
    assert egress.open_requests() == []
    with pytest.raises(Denied):
        egress.decide(asked["id"], "once")


def test_open_requests_for_the_owner(engine):
    egress = enabled(engine).egress
    agent = Agent(engine)
    egress.client_seen(IP_A, agent.key["id"])
    read_mail(engine, agent)
    read_mail(engine, agent, words(3, 20), "Second")
    task_id = engine.tasks.create("Upload the slides")
    _, session = engine.tasks.claim(agent.key, task_id)
    egress.ingest([{"ts": clock.now().timestamp(), "client_ip": IP_A, "kind": "http", "host": "upload.slides.example",
                    "port": 443, "method": "POST", "decision": "deny", "rule": "risky_tlds", "detail": "no"}])
    asked = egress.request_access(session, agent.key, {"target": "slides.example", "reason": "the upload page"})
    [item] = egress.open_requests()
    assert item["id"] == asked["id"] and item["target"] == "slides.example" and item["reason"] == "the upload page"
    assert item["agent"] == "test-solo" and item["asked"] and item["expires"]
    assert item["task"] == {"id": task_id, "text": "Upload the slides", "trusted": 1, "origin": "owner"}
    assert item["blocked"]["rule"] == "risky_tlds" and item["blocked"]["detail"] == "no" and item["blocked"]["ts"]
    assert item["reads"] == "read 2 mail items in the last 24 h"


# ---------------------------------------------------------------- the proxy's log, tool calls


def record(**fields):
    return {"ts": clock.now().timestamp(), "client_ip": IP_A, "kind": "http", "host": "example.org",
            "ip": "93.184.216.34", "port": 443, "method": "GET", "path": "/", "status": 200, "bytes_up": 100, "bytes_down": 2000,
            "decision": "allow", "rule": "default", "detail": "", "leak": None, "process": None,
            "duration_ms": 30, "scanned": True, **fields}


def test_ingest_large_upload_first_contact(engine):
    egress = enabled(engine).egress
    agent = Agent(engine)
    egress.client_seen(IP_A, agent.key["id"])
    task_id = engine.tasks.create("Send the dataset")
    engine.tasks.claim(agent.key, task_id)
    egress.ingest([record(host="old.example")])
    clock.advance(60)
    big = 6 * 1024 * 1024
    curl = {"pid": 7, "exe": "/usr/bin/curl", "cmdline": "curl -T data", "chain": []}
    assert egress.ingest([record(host="old.example", method="PUT", bytes_up=big),
                          record(host="new.example", method="PUT", bytes_up=big, path="/x" * 400, surprise="drop me",
                                 leak={"chars": 120, "sources": ["mail.read: x"]}, process=curl)]) == 2
    [item] = attention(engine, "egress_upload")
    assert "new.example" in item["title"] + item["detail"]
    rows = engine.db.all("SELECT * FROM egress_log ORDER BY id")
    assert all(r["key_id"] == agent.key["id"] and r["task_id"] == task_id for r in rows)
    assert len(rows[-1]["path"]) == 300 and "surprise" not in rows[-1]
    view = egress.log_view(task_id=task_id)
    assert view[0]["host"] == "new.example" and view[0]["leak"]["chars"] == 120 and view[0]["process"]["pid"] == 7
    assert view[0]["scanned"] is True
    assert [r["host"] for r in egress.log_view(only="leaks")] == ["new.example"]
    egress.ingest([record(host="new.example", method="PUT", bytes_up=big)])
    assert len(attention(engine, "egress_upload")) == 1  # it knows that host now
    with pytest.raises(Denied):
        egress.ingest([record()] * 501)


def test_correlate_by_chain_then_window_and_outside_call(engine):
    egress = enabled(engine).egress
    agent = Agent(engine)
    egress.client_seen(IP_A, agent.key["id"])
    t0 = clock.now().timestamp()
    egress.activity(agent.session, agent.key, {"phase": "start", "call_id": "c1", "tool": "Bash",
                                               "summary": "curl https://example.org/data"})
    clock.advance(1)
    egress.activity(agent.session, agent.key, {"phase": "start", "call_id": "c2", "tool": "Bash",
                                               "summary": "python3 fetch.py"})
    clock.advance(2)
    egress.activity(agent.session, agent.key, {"phase": "end", "call_id": "c2", "tool": "Bash", "status": "ok"})
    clock.advance(2)
    egress.activity(agent.session, agent.key, {"phase": "end", "call_id": "c1", "tool": "Bash"})
    chain = {"pid": 40, "exe": "/usr/bin/curl", "cmdline": "curl https://example.org/data",
             "chain": [{"pid": 30, "cmdline": "bash -c curl https://example.org/data"},
                       {"pid": 1, "cmdline": "hermes"}]}
    egress.ingest([record(ts=t0 + 2, process=chain), record(ts=t0 + 2, host="b.example"),
                   record(ts=t0 + 60, host="c.example"), record(ts=t0 + 2, client_ip="10.1.1.1", host="d.example")])
    rows = {r["host"]: r for r in egress.log_view()}
    assert rows["example.org"]["call"] == {"id": "c1", "tool": "Bash", "summary": "curl https://example.org/data"}
    assert rows["b.example"]["call"]["id"] == "c2"  # inside both windows: the latest started
    assert rows["c.example"].get("call") is None and rows["c.example"]["outside_call"] is True
    assert "call" not in rows["d.example"] and "outside_call" not in rows["d.example"]
    # a key that never reported a tool call: no "outside" mark either
    other = Agent(engine)
    egress.client_seen(IP_B, other.key["id"])
    egress.ingest([record(client_ip=IP_B, host="e.example")])
    assert "outside_call" not in egress.log_view(key_id=other.key["id"])[0]
    # an end without a start is kept as a closed call
    egress.activity(agent.session, agent.key, {"phase": "end", "call_id": "c9", "tool": "WebFetch"})
    assert engine.db.one("SELECT * FROM agent_activity WHERE call_id='c9'")["ended"]
    with pytest.raises(Denied):
        egress.activity(agent.session, agent.key, {"phase": "middle", "call_id": "c1", "tool": "Bash"})


def test_blocked_recent(engine):
    egress = enabled(engine).egress
    agent = Agent(engine)
    egress.client_seen(IP_A, agent.key["id"])
    egress.ingest([record(host="ok.example"),
                   record(host="paste.example", decision="deny", rule="exfil_upload", detail="uploads are blocked")])
    [row] = egress.blocked_recent(agent.key)
    assert row == {"ts": row["ts"], "host": "paste.example", "port": 443, "rule": "exfil_upload",
                   "detail": "uploads are blocked"}


# ---------------------------------------------------------------- housekeeping


def test_sweep_prunes(engine):
    egress = enabled(engine).egress
    agent = Agent(engine)
    egress.client_seen(IP_A, agent.key["id"])
    read_mail(engine, agent)
    egress.ingest([record()])
    egress.activity(agent.session, agent.key, {"phase": "start", "call_id": "c1", "tool": "Bash", "summary": "ls"})
    egress.proxy_status({"version": "1", "geoip": {"rows": 3, "date": "2026-11"}})
    assert egress.status_view()["up"] is True
    clock.advance(6 * 60)
    egress.sweep(force=True)
    [down] = attention(engine, "egress_proxy_down")
    egress.proxy_status({"version": "1"})
    egress.sweep(force=True)
    assert attention(engine, "egress_proxy_down") == []
    egress.policy(seen=True)  # the proxy's policy poll counts too
    clock.advance(25 * 3600)
    egress.policy(seen=True)
    egress.sweep(force=True)
    assert engine.db.one("SELECT COUNT(*) AS n FROM egress_prints")["n"] == 0
    assert engine.db.one("SELECT COUNT(*) AS n FROM egress_sources")["n"] == 0
    assert engine.db.one("SELECT COUNT(*) AS n FROM egress_log")["n"] == 1  # kept for log_days
    clock.advance(31 * 86400)
    egress.policy(seen=True)
    egress.sweep(force=True)
    assert engine.db.one("SELECT COUNT(*) AS n FROM egress_log")["n"] == 0
    assert engine.db.one("SELECT COUNT(*) AS n FROM agent_activity")["n"] == 0


# ---------------------------------------------------------------- review fixes: bounds, attribution, scores


IP_C = "172.32.0.5"


def stall(engine, monkeypatch):
    """Large reads stay in the queue: no worker thread takes them."""
    monkeypatch.setattr(engine.egress, "_start_worker", lambda: None)


def sources(engine):
    return engine.db.all("SELECT * FROM egress_sources ORDER BY id")


def test_rereading_the_same_text_adds_nothing_but_keeps_it_fresh(engine):
    enabled(engine)
    agent = Agent(engine)
    engine.egress.client_seen(IP_A, agent.key["id"])
    mid = engine.registry.instance("mail").add("inbox", "anna@example.com", "Contract draft", BODY)
    for _ in range(3):
        agent.read("mail.read", {"id": mid})
        assert engine.egress.flush(5)
    assert len(sources(engine)) == 1
    prints = engine.db.one("SELECT COUNT(*) AS n FROM egress_prints")["n"]
    clock.advance(20 * 3600)
    engine.egress.client_seen(IP_A, agent.key["id"])
    agent.read("mail.read", {"id": mid})  # read again: remembered from now on
    assert engine.egress.flush(5)
    assert len(sources(engine)) == 1 and engine.db.one("SELECT COUNT(*) AS n FROM egress_prints")["n"] == prints
    clock.advance(10 * 3600)
    engine.egress.client_seen(IP_A, agent.key["id"])
    engine.egress.sweep(force=True)
    assert check(engine, IP_A, BODY[50:350])["action"] == "deny"
    other = Agent(engine)  # another key reading the same text: a source of its own
    other.read("mail.read", {"id": mid})
    assert engine.egress.flush(5) and len(sources(engine)) == 2


def test_small_reads_are_fingerprinted_on_the_spot(engine, monkeypatch):
    enabled(engine)
    stall(engine, monkeypatch)
    agent = Agent(engine)
    engine.egress.client_seen(IP_A, agent.key["id"])
    mid = engine.registry.instance("mail").add("inbox", "anna@example.com", "Contract draft", BODY)
    agent.read("mail.read", {"id": mid})
    assert len(sources(engine)) == 1  # no worker, no flush: it's there
    assert check(engine, IP_A, BODY[50:350])["action"] == "deny"


def test_check_answers_unknown_when_the_queue_is_behind(engine, monkeypatch):
    enabled(engine)
    stall(engine, monkeypatch)
    monkeypatch.setattr(service, "INLINE_CHARS", 10)
    monkeypatch.setattr(service, "CHECK_WAIT", 0.05)
    agent = Agent(engine)
    engine.egress.client_seen(IP_A, agent.key["id"])
    mid = engine.registry.instance("mail").add("inbox", "anna@example.com", "Contract draft", BODY)
    agent.read("mail.read", {"id": mid})
    out = check(engine, IP_A, BODY[50:350])
    assert out["action"] == "unknown" and out["reason"]
    assert not engine.auth.paused(agent.key["id"])
    # a honeytoken needs no fingerprints: still blocked at once
    assert check(engine, IP_A, honeytokens=["canary-7f3a9c2e"])["action"] == "deny"


def test_the_queue_is_bounded_and_a_dropped_read_makes_its_key_unknown(engine, monkeypatch):
    enabled(engine)
    stall(engine, monkeypatch)
    monkeypatch.setattr(service, "INLINE_CHARS", 10)
    monkeypatch.setattr(service, "QUEUE_CHARS", 1000)
    first, second = Agent(engine), Agent(engine)
    engine.egress.client_seen(IP_A, first.key["id"])
    engine.egress.client_seen(IP_B, second.key["id"])
    mail = engine.registry.instance("mail")
    texts = [words(10 + n, 80)[:400] for n in range(4)]
    for n, text in enumerate(texts):  # 4 × 400 characters: the third doesn't fit any more
        first.read("mail.read", {"id": mail.add("inbox", "anna@example.com", f"Mail {n}", text)})
    assert engine.egress._queued_chars <= 1000
    monkeypatch.undo()
    engine.egress._start_worker()
    assert engine.egress.flush(5)
    assert len(sources(engine)) == 2
    assert check(engine, IP_A, texts[0][50:350])["action"] == "unknown"  # not all it read was fingerprinted
    read_mail(engine, second)
    assert check(engine, IP_B, BODY[50:350])["action"] == "deny"  # the other key is checked as before
    [item] = attention(engine, "egress_blind")
    assert "test-solo" in item["title"] + item["detail"]
    clock.advance(25 * 3600)
    engine.egress.client_seen(IP_A, first.key["id"])
    engine.egress.sweep(force=True)
    assert check(engine, IP_A, texts[0][50:350])["action"] == "allow"
    assert attention(engine, "egress_blind") == []


def test_a_key_over_its_hourly_budget_isnt_fingerprinted_and_checks_answer_unknown(engine, monkeypatch):
    enabled(engine)
    monkeypatch.setattr(service, "BUDGET_CHARS", 600)
    first, second = Agent(engine), Agent(engine)
    engine.egress.client_seen(IP_A, first.key["id"])
    engine.egress.client_seen(IP_B, second.key["id"])
    read_mail(engine, first)
    other = words(5, 80)[:400]
    read_mail(engine, first, other, "Second")
    assert [s["label"] for s in sources(engine)] == ["mail.read: Contract draft"]
    assert check(engine, IP_A, other[50:350])["action"] == "unknown"
    mine = words(6, 80)[:400]
    read_mail(engine, second, mine, "Its own")
    assert check(engine, IP_B, mine[50:350])["action"] == "deny"
    clock.advance(25 * 3600)
    engine.egress.client_seen(IP_A, first.key["id"])
    engine.egress.sweep(force=True)
    read_mail(engine, first, other, "Second")  # a new hour, a new budget
    assert check(engine, IP_A, other[50:350])["action"] == "deny"


def test_sweep_deletes_old_prints_in_batches(engine, monkeypatch):
    enabled(engine)
    monkeypatch.setattr(service, "DELETE_BATCH", 7)
    agent = Agent(engine)
    read_mail(engine, agent)
    read_mail(engine, agent, words(4, 80)[:400], "Other")
    assert engine.db.one("SELECT COUNT(*) AS n FROM egress_prints")["n"] > 7
    clock.advance(25 * 3600)
    engine.egress.sweep(force=True)
    assert engine.db.one("SELECT COUNT(*) AS n FROM egress_prints")["n"] == 0
    assert sources(engine) == []


def test_leak_score_is_the_best_single_source(engine):
    """Pieces of several reads, none a leak alone, don't add up to one."""
    enabled(engine)
    agent = Agent(engine)
    engine.egress.client_seen(IP_A, agent.key["id"])
    parts = [words(20 + n, 40)[:170] for n in range(3)]
    for n, part in enumerate(parts):
        read_mail(engine, agent, part, f"Part {n}")
    out = check(engine, IP_A, "\n".join(parts))
    assert out["action"] == "allow" and 40 <= out["chars"] < 200
    assert not engine.auth.paused(agent.key["id"])


def test_the_proxy_only_hears_the_sources_of_the_keys_at_that_address(engine):
    enabled(engine)
    reader, leaker = Agent(engine), Agent(engine)
    engine.egress.client_seen(IP_A, reader.key["id"])
    engine.egress.client_seen(IP_B, leaker.key["id"])
    read_mail(engine, reader)
    noted = check(engine, IP_B, BODY[100:220])
    assert noted["action"] == "allow" and noted["chars"] >= 40 and noted["sources"] == []
    out = check(engine, IP_B, BODY[50:350])
    assert out["action"] == "deny" and out["sources"] == []
    assert "Contract draft" not in out["reason"]
    [item] = attention(engine, "egress_leak")
    assert "Contract draft" in item["detail"]  # the owner hears all of it


def test_one_address_two_keys_a_leak_pauses_both(engine):
    enabled(engine)
    first, second, third = Agent(engine), Agent(engine), Agent(engine)
    egress = engine.egress
    egress.client_seen(IP_A, first.key["id"])
    clock.advance(1)
    egress.client_seen(IP_A, second.key["id"])
    egress.client_seen(IP_B, third.key["id"])
    assert egress.keys_for_ip(IP_A) == [second.key["id"], first.key["id"]]
    assert egress.key_for_ip(IP_A) == second.key["id"]
    read_mail(engine, third)
    assert check(engine, IP_A, BODY[50:350])["action"] == "deny"
    assert engine.auth.paused(first.key["id"]) and engine.auth.paused(second.key["id"])
    assert not engine.auth.paused(third.key["id"])
    egress.ingest([record(client_ip=IP_A, host="x.example")])
    assert engine.db.one("SELECT key_id FROM egress_log")["key_id"] == second.key["id"]  # the latest
    # a key last seen there more than a day ago no longer counts, and the sweep forgets it
    clock.advance(25 * 3600)
    egress.client_seen(IP_A, first.key["id"])
    assert egress.keys_for_ip(IP_A) == [first.key["id"]]
    egress.sweep(force=True)
    assert {r["key_id"] for r in engine.db.all("SELECT key_id FROM agent_addresses WHERE ip=?", (IP_A,))} == {
        first.key["id"]}


def test_migration_v4_lets_an_address_have_several_keys(tmp_path):
    import sqlite3
    from doorman.db import Database
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.executescript("CREATE TABLE agent_addresses (ip TEXT PRIMARY KEY, key_id INTEGER, seen TEXT);"
                      "CREATE TABLE egress_sources (id INTEGER PRIMARY KEY, key_id INTEGER, task_id INTEGER, "
                      "ts TEXT, name TEXT, label TEXT);"
                      "INSERT INTO agent_addresses VALUES('10.0.0.1', 1, '2026-11-07T10:00:00+00:00');"
                      "PRAGMA user_version=3;")
    old.close()
    db = Database(path)
    db.exec("INSERT INTO agent_addresses(ip, key_id, seen) VALUES('10.0.0.1', 1, 'x')")
    db.exec("INSERT INTO agent_addresses(ip, key_id, seen) VALUES('10.0.0.1', 2, 'y')")
    db.exec("INSERT INTO egress_sources(key_id, digest) VALUES(1, 'abc')")
    assert len(db.all("SELECT * FROM agent_addresses")) == 2


def test_exceptions_carry_the_clients_of_the_asking_key(engine):
    egress = enabled(engine).egress
    agent, quiet = Agent(engine), Agent(engine)
    egress.client_seen(IP_A, agent.key["id"])
    egress.client_seen(IP_C, agent.key["id"])
    asked = egress.request_access(agent.session, agent.key, {"target": "a.example", "reason": "the data is there"})
    egress.decide(asked["id"], "once")
    unseen = egress.request_access(quiet.session, quiet.key, {"target": "b.example", "reason": "the data is there"})
    egress.decide(unseen["id"], "once")
    by_target = {e["target"]: e for e in egress.policy()["exemptions"]}
    assert by_target["a.example"]["clients"] == [IP_A, IP_C]
    assert by_target["b.example"]["clients"] == []  # no address known: nobody


def test_activity_is_rate_limited_and_open_calls_are_capped(engine):
    egress = enabled(engine).egress
    agent = Agent(engine)
    for n in range(201):
        egress.activity(agent.session, agent.key, {"phase": "start", "call_id": f"c{n}", "tool": "Bash"})
    assert engine.db.one("SELECT COUNT(*) AS n FROM agent_activity WHERE ended IS NULL")["n"] == 200
    oldest = engine.db.one("SELECT * FROM agent_activity WHERE call_id='c0'")
    assert oldest["status"] == "abandoned" and oldest["ended"]
    for n in range(399):
        egress.activity(agent.session, agent.key, {"phase": "end", "call_id": f"x{n}", "tool": "Bash"})
    with pytest.raises(Denied) as exc:
        egress.activity(agent.session, agent.key, {"phase": "start", "call_id": "late", "tool": "Bash"})
    assert exc.value.code == "too_many"
    other = Agent(engine)  # per key
    egress.activity(other.session, other.key, {"phase": "start", "call_id": "o1", "tool": "Bash"})
    clock.advance(601)
    egress.activity(agent.session, agent.key, {"phase": "start", "call_id": "later", "tool": "Bash"})


def test_calls_open_for_over_an_hour_are_closed(engine):
    egress = enabled(engine).egress
    agent = Agent(engine)
    egress.client_seen(IP_A, agent.key["id"])
    egress.activity(agent.session, agent.key, {"phase": "start", "call_id": "forever", "tool": "Bash",
                                               "summary": "sleep infinity"})
    clock.advance(2 * 3600)
    egress.client_seen(IP_A, agent.key["id"])
    egress.ingest([record(host="late.example")])
    [row] = egress.log_view()
    assert "call" not in row and row["outside_call"] is True  # an open call covers an hour at most
    egress.sweep(force=True)
    call = engine.db.one("SELECT * FROM agent_activity WHERE call_id='forever'")
    assert call["status"] == "abandoned"
    assert (clock.parse(call["ended"]) - clock.parse(call["started"])).total_seconds() == 3600


def test_unscanned_setting(engine):
    egress = enabled(engine).egress
    assert egress.settings()["unscanned"] == "allow" and egress.policy()["unscanned"] == "allow"
    with pytest.raises(Denied):
        egress.save_settings({"unscanned": "maybe"})
    assert egress.save_settings({"unscanned": "block"})["unscanned"] == "block"
    assert egress.policy()["unscanned"] == "block"


def test_model_keys_and_a_second_key_for_a_provider(engine):
    egress = enabled(engine).egress
    agent = Agent(engine)
    egress.client_seen(IP_A, agent.key["id"])
    mine, theirs = "a" * 16, "b" * 16
    egress.ingest([record(host="api.anthropic.com", auth_hash=mine), record(host="api.anthropic.com", auth_hash=mine),
                   record(host="api.openai.com", auth_hash="c" * 16), record(host="example.org", auth_hash=None),
                   record(host="api.anthropic.com", auth_hash="not hex")])
    keys = {(k["host"], k["auth_hash"]): k for k in egress.model_keys()}
    assert set(keys) == {("api.anthropic.com", mine), ("api.openai.com", "c" * 16)}
    assert keys[("api.anthropic.com", mine)]["count"] == 2 and keys[("api.anthropic.com", mine)]["first_seen"]
    assert attention(engine, "egress_model_key") == []
    clock.advance(60)
    egress.ingest([record(host="api.anthropic.com", auth_hash=theirs)])
    [item] = attention(engine, "egress_model_key")
    assert "api.anthropic.com" in item["title"] + item["detail"]
    note = engine.db.one("SELECT * FROM notifications ORDER BY id DESC LIMIT 1")
    assert note["title"] == item["title"]
    pushes = engine.db.one("SELECT COUNT(*) AS n FROM notifications")["n"]
    egress.ingest([record(host="api.anthropic.com", auth_hash="d" * 16)])
    assert engine.db.one("SELECT COUNT(*) AS n FROM notifications")["n"] == pushes  # listed once
    assert len(egress.model_keys()) == 4


def test_default_no_scan_has_the_model_apis():
    from doorman.config import DEFAULTS
    hosts = DEFAULTS["egress"]["no_scan"]
    for host in ("api.mistral.ai", "api.groq.com", "api.together.xyz", "api.fireworks.ai", "api.x.ai",
                 "api.cohere.com", "api.anthropic.com"):
        assert host in hosts
    assert not any("amazonaws" in h for h in hosts)


def test_dropped_log_records_tell_the_owner(engine):
    egress = enabled(engine).egress
    egress.proxy_status({"version": "1", "dropped": 0})
    assert attention(engine, "egress_log_dropped") == []
    egress.proxy_status({"version": "1", "dropped": 3})
    [item] = attention(engine, "egress_log_dropped")
    assert "3" in item["detail"]
    clock.advance(30 * 60)
    egress.proxy_status({"version": "1", "dropped": 3})
    egress.sweep(force=True)
    assert attention(engine, "egress_log_dropped")  # not an hour without new drops yet
    clock.advance(31 * 60)
    egress.proxy_status({"version": "1", "dropped": 3})
    egress.sweep(force=True)
    assert attention(engine, "egress_log_dropped") == []
    egress.proxy_status({"version": "1", "dropped": 1})  # the proxy restarted and dropped again
    assert attention(engine, "egress_log_dropped")


def test_trigger_task_text_is_fingerprinted(engine):
    enabled(engine)
    agent = Agent(engine)
    engine.egress.client_seen(IP_A, agent.key["id"])
    stranger = words(30, 80)[:400]
    task_id = engine.tasks.create(f"Answer this mail: {stranger}", origin="trigger:new-mail", trusted=False)
    engine.tasks.create(f"My own words: {BODY}")  # the owner's: theirs to send
    assert engine.egress.flush(5)
    [source] = sources(engine)
    assert source["key_id"] is None and source["task_id"] == task_id
    assert check(engine, IP_A, BODY[50:350])["chars"] == 0
    assert check(engine, IP_A, stranger)["action"] == "deny"
    assert engine.auth.paused(agent.key["id"])


def test_tool_results_are_fingerprinted_for_the_calling_key(engine, monkeypatch):
    enabled(engine)
    agent = Agent(engine)
    engine.egress.client_seen(IP_A, agent.key["id"])
    _, _, tool = engine.registry.find_tool("notes.create")
    fetched = words(31, 80)[:400]
    monkeypatch.setattr(tool, "execute", lambda args, before: ExecResult(
        result={"id": "n1", "echo": args["body"], "page": fetched}, after={"title": "t"}, object_ref="n1"))
    own = words(32, 80)[:400]
    out = agent.call("notes.create", {"title": "From the web", "body": own})
    assert out["status"] == "done"
    assert engine.egress.flush(5)
    [source] = sources(engine)
    assert source["key_id"] == agent.key["id"] and source["name"] == "notes.create"
    assert check(engine, IP_A, own[50:350])["chars"] == 0  # its own words, echoed back, aren't something it read
    assert check(engine, IP_A, fetched[50:350])["action"] == "deny"
