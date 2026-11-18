"""The WhatsApp plugin against the real sidecar: sidecars/whatsapp/shim.py running a real wacli binary.

No WhatsApp account is involved: the test writes chats and messages into wacli's store the way
`wacli sync` would (wacli's own SQL triggers fill its change log and search index), then reads them
through the shim and the plugin. Runs only with DOORMAN_TEST_WACLI=/path/to/wacli (build it from
github.com/steipete/wacli, see sidecars/whatsapp/README.md).
"""

import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from doorman import clock
from conftest import Agent, make_engine

WACLI = os.environ.get("DOORMAN_TEST_WACLI")
pytestmark = pytest.mark.skipif(not WACLI, reason="set DOORMAN_TEST_WACLI to a wacli binary")
SHIM = Path(__file__).resolve().parents[1] / "sidecars" / "whatsapp" / "shim.py"
TOKEN = "0123456789abcdef0123"
FAMILY, MUM = "120363000@g.us", "4915100000000@s.whatsapp.net"


@pytest.fixture
def sidecar(tmp_path):
    env = {**os.environ, "WACLI": WACLI, "WACLI_STORE_DIR": str(tmp_path / "store"),
           "XDG_STATE_HOME": str(tmp_path / "state"), "XDG_CONFIG_HOME": str(tmp_path / "config"),
           "XDG_CACHE_HOME": str(tmp_path / "cache"), "SIDECAR_TOKEN": TOKEN}
    # A writable open migrates the new store; the shim itself only opens it read-only.
    subprocess.run([WACLI, "--json", "messages", "changes", "--checkpoint"], env=env, check=True,
                   capture_output=True)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env["LISTEN"] = f"127.0.0.1:{port}"
    process = subprocess.Popen([sys.executable, "-I", str(SHIM)], env=env, stderr=subprocess.PIPE, text=True)
    url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            httpx.get(url + "/status", headers={"Authorization": f"Bearer {TOKEN}"}, timeout=1)
            break
        except httpx.HTTPError:
            time.sleep(0.1)
    db = sqlite3.connect(tmp_path / "store" / "wacli.db")

    def add(chat, name, msg_id, text, from_me=False, ago=60):
        ts = int(clock.now().timestamp()) - ago
        db.execute("INSERT INTO chats(jid, kind, name, last_message_ts) VALUES(?,?,?,?) ON CONFLICT(jid) "
                   "DO UPDATE SET last_message_ts=excluded.last_message_ts",
                   (chat, "group" if chat.endswith("@g.us") else "dm", name, ts))
        db.execute("INSERT INTO messages(chat_jid, chat_name, msg_id, sender_jid, sender_name, ts, from_me, text, "
                   "display_text) VALUES(?,?,?,?,?,?,?,?,?)",
                   (chat, name, msg_id, "me" if from_me else MUM, "" if from_me else "Mum", ts, int(from_me),
                    text, text))
        db.commit()

    yield url, add
    process.terminate()
    process.wait(5)
    db.close()


def test_reads_events_and_send_through_wacli(tmp_path, sidecar):
    url, add = sidecar
    engine = make_engine(tmp_path / "doorman", plugins={"whatsapp": {"enabled": True, "config": {"sidecar_url": url}}})
    engine.vault.set("whatsapp", "sidecar_token", TOKEN)
    agent = Agent(engine)

    add(FAMILY, "Family", "A", "Wer bringt den Kuchen mit?", ago=3600)
    assert engine.poll_triggers() is not None  # the first poll takes wacli's checkpoint: no events
    assert engine.db.all("SELECT * FROM events") == []

    chats = agent.read("whatsapp.chats")
    assert [(c["id"], c["name"]) for c in chats] == [(FAMILY, "Family")]
    messages = agent.read("whatsapp.messages", {"chat": FAMILY})
    assert [(m["id"], m["text"], m["from_me"]) for m in messages] == [("A", "Wer bringt den Kuchen mit?", False)]
    # doorman search: the first feed reads the history back through the shim, a chat's day at a time
    assert engine.search.pull("whatsapp")["changed"] == 1
    [hit] = engine.search.any_word(agent.session, agent.key, {"query": "Kuchen"})["results"]
    assert (hit["chat_id"], hit["chat"], hit["ref"]) == (FAMILY, "Family", f"whatsapp:{FAMILY}/A")
    add(MUM, "Mum", "M0", "hallo", ago=8 * 3600)  # history, not news: no event for it below
    assert [c["name"] for c in agent.read("whatsapp.chats", {"query": "mu"})] == ["Mum"]  # wacli filters
    assert [c["name"] for c in agent.read("whatsapp.chats", {"query": "+49 151 000"})] == ["Mum"]
    assert [c["name"] for c in agent.read("whatsapp.chats", {"limit": 1})] == ["Family"]  # most recent first
    one = agent.read("whatsapp.message", {"id": f"{FAMILY}/A"})
    assert (one["text"], one["chat"], one["chat_name"], one["context"]) == ("Wer bringt den Kuchen mit?", FAMILY,
                                                                            "Family", [])
    assert engine.meta(agent.session, agent.key, f"whatsapp:{FAMILY}/A")["sender"] == MUM

    add(FAMILY, "Family", "B", "Dinner at 7?")
    add(FAMILY, "Family", "C", "yes", from_me=True)
    add(MUM, "Mum", "D", "call me")
    clock.advance(300)
    engine.poll_triggers()
    rows = engine.db.all("SELECT * FROM events ORDER BY id")
    assert sorted(r["ref"] for r in rows) == [f"whatsapp:{FAMILY}/B", f"whatsapp:{MUM}/D"]
    assert {json.loads(r["data"])["text"] for r in rows} == {"Dinner at 7?", "call me"}
    clock.advance(300)
    engine.poll_triggers()
    assert len(engine.db.all("SELECT * FROM events")) == 2
    # later feeds follow wacli's change log: the days it names are read again, between after and before
    engine.search.pull("whatsapp")
    [day] = engine.search.any_word(agent.session, agent.key, {"query": "Dinner"})["results"]
    assert "Mum: Dinner at 7?" in day["passage"] and "me: yes" in day["passage"]
    assert [h["chat_id"] for h in engine.search.any_word(agent.session, agent.key, {"query": "call"})["results"]] == [MUM]

    # Not linked, so sync isn't running: the shim refuses before wacli is asked, and Doorman knows
    # nothing went out.
    assert engine.registry.instance("whatsapp").check().startswith("WhatsApp isn't linked")
    engine.db.exec("INSERT INTO trust(kind, value, label, created) VALUES('chat',?,'Family','x')", (FAMILY,))
    send = agent.call("whatsapp.send", {"chat": FAMILY, "text": "on my way"})
    engine.approvals.decide(send["approval_id"], approve=True)
    entry = engine.journal.get(send["entry_id"])
    assert entry["status"] == "failed" and "nothing was sent" in entry["error"]
    clock.reset()
