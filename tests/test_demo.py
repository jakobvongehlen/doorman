"""doorman-admin demo: seeds a directory, starts the fakes and Doorman, answers an agent, and stops it all."""

import json
import os

import httpx
import pytest

from doorman import demo
from doorman.demo import fakes
from conftest import free_port

pytestmark = [pytest.mark.integration,
              pytest.mark.skipif(not fakes.dovecot_binary(), reason="dovecot not installed"),
              pytest.mark.skipif(not fakes.radicale_available(), reason="radicale not installed")]


def port_base() -> int:
    """Six free ports in a row (the demo's agent, owner, IMAP, SMTP, CalDAV and fake HTTP ports)."""
    for _ in range(50):
        base = free_port()
        if base + 5 < 65536 and all(fakes.port_free(base + i) for i in range(6)):
            return base
    pytest.skip("no six free ports in a row")


def agent_env(directory) -> dict:
    out = {}
    for line in (directory / "agent.env").read_text().splitlines():
        if line.startswith("export DOORMAN_"):
            key, _, value = line[len("export "):].partition("=")
            out[key] = value
    return out


def test_seeds_serves_an_agent_and_stops(tmp_path):
    directory = tmp_path / "demo"
    demo.start_background(directory, port_base(), timeout=90)
    state = json.loads((directory / "demo.json").read_text())
    run = json.loads((directory / "run.json").read_text())
    try:
        env = agent_env(directory)
        assert env["DOORMAN_URL"] == f"http://127.0.0.1:{state['port_base']}" and env["DOORMAN_TOKEN"].startswith("dmn_")
        assert os.access(directory / "bin" / "doorman", os.X_OK)
        client = httpx.Client(base_url=env["DOORMAN_URL"], headers={"Authorization": f"Bearer {env['DOORMAN_TOKEN']}"},
                              timeout=60)
        mail = client.post("/v1/read/mail.search", json={"params": {"limit": 50}}).json()
        assert len(mail["data"]) >= 14 and mail["spotlight"]["tag"]  # the seeded inbox, as third-party text
        notes = client.post("/v1/read/notes.list", json={"params": {}}).json()
        assert "Assignment 2 plan" in [n["title"] for n in notes["data"]]
        people = client.post("/v1/read/contacts.search", json={"params": {"query": "group 7"}}).json()
        assert people["data"]["contacts"] == []  # the note isn't searched; a name, address or number is
        lena = client.post("/v1/read/contacts.search", json={"params": {"query": "+31 6 00000101"}}).json()
        assert [c["name"] for c in lena["data"]["contacts"]] == ["Lena Bakker"]  # her WhatsApp number
        # the flat's collection is shared with Sam, and Dr. Peters' invitation waits for an answer
        lists = client.post("/v1/read/caldav.lists", json={"params": {}}).json()["data"]
        assert {c["name"]: c["shared"] for c in lists} == {"Tasks": False, "Flat": True}
        week = client.post("/v1/read/caldav.events", json={"params": {"start": "2020-01-01", "end": "2100-01-01"}}).json()
        [invitation] = [e for e in week["data"] if e["uid"] == "demo-invitation-1@uni.example"]
        assert invitation["organizer"] == "m.peters@uni.example" and invitation["response"] == "needs-action"
        # the owner stand-in reaches the owner API; the planted injection was held back by the list read already
        # (the guard scans the text behind a mail row's snippet)
        assert [line.split(":")[0] for line in demo.inbox(directory)] == ["held 1"]
    finally:
        assert demo.stop(directory)
    assert not (directory / "run.json").exists()
    assert not fakes.alive(run["pid"]) and not fakes.alive(run["radicale_pid"])
    assert not os.path.exists(run["dovecot_run"])  # Dovecot's run directory goes with it
    assert demo.stop(directory) is False  # stopping again is harmless


def test_refuses_a_directory_it_did_not_make(tmp_path):
    (tmp_path / "notes.txt").write_text("mine")
    with pytest.raises(demo.DemoError, match="isn't empty"):
        demo.run(tmp_path)
    with pytest.raises(demo.DemoError, match="isn't a demo"):
        demo.inbox(tmp_path)  # the owner stand-in only ever works on a demo's directory
    assert os.listdir(tmp_path) == ["notes.txt"]
