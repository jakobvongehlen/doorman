"""Starts `doorman-admin serve` for real and drives it with the agent CLI from the skill."""

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "doorman" / "agent_skill" / "scripts" / "doorman.py"
ADMIN = [sys.executable, "-m", "doorman.admin"]
pytestmark = pytest.mark.integration


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def server(tmp_path):
    agent_port, owner_port = free_port(), free_port()
    config = tmp_path / "doorman.yaml"
    config.write_text(yaml.safe_dump({
        "data_dir": "data", "public_url": f"http://localhost:{owner_port}",
        "agent_listen": f"127.0.0.1:{agent_port}", "owner_listen": f"127.0.0.1:{owner_port}",
        "worker_interval_seconds": 0.5}))  # a new Doorman: notes and the file archive from the start
    env = {**os.environ, "DOORMAN_CONFIG": str(config)}
    token = subprocess.run([*ADMIN, "key", "create", "claude", "--role", "solo"], env=env, capture_output=True,
                           text=True, check=True).stdout.strip().splitlines()[-1]
    subprocess.run([*ADMIN, "trust", "add", "email", "anna@example.com", "--label", "Anna"], env=env, check=True,
                   capture_output=True)
    proc = subprocess.Popen([*ADMIN, "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", owner_port), timeout=0.2).close()
            socket.create_connection(("127.0.0.1", agent_port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    cli_env = {**env, "DOORMAN_URL": f"http://127.0.0.1:{agent_port}", "DOORMAN_TOKEN": token,
               "XDG_CONFIG_HOME": str(tmp_path / "xdg")}
    yield cli_env, owner_port, env
    proc.terminate()
    proc.wait(timeout=10)


def cli(env, *args, stdin=None):
    done = subprocess.run([sys.executable, str(CLI), *args], env=env, capture_output=True, text=True, input=stdin)
    return done.returncode, (json.loads(done.stdout) if done.stdout.strip().startswith(("{", "[")) else done.stdout)


def test_cli_against_running_server(server, tmp_path):
    env, owner_port, admin_env = server
    code, caps = cli(env, "caps")
    assert code == 0 and caps["plugins"][0]["name"] == "notes"

    body = tmp_path / "body.txt"
    body.write_text('Thu 08:00 "quoted" and\nmultiple lines')
    code, created = cli(env, "call", "notes.create", "title=Gym", f"body@{body}", "tags:=[\"sport\"]")
    assert code == 0 and created["status"] == "done"
    code, note = cli(env, "read", "notes.get", f"id={created['result']['id']}")
    assert note["body"] == body.read_text() and note["tags"] == ["sport"]

    code, sent = cli(env, "call", "notes.send_copy", f"id={created['result']['id']}", "to=anna@example.com")
    assert sent["status"] == "waiting_approval" and sent["warnings"] == []
    time.sleep(1.5)  # a few worker ticks: nothing goes out without the owner's approval
    code, status = cli(env, "status", str(sent["entry_id"]))
    assert status["status"] == "waiting_approval"

    code, denied = cli(env, "call", "notes.send_copy", "id=nope", "to=not-an-email")
    assert code == 3 and denied["code"] == "invalid"

    actions = json.dumps([{"tool": "notes.update", "args": {"id": created["result"]["id"], "title": "Gym (Fri)"}}])
    code, cs = cli(env, "propose", "--title", "Move gym", "--file", "-", stdin=actions)
    assert code == 0 and cs["status"] == "proposed" and cs["preview"][0]["decision"] == "run"

    code, journal = cli(env, "journal")
    assert [e["status"] for e in journal["entries"]][:3] == ["denied", "waiting_approval", "done"]

    subprocess.run([*ADMIN, "task", "Tidy", "notes"], env=admin_env, check=True, capture_output=True)
    code, claimed = cli(env, "claim")
    assert claimed["task"]["text"] == "Tidy notes"
    code, _ = cli(env, "report", str(claimed["task"]["id"]), "done", "Nothing to tidy")
    assert code == 0

    with urllib.request.urlopen(f"http://127.0.0.1:{owner_port}/app/") as response:
        page = response.read().decode()
        assert response.headers["Cache-Control"] == "no-cache"  # else phones mix new HTML with old CSS
    assert "<title>Doorman</title>" in page
    with urllib.request.urlopen(f"http://127.0.0.1:{owner_port}/app/app.css") as response:
        assert response.headers["Cache-Control"] == "no-cache"
    verify = subprocess.run([*ADMIN, "journal", "verify"], env=admin_env, capture_output=True, text=True)
    assert "intact" in verify.stdout


def _task_status(admin_env, text):
    import sqlite3
    config = yaml.safe_load(open(admin_env["DOORMAN_CONFIG"]))
    db = os.path.join(os.path.dirname(admin_env["DOORMAN_CONFIG"]), config["data_dir"], "doorman.db")
    row = sqlite3.connect(db).execute("SELECT status, report FROM tasks WHERE text=?", (text,)).fetchone()
    return row


def test_watch_reports_a_silent_run_and_honours_a_real_report(server):
    env, _, admin_env = server
    subprocess.run([*ADMIN, "task", "Silent", "run"], env=admin_env, check=True, capture_output=True)
    done = subprocess.run([sys.executable, str(CLI), "watch", "--once", "--exec", "true"], env=env,
                          capture_output=True, text=True, timeout=60)
    assert "marked failed" in done.stderr, done.stderr
    status, report = _task_status(admin_env, "Silent run")
    assert status == "failed" and "without reporting" in report

    subprocess.run([*ADMIN, "task", "Polite", "run"], env=admin_env, check=True, capture_output=True)
    command = f"{sys.executable} {CLI} report {{task_id}} done 'all good'"
    done = subprocess.run([sys.executable, str(CLI), "watch", "--once", "--exec", command], env=env,
                          capture_output=True, text=True, timeout=60)
    assert "marked failed" not in done.stderr, done.stderr
    assert _task_status(admin_env, "Polite run") == ("done", "all good")


def test_watch_waits_for_an_unreachable_doorman(tmp_path):
    env = {**os.environ, "DOORMAN_URL": f"http://127.0.0.1:{free_port()}", "DOORMAN_TOKEN": "x",
           "XDG_CONFIG_HOME": str(tmp_path)}
    proc = subprocess.Popen([sys.executable, str(CLI), "watch", "--once", "--exec", "true"], env=env,
                            stderr=subprocess.PIPE, text=True)
    time.sleep(2)
    assert proc.poll() is None  # still waiting, not exited
    proc.terminate()
    assert "trying again" in proc.communicate(timeout=10)[1]
