"""Backups, restore, the vault key guard and /health; the nightly backup and the dead-man ping."""

import asyncio
import json
import shutil
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx
import pytest
import yaml
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from doorman import admin, backup, clock, config, server, upkeep
from doorman.api.agent import create_agent_app
from doorman.engine import Engine
from doorman.vault import Vault, VaultKeyError
from conftest import Agent, make_engine


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.delenv("DOORMAN_VAULT_KEY", raising=False)
    engine = make_engine(tmp_path)
    engine.vault.set("mail", "password", "hunter2")
    agent = Agent(engine)
    note_id = agent.call("notes.create", {"title": "Plan", "body": "v1"})["result"]["id"]
    updated = agent.call("notes.update", {"id": note_id, "body": "v2"})
    return engine, agent, note_id, updated["entry_id"], tmp_path


def test_a_restored_backup_still_undoes(world, tmp_path):
    engine, agent, note_id, entry_id, _ = world
    made = backup.make_backup(engine.config.data_dir, None, tmp_path / "backups")
    files = json.loads((made / "manifest.json").read_text())["files"]
    assert "data/doorman.db" in files and "data/vault.enc" in files
    assert f"data/plugins/notes/{note_id}.json" in files
    assert not any(name.endswith("vault.key") for name in files)

    target = tmp_path / "restored"
    backup.restore(made, target)
    shutil.copy(engine.config.data_dir / "vault.key", target / "vault.key")  # the key comes from elsewhere
    restored = Engine(config.load(overrides={"data_dir": str(target)}))
    assert restored.vault.get("mail") == {"password": "hunter2"}
    assert restored.revert_entry(entry_id)["reverted"] == [entry_id]
    assert restored.registry.instance("notes").load(note_id)["body"] == "v1"
    assert restored.journal.verify()[0]


def test_restore_without_the_key_refuses_to_start(world, tmp_path):
    engine, *_ = world
    made = backup.make_backup(engine.config.data_dir, None, tmp_path / "backups")
    target = tmp_path / "restored"
    backup.restore(made, target)
    with pytest.raises(VaultKeyError, match="no key"):
        Vault(target)
    assert not (target / "vault.key").exists()  # it didn't quietly make a new one


def test_a_wrong_key_refuses_to_start(world, monkeypatch):
    engine, *_ = world
    monkeypatch.setenv("DOORMAN_VAULT_KEY", Fernet.generate_key().decode())
    with pytest.raises(VaultKeyError, match="doesn't open"):
        Vault(engine.config.data_dir)


def test_backups_are_pruned_and_partial_ones_ignored(world, tmp_path):
    engine, *_ = world
    dest = tmp_path / "backups"
    (dest / "doorman-20200101-000000.partial").mkdir(parents=True)
    made = []
    for _ in range(4):
        made.append(backup.make_backup(engine.config.data_dir, None, dest, keep=2))
        clock.advance(86400)
    assert backup.list_backups(dest) == made[-2:]  # the two newest
    assert (dest / "doorman-20200101-000000.partial").exists()  # never counted, never pruned


def test_tampered_backup_is_refused(world, tmp_path):
    engine, *_ = world
    made = backup.make_backup(engine.config.data_dir, None, tmp_path / "backups")
    (made / "data" / "vault.enc").write_bytes(b"x")
    with pytest.raises(backup.BackupError, match="changed"):
        backup.restore(made, tmp_path / "restored")


def test_restore_does_not_overwrite_a_live_doorman(world, tmp_path):
    engine, *_ = world
    made = backup.make_backup(engine.config.data_dir, None, tmp_path / "backups")
    with pytest.raises(backup.BackupError, match="--force"):
        backup.restore(made, engine.config.data_dir)


def test_backup_includes_extra_paths(world, tmp_path):
    engine, *_ = world
    sidecar = tmp_path / "whatsapp"
    sidecar.mkdir()
    import sqlite3
    db = sqlite3.connect(sidecar / "session.db")
    db.execute("CREATE TABLE t(x)")
    db.execute("INSERT INTO t VALUES (1)")
    db.commit()
    made = backup.make_backup(engine.config.data_dir, None, tmp_path / "backups", extra_paths=[str(sidecar)])
    copied = sqlite3.connect(made / "extra" / "whatsapp" / "session.db")
    assert copied.execute("SELECT x FROM t").fetchall() == [(1,)]



def test_restore_puts_extras_back_and_drops_stale_wal(world, tmp_path):
    """The WhatsApp session comes back on restore, and an old -wal can't replay over a restored db."""
    import sqlite3
    engine, *_ = world
    sidecar = tmp_path / "whatsapp"
    sidecar.mkdir()
    db = sqlite3.connect(sidecar / "session.db")
    db.execute("CREATE TABLE t(x)")
    db.execute("INSERT INTO t VALUES ('paired')")
    db.commit()
    db.close()
    (sidecar / "keys").mkdir()
    (sidecar / "keys" / "device.json").write_text('{"id": 1}')
    made = backup.make_backup(engine.config.data_dir, None, tmp_path / "backups", extra_paths=[str(sidecar)])

    # the session is lost (new host, wiped volume); a stale WAL of something else lies around
    import shutil
    shutil.rmtree(sidecar)
    (engine.config.data_dir / "doorman.db-wal").write_bytes(b"stale")
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    (fresh / "doorman.db-wal").write_bytes(b"stale")
    backup.restore(made, fresh)
    assert not (fresh / "doorman.db-wal").exists()
    restored = sqlite3.connect(sidecar / "session.db")
    assert restored.execute("SELECT x FROM t").fetchall() == [("paired",)]
    assert (sidecar / "keys" / "device.json").read_text() == '{"id": 1}'

    # an existing session is only replaced with force, and a moved one follows extra_paths
    with pytest.raises(backup.BackupError, match="--force"):
        backup.restore(made, tmp_path / "again")
    moved = tmp_path / "srv" / "whatsapp"
    backup.restore(made, tmp_path / "third", extra_paths=[str(moved)])
    assert (moved / "keys" / "device.json").exists()

def test_restore_clears_derived_caches_so_they_are_rebuilt(world, tmp_path):
    """A mail archive's search index isn't backed up. Restoring over a data directory must not leave the old
    one there: it would point at messages the restored archive.db doesn't have (or numbers them differently),
    and the archive only rebuilds an index that's missing."""
    engine, *_ = world
    plugins = engine.config.data_dir / "plugins"
    archive = plugins / "mail" / "archive"
    (archive / "cache").mkdir(parents=True)
    (archive / "cache" / ".no-backup").touch()
    (archive / "archive.db").write_bytes(b"messages as of the backup")
    (archive / "cache" / "index.db").write_bytes(b"index as of the backup")
    made = backup.make_backup(engine.config.data_dir, None, tmp_path / "backups")
    assert not any("cache" in name for name in json.loads((made / "manifest.json").read_text())["files"])

    # life goes on: more mail, a newer index; then the owner restores the backup over it
    (archive / "archive.db").write_bytes(b"messages from later")
    (archive / "cache" / "index.db").write_bytes(b"index from later")
    (archive / "cache" / "index.db-wal").write_bytes(b"its log")
    backup.restore(made, engine.config.data_dir, force=True)
    assert (archive / "archive.db").read_bytes() == b"messages as of the backup"
    assert not (archive / "cache").exists()  # rebuilt from archive.db on the next start
    assert (plugins / "notes").is_dir()  # what isn't derived stays


def test_admin_backup_and_restore_commands(world, tmp_path, capsys):
    engine, agent, note_id, entry_id, _ = world
    config_path = tmp_path / "doorman.yaml"
    config_path.write_text(yaml.safe_dump({"data_dir": str(engine.config.data_dir),
                                           "backup": {"dir": str(tmp_path / "nightly"), "keep": 3}}))
    admin.main(["--config", str(config_path), "backup"])
    assert "the vault key is not in it" in capsys.readouterr().out
    made = backup.list_backups(tmp_path / "nightly")[0]
    reopened = Engine(config.load(config_path))
    assert reopened.db.get_setting("last_backup")
    admin.main(["--config", str(config_path), "restore", str(made), "--data-dir", str(tmp_path / "copy")])
    assert (tmp_path / "copy" / "doorman.db").exists()


def test_a_failed_backup_needs_attention(world, tmp_path):
    engine, *_ = world
    config_path = tmp_path / "doorman.yaml"
    config_path.write_text(yaml.safe_dump({"data_dir": str(engine.config.data_dir),
                                           "backup": {"dir": str(tmp_path / "b"), "extra_paths": ["/nope"]}}))
    with pytest.raises(SystemExit, match="backup failed"):
        admin.main(["--config", str(config_path), "backup"])
    reopened = Engine(config.load(config_path))
    assert [i["title"] for i in reopened.attention_list()] == ["The backup failed"]


def test_health(world):
    engine, *_ = world
    client = TestClient(create_agent_app(engine))
    assert client.get("/health").json()["status"] == "ok"  # no tick yet: just started
    engine.tick()
    body = client.get("/health").json()
    assert body["status"] == "ok" and body["db"] and body["worker_seconds_ago"] is not None
    clock.advance(600)
    response = client.get("/health")
    assert response.status_code == 503 and response.json()["status"] == "unhealthy"


# ------------------------------------------------------------------ the nightly backup and the dead-man ping

def _fake_copy(tmp_path, body: str = "") -> Path:
    """A stand-in for rclone or restic: notes its arguments and environment in argv[1], then runs `body`."""
    script = tmp_path / "fake-copy"
    script.write_text(f"#!{sys.executable}\n"
                      "import json, os, sys, time\n"
                      "json.dump({'argv': sys.argv[1:], 'env': dict(os.environ)}, open(sys.argv[1], 'w'))\n"
                      f"{body}\n")
    script.chmod(0o755)
    return script


def _nightly(tmp_path, **backup_settings):
    clock.reset()
    engine = make_engine(tmp_path, timezone="Europe/Amsterdam",
                         backup={"dir": str(tmp_path / "nightly"), "keep": 2, **backup_settings})
    # started two days ago and never backed up: the first one is due at once
    engine.db.set_setting("first_start", clock.iso(clock.now() - timedelta(days=2)))
    return engine


def test_next_run_is_the_time_of_day_in_the_owners_timezone():
    zone = ZoneInfo("Europe/Amsterdam")
    after = datetime(2026, 11, 7, 1, 0, tzinfo=timezone.utc)  # 02:00 in Amsterdam
    assert backup.next_run("03:30", zone, after) == datetime(2026, 11, 7, 3, 30, tzinfo=zone)
    assert backup.next_run("01:15", zone, after) == datetime(2026, 11, 8, 1, 15, tzinfo=zone)
    unquoted = yaml.safe_load("schedule: 3:30")["schedule"]  # YAML 1.1: 210, in base 60
    assert backup.next_run(unquoted, zone, after) == datetime(2026, 11, 7, 3, 30, tzinfo=zone)
    # 29 March 2026: the clocks jump from 02:00 to 03:00, so 02:30 runs an hour later that day
    spring = backup.next_run("02:30", zone, datetime(2026, 3, 28, 12, 0, tzinfo=timezone.utc))
    assert spring.astimezone(timezone.utc) == datetime(2026, 3, 29, 1, 30, tzinfo=timezone.utc)
    for bad in ("3am", "25:00", "", None):
        with pytest.raises(backup.BackupError, match="time of day"):
            backup.next_run(bad, zone, after)


def test_the_copy_command_is_split_without_a_shell(tmp_path):
    made = tmp_path / "my backups" / "doorman-20261107-033000"
    args = backup.copy_command_args("rclone copy {path} 'remote:doorman/{name}' ; rm -rf /", made)
    assert args == ["rclone", "copy", str(made), "remote:doorman/doorman-20261107-033000", ";", "rm", "-rf", "/"]
    with pytest.raises(backup.BackupError, match="split"):
        backup.copy_command_args("rclone 'unclosed", made)


def test_the_copy_gets_no_secrets_and_is_stopped_on_a_timeout(tmp_path, monkeypatch):
    monkeypatch.setenv("DOORMAN_VAULT_KEY", "the-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setenv("RESTIC_PASSWORD", "restic-secret")
    made = tmp_path / "doorman-20261107-033000"
    made.mkdir()
    out = tmp_path / "seen.json"
    backup.copy_off_host(made, [str(_fake_copy(tmp_path)), str(out), "{path}"], 30, ["RESTIC_PASSWORD"])
    seen = json.loads(out.read_text())
    assert seen["argv"] == [str(out), str(made)]
    assert seen["env"]["RESTIC_PASSWORD"] == "restic-secret"
    assert "DOORMAN_VAULT_KEY" not in seen["env"] and "ANTHROPIC_API_KEY" not in seen["env"]
    with pytest.raises(backup.BackupError, match="never passed"):
        backup.copy_off_host(made, [str(_fake_copy(tmp_path)), str(out)], 30, ["DOORMAN_VAULT_KEY"])

    with pytest.raises(backup.BackupError, match="exited with 3: no route to remote"):
        backup.copy_off_host(made, [str(_fake_copy(tmp_path, "print('no route to remote'); sys.exit(3)")), str(out)], 30)
    began = time.monotonic()
    with pytest.raises(backup.BackupError, match="longer than 1 seconds"):
        backup.copy_off_host(made, [str(_fake_copy(tmp_path, "time.sleep(60)")), str(out)], 1)
    assert time.monotonic() - began < 10
    with pytest.raises(backup.BackupError, match="couldn't start"):
        backup.copy_off_host(made, [str(tmp_path / "no-such-tool")], 30)


def test_the_worker_backs_up_nightly_and_copies_it_off_the_host(tmp_path):
    out = tmp_path / "seen.json"
    script = _fake_copy(tmp_path, "sys.exit(0 if os.path.exists(sys.argv[2] + '/manifest.json') else 1)")
    engine = _nightly(tmp_path, copy_command=f"{script} {out} {{path}}")
    assert upkeep.due(engine)
    run = upkeep.run_backup(engine)
    assert run["ok"] and run["copy"] == {"ok": True, "error": None}
    assert json.loads(out.read_text())["argv"][1] == run["path"]
    assert backup.list_backups(tmp_path / "nightly") == [Path(run["path"])]
    assert not upkeep.due(engine)  # the next one is tonight
    row = engine.status()["backup"]
    assert row["last"] and row["problem"] is None and row["copied"] is True and row["failed"] is False
    assert clock.parse(row["next"]) - clock.now() <= timedelta(hours=24)
    clock.advance(25 * 3600)
    assert upkeep.due(engine)


def test_a_failed_copy_and_an_old_backup_need_attention(tmp_path):
    engine = _nightly(tmp_path, copy_command=[str(_fake_copy(tmp_path, "sys.exit(2)")), str(tmp_path / "o")])
    run = upkeep.run_backup(engine)
    assert run["ok"] and run["copy"]["ok"] is False and "exited with 2" in run["copy"]["error"]
    assert [i["title"] for i in engine.attention_list()] == ["The backup wasn't copied off the host"]
    row = engine.status()["backup"]
    assert row["copied"] is False and row["failed"] and row["problem"] == "The backup wasn't copied off the host"

    engine.config["backup"]["copy_command"] = [str(_fake_copy(tmp_path)), str(tmp_path / "o")]
    clock.advance(60)  # backups are named by the second
    upkeep.run_backup(engine)
    assert engine.attention_list() == []

    # scheduled, a backup older than 36 hours is listed (not after backup_warn_days)
    clock.advance(30 * 3600)
    assert engine.check_silence(force=True) == []
    clock.advance(7 * 3600)
    assert "backup" in engine.check_silence(force=True)
    assert [i["title"] for i in engine.attention_list()] == ["No backup for 36 hours"]
    assert "doorman-admin backup status" in engine.attention_list()[0]["detail"]
    upkeep.run_backup(engine)
    engine.check_silence(force=True)
    assert engine.attention_list() == []


def test_a_failed_nightly_backup_waits_for_the_next_night(tmp_path):
    engine = _nightly(tmp_path, extra_paths=["/nope"])
    run = upkeep.run_backup(engine)
    assert not run["ok"] and "doesn't exist" in run["error"]
    assert [i["title"] for i in engine.attention_list()] == ["The backup failed"]
    assert engine.status()["backup"]["failed"] and not upkeep.due(engine)
    engine.config["backup"]["schedule"] = "half past three"
    assert not upkeep.due(engine)
    assert "Backups don't run on their own" in [i["title"] for i in engine.attention_list()]


def test_admin_backup_status(tmp_path, capsys):
    engine = _nightly(tmp_path)
    config_path = tmp_path / "doorman.yaml"
    config_path.write_text(yaml.safe_dump({"data_dir": str(engine.config.data_dir), "timezone": "Europe/Amsterdam",
                                           "backup": {"dir": str(tmp_path / "nightly"), "schedule": "04:15"}}))
    admin.main(["--config", str(config_path), "backup", "status"])
    out = capsys.readouterr().out
    assert "every day at 04:15 (Europe/Amsterdam)" in out and "last run:  none" in out
    assert "as soon as Doorman's worker runs" in out and "backups stay on this host" in out
    admin.main(["--config", str(config_path), "backup"])
    capsys.readouterr()
    admin.main(["--config", str(config_path), "backup", "status"])
    out = capsys.readouterr().out
    assert ", ok: " in out and "04:15 CE" in out.split("next run:")[1]


def test_the_dead_man_ping(tmp_path, monkeypatch):
    engine = make_engine(tmp_path, health={"ping_url": "https://hc-ping.example/abc-123"})
    seen = []
    transport = httpx.MockTransport(lambda request: seen.append(str(request.url)) or httpx.Response(200))
    assert upkeep.ping(engine, transport)["status"] == 200
    monkeypatch.setattr(engine, "health", lambda: (False, {}))
    assert upkeep.ping(engine, transport)["healthy"] is False
    assert seen == ["https://hc-ping.example/abc-123", "https://hc-ping.example/abc-123/fail"]

    def down(request):
        raise httpx.ConnectTimeout("too slow", request=request)
    assert upkeep.ping(engine, httpx.MockTransport(down))["error"] == "ConnectTimeout"
    engine.config["health"]["ping_url"] = None
    assert upkeep.ping(engine, transport) is None


def test_the_worker_pings_and_backs_up_beside_the_tick(tmp_path, monkeypatch):
    engine = _nightly(tmp_path)
    engine.config["health"]["ping_url"] = "https://hc-ping.example/abc-123"
    pinged = threading.Event()

    def slow_ping(engine):
        pinged.set()
        time.sleep(1)  # a slow ping service
    monkeypatch.setattr(upkeep, "ping", slow_ping)

    async def go():
        running, last = {}, {}
        began = time.monotonic()
        assert server.start_ping(engine, last, running) and server.start_backup(engine, last, running)
        assert time.monotonic() - began < 0.5 and set(running) == {"ping", "backup"}
        assert not server.start_ping(engine, last, running) and not server.start_backup(engine, last, running)
        await asyncio.gather(*running.values())
        assert not server.start_ping(engine, last, running)  # not again for five minutes
    asyncio.run(go())
    assert pinged.is_set() and upkeep.last_run(engine)["ok"]
