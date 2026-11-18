"""Plugins live in doorman.db only: a `plugins:` block in doorman.yaml stops Doorman, and schema version 6
drops the take-over mark that version 5 kept for plugins moved out of doorman.yaml."""

import sqlite3
from pathlib import Path

import pytest

from doorman import admin, config
from doorman import db as dbmod
from doorman.db import SCHEMA, SCHEMA_VERSION, Database
from doorman.util import dumps


def v5_database(path: Path) -> None:
    """doorman.db at schema version 5: google_calendar taken over in the app with a real
    client_id, one of work's tools switched to Ask me in the app."""
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    for migrate in dbmod.MIGRATIONS[:5]:
        migrate(conn)
    conn.execute("PRAGMA user_version=5")
    conn.execute("INSERT INTO plugin_instances(name, type, config, no_approval, created, taken_over) "
                 "VALUES('google_calendar', 'google_calendar', ?, 0, '2026-11-10T17:00:00+00:00', 1)",
                 (dumps({"client_id": "real.apps.googleusercontent.com", "timezone": "Europe/Berlin"}),))
    conn.execute("INSERT INTO plugin_state(name, enabled, read_only, disabled_tools, tool_approval) "
                 "VALUES('google_calendar', 1, 0, '[]', '{}')")
    conn.execute("INSERT INTO plugin_state(name, enabled, read_only, disabled_tools, tool_approval) "
                 "VALUES('work', 1, 0, '[]', ?)", (dumps({"delete": "ask"}),))
    conn.commit()
    conn.close()


def test_doorman_doesnt_start_while_doorman_yaml_defines_plugins(tmp_path):
    path = tmp_path / "doorman.yaml"
    path.write_text("data_dir: ./data\nplugins:\n  notes: {enabled: true}\n  work: {type: nextcloud_notes}\n")
    with pytest.raises(config.PluginsInConfig, match="notes, work") as exc:
        config.load(path)
    assert "remove the `plugins:` block" in str(exc.value)
    for command in (["plugins"], ["restore", str(tmp_path / "backup.tar")]):
        with pytest.raises(SystemExit, match="refusing to start: .*owner app"):
            admin.main(["--config", str(path), *command])
    with pytest.raises(TypeError):
        config.load(overrides={"plugins": {"notes": {"enabled": True}}})


def test_migration_6_drops_the_take_over_mark(tmp_path):
    path = tmp_path / "doorman.db"
    v5_database(path)
    database = Database(path)
    assert database.version() == SCHEMA_VERSION and not database.fresh
    assert "taken_over" not in {r[1] for r in database.conn.execute("PRAGMA table_info(plugin_instances)")}
    row = database.one("SELECT * FROM plugin_instances")
    assert row["name"] == "google_calendar" and "real.apps" in row["config"]
    assert len(list(tmp_path.glob("doorman.db.v5-*.bak"))) == 1
    assert Database(tmp_path / "new.db").fresh
