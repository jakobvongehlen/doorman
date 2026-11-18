"""Schema versions: PRAGMA user_version, ordered migrations, a copy before migrating, and a refusal to run on
a database a newer Doorman wrote."""

import sqlite3

import pytest
import yaml

from doorman import admin, db as dbmod
from doorman.db import SCHEMA, SCHEMA_VERSION, Database, SchemaTooNew


def columns(database, table):
    return {row[1] for row in database.conn.execute(f"PRAGMA table_info({table})")}


def test_a_new_database_starts_at_the_latest_version_without_a_copy(tmp_path):
    database = Database(tmp_path / "doorman.db")
    assert database.version() == SCHEMA_VERSION
    assert "rp_id" in columns(database, "webauthn_credentials")
    assert not list(tmp_path.glob("*.bak"))


def test_a_database_from_before_versions_is_copied_then_migrated(tmp_path):
    path = tmp_path / "doorman.db"
    old = sqlite3.connect(path)
    old.executescript(SCHEMA)  # the tables as an early Doorman made them, user_version 0
    for table, column, kind in dbmod._COLUMNS_V1[:3]:  # some of the columns added since, not all
        dbmod.add_column(old, table, column, kind)
    old.execute("INSERT INTO agent_keys(name, token_hash, role, created) VALUES('agent', 'h', 'solo', 'now')")
    old.commit()
    old.close()

    database = Database(path)
    assert database.version() == SCHEMA_VERSION
    assert {"last_used", "third_party_at"} <= columns(database, "agent_keys")
    assert database.one("SELECT name FROM agent_keys")["name"] == "agent"
    copies = list(tmp_path.glob("doorman.db.v0-*.bak"))
    assert len(copies) == 1
    copy = sqlite3.connect(copies[0])
    assert copy.execute("PRAGMA user_version").fetchone()[0] == 0
    assert copy.execute("SELECT name FROM agent_keys").fetchall() == [("agent",)]
    assert "last_used" not in {r[1] for r in copy.execute("PRAGMA table_info(agent_keys)")}

    database.close()
    Database(path)  # opened again: nothing to do, no second copy
    assert len(list(tmp_path.glob("*.bak"))) == 1


def test_a_failing_migration_changes_nothing(tmp_path, monkeypatch):
    path = tmp_path / "doorman.db"
    Database(path).close()

    def broken(conn):
        conn.execute("ALTER TABLE tasks ADD COLUMN half TEXT")
        raise RuntimeError("halfway")

    monkeypatch.setattr(dbmod, "MIGRATIONS", [*dbmod.MIGRATIONS, broken])
    monkeypatch.setattr(dbmod, "SCHEMA_VERSION", SCHEMA_VERSION + 1)
    with pytest.raises(RuntimeError, match="halfway"):
        Database(path)
    monkeypatch.undo()
    database = Database(path)
    assert database.version() == SCHEMA_VERSION and "half" not in columns(database, "tasks")


def test_a_database_from_a_newer_doorman_is_refused(tmp_path):
    path = tmp_path / "data" / "doorman.db"
    database = Database(path)
    database.conn.execute(f"PRAGMA user_version={SCHEMA_VERSION + 1}")
    database.close()
    with pytest.raises(SchemaTooNew, match=f"version {SCHEMA_VERSION + 1}"):
        Database(path)

    config_path = tmp_path / "doorman.yaml"
    config_path.write_text(yaml.safe_dump({"data_dir": str(tmp_path / "data")}))
    with pytest.raises(SystemExit, match="refusing to start: .*newer Doorman"):
        admin.main(["--config", str(config_path), "key", "list"])
