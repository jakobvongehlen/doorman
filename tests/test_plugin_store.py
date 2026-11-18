"""A plugin's own SQLite database (plugin_api.open_store): its layout's version, migrations with a copy before
them, refusing a store a newer plugin wrote, and keeping to the account it was made for: the mail archive sets
aside one made for another mailbox, the file index's feed starts over when its store was made anew."""

import sqlite3

import pytest

from doorman.plugin_api import StoreOfAnother, StoreTooNew, open_store, set_aside
from conftest import make_engine

SCHEMA = "CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, text TEXT, stars INTEGER DEFAULT 0);"


def version(conn):
    return conn.execute("PRAGMA user_version").fetchone()[0]


def test_a_new_store_gets_the_newest_layout_and_runs_no_migration(tmp_path):
    ran = []
    conn = open_store(tmp_path / "s.db", SCHEMA, [lambda c: ran.append(1)])
    assert version(conn) == 2 and ran == []
    conn.execute("INSERT INTO notes(text, stars) VALUES('a', 3)")
    conn.commit()
    conn.close()
    assert version(open_store(tmp_path / "s.db", SCHEMA, [lambda c: ran.append(1)])) == 2 and ran == []
    assert not list(tmp_path.glob("*.bak"))


def test_an_older_store_is_copied_then_migrated(tmp_path):
    old = sqlite3.connect(tmp_path / "s.db")           # a store from before versions: the first layout
    old.execute("CREATE TABLE notes(id INTEGER PRIMARY KEY, text TEXT)")
    old.execute("INSERT INTO notes(text) VALUES('kept')")
    old.commit()
    old.close()

    def add_stars(conn):
        conn.execute("ALTER TABLE notes ADD COLUMN stars INTEGER DEFAULT 0")
        conn.execute("UPDATE notes SET stars = 5")

    conn = open_store(tmp_path / "s.db", SCHEMA, [add_stars])
    assert version(conn) == 2 and conn.execute("SELECT text, stars FROM notes").fetchall() == [("kept", 5)]
    backup = sqlite3.connect(tmp_path / "s.db.v1.bak")
    assert backup.execute("SELECT * FROM notes").fetchall() == [(1, "kept")]


def test_a_migration_that_fails_changes_nothing(tmp_path):
    open_store(tmp_path / "s.db", SCHEMA).close()

    def half(conn):
        conn.execute("UPDATE notes SET stars = 1")
        raise RuntimeError("bug")

    with pytest.raises(RuntimeError):
        open_store(tmp_path / "s.db", SCHEMA, [half])
    assert version(sqlite3.connect(tmp_path / "s.db")) == 1


def test_a_store_a_newer_plugin_wrote_is_refused(tmp_path):
    open_store(tmp_path / "s.db", SCHEMA, [lambda c: None, lambda c: None]).close()
    with pytest.raises(StoreTooNew, match="version 3 .* knows up to 1"):
        open_store(tmp_path / "s.db", SCHEMA)


def test_a_store_keeps_to_what_it_was_made_for(tmp_path):
    open_store(tmp_path / "s.db", SCHEMA, belongs_to="anna on imap.example.com").close()
    open_store(tmp_path / "s.db", SCHEMA, belongs_to="anna on imap.example.com").close()
    with pytest.raises(StoreOfAnother, match="made for anna on imap.example.com.*now for bob"):
        open_store(tmp_path / "s.db", SCHEMA, belongs_to="bob on imap.example.com")
    kept = set_aside(tmp_path / "s.db", "other")
    assert kept.name.startswith("s.db.other-") and not (tmp_path / "s.db").exists()
    assert open_store(tmp_path / "s.db", SCHEMA, belongs_to="bob on imap.example.com")


def test_a_mail_archive_made_for_another_mailbox_is_set_aside(tmp_path):
    engine = make_engine(tmp_path, plugins={"mail": {"type": "mail_imap", "enabled": True, "config": {
        "imap_host": "imap.example.com", "smtp_host": "smtp.example.com", "from_address": "me@example.com"}}})
    engine.vault.set("mail", "username", "Anna")
    archive = engine.registry.instance("mail").archive
    cursor = archive.feed(None, 10)["cursor"]
    archive.meta("note", "anna's archive")
    engine.vault.set("mail", "username", "bob")              # the same plugin, now for another mailbox
    engine.registry.invalidate("mail")
    archive = engine.registry.instance("mail").archive
    assert archive.meta("note") is None
    folder = tmp_path / "data" / "plugins" / "mail"
    [kept] = folder.glob("archive.other-mailbox-*")
    assert (kept / "archive.db").exists()
    assert archive.feed(cursor, 10).get("reset") is True     # the search index starts over with this one
    engine.registry.invalidate("mail")
    assert engine.registry.instance("mail").archive.meta("note") is None and len(list(folder.glob("archive.*"))) == 1


def test_the_file_index_made_anew_starts_its_feed_over(tmp_path):
    root = tmp_path / "files"
    root.mkdir()
    (root / "a.txt").write_text("Alpha")
    engine = make_engine(tmp_path, plugins={"files": {"enabled": True, "config": {"root": str(root)}},
                                            "notes": {"enabled": False}})
    files = engine.registry.instance("files")
    files.index()
    cursor = files.index_feed(None, 60)["cursor"]
    assert files.index_feed(cursor, 60) == {"items": [], "removed": [], "cursor": cursor, "more": False}
    engine.registry.invalidate("files")
    (tmp_path / "data" / "plugins" / "files" / "index.db").unlink()
    files = engine.registry.instance("files")
    files.index()
    out = files.index_feed(cursor, 60)
    assert out["reset"] is True and [i["key"] for i in out["items"]] == ["a.txt"]
