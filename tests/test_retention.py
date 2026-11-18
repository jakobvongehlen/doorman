"""Retention: what grows with use leaves doorman.db after its time (retention.py), plus an occasional VACUUM."""

import os

from doorman import clock, retention
from conftest import make_engine

OLD = "2020-01-01T00:00:00+00:00"


def fill(engine):
    now = clock.iso()
    rows = {
        "scans(sha256, model, score, start, end, ts)": [("old", "m", 0.1, 0, 0, OLD), ("new", "m", 0.1, 0, 0, now)],
        "quarantine(sha256, source, status, created, decided)": [
            ("released-old", "mail", "released", OLD, OLD), ("kept-old", "mail", "kept", OLD, OLD),
            ("held-old", "mail", "held", OLD, None), ("released-new", "mail", "released", OLD, now)],
        "provenance(session_id, kind, value, origin, trust, ts)": [
            ("s", "email", "old@example.com", "mail:1", "third_party", OLD),
            ("s", "email", "new@example.com", "mail:2", "third_party", now)],
        "notifications(ts, title, message, url, delivered)": [(OLD, "old", "", "", 1), (now, "new", "", "", 1)],
        "attention(kind, ref, title, created, resolved)": [
            ("job", "a", "resolved long ago", OLD, OLD), ("job", "b", "still open", OLD, None),
            ("job", "c", "resolved today", OLD, now)],
        "records(source, data, session_id, created)": [("mail:1", "{}", "s", OLD), ("mail:2", "{}", "s", now)],
        "owner_sessions(token_hash, created, expires)": [("expired", OLD, OLD), ("live", now, "2999-01-01")],
        "challenges(id, purpose, challenge, created)": [("c-old", "login", b"x", OLD), ("c-new", "login", b"x", now)],
        "push_gone(endpoint, ts)": [("https://old", OLD), ("https://new", now)],
        "push_logged_out(endpoint_hash, credential_id, ts)": [("old", None, OLD), ("new", None, now)],
        "pseudonyms(token, original, label, created)": [("PSN-00000001", "Zahnarzt", "Gesundheit", OLD)],
    }
    with engine.db.tx() as conn:
        for table, values in rows.items():
            marks = ",".join("?" * len(values[0]))
            conn.executemany(f"INSERT INTO {table} VALUES({marks})", values)


def column(engine, sql):
    return sorted(r[next(iter(r))] for r in engine.db.all(sql))


def test_the_worker_prunes_what_is_past_its_time(tmp_path):
    engine = make_engine(tmp_path)
    fill(engine)
    engine.tick()
    assert column(engine, "SELECT sha256 FROM scans") == ["new"]
    assert column(engine, "SELECT sha256 FROM quarantine") == ["held-old", "released-new"]  # undecided stays
    assert column(engine, "SELECT value FROM provenance") == ["new@example.com"]
    assert column(engine, "SELECT title FROM notifications") == ["new"]
    assert column(engine, "SELECT title FROM attention") == ["resolved today", "still open"]
    assert column(engine, "SELECT source FROM records") == ["mail:2"]
    assert column(engine, "SELECT token_hash FROM owner_sessions") == ["live"]
    assert column(engine, "SELECT id FROM challenges") == ["c-new"]
    assert column(engine, "SELECT endpoint FROM push_gone") == ["https://new"]
    assert column(engine, "SELECT endpoint_hash FROM push_logged_out") == ["new"]
    assert column(engine, "SELECT token FROM pseudonyms") == ["PSN-00000001"]  # never: an agent may still hold it

    engine.db.exec("INSERT INTO scans(sha256, model, score, start, end, ts) VALUES('x','m',0,0,0,?)",
                   (OLD,))
    engine.tick()  # hourly, not every tick
    assert "x" in column(engine, "SELECT sha256 FROM scans")
    clock.advance(3601)
    engine.tick()
    assert "x" not in column(engine, "SELECT sha256 FROM scans")


def test_zero_days_keeps_everything_of_that_kind(tmp_path):
    engine = make_engine(tmp_path, retention={"scans_days": 0, "provenance_days": 0})
    fill(engine)
    engine.prune_tables()
    assert column(engine, "SELECT sha256 FROM scans") == ["new", "old"]
    assert len(column(engine, "SELECT value FROM provenance")) == 2
    assert column(engine, "SELECT title FROM notifications") == ["new"]  # the others still apply


def test_vacuum_when_enough_of_the_file_is_free(tmp_path, monkeypatch):
    monkeypatch.setattr(retention, "VACUUM_MIN_FREE", 0)
    engine = make_engine(tmp_path)
    path = tmp_path / "data" / "doorman.db"
    with engine.db.tx() as conn:
        conn.executemany("INSERT INTO notifications(ts, title, message, url, delivered) VALUES(?,?,?,?,1)",
                         [(OLD, "old", "x" * 2000, "") for _ in range(1000)])
    engine.db.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    full = os.path.getsize(path)
    assert not retention.maybe_vacuum(engine.db, 7)  # little free yet: it looks, and waits a week
    engine.db.set_setting("last_vacuum", None)
    retention.prune(engine.db, retention.DEFAULTS)
    assert retention.maybe_vacuum(engine.db, 7)
    assert os.path.getsize(path) < full / 2
    assert not retention.maybe_vacuum(engine.db, 7)  # not again this week
    assert engine.db.one("SELECT COUNT(*) AS n FROM notifications")["n"] == 0
