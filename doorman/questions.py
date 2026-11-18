"""Questions an agent asks the reader about one item (`doorman ask <ref> "..."`), and the reader's answers.

An actor key under the reader/actor split can't read raw third-party text. When a record isn't enough
("which attachment is the invoice, what's the amount and the due date?"), it asks:

1. POST /v1/questions {ref, question}: queued here (table `questions`).
2. doorman-reader long-polls GET /v1/reader/questions, so it picks the question up within seconds. Each
   comes with the read that returns the item (the plugin's `item:` in its manifest). The reader reads it
   with its own key, asks its model in a fresh conversation, and answers in a fixed form
   (structure.ANSWER_SCHEMA): a short answer text, plus attachments, participants, ids, dates and
   amounts it takes from the item itself, each checked against a pattern here again.
3. The asker gets question_answered in its event feed (or follows it with `doorman wait question:<id>`) and
   fetches GET /v1/questions/<id>. The answer is third-party-derived, so on its way out it takes
   the path of a record: cleaned, redacted, scanned by the guard (a hit comes back as `quarantined`),
   placeholders, taint, provenance, the read log, and spotlighting in the API.

The reader stays stateless: Doorman keeps the queue, leases a question to the reader that took it, and
gives it up when nobody answers within EXPIRE_MINUTES.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from . import clock, sanitize
from .plugin_api import Denied
from .structure import ANSWER_ERRORS, ANSWER_SCHEMA, QUESTION_SCHEMA
from .util import dumps, loads

LEASE_MINUTES = 5     # a question the reader took but didn't answer by then goes back to the queue
EXPIRE_MINUTES = 60   # a question nobody answered by then is given up
OPEN_PER_KEY = 20     # questions one key may have waiting at once
KEEP_DAYS = 7         # answered and given-up questions are deleted after this
OPEN = ("pending", "claimed")
EXPIRED = "Nobody answered within an hour. Is doorman-reader running?"


class Questions:
    def __init__(self, engine):
        self.engine = engine
        self.db = engine.db
        self._swept = 0.0

    # ------------------------------------------------------------------ the asking agent

    def ask(self, session: dict, key: dict, body: Any) -> dict:
        engine = self.engine
        engine._guard(session, None, write=False)
        if key["role"] == "reader":
            raise Denied("reader keys answer questions, they don't ask them", "role")
        engine._validate(QUESTION_SCHEMA, body, "question")
        item = engine.item_of(body["ref"])
        engine._guard(session, item["instance"], write=False)
        engine.registry.find_read(item["read"])  # switched off: refused now, not by the reader later
        if not self.db.one("SELECT 1 FROM agent_keys WHERE role='reader' AND revoked=0"):
            raise Denied("no reader is set up to answer questions; the owner starts doorman-reader with a reader key",
                         "no_reader")
        self.sweep()
        waiting = self.db.one(f"SELECT COUNT(*) AS n FROM questions WHERE key_id=? AND status IN {OPEN}",
                              (key["id"],))["n"]
        if waiting >= OPEN_PER_KEY:
            raise Denied(f"{waiting} of your questions are still waiting; wait for their answers first", "too_many")
        question = " ".join(sanitize.clean_text(body["question"])[0].split())
        qid = self.db.exec("INSERT INTO questions(key_id, session_id, ref, question, status, created) "
                           "VALUES(?,?,?,?,'pending',?)", (key["id"], session["id"], body["ref"], question, clock.iso()))
        engine.feed.bell.ring()  # wakes doorman-reader's waiting GET /v1/reader/questions
        return self._view(self.db.one("SELECT * FROM questions WHERE id=?", (qid,)))

    def mine(self, session: dict, key: dict, limit: int = 20) -> list[dict]:
        """This key's latest questions, without their answers (get() shows one with its answer)."""
        self.engine._guard(session, None, write=False)
        self.sweep()
        rows = self.db.all("SELECT * FROM questions WHERE key_id=? ORDER BY id DESC LIMIT ?",
                           (key["id"], max(1, min(int(limit), 100))))
        return [self._view(r) for r in rows]

    def get(self, session: dict, key: dict, qid: int) -> dict:
        """One question of this key's, with the answer once there is one: checked like a record on its way out."""
        engine = self.engine
        engine._guard(session, None, write=False)
        self.sweep()
        row = self.db.one("SELECT * FROM questions WHERE id=?", (qid,))
        if row is None or row["key_id"] != key["id"]:
            raise Denied("no such question", "not_found")
        out = self._view(row)
        if row["status"] != "answered":
            return out
        instance = row["ref"].split(":", 1)[0]
        answer = engine.redactor.value(sanitize.clean_value({"ref": row["ref"], **loads(row["answer"], {})})[0])
        (answer,), unscanned = engine._scan("questions", {}, {"id": qid}, [answer])
        engine.auth.taint(session["id"], True, False)
        engine.provenance.record(session["id"], answer, "questions", "third_party")
        shown, hidden = engine.pseudonyms.hide(answer, engine.plugin_type(instance))
        engine.reads.add(key, session, "questions", {"id": qid}, shown, trust="third_party", hidden=hidden,
                         status="unscanned" if unscanned else "ok", error=unscanned)
        out["answer"] = {k: v for k, v in shown.items() if k != "ref"}
        return out

    @staticmethod
    def _view(row: dict) -> dict:
        out = {"id": row["id"], "ref": row["ref"], "question": row["question"],
               "status": "pending" if row["status"] == "claimed" else row["status"], "asked": row["created"]}
        if row["answered"]:
            out["answered"] = row["answered"]
        if row["status"] == "failed":
            out["error"] = ANSWER_ERRORS.get(row["error"] or "", ANSWER_ERRORS["unreadable"])
        elif row["status"] == "expired":
            out["error"] = EXPIRED
        return out

    # ------------------------------------------------------------------ the reader

    def claim(self, key: dict, limit: int = 5) -> list[dict]:
        """Up to `limit` waiting questions for this reader key, each leased to it for LEASE_MINUTES, with the
        read that returns its item ({read, params}) and, for a mailbox, the read for an attachment's text."""
        if key["role"] != "reader":
            raise Denied("only reader keys answer questions", "role")
        if self.engine.killed():
            return []
        self.sweep()
        now = clock.now()
        with self.db.tx():
            rows = self.db.all("SELECT * FROM questions WHERE status='pending' OR (status='claimed' AND lease_until<?) "
                               "ORDER BY id LIMIT ?", (clock.iso(now), max(1, min(int(limit), 20))))
            for row in rows:
                self.db.exec("UPDATE questions SET status='claimed', claimed_by=?, lease_until=? WHERE id=?",
                             (key["id"], clock.iso(now + timedelta(minutes=LEASE_MINUTES)), row["id"]))
        out = []
        for row in rows:
            try:
                item = self.engine.item_of(row["ref"])
            except Denied:  # the plugin was removed meanwhile
                self._close(row["id"], "failed", error="not_found")
                continue
            out.append({"id": row["id"], "ref": row["ref"], "question": row["question"], "read": item["read"],
                        "params": item["params"], "attachments": item["attachments"], "context": item["context"]})
        return out

    def answer(self, key: dict, qid: int, body: Any) -> dict:
        """The reader's answer ({"answer": {...}}) or why there is none ({"error": <code>})."""
        if key["role"] != "reader":
            raise Denied("only reader keys answer questions", "role")
        row = self.db.one("SELECT * FROM questions WHERE id=?", (qid,))
        if row is None:
            raise Denied("no such question", "not_found")
        if row["status"] != "claimed" or row["claimed_by"] != key["id"]:
            raise Denied("this question isn't yours to answer (any more)", "not_claimed")
        if not isinstance(body, dict) or len(body) != 1 or not ({"answer", "error"} & set(body)):
            raise Denied("send {\"answer\": {...}} or {\"error\": <code>}", "invalid")
        if "error" in body:
            if body["error"] not in ANSWER_ERRORS:
                raise Denied(f"error is one of {', '.join(ANSWER_ERRORS)}", "invalid")
            self._close(qid, "failed", error=body["error"])
        else:
            self.engine._validate(ANSWER_SCHEMA, body["answer"], "answer")
            self._close(qid, "answered", answer=body["answer"])
        return {"id": qid, "status": "answered" if "answer" in body else "failed"}

    def _close(self, qid: int, status: str, answer: dict | None = None, error: str | None = None) -> None:
        self.db.exec("UPDATE questions SET status=?, answered=?, answer=?, error=?, lease_until=NULL WHERE id=?",
                      (status, clock.iso(), dumps(answer) if answer is not None else None, error, qid))
        self.answered(self.db.one("SELECT * FROM questions WHERE id=?", (qid,)))

    def answered(self, question: dict) -> None:
        """Called once per question when the reader answered it, said why it couldn't, or nobody answered in
        time: question_answered in the asking key's feed (id, ref and status; the answer itself is fetched
        with GET /v1/questions/<id>, where it takes the third-party path)."""
        self.engine.feed.question_answered(question)

    # ------------------------------------------------------------------ housekeeping

    def sweep(self, force: bool = False) -> None:
        """At most once a minute: give up questions nobody answered in time, delete old ones."""
        if not force and clock.now().timestamp() - self._swept < 60:
            return
        self._swept = clock.now().timestamp()
        now = clock.now()
        cutoff = clock.iso(now - timedelta(minutes=EXPIRE_MINUTES))
        with self.db.tx() as conn:
            expired = [dict(r) for r in conn.execute(f"SELECT * FROM questions WHERE status IN {OPEN} AND created<?",
                                                     (cutoff,)).fetchall()]
            conn.execute(f"UPDATE questions SET status='expired' WHERE status IN {OPEN} AND created<?", (cutoff,))
        for row in expired:
            self.answered({**row, "status": "expired"})
        self.db.exec(f"DELETE FROM questions WHERE status NOT IN {OPEN} AND created<?",
                     (clock.iso(now - timedelta(days=KEEP_DAYS)),))
