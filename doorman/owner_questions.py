"""Questions an agent asks the owner (`doorman ask-owner "Tue 10:00 or Wed 14:00?" --option ... --option ...`).

When a task is unclear (which of two meetings, whether a placeholder is the dentist), the agent asks instead of
guessing or failing:

1. POST /v1/owner-questions {question, options?}: stored here (table `owner_questions`) and pushed to the
   owner ("Your agent asks"), opening the inbox. GET /owner/inbox lists the open ones under `questions`.
2. The owner answers (POST /owner/questions/<id>/answer {answer} or {option}) or dismisses it
   (POST /owner/questions/<id>/dismiss). A question nobody answered within EXPIRE_HOURS is given up. Each
   answer and dismissal is a journal entry (kind config): the owner's word went out and can't be taken back.
3. The asking key gets `owner_answered` in its event feed with the answer itself, and `doorman wait
   owner-question:<id>` follows it to the end. The answer is the owner's own text, like a task's, so it comes
   back whole and unwrapped, never as third-party content. Addresses the owner typed in it count as theirs in
   the recipient check, like the task text's (Policy.owner_answers); a tapped option doesn't: it's the agent's.

The question is the agent's text, and an agent may have been steered by something it read: the owner app
shows it as the agent's ("Your agent asks"), never as Doorman's. Placeholders the agent puts in it (an
appointment's hidden title) are turned back into the real text for the owner, who may of course see them.

Answering needs the logged-in app, not a fresh passkey check, like Deny and like writing a task. An address
in an answer does become trusted, but only as far as the task text's: for this key, for this task (or outside
a task), until the question is deleted after KEEP_DAYS, and only when the owner typed it. Every send to it
still waits for approval, unless the owner set that tool to run without asking, which is the same for an
address in a task they wrote. The trust list is different: it is permanent and for every key, so adding to it
takes a fresh check (api/owner.py, /owner/trust).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from . import clock, sanitize
from .plugin_api import Denied
from .util import dumps, loads

EXPIRE_HOURS = 24     # a question nobody answered by then is given up
OPEN_PER_KEY = 5      # questions one key may have waiting at once: the owner's inbox isn't a chat
KEEP_DAYS = 7         # answered and given-up questions are deleted after this
QUESTION_CHARS, OPTION_CHARS, ANSWER_CHARS, MAX_OPTIONS = 500, 100, 1000, 6

ASK_SCHEMA = {
    "type": "object",
    "properties": {
        "question": {"type": "string", "minLength": 3, "maxLength": QUESTION_CHARS},
        "options": {"type": "array", "maxItems": MAX_OPTIONS,
                    "items": {"type": "string", "minLength": 1, "maxLength": OPTION_CHARS}},
    },
    "required": ["question"],
    "additionalProperties": False,
}


def _clip(text: str, n: int = 80) -> str:
    return text if len(text) <= n else text[:n - 1].rstrip() + "…"


def _one_line(text: str) -> str:
    return " ".join(sanitize.clean_text(text)[0].split())


class OwnerQuestions:
    def __init__(self, engine):
        self.engine = engine
        self.db = engine.db
        self._swept = 0.0

    # ------------------------------------------------------------------ the asking agent

    def ask(self, session: dict, key: dict, body: Any) -> dict:
        engine = self.engine
        engine._guard(session, None, write=False)
        if key["role"] == "reader":
            raise Denied("reader keys don't ask the owner; they answer questions", "role")
        engine._validate(ASK_SCHEMA, body, "question")
        self.sweep()
        waiting = self.db.one("SELECT COUNT(*) AS n FROM owner_questions WHERE key_id=? AND status='open'",
                              (key["id"],))["n"]
        if waiting >= OPEN_PER_KEY:
            raise Denied(f"{waiting} of your questions to the owner are still open; wait for their answers "
                         "(doorman wait owner-question:<id>) before asking more", "too_many")
        question = _one_line(body["question"])
        options = [o for o in (_one_line(o) for o in body.get("options") or []) if o]
        if not question:
            raise Denied("the question is empty", "invalid")
        now = clock.now()
        qid = self.db.exec(
            "INSERT INTO owner_questions(key_id, session_id, task_id, question, options, status, created, expires) "
            "VALUES(?,?,?,?,?,'open',?,?)",
            (key["id"], session["id"], session.get("task_id"), question, dumps(options), clock.iso(now),
             clock.iso(now + timedelta(hours=EXPIRE_HOURS))))
        # as the agent wrote it: a placeholder's real text is for the app (open()), not for the lock screen
        # a tap opens the inbox with this question on top (app.js screens.inbox)
        engine.notifier.push(f"{key.get('name') or 'Your agent'} asks", question[:300],
                             url=f"{engine.public_url}/app/#/inbox/question/{qid}", priority=4)
        return self._view(self.db.one("SELECT * FROM owner_questions WHERE id=?", (qid,)))

    def get(self, session: dict, key: dict, qid: int) -> dict:
        self.engine._guard(session, None, write=False)
        self.sweep()
        row = self.db.one("SELECT * FROM owner_questions WHERE id=?", (qid,))
        if row is None or row["key_id"] != key["id"]:
            raise Denied("no such question to the owner", "not_found")
        return self._view(row)

    def mine(self, session: dict, key: dict, limit: int = 20) -> list[dict]:
        self.engine._guard(session, None, write=False)
        self.sweep()
        rows = self.db.all("SELECT * FROM owner_questions WHERE key_id=? ORDER BY id DESC LIMIT ?",
                           (key["id"], max(1, min(int(limit), 100))))
        return [self._view(r) for r in rows]

    @staticmethod
    def _view(row: dict) -> dict:
        """What the agent sees: its own question, and the owner's answer once there is one."""
        out = {"id": row["id"], "question": row["question"], "options": loads(row["options"], []),
               "status": row["status"], "asked": row["created"], "expires": row["expires"]}
        if row["task_id"]:
            out["task_id"] = row["task_id"]
        if row["answered"]:
            out["answered"] = row["answered"]
        if row["status"] == "answered":
            out["answer"] = row["answer"]
        return out

    # ------------------------------------------------------------------ the owner

    def open(self) -> list[dict]:
        """The owner's inbox: open questions, oldest first, each with the asking key's name and the task."""
        self.sweep()
        rows = self.db.all("SELECT q.*, k.name AS key_name FROM owner_questions q LEFT JOIN agent_keys k "
                           "ON k.id=q.key_id WHERE q.status='open' ORDER BY q.id")
        out = []
        for row in rows:
            task = self.engine.tasks.get(row["task_id"]) if row["task_id"] else None
            out.append({"id": row["id"], "question": self.engine.pseudonyms.restore(row["question"]),
                        "options": [self.engine.pseudonyms.restore(o) for o in loads(row["options"], [])],
                        "agent": row["key_name"], "asked": row["created"], "expires": row["expires"],
                        "task": {"id": task["id"], "text": task["text"], "trusted": task["trusted"],
                                 "origin": task.get("origin")} if task else None})
        return out

    def answer(self, qid: int, answer: Any = None, option: Any = None) -> dict:
        """The owner's answer: free text, or one of the options (by its number from 0, or its text)."""
        row = self._open_row(qid)
        options = loads(row["options"], [])
        if option is not None:
            if isinstance(option, int) and not isinstance(option, bool) and 0 <= option < len(options):
                answer = options[option]
            elif isinstance(option, str) and option in options:
                answer = option
            else:
                raise Denied("that isn't one of the question's options", "invalid")
        text = sanitize.clean_text(answer if isinstance(answer, str) else "")[0].strip()
        if not text:
            raise Denied("give an answer, or dismiss the question", "invalid")
        if len(text) > ANSWER_CHARS:
            raise Denied(f"answers are at most {ANSWER_CHARS} characters", "invalid")
        return self._close(row, "answered", text)

    def dismiss(self, qid: int) -> dict:
        return self._close(self._open_row(qid), "dismissed")

    def _open_row(self, qid: int) -> dict:
        self.sweep()
        row = self.db.one("SELECT * FROM owner_questions WHERE id=?", (qid,))
        if row is None:
            raise Denied("no such question", "not_found")
        if row["status"] != "open":
            raise Denied(f"this question is {row['status']} already", "invalid")
        return row

    def _close(self, row: dict, status: str, answer: str | None = None) -> dict:
        with self.db.tx() as conn:
            changed = conn.execute("UPDATE owner_questions SET status=?, answer=?, answered=? WHERE id=? AND "
                                   "status='open'", (status, answer, clock.iso(), row["id"])).rowcount
        if not changed:
            raise Denied("this question was closed meanwhile", "invalid")
        row = self.db.one("SELECT * FROM owner_questions WHERE id=?", (row["id"],))
        self._journal(row)
        self.engine.feed.owner_answered(row)
        return self._view(row)

    def _journal(self, row: dict) -> None:
        """The owner's answer or dismissal goes in the journal like their other decisions: it reached the agent
        and can't be taken back, and an answer's addresses now count as the owner's (Policy.owner_answers)."""
        key = self.db.one("SELECT name FROM agent_keys WHERE id=?", (row["key_id"],)) or {}
        asked = f"{key.get('name') or 'the agent'}'s question “{_clip(self.engine.pseudonyms.restore(row['question']))}”"
        answered = row["status"] == "answered"
        self.engine.journal.create(
            kind="config", tool="owner_question.answer" if answered else "owner_question.dismiss",
            tier="irreversible", decision="run", status="done", task_id=row["task_id"],
            args={"question_id": row["id"]},
            summary=f"Answered {asked}: {_clip(row['answer'])}" if answered else f"Dismissed {asked}")

    # ------------------------------------------------------------------ housekeeping

    def sweep(self, force: bool = False) -> None:
        """At most once a minute: give up questions nobody answered in time (the agent hears `expired`),
        delete old ones."""
        if not force and clock.now().timestamp() - self._swept < 60:
            return
        self._swept = clock.now().timestamp()
        now = clock.iso()
        with self.db.tx() as conn:
            expired = [dict(r) for r in conn.execute("SELECT * FROM owner_questions WHERE status='open' AND "
                                                     "expires<?", (now,)).fetchall()]
            conn.execute("UPDATE owner_questions SET status='expired' WHERE status='open' AND expires<?", (now,))
        for row in expired:
            self.engine.feed.owner_answered({**row, "status": "expired"})
        self.db.exec("DELETE FROM owner_questions WHERE status!='open' AND created<?",
                     (clock.iso(clock.now() - timedelta(days=KEEP_DAYS)),))
