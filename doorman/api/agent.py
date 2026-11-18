"""The agent API: reads, write tools, changesets, tasks, records. Bearer token per agent key."""

import difflib
import json
import threading
import time
from pathlib import Path
from urllib.parse import unquote
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response

from .. import agenda, caps, recent, sanitize
from ..agent_setup import READS as SETUP_READS, TOOLS as SETUP_TOOLS
from ..caps import brief_caps, may_ask, one_line  # noqa: F401 - one_line: imported from here by tests
from ..engine import KEY_PAUSED, PAUSED, Engine
from ..search import SEARCH_SCHEMA
from ..feed import MAX_WAIT, RECHECK_SECONDS
from ..plugin_api import Denied
from ..sends import checking
from ..spotlight import unmark
from . import errors
from .mcp import mount_mcp

# calls that only wait for news don't keep a task's lease alive: a hung agent's background loop mustn't
LEASE_IDLE_PATHS = ("/v1/events", "/v1/wait", "/v1/status")
UPLOADS_IN_FLIGHT = 2  # per key
# while the owner has paused Doorman, only the capabilities answer: they say `paused`, so `doorman caps` and
# a reader can tell a pause from a broken key
OPEN_WHILE_PAUSED = ("/v1/capabilities",)
# how `doorman wait` names what it follows, and the outcomes that end the wait (feed.py has the events)
WAIT_KINDS = ("entry", "changeset", "question", "owner-question", "egress-request")
ENTRY_OUTCOMES = {"done": "done", "failed": "failed", "unknown": "unknown", "rejected": "declined",
                  "expired": "expired", "cancelled": "cancelled", "reverted": "reverted", "denied": "denied"}
CHANGESET_OUTCOMES = {"applied": "applied", "partially_applied": "partly", "rejected": "declined"}
REVOKED = ("missing or revoked agent key: stop and tell the owner; a new key comes from the owner app (More → "
           "Agents), there is no other way in")
QUESTION_OUTCOMES = {"answered": "answered", "failed": "failed", "expired": "expired"}
OWNER_QUESTION_OUTCOMES = {"answered": "answered", "dismissed": "declined", "expired": "expired"}
EGRESS_OUTCOMES = {"granted": "granted", "denied": "denied", "expired": "expired"}
PROXY_ONLY = ("this is the network proxy's API: it takes the proxy token from the owner app (More → Network), "
              "never an agent key")
# doorman status: an action of the agent's that hasn't ended yet (waiting for the owner, going out) or a send
# whose end Doorman is still checking (`unknown` with checking())
OPEN_ENTRY_STATUSES = ("waiting_approval", "approved", "sending", "unknown")


def create_agent_app(engine: Engine) -> FastAPI:
    app = FastAPI(title="Doorman: agent API", version="1", docs_url="/docs", redoc_url=None)
    errors.install(app, hide=engine.pseudonyms.text)

    def caller(request: Request, authorization: str | None = Header(None),
               x_doorman_session: str | None = Header(None)) -> tuple[dict, dict]:
        token = authorization.split(" ", 1)[1] if authorization and authorization.lower().startswith("bearer ") else None
        key = engine.auth.key_from_token(token)
        if key is None:
            raise Denied(REVOKED, "unauthenticated")
        engine.auth.touch(key)
        # the network proxy knows a connection only by its source address: this key is the one calling from it
        engine.egress.client_seen(request.client.host if request.client else None, key["id"])
        if engine.killed() and not request.url.path.startswith(OPEN_WHILE_PAUSED):
            raise Denied(PAUSED, "paused")  # every call, task reports and the event feed included
        if engine.auth.paused(key["id"]) and not request.url.path.startswith(OPEN_WHILE_PAUSED):
            raise Denied(KEY_PAUSED, "key_paused")  # this key only: a honeytoken, a decoy key or a leak
        session = engine.auth.session_for(key, x_doorman_session)
        if session["task_id"] and request.url.path not in LEASE_IDLE_PATHS:
            engine.tasks.renew_lease(session)  # working on a task: every call keeps its lease alive
        return key, session

    def answering(fn):
        """`fn` as an agent's call: scans it needs answer `busy` after guard.answer_seconds instead of
        holding the call past the agent's own timeout (guard.py)."""
        def call(*args, **kwargs):
            with engine.guard.answer_within():
                return fn(*args, **kwargs)
        return call

    def key_sessions(key: dict) -> set[str]:
        return {r["id"] for r in engine.db.all("SELECT id FROM sessions WHERE key_id=?", (key["id"],))}

    @app.get("/health")
    def health():
        """No login: for Docker's healthcheck. Says nothing beyond up/down and timings."""
        ok, body = engine.health()
        return JSONResponse(body, status_code=200 if ok else 503)

    SKILL_DIR = Path(__file__).resolve().parent.parent / "agent_skill"
    SKILL_FILES = {"SKILL.md": "text/markdown; charset=utf-8", "scripts/doorman.py": "text/x-python; charset=utf-8"}

    @app.get("/v1/skill/{path:path}")
    def skill_file(path: str, authorization: str | None = Header(None)):
        """The doorman skill, so an agent can install it with nothing but its key."""
        token = authorization.split(" ", 1)[1] if authorization and authorization.lower().startswith("bearer ") else None
        if engine.auth.key_from_token(token) is None:
            raise Denied(REVOKED, "unauthenticated")
        if path not in SKILL_FILES:
            raise Denied("no such skill file", "not_found")
        return Response((SKILL_DIR / path).read_bytes(), media_type=SKILL_FILES[path])

    def caps_for(key: dict, session: dict, off: dict | None = None) -> dict:
        return caps.caps_for(engine, key, session, off)

    app.state.engine = engine

    @app.get("/v1/capabilities")
    def capabilities(brief: bool = False, who=Depends(caller)):
        """Everything with full parameter schemas, or with brief=true one line per read and tool (doorman caps
        --brief). `version` changes whenever what this returns changes, so an agent can keep a copy."""
        key, session = who
        off: dict = {}
        caps = caps_for(key, session, off)
        return brief_caps(caps, off) if brief else caps

    @app.get("/v1/capabilities/{name}")
    def capability(name: str, who=Depends(caller)):
        """One read or tool with its whole parameter schema (doorman help <name>)."""
        key, session = who
        caps = caps_for(key, session)
        if name == "search":
            return {"name": "search", "kind": "read", "description": "One search over everything searchable: "
                    "mail archives, files, notes, calendars, chats (doorman search). Best first, each hit with "
                    "its passage; sort=date for the newest first", "params": SEARCH_SCHEMA,
                    "sources": caps["search"]["sources"]}
        if name == "agenda":
            return {"name": "agenda", "kind": "read", "description": agenda.__doc__.split("\n\n")[0],
                    "params": agenda.AGENDA_SCHEMA, "sources": caps["agenda"]["sources"]}
        if name == "recent":
            return {"name": "recent", "kind": "read", "description": recent.__doc__.split("\n\n")[0],
                    "params": recent.RECENT_SCHEMA, "sources": caps["recent"]["sources"]}
        for plugin in caps["plugins"]:
            for kind in ("reads", "tools"):
                for entry in plugin[kind]:
                    if entry["name"] == name:
                        extra = {"may_ask": may_ask(entry)} if entry.get("can_send") else {}
                        return {"kind": kind[:-1], "plugin": plugin["name"], **entry, **extra,
                                "version": caps["version"]}
        everything = [e["name"] for p in caps["plugins"] for kind in ("reads", "tools") for e in p[kind]]
        close = difflib.get_close_matches(name, everything + ["search", "agenda", "recent"], n=3, cutoff=0.6)
        raise Denied(f"no read or tool {name} here" + (f"; did you mean {' or '.join(close)}?" if close else
                                                       "; doorman caps --brief lists them"), "not_found")

    def task_arg(body: dict, session: dict) -> None:
        """A request may name a task only if it's the one this session is working on."""
        requested = body.get("task_id")
        if requested is not None and requested != session["task_id"]:
            raise Denied("this session isn't working on that task; claim it first", "session")

    @app.post("/v1/sessions")
    def new_session(who=Depends(caller)):
        key, session = who
        if session["task_id"]:
            raise Denied(f"finish task #{session['task_id']} first", "task_active")
        return {"session": engine.auth.new_session(key)["id"]}

    @app.post("/v1/read/{name}")
    async def read(name: str, request: Request, who=Depends(caller)):
        key, session = who
        body = unmark(_object(await _json(request)))
        params = body.get("params", body)
        if name in SETUP_READS:  # Doorman's own setup (agent_setup.py)
            data = await run_in_threadpool(engine.setup.read, session, key, name)
            return engine.spotlit(session, name, data, trust="owner")
        if name == "search":  # the common search over every searchable source
            data = await run_in_threadpool(answering(engine.search.any_word), session, key, _object(params))
            return engine.spotlit(session, name, data, trust="third_party")
        if name == "agenda":  # every calendar's entries in one list (agenda.py)
            data = await run_in_threadpool(answering(agenda.run), engine, session, key, _object(params))
            return engine.spotlit(session, name, data, trust="third_party")
        if name == "recent":  # what's new across mail and chats in one list (recent.py)
            data = await run_in_threadpool(answering(recent.run), engine, session, key, _object(params))
            return engine.spotlit(session, name, data, trust="third_party")
        data = await run_in_threadpool(answering(engine.read), session, key, name, _object(params))
        return engine.spotlit(session, name, data)

    @app.get("/v1/events")
    async def events(after: int | None = None, limit: int = 50, wait: float = 0, peek: bool = False,
                     only: str | None = None, wake: str | None = None, who=Depends(caller)):
        """What happened: plugin events (`events`: new mail, a message, an entry starting soon; third-party,
        spotlit) and Doorman's own for this key (`doorman`: an approval decided, a send's result, a task...).

        Doorman keeps a cursor per key (feed.py). Without `after` the batch starts after it. With `after=N`
        it starts after N, and everything up to N counts as acknowledged: the cursor moves to N (never back).
        So pass the `cursor` of each answer as `after` next time; after a restart, leave `after` out and the
        last batch you didn't acknowledge comes again. `peek=true` acknowledges nothing; `only=doorman` leaves
        plugin events out and acknowledges nothing either. With `wait` (at most 60 s) the request holds on
        until there is something, and wakes as soon as an event comes in. Every answer has the `cursor` and
        `watch`: when each plugin was last asked for events (engine.watch_status).

        `wake` (with `wait`): hold on until an event of these types comes, comma-separated, `incoming` for
        anything from outside (every plugin event, task_created, reminder_due). The answer still has every
        event since the cursor, the agent's own approval news too, so nothing is skipped; `woke` says whether
        one of those types is among them. Without it, any event ends the wait."""
        key, session = who
        if (after is not None and after < 0) or not 0 <= limit <= 200 or only not in (None, "doorman"):
            raise Denied("after is an event id (0 for the oldest kept); limit is 0 to 200; only is doorman",
                         "invalid")
        woken_by = wake_types(wake)
        if after is None:
            after = await run_in_threadpool(engine.feed.cursor, key)
        elif not peek and only is None:
            await run_in_threadpool(engine.feed.ack, key, after)
        deadline = time.monotonic() + max(0.0, min(float(wait), MAX_WAIT))
        while True:
            seen = engine.feed.bell.generation
            feed = await run_in_threadpool(answering(engine.event_feed), session, key, after, limit, only == "doorman")
            left = deadline - time.monotonic()
            news = feed["events"] or feed["doorman"]
            if woken_by is not None:
                feed["woke"] = woke(feed, woken_by)
                # a full batch of other news: hand it over rather than wait behind it
                news = feed["woke"] or (news and feed["more"])
            if news or limit == 0 or left <= 0:
                break
            # woken by the next insert; RECHECK_SECONDS catches what another process (doorman-admin) added
            await engine.feed.bell.wait(seen, min(RECHECK_SECONDS, left))
            session = engine.auth.get_session(session["id"])  # ended meanwhile: _guard refuses the next round
        # when each plugin was last asked, so "nothing new" says how fresh it is
        feed["watch"] = engine.watch_status() if limit else {}
        if not feed["events"]:  # nothing third-party in it: no notice to wrap around nothing
            return feed
        out = engine.spotlit(session, "events", feed.pop("events"), trust="third_party")
        return {**out, "events": out.pop("data"), **feed}

    def wait_state(key: dict, session: dict, kind: str, item_id: int) -> dict:
        """Where one action stands: {for, outcome, done, <kind>: its view}. An edited send is followed to
        the version that replaced it."""
        if kind == "entry":
            mine = key_sessions(key)
            for _ in range(20):  # superseded by an edit: the edit is what the agent's send became
                entry = engine.journal.get(item_id)
                if entry is None or entry["session_id"] not in mine:
                    raise Denied("no such entry", "not_found")
                follow = (entry["result"] or {}).get("superseded_by") if entry["status"] == "superseded" else None
                if not follow:
                    break
                item_id = follow
            view = _entry_for_agent(entry, engine)
            note = engine.approvals.deny_note(item_id) if entry["status"] == "rejected" else None
            if note:
                view["note"] = note
            outcome = ENTRY_OUTCOMES.get(entry["status"])
            if outcome == "done" and entry["tier"] != "reversible":
                outcome = "sent"
            state = {"for": f"entry:{item_id}", "outcome": outcome or entry["status"], "done": outcome is not None,
                     "entry": view}
            if checking(entry):  # unknown for now: Doorman checks itself, and a later send_result says
                state["checking"] = True
            return state
        if kind == "changeset":
            cs = engine.changeset(item_id)
            if cs is None or cs["session_id"] not in key_sessions(key):
                raise Denied("no such changeset", "not_found")
            outcome = CHANGESET_OUTCOMES.get(cs["status"])
            return {"for": f"changeset:{item_id}", "outcome": outcome or cs["status"], "done": outcome is not None,
                    "changeset": _changeset_for_agent(cs, engine)}
        if kind == "egress-request":  # the owner's decision on network access (egress/service.py)
            asked = engine.egress.get_request(session, key, item_id)
            outcome = EGRESS_OUTCOMES.get(asked["status"])
            return {"for": f"egress-request:{item_id}", "outcome": outcome or asked["status"],
                    "done": outcome is not None, "egress_request": asked}
        if kind == "owner-question":  # the owner's answer is their own text: no spotlight
            asked = engine.owner_questions.get(session, key, item_id)
            outcome = OWNER_QUESTION_OUTCOMES.get(asked["status"])
            return {"for": f"owner-question:{item_id}", "outcome": outcome or asked["status"],
                    "done": outcome is not None, "owner_question": asked}
        question = engine.questions.get(session, key, item_id)
        outcome = QUESTION_OUTCOMES.get(question["status"])
        return {"for": f"question:{item_id}", "outcome": outcome or question["status"], "done": outcome is not None,
                "question": question}

    @app.get("/v1/wait")
    async def wait_for(target: str = Query(..., alias="for"), wait: float = 0, who=Depends(caller)):
        """doorman wait: follow one action to its end. `for` is entry:<id> (or a bare id), changeset:<id>,
        question:<id> (the reader's answer), owner-question:<id> (the owner's) or egress-request:<id> (the
        owner's decision on network access: granted, denied or expired). Answers at once when it has ended,
        else holds on up to `wait` seconds (at most 60) and answers when it ends: `done` says which. Woken by
        the same events as the feed; acknowledges nothing."""
        key, session = who
        kind, _, number = target.rpartition(":")
        kind = kind or "entry"
        if kind not in WAIT_KINDS or not number.isdigit():
            raise Denied("for is entry:<id>, changeset:<id>, question:<id>, owner-question:<id> or "
                         "egress-request:<id>", "invalid")
        deadline = time.monotonic() + max(0.0, min(float(wait), MAX_WAIT))
        while True:
            seen = engine.feed.bell.generation
            state = await run_in_threadpool(wait_state, key, session, kind, int(number))
            left = deadline - time.monotonic()
            if state["done"] or left <= 0:
                break
            await engine.feed.bell.wait(seen, min(RECHECK_SECONDS, left))
        if kind == "question" and state["outcome"] == "answered":  # the answer is third-party-derived
            wrapped = engine.spotlit(session, "questions", state.pop("question"), trust="third_party")
            return {**state, **wrapped, "question": wrapped.pop("data")}
        return state

    uploading: dict[int, int] = {}  # uploads in flight per key
    uploading_lock = threading.Lock()

    @app.post("/v1/uploads")
    async def upload(request: Request, x_filename: str | None = Header(None), who=Depends(caller)):
        """A file the agent made, as the raw request body; X-Filename (percent-encoded) names it. Returns
        upload:<sha256> to attach to a draft or send, or to keep with files.save."""
        key, session = who
        limit = int(float((engine.config.get("uploads") or {}).get("max_mb", 25)) * 1024 * 1024)
        with uploading_lock:  # a few at a time per key: parallel uploads mustn't fill this small box's memory
            if uploading.get(key["id"], 0) >= UPLOADS_IN_FLIGHT:
                raise Denied(f"at most {UPLOADS_IN_FLIGHT} uploads at a time per key; send the next when one is "
                             "done", "busy")
            uploading[key["id"]] = uploading.get(key["id"], 0) + 1
        try:
            body, size = bytearray(), 0
            async for chunk in request.stream():
                size += len(chunk)
                if size > limit:
                    raise Denied(f"uploads are at most {limit // (1024 * 1024)} MB", "too_large")
                body += chunk
            return await run_in_threadpool(engine.upload, session, key, unquote(x_filename or ""), bytes(body))
        finally:
            with uploading_lock:
                uploading[key["id"]] -= 1

    @app.post("/v1/tools/{name}")
    async def call(name: str, request: Request, who=Depends(caller)):
        key, session = who
        body = unmark(_object(await _json(request)))
        task_arg(body, session)
        if name in SETUP_TOOLS:  # Doorman's own setup (agent_setup.py)
            return await run_in_threadpool(engine.setup.call, session, key, name, _object(body.get("args", {})))
        result = await run_in_threadpool(engine.call_tool, session, key, name, _object(body.get("args", {})))
        if "summary" in result:
            result["summary"] = engine.redactor.text(result["summary"] or "")
        # a write's result can carry text from outside (a sync's output): no invisible or look-alike characters
        result = sanitize.clean_value(result)[0]
        return engine.for_agent(result, name.split(".", 1)[0])

    @app.post("/v1/changesets")
    def propose(body: dict = Body(...), who=Depends(caller)):
        key, session = who
        body = unmark(body)
        task_arg(body, session)
        cs = engine.propose_changeset(session, key, str(body.get("title") or "Changes"), body.get("actions", []))
        return _changeset_for_agent(cs, engine)

    @app.get("/v1/changesets/{changeset_id}")
    def get_changeset(changeset_id: int, who=Depends(caller)):
        key, _ = who
        cs = engine.changeset(changeset_id)
        if cs is None or cs["session_id"] not in key_sessions(key):
            raise Denied("no such changeset", "not_found")
        return _changeset_for_agent(cs, engine)

    @app.get("/v1/journal")
    def journal(task_id: int | None = None, since: str | None = None, limit: int = 50, who=Depends(caller)):
        key, _ = who
        mine = key_sessions(key)
        entries = engine.journal.list(task_id=task_id, since=since, limit=500, include_denied=True)
        out = [_entry_for_agent(e, engine) for e in entries if e["session_id"] in mine]
        return {"entries": out[:limit]}

    @app.post("/v1/journal/{entry_id}/undo")
    def undo(entry_id: int, who=Depends(caller)):
        """doorman undo <entry>: revert a reversible change this key made (engine.agent_undo)."""
        key, session = who
        return engine.agent_undo(session, key, entry_id=entry_id)

    @app.post("/v1/undo")
    def undo_task(body: dict = Body(...), who=Depends(caller)):
        """doorman undo --task <id>: every reversible change this key made for that task."""
        key, session = who
        task_id = body.get("task_id") if isinstance(body, dict) else None
        if not isinstance(task_id, int) or isinstance(task_id, bool):
            raise Denied("give task_id, or undo one entry with POST /v1/journal/<id>/undo", "invalid")
        return engine.agent_undo(session, key, task_id=task_id)

    @app.get("/v1/journal/{entry_id}")
    def journal_entry(entry_id: int, who=Depends(caller)):
        key, session = who
        entry = engine.journal.get(entry_id)
        if entry is None or entry["session_id"] not in key_sessions(key):
            raise Denied("no such entry", "not_found")
        out = _entry_for_agent(entry, engine)
        note = engine.approvals.deny_note(entry_id) if entry["status"] == "rejected" else None
        if note:
            out["note"] = note  # the owner's word on the Deny
        # doorman status: also whether the agent's copy of the capabilities is still current
        return {**out, "caps_version": caps_for(key, session)["version"]}

    @app.get("/v1/status")
    def open_items(who=Depends(caller)):
        """doorman status without an id: what this key has open, in one answer. `approvals`: its writes that
        wait for the owner (or were approved and are going out); `checking`: sends that broke off and that
        Doorman checks itself; `owner_questions`: its questions the owner hasn't answered; `task`: the task
        this session works on, with its lease; `egress_requests`: its requests for network access the owner
        hasn't decided. Doesn't renew the lease (LEASE_IDLE_PATHS)."""
        key, session = who
        mine = key_sessions(key)
        entries = [e for e in engine.journal.list(status=OPEN_ENTRY_STATUSES, kinds=("action",), limit=500)
                   if e["session_id"] in mine]

        def brief(entry: dict) -> dict:
            view = _entry_for_agent(entry, engine)
            return {k: view[k] for k in ("id", "ts", "tool", "status", "summary", "task_id", "changeset_id")
                    if view.get(k) is not None}

        task = engine.tasks.get(session["task_id"]) if session["task_id"] else None
        return {"approvals": [brief(e) for e in entries if e["status"] != "unknown"],
                "checking": [brief(e) for e in entries if e["status"] == "unknown" and checking(e)],
                "owner_questions": [q for q in engine.owner_questions.mine(session, key, 100)
                                    if q["status"] == "open"],
                "egress_requests": [r for r in engine.egress.my_requests(session, key, 100) if r["status"] == "open"],
                "task":({**_task_for_agent(task, engine), "lease_until": task["lease_until"]}
                         if task and task["status"] == "claimed" else None)}

    @app.get("/v1/tasks")
    def tasks(who=Depends(caller)):
        key, _ = who
        return {"tasks": [_task_for_agent(t, engine) for t in engine.tasks.for_key(key)]}

    @app.post("/v1/tasks/claim")
    def claim(body: dict = Body(default={}), who=Depends(caller)):
        key, _ = who
        claimed = engine.tasks.claim(key, body.get("task_id") if isinstance(body, dict) else None)
        if claimed is None:
            return {"task": None}
        task, session = claimed
        # a task may limit plugins or make the session read-only: its capabilities can differ from the key's
        return {"task": _task_for_agent(task, engine), "session": session["id"],
                "caps_version": caps_for(key, session)["version"]}

    @app.post("/v1/tasks/{task_id}/report")
    def report(task_id: int, body: dict = Body(...), who=Depends(caller)):
        key, session = who
        body = unmark(body)
        return engine.tasks.report(session, task_id, body.get("status", "done"), body.get("summary") or "", key)

    @app.post("/v1/tasks/{task_id}/renew")
    def renew(task_id: int, body: dict = Body(default={}), who=Depends(caller)):
        """Push the task's lease out (task_lease_minutes, or `minutes` up to 240) for a long job between
        calls. Any other call renews it too."""
        _, session = who
        minutes = body.get("minutes") if isinstance(body, dict) else None
        return engine.tasks.renew_lease(session, task_id, minutes, explicit=True)

    @app.post("/v1/records")
    def put_record(record: dict = Body(...), who=Depends(caller)):
        key, session = who
        return {"id": engine.put_record(session, key, unmark(record))}

    @app.get("/v1/records")
    def records(source: str | None = None, category: str | None = None, limit: int = 50,
                sender: str | None = Query(None, alias="from"), since: str | None = None, until: str | None = None,
                text: str | None = None, who=Depends(caller)):
        """source: a plugin (mail), a ref, or a ref's start ending in *; from and text: words in the sender
        and the summary; since/until: YYYY-MM-DD."""
        key, session = who
        found = answering(engine.list_records)(session, key, source, category, limit, sender=sender, since=since,
                                               until=until, text=text)
        out = engine.spotlit(session, "records", found, trust="third_party")
        return {**out, "records": out.pop("data")}

    @app.get("/v1/meta")
    def meta(ref: str, who=Depends(caller)):
        """One item's structural fields (ids, addresses, attachment parts, timestamps) without its text; actor
        keys may ask too (structure.py)."""
        key, session = who
        return engine.spotlit(session, "meta", engine.meta(session, key, ref), trust="third_party")

    @app.post("/v1/questions")
    def ask(body: dict = Body(...), who=Depends(caller)):
        """Ask the reader about one item: {ref, question}. Poll GET /v1/questions/<id> for the answer."""
        key, session = who
        return {"question": engine.questions.ask(session, key, unmark(body))}

    @app.get("/v1/questions")
    def my_questions(limit: int = 20, who=Depends(caller)):
        key, session = who
        return {"questions": engine.questions.mine(session, key, limit)}

    @app.get("/v1/questions/{qid}")
    def question(qid: int, who=Depends(caller)):
        """The question and, once the reader answered, its answer: third-party-derived, so spotlighted."""
        key, session = who
        out = engine.questions.get(session, key, qid)
        if "answer" not in out:
            return {"question": out}
        wrapped = engine.spotlit(session, "questions", out, trust="third_party")
        return {**wrapped, "question": wrapped.pop("data")}

    @app.post("/v1/owner-questions")
    def ask_owner(body: dict = Body(...), who=Depends(caller)):
        """Ask the owner (doorman ask-owner): {question, options?}. It goes to their inbox with a push; the
        answer comes as owner_answered in the feed, or with doorman wait owner-question:<id>."""
        key, session = who
        return {"owner_question": engine.owner_questions.ask(session, key, unmark(body))}

    @app.get("/v1/owner-questions")
    def my_owner_questions(limit: int = 20, who=Depends(caller)):
        key, session = who
        return {"owner_questions": engine.owner_questions.mine(session, key, limit)}

    @app.get("/v1/owner-questions/{qid}")
    def owner_question(qid: int, who=Depends(caller)):
        key, session = who
        return {"owner_question": engine.owner_questions.get(session, key, qid)}

    @app.get("/v1/reader/questions")
    async def reader_questions(wait: float = 0, limit: int = 5, who=Depends(caller)):
        """doorman-reader: questions waiting for an answer, each leased to this key for a few minutes. With
        `wait` (at most 60 seconds) it holds the request until there is one, so questions are answered within
        seconds instead of at the reader's next round."""
        key, _ = who
        deadline = time.monotonic() + max(0.0, min(float(wait), MAX_WAIT))
        while True:
            seen = engine.feed.bell.generation
            found = await run_in_threadpool(engine.questions.claim, key, limit)
            left = deadline - time.monotonic()
            if found or left <= 0:
                return {"questions": found}
            await engine.feed.bell.wait(seen, min(RECHECK_SECONDS, left))  # ask() rings the bell

    @app.post("/v1/reader/questions/{qid}/answer")
    def answer_question(qid: int, body: dict = Body(...), who=Depends(caller)):
        key, _ = who
        return engine.questions.answer(key, qid, unmark(body))

    @app.post("/v1/reader/round")
    def reader_round(body: dict = Body(...), who=Depends(caller)):
        key, _ = who
        return engine.reader_round(key, body if isinstance(body, dict) else {})

    @app.post("/v1/reminders")
    def reminder(body: dict = Body(...), who=Depends(caller)):
        _, session = who
        body = unmark(body)
        return {"task_id": engine.tasks.remind(session, body.get("when"), body.get("text"))}

    # ---------------------------------------------------------------- network watch (egress/service.py)

    @app.post("/v1/egress/requests")
    def request_network(body: dict = Body(...), who=Depends(caller)):
        """Ask the owner for network access (doorman egress request): {target, reason}. The decision comes as
        egress_decided in the feed, or with doorman wait egress-request:<id>."""
        key, session = who
        return {"egress_request": engine.egress.request_access(session, key, unmark(body))}

    @app.get("/v1/egress/requests")
    def my_network_requests(limit: int = 20, who=Depends(caller)):
        key, session = who
        return {"egress_requests": engine.egress.my_requests(session, key, limit)}

    @app.get("/v1/egress/requests/{rid}")
    def network_request(rid: int, who=Depends(caller)):
        key, session = who
        return {"egress_request": engine.egress.get_request(session, key, rid)}

    @app.get("/v1/egress/blocked")
    def blocked(limit: int = 20, who=Depends(caller)):
        """What the proxy blocked for this key lately, newest first (doorman egress blocked)."""
        key, _ = who
        return {"blocked": engine.egress.blocked_recent(key, limit)}

    @app.post("/v1/activity")
    def activity(body: dict = Body(...), who=Depends(caller)):
        """A tool call starting or ending, from the agent's hooks (doorman activity), so the owner sees which
        call made which connection."""
        key, session = who
        return engine.egress.activity(session, key, body)

    def proxy_caller(authorization: str | None = Header(None)) -> bool:
        """The network proxy, with its own token (never an agent key, and the proxy's token opens nothing
        else). Works while Doorman is paused: the proxy keeps blocking and logging then."""
        token = authorization.split(" ", 1)[1] if authorization and authorization.lower().startswith("bearer ") else None
        if not engine.egress.token_ok(token):
            raise Denied(PROXY_ONLY, "unauthenticated")
        return True

    @app.get("/v1/egress/proxy/policy", dependencies=[Depends(proxy_caller)])
    def proxy_policy():
        return engine.egress.policy(seen=True)

    @app.post("/v1/egress/proxy/check", dependencies=[Depends(proxy_caller)])
    async def proxy_check(body: dict = Body(...)):
        """Waits (CHECK_WAIT at most, without holding a thread) for the reads queued before it to be
        fingerprinted; still behind then: `unknown` (the proxy treats it like Doorman being down)."""
        flushed = await engine.egress.wait_flushed() if isinstance(body, dict) and body.get("prints") else True
        return await run_in_threadpool(engine.egress.check, body, flushed)

    @app.post("/v1/egress/proxy/log", dependencies=[Depends(proxy_caller)])
    def proxy_log(body: dict = Body(...)):
        return {"ok": engine.egress.ingest(body.get("records"))}

    @app.post("/v1/egress/proxy/status", dependencies=[Depends(proxy_caller)])
    def proxy_status(body: dict = Body(...)):
        engine.egress.proxy_status(body)
        return {"ok": True}

    @app.get("/v1/egress/proxy/decoys", dependencies=[Depends(proxy_caller)])
    def proxy_decoys():
        """The decoy keys' file for the agent's container: {version, filename, content}; content null (and
        version "off") while the owner has them switched off. Only ever to the proxy's token."""
        return engine.egress.decoys_file()

    @app.post("/v1/egress/proxy/tripwire", dependencies=[Depends(proxy_caller)])
    def proxy_tripwire(body: dict = Body(...)):
        """The observer saw the decoy file (or its folder) touched: {client_ip, event, path, ts}."""
        return engine.egress.tripwire(body)

    mount_mcp(app)  # the same API for agents that speak MCP: POST /mcp (mcp.py)
    return app


# `wake=incoming`: what comes in from outside. Every plugin event counts (new mail, a message, an invitation,
# an entry starting soon...); of Doorman's own, only a new task or a due reminder.
INCOMING = ("task_created", "reminder_due")


def wake_types(wake: str | None) -> set[str] | None:
    """The event types `wake` names (None: any event wakes). `incoming` stands for INCOMING and every plugin
    event; the rest are type names as the feed has them (feed.TYPES, a plugin's events in doorman caps)."""
    if wake is None:
        return None
    types = {t.strip() for t in wake.split(",") if t.strip()}
    if not types or any(len(t) > 60 or not t.replace("_", "").replace("-", "").isalnum() for t in types):
        raise Denied("wake is a comma-separated list of event types, or incoming", "invalid")
    return types


def woke(feed: dict, types: set[str]) -> bool:
    """Whether the batch has an event of one of these types (`incoming`: any plugin event, a new task)."""
    incoming = "incoming" in types
    return (any(incoming or e.get("type") in types for e in feed["events"])
            or any(e.get("type") in types or (incoming and e.get("type") in INCOMING) for e in feed["doorman"]))


async def _json(request: Request) -> Any:
    raw = await request.body()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except ValueError:
        raise Denied("request body must be JSON", "invalid") from None


def _object(value: Any) -> dict:
    if not isinstance(value, dict):
        raise Denied("expected a JSON object", "invalid")
    return value


def _entry_for_agent(entry: dict, engine: Engine) -> dict:
    keys = ("id", "ts", "kind", "task_id", "changeset_id", "tool", "tier", "decision", "status", "summary",
            "result", "error", "reverted_by")
    out = {k: entry.get(k) for k in keys}
    if out["status"] == "rejected":
        out["status"] = "declined"  # the owner's no has one name for agents (SKILL.md); `denied` is Doorman's
    # only the private values become placeholders: when, which tool and what happened stay readable
    plugin_type, states = engine.plugin_type(entry.get("plugin")), [entry.get("before"), entry.get("after")]
    out["summary"] = engine.pseudonyms.summary(engine.redactor.text(out["summary"] or ""), states, plugin_type)
    if out["error"]:
        out["error"] = engine.pseudonyms.summary(str(out["error"]), states, plugin_type)
    if out["result"] is not None:
        out["result"] = engine.for_agent(out["result"], entry.get("plugin"))
    if out["kind"] in ("action", "revert") and out["status"] == "done":
        out["undo"] = ("can't: it left Doorman (a send)" if out["tier"] != "reversible" else
                       "the owner's: they approved it" if out["decision"] == "approval" else
                       f"doorman undo {out['id']}")
    return out


def _task_for_agent(task: dict, engine: Engine) -> dict:
    out = {k: task.get(k) for k in ("id", "text", "origin", "trusted", "due", "status", "source_ref")}
    # the owner's own tasks and routines say what they mean; tasks a trigger built from a mail or an event
    # (or an agent's reminder) carry third-party text
    if (task.get("origin") or "owner") != "owner" and not str(task.get("origin")).startswith("routine:"):
        out["text"] = engine.pseudonyms.text(out["text"] or "")
    return out


def _changeset_for_agent(cs: dict, engine: Engine) -> dict:
    # each action's preview and result under its own plugin's rules ("Dr." counts in a calendar's titles)
    tools = [str(a.get("tool") or "") if isinstance(a, dict) else "" for a in cs.get("actions") or []]

    def plugin(index: Any) -> str | None:
        ok = isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(tools)
        return (tools[index].split(".", 1)[0] or None) if ok else None

    out = engine.for_agent({"id": cs["id"], "title": cs["title"], "comment": cs["comment"],
                            "status": "declined" if cs["status"] == "rejected" else cs["status"]})
    result = cs["result"]
    if isinstance(result, dict) and isinstance(result.get("results"), list):
        results = [engine.for_agent(r, plugin(r.get("index")) if isinstance(r, dict) else None)
                   for r in result["results"]]
        result = {**engine.for_agent({k: v for k, v in result.items() if k != "results"}), "results": results}
    else:
        result = engine.for_agent(result)
    out["result"] = result
    # no diff: it's built from snapshots of third-party data the agent may not be allowed to read
    out["preview"] = [engine.for_agent({k: p.get(k) for k in ("index", "tool", "summary", "tier", "decision",
                                                                "warnings")}, plugin(p.get("index")))
                      for p in cs["preview"]]
    return out
