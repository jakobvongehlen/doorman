"""The owner API and the phone app. Passkey login, or a password where `doorman-admin sign-in password` set
one; approvals are a tap in the logged-in app, or signed with the passkey when `approval_passkey` is on."""

import ipaddress
import time
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import Body, Depends, FastAPI, Header, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .. import clock, crossread
from ..egress import rules
from ..auth import FREE_TRIES
from ..engine import Engine
from ..mcp.known import KNOWN as KNOWN_MCP
from ..feed import MAX_WAIT, RECHECK_SECONDS
from ..notify import PushGone, subject_ok
from ..plugin_api import Denied
from ..util import dumps, normalize
from ..webauthn_support import Passkeys
from . import errors

APP_DIR = Path(__file__).resolve().parent.parent / "owner_app"
COOKIE = "doorman_owner"
TRUST_KINDS = ("email", "phone", "iban", "chat", "url")

# On every answer, the app's files and the API alike. No other site may show the app in a frame (a Send
# button under someone else's page); the app loads only its own files (no inline script or style, no
# third-party anything), and links out of it carry no address.
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
                               "font-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self'; "
                               "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def create_owner_app(engine: Engine) -> FastAPI:
    app = FastAPI(title="Doorman: owner API", version="1", docs_url=None, redoc_url=None)
    errors.install(app)
    passkeys = Passkeys(engine.db, engine.public_url)
    secure_cookie = engine.public_url.startswith("https://")
    dev_token = engine.config.get("dev_owner_token")
    approval_passkey = bool(engine.config.get("approval_passkey"))
    # strict=False: a network may be written as the host's own address with its prefix (192.168.1.20/24)
    allowed_networks = [ipaddress.ip_network(c, strict=False) for c in engine.config.get("owner_allow_cidrs") or []]

    @app.middleware("http")
    async def client_allowlist(request: Request, call_next):
        """Keeps the owner app unreachable from the agent's network when the two share a host, and puts
        SECURITY_HEADERS on every answer."""
        if allowed_networks:
            client = ipaddress.ip_address(request.client.host if request.client else "0.0.0.0")
            if not any(client in network for network in allowed_networks):
                return JSONResponse({"status": "denied", "code": "network", "reason": "not reachable from here"},
                                    status_code=403, headers=SECURITY_HEADERS)
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        if request.url.path.startswith("/app/") or request.url.path == "/app":
            # Without this, browsers cache the app's files heuristically for hours or days and mix a new
            # index.html with an old app.css after an update. no-cache still allows cheap 304s (ETag).
            response.headers["Cache-Control"] = "no-cache"
        return response

    def owner(request: Request, authorization: str | None = Header(None),
              x_requested_with: str | None = Header(None)) -> bool:
        if dev_token and authorization == f"Bearer {dev_token}":
            return True
        if not engine.auth.check_owner_session(request.cookies.get(COOKIE)):
            raise Denied(f"log in with your {engine.auth.sign_in()}", "unauthenticated")
        if request.method not in ("GET", "HEAD") and x_requested_with != "doorman":
            raise Denied("missing X-Requested-With header", "csrf")
        return True

    STEP_UP_MINUTES = 5

    def fresh(request: Request, authorization: str | None = Header(None),
              x_requested_with: str | None = Header(None)) -> bool:
        """For changes to plugins and credentials: a passkey check (or the password, where Doorman signs in
        with one) in the last few minutes, not just a session that stayed logged in."""
        owner(request, authorization, x_requested_with)
        if dev_token and authorization == f"Bearer {dev_token}":
            return True
        if not engine.auth.verified_recently(request.cookies.get(COOKIE), STEP_UP_MINUTES):
            raise Denied(f"confirm with your {engine.auth.sign_in()} first", "reauth")
        return True

    def signs_in_with(method: str) -> None:
        """One method per Doorman: a password Doorman takes no passkey (not from a setup code either), and
        a passkey Doorman no password."""
        actual = engine.auth.sign_in()
        if actual != method:
            raise Denied(f"this Doorman signs in with a {actual}; `doorman-admin sign-in {method}` on its host "
                         f"changes that", "sign_in")

    def password_ok(body: dict, x_requested_with: str | None) -> None:
        if x_requested_with != "doorman":
            raise Denied("missing X-Requested-With header", "csrf")
        signs_in_with("password")
        if engine.auth.check_password(str(body.get("password") or "")):   # PasswordLocked while it waits
            return
        wrong = engine.auth.wrong_passwords()
        if wrong >= FREE_TRIES:  # one notice until the owner dismisses it, however long the guessing goes on
            engine.attention("sign_in", "password", f"{wrong} wrong passwords at the sign-in",
                             "Someone who can reach the owner app tried passwords. Each further try now has to "
                             "wait, longer every time. If it wasn't you, choose a new password on Doorman's "
                             "host: doorman-admin sign-in password", url=f"{engine.public_url}/app/#/more", priority=4)
        raise Denied("wrong password", "password")

    def login(response: Response, credential_id: str | None) -> None:
        token = engine.auth.create_owner_session(credential_id)
        response.set_cookie(COOKIE, token, httponly=True, secure=secure_cookie, samesite="strict",
                            max_age=12 * 3600, path="/")

    @app.get("/health")
    def health():
        """No login: for Docker's healthcheck. Says nothing beyond up/down and timings."""
        ok, body = engine.health()
        return JSONResponse(body, status_code=200 if ok else 503)

    @app.get("/")
    def root():
        return RedirectResponse("/app/")

    # ---------------------------------------------------------------- auth

    @app.get("/owner/auth/status")
    def auth_status(request: Request):
        return {"logged_in": engine.auth.check_owner_session(request.cookies.get(COOKIE)),
                "sign_in": engine.auth.sign_in(),
                "has_passkey": passkeys.has_credentials(), "approval_passkey": approval_passkey}

    # Registrations started with a setup code while passkeys existed: a lost phone, or a new address (a
    # passkey only works on the domain it was made for). Adding one tells the owner on their other devices.
    by_setup_code: set[str] = set()

    @app.post("/owner/auth/register/options")
    def register_options(request: Request, body: dict = Body(default={}), authorization: str | None = Header(None),
                         x_requested_with: str | None = Header(None)):
        """The first passkey takes a setup code from the host (`doorman-admin setup-code`). Another one
        takes a logged-in owner who confirmed with a passkey in the last few minutes (a phone left unlocked
        or a stolen cookie isn't enough for permanent access), or a setup code too: whoever can run that on
        the host can set up anyway."""
        signs_in_with("passkey")
        logged_in = engine.auth.check_owner_session(request.cookies.get(COOKIE))
        existing = passkeys.has_credentials()
        code = body.get("setup_code", "")
        if existing and logged_in and not code:
            fresh(request, authorization, x_requested_with)
            return passkeys.registration_options()
        if existing and not code:
            raise Denied("log in first to add another passkey, or use a setup code", "unauthenticated")
        if not engine.auth.consume_setup_code(code):
            raise Denied("wrong or expired setup code; run `doorman-admin setup-code`", "setup_code")
        options = passkeys.registration_options()
        if existing:
            by_setup_code.add(options["challenge_id"])
        return options

    @app.post("/owner/auth/register/verify")
    def register_verify(response: Response, body: dict = Body(...)):
        signs_in_with("passkey")  # also a registration begun before the switch to a password
        label = str(body.get("label", "passkey"))[:100]
        existing = passkeys.has_credentials()
        credential_id = passkeys.register(body["challenge_id"], body["credential"], label)
        if body["challenge_id"] in by_setup_code:
            by_setup_code.discard(body["challenge_id"])
            engine.attention("passkey", f"setup:{clock.iso()}", f"New passkey added with a setup code: {label}",
                             "Someone with a setup code from Doorman's host added a passkey. If it wasn't you, "
                             "remove it under More → Passkeys.", url=f"{engine.public_url}/app/#/more", priority=4)
        elif existing:  # every new passkey is permanent access: the owner hears about each one
            engine.attention("passkey", f"added:{clock.iso()}", f"New passkey added: {label}",
                             "A passkey was added from a logged-in session. If it wasn't you, remove it under "
                             "More → Passkeys.", url=f"{engine.public_url}/app/#/more", priority=4)
        login(response, credential_id)  # a session from a setup code belongs to the passkey it just added
        return {"ok": True}

    @app.post("/owner/auth/login/options")
    def login_options():
        signs_in_with("passkey")
        return passkeys.authentication_options("login")

    @app.post("/owner/auth/login/verify")
    def login_verify(response: Response, body: dict = Body(...)):
        signs_in_with("passkey")
        login(response, passkeys.verify(body["challenge_id"], "login", body["credential"]))
        return {"ok": True}

    @app.post("/owner/auth/login/password")
    def login_password(response: Response, body: dict = Body(...), x_requested_with: str | None = Header(None)):
        password_ok(body, x_requested_with)
        login(response, None)
        return {"ok": True}

    @app.post("/owner/auth/reauth/password", dependencies=[Depends(owner)])
    def reauth_password(request: Request, body: dict = Body(...), x_requested_with: str | None = Header(None)):
        """The password again, where a passkey Doorman asks for a fresh passkey check."""
        password_ok(body, x_requested_with)
        engine.auth.mark_verified(request.cookies.get(COOKIE))
        return {"ok": True}

    @app.post("/owner/auth/reauth/options", dependencies=[Depends(owner)])
    def reauth_options():
        signs_in_with("passkey")
        return passkeys.authentication_options("login")

    @app.post("/owner/auth/reauth/verify", dependencies=[Depends(owner)])
    def reauth_verify(request: Request, body: dict = Body(...)):
        signs_in_with("passkey")
        credential_id = passkeys.verify(body["challenge_id"], "login", body["credential"])
        engine.auth.mark_verified(request.cookies.get(COOKIE), credential_id)
        return {"ok": True}

    @app.post("/owner/auth/logout")
    def logout(request: Request, response: Response, x_requested_with: str | None = Header(None)):
        if x_requested_with != "doorman":  # another site can't log the owner out, as for every other POST
            raise Denied("missing X-Requested-With header", "csrf")
        token = request.cookies.get(COOKIE)
        if token:
            engine.auth.end_owner_session(token)  # and this device's push subscription with it
        response.delete_cookie(COOKIE, path="/")
        return {"ok": True}

    @app.get("/owner/passkeys", dependencies=[Depends(owner)])
    def list_passkeys():
        return {"passkeys": passkeys.credentials()}

    @app.post("/owner/passkeys/remove", dependencies=[Depends(fresh)])
    def remove_passkey(request: Request, body: dict = Body(...)):
        """The device it was on is logged out and gets no pushes any more; `signed_out` says whether that
        was this one."""
        mine = engine.auth.owner_session(request.cookies.get(COOKIE))
        ended = passkeys.remove(str(body.get("id", "")))
        signed_out = bool(mine) and not engine.auth.check_owner_session(request.cookies.get(COOKIE))
        return {"ok": True, **ended, "signed_out": signed_out}

    # ---------------------------------------------------------------- push notifications

    @app.get("/owner/push", dependencies=[Depends(owner)])
    def push_status():
        return {"public_key": engine.notifier.vapid.public_key, "subject_ok": subject_ok(engine.notifier.subject),
                "subscriptions": engine.notifier.subscriptions()}

    @app.post("/owner/push/subscribe", dependencies=[Depends(owner)])
    def push_subscribe(request: Request, body: dict = Body(...)):
        """The app calls this on every start and after every login, so it is an upsert. The device's
        subscription belongs to the passkey it logged in with and to this login: removing that passkey drops
        it, and so does logging out on the device. A device new to Doorman is announced on the others, as a
        new passkey is: someone with the phone for a minute, or with a stolen cookie, would otherwise read
        every approval from then on."""
        session = engine.auth.owner_session(request.cookies.get(COOKIE))
        subscription = body.get("subscription") if isinstance(body.get("subscription"), dict) else {}
        label = str(body.get("label") or "")[:80]
        new = not engine.notifier.known(subscription.get("endpoint"))
        try:
            subscription_id = engine.notifier.subscribe(subscription, label,
                                                        credential_id=session["credential_id"] if session else None,
                                                        session_hash=session["token_hash"] if session else None)
        except PushGone as exc:
            raise Denied(str(exc), "push_gone") from exc
        except ValueError as exc:
            raise Denied(str(exc), "invalid") from exc
        if new:
            announce_device(subscription_id, label)
        return {"id": subscription_id}

    def device_ref(subscription_id: int) -> str | None:
        row = engine.db.one("SELECT created FROM push_subscriptions WHERE id=?", (subscription_id,))
        return f"{subscription_id}:{row['created']}" if row else None

    def announce_device(subscription_id: int, label: str) -> None:
        """Needs attention, and a push to the owner's other devices (not to the new one)."""
        try:
            local = clock.now().astimezone(ZoneInfo(engine.config.get("timezone") or "UTC"))
        except (KeyError, ValueError):  # a timezone that doesn't exist must not keep the device unannounced
            local = clock.now()
        name = label or f"Device {subscription_id}"
        engine.attention("push_device", device_ref(subscription_id), f"A new device gets Doorman's notifications: {name}",
                         f"Since {local.day} {local:%b}, {local:%H:%M}, it gets every push: each approval with what it "
                         "sends, the agent's questions and every alert. Not you? Remove it under More → Notifications, "
                         "and the passkey it logged in with under More → Passkeys.",
                         url=f"{engine.public_url}/app/#/more", priority=4, exclude=subscription_id)

    @app.delete("/owner/push/{subscription_id}", dependencies=[Depends(owner)])
    def push_remove(subscription_id: int):
        ref = device_ref(subscription_id)
        if not engine.notifier.unsubscribe(subscription_id=subscription_id):
            raise Denied("no such device", "not_found")
        engine.resolve_attention("push_device", ref)  # its "new device" notice has done its job
        return {"ok": True}

    @app.post("/owner/push/test", dependencies=[Depends(owner)])
    def push_test():
        if not engine.notifier.subscriptions():
            raise Denied("no device has notifications turned on", "invalid")
        return {"results": engine.notifier.test(url=f"{engine.public_url}/app/#/more")}

    # ---------------------------------------------------------------- inbox and approvals

    @app.get("/owner/inbox", dependencies=[Depends(owner)])
    def inbox():
        return {
            "approvals": engine.approvals.pending(),
            "changesets": [engine.changeset(r["id"]) for r in
                           engine.db.all("SELECT id FROM changesets WHERE status='proposed' ORDER BY id DESC")],
            "paused": engine.killed(),
            "attention": engine.attention_stacked(),  # the same message several times: once, with its count
            "questions": engine.owner_questions.open(),  # an agent asks (owner_questions.py)
            "network": engine.egress.open_requests(),  # an agent asks for network access (egress/service.py)
            "first_steps": engine.first_steps(),  # a new owner's Get started card
        }

    # ---------------------------------------------------------------- network watch (egress/service.py)

    @app.get("/owner/egress", dependencies=[Depends(owner)])
    def egress_overview():
        return {"settings": engine.egress.settings(),
                "lists": {"risky_tlds": rules.default_list("risky_tlds"),
                          "exfil_hosts": rules.default_list("exfil_hosts")},
                "status": engine.egress.status_view(), "enabled": engine.egress.enabled(),
                "counts": engine.egress.counts(),
                "model_keys": engine.egress.model_keys(),  # API keys seen with model providers (no_scan)
                "decoys": engine.egress.decoys_view(),  # never the values
                "quarantine": engine.egress.quarantine_view()}

    @app.post("/owner/egress", dependencies=[Depends(fresh)])
    def egress_save(body: dict = Body(...)):
        """The owner's network rules: what the proxy lets through is a change like a plugin's settings, so it
        takes a fresh passkey check."""
        return engine.egress.save_settings(body)

    @app.post("/owner/egress/token", dependencies=[Depends(fresh)])
    def egress_token():
        """A new token for the proxy (DOORMAN_EGRESS_TOKEN), shown once; it replaces the old one."""
        return {"token": engine.egress.new_token()}

    @app.post("/owner/egress/decoys/rotate", dependencies=[Depends(fresh)])
    def egress_decoys_rotate():
        """New decoy keys; the old ones stay honeytokens."""
        return engine.egress.rotate_decoys()

    @app.post("/owner/egress/quarantine/lift", dependencies=[Depends(fresh)])
    def egress_quarantine_lift(body: dict = Body(...)):
        """{client_ip}: the proxy lets that address out again (the agent's keys stay paused until resumed)."""
        return engine.egress.lift_quarantine(body.get("client_ip"))

    @app.get("/owner/egress/log", dependencies=[Depends(owner)])
    def egress_log(task_id: int | None = None, key_id: int | None = None, only: str = "all",
                   before: int | None = None, limit: int = 100):
        return {"rows": engine.egress.log_view(task_id=task_id, key_id=key_id, only=only, before=before,
                                               limit=limit)}

    @app.get("/owner/egress/exemptions", dependencies=[Depends(owner)])
    def egress_exemptions():
        return {"exemptions": engine.egress.exemptions()}

    @app.post("/owner/egress/exemptions/{eid}/revoke", dependencies=[Depends(owner)])
    def egress_revoke(eid: int):
        """Ending an exception only takes access away: a logged-in tap is enough."""
        engine.egress.revoke_exemption(eid)
        return {"ok": True}

    @app.post("/owner/egress/requests/{rid}/decide", dependencies=[Depends(owner)])
    def egress_decide(rid: int, request: Request, body: dict = Body(...), authorization: str | None = Header(None),
                      x_requested_with: str | None = Header(None)):
        """{decision: once | task | always | deny}. Once, for this task and deny are a tap, like answering an
        agent's question; always puts the target on the allow list for good, for every key, so it takes a
        fresh passkey check like adding to the trust list."""
        decision = body.get("decision")
        if decision == "always":
            fresh(request, authorization, x_requested_with)
        if body.get("via") == "notification" and decision != "deny" and not engine.push_accepts():
            raise Denied("open Doorman to allow it", "open_app")  # approval_passkey: no yes from a push
        return engine.egress.decide(rid, str(decision or ""))

    @app.post("/owner/questions/{qid}/answer", dependencies=[Depends(owner)])
    def answer_question(qid: int, body: dict = Body(...)):
        """The owner's answer to an agent's question: {answer: text} or {option: its number or text}."""
        return engine.owner_questions.answer(qid, body.get("answer"), body.get("option"))

    @app.post("/owner/questions/{qid}/dismiss", dependencies=[Depends(owner)])
    def dismiss_question(qid: int):
        return engine.owner_questions.dismiss(qid)

    @app.post("/owner/attention/{item_id}/dismiss", dependencies=[Depends(owner)])
    def dismiss_attention(item_id: int):
        if not engine.dismiss_attention(item_id):
            raise Denied("nothing open with that id", "not_found")
        return {"ok": True}

    @app.post("/owner/plugins/check", dependencies=[Depends(owner)])
    async def check_plugins():
        return {"results": await run_in_threadpool(engine.check_plugins, True)}

    @app.get("/owner/approvals/{approval_id}", dependencies=[Depends(owner)])
    def get_approval(approval_id: int):
        approval = engine.approvals.get(approval_id)
        if approval is None:
            raise Denied("no such approval", "not_found")
        return approval

    @app.post("/owner/approvals/{approval_id}/options", dependencies=[Depends(owner)])
    def approval_options(approval_id: int):
        if not approval_passkey:
            raise Denied("approvals don't use the passkey here; send payload_hash instead", "invalid")
        challenge = engine.approvals.challenge(approval_id)
        return passkeys.authentication_options("approval", challenge=challenge, ref=str(approval_id))

    @app.post("/owner/approvals/{approval_id}/decide", dependencies=[Depends(owner)])
    async def decide(approval_id: int, body: dict = Body(...)):
        approve = bool(body.get("approve"))
        from_push = body.get("via") == "notification"  # the service worker, from Accept or Decline on a push
        if not approve:  # with the owner's optional note for the agent (approval_decided, doorman status)
            return await run_in_threadpool(lambda: engine.approvals.decide(
                approval_id, False, method="notification" if from_push else None, note=body.get("note")))
        if from_push and not await run_in_threadpool(engine.approvals.accept_from_notification, approval_id):
            # a passkey, a payment, a warning or more than one send: that needs the approval screen
            raise Denied("open the approval in Doorman to accept it", "open_app")
        if approval_passkey:
            credential_id = passkeys.verify(body.get("challenge_id", ""), "approval", body.get("credential") or {},
                                            expected_challenge=engine.approvals.challenge(approval_id),
                                            ref=str(approval_id))
            return await run_in_threadpool(lambda: engine.approvals.decide(approval_id, True, credential_id, method="passkey"))
        # a tap: the logged-in session is the proof; the hash binds it to the payload the screen showed
        seen = body.get("payload_hash")
        if not isinstance(seen, str) or not seen:
            raise Denied("payload_hash is missing: approve from the approval screen", "invalid")
        return await run_in_threadpool(lambda: engine.approvals.decide(
            approval_id, True, seen_hash=seen, method="notification" if from_push else "tap"))

    @app.get("/owner/approvals/{approval_id}/results", dependencies=[Depends(owner)])
    async def approval_results(approval_id: int, wait: float = 0):
        """What an approved send did: each entry's result, "sending" while it runs, and `done` once all
        ended. With `wait` (at most 60 s) it holds on until they ended: the app's "Sending…" follows it.
        Woken by the feed's bell, which every result rings."""
        deadline = time.monotonic() + max(0.0, min(float(wait), MAX_WAIT))
        while True:
            seen = engine.feed.bell.generation
            out = await run_in_threadpool(engine.sends.view, approval_id)
            if out is None:
                raise Denied("no such approval", "not_found")
            left = deadline - time.monotonic()
            if out["done"] or left <= 0:
                return out
            await engine.feed.bell.wait(seen, min(RECHECK_SECONDS, left))

    @app.post("/owner/approvals/{approval_id}/ask-again", dependencies=[Depends(owner)])
    def ask_again(approval_id: int):
        """An expired approval: tell the agent the owner still wants it, so it asks again."""
        return engine.approvals.ask_again(approval_id)

    @app.post("/owner/approvals/{approval_id}/edit", dependencies=[Depends(owner)])
    def edit_approval(approval_id: int, body: dict = Body(...)):
        """Change the text of a waiting send; answers with the new approval to look at and approve."""
        return engine.approvals.edit(approval_id, int(body.get("entry_id") or 0), body.get("changes") or {},
                                    body.get("payload_hash"))

    # ---------------------------------------------------------------- journal and rollback

    @app.get("/owner/journal", dependencies=[Depends(owner)])
    def journal(task_id: int | None = None, since: str | None = None, include_denied: bool = False,
                before: int | None = None, limit: int = 100):
        entries = engine.journal.list(task_id=task_id, since=since, include_denied=include_denied, limit=limit,
                                      before=before)
        tasks = {t["id"]: t for t in engine.tasks.list(limit=500)}
        return {"entries": [engine.entry_view(e) for e in entries],
                "tasks": {str(k): {"id": v["id"], "text": v["text"], "status": v["status"],
                                   "closed_by_owner": v["closed_by_owner"]} for k, v in tasks.items()}}

    @app.get("/owner/reads", dependencies=[Depends(owner)])
    def reads(task_id: int | None = None, key_id: int | None = None, before: int | None = None, limit: int = 100):
        """The read log: who read what. Not part of the journal's hash chain."""
        rows = engine.reads.list(task_id=task_id, key_id=key_id, before=before, limit=limit)
        ids = {r["task_id"] for r in rows if r["task_id"]}
        tasks = {t["id"]: t for t in engine.tasks.list(limit=500) if t["id"] in ids}
        return {"reads": rows, "keep_days": engine.config.get("read_log_days", 90),
                "tasks": {str(k): {"id": v["id"], "text": v["text"], "status": v["status"]} for k, v in tasks.items()}}

    @app.get("/owner/events", dependencies=[Depends(owner)])
    def events(before: int | None = None, limit: int = 50, source: str | None = None, task_id: int | None = None):
        """The event feed as agents get it, for the owner: newest first, each key's place in it (feed.py)."""
        return engine.feed.owner_view(before=before, limit=limit, source=source, task_id=task_id)

    @app.get("/owner/journal/verify", dependencies=[Depends(owner)])
    def verify():
        ok, bad = engine.journal.verify()
        return {"ok": ok, "first_bad_entry": bad}

    @app.get("/owner/journal/{entry_id}", dependencies=[Depends(owner)])
    def journal_entry(entry_id: int):
        entry = engine.journal.get(entry_id)
        if entry is None:
            raise Denied("no such entry", "not_found")
        return engine.entry_view(entry)

    @app.post("/owner/journal/{entry_id}/revert")
    async def revert(entry_id: int, request: Request, body: dict = Body(default={}),
                     authorization: str | None = Header(None), x_requested_with: str | None = Header(None)):
        # reverting can hand back a looser setting ("Always allow", no_approval): that needs a fresh check,
        # as it did the first time
        (fresh if engine.plugin_setup.revert_loosens(entry_id) else owner)(request, authorization, x_requested_with)
        return await run_in_threadpool(engine.revert_entry, entry_id, bool(body.get("force")))

    @app.post("/owner/revert", dependencies=[Depends(owner)])
    async def revert_scope(body: dict = Body(...)):
        if not body.get("task_id") and not body.get("since"):
            raise Denied("give task_id or since", "invalid")
        return await run_in_threadpool(engine.revert_scope, body.get("task_id"), body.get("since"),
                                       bool(body.get("preview")))

    # ---------------------------------------------------------------- changesets and tasks

    @app.get("/owner/changesets/{changeset_id}", dependencies=[Depends(owner)])
    def changeset(changeset_id: int):
        cs = engine.changeset(changeset_id)
        if cs is None:
            raise Denied("no such changeset", "not_found")
        return cs

    @app.post("/owner/changesets/{changeset_id}/apply", dependencies=[Depends(owner)])
    async def apply(changeset_id: int, body: dict = Body(default={})):
        if body.get("via") == "notification":  # Apply all on the push: only what Doorman has no warning on
            cs = engine.changeset(changeset_id)
            if cs and cs["status"] == "proposed" and not engine.push_accepts(engine.changeset_clean(cs["preview"])):
                raise Denied("open the changeset in Doorman to apply it", "open_app")
        return await run_in_threadpool(engine.apply_changeset, changeset_id, body.get("selected"))

    @app.post("/owner/changesets/{changeset_id}/reject", dependencies=[Depends(owner)])
    def reject(changeset_id: int, body: dict = Body(default={})):
        rejected = engine.reject_changeset(changeset_id, body.get("comment", ""))
        if not rejected and body.get("via") == "notification":  # the push must not say "Denied" of what ran
            raise Denied("no open changeset with that id", "changeset")
        return {"ok": True}

    @app.get("/owner/tasks", dependencies=[Depends(owner)])
    def tasks():
        return {"tasks": engine.tasks.list()}

    @app.get("/owner/tasks/{task_id}", dependencies=[Depends(owner)])
    def task(task_id: int):
        """One task's screen: its text, origin and report, its journal entries and its waiting approvals."""
        view = engine.tasks.view(task_id)
        if view is None:
            raise Denied("no such task", "not_found")
        return view

    @app.post("/owner/tasks", dependencies=[Depends(owner)])
    def create_task(body: dict = Body(...)):
        """A task is its text. What the agent may do on it is set in each plugin's settings, nowhere else."""
        text = (body.get("text") or "").strip()
        if not text:
            raise Denied("a task needs text", "invalid")
        return {"id": engine.tasks.create(text)}

    # ---------------------------------------------------------------- routines and triggers

    @app.post("/owner/tasks/{task_id}/close", dependencies=[Depends(owner)])
    def close_task(task_id: int, body: dict = Body(default={})):
        """End a claimed task the agent never reported, which frees the agent key for new tasks."""
        return engine.tasks.close(task_id, body.get("reason"))

    @app.get("/owner/routines", dependencies=[Depends(owner)])
    def routines():
        return {"routines": engine.db.all("SELECT * FROM routines ORDER BY id"),
                "triggers": engine.db.all("SELECT * FROM triggers ORDER BY id")}

    def note(tool: str, summary: str) -> None:
        """Trust entries, routines and triggers decide what counts as owner-written: journal every change."""
        engine.journal.create(kind="config", tool=tool, tier="irreversible", decision="run", status="done",
                              summary=summary)

    @app.post("/owner/routines", dependencies=[Depends(fresh)])
    def add_routine(body: dict = Body(...)):
        from croniter import croniter

        if not croniter.is_valid(body.get("cron", "")):
            raise Denied("not a valid cron expression", "invalid")
        if not str(body.get("name") or "").strip() or not str(body.get("task_text") or "").strip():
            raise Denied("a routine needs a name and a task", "invalid")
        routine_id = engine.db.exec("INSERT INTO routines(name, cron, task_text, enabled) VALUES(?,?,?,1)",
                                    (body["name"], body["cron"], body["task_text"]))
        note("routine.add", f"Routine “{body['name']}” added ({body['cron']}): {body['task_text'][:80]}")
        return {"id": routine_id}

    def routine_name(routine_id: int) -> str:
        row = engine.db.one("SELECT name FROM routines WHERE id=?", (routine_id,))
        if row is None:
            raise Denied("no such routine", "not_found")
        return row["name"]

    @app.post("/owner/routines/{routine_id}", dependencies=[Depends(fresh)])
    def toggle_routine(routine_id: int, body: dict = Body(...)):
        name = routine_name(routine_id)
        engine.db.exec("UPDATE routines SET enabled=? WHERE id=?", (int(bool(body.get("enabled"))), routine_id))
        note("routine.state", f"Routine “{name}” {'on' if body.get('enabled') else 'off'}")
        return {"ok": True}

    @app.delete("/owner/routines/{routine_id}", dependencies=[Depends(owner)])
    def delete_routine(routine_id: int):
        name = routine_name(routine_id)
        engine.db.exec("DELETE FROM routines WHERE id=?", (routine_id,))
        note("routine.delete", f"Routine “{name}” deleted")
        return {"ok": True}

    @app.post("/owner/triggers", dependencies=[Depends(fresh)])
    def add_trigger(body: dict = Body(...)):
        if not all(isinstance(body.get(k), str) and body[k].strip() for k in ("name", "plugin", "event", "task_text")):
            raise Denied("a trigger needs a name, a plugin, an event and a task", "invalid")
        if body["plugin"] not in engine.registry.configured():
            raise Denied(f"no plugin called {body['plugin']}", "invalid")
        if not isinstance(body.get("match") or {}, dict):
            raise Denied("match is a set of field: pattern pairs", "invalid")
        trigger_id = engine.db.exec(
            "INSERT INTO triggers(name, plugin, event, match, task_text, enabled) VALUES(?,?,?,?,?,1)",
            (body["name"], body["plugin"], body["event"], dumps(body.get("match") or {}), body["task_text"]))
        note("trigger.add", f"Trigger “{body['name']}” added: {body['plugin']} {body['event']}")
        return {"id": trigger_id}

    @app.delete("/owner/triggers/{trigger_id}", dependencies=[Depends(owner)])
    def delete_trigger(trigger_id: int):
        row = engine.db.one("SELECT name FROM triggers WHERE id=?", (trigger_id,))
        engine.db.exec("DELETE FROM triggers WHERE id=?", (trigger_id,))
        if row:
            note("trigger.delete", f"Trigger “{row['name']}” deleted")
        return {"ok": True}

    # ---------------------------------------------------------------- trust lists

    # ---------------------------------------------------------------- privacy: pseudonyms for agents

    @app.get("/owner/privacy", dependencies=[Depends(owner)])
    def privacy():
        count = engine.db.one("SELECT COUNT(*) AS n FROM pseudonyms")["n"]
        return {**engine.pseudonyms.settings(), "pseudonyms": count}

    @app.post("/owner/privacy", dependencies=[Depends(fresh)])
    def save_privacy(body: dict = Body(...)):
        words = body.get("extra_words", [])
        if not isinstance(words, list) or not all(isinstance(w, str) for w in words):
            raise Denied("extra_words must be a list of words", "invalid")
        if len(words) > 300 or any(len(w) > 100 for w in words):
            raise Denied("at most 300 words of up to 100 characters", "invalid")
        before = engine.pseudonyms.settings()
        engine.pseudonyms.save(bool(body.get("enabled", True)), words)
        after = engine.pseudonyms.settings()
        changes = []
        if before["enabled"] != after["enabled"]:
            changes.append("on" if after["enabled"] else "OFF: agents see everything")
        if before["extra_words"] != after["extra_words"]:
            changes.append(f"{len(after['extra_words'])} own words")
        note("privacy.pseudonyms", "Pseudonyms for agents: " + (", ".join(changes) or "saved, unchanged"))
        return {**after, "pseudonyms": engine.db.one("SELECT COUNT(*) AS n FROM pseudonyms")["n"]}

    @app.post("/owner/privacy/preview", dependencies=[Depends(owner)])
    def privacy_preview(body: dict = Body(...)):
        """What an agent would get for this text as a calendar title and inside a mail."""
        text = str(body.get("text") or "")[:2000]
        title = engine.pseudonyms.hide({"summary": text}, "google_calendar")[0]["summary"]
        return {"as_title": title, "in_mail": engine.pseudonyms.text(text, "mail_imap")}

    @app.get("/owner/trust", dependencies=[Depends(owner)])
    def trust():
        return {"trust": engine.db.all("SELECT * FROM trust ORDER BY kind, value"),
                "known": engine.policy.known_settings()}

    @app.post("/owner/trust/known")
    def trust_known(request: Request, body: dict = Body(...), authorization: str | None = Header(None),
                    x_requested_with: str | None = Header(None)):
        """The switches for who else counts as the owner's: people in their contacts (`contacts`), and
        whom they wrote to before (`written_before`). Switching one on silences warnings, so it takes a
        fresh passkey check, like adding to the trust list; switching one off doesn't."""
        changes = {k: body[k] for k in ("contacts", "written_before") if k in body}
        (fresh if engine.policy.known_loosens(changes) else owner)(request, authorization, x_requested_with)
        before, after = engine.policy.save_known_settings(changes)
        words = {"contacts": "people in your contacts", "written_before": "people you wrote to before"}
        changed = [f"{words[k]} {'count as yours' if after[k] else 'get the new recipient warning'}"
                   for k in words if before[k] != after[k]]
        if changed:
            note("trust.known", "Trust: " + "; ".join(changed))
        return after

    @app.post("/owner/trust", dependencies=[Depends(fresh)])
    def add_trust(body: dict = Body(...)):
        kind = body.get("kind")
        if kind not in TRUST_KINDS:
            raise Denied(f"kind must be one of {', '.join(TRUST_KINDS)}", "invalid")
        value = normalize(kind, body.get("value", ""))
        if not value:
            raise Denied("a trust entry needs a value", "invalid")
        known = engine.db.one("SELECT id FROM trust WHERE kind=? AND value=?", (kind, value))
        if not known:
            engine.db.exec("INSERT OR IGNORE INTO trust(kind, value, label, created) VALUES(?,?,?,?)",
                           (kind, value, body.get("label", ""), clock.iso()))
            note("trust.add", f"Trusted {kind} {value}")
        # the id lets the app offer Undo (DELETE), but only for an entry this call added
        row = engine.db.one("SELECT id FROM trust WHERE kind=? AND value=?", (kind, value))
        return {"ok": True, "value": value, "id": row["id"] if row else None, "added": not known}

    @app.get("/owner/contacts", dependencies=[Depends(owner)])
    def contacts(q: str = "", limit: int = 50):
        """People with an email address from every address book (a manifest's `contacts: <read>`), for
        "Trust a contact": the app adds the address picked with POST /owner/trust."""
        if len(q) > 200 or not 1 <= limit <= 200:
            raise Denied("q is at most 200 characters, limit 1 to 200", "invalid")
        trusted = {row["value"] for row in engine.db.all("SELECT value FROM trust WHERE kind='email'")}
        people, report, more = [], {}, False
        params = {"query": q.strip(), "with_email": True, "limit": limit}
        for source, data, problem in crossread.for_owner(engine, "contacts", params):
            if problem:
                report[source["name"]] = problem
                continue
            found = data.get("contacts") if isinstance(data, dict) else data
            found = [c for c in found if isinstance(c, dict)] if isinstance(found, list) else []
            more = more or bool(isinstance(data, dict) and data.get("more"))
            report[source["name"]] = {"count": len(found)}
            for person in found:
                emails = [{"address": e["address"], "type": e.get("type") or "",
                           "trusted": normalize("email", e["address"]) in trusted}
                          for e in person.get("emails") or [] if isinstance(e, dict) and e.get("address")]
                if emails:
                    people.append({"name": person.get("name") or emails[0]["address"],
                                   "organisation": person.get("organisation") or "", "source": source["name"],
                                   "ref": person.get("ref"), "emails": emails})
        people.sort(key=lambda p: p["name"].casefold())
        return {"contacts": people[:limit], "sources": report, "more": more or len(people) > limit}

    @app.delete("/owner/trust/{trust_id}", dependencies=[Depends(owner)])
    def delete_trust(trust_id: int):
        row = engine.db.one("SELECT kind, value FROM trust WHERE id=?", (trust_id,))
        engine.db.exec("DELETE FROM trust WHERE id=?", (trust_id,))
        if row:
            note("trust.delete", f"No longer trusted: {row['kind']} {row['value']}")
        return {"ok": True}

    # ---------------------------------------------------------------- plugins, settings, kill switch

    @app.get("/owner/plugins", dependencies=[Depends(owner)])
    def plugins():
        listed = [{**p, "job_status": engine.job_status(p["name"])} for p in engine.registry.list()]
        return {"plugins": listed, "available": engine.registry.available(), "mcp_known": KNOWN_MCP}

    @app.post("/owner/plugins/{name}/jobs/{job}/dismiss", dependencies=[Depends(owner)])
    def dismiss_job_error(name: str, job: str):
        return engine.dismiss_job_error(name, job)

    @app.post("/owner/plugins/{name}")
    def set_plugin(name: str, request: Request, body: dict = Body(...),
                   authorization: str | None = Header(None), x_requested_with: str | None = Header(None)):
        """A change that lets a send run without asking where it couldn't before needs a fresh passkey
        check, like a plugin's no_approval: a send set to Auto, or read-only off, or the tool or the plugin
        switched back on while Auto or no_approval holds for a send (engine.plugin_setup.sends_loosen). Everything else
        here only tightens, or changes what asks anyway."""
        owner(request, authorization, x_requested_with)
        return engine.plugin_setup.switch(name, enabled=body.get("enabled"), read_only=body.get("read_only"),
                                 tool=body.get("tool"), tool_enabled=body.get("tool_enabled"), mode=body.get("mode"),
                                 confirm=lambda: fresh(request, authorization, x_requested_with))

    # plugins set up in the app; every change needs a fresh passkey check
    @app.post("/owner/instances", dependencies=[Depends(fresh)])
    def add_instance(body: dict = Body(...)):
        return engine.plugin_setup.add(body.get("name"), body.get("type"), body.get("config") or {},
                                 bool(body.get("no_approval")), body.get("credentials") or {})

    @app.post("/owner/instances/{name}/config", dependencies=[Depends(fresh)])
    def configure_instance(name: str, body: dict = Body(...)):
        return engine.plugin_setup.configure(name, body.get("config"), body.get("no_approval"))

    @app.post("/owner/instances/{name}/remove", dependencies=[Depends(fresh)])
    def remove_instance(name: str):
        return engine.plugin_setup.remove(name)

    @app.post("/owner/instances/{name}/credentials", dependencies=[Depends(fresh)])
    def set_credential(name: str, body: dict = Body(...)):
        return engine.plugin_setup.set_credential(name, body.get("key"), body.get("value"))

    @app.get("/owner/plugins/{name}/login", dependencies=[Depends(owner)])
    async def login_status(name: str):
        return await run_in_threadpool(engine.plugin_setup.login_status, name)

    @app.post("/owner/plugins/{name}/login/start", dependencies=[Depends(fresh)])  # connecting is a change
    async def login_start(name: str, body: dict = Body(default={})):
        phone = body.get("phone")  # link logins (WhatsApp): a pairing code for this number, not a QR code
        if phone is not None and (not isinstance(phone, str) or len(phone) > 32):
            raise Denied("phone: a phone number with its country code", "invalid")
        return await run_in_threadpool(engine.plugin_setup.login_start, name, phone or None)

    @app.post("/owner/plugins/{name}/login/finish", dependencies=[Depends(owner)])
    async def login_finish(name: str, body: dict = Body(...)):
        url = body.get("url")
        if not isinstance(url, str) or not url.strip():
            raise Denied("paste the address of the page the sign-in sent you to", "invalid")
        return await run_in_threadpool(engine.plugin_setup.login_finish, name, url)

    @app.post("/owner/plugins/{name}/logout", dependencies=[Depends(owner)])
    async def plugin_logout(name: str):
        return await run_in_threadpool(engine.plugin_setup.logout, name)

    # MCP servers: refresh the tool list, and the owner's choice per tool
    @app.post("/owner/mcp/{name}/sync", dependencies=[Depends(owner)])
    async def mcp_sync(name: str):
        return await run_in_threadpool(engine.plugin_setup.mcp_sync, name)

    @app.post("/owner/mcp/{name}/seen", dependencies=[Depends(owner)])
    def mcp_seen(name: str):
        return engine.plugin_setup.mcp_seen(name)

    @app.post("/owner/mcp/{name}/tools/{tool}")
    def mcp_tool(name: str, tool: str, request: Request, body: dict = Body(...),
                 authorization: str | None = Header(None), x_requested_with: str | None = Header(None)):
        """Letting a tool run without asking, or treating it as a read (or as the server labels it), loosens
        it: that needs a fresh passkey check. Asking first again and treating it as a write don't."""
        treat_as = body["treat_as"] if "treat_as" in body else "unchanged"
        allowed = body.get("allowed")
        if treat_as not in ("unchanged", "read", "write", None) or not (allowed is None or isinstance(allowed, bool)):
            owner(request, authorization, x_requested_with)
            raise Denied("allowed is true or false; treat_as is read, write or null", "invalid")
        loosens = allowed is True or treat_as in ("read", None)
        (fresh if loosens else owner)(request, authorization, x_requested_with)
        return engine.plugin_setup.mcp_tool_rule(name, tool, treat_as=treat_as, allowed=allowed)

    # ---------------------------------------------------------------- the injection guard

    @app.get("/owner/guard", dependencies=[Depends(owner)])
    def guard_status():
        return engine.guard.status()

    @app.post("/owner/guard")
    def guard_settings(request: Request, body: dict = Body(...), authorization: str | None = Header(None),
                       x_requested_with: str | None = Header(None)):
        """Switching the guard off or raising its threshold lets more through: that needs a fresh passkey
        check. Switching it on and lowering the threshold don't."""
        enabled, threshold = body.get("enabled"), body.get("threshold")
        (fresh if engine.guard.loosens(enabled, threshold) else owner)(request, authorization, x_requested_with)
        return engine.guard_settings(enabled=enabled, threshold=threshold)

    # ---------------------------------------------------------------- semantic search

    @app.get("/owner/semantic", dependencies=[Depends(owner)])
    def semantic_status():
        """The model, and per source of the search index how far its vectors are (library.py)."""
        index = engine.search.status()
        sources = [{"name": src["name"], "items": src["items"], "pulled": src["pulled"], "error": src["error"],
                    "skipped": src["skipped"], "skip_note": src["skip_note"],
                    **(src.get("semantic") or {"embedded": 0, "of": src["parts"]})} for src in index["sources"]]
        return {**engine.embedder.status(), "sources": sources,
                "index": {k: index[k] for k in ("items", "parts", "summary")}}

    @app.post("/owner/semantic", dependencies=[Depends(owner)])
    def semantic_settings(body: dict = Body(...)):
        return engine.embedder.save(body.get("enabled"))

    @app.post("/owner/semantic/fetch", dependencies=[Depends(owner)])
    def semantic_fetch():
        return engine.embedder.fetch()

    @app.post("/owner/guard/fetch", dependencies=[Depends(owner)])
    def guard_fetch():
        return engine.guard.fetch()

    @app.get("/owner/quarantine", dependencies=[Depends(owner)])
    def quarantine(status: str | None = None, limit: int = 100):
        return {"items": engine.guard.list(status, max(1, min(limit, 500)))}

    @app.get("/owner/quarantine/{qid}", dependencies=[Depends(owner)])
    def quarantine_item(qid: int):
        row = engine.guard.quarantined(qid)
        if row is None:
            raise Denied("nothing quarantined with that id", "not_found")
        return row

    @app.post("/owner/quarantine/{qid}/release", dependencies=[Depends(owner)])
    def quarantine_release(qid: int):
        return engine.quarantine_decide(qid, release=True)

    @app.post("/owner/quarantine/{qid}/keep", dependencies=[Depends(owner)])
    def quarantine_keep(qid: int):
        return engine.quarantine_decide(qid, release=False)

    # ---------------------------------------------------------------- agent keys

    @app.get("/owner/status", dependencies=[Depends(owner)])
    def status():
        return engine.status()

    @app.get("/owner/week", dependencies=[Depends(owner)])
    def week():
        return engine.week()

    @app.get("/owner/keys", dependencies=[Depends(owner)])
    def list_keys():
        return {"keys": engine.auth.list_keys(), "agent_url": engine.agent_url(),
                "reader_actor_split": engine.config["reader_actor_split"]}

    @app.post("/owner/keys", dependencies=[Depends(fresh)])
    def create_key(body: dict = Body(...)):
        return engine.create_agent_key(str(body.get("name") or ""), str(body.get("role") or "solo"))

    @app.post("/owner/keys/{key_id}/revoke", dependencies=[Depends(owner)])
    def revoke_key(key_id: int):
        return engine.revoke_agent_key(key_id)

    @app.post("/owner/keys/{key_id}/resume", dependencies=[Depends(fresh)])
    def resume_key(key_id: int):
        return engine.resume_agent_key(key_id)

    @app.get("/owner/settings", dependencies=[Depends(owner)])
    def settings():
        return {"paused": engine.killed(),
                # after "Revoke all keys" there are none: resuming then brings no agent back by itself
                "agent_keys": engine.db.one("SELECT COUNT(*) AS n FROM agent_keys WHERE revoked=0")["n"],
                "limits": engine.config.get("limits"), "payments": engine.config.get("payments"),
                "reader_actor_split": engine.config["reader_actor_split"],
                "reviewer": bool(engine.reviewer.enabled), "public_url": engine.public_url,
                "sign_in": engine.auth.sign_in(), "approval_passkey": approval_passkey}

    # Stopping is never slowed down by a passkey prompt: pausing and revoking only take access away, so a
    # logged-in session is enough, as it is for revoking one key. Resuming gives it back to every key that
    # still works, so it asks for a fresh passkey check, like creating a key.
    @app.post("/owner/pause", dependencies=[Depends(owner)])
    def pause():
        engine.pause()
        return {"ok": True}

    @app.post("/owner/kill", dependencies=[Depends(owner)])
    def kill():
        """Revoke all keys (and pause)."""
        engine.kill()
        return {"ok": True}

    @app.post("/owner/resume", dependencies=[Depends(fresh)])
    def resume():
        engine.resume()
        return {"ok": True}

    @app.get("/owner/notifications", dependencies=[Depends(owner)])
    def notifications():
        return {"notifications": engine.db.all("SELECT * FROM notifications ORDER BY id DESC LIMIT 50")}

    app.mount("/app", StaticFiles(directory=APP_DIR, html=True), name="app")
    return app

