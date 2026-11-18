"""doorman-admin demo: Doorman with realistic but entirely made-up data, and no real accounts.

`doorman-admin demo --dir D` creates D on its first run: a doorman.yaml, a data directory, an agent key and
the fake world in seed.py (a student's mail, calendar, contacts, timetable, notes, files and WhatsApp
chats). Then it starts the local stand-ins the plugins talk to (fakes.py) and Doorman itself, as the user
who runs it, without privsep and with plugins in Doorman's process. Ctrl-C or `doorman-admin demo stop
--dir D` stops all of it. Run it again on the same D to continue where it stopped.

There is no phone app in the demo: `demo inbox`, `demo approve`, `demo deny`, `demo release` and `demo answer`
play the owner through the owner API, with a token only a demo's doorman.yaml carries (dev_owner_token)."""

import asyncio
import json
import logging
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from . import fakes, seed

STATE = "demo.json"       # marks a directory as a demo's; holds its ports and made-up secrets
RUN = "run.json"          # while it runs: the processes to stop
DEFAULT_PORT_BASE = 8730  # the real instance uses 8710/8711, the WhatsApp sidecar 8720
PORTS = {"agent": 0, "owner": 1, "imap": 2, "smtp": 3, "caldav": 4, "fakes": 5}
ZONE = "Europe/Amsterdam"


class DemoError(Exception):
    pass


def ports(state: dict) -> dict[str, int]:
    return {name: state["port_base"] + offset for name, offset in PORTS.items()}


def _write_private(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o600)


def load_state(directory: Path) -> dict:
    path = directory / STATE
    if not path.is_file():
        raise DemoError(f"{directory} isn't a demo made by `doorman-admin demo` (no {STATE} in it)")
    return json.loads(path.read_text())


def save_state(directory: Path, state: dict) -> None:
    _write_private(directory / STATE, json.dumps(state, indent=2))


def _new_state(directory: Path, port_base: int) -> dict:
    if directory.exists() and any(p.name != "demo.log" for p in directory.iterdir()):
        raise DemoError(f"{directory} exists and isn't empty; pick a new directory for the demo")
    directory.mkdir(parents=True, exist_ok=True)
    try:
        import aiosmtpd  # noqa: F401
        smtp = True
    except ImportError:
        smtp = False
    state = {
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"), "port_base": port_base,
        "owner_token": "demo-owner-" + secrets.token_urlsafe(18), "mail_password": secrets.token_urlsafe(12),
        "whatsapp_token": secrets.token_urlsafe(18), "agent_token": None, "seeded": [],
        "parts": {"mail": bool(fakes.dovecot_binary()) and smtp, "caldav": fakes.radicale_available(),
                  "whatsapp": True, "timetable": True},
    }
    save_state(directory, state)
    return state


def demo_plugins(directory: Path, state: dict) -> dict[str, dict]:
    """The demo's plugins, put into its database on every start (Registry.put_plugin) so their ports follow
    --port-base; switches the demo's owner changed stay."""
    p, parts = ports(state), state["parts"]
    plugins = {
        "notes": {"enabled": True},
        "files": {"enabled": True, "config": {"root": str(directory / "files"), "ocr": False}},
    }
    if parts.get("mail"):
        plugins["mail"] = {"type": "mail_imap", "enabled": True, "config": {
            "imap_host": "127.0.0.1", "imap_port": p["imap"], "imap_security": "none",
            "smtp_host": "127.0.0.1", "smtp_port": p["smtp"], "smtp_security": "none", "from_address": seed.OWNER}}
    if parts.get("caldav"):
        plugins["caldav"] = {"enabled": True, "config": {
            "url": f"http://127.0.0.1:{p['caldav']}/", "allow_http": True, "owner_emails": [seed.OWNER],
            "timezone": ZONE, "default_calendar": "Personal", "default_list": "Tasks"}}
        plugins["contacts"] = {"enabled": True, "config": {
            "url": f"http://127.0.0.1:{p['caldav']}/", "allow_http": True}}
    if parts.get("timetable"):
        plugins["timetable"] = {"type": "ics", "enabled": True, "config": {
            "label": "University timetable", "timezone": ZONE, "allow_http": True}}
    if parts.get("whatsapp"):
        plugins["whatsapp"] = {"enabled": True, "config": {"sidecar_url": f"http://127.0.0.1:{p['fakes']}"}}
    return plugins


def write_config(directory: Path, state: dict) -> Path:
    """doorman.yaml, written again on every start so the ports follow --port-base."""
    p = ports(state)
    config = {
        "data_dir": "./data",
        "vault_key_file_warn": False,  # the demo's made-up credentials sit behind data/vault.key on purpose
        "public_url": f"http://localhost:{p['owner']}",
        "agent_listen": f"127.0.0.1:{p['agent']}",
        "owner_listen": f"127.0.0.1:{p['owner']}",
        "agent_url": f"http://127.0.0.1:{p['agent']}",
        "owner_allow_cidrs": ["127.0.0.0/8"],
        "timezone": ZONE,
        "owner": {"identities": [seed.OWNER]},
        # the owner stand-in's way in (demo approve and friends); never in a real doorman.yaml
        "dev_owner_token": state["owner_token"],
        # in Doorman's own process, as the demo's user: no privsep, no sandbox, less memory
        "plugin_sandbox": False,
        "extract": {"ocr": False},
        # optional in a real Doorman; on here with its stand-in scorer, so the planted injection is held back
        "guard": {"enabled": True},
    }
    path = directory / "doorman.yaml"
    _write_private(path, "# Written by `doorman-admin demo` on every start: fake accounts only, don't edit.\n"
                   + yaml.safe_dump(config, sort_keys=False))
    return path


def write_agent_env(directory: Path, state: dict) -> Path:
    """agent.env (source it) and bin/doorman, the agent's command-line tool from this Doorman."""
    from .. import __file__ as package_file

    cli = Path(package_file).resolve().parent / "agent_skill" / "scripts" / "doorman.py"
    bin_dir = directory / "bin"
    bin_dir.mkdir(exist_ok=True)
    wrapper = bin_dir / "doorman"
    wrapper.write_text(f"#!/bin/sh\nexec {sys.executable} {cli} \"$@\"\n")
    wrapper.chmod(0o755)
    env = directory / "agent.env"
    _write_private(env, f"# The Doorman demo in {directory}: `source` this, then e.g. `doorman caps --brief`\n"
                   f"export DOORMAN_URL=http://127.0.0.1:{ports(state)['agent']}\n"
                   f"export DOORMAN_TOKEN={state['agent_token']}\n"
                   f"export PATH=\"{bin_dir}:$PATH\"\n")
    return env


def demo_scorer(texts: list[str]) -> list[dict]:
    """The injection guard's stand-in in the demo, so it needs no 316 MB model: a few telltale phrases
    score 0.97, everything else 0.01. It catches the planted mail, and little else."""
    out = []
    for text in texts:
        low = text.lower()
        hits = sorted((low.find(m), m) for m in seed.INJECTION_MARKERS if m in low)
        out.append({"score": 0.97, "start": hits[0][0], "end": hits[0][0] + len(hits[0][1])} if hits
                   else {"score": 0.01, "start": 0, "end": min(len(text), 50)})
    return out


# ------------------------------------------------------------------------------------------ seeding


def seed_files(directory: Path, state: dict) -> None:
    root = directory / "files"
    for rel, text in seed.FILES.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    for rel, lines in seed.FILES_PDF.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(seed.minimal_pdf(lines))
    fake_dir = directory / "fakes"
    fake_dir.mkdir(exist_ok=True)
    today = datetime.now(seed.ZONE).date()
    (fake_dir / "timetable.ics").write_text(seed.timetable_ics(today))
    (fake_dir / "whatsapp.json").write_text(json.dumps(seed.whatsapp(datetime.now(seed.ZONE)), indent=1,
                                                       ensure_ascii=False))


def seed_mail(port: int, password: str) -> None:
    from imapclient import IMAPClient

    client = IMAPClient("127.0.0.1", port=port, ssl=False)
    client.login(seed.MAIL_USER, password)
    try:
        for mail in seed.mails(datetime.now(seed.ZONE)):
            client.append(mail["folder"], mail["message"].as_bytes(), flags=mail["flags"], msg_time=mail["when"])
    finally:
        client.logout()


def seed_caldav(port: int) -> None:
    import caldav

    principal = caldav.DAVClient(url=f"http://127.0.0.1:{port}/", username=seed.MAIL_USER, password="x",
                                 require_tls=False).principal()
    personal = principal.make_calendar(name="Personal", supported_calendar_component_set=["VEVENT"])
    tasks = principal.make_calendar(name="Tasks", supported_calendar_component_set=["VTODO"])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    today = datetime.now(seed.ZONE).date()
    for day in seed.days_ahead(today):
        for j, (start, end, summary, where) in enumerate(seed.PERSONAL.get(day.weekday(), [])):
            # zone-aware times: stored with TZID=Europe/Amsterdam, as a phone's calendar app would
            personal.save_event(uid=f"demo-{day:%Y%m%d}-{j}@doorman.demo", dtstart=seed.local(day, start),
                                dtend=seed.local(day, end), summary=summary, location=where)
    for i, (summary, due_in, done) in enumerate(seed.TASKS):
        lines = [f"UID:demo-task-{i}@doorman.demo", f"DTSTAMP:{stamp}", f"SUMMARY:{summary}",
                 "STATUS:COMPLETED" if done else "STATUS:NEEDS-ACTION"]
        if due_in is not None:
            lines.append(f"DUE;VALUE=DATE:{today + timedelta(days=due_in):%Y%m%d}")
        if done:
            lines.append(f"COMPLETED:{stamp}")
        tasks.save_todo("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Doorman demo//EN\r\nBEGIN:VTODO\r\n"
                        + "\r\n".join(lines) + "\r\nEND:VTODO\r\nEND:VCALENDAR\r\n")
    personal.add_event(seed.invitation_ics(today))
    seed_flat(principal, today)


def seed_flat(principal, today) -> None:
    """The flat's calendar and shopping list, Lena's and shared with Sam. Radicale doesn't share, but it keeps
    properties it doesn't know: nc:owner-principal makes it look as Nextcloud shows a calendar shared with you."""
    flat = principal.make_calendar(name="Flat", supported_calendar_component_set=["VEVENT", "VTODO"])
    owner = ('<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:" xmlns:nc="http://nextcloud.com/ns"><d:set>'
             f'<d:prop><nc:owner-principal>{seed.FLAT_OWNER}</nc:owner-principal></d:prop></d:set></d:propertyupdate>')
    flat.client.proppatch(str(flat.url), owner)
    days, start, end, summary, where = seed.FLAT_EVENT
    day = today + timedelta(days=days)
    flat.save_event(uid="demo-flat-meeting@doorman.demo", dtstart=seed.local(day, start), dtend=seed.local(day, end),
                    summary=summary, location=where)
    for i, summary in enumerate(seed.FLAT_TASKS):
        flat.save_todo(uid=f"demo-flat-{i}@doorman.demo", summary=summary)


def seed_contacts(port: int) -> None:
    """The address book: one CardDAV collection made with an extended MKCOL, one vCard per contact."""
    import httpx

    book = f"http://127.0.0.1:{port}/{seed.MAIL_USER}/contacts/"
    mkcol = ('<d:mkcol xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav"><d:set><d:prop><d:resourcetype>'
             '<d:collection/><c:addressbook/></d:resourcetype><d:displayname>Contacts</d:displayname></d:prop>'
             '</d:set></d:mkcol>')
    with httpx.Client(auth=(seed.MAIL_USER, "x"), timeout=30) as client:
        client.request("MKCOL", book, content=mkcol.encode()).raise_for_status()
        for entry in seed.CONTACTS:
            client.put(f"{book}{entry[0]}.vcf", content=seed.contact_vcard(entry).encode(),
                       headers={"Content-Type": "text/vcard; charset=utf-8"}).raise_for_status()


def seed_engine(engine, state: dict) -> None:
    """Credentials for the fakes, the notes, and the agent's key."""
    p, parts = ports(state), state["parts"]
    if parts.get("mail"):
        engine.vault.set("mail", "username", seed.MAIL_USER)
        engine.vault.set("mail", "password", state["mail_password"])
    if parts.get("caldav"):
        engine.vault.set("caldav", "username", seed.MAIL_USER)
        engine.vault.set("caldav", "password", "x")
    if parts.get("timetable"):
        engine.vault.set("timetable", "url", f"http://127.0.0.1:{p['fakes']}/timetable.ics")
    if parts.get("whatsapp"):
        engine.vault.set("whatsapp", "sidecar_token", state["whatsapp_token"])
    notes = engine.registry.instance("notes")
    from .. import clock

    for title, body, tags in seed.NOTES:
        note_id = secrets.token_hex(4)
        notes.store(note_id, {"id": note_id, "title": title, "body": body, "tags": tags, "updated": clock.iso()})
    state["agent_token"] = engine.auth.create_key("demo-agent", "solo")


# ------------------------------------------------------------------------------------------ running


def _read_run(directory: Path) -> dict | None:
    try:
        return json.loads((directory / RUN).read_text())
    except (OSError, ValueError):
        return None


def _write_run(directory: Path, run: dict) -> None:
    _write_private(directory / RUN, json.dumps(run))


def _cmdline(pid: int) -> bytes:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return b""


def _is_demo_process(pid: int | None) -> bool:
    return fakes.alive(pid) and b"demo" in _cmdline(pid)


def _clean_leftovers(directory: Path) -> None:
    """What a demo that was killed (rather than stopped) left running."""
    run = _read_run(directory)
    if not run:
        return
    radicale = run.get("radicale_pid")
    if radicale and b"radicale" in _cmdline(radicale):
        fakes.stop_process(radicale)
    fakes.stop_dovecot(run.get("dovecot_run"))
    (directory / RUN).unlink(missing_ok=True)


def run(directory: Path, port_base: int | None = None) -> None:
    """Create the demo if it's new, start the fakes and Doorman, and keep running until Ctrl-C or SIGTERM;
    then stop everything it started."""
    directory = directory.expanduser().resolve()
    if os.geteuid() == 0:
        raise DemoError("the demo doesn't run as root; start it as an ordinary user")
    running = _read_run(directory)
    if running and _is_demo_process(running.get("pid")):
        raise DemoError(f"the demo in {directory} is already running (pid {running['pid']}); "
                        f"`doorman-admin demo stop --dir {directory}` first")
    _clean_leftovers(directory)
    fresh = not (directory / STATE).exists()
    state = _new_state(directory, port_base or DEFAULT_PORT_BASE) if fresh else load_state(directory)
    if port_base and port_base != state["port_base"]:
        state["port_base"] = port_base
        save_state(directory, state)
    p = ports(state)
    busy = [f"{name} {port}" for name, port in p.items() if not fakes.port_free(port)]
    if busy:
        raise DemoError(f"ports in use: {', '.join(busy)}; pass another --port-base (it uses six ports from it)")

    # a stop before Doorman serves: unwind through the finally below. While it serves, uvicorn takes the
    # signal first, shuts down, and passes it on to this handler, which then has nothing left to do.
    serving = {"on": False}

    def on_signal(signum, frame):
        if not serving["on"]:
            raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    run_state = {"pid": os.getpid(), "ready": False}
    _write_run(directory, run_state)
    smtp = http = engine = None
    try:
        if "files" not in state["seeded"]:
            seed_files(directory, state)
            state["seeded"].append("files")
            save_state(directory, state)
        parts = state["parts"]
        if parts.get("mail"):
            run_state["dovecot_run"] = fakes.dovecot_run_dir()
            _write_run(directory, run_state)
            fakes.start_dovecot(directory / "fakes" / "dovecot", p["imap"], seed.MAIL_USER, state["mail_password"],
                                run_state["dovecot_run"])
            smtp = fakes.start_smtp(p["smtp"], directory / "outbox")
            if "mail" not in state["seeded"]:
                seed_mail(p["imap"], state["mail_password"])
                state["seeded"].append("mail")
                save_state(directory, state)
        if parts.get("caldav"):
            radicale = fakes.start_radicale(directory / "fakes" / "radicale", p["caldav"],
                                            directory / "fakes" / "radicale.log")
            run_state["radicale_pid"] = radicale.pid
            _write_run(directory, run_state)
            if "caldav" not in state["seeded"]:
                seed_caldav(p["caldav"])
                state["seeded"].append("caldav")
                save_state(directory, state)
            if "contacts" not in state["seeded"]:  # the same Radicale serves CardDAV
                seed_contacts(p["caldav"])
                state["seeded"].append("contacts")
                save_state(directory, state)
        whatsapp = fakes.WhatsAppState(directory / "fakes" / "whatsapp.json") if parts.get("whatsapp") else None
        http = fakes.start_http(p["fakes"], directory / "fakes" / "timetable.ics", whatsapp, state["whatsapp_token"])

        from .. import config
        from ..engine import Engine
        from ..guard import Guard
        from ..server import serve

        os.environ.pop("DOORMAN_VAULT_KEY", None)  # the demo's vault has its own key, in data/vault.key
        Guard.backend = staticmethod(demo_scorer)
        engine = Engine(config.load(write_config(directory, state)), starter_plugins=False)
        for name, block in demo_plugins(directory, state).items():
            engine.registry.put_plugin(name, block)
        if "engine" not in state["seeded"]:
            seed_engine(engine, state)
            state["seeded"].append("engine")
            save_state(directory, state)
        if parts.get("caldav") and not engine.vault.get("contacts"):  # also for a demo made before contacts
            engine.vault.set("contacts", "username", seed.MAIL_USER)
            engine.vault.set("contacts", "password", "x")
        env = write_agent_env(directory, state)
        run_state["ready"] = True
        _write_run(directory, run_state)
        print(banner(directory, state, env), flush=True)
        serving["on"] = True
        asyncio.run(serve(engine))
    except KeyboardInterrupt:
        pass
    except fakes.FakeError as exc:
        raise DemoError(str(exc)) from None
    finally:
        serving["on"] = False
        signal.signal(signal.SIGTERM, signal.SIG_IGN)  # a second stop mustn't cut the cleanup short
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        _shutdown(directory, run_state, smtp, http, engine)
        print("demo stopped", flush=True)


def _shutdown(directory: Path, run_state: dict, smtp, http, engine) -> None:
    from ..plugin_host import stop_all

    stop_all()
    if engine is not None:
        engine.guard.stop()
        engine.extractor.stop()
    if http is not None:
        http.shutdown()
        http.server_close()
    if smtp is not None:
        smtp.stop()
    fakes.stop_process(run_state.get("radicale_pid"))
    fakes.stop_dovecot(run_state.get("dovecot_run"))
    (directory / RUN).unlink(missing_ok=True)


def banner(directory: Path, state: dict, env: Path) -> str:
    p, parts = ports(state), state["parts"]
    skipped = [name for name, on in parts.items() if not on]
    lines = [
        f"Doorman demo running in {directory} (made-up data, no real accounts)",
        f"  agent API  http://127.0.0.1:{p['agent']}    owner API  http://127.0.0.1:{p['owner']}",
        f"  plugins    notes, files{', mail' if parts.get('mail') else ''}"
        f"{', caldav, contacts' if parts.get('caldav') else ''}{', timetable (ics)' if parts.get('timetable') else ''}"
        f"{', whatsapp' if parts.get('whatsapp') else ''}",
    ]
    if skipped:
        lines.append(f"  left out  {', '.join(skipped)} (dovecot, aiosmtpd or radicale missing)")
    lines += [
        f"  agent      source {env}   then: doorman caps --brief",
        f"  owner      doorman-admin demo inbox|approve|deny|release|answer --dir {directory}",
        f"  sent mail  {directory / 'outbox'}",
        f"  stop       Ctrl-C, or doorman-admin demo stop --dir {directory}",
    ]
    return "\n".join(lines)


def start_background(directory: Path, port_base: int | None = None, timeout: float = 120) -> None:
    """Start the demo as a process of its own (output in demo.log) and come back once it serves."""
    directory = directory.expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)
    log = directory / "demo.log"
    import doorman

    env = {**os.environ, "PYTHONPATH": os.pathsep.join(
        [str(Path(doorman.__file__).resolve().parent.parent), os.environ.get("PYTHONPATH", "")]).rstrip(os.pathsep)}
    command = [sys.executable, "-m", "doorman.admin", "demo", "start", "--dir", str(directory)]
    if port_base:
        command += ["--port-base", str(port_base)]
    with open(log, "ab") as out:
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                env=env, start_new_session=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            tail = log.read_text(errors="replace").splitlines()[-15:]
            raise DemoError("the demo didn't start:\n" + "\n".join(tail))
        state = _read_run(directory)
        if state and state.get("pid") == proc.pid and state.get("ready") and _health(directory):
            print(banner(directory, load_state(directory), directory / "agent.env"))
            print(f"  log        {log}")
            return
        time.sleep(0.3)
    raise DemoError(f"the demo didn't come up within {timeout:g} s; see {log}")


def _health(directory: Path) -> bool:
    try:
        port = ports(load_state(directory))["agent"]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as response:
            return response.status == 200
    except (OSError, DemoError, ValueError):
        return False


def stop(directory: Path, timeout: float = 30) -> bool:
    """Stop a running demo: SIGTERM, and what's still there after timeout seconds is killed."""
    directory = directory.expanduser().resolve()
    load_state(directory)  # only ever a demo's directory
    run_state = _read_run(directory)
    pid = (run_state or {}).get("pid")
    if not _is_demo_process(pid):
        _clean_leftovers(directory)
        return False
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and fakes.alive(pid):
        time.sleep(0.2)
    if fakes.alive(pid):
        os.kill(pid, signal.SIGKILL)
        time.sleep(0.3)
    _clean_leftovers(directory)
    return True


# ------------------------------------------------------------------------------------------ the owner


def owner_api(directory: Path, method: str, path: str, body: dict | None = None) -> dict:
    """The owner API of the running demo, with its dev_owner_token: only a demo's doorman.yaml sets one."""
    state = load_state(directory.expanduser().resolve())
    request = urllib.request.Request(
        f"http://127.0.0.1:{ports(state)['owner']}{path}", method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {state['owner_token']}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read())
        except ValueError:
            payload = {}
        raise DemoError(payload.get("reason") or payload.get("error") or f"HTTP {exc.code}") from None
    except urllib.error.URLError as exc:
        raise DemoError(f"the demo isn't running ({exc.reason}); start it with `doorman-admin demo --dir "
                        f"{directory}`") from None


def inbox(directory: Path) -> list[str]:
    box = owner_api(directory, "GET", "/owner/inbox")
    lines = []
    for approval in box["approvals"]:
        for entry in approval["entries"]:
            failed = [c.get("detail") or c.get("name") for c in (entry.get("checks") or {}).get("checks") or []
                      if not c.get("ok")]
            lines.append(f"approval {approval['id']}: {entry.get('summary') or entry.get('tool')}")
            outgoing = entry.get("outgoing") or {}  # what the app's card shows goes out
            lines += [f"    {line}" for line in str(outgoing.get("text") or outgoing.get("title") or "").splitlines()]
            lines += [f"    warning: {detail}" for detail in failed]
    for cs in box["changesets"]:
        lines.append(f"changeset:{cs['id']}: {cs.get('title') or ''} ({len(cs.get('items') or [])} changes)")
    for question in box.get("questions") or []:  # an agent asks (doorman ask-owner)
        options = f" options: {' | '.join(question['options'])}" if question.get("options") else ""
        lines.append(f"question {question['id']} from {question.get('agent') or 'an agent'}: {question['question']}"
                     f"{options}; `demo answer {question['id']} \"...\"` answers it")
    for item in owner_api(directory, "GET", "/owner/quarantine?status=held")["items"]:
        lines.append(f"held {item['id']}: {item.get('label') or item.get('ref')} from {item.get('sender') or '?'} "
                     f"(guard score {item.get('score', 0):.2f}); `demo release {item['id']}` lets the agent read it")
    return lines or ["nothing waits for the owner"]


def decide(directory: Path, target: str | None, approve: bool, note: str | None = None) -> list[str]:
    """Approve or deny one approval (its id), apply or reject one changeset (changeset:<id>), or with
    target None every pending one."""
    if target is None:
        box = owner_api(directory, "GET", "/owner/inbox")
        targets = [str(a["id"]) for a in box["approvals"]] + [f"changeset:{c['id']}" for c in box["changesets"]]
        if not targets:
            return ["nothing waits for the owner"]
    else:
        targets = [target]
    out = []
    for item in targets:
        if item.startswith("changeset:"):
            cs = int(item.split(":", 1)[1])
            if approve:
                result = owner_api(directory, "POST", f"/owner/changesets/{cs}/apply", {})
                out.append(f"changeset {cs} applied: {result.get('status', result)}")
            else:
                owner_api(directory, "POST", f"/owner/changesets/{cs}/reject", {"comment": note or ""})
                out.append(f"changeset {cs} rejected")
            continue
        approval_id = int(item)
        if approve:
            seen = owner_api(directory, "GET", f"/owner/approvals/{approval_id}")
            result = owner_api(directory, "POST", f"/owner/approvals/{approval_id}/decide",
                               {"approve": True, "payload_hash": seen["payload_hash"]})
            done = ", ".join(str(r.get("status")) for r in result.get("results") or [])
            out.append(f"approval {approval_id} approved: {done or result.get('status')}")
        else:
            owner_api(directory, "POST", f"/owner/approvals/{approval_id}/decide", {"approve": False, "note": note})
            out.append(f"approval {approval_id} denied")
    return out


def answer(directory: Path, qid: int, text: str | None) -> str:
    """The owner's answer to an agent's question (doorman ask-owner): text, an option's number from 1, or
    without text a dismissal."""
    if not text:
        owner_api(directory, "POST", f"/owner/questions/{qid}/dismiss", {})
        return f"question {qid} dismissed"
    body = {"option": int(text) - 1} if text.isdigit() else {"answer": text}
    out = owner_api(directory, "POST", f"/owner/questions/{qid}/answer", body)
    return f"question {qid} answered: {out.get('answer')}"


def release(directory: Path, qid: int) -> str:
    owner_api(directory, "POST", f"/owner/quarantine/{qid}/release", {})
    return f"released held item {qid}: the agent can read it now"
