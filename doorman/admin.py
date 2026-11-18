"""doorman-admin: set up and run Doorman on its own host."""

import argparse
import asyncio
import getpass
import json
import logging
import os
import shutil
import sys
from pathlib import Path
from zoneinfo import ZoneInfo

from . import backup, clock, config, upkeep
from .auth import MIN_PASSWORD
from .engine import Engine
from .db import SchemaTooNew
from .vault import VaultKeyError
from .util import normalize

EXAMPLE = Path(__file__).resolve().parent / "doorman.example.yaml"


def _config_path(args) -> Path:
    return Path(args.config or os.environ.get("DOORMAN_CONFIG") or "doorman.yaml")


def _load(path: Path) -> config.Config:
    try:
        return config.load(path)
    except config.PluginsInConfig as exc:
        sys.exit(f"refusing to start: {exc}")


def _engine(args) -> Engine:
    path = _config_path(args)
    if not path.exists():
        sys.exit(f"no config at {path}; run `doorman-admin init` first")
    try:
        return Engine(_load(path))
    except (VaultKeyError, SchemaTooNew) as exc:
        sys.exit(f"refusing to start: {exc}")


def cmd_init(args) -> None:
    target = Path(args.config or "doorman.yaml")
    if target.exists():
        print(f"{target} already exists")
    else:
        shutil.copy(EXAMPLE, target)
        print(f"wrote {target}; edit it, then run `doorman-admin setup-code` and `doorman-admin serve`")
    engine = Engine(config.load(target))
    print(f"data directory: {engine.config.data_dir}")


def cmd_serve(args) -> None:
    from .server import serve

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    engine = _engine(args)
    sign_in_fits(engine)
    if engine.config.get("dev_owner_token"):
        logging.warning("dev_owner_token is set: anyone with it can act as the owner. Remove it in production.")
    asyncio.run(serve(engine))


def cmd_key(args) -> None:
    engine = _engine(args)
    if args.action == "create":
        token = engine.auth.create_key(args.name, args.role)
        print(f"agent key for {args.name} ({args.role}). It is shown once:\n{token}")
    elif args.action == "list":
        for key in engine.auth.list_keys():
            print(f"{key['id']:>3}  {key['name']:<20} {key['role']:<7} {key['created']}  "
                  f"{'revoked' if key['revoked'] else 'active'}")
    elif args.action == "revoke":
        engine.auth.revoke_key(int(args.name))
        print("revoked")


def cmd_setup_code(args) -> None:
    engine = _engine(args)
    if engine.auth.sign_in() == "password":
        sys.exit("this Doorman signs in with a password, so there is no passkey to register. To change the "
                 "password: doorman-admin sign-in password. To use a passkey: doorman-admin sign-in passkey")
    code = engine.auth.create_setup_code()
    print(f"setup code (valid 30 minutes): {code}\nopen {engine.public_url}/app/ and register your passkey")


def sign_in_fits(engine: Engine) -> None:
    """`approval_passkey` signs every approval with the passkey, and a password Doorman has none."""
    if engine.config.get("approval_passkey") and engine.auth.sign_in() == "password":
        sys.exit("refusing to start: approval_passkey is on in doorman.yaml, but this Doorman signs in with a "
                 "password. Switch approval_passkey off, or go back to a passkey: doorman-admin sign-in passkey")


def _typed_password() -> str:
    """Typed twice at a terminal; one line from a pipe (the setup script's)."""
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass(f"New password for the owner app (at least {MIN_PASSWORD} characters): ")
    if getpass.getpass("Once more: ") != first:
        sys.exit("the two don't match; nothing changed")
    return first


def cmd_sign_in(args) -> None:
    """How the owner logs in to the app: a passkey (needs HTTPS and a domain, or localhost) or a password.
    One or the other. Switching logs every device out; choosing the password again changes it."""
    engine = _engine(args)
    current = engine.auth.sign_in()
    if args.method is None:
        other = "password" if current == "passkey" else "passkey"
        print(f"the owner app signs in with a {current}; `doorman-admin sign-in {other}` switches")
        return
    if args.method == "password":
        if engine.config.get("approval_passkey"):
            sys.exit("approval_passkey is on in doorman.yaml: approvals are signed with the passkey. Switch it "
                     "off first; nothing changed")
        try:
            engine.auth.set_password(_typed_password())
        except ValueError as exc:
            sys.exit(f"{exc}; nothing changed")
        with engine.db.tx() as conn:  # one or the other: no passkey stays behind that could still log in
            passkeys = conn.execute("DELETE FROM webauthn_credentials").rowcount
        engine.auth.logout_all()
        removed = f" Removed {passkeys} passkey{'' if passkeys == 1 else 's'}." if passkeys else ""
        print(f"the owner app now signs in with this password, at {engine.public_url}/app/. Every device is "
              f"logged out.{removed}")
        if not engine.public_url.startswith("https://"):
            print("Without HTTPS, others on the network can read the password and what the app shows, and "
                  "browsers give no notifications: you see what waits when you open the app.")
        return
    engine.auth.clear_password()
    engine.auth.logout_all()
    code = engine.auth.create_setup_code()
    print(f"the owner app signs in with a passkey again. Every device is logged out.\n"
          f"setup code (valid 30 minutes): {code}\nopen {engine.public_url}/app/ and register your passkey")


def cmd_logout_all(args) -> None:
    engine = _engine(args)
    ended = engine.auth.logout_all()
    print(f"ended {ended['sessions']} owner session(s) and dropped {ended['push']} push subscription(s). Each "
          f"device needs its passkey to log in again, and gets pushes again once it has. For a lost device, also "
          f"remove its passkey (More → Passkeys)")


def cmd_vault(args) -> None:
    engine = _engine(args)
    if args.action == "set":
        value = args.value if args.value is not None else getpass.getpass(f"{args.plugin}.{args.key}: ")
        engine.vault.set(args.plugin, args.key, value)
        engine.registry.invalidate(args.plugin)
        print("stored")
    elif args.action == "list":
        for plugin, keys in engine.vault.keys().items():
            print(f"{plugin}: {', '.join(keys)}")
    elif args.action == "delete":
        engine.vault.delete(args.plugin, args.key)
        print("deleted")


def cmd_trust(args) -> None:
    engine = _engine(args)
    if args.action == "add":
        value = normalize(args.kind, args.value)
        engine.db.exec("INSERT OR IGNORE INTO trust(kind, value, label, created) VALUES(?,?,?,?)",
                       (args.kind, value, args.label or "", clock.iso()))
        print(f"trusted {args.kind} {value}")
    else:
        for row in engine.db.all("SELECT * FROM trust ORDER BY kind, value"):
            print(f"{row['id']:>3}  {row['kind']:<6} {row['value']:<40} {row['label']}")


def _plugin_folders(args) -> list[Path]:
    """Every plugin folder Doorman would load: the built-in ones and those under the config's plugin_paths."""
    from .registry import BUILTIN_DIR

    bases = [BUILTIN_DIR]
    path = _config_path(args)
    if path.exists():
        import yaml

        data = yaml.safe_load(path.read_text()) or {}
        bases += [Path(p) for p in data.get("plugin_paths") or []]  # as registry.discover takes them
    return [folder for base in bases if base.is_dir() for folder in sorted(base.iterdir())
            if (folder / "manifest.yaml").is_file()]


def check_plugin_folder(folder: Path) -> tuple[list[str], list[str]]:
    """(errors, warnings) for one plugin folder: its manifest (manifest_check.check) and, when that has no
    errors, whether plugin.py has what the manifest names. This imports plugin.py, as running Doorman
    with the plugin would."""
    import importlib.util

    from . import manifest_check
    from .registry import merged_manifest

    try:
        manifest = merged_manifest(folder)
    except Exception as exc:  # noqa: BLE001 - YAML errors, a missing base: the problem to report
        return [f"{type(exc).__name__}: {exc}"], []
    errors, warnings = manifest_check.check(manifest)
    if errors:
        return errors, warnings
    if not (folder / "plugin.py").is_file():
        return ["there's no plugin.py next to the manifest"], warnings
    try:
        spec = importlib.util.spec_from_file_location(f"doorman_check_{folder.name}", folder / "plugin.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        plugin_cls = module.Plugin
    except Exception as exc:  # noqa: BLE001 - an import error is the problem to report
        return [f"plugin.py doesn't load: {type(exc).__name__}: {exc}"], warnings
    return manifest_check.check_code(plugin_cls, manifest), warnings


def cmd_plugin_check(args) -> None:
    """doorman-admin plugin check [<folder|name>]: every problem with its manifest's path; exit 1 on errors."""
    target = args.name
    if target is None:
        folders = _plugin_folders(args)
    elif Path(target).exists():
        folders = [Path(target).parent if Path(target).name == "manifest.yaml" else Path(target)]
    else:
        folders = [f for f in _plugin_folders(args) if f.name == target]
        if not folders:
            sys.exit(f"no plugin folder named {target}; give its path instead")
    failed = False
    for folder in folders:
        errors, warnings = check_plugin_folder(folder)
        where = folder / "manifest.yaml"
        for error in errors:
            print(f"{where}: error: {error}")
        for warning in warnings:
            print(f"{where}: warning: {warning}")
        if not errors and not warnings:
            print(f"{where}: ok")
        failed = failed or bool(errors)
    if failed:
        sys.exit(1)


def cmd_plugins(args) -> None:
    if args.action == "check":
        return cmd_plugin_check(args)
    engine = _engine(args)
    if args.action in ("on", "off"):
        engine.plugin_setup.switch(args.name, enabled=args.action == "on")
    for plugin in engine.registry.list():
        state = "on" if plugin["enabled"] else "off"
        if plugin["read_only"]:
            state += ", read-only"
        missing = f"  missing credentials: {', '.join(plugin['missing_credentials'])}" \
            if plugin["missing_credentials"] else ""
        print(f"{plugin['name']:<12} {plugin['type']:<12} {state}{missing}")


def cmd_journal(args) -> None:
    engine = _engine(args)
    if args.action == "verify":
        ok, bad = engine.journal.verify()
        print("journal chain intact" if ok else f"journal chain broken at entry {bad}")
        sys.exit(0 if ok else 1)
    for entry in reversed(engine.journal.list(limit=args.limit, include_denied=True)):
        print(f"{entry['id']:>5}  {entry['ts']}  {entry['status']:<16} {entry['summary']}")


def cmd_maintain(args) -> None:
    engine = _engine(args)
    engine.registry.instance(args.name).maintenance()
    print("done")


def cmd_job(args) -> None:
    engine = _engine(args)
    jobs = engine.registry.manifest(args.name).get("jobs") or []
    job = next((j for j in jobs if j["name"] == args.job), None) if args.job else (jobs[0] if jobs else None)
    if job is None:
        sys.exit(f"{args.name} has no job {args.job or ''}".rstrip() + f" (jobs: {', '.join(j['name'] for j in jobs) or 'none'})")
    budget = args.budget or float(job.get("budget_seconds", 120))
    status = engine.registry.instance(args.name).run_job(job["name"], budget)
    # events the run returned go into the feed and to the triggers, as from the worker: the plugin has already
    # noted them as seen, so printing them alone would lose them
    print(json.dumps(engine.job_events(args.name, job["name"], status), indent=2, ensure_ascii=False))


def cmd_index(args) -> None:
    """The search index: its state per source; --pull asks sources for what changed now, --rebuild feeds a
    source (or every one) again from the start, --upkeep runs stems and vectors for a while."""
    import time

    engine = _engine(args)
    names = [args.name] if args.name else [s["name"] for s in engine.search.status()["sources"]]
    if args.rebuild:
        for name in names:
            engine.library.rebuild(name)
    out = {}
    if args.pull or args.rebuild:
        out["pulled"] = {name: engine.search.pull(name, args.budget, wait=True) for name in names}
    if args.upkeep:
        out["upkeep"] = engine.library.run(time.monotonic() + args.budget)
    out["index"] = engine.search.status()
    print(json.dumps(out, indent=2, ensure_ascii=False))


def cmd_login(args) -> None:
    engine = _engine(args)
    plugin = engine.registry.instance(args.name)
    if not hasattr(plugin, "interactive_login"):
        sys.exit(f"{args.name} has no interactive login")
    if engine.registry.manifest(args.name).get("login") == "oauth" and plugin.config.get("login_flow") == "device":
        result = engine.plugin_setup.logged_in(args.name, plugin.device_login(print))
        print(f"Connected {result.get('account') or args.name}.")
    elif engine.registry.manifest(args.name).get("login") == "oauth":
        plugin.interactive_login(print, finish=lambda url: engine.plugin_setup.login_finish(args.name, url))
    else:
        plugin.interactive_login(print)


def cmd_backup(args) -> None:
    engine = _engine(args)
    if args.dest == "status":
        print(backup_status_text(engine))
        return
    settings = upkeep.settings(engine)
    keep = args.keep if args.keep is not None else int(settings.get("keep", 14))
    try:
        run = upkeep.run_backup(engine, dest=args.dest, keep=keep, config_path=_config_path(args))
    except backup.BackupError as exc:
        sys.exit(str(exc))
    if not run["ok"]:
        sys.exit(f"backup failed: {run['error']}")
    print(f"backed up to {run['path']} (keeping {keep}); the vault key is not in it, so keep it elsewhere too")
    if run["copy"]:
        print("copied off the host" if run["copy"]["ok"] else f"copying it off the host failed: {run['copy']['error']}")
        if not run["copy"]["ok"]:
            sys.exit(1)


def _local(engine, iso: str | None) -> str:
    if not iso:
        return "-"
    zone = ZoneInfo(engine.config.get("timezone") or "UTC")
    return clock.parse(iso).astimezone(zone).strftime("%Y-%m-%d %H:%M %Z")


def backup_status_text(engine) -> str:
    """doorman-admin backup status: the schedule, the last run and the next, in the owner's timezone."""
    s = upkeep.settings(engine)
    zone = engine.config.get("timezone") or "UTC"
    if not s.get("dir"):
        schedule = "off: set backup.dir in doorman.yaml (and backup.schedule, default 03:30)"
    elif not s.get("schedule"):
        schedule = f"off (backup.schedule isn't set); doorman-admin backup writes into {s['dir']}"
    else:
        schedule = f"every day at {upkeep.schedule_label(engine)} ({zone}) into {s['dir']}, keeping {s.get('keep', 14)}"
    lines = [f"schedule:  {schedule}",
             f"copy:      {s['copy_command'] if s.get('copy_command') else 'none: backups stay on this host (backup.copy_command)'}"]
    run = upkeep.last_run(engine)
    last_good = engine.db.get_setting("last_backup")
    if not run:
        lines.append(f"last run:  {'none' if not last_good else 'unknown'}")
    elif not run.get("finished"):
        lines.append(f"last run:  started {_local(engine, run['started'])}, not finished (still running, or cut off)")
    elif run["ok"]:
        copy = run.get("copy")
        copied = "" if not copy else ", copied off the host" if copy["ok"] else f", but the copy failed: {copy['error']}"
        lines.append(f"last run:  {_local(engine, run['started'])}, ok: {run['path']}{copied}")
    else:
        lines.append(f"last run:  {_local(engine, run['started'])}, failed: {run['error']}")
    lines.append(f"last good: {_local(engine, last_good)}")
    try:
        upcoming = upkeep.next_backup(engine)
        lines.append(f"next run:  {_local(engine, clock.iso(upcoming)) if upcoming else '-'}"
                     + (" (as soon as Doorman's worker runs)" if upcoming and upcoming <= clock.now() else ""))
    except backup.BackupError as exc:
        lines.append(f"next run:  never: {exc}")
    return "\n".join(lines)


def cmd_restore(args) -> None:
    config_path = _config_path(args)
    data_dir = Path(args.data_dir) if args.data_dir else None
    if data_dir is None:
        if not config_path.exists():
            sys.exit("pass --data-dir, or --config pointing at doorman.yaml to restore into")
        data_dir = _load(config_path).data_dir
    extra_paths = ((_load(config_path).get("backup") or {}).get("extra_paths") or []) if config_path.exists() else []
    try:
        manifest = backup.restore(Path(args.backup), data_dir, config_path=config_path if args.with_config else None,
                                  force=args.force, extra_paths=extra_paths)
    except backup.BackupError as exc:
        sys.exit(f"restore failed: {exc}")
    print(f"restored the backup from {manifest['created']} into {data_dir}. Start Doorman with the same "
          f"vault key as before (DOORMAN_VAULT_KEY or vault.key).")


def cmd_guard(args) -> None:
    engine = _engine(args)
    if args.action == "fetch":
        print(f"downloading {engine.guard.status()['model']['name']} into {engine.guard.model_dir} ...")
        status = engine.guard.fetch(wait=True)
        if status["download"]["state"] != "done":
            sys.exit(f"download failed: {status['download']['error']}")
        print("done; the guard uses it from the next scan")
    elif args.action == "scan":
        text = sys.stdin.read() if args.text in (None, "-") else args.text
        result = engine.guard.scores([text])[0]
        engine.guard.stop()
        verdict = "held back" if result["score"] >= engine.guard.threshold else "passes"
        print(f"score {result['score']:.4f} ({verdict} at threshold {engine.guard.threshold:g})")
    else:
        status = engine.guard.status()
        print(json.dumps({k: status[k] for k in ("state", "enabled", "threshold", "locked", "held", "error")},
                         indent=2))


def cmd_extract(args) -> None:
    """The text Doorman's extractor gets out of a file, as an agent would read it."""
    engine = _engine(args)
    path = Path(args.file)
    try:
        out = engine.extractor.extract(path.name, path.read_bytes(), None, ocr=not args.no_ocr)
    finally:
        engine.extractor.stop()
    for key in ("pages", "ocr_pages", "note"):
        if out.get(key):
            print(f"{key}: {out[key]}", file=sys.stderr)
    print(out.get("text") or "")


def cmd_task(args) -> None:
    engine = _engine(args)
    task_id = engine.tasks.create(" ".join(args.text))
    print(f"task {task_id} created")


def cmd_demo(args) -> None:
    from . import demo

    directory = Path(args.dir)
    try:
        if args.action == "start" and args.background:
            demo.start_background(directory, args.port_base)
        elif args.action == "start":
            demo.run(directory, args.port_base)
        elif args.action == "stop":
            print("demo stopped" if demo.stop(directory) else "the demo wasn't running")
        elif args.action == "inbox":
            print("\n".join(demo.inbox(directory)))
        elif args.action == "release":
            if not args.id:
                sys.exit("which held item? doorman-admin demo release <id> --dir ...")
            print(demo.release(directory, int(args.id)))
        elif args.action == "answer":
            if not args.id or not args.id.isdigit():
                sys.exit("which question? doorman-admin demo answer <id> \"the answer\" --dir ... (no answer: "
                         "dismiss it)")
            print(demo.answer(directory, int(args.id), args.text))
        else:
            if bool(args.id) == bool(args.all):
                sys.exit(f"{args.action} one item (an approval id, or changeset:<id>) or --all")
            print("\n".join(demo.decide(directory, args.id, args.action == "approve", args.note)))
    except demo.DemoError as exc:
        sys.exit(str(exc))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="doorman-admin", description=__doc__)
    parser.add_argument("--config", help="path to doorman.yaml (default: $DOORMAN_CONFIG or ./doorman.yaml)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="write doorman.yaml and create the data directory").set_defaults(fn=cmd_init)
    sub.add_parser("serve", help="run the APIs and the worker").set_defaults(fn=cmd_serve)
    sub.add_parser("setup-code", help="one-time code to register the first passkey").set_defaults(fn=cmd_setup_code)
    sign_in = sub.add_parser("sign-in", help="how you log in to the owner app: a passkey, or a password where "
                             "the app has no HTTPS address; without an argument, says which it is")
    sign_in.add_argument("method", nargs="?", choices=["passkey", "password"])
    sign_in.set_defaults(fn=cmd_sign_in)
    sub.add_parser("logout-all", help="log out every device of the owner app and stop all pushes "
                   "(a lost phone)").set_defaults(fn=cmd_logout_all)

    key = sub.add_parser("key", help="agent keys")
    key.add_argument("action", choices=["create", "list", "revoke"])
    key.add_argument("name", nargs="?", default="agent", help="key name, or key id for revoke")
    key.add_argument("--role", choices=["solo", "reader", "actor"], default="solo")
    key.set_defaults(fn=cmd_key)

    vault = sub.add_parser("vault", help="plugin credentials")
    vault.add_argument("action", choices=["set", "list", "delete"])
    vault.add_argument("plugin", nargs="?")
    vault.add_argument("key", nargs="?")
    vault.add_argument("--value", help="value (prompted if left out)")
    vault.set_defaults(fn=cmd_vault)

    trust = sub.add_parser("trust", help="trust lists")
    trust.add_argument("action", choices=["add", "list"])
    trust.add_argument("kind", nargs="?", choices=["email", "phone", "iban", "chat", "url"])
    trust.add_argument("value", nargs="?")
    trust.add_argument("--label")
    trust.set_defaults(fn=cmd_trust)

    plugins = sub.add_parser("plugins", aliases=["plugin"],
                             help="list plugins, switch one on/off, check a plugin's manifest and code "
                                  "(check [<folder|name>]; it imports plugin.py)")
    plugins.add_argument("action", nargs="?", choices=["list", "on", "off", "check"], default="list")
    plugins.add_argument("name", nargs="?")
    plugins.set_defaults(fn=cmd_plugins)

    journal = sub.add_parser("journal", help="show the journal or verify its hash chain")
    journal.add_argument("action", nargs="?", choices=["show", "verify"], default="show")
    journal.add_argument("--limit", type=int, default=30)
    journal.set_defaults(fn=cmd_journal)

    maintain = sub.add_parser("maintain", help="run a plugin's maintenance now (e.g. rebuild the file index)")
    maintain.add_argument("name")
    maintain.set_defaults(fn=cmd_maintain)

    job = sub.add_parser("job", help="run one slice of a plugin's background job now (e.g. the mail archive sync)")
    job.add_argument("name")
    job.add_argument("job", nargs="?", help="default: the plugin's first job")
    job.add_argument("--budget", type=float, help="seconds for this run (default the job's budget_seconds)")
    job.set_defaults(fn=cmd_job)

    index = sub.add_parser("index", help="the search index: how far each source is; --pull, --rebuild, --upkeep")
    index.add_argument("name", nargs="?", help="one source (a plugin name); default every indexed one")
    index.add_argument("--pull", action="store_true", help="ask the sources for what changed now")
    index.add_argument("--rebuild", action="store_true", help="feed them again from the start (after a restore)")
    index.add_argument("--upkeep", action="store_true", help="stems and vectors for --budget seconds")
    index.add_argument("--budget", type=float, default=120, help="seconds per source or for the upkeep (default 120)")
    index.set_defaults(fn=cmd_index)

    login = sub.add_parser("login", help="interactive login for a plugin (Google Calendar, Outlook)")
    login.add_argument("name")
    login.set_defaults(fn=cmd_login)

    bk = sub.add_parser("backup", help="back up the database, vault and plugin data (never the vault key) and copy it "
                        "off the host (backup.copy_command); 'backup status': the schedule, the last run and the next")
    bk.add_argument("dest", nargs="?", help="directory for backups (default backup.dir), or 'status'")
    bk.add_argument("--keep", type=int, help="how many to keep (default backup.keep or 14)")
    bk.set_defaults(fn=cmd_backup)

    rs = sub.add_parser("restore", help="put a backup back; stop Doorman first")
    rs.add_argument("backup", help="a doorman-YYYYmmdd-HHMMSS directory")
    rs.add_argument("--data-dir", help="restore into this directory (default the config's data_dir)")
    rs.add_argument("--with-config", action="store_true", help="also put back doorman.yaml")
    rs.add_argument("--force", action="store_true", help="replace an existing doorman.db")
    rs.set_defaults(fn=cmd_restore)

    guard = sub.add_parser("guard", help="the injection guard: download its model, try a text, or show its state")
    guard.add_argument("action", nargs="?", choices=["status", "fetch", "scan"], default="status")
    guard.add_argument("text", nargs="?", help="scan: the text to score ('-' or nothing: stdin)")
    guard.set_defaults(fn=cmd_guard)

    extract = sub.add_parser("extract", help="show the text Doorman reads from a file (PDF, scan, image, Word)")
    extract.add_argument("file")
    extract.add_argument("--no-ocr", action="store_true", help="text layers only, no OCR")
    extract.set_defaults(fn=cmd_extract)

    task = sub.add_parser("task", help="create a task for the agent")
    task.add_argument("text", nargs="+")
    task.set_defaults(fn=cmd_task)

    dm = sub.add_parser("demo", help="Doorman with made-up data and local fakes, no real accounts (demo-only "
                        "owner commands: inbox, approve, deny, release, answer)")
    dm.add_argument("action", nargs="?", default="start",
                    choices=["start", "stop", "inbox", "approve", "deny", "release", "answer"])
    dm.add_argument("id", nargs="?", help="approve/deny: an approval id or changeset:<id>; release: a held item's "
                                          "id; answer: an agent's question")
    dm.add_argument("text", nargs="?", help="answer: the owner's answer (an option's number from 1, or text)")
    dm.add_argument("--dir", required=True, help="the demo's directory (created on the first start)")
    dm.add_argument("--port-base", type=int, help="first of six ports on 127.0.0.1 (default 8730)")
    dm.add_argument("--background", action="store_true", help="start: run detached, return once it serves")
    dm.add_argument("--all", action="store_true", help="approve/deny: everything that waits")
    dm.add_argument("--note", help="deny: a short word for the agent")
    dm.set_defaults(fn=cmd_demo)

    args = parser.parse_args(argv)
    if args.command == "demo" and os.geteuid() == 0:
        sys.exit("the demo doesn't run as root (it needs no privsep); run it as an ordinary user")
    if os.geteuid() == 0:
        _as_root(args, sys.argv[1:] if argv is None else list(argv))
    args.fn(args)


def _as_root(args, argv: list[str]) -> None:
    """Started as root (the Docker image does): `serve` keeps a small root process that starts each
    plugin as a Linux user of its own (privsep.py) and runs Doorman as Doorman's user; every other
    command just becomes Doorman's user, so nothing in the data directory ends up owned by root."""
    from . import privsep

    try:
        if args.command == "serve" and privsep.FD_ENV not in os.environ:
            path = _config_path(args)
            if not path.exists():
                sys.exit(f"no config at {path}; run `doorman-admin init` first")
            # a fresh interpreter with only privsep.py loaded stays root, not the whole doorman
            backup_dir = _backup_dir(path)
            os.execv(sys.executable, [sys.executable, "-m", "doorman.privsep", "--data-dir", str(_data_dir(path)),
                                      *(["--backup-dir", str(backup_dir)] if backup_dir else []),
                                      "--", sys.executable, "-m", "doorman.admin", *argv])
        privsep.drop_to(privsep.doorman_user())
    except privsep.PrivsepError as exc:
        sys.exit(f"refusing to run as root: {exc}")


def _data_dir(path: Path) -> Path:
    """The config's data directory, without creating it (that happens as Doorman's user)."""
    import yaml

    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    data_dir = Path(data.get("data_dir") or config.DEFAULTS["data_dir"])
    return data_dir if data_dir.is_absolute() else (path.parent / data_dir).resolve()


def _backup_dir(path: Path) -> Path | None:
    """The config's backup.dir (absolute; a relative one is the config's folder's), or None without one."""
    import yaml

    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    section = data.get("backup")
    folder = section.get("dir") if isinstance(section, dict) else None
    if not folder:
        return None
    folder = Path(folder)
    return folder if folder.is_absolute() else (path.parent / folder).resolve()


if __name__ == "__main__":
    main()
