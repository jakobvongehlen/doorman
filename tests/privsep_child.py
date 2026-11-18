"""Doorman's side of test_privsep.py: started by privsep.py as Doorman's user, it runs plugins and
helper processes through the root process and prints what each could reach, as JSON."""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from doorman import config, worker_process  # noqa: E402
from doorman.engine import Engine  # noqa: E402
from doorman.plugin_api import PluginError  # noqa: E402
from doorman.worker_process import Worker, WorkerUnavailable  # noqa: E402

FAKE_PLUGINS = str(ROOT / "tests" / "fakes" / "plugins")


def main(data_dir: str) -> None:
    data = Path(data_dir)
    engine = Engine(config.load(overrides={
        "data_dir": data_dir, "plugin_sandbox": True, "plugin_paths": [FAKE_PLUGINS],
        "plugin_sandbox_overrides": {
            "openfs": {"filesystem": "open"},  # only the users keep this one apart: its files aren't limited by Landlock
            "shared": {"user": "doorman"},     # runs as Doorman's user, like the files plugin
        },
    }), starter_plugins=False)
    for name in ("probe", "other", "openfs", "shared"):
        engine.registry.put_plugin(name, {"type": "fake_probe", "enabled": True})
    engine.vault.set("probe", "secret", "probe's own")
    engine.vault.set("other", "secret", "other's own")
    registry = engine.registry

    def probe(name, action, **params):
        return registry.instance(name).run_read("probe", {"action": action, **params})

    out = {"doorman_uid": os.getuid(), "doorman_gid": os.getgid()}
    for name in ("probe", "other", "openfs", "shared"):
        out[name] = probe(name, "whoami")["result"]
    private = data / "plugins" / "other" / "private.txt"
    out["other_writes_own"] = probe("other", "write", path=str(private))
    folder = (data / "plugins" / "other").stat()
    out["folder"] = {"uid": folder.st_uid, "gid": folder.st_gid, "mode": oct(folder.st_mode & 0o7777)}
    file_ = private.stat()
    out["file"] = {"uid": file_.st_uid, "gid": file_.st_gid, "mode": oct(file_.st_mode & 0o777)}
    out["doorman_reads_plugin_file"] = private.read_text()  # backups read plugin folders through the group
    out["open"] = {
        "other_file": probe("openfs", "read", path=str(private)),
        "other_folder": probe("openfs", "list", path=str(private.parent)),
        "data_dir": probe("openfs", "list", path=str(data)),
        "doorman_db": probe("openfs", "read", path=str(data / "doorman.db")),
        "vault": probe("openfs", "read", path=str(data / "vault.enc")),
        "doorman_environ": probe("openfs", "environ", pid=os.getpid()),
        "other_environ": probe("openfs", "environ", pid=out["other"]["pid"]),
        "signal_other": probe("openfs", "signal", pid=out["other"]["pid"]),
        "own_write": probe("openfs", "write", path=str(data / "plugins" / "openfs" / "mine.txt")),
    }
    before = out["probe"]["pid"]
    try:
        registry.find_tool("probe.crash")[2].execute({}, None)
        out["crash"] = "no error"
    except PluginError as exc:
        out["crash"] = str(exc)
    after = probe("probe", "whoami")["result"]
    out["after_crash"] = {"pid_changed": after["pid"] != before, "uid": after["uid"]}
    with engine.db.tx() as conn:
        out["users_table"] = dict(conn.execute("SELECT name, uid FROM plugin_users").fetchall())

    # the helper processes, each as a user of its own
    text = engine.extractor.extract("note.txt", b"hello from a helper", "text/plain")
    out["extract"] = {"text": text.get("text"), "note": text.get("note"), "uid": uid_of(engine.extractor.worker.pid)}
    model = data / "models" / "fake-scanner"  # made as Doorman's user, private (umask 077)
    model.mkdir(parents=True, exist_ok=True)
    for name in ("model.onnx", "tokenizer.json", "config.json"):
        (model / name).write_bytes(b"not a model")
    try:
        Worker("doorman.guard_worker", [str(model), "512", "64", "sandbox"], "scanner", own_user=True,
               shared=model).start(timeout=120)
        out["guard"] = "started"
    except WorkerUnavailable as exc:
        out["guard"] = str(exc)
    worker_process.stop_all()
    for name in list(registry.instances):
        registry.invalidate(name)
    print("RESULT " + json.dumps(out), flush=True)


def uid_of(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("Uid:"):
            return int(line.split()[1])
    return -1


if __name__ == "__main__":
    main(sys.argv[1])
