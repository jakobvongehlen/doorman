"""privsep.py: as root, Doorman runs as its own user and every plugin as a user of its own.

Runs only as root, with Python, its packages and the checkout readable by other users (the plugin
users run them). Doorman's user is `nobody` unless DOORMAN_TEST_USER names another.
tests/privsep_child.py is Doorman's side.
"""

import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from doorman import privsep, sandbox

ROOT = Path(__file__).resolve().parent.parent

pytestmark = [
    pytest.mark.skipif(os.geteuid() != 0, reason="privsep needs root"),
    pytest.mark.skipif(sandbox.landlock_abi() < 4, reason="needs Landlock 4 (Linux 6.7+)"),
]


@pytest.fixture
def doorman_user():
    return pwd.getpwnam(os.environ.get("DOORMAN_TEST_USER", "nobody"))


@pytest.fixture
def data_dir():
    path = Path(tempfile.mkdtemp(prefix="privsep-", dir="/tmp"))  # root's pytest tmp isn't passable for others
    yield path / "data"
    shutil.rmtree(path, ignore_errors=True)


VAULT_KEY = Fernet.generate_key().decode()


def run_doorman(data_dir, user, timeout=120):
    env = {**os.environ, "DOORMAN_VAULT_KEY": VAULT_KEY}
    data_dir.parent.chmod(0o711)
    done = subprocess.run(
        [sys.executable, "-m", "doorman.privsep", "--user", user.pw_name, "--data-dir", str(data_dir), "--",
         sys.executable, str(ROOT / "tests" / "privsep_child.py"), str(data_dir)],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=timeout)
    lines = [line for line in done.stdout.splitlines() if line.startswith("RESULT ")]
    assert done.returncode == 0 and lines, done.stdout + done.stderr
    return json.loads(lines[-1][len("RESULT "):])


def test_each_plugin_runs_as_a_user_of_its_own(data_dir, doorman_user):
    out = run_doorman(data_dir, doorman_user)
    in_range = range(privsep.UID_BASE, privsep.UID_BASE + privsep.UID_COUNT)

    assert out["doorman_uid"] == doorman_user.pw_uid
    uids = {name: out[name]["uid"] for name in ("probe", "other", "openfs")}
    assert all(uid in in_range for uid in uids.values()), uids
    assert len(set(uids.values())) == 3, uids
    assert out["shared"]["uid"] == doorman_user.pw_uid  # sandbox: {user: doorman}
    assert out["users_table"] == uids
    assert out["probe"]["secret"] == "probe's own" and out["other"]["secret"] == "other's own"

    # the folder is the plugin's, Doorman keeps reading it through the group
    assert out["folder"] == {"uid": uids["other"], "gid": doorman_user.pw_gid, "mode": "0o2770"}
    assert out["file"]["uid"] == uids["other"] and out["file"]["gid"] == doorman_user.pw_gid
    assert out["file"]["mode"] == "0o660"
    assert out["doorman_reads_plugin_file"] == "probe"

    # a plugin with open files still can't reach Doorman or another plugin
    blocked = {k: v for k, v in out["open"].items() if k != "own_write"}
    assert all(not v["ok"] for v in blocked.values()), blocked
    assert out["open"]["own_write"]["ok"], out["open"]

    assert "stopped during execute" in out["crash"]
    assert out["after_crash"] == {"pid_changed": True, "uid": uids["probe"]}


def test_a_restart_keeps_each_plugins_user_and_fixes_a_folder_the_doorman_made(data_dir, doorman_user):
    first = run_doorman(data_dir, doorman_user)
    # a restored backup: the folder and its files belong to Doorman again
    folder = data_dir / "plugins" / "other"
    for path in [folder, *folder.rglob("*")]:
        os.chown(path, doorman_user.pw_uid, doorman_user.pw_gid, follow_symlinks=False)
    (folder / "planted").symlink_to("/etc/shadow")
    second = run_doorman(data_dir, doorman_user)
    # a file Doorman's user writes later (doorman-admin login) is the plugin's again on the next start
    late = folder / "token-cache.json"
    late.write_text("{}")
    os.chown(late, doorman_user.pw_uid, doorman_user.pw_gid)
    late.chmod(0o600)
    run_doorman(data_dir, doorman_user)
    assert late.stat().st_uid == first["users_table"]["other"] and oct(late.stat().st_mode & 0o777) == "0o660"
    assert second["users_table"] == first["users_table"]
    assert (folder / "private.txt").stat().st_uid == first["users_table"]["other"]
    assert os.stat("/etc/shadow").st_uid == 0  # the link was left alone


def test_the_root_process_refuses_what_isnt_a_plugin_start(data_dir, doorman_user):
    data_dir.mkdir(parents=True)
    supervisor = privsep.Supervisor(doorman_user, data_dir, ["true"])
    with pytest.raises(privsep.PrivsepError, match="plugin range"):
        supervisor.spawn({"instance": "x", "uid": 0, "env": {}}, [])
    with pytest.raises(privsep.PrivsepError, match="plugin range"):
        supervisor.spawn({"instance": "x", "uid": doorman_user.pw_uid, "env": {}}, [])
    with pytest.raises(privsep.PrivsepError, match="bad plugin name"):
        supervisor.spawn({"instance": "../../etc", "uid": privsep.UID_BASE, "env": {}}, [])
    with pytest.raises(privsep.PrivsepError, match="no helper"):
        supervisor.spawn_helper({"helper": "doorman.plugin_runner", "args": [], "env": {}}, [])
    with pytest.raises(privsep.PrivsepError, match="bad helper arguments"):
        supervisor.spawn_helper({"helper": "extract", "args": "200 20", "env": {}}, [])
    assert supervisor.kill({"pid": 1}) == {"error": "not a plugin or helper process of this doorman"}


def test_each_helper_runs_as_a_user_of_its_own(data_dir, doorman_user):
    """The extractor, the scanner and the embedding model parse a stranger's bytes: not as Doorman's user. The
    scanner's own user reads the model Doorman wrote privately (a fake one here, so it fails on its content)."""
    out = run_doorman(data_dir, doorman_user)
    assert out["extract"]["text"].strip() == "hello from a helper", out["extract"]
    assert out["extract"]["uid"] == privsep.HELPERS["extract"][1]
    assert "Protobuf" in out["guard"] and "ermission" not in out["guard"], out["guard"]
    model = data_dir / "models" / "fake-scanner"
    assert oct((data_dir / "models").stat().st_mode & 0o777) == "0o711"
    assert oct((model / "model.onnx").stat().st_mode & 0o777) == "0o644"
    assert oct((data_dir / "doorman.db").stat().st_mode & 0o777) == "0o600"
