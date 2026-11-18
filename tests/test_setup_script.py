"""./setup.sh: the answers end up in doorman.yaml and deploy/.env as the owner gave them, and the right
doorman-admin commands follow. The Python install runs for real, against this environment's doorman-admin;
the Docker one runs against a stand-in `docker` that records what it was asked to do."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from cryptography.fernet import Fernet

REPO = Path(__file__).resolve().parent.parent
ADMIN = Path(sys.executable).parent / "doorman-admin"
PASSWORD = "correct horse battery"
PYTHON, DOCKER = "2", "1"
LOCALHOST, HTTPS, NETWORK = "1", "2", "3"
PASSKEY, WITH_PASSWORD = "1", "2"

pytestmark = pytest.mark.skipif(not ADMIN.exists() or shutil.which("bash") is None,
                                reason="needs bash and an installed doorman-admin")


def run(script: Path, answers: list[str], *args, env=None, check=True):
    done = subprocess.run(["bash", str(script), *args], input="\n".join(answers) + "\n", text=True,
                          capture_output=True, timeout=120,
                          env={**os.environ, "DOORMAN_SETUP_ADMIN": str(ADMIN), **(env or {})})
    if check:
        assert done.returncode == 0, done.stdout + done.stderr
    return done


def config_of(folder: Path) -> dict:
    return yaml.safe_load((folder / "doorman.yaml").read_text())


def admin(folder: Path, *args) -> str:
    return subprocess.run([str(ADMIN), "--config", str(folder / "doorman.yaml"), *args], text=True,
                          capture_output=True, timeout=60, cwd=folder).stdout


# ---------------------------------------------------------------- with Python on this machine

def test_this_machine_with_a_passkey(tmp_path):
    done = run(REPO / "setup.sh", [PYTHON, LOCALHOST, PASSKEY, "n"], "--dir", str(tmp_path))
    config = config_of(tmp_path)
    assert config["public_url"] == "http://localhost:8711"
    # nothing of it is open to the network
    assert config["owner_listen"] == "127.0.0.1:8711" and config["agent_listen"] == "127.0.0.1:8710"
    assert config["owner_allow_cidrs"] == ["127.0.0.0/8"]
    assert "setup code" in done.stdout and "register your passkey" in done.stdout
    assert "with a passkey" in admin(tmp_path, "sign-in")


def test_the_network_without_https_means_a_password(tmp_path):
    """No question about the sign-in there: a passkey can't be made on such an address."""
    done = run(REPO / "setup.sh", [PYTHON, NETWORK, "http://192.168.1.20:8711", "192.168.1.20/24", PASSWORD, "n"],
               "--dir", str(tmp_path))
    config = config_of(tmp_path)
    assert config["public_url"] == "http://192.168.1.20:8711"
    assert config["owner_listen"] == "0.0.0.0:8711"
    assert config["owner_allow_cidrs"] == ["127.0.0.0/8", "192.168.1.20/24"]
    assert "How do you want to sign in" not in done.stderr and "no notifications" in done.stderr
    assert "log in with your password" in done.stdout and PASSWORD not in done.stdout + done.stderr
    assert "with a password" in admin(tmp_path, "sign-in")


def test_an_https_address_is_asked_until_it_is_one(tmp_path):
    done = run(REPO / "setup.sh", [PYTHON, HTTPS, "doorman.example.com", "https://doorman.example.com/",
                                   WITH_PASSWORD, PASSWORD, "n"], "--dir", str(tmp_path))
    assert config_of(tmp_path)["public_url"] == "https://doorman.example.com"
    assert "has to start with https://" in done.stderr
    assert "with a password" in admin(tmp_path, "sign-in")


def test_a_short_password_stops_before_anything_is_written(tmp_path):
    done = run(REPO / "setup.sh", [PYTHON, LOCALHOST, WITH_PASSWORD, "short", "n"], "--dir", str(tmp_path / "d"),
               check=False)
    assert done.returncode == 1 and "at least 10 characters" in done.stderr
    assert not (tmp_path / "d").exists()


def test_running_it_again_changes_the_answers_and_keeps_the_data(tmp_path):
    run(REPO / "setup.sh", [PYTHON, LOCALHOST, WITH_PASSWORD, PASSWORD, "n"], "--dir", str(tmp_path))
    vault_key = (tmp_path / "data" / "vault.key").read_bytes()
    done = run(REPO / "setup.sh", [PYTHON, LOCALHOST, PASSKEY, "n"], "--dir", str(tmp_path))
    assert (tmp_path / "data" / "vault.key").read_bytes() == vault_key
    assert "setup code" in done.stdout and "with a passkey" in admin(tmp_path, "sign-in")


def test_both_config_templates_have_the_lines_the_script_sets():
    """The script changes whole top-level lines; a key that moved or went would be appended a second time."""
    for template in (REPO / "doorman" / "doorman.example.yaml", REPO / "deploy" / "doorman.example.yaml"):
        lines = template.read_text().splitlines()
        for key in ("public_url", "owner_listen", "agent_listen", "owner_allow_cidrs"):
            assert sum(line.startswith(f"{key}:") for line in lines) == 1, (template, key)


# ---------------------------------------------------------------- with Docker

FAKE_DOCKER = """#!/usr/bin/env bash
# records each call; a sign-in's stdin (the password) goes to its own file
printf '%s\\n' "$*" >> "$DOCKER_LOG"
case "$*" in
  *"sign-in password") cat > "$DOCKER_LOG.password"; echo "the owner app now signs in with this password" ;;
  *"sign-in") echo "the owner app signs in with a passkey; \\`doorman-admin sign-in password\\` switches" ;;
  *"setup-code") echo "setup code (valid 30 minutes): abcd-ef01-2345" ;;
esac
"""


@pytest.fixture
def docker_repo(tmp_path):
    """A copy of what the script touches, and a `docker` on the PATH that only takes notes."""
    repo = tmp_path / "repo"
    (repo / "deploy").mkdir(parents=True)
    shutil.copy(REPO / "setup.sh", repo / "setup.sh")
    for name in ("doorman.example.yaml", ".env.example"):
        shutil.copy(REPO / "deploy" / name, repo / "deploy" / name)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(FAKE_DOCKER)
    (bin_dir / "docker").chmod(0o755)
    log = tmp_path / "docker.log"
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "DOCKER_LOG": str(log)}
    return repo, env, log


def env_of(repo: Path) -> dict:
    lines = (repo / "deploy" / ".env").read_text().splitlines()
    return dict(line.split("=", 1) for line in lines if "=" in line and not line.startswith("#"))


def test_docker_behind_https_with_a_passkey(docker_repo):
    repo, env, log = docker_repo
    done = run(repo / "setup.sh", [DOCKER, HTTPS, "https://doorman.example.com", PASSKEY], env=env)
    config = yaml.safe_load((repo / "deploy" / "data" / "doorman.yaml").read_text())
    assert config["public_url"] == "https://doorman.example.com"
    assert config["owner_allow_cidrs"] == ["172.30.0.0/24", "127.0.0.0/8"]
    settings = env_of(repo)
    assert settings["DOORMAN_OWNER_BIND"] == "127.0.0.1"
    Fernet(settings["DOORMAN_VAULT_KEY"])   # a key the vault takes
    calls = log.read_text().splitlines()
    assert "compose up -d --build" in calls
    assert calls[-1] == "compose exec -T doorman doorman-admin setup-code"
    assert "abcd-ef01-2345" in done.stdout and "DOORMAN_VAULT_KEY" in done.stdout


def test_docker_on_the_network_opens_the_port_and_names_the_network(docker_repo):
    repo, env, log = docker_repo
    run(repo / "setup.sh", [DOCKER, NETWORK, "http://192.168.1.20:8711", "192.168.1.0/24", PASSWORD], env=env)
    config = yaml.safe_load((repo / "deploy" / "data" / "doorman.yaml").read_text())
    # the compose network, this machine and the named network; never the agent's (172.31.0.0/24)
    assert config["owner_allow_cidrs"] == ["172.30.0.0/24", "127.0.0.0/8", "192.168.1.0/24"]
    assert env_of(repo)["DOORMAN_OWNER_BIND"] == "0.0.0.0"
    assert log.read_text().splitlines()[-1] == "compose exec -T doorman doorman-admin sign-in password"
    assert Path(f"{log}.password").read_text() == PASSWORD + "\n"   # through a pipe, not on a command line
    assert PASSWORD not in log.read_text()


def test_running_it_again_never_replaces_the_vault_key(docker_repo):
    repo, env, _ = docker_repo
    run(repo / "setup.sh", [DOCKER, NETWORK, "http://192.168.1.20:8711", "192.168.1.0/24", PASSWORD], env=env)
    key = env_of(repo)["DOORMAN_VAULT_KEY"]
    done = run(repo / "setup.sh", [DOCKER, LOCALHOST, PASSKEY], env=env)
    assert env_of(repo)["DOORMAN_VAULT_KEY"] == key and env_of(repo)["DOORMAN_OWNER_BIND"] == "127.0.0.1"
    assert "DOORMAN_VAULT_KEY" not in done.stdout   # said once, when it was made


def test_the_compose_file_keeps_the_owner_app_on_this_machine_unless_told():
    compose = yaml.safe_load((REPO / "deploy" / "compose.yaml").read_text())
    assert compose["services"]["doorman"]["ports"] == ["${DOORMAN_OWNER_BIND:-127.0.0.1}:8711:8711"]
    assert "DOORMAN_OWNER_BIND=127.0.0.1" in (REPO / "deploy" / ".env.example").read_text()
