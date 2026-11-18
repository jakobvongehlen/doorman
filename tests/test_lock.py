"""deploy/requirements.lock keeps up with pyproject.toml: every dependency the image installs is in it, at a
version the project allows. Rewrite it with `python deploy/lock.py` after changing the dependencies."""

import re
import tomllib
from pathlib import Path

import pytest

requirements = pytest.importorskip("packaging.requirements")

ROOT = Path(__file__).resolve().parent.parent


def _locked(path: Path) -> dict[str, str]:
    found = {}
    for line in path.read_text().splitlines():
        match = re.match(r"([A-Za-z0-9_.-]+)==([^ \\]+)", line)
        if match:
            found[re.sub(r"[-_.]+", "-", match.group(1)).lower()] = match.group(2)
    return found


def test_the_lock_has_every_dependency_of_the_image_at_an_allowed_version():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    wanted = project["project"]["dependencies"] + project["project"]["optional-dependencies"]["all"]
    wanted += project["build-system"]["requires"] + ["anthropic"]
    locked = _locked(ROOT / "deploy" / "requirements.lock")
    for spec in wanted:
        req = requirements.Requirement(spec)
        name = re.sub(r"[-_.]+", "-", req.name).lower()
        assert name in locked, f"{req.name} is missing from deploy/requirements.lock: run deploy/lock.py"
        assert req.specifier.contains(locked[name], prereleases=True), \
            f"{req.name} {locked[name]} doesn't meet {req.specifier}: run deploy/lock.py"


def test_every_locked_package_carries_a_hash_and_the_reader_matches_doorman():
    for name in ("requirements.lock", "reader.lock", "egress/requirements.lock"):
        text = (ROOT / "deploy" / name).read_text()
        assert text.count("==") == text.count("--hash=sha256:")
    assert _locked(ROOT / "deploy" / "reader.lock")["httpx"] == _locked(ROOT / "deploy" / "requirements.lock")["httpx"]


def test_the_egress_proxy_gets_the_mitmproxy_its_addon_is_written_for():
    pinned = re.search(r'EGRESS_MITMPROXY = "([^"]+)"', (ROOT / "deploy" / "lock.py").read_text()).group(1)
    locked = _locked(ROOT / "deploy" / "egress" / "requirements.lock")
    assert locked["mitmproxy"] == pinned, "run deploy/lock.py egress"
    assert {"mitmproxy-rs", "mitmproxy-linux"} <= set(locked)
