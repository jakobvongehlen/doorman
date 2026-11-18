"""Writes deploy/requirements.lock (every package the Doorman image installs, at one version, with its hash),
deploy/reader.lock (the same for the reader image: httpx at the version Doorman's lock has) and
deploy/egress/requirements.lock (the egress proxy's image: mitmproxy at EGRESS_MITMPROXY).

The image installs from the lock with `pip install --require-hashes`, so a build gets exactly the packages
that were tested, and a package re-uploaded under the same version fails the build instead of slipping in.
Run it after changing the dependencies in pyproject.toml, then run the tests and commit both:

    .venv/bin/python deploy/lock.py            # all three
    .venv/bin/python deploy/lock.py egress     # only the egress proxy's (doorman: the other two)

It asks pip to resolve `.[all]` plus `anthropic` (as the Dockerfile installs them) without installing
anything, for the Python and platform it runs on. The image is python:3.13-slim on x86_64, so run it with
Python 3.13 on x86_64 Linux; the wheels' hashes differ elsewhere.
"""

import json
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "deploy" / "requirements.lock"
READER_LOCK = ROOT / "deploy" / "reader.lock"
EGRESS_LOCK = ROOT / "deploy" / "egress" / "requirements.lock"
EGRESS_MITMPROXY = "12.3.1"  # the addon (deploy/egress/addon.py) is written and tested against this version
EXTRAS = [".[all]", "anthropic"]  # what deploy/Dockerfile installs
BUILD = ["setuptools>=77"]  # pyproject's build backend: the image builds Doorman without build isolation
HEADER = "# Written by deploy/lock.py for Python 3.13 on x86_64 Linux; don't edit by hand.\n"


def resolve(requirements: list[str]) -> list[tuple[str, str, str]]:
    """(name, version, sha256) of everything pip would install for these requirements, without installing."""
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        subprocess.run([sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--quiet",
                        "--report", str(report), *requirements], cwd=ROOT, check=True)
        install = json.loads(report.read_text())["install"]
    found = []
    for item in sorted(install, key=lambda i: i["metadata"]["name"].lower()):
        name, version = item["metadata"]["name"], item["metadata"]["version"]
        if name == "doorman":
            continue  # installed from the source tree with --no-deps
        hashes = item["download_info"].get("archive_info", {}).get("hashes", {})
        if "sha256" not in hashes:
            raise SystemExit(f"{name} {version} has no sha256 in pip's report")
        found.append((name, version, hashes["sha256"]))
    return found


def write(path: Path, packages: list[tuple[str, str, str]]) -> None:
    path.write_text(HEADER + "".join(f"{n}=={v} \\\n    --hash=sha256:{h}\n" for n, v, h in packages))
    print(f"{path.relative_to(ROOT)}: {len(packages)} packages")


def main(targets: list[str]) -> int:
    if sys.version_info[:2] != (3, 13) or platform.machine() != "x86_64" or sys.platform != "linux":
        print("run this with Python 3.13 on x86_64 Linux, as the image is built", file=sys.stderr)
        return 2
    targets = targets or ["doorman", "egress"]
    if unknown := set(targets) - {"doorman", "egress"}:
        print(f"unknown target {', '.join(sorted(unknown))}: doorman or egress", file=sys.stderr)
        return 2
    if "doorman" in targets:
        packages = resolve(EXTRAS + BUILD)
        write(LOCK, packages)
        httpx = next(v for n, v, _ in packages if n.lower() == "httpx")
        write(READER_LOCK, resolve([f"httpx=={httpx}"]))
    if "egress" in targets:
        write(EGRESS_LOCK, resolve([f"mitmproxy=={EGRESS_MITMPROXY}"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
