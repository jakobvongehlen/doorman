import hashlib
import itertools
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from doorman import clock, config, textsearch
from doorman import embedder as embedder_mod
from doorman.engine import Engine
from doorman import guard as guard_module
from doorman.guard import Guard
from doorman.registry import Registry

FAKE_PLUGINS = str(Path(__file__).parent / "fakes" / "plugins")  # fake_mail: a mailbox in a JSON file

# Most tests reach into plugin objects (fake servers, injected transports), which needs them in the
# doorman's process. test_plugin_sandbox.py runs plugins in their own; DOORMAN_TEST_SANDBOX=1 runs the
# whole suite that way, to see which flows still work through the process boundary.
config.DEFAULTS["plugin_sandbox"] = os.environ.get("DOORMAN_TEST_SANDBOX") == "1"
# An approval waits for its sends' results (sends.py) as long as a test may need on a busy box, so a test
# reads the outcome from approvals.decide; the tests of "sending" set a short wait themselves.
config.DEFAULTS["send_wait_seconds"] = 60
# a write doesn't pull its plugin's search feed in a thread of its own: tests pull (engine.search.pull) when
# they search what they just wrote
config.DEFAULTS["search_index"] = {**config.DEFAULTS["search_index"], "pull_after_writes": False}

INJECTION_MARKER = "ignore previous instructions"


def fake_scorer(texts):
    """The guard's model stand-in: text containing INJECTION_MARKER scores 0.97, anything else 0.01.
    test_guard.py has one test with the real model, skipped unless it was downloaded."""
    out = []
    for text in texts:
        at = text.lower().find(INJECTION_MARKER)
        out.append({"score": 0.97, "start": at, "end": at + len(INJECTION_MARKER)} if at >= 0
                   else {"score": 0.01, "start": 0, "end": min(len(text), 50)})
    return out


Guard.backend = staticmethod(fake_scorer)
# the guard is opt-in (test_guard.py: test_the_guard_is_off_until_switched_on); the tests run with it on, as
# an owner who wants it has it, so every read path is checked with the scan in it
guard_module.DEFAULTS = {**guard_module.DEFAULTS, "enabled": True}
# a test's engine has the plugins it asks for (make_engine's plugins=), not a new Doorman's notes and file
# archive; test_files_default.py checks those
Registry.starter = {}


@pytest.fixture(autouse=True)
def _stop_plugin_processes():
    """Plugins in their own process outlive a test's engine; stop them, or they pile up."""
    yield
    from doorman import plugin_host, worker_process

    plugin_host.stop_all()
    worker_process.stop_all()  # the guard's scanner and the text extractor


def put_plugins(engine, plugins: dict) -> None:
    """Plugins as blocks (type, config, no_approval, enabled, read_only, disabled_tools, tool_approval), into
    the database as the owner app keeps them; a block's `sandbox` goes to plugin_sandbox_overrides, where the
    host sets it."""
    for name, block in plugins.items():
        block = dict(block or {})
        if "sandbox" in block:
            engine.config["plugin_sandbox_overrides"][name] = block.pop("sandbox")
        engine.registry.put_plugin(name, block)


def make_engine(tmp_path, plugins=None, **overrides):
    clock.reset()
    base = {
        "data_dir": str(tmp_path / "data"),
        "vault_key_file_warn": False,  # tests open their vault with vault.key; test_vault_key_file_is_listed
    }
    base.update(overrides)
    engine = Engine(config.load(overrides=base))
    put_plugins(engine, {"notes": {"enabled": True}} if plugins is None else plugins)
    return engine


@pytest.fixture
def engine(tmp_path):
    eng = make_engine(tmp_path)
    yield eng
    clock.reset()


class Agent:
    """A key plus a session, re-read from the database before every call."""

    def __init__(self, engine, role="solo"):
        self.engine = engine
        token = engine.auth.create_key(f"test-{role}", role)
        self.token = token
        self.key = engine.auth.key_from_token(token)
        self.session_id = engine.auth.session_for(self.key, None)["id"]

    @property
    def session(self):
        return self.engine.auth.get_session(self.session_id)

    def call(self, name, args, **kw):
        return self.engine.call_tool(self.session, self.key, name, args, **kw)

    def read(self, name, params=None):
        return self.engine.read(self.session, self.key, name, params or {})


@pytest.fixture
def agent(engine):
    return Agent(engine)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="session")
def radicale_server(tmp_path_factory):
    """One Radicale for the whole run (starting one takes a second or two); `new_user()` gives a test a
    user of its own, and with it collections no other test sees. test_caldav.py's `radicale` makes them."""
    port = free_port()
    storage = tmp_path_factory.mktemp("radicale")
    proc = subprocess.Popen(
        [sys.executable, "-m", "radicale", "--server-hosts", f"127.0.0.1:{port}", "--auth-type", "none",
         "--storage-filesystem-folder", str(storage), "--logging-level", "error"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    url, numbers = f"http://127.0.0.1:{port}/", itertools.count(1)
    yield SimpleNamespace(new_user=lambda: SimpleNamespace(url=url, user=f"owner{next(numbers)}"))
    proc.terminate()
    proc.wait(timeout=5)


# ------------------------------------------------------------------ semantic search without the model

CONCEPTS = {"kaution": 0, "deposit": 0, "borg": 0, "waarborg": 0, "mietkaution": 0,
            "pizza": 1, "rezept": 1, "tomaten": 1, "zug": 2, "train": 2, "fahrkarte": 2}


def concept_vectors(texts):
    """A stand-in for the model: words that mean the same land in the same dimension."""
    out = []
    for text in texts:
        vector = [0.0] * embedder_mod.DIM
        for word in textsearch.WORD.findall(text.lower()):
            if word in CONCEPTS:
                vector[CONCEPTS[word]] += 1.0
            else:
                vector[10 + int(hashlib.sha256(word.encode()).hexdigest(), 16) % 370] += 0.05
        out.append(vector)
    return out
