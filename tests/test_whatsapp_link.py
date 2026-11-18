"""Linking WhatsApp from the owner app, and the sidecar's token reaching Doorman without anyone typing it.

The shim runs against a fake wacli (a script that answers the commands the shim uses, the way wacli 0.26
does: --json envelopes on stdout, --events NDJSON on stderr). The real wacli's QR flow needs WhatsApp's
servers; it was tried by hand (a QR code arrives within a couple of seconds). Doorman's side runs against a
fake sidecar.
"""

import json
import os
import socket
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from doorman.api.owner import create_owner_app
from doorman.plugin_api import Denied
from conftest import make_engine

SHIM = Path(__file__).resolve().parents[1] / "sidecars" / "whatsapp" / "shim.py"
QR = "2@fake-ref,fake-noise,fake-identity,fake-adv"

FAKE_WACLI = textwrap.dedent('''\
    import json, os, sys, time
    from pathlib import Path
    state = Path(os.environ["FAKE_STATE"])
    args = [a for a in sys.argv[1:] if a not in ("--json", "--events", "--read-only")]
    if args[:1] == ["--timeout"]:
        args = args[2:]
    with open(state / "calls", "a") as fh:
        fh.write(" ".join(args) + "\\n")
    def ok(data):
        print(json.dumps({"success": True, "data": data, "error": None}))
        sys.exit(0)
    def event(name, data=None):
        print(json.dumps({"event": name, "data": data or {}, "ts": 1}), file=sys.stderr, flush=True)
    linked = (state / "linked").exists()
    if args[:2] == ["auth", "status"]:
        ok({"authenticated": True, "linked_jid": "4915100000000@s.whatsapp.net", "phone": "4915100000000"}
           if linked else {"authenticated": False})
    if args[:2] == ["auth", "logout"]:
        (state / "linked").unlink(missing_ok=True)
        ok({"logged_out": True})
    if args[:1] == ["auth"]:
        event("auth_starting")
        if (state / "fail").exists():
            event("error", {"message": (state / "fail").read_text()})
            print(json.dumps({"success": False, "data": None, "error": (state / "fail").read_text()}))
            sys.exit(1)
        phone = next((a.split("=", 1)[1] for a in args if a.startswith("--phone=")), None)
        if phone:
            event("pair_code", {"phone": phone, "code": "ABCD-1234"})
        else:
            event("qr_code", {"code": "QR-1"})
        lifetime = int((state / "lifetime").read_text()) if (state / "lifetime").exists() else 400
        for i in range(lifetime):
            if (state / "scanned").exists():
                (state / "linked").touch()
                ok({"authenticated": True, "messages_stored": 3})
            if not phone and i == 5:
                event("qr_code", {"code": "QR-2"})
            time.sleep(0.05)
        event("error", {"message": "QR code timed out; run `wacli auth` again to get a new code"})
        sys.exit(1)
    if args[:1] == ["sync"]:
        while True:
            time.sleep(0.1)
    ok({})
''')


def wait_for(check, seconds=10.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("timed out")


@pytest.fixture
def shim(tmp_path):
    """Starts the shim on a free port; returns (start, state dir). start(env) may be called again."""
    fake = tmp_path / "wacli"
    fake.write_text(f"#!{sys.executable}\n" + FAKE_WACLI)
    fake.chmod(0o755)
    state = tmp_path / "state"
    state.mkdir()
    running = []

    def start(**env_extra):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        env = {**os.environ, "WACLI": str(fake), "FAKE_STATE": str(state), "LISTEN": f"127.0.0.1:{port}",
               "SIDECAR_TOKEN": "", **env_extra}
        process = subprocess.Popen([sys.executable, "-I", str(SHIM)], env=env, stderr=subprocess.PIPE, text=True)
        running.append(process)
        url = f"http://127.0.0.1:{port}"
        for _ in range(100):
            if process.poll() is not None:
                return SimpleShim(url, None, process)
            try:
                httpx.get(url + "/status", timeout=1)
                break
            except httpx.HTTPError:
                time.sleep(0.05)
        return SimpleShim(url, env, process)

    yield start, state
    for process in running:
        process.terminate()
        process.wait(5)


class SimpleShim:
    def __init__(self, url, env, process):
        self.url, self.env, self.process = url, env, process

    def client(self, token):
        return httpx.Client(base_url=self.url, headers={"Authorization": f"Bearer {token}"}, timeout=30)


def test_token_is_made_up_once_and_written_for_doorman(tmp_path, shim):
    start, _ = shim
    token_file = tmp_path / "token" / "token"
    token_file.parent.mkdir()
    first = start(SIDECAR_TOKEN_FILE=str(token_file))
    token = token_file.read_text().strip()
    assert len(token) == 48 and stat.S_IMODE(token_file.stat().st_mode) == 0o600
    assert first.client(token).get("/status").status_code == 200
    assert first.client("wrong" * 4).get("/status").status_code == 401
    first.process.terminate()
    first.process.wait(5)
    again = start(SIDECAR_TOKEN_FILE=str(token_file))  # a restart keeps it
    assert token_file.read_text().strip() == token
    assert again.client(token).get("/status").status_code == 200
    own = start(SIDECAR_TOKEN_FILE=str(token_file), SIDECAR_TOKEN="my-own-token-0123456789")
    assert token_file.read_text().strip() == "my-own-token-0123456789"  # what it uses is what Doorman reads
    assert own.client("my-own-token-0123456789").get("/status").status_code == 200
    none = start()  # neither: it refuses to start
    assert none.process.wait(5) != 0


def test_link_by_qr_code_then_sync_then_unlink(tmp_path, shim):
    start, state = shim
    api = start(SIDECAR_TOKEN="0123456789abcdef0123").client("0123456789abcdef0123")
    assert api.get("/status").json()["link"] == {"state": "idle"}
    assert api.post("/link", json={}).json()["state"] in ("starting", "scan")
    assert wait_for(lambda: api.get("/link").json().get("qr")) in ("QR-1", "QR-2")
    assert wait_for(lambda: api.get("/link").json().get("qr") == "QR-2")  # a new code replaces the old one
    assert api.post("/link", json={}).json()["qr"] == "QR-2"  # the same again: the running one
    assert (state / "calls").read_text().count("auth --idle-exit 30s") == 1
    (state / "scanned").touch()
    status = wait_for(lambda: (s := api.get("/status").json())["sync_running"] and s)
    assert status["linked"] is True and status["phone"] == "4915100000000"
    assert status["link"]["state"] == "linked" and "qr" not in status["link"]
    again = api.post("/link", json={})
    assert again.status_code == 409 and "already linked" in again.json()["error"]

    assert api.post("/unlink", json={}).json() == {"linked": False}
    status = api.get("/status").json()
    assert status["linked"] is False and status["sync_running"] is False and status["last_error"] == ""
    assert status["link"] == {"state": "idle"}
    assert "auth logout" in (state / "calls").read_text()


def test_link_by_pairing_code_and_switching(tmp_path, shim):
    start, state = shim
    api = start(SIDECAR_TOKEN="0123456789abcdef0123").client("0123456789abcdef0123")
    bad = api.post("/link", json={"phone": "call me"})
    assert bad.status_code == 400 and "country code" in bad.json()["error"]
    api.post("/link", json={})
    wait_for(lambda: api.get("/link").json().get("qr"))
    api.post("/link", json={"phone": "+49 151 0000-0000"})  # another way: replaces the QR one
    shown = wait_for(lambda: (s := api.get("/link").json()).get("pair_code") and s)
    assert shown == {"state": "enter_code", "pair_code": "ABCD-1234", "phone": "4915100000000"}
    time.sleep(0.5)  # the replaced QR process's end mustn't turn this one into "failed"
    assert api.get("/link").json()["state"] == "enter_code"
    assert "auth --idle-exit 30s --phone=4915100000000" in (state / "calls").read_text()


def test_a_failed_link_says_why(tmp_path, shim):
    start, state = shim
    (state / "fail").write_text("WhatsApp client outdated; update wacli and try again")
    api = start(SIDECAR_TOKEN="0123456789abcdef0123").client("0123456789abcdef0123")
    api.post("/link", json={})
    failed = wait_for(lambda: (s := api.get("/link").json())["state"] == "failed" and s)
    assert failed["error"] == "WhatsApp client outdated; update wacli and try again"


def test_an_expired_code_says_start_again(tmp_path, shim):
    start, state = shim
    (state / "lifetime").write_text("20")  # a second, not WhatsApp's minutes
    api = start(SIDECAR_TOKEN="0123456789abcdef0123").client("0123456789abcdef0123")
    api.post("/link", json={"phone": "+4915100000000"})
    failed = wait_for(lambda: (s := api.get("/link").json())["state"] == "failed" and s)
    assert failed["error"] == "The code expired before the phone linked. Start again."


# ---------------------------------------------------------------- Doorman's side


class Sidecar:
    """A fake sidecar: what /status, /link and /unlink answer."""

    def __init__(self):
        self.linked, self.link, self.calls = False, {"state": "idle"}, []

    def __call__(self, request: httpx.Request):
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, request.url.path, body))
        if request.headers["Authorization"] != "Bearer tok":
            return httpx.Response(401, json={"error": "unauthorized"})
        if request.url.path == "/status":
            return httpx.Response(200, json={"linked": self.linked, "phone": "4915100000000" if self.linked else None,
                                             "sync_running": self.linked, "last_error": "", "link": self.link})
        if request.url.path == "/link":
            self.link = ({"state": "enter_code", "pair_code": "ABCD-1234", "phone": "4915100000000"}
                         if body.get("phone") else {"state": "scan", "qr": QR})
            return httpx.Response(200, json=self.link)
        if request.url.path == "/unlink":
            self.linked, self.link = False, {"state": "idle"}
            return httpx.Response(200, json={"linked": False})
        return httpx.Response(404, json={"error": "not found"})


def whatsapp(tmp_path):
    engine = make_engine(tmp_path, plugins={"whatsapp": {"enabled": True}})
    engine.vault.set("whatsapp", "sidecar_token", "tok")
    sidecar = Sidecar()
    engine.registry.instance("whatsapp").transport = httpx.MockTransport(sidecar)
    return engine, sidecar


def test_link_through_the_engine_is_journaled_once(tmp_path):
    engine, sidecar = whatsapp(tmp_path)
    assert engine.plugin_setup.login_status("whatsapp") == {"connected": False, "ready": True, "link": {"state": "idle"}}
    started = engine.plugin_setup.login_start("whatsapp")["link"]
    assert started["state"] == "scan"
    qr = started["qr"]
    assert qr["size"] == len(qr["rows"]) and set("".join(qr["rows"])) == {"0", "1"}
    assert qr["rows"][0].startswith("1111111")  # a finder pattern in the corner
    by_phone = engine.plugin_setup.login_start("whatsapp", phone="+49 151 0000 0000")["link"]
    assert by_phone == {"state": "enter_code", "pair_code": "ABCD-1234", "phone": "4915100000000"}
    assert sidecar.calls[-1] == ("POST", "/link", {"phone": "+49 151 0000 0000"})

    sidecar.linked = True
    status = engine.plugin_setup.login_status("whatsapp")
    assert status["connected"] is True and status["account"] == "+4915100000000"
    engine.plugin_setup.login_status("whatsapp")
    logins = engine.db.all("SELECT summary FROM journal WHERE tool='plugin.login'")
    assert [r["summary"] for r in logins] == ["Connected whatsapp to +4915100000000"]  # once

    assert engine.plugin_setup.logout("whatsapp") == {"connected": False}
    assert sidecar.calls[-1] == ("POST", "/unlink", {})
    assert engine.db.one("SELECT summary FROM journal WHERE tool='plugin.logout'")["summary"] == "Disconnected whatsapp"
    with pytest.raises(Denied):
        engine.plugin_setup.login_finish("whatsapp", "http://localhost/?code=x")  # no pasted address for a link


def test_link_status_without_a_token_or_sidecar(tmp_path):
    engine = make_engine(tmp_path, plugins={"whatsapp": {"enabled": True}})
    status = engine.plugin_setup.login_status("whatsapp")
    assert status["ready"] is False and "No sidecar token yet" in status["error"]
    engine.vault.set("whatsapp", "sidecar_token", "tok")
    engine.registry.instance("whatsapp").transport = httpx.MockTransport(
        lambda request: (_ for _ in ()).throw(httpx.ConnectError("refused")))
    status = engine.plugin_setup.login_status("whatsapp")
    assert status["ready"] is False and "sidecar unreachable" in status["error"]


def test_owner_api_link_endpoints(tmp_path):
    engine, sidecar = whatsapp(tmp_path)
    engine.config["dev_owner_token"] = "dev"
    owner = TestClient(create_owner_app(engine), headers={"Authorization": "Bearer dev"})
    assert owner.post("/owner/plugins/whatsapp/login/start").json()["link"]["state"] == "scan"
    phone = owner.post("/owner/plugins/whatsapp/login/start", json={"phone": "+4915100000000"})
    assert phone.json()["link"]["pair_code"] == "ABCD-1234"
    assert owner.post("/owner/plugins/whatsapp/login/start", json={"phone": 49}).status_code == 403
    assert owner.post("/owner/plugins/notes/login/start", json={"phone": "+49151"}).status_code == 403
    listed = next(p for p in owner.get("/owner/plugins").json()["plugins"] if p["name"] == "whatsapp")
    assert listed["login"] == "link" and listed["login_provider"] == "WhatsApp"


def test_sidecar_token_comes_from_the_shared_file(tmp_path):
    engine = make_engine(tmp_path, plugins={"whatsapp": {"enabled": True}})
    token_file = tmp_path / "token"
    engine.registry.types["whatsapp"].manifest["credential_files"] = {"sidecar_token": str(token_file)}
    engine.tick()
    assert "sidecar_token" not in engine.vault.get("whatsapp")  # no file yet: nothing
    token_file.write_text("generated-token-1\n")
    engine.tick()
    assert engine.vault.get("whatsapp")["sidecar_token"] == "generated-token-1"
    engine.tick()
    entries = engine.db.all("SELECT summary, args FROM journal WHERE tool='credential.set'")
    assert len(entries) == 1 and "from the file its sidecar wrote" in entries[0]["summary"]
    assert "generated-token-1" not in entries[0]["args"]
    token_file.write_text("generated-token-2\n")  # the sidecar's volume was made anew
    os.utime(token_file, ns=(time.time_ns() + 10**9,) * 2)
    engine.tick()
    assert engine.vault.get("whatsapp")["sidecar_token"] == "generated-token-2"
    engine.vault.delete("whatsapp", "sidecar_token")  # removed by hand: the file brings it back
    engine.tick()
    assert engine.vault.get("whatsapp")["sidecar_token"] == "generated-token-2"


def test_only_built_in_plugins_may_name_credential_files(tmp_path):
    plugins = tmp_path / "plugins" / "nosy"
    plugins.mkdir(parents=True)
    secret = tmp_path / "secret"
    secret.write_text("not yours")
    (plugins / "manifest.yaml").write_text(f"name: nosy\nversion: 0.1.0\ndescription: x\ncredentials: [loot]\n"
                                           f"credential_files: {{loot: {secret}}}\n")
    (plugins / "plugin.py").write_text("from doorman.plugin_api import BasePlugin\n\nclass Plugin(BasePlugin):\n"
                                       "    pass\n")
    engine = make_engine(tmp_path, plugin_paths=[str(tmp_path / "plugins")], plugins={"nosy": {"enabled": True}})
    assert engine.registry.import_credential_files() == []
    assert engine.vault.get("nosy") == {}
