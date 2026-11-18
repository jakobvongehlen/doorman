"""Signing in with a password instead of a passkey: for an owner app opened without HTTPS and a domain, where
passkeys don't exist. One method per Doorman, set on the host with `doorman-admin sign-in`."""

import argparse
import io

import pytest
from fastapi.testclient import TestClient

from conftest import make_engine
from doorman import admin, auth, clock
from doorman.api.owner import create_owner_app
from doorman.auth import MIN_PASSWORD, PasswordLocked
from soft_authenticator import SoftAuthenticator
from test_api import CSRF, OWNER_URL, register

REAL_SCRYPT = dict(auth.SCRYPT)
PASSWORD = "correct horse battery"
PLAIN_URL = "http://192.168.1.20:8711"   # no HTTPS and no name: where a passkey can't be made


@pytest.fixture(autouse=True)
def cheap_hash(monkeypatch):
    """The real scrypt setting takes a quarter of a second a check; these tests check dozens of times."""
    monkeypatch.setitem(auth.SCRYPT, "n", 2 ** 4)


def test_the_hash_is_an_expensive_one():
    assert REAL_SCRYPT["n"] >= 2 ** 15 and REAL_SCRYPT["r"] == 8


def password_app(tmp_path, **config):
    engine = make_engine(tmp_path, public_url=PLAIN_URL, **config)
    engine.auth.set_password(PASSWORD)
    return engine, TestClient(create_owner_app(engine), base_url=PLAIN_URL)


def log_in(owner, password=PASSWORD):
    return owner.post("/owner/auth/login/password", headers=CSRF, json={"password": password})


def code(response) -> str:
    return response.json()["code"]


# ---------------------------------------------------------------- the password itself

def test_a_doorman_signs_in_with_a_passkey_until_a_password_is_set(engine):
    assert engine.auth.sign_in() == "passkey"
    engine.auth.set_password(PASSWORD)
    assert engine.auth.sign_in() == "password"
    assert engine.auth.check_password(PASSWORD) and not engine.auth.check_password(PASSWORD + "x")
    engine.auth.clear_password()
    assert engine.auth.sign_in() == "passkey" and not engine.auth.check_password(PASSWORD)


def test_the_password_is_stored_as_a_salted_hash(engine):
    engine.auth.set_password(PASSWORD)
    stored = engine.db.get_setting("owner_password")
    assert stored.startswith("scrypt$") and PASSWORD not in stored
    engine.auth.set_password(PASSWORD)
    assert engine.db.get_setting("owner_password") != stored   # a new salt each time


def test_a_short_password_is_refused(engine):
    with pytest.raises(ValueError, match=str(MIN_PASSWORD)):
        engine.auth.set_password("x" * (MIN_PASSWORD - 1))
    assert engine.auth.sign_in() == "passkey"


def test_wrong_passwords_lock_the_sign_in_for_a_growing_while(engine):
    """Whoever reaches the owner app can try passwords, an agent on the same machine too: after five wrong
    ones each further try has to wait, longer every time, and the right password doesn't count meanwhile."""
    engine.auth.set_password(PASSWORD)
    for _ in range(5):
        assert not engine.auth.check_password("wrong password")
    with pytest.raises(PasswordLocked) as first:
        engine.auth.check_password(PASSWORD)
    assert 0 < first.value.seconds <= 15
    clock.advance(16)
    assert not engine.auth.check_password("wrong again")
    with pytest.raises(PasswordLocked) as second:
        engine.auth.check_password(PASSWORD)
    assert second.value.seconds > 15
    clock.advance(31)
    assert engine.auth.check_password(PASSWORD)      # and the count starts over
    assert not engine.auth.check_password("wrong password")
    assert engine.auth.check_password(PASSWORD)


# ---------------------------------------------------------------- the owner API

def test_logging_in_with_the_password(tmp_path):
    engine, owner = password_app(tmp_path)
    status = owner.get("/owner/auth/status").json()
    assert status["sign_in"] == "password" and not status["logged_in"]
    assert owner.get("/owner/settings").status_code == 401
    wrong = log_in(owner, "not the password")
    assert wrong.status_code == 403 and code(wrong) == "password"
    assert log_in(owner).status_code == 200
    assert owner.get("/owner/auth/status").json()["logged_in"]
    assert owner.get("/owner/settings").json()["sign_in"] == "password"


def test_the_cookie_works_without_https(tmp_path):
    _, owner = password_app(tmp_path)
    assert "secure" not in log_in(owner).headers["set-cookie"].lower()


def test_logging_in_needs_the_apps_header(tmp_path):
    _, owner = password_app(tmp_path)
    response = owner.post("/owner/auth/login/password", json={"password": PASSWORD})
    assert response.status_code == 403 and code(response) == "csrf"


def test_sensitive_changes_ask_for_the_password_again(tmp_path):
    """What takes a fresh passkey check on a passkey Doorman takes the password again here."""
    engine, owner = password_app(tmp_path)
    log_in(owner)
    create = lambda: owner.post("/owner/keys", headers=CSRF, json={"name": "agent", "role": "solo"})  # noqa: E731
    assert create().status_code == 200          # just logged in: that is fresh
    clock.advance(6 * 60)
    stale = create()
    assert stale.status_code == 403 and code(stale) == "reauth" and "password" in stale.json()["reason"]
    wrong = owner.post("/owner/auth/reauth/password", headers=CSRF, json={"password": "not the password"})
    assert code(wrong) == "password" and code(create()) == "reauth"
    assert owner.post("/owner/auth/reauth/password", headers=CSRF, json={"password": PASSWORD}).status_code == 200
    assert create().status_code == 200


def test_confirming_with_the_password_needs_a_login(tmp_path):
    _, owner = password_app(tmp_path)
    response = owner.post("/owner/auth/reauth/password", headers=CSRF, json={"password": PASSWORD})
    assert response.status_code == 401


def test_a_locked_sign_in_says_how_long_and_tells_the_owner(tmp_path):
    engine, owner = password_app(tmp_path)
    for _ in range(5):
        assert code(log_in(owner, "wrong password")) == "password"
    locked = log_in(owner)
    assert locked.status_code == 429 and code(locked) == "locked" and locked.json()["retry_after"] > 0
    notices = [a for a in engine.attention_list() if a["kind"] == "sign_in"]
    assert len(notices) == 1 and "5 wrong passwords" in notices[0]["title"]
    clock.advance(16)
    assert log_in(owner).status_code == 200


def test_a_password_doorman_takes_no_passkeys(tmp_path):
    """One or the other: a setup code doesn't add a passkey next to the password."""
    engine, owner = password_app(tmp_path)
    setup = owner.post("/owner/auth/register/options", json={"setup_code": engine.auth.create_setup_code()})
    assert setup.status_code == 403 and code(setup) == "sign_in"
    assert code(owner.post("/owner/auth/login/options")) == "sign_in"


def test_a_passkey_begun_before_the_switch_isnt_finished_after_it(tmp_path):
    engine = make_engine(tmp_path, public_url=OWNER_URL)
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL)
    passkey = SoftAuthenticator("localhost", OWNER_URL)
    options = owner.post("/owner/auth/register/options", json={"setup_code": engine.auth.create_setup_code()}).json()
    engine.auth.set_password(PASSWORD)
    late = owner.post("/owner/auth/register/verify", json={
        "challenge_id": options["challenge_id"], "credential": passkey.create(options["options"]), "label": "late"})
    assert late.status_code == 403 and code(late) == "sign_in"
    assert owner.get("/owner/settings").status_code == 401
    assert engine.db.one("SELECT COUNT(*) AS n FROM webauthn_credentials")["n"] == 0


def test_a_passkey_doorman_takes_no_password(tmp_path):
    engine = make_engine(tmp_path, public_url=OWNER_URL)
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL)
    register(engine, owner, SoftAuthenticator("localhost", OWNER_URL))
    assert owner.get("/owner/auth/status").json()["sign_in"] == "passkey"
    response = owner.post("/owner/auth/login/password", headers=CSRF, json={"password": PASSWORD})
    assert response.status_code == 403 and code(response) == "sign_in"
    response = owner.post("/owner/auth/reauth/password", headers=CSRF, json={"password": PASSWORD})
    assert code(response) == "sign_in"


def test_a_network_in_owner_allow_cidrs_may_be_written_with_the_hosts_address(tmp_path):
    """The setup script writes the machine's own address with its prefix (192.168.1.20/24)."""
    engine, _ = password_app(tmp_path, owner_allow_cidrs=["192.168.1.20/24"])
    near = TestClient(create_owner_app(engine), base_url=PLAIN_URL, client=("192.168.1.77", 50000))
    far = TestClient(create_owner_app(engine), base_url=PLAIN_URL, client=("172.31.0.5", 50000))
    assert near.get("/owner/auth/status").status_code == 200
    assert far.get("/owner/auth/status").status_code == 403


# ---------------------------------------------------------------- doorman-admin sign-in

@pytest.fixture
def host(tmp_path, monkeypatch):
    """`doorman-admin sign-in` on this test's Doorman, with `typed` as what the owner types."""
    engine = make_engine(tmp_path, public_url=OWNER_URL)
    monkeypatch.setattr(admin, "_engine", lambda args: engine)

    def run(method=None, typed=""):
        monkeypatch.setattr("sys.stdin", io.StringIO(typed))
        admin.cmd_sign_in(argparse.Namespace(config=None, method=method))
    return engine, run


def test_switching_to_a_password_on_the_host(host, capsys):
    engine, run = host
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL)
    register(engine, owner, SoftAuthenticator("localhost", OWNER_URL))
    assert owner.get("/owner/settings").status_code == 200
    run("password", PASSWORD + "\n")
    assert engine.auth.sign_in() == "password" and engine.auth.check_password(PASSWORD)
    assert owner.get("/owner/settings").status_code == 401           # every device is logged out
    assert engine.db.one("SELECT COUNT(*) AS n FROM webauthn_credentials")["n"] == 0   # one or the other
    assert "1 passkey" in capsys.readouterr().out


def test_switching_back_to_a_passkey_gives_a_setup_code(host, capsys):
    engine, run = host
    engine.auth.set_password(PASSWORD)
    owner = TestClient(create_owner_app(engine), base_url=OWNER_URL)
    log_in(owner)
    run("passkey")
    assert engine.auth.sign_in() == "passkey" and engine.db.get_setting("owner_password") is None
    assert owner.get("/owner/settings").status_code == 401
    assert "setup code" in capsys.readouterr().out and engine.db.get_setting("setup_code")


def test_sign_in_alone_says_which_it_is(host, capsys):
    engine, run = host
    run()
    assert "passkey" in capsys.readouterr().out
    engine.auth.set_password(PASSWORD)
    run()
    assert "password" in capsys.readouterr().out


def test_a_short_password_is_refused_on_the_host(host):
    engine, run = host
    with pytest.raises(SystemExit, match=str(MIN_PASSWORD)):
        run("password", "short\n")
    assert engine.auth.sign_in() == "passkey"


def test_a_password_and_passkey_signed_approvals_dont_go_together(tmp_path, monkeypatch):
    """`approval_passkey` signs every approval with the passkey: there is none on a password Doorman."""
    engine = make_engine(tmp_path, public_url=OWNER_URL, approval_passkey=True)
    monkeypatch.setattr(admin, "_engine", lambda args: engine)
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    with pytest.raises(SystemExit, match="approval_passkey"):
        admin.cmd_sign_in(argparse.Namespace(config=None, method="password"))
    assert engine.auth.sign_in() == "passkey"
    engine.auth.set_password(PASSWORD)   # set anyway (an older database, the setting switched on later)
    with pytest.raises(SystemExit, match="approval_passkey"):
        admin.sign_in_fits(engine)
