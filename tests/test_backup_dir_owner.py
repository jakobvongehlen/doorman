"""backup.dir is made Doorman's at start (privsep.claim_backup_dir), so the nightly backup can write into a
bind mount that reaches the container as root's. Runs without root: `unclaimed_uid` stands in for root's
uid, and the chown is recorded instead of done."""

import os
import pwd
import types

import pytest

from doorman import admin, privsep

WHO = pwd.struct_passwd(("doorman", "x", 10001, 10001, "", "/home/doorman", "/bin/sh"))


@pytest.fixture
def chowns(monkeypatch):
    done = []
    monkeypatch.setattr(privsep.os, "fchown", lambda fd, uid, gid: done.append((uid, gid)))
    return done


def test_a_fresh_backup_folder_becomes_doormans_and_private(tmp_path, chowns):
    folder = tmp_path / "backups"
    folder.mkdir(mode=0o755)

    assert privsep.claim_backup_dir(folder, WHO, unclaimed_uid=os.getuid())
    assert chowns == [(10001, 10001)]
    assert oct(folder.stat().st_mode & 0o777) == "0o700"


def test_a_missing_backup_folder_is_made(tmp_path, chowns):
    folder = tmp_path / "mnt" / "backups"

    assert privsep.claim_backup_dir(folder, WHO, unclaimed_uid=os.getuid())
    assert folder.is_dir() and chowns == [(10001, 10001)]


def test_earlier_backups_and_lost_and_found_dont_stop_it(tmp_path, chowns):
    for name in ("doorman-20261110-033000", "doorman-20261111-033000.partial", "lost+found"):
        (tmp_path / name).mkdir()

    assert privsep.claim_backup_dir(tmp_path, WHO, unclaimed_uid=os.getuid())


def test_a_folder_with_anything_else_in_it_stays_as_it_is(tmp_path, chowns):
    (tmp_path / "etc").mkdir()
    before = tmp_path.stat().st_mode

    with pytest.raises(privsep.PrivsepError, match="more than Doorman's backups"):
        privsep.claim_backup_dir(tmp_path, WHO, unclaimed_uid=os.getuid())
    assert chowns == [] and tmp_path.stat().st_mode == before


def test_a_folder_someone_owns_already_is_left_alone(tmp_path, chowns):
    assert not privsep.claim_backup_dir(tmp_path, WHO, unclaimed_uid=os.getuid() + 1)
    assert chowns == []


def test_never_through_a_link(tmp_path, chowns):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)

    with pytest.raises(OSError):
        privsep.claim_backup_dir(tmp_path / "link", WHO, unclaimed_uid=os.getuid())
    assert chowns == []


def test_a_relative_path_is_refused(chowns):
    with pytest.raises(privsep.PrivsepError, match="absolute"):
        privsep.claim_backup_dir("backups", WHO, unclaimed_uid=os.getuid())


def test_backup_dir_comes_from_the_config(tmp_path):
    config = tmp_path / "doorman.yaml"
    config.write_text("backup:\n  dir: /backups\n")
    assert admin._backup_dir(config) == privsep.Path("/backups")

    config.write_text("backup:\n  dir: backups\n")
    assert admin._backup_dir(config) == (tmp_path / "backups").resolve()

    config.write_text("backup:\n  keep: 3\n")
    assert admin._backup_dir(config) is None
    config.write_text("public_url: http://localhost:8711\n")
    assert admin._backup_dir(config) is None


def test_serve_as_root_hands_backup_dir_to_privsep(tmp_path, monkeypatch):
    config = tmp_path / "doorman.yaml"
    config.write_text("data_dir: data\nbackup:\n  dir: /backups\n")
    calls = []
    monkeypatch.delenv(privsep.FD_ENV, raising=False)
    monkeypatch.setattr(admin.os, "execv", lambda exe, argv: calls.append(argv))
    monkeypatch.setattr(privsep, "drop_to", lambda user: None)  # execv is stubbed, so _as_root goes on to it
    monkeypatch.setattr(privsep, "doorman_user", lambda name=None: WHO)

    admin._as_root(types.SimpleNamespace(command="serve", config=str(config)), ["serve"])

    argv = calls[0]
    assert argv[argv.index("--backup-dir") + 1] == "/backups"
    assert argv[argv.index("--data-dir") + 1] == str((tmp_path / "data").resolve())
    assert argv[argv.index("--") + 1:] == [admin.sys.executable, "-m", "doorman.admin", "serve"]
