"""Secrets stay in Doorman: helper processes (extractor, guard, embedder) start with an allowlisted
environment, and the vault key leaves os.environ once the vault has it."""

import os

from cryptography.fernet import Fernet

from doorman.worker_process import Worker
from conftest import make_engine


def test_a_helper_process_gets_neither_the_vault_key_nor_api_keys(monkeypatch):
    monkeypatch.setenv("DOORMAN_VAULT_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("READER_API_KEY", "reader-secret")
    monkeypatch.setenv("LANG", "C.UTF-8")
    worker = Worker("tests.worker_env_child", [], "env probe").start(timeout=30)
    try:
        env = worker.call({}, timeout=30)["env"]
    finally:
        worker.stop()
    assert not {"DOORMAN_VAULT_KEY", "ANTHROPIC_API_KEY", "READER_API_KEY"} & set(env)
    assert env["LANG"] == "C.UTF-8" and env["PATH"] and env["OMP_NUM_THREADS"] == "1"


def test_the_vault_key_leaves_the_environment_once_the_vault_has_it(tmp_path, monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("DOORMAN_VAULT_KEY", key)
    engine = make_engine(tmp_path)
    assert "DOORMAN_VAULT_KEY" not in os.environ
    engine.vault.set("mail", "password", "hunter2")
    assert engine.vault.get("mail") == {"password": "hunter2"}
    assert not (tmp_path / "data" / "vault.key").exists()  # it used the key it was given, and kept it
    monkeypatch.setenv("DOORMAN_VAULT_KEY", key)  # the next start gets it again and opens the vault
    assert make_engine(tmp_path).vault.get("mail") == {"password": "hunter2"}
