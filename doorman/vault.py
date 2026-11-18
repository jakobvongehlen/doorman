"""Credential vault: one encrypted JSON file, one section per plugin.

The key comes from DOORMAN_VAULT_KEY, or from vault.key next to the vault.
A key file on the same disk only stops casual reading; on a real deployment
pass the key through the environment. Once the vault has it, it is taken out
of the environment again, so no process Doorman starts inherits it.
"""

import json
import os
import threading
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


class VaultKeyError(Exception):
    """The key doesn't open the vault. Doorman refuses to start rather than make a new key, which would
    lock the stored credentials away for good."""


class Vault:
    def __init__(self, data_dir: Path):
        self.path = Path(data_dir) / "vault.enc"
        self.key_path = Path(data_dir) / "vault.key"
        self.lock = threading.Lock()
        self.key_source = "environment"  # or "file": data/vault.key, which goes wherever a copy of the data
        # folder goes; the worker lists that under Needs attention (Engine.check_silence)
        try:
            self.fernet = Fernet(self._load_key())
        except ValueError:
            raise VaultKeyError("the vault key isn't a valid key (32 url-safe base64 bytes)") from None
        if self.path.exists():
            try:
                self._read()
            except InvalidToken:
                raise VaultKeyError(
                    f"the vault key doesn't open {self.path}. Set DOORMAN_VAULT_KEY to the key it was made with "
                    f"(or put back vault.key); Doorman won't start with a different one") from None
        # The key now lives in this object only. Out of the environment, nothing Doorman starts later (a
        # helper process, a plugin kept in Doorman's process that runs a command) can inherit it. One Vault
        # per process: the engine's.
        os.environ.pop("DOORMAN_VAULT_KEY", None)

    def _load_key(self) -> bytes:
        env = os.environ.get("DOORMAN_VAULT_KEY")
        if env:
            return env.encode()
        if not self.key_path.exists():
            if self.path.exists():
                raise VaultKeyError(f"{self.path} exists but there is no key: set DOORMAN_VAULT_KEY or put back "
                                    f"vault.key (it is never in a backup)")
            self.key_path.write_bytes(Fernet.generate_key())
            os.chmod(self.key_path, 0o600)
        self.key_source = "file"
        return self.key_path.read_bytes().strip()

    def _read(self) -> dict:
        """The decrypted vault. Decrypted again only when the file changed (a write here, or doorman-admin
        in another process), since the worker lists plugins every few seconds."""
        version = self.version()
        if version is None:
            return {}
        cached = getattr(self, "_cache", None)
        if cached and cached[0] == version:
            return json.loads(cached[1])
        raw = self.fernet.decrypt(self.path.read_bytes())
        self._cache = (version, raw)
        return json.loads(raw)

    def _write(self, data: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        raw = json.dumps(data).encode()
        tmp.write_bytes(self.fernet.encrypt(raw))
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)  # a new inode, so another process's cache sees the change
        self._cache = (self.version(), raw)

    def version(self) -> tuple[int, int] | None:
        """Changes whenever the vault file is rewritten, by this process or another one."""
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return None
        return stat.st_mtime_ns, stat.st_ino

    def get(self, plugin: str) -> dict:
        """Only a plugin's own section; plugins never see each other's secrets."""
        with self.lock:
            return dict(self._read().get(plugin, {}))

    def set(self, plugin: str, key: str, value: str) -> None:
        with self.lock:
            data = self._read()
            data.setdefault(plugin, {})[key] = value
            self._write(data)

    def delete(self, plugin: str, key: str | None = None) -> None:
        with self.lock:
            data = self._read()
            if key is None:
                data.pop(plugin, None)
            else:
                data.get(plugin, {}).pop(key, None)
            self._write(data)

    def keys(self) -> dict[str, list[str]]:
        with self.lock:
            return {plugin: sorted(values) for plugin, values in self._read().items()}
