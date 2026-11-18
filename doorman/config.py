"""Configuration: a YAML file merged over defaults."""

import copy
import os
from pathlib import Path
from typing import Any

import yaml

DEFAULTS: dict[str, Any] = {
    "data_dir": "./data",
    "public_url": "http://localhost:8711",
    "timezone": "UTC",
    "agent_listen": "127.0.0.1:8710",
    "agent_url": None,  # how agents reach the agent API, for the setup instructions (default: from agent_listen)
    "owner_listen": "127.0.0.1:8711",
    "approval_ttl_hours": 24,
    "push_group_seconds": 60,  # sends of one task within this long of the first share one push
    "send_wait_seconds": 3,  # the approve call waits this long for the send's result, then answers "sending"
    "task_lease_minutes": 30,  # a claimed task without a report by then fails, and the key is free again
    "approval_passkey": False,  # True: every approval is signed with the passkey, not just a tap
    "reader_actor_split": True,
    "taint_window_hours": 12,
    "owner_allow_cidrs": [],
    # addresses whose X-Forwarded-For the agent API believes, besides 127.0.0.1: the relay of an agent on a
    # Docker of its own that reaches Doorman through a relay, so network watch ties the agent's address to its key
    "agent_forwarded_from": [],
    "limits": {"direct_per_day": 30},  # no_approval plugins: actions without asking per 24 h, then they ask
    "payments": {"monthly_budget": 500.0},
    # who counts as the owner's on a send besides the trust list (policy.py KNOWN_DEFAULTS): `contacts` (their
    # own address books) and `written_before` (sends they approved, their Sent mail), both on. Not in the
    # defaults on purpose, like `guard`: a key set in doorman.yaml is fixed there; otherwise the app decides.
    "trust": {},
    "push": {"subject": None, "ttl_seconds": 86400},
    "reviewer": {"enabled": False, "model": "claude-opus-5-5", "effort": "medium", "api_key_env": "ANTHROPIC_API_KEY"},
    "owner": {"identities": []},
    "maintenance_interval_minutes": 60,
    "plugin_check_minutes": 60,  # how often each switched-on plugin's login is checked
    "trigger_poll_minutes": 5,  # how often plugins that declare events (or have triggers) are asked for new ones
    "events_days": 7,           # the event feed agents poll (GET /v1/events) keeps this many days
    "backup_warn_days": 7,  # no backup for this long: listed under Needs attention (0: never)
    # the worker's nightly backup (upkeep.py): at `schedule` (HH:MM, the owner's timezone) into `dir`, once
    # `dir` is set; then `copy_command` (rclone, restic...) copies it off the host. Scheduled, a backup older
    # than 36 hours is listed under Needs attention instead of after backup_warn_days.
    "backup": {"dir": None, "keep": 14, "extra_paths": [], "schedule": "03:30", "copy_command": None,
               "copy_env": [], "copy_timeout_minutes": 120},
    # a dead-man switch (healthchecks.io and the like): the worker GETs ping_url every 5 minutes, ping_url/fail
    # while /health would say unhealthy; the service alerts when the pings stop
    "health": {"ping_url": None},
    "reader_silent_minutes": 60,  # a reader key with no good round for this long: listed (0: never)
    "task_wait_warn_minutes": 60,  # tasks nobody picked up for this long: listed (0: never)
    # the vault key came from data/vault.key rather than DOORMAN_VAULT_KEY: listed under Needs attention
    # (false: never, for a demo or a dev instance)
    "vault_key_file_warn": True,
    "redaction": {
        # how much of one-time codes and sign-in links an agent loses (redaction.py): basic, strict or off
        "codes": "basic",
        "security_senders": [
            "no-reply@accounts.google.com",
            "account-security-noreply@accountprotection.microsoft.com",
            "security@*",
            "noreply@*bank*",
        ],
    },
    "honeytokens": [],
    # Doorman's one search index (library.py): plugins with `index:` feed it every few minutes, after their
    # jobs, and right after a write Doorman made through them or a change of their settings, then to the end
    # of that pass (pull_after_writes: off leaves both to those every few minutes)
    "search_index": {"pull_after_writes": True, "upkeep_minutes": 2},
    "plugin_paths": [],
    # every plugin in its own process, locked down with Landlock and seccomp (plugin_host.py); as root,
    # each also as a Linux user of its own (privsep.py)
    "plugin_sandbox": True,
    # plugin name -> what its process may touch beyond its manifest ({network: [...], user: doorman,
    # filesystem: open, read: [...], call_timeout_seconds: 600}), or false to keep it in Doorman's process.
    # Only here, on the host: the app and agents can't widen a sandbox. The plugins themselves are set up in
    # the app and live in doorman.db.
    "plugin_sandbox_overrides": {},
    "plugin_call_timeout_seconds": 300,  # a plugin call that takes longer fails, and the process restarts
    "plugin_idle_minutes": 15,           # a plugin's process stops after this long without calls
    # the injection guard (guard.py). Not in the defaults on purpose: a key set here in doorman.yaml
    # (enabled, threshold) is fixed there and read-only in the app; otherwise the app decides.
    # Also: window_tokens (512), overlap_tokens (64), idle_minutes (10), threads (0: half the CPUs, at most 4),
    # answer_seconds (80: an agent's call that waits longer for its scans answers `busy`).
    "guard": {},
    # files agents upload to attach (upload:<sha256>); per key at most max_total_mb and max_files kept at a time
    "uploads": {"max_mb": 25, "keep_days": 7, "max_total_mb": 500, "max_files": 200},
    # text from documents (extractor.py): pypdfium2, and RapidOCR (PP-OCRv6) for pages without a text layer
    # memory_mb caps the extractor's address space (virtual memory; 0: no cap)
    "extract": {"ocr": True, "dpi": 200, "ocr_max_pages": 20, "idle_minutes": 10, "max_mb": 50, "memory_mb": 2048},
    "dev_owner_token": None,
    "read_log_days": 90,           # the read log (who read what) keeps this many days; 0 keeps all
    # how long doorman.db keeps what grows with use, in days (0: for good); retention.py says what each means
    "retention": {"scans_days": 180, "quarantine_days": 365, "provenance_days": 90, "notifications_days": 90,
                  "attention_days": 90, "records_days": 365, "vacuum_days": 7},
    "worker_interval_seconds": 5,
    # network watch (egress/service.py): the proxy in front of the acting agent's container. It is on once the
    # owner made a proxy token in the app (`enabled` follows that); the rest are starting values the app
    # changes. risky_tlds and exfil_hosts None: the built-in lists (doorman/egress/data/).
    "egress": {
        "enabled": False,
        "match_hours": 24,        # how long what an agent read is remembered for the leak check
        "note_chars": 40,         # a request carrying this much of it is noted in the log
        "leak_chars": 200,        # and this much is a leak: the owner is told, every time
        "leak_action": "alert",   # alert: it goes out | block: it doesn't, and the agent's key is paused
        "log_days": 30,
        "large_upload_mb": 5,     # an upload this big to a host never seen before: the owner hears of it
        "nonweb": "log",          # log | block: connections that aren't web traffic
        "web_ports": [80, 443, 8080, 8443],
        "categories": {"exfil_upload": True, "risky_tlds": True, "countries": True, "bare_ip_nonweb": True,
                       "dns_tunnel": True},
        "countries": ["RU", "BY", "KP", "IR"],
        # what the leak check couldn't look at goes out too, unless the owner has it blocked (allow | block):
        "when_doorman_down": "allow",  # a request the proxy can't ask Doorman about
        "unscanned": "allow",     # an upload too large to check, to a host not allowed
        # model providers: not read (they get everything by design); exact API hosts only, never a cloud's
        # whole domain (a storage bucket there is a drop box). The API keys used with them are listed.
        "no_scan": ["api.anthropic.com", "api.openai.com", "openrouter.ai", "inference-api.nousresearch.com",
                    "generativelanguage.googleapis.com", "api.deepseek.com", "api.mistral.ai", "api.groq.com",
                    "api.together.xyz", "api.fireworks.ai", "api.x.ai", "api.cohere.com"],
        "deny": [], "allow": [], "passthrough": [],
        "risky_tlds": None, "exfil_hosts": None,
        # a file of fake API keys in the agent's container (egress/service.py, "decoy keys"): reading it or
        # using a key stops the agent (on_trip quarantine: keys paused, address cut off) or only tells (alert)
        "decoys": {"enabled": True, "on_trip": "quarantine"},
    },
}


def _merge(base: dict, extra: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (extra or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


class Config(dict):
    """Dict with a resolved data_dir and a few typed accessors."""

    path: Path | None = None  # the doorman.yaml it was loaded from, which a backup copies too

    @property
    def data_dir(self) -> Path:
        return Path(self["data_dir"])

    def secret_from_env(self, env_name: str | None) -> str | None:
        return os.environ.get(env_name) if env_name else None


class PluginsInConfig(Exception):
    """doorman.yaml defines plugins. They are set up in the owner app and live in doorman.db, so Doorman
    doesn't start: running on would quietly leave them out."""


def load(path: str | os.PathLike | None = None, overrides: dict | None = None) -> Config:
    """doorman.yaml over the defaults. A `plugins:` block in it stops this with PluginsInConfig."""
    data: dict = {}
    if path:
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
    plugins = data.pop("plugins", None) or {}
    if plugins:
        names = ", ".join(sorted(map(str, plugins))) if isinstance(plugins, dict) else "?"
        raise PluginsInConfig(
            f"{path} defines plugins ({names}). Plugins are set up in the owner app (Plugins → Add a plugin) and "
            f"kept in doorman.db: remove the `plugins:` block from the file")
    if "plugins" in (overrides or {}):
        raise TypeError("plugins aren't configuration: put them into the database (Registry.put_plugin)")
    merged = _merge(DEFAULTS, data)
    merged = _merge(merged, overrides or {})
    config = Config(merged)
    config.path = Path(path).resolve() if path else None
    base = Path(path).parent if path else Path.cwd()
    data_dir = Path(config["data_dir"])
    if not data_dir.is_absolute():
        data_dir = (base / data_dir).resolve()
    config["data_dir"] = str(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    return config


def archive_settings(name: str, settings: Any, base: Path, data_dir: Path, create: bool = True) -> dict:
    """A files plugin's settings with its `root` made absolute: without one, the archive is in the data
    directory (`archive/` for the instance named files, `archive-<name>` for another); a relative one is
    relative to doorman.yaml, like data_dir. With `create`, a missing folder is made; one Doorman can't
    create (/srv/archive without the rights) is left to the plugin's check, which says it isn't there.
    registry.configured applies it to every files plugin; it runs as Doorman's user (admin.py drops root
    or hands over to privsep first), so a folder it creates is Doorman's."""
    settings = dict(settings) if isinstance(settings, dict) else {}
    root = settings.get("root")
    if not root:
        root = data_dir / ("archive" if name == "files" else f"archive-{name}")
    else:
        root = Path(str(root)).expanduser()
        if not root.is_absolute():
            root = (base / root).resolve()
    if create and not root.is_dir():
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
    return {**settings, "root": str(root)}
