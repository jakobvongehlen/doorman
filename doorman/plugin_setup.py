"""Plugins as the owner sets them up: adding, settings, credentials, logins, and each tool's switch.

Every change here is the owner's (the owner app, doorman-admin) or an agent's within a manifest's allowlist
(agent_setup.py), and each is journaled as a `config` entry, so the ones that can be undone are reverted
like any other entry (revert_config). What a plugin is and how it runs is registry.py.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Callable

import yaml

from . import clock
from .mcp.client import check_url as check_mcp_url
from .plugin_api import Denied, PluginError
from .util import UPLOAD

log = logging.getLogger("doorman.plugin_setup")


class PluginSetup:
    def __init__(self, engine):
        self.engine = engine
        self.db = engine.db
        self._linking: set[str] = set()  # link logins started in the app; journaled once the phone links

    NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
    CREDENTIAL_RE = re.compile(r"^[a-z][a-z0-9_]{0,40}$")

    def _instance_block(self, name: str) -> dict:
        block = self.engine.registry.configured().get(name)
        if block is None:
            raise Denied(f"no plugin named {name}", "unknown_plugin")
        return block

    @staticmethod
    def _clean_config(config: Any) -> dict:
        if not isinstance(config, dict):
            raise Denied("config must be an object", "invalid")
        out = {}
        for key, value in config.items():
            if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,40}", key):
                raise Denied(f"bad config key {key!r}", "invalid")
            if value is None or value == "":
                continue
            if isinstance(value, str) and value.strip()[:1] in ("[", "{"):
                try:
                    value = yaml.safe_load(value)  # a list or mapping typed into the app: [a, b]
                except yaml.YAMLError:
                    raise Denied(f"{key}: not a valid list or mapping", "invalid") from None
            elif isinstance(value, str) and value.strip().lower() in ("true", "false"):
                value = value.strip().lower() == "true"
            if not isinstance(value, (str, int, float, bool, list, dict)):
                raise Denied(f"bad value for {key}", "invalid")
            out[key] = value
        return out

    def add(self, name: str, plugin_type: str, config: dict | None = None, no_approval: bool = False,
                   credentials: dict | None = None) -> dict:
        if not isinstance(name, str) or not self.NAME_RE.match(name):
            raise Denied("a plugin name is lower-case letters, digits and _, starting with a letter", "invalid")
        if name in self.engine.registry.configured() or name in (UPLOAD, "doorman"):
            raise Denied(f"there is already a plugin named {name}", "invalid")
        if plugin_type not in self.engine.registry.types:
            raise Denied(f"no plugin type {plugin_type}", "invalid")
        config = self._clean_config(config or {})
        if plugin_type == "mcp":
            config["url"] = self._mcp_url(config.get("url"))
            no_approval = False  # an MCP server's tools are allowed one by one
        for key, value in (credentials or {}).items():
            self._check_credential(key, value)
        self.engine.registry.save_instance(name, plugin_type, config, bool(no_approval))
        self.engine.registry.set_state(name, {"enabled": True, "read_only": False, "disabled_tools": []})
        for key, value in (credentials or {}).items():
            if value:
                self.engine.vault.set(name, key, value)
        after = {"type": plugin_type, "config": config, "no_approval": bool(no_approval)}
        what = f"MCP server {config['url']}" if plugin_type == "mcp" else plugin_type
        entry_id = self.engine.journal.create(
            kind="config", plugin=name, tool="plugin.add", tier="reversible", decision="run", status="done",
            before=None, after=after, args={"credentials": sorted(k for k, v in (credentials or {}).items() if v)},
            summary=f"Added plugin {name} ({what}){', runs sends without approval' if no_approval else ''}")
        if plugin_type == "mcp":
            self._mcp_try_sync(name)
        return {"entry_id": entry_id, "name": name}

    def configure(self, name: str, config: dict | None = None, no_approval: bool | None = None) -> dict:
        block = self._instance_block(name)
        before = {"type": block["type"], "config": dict(block.get("config") or {}),
                  "no_approval": bool(block.get("no_approval"))}
        after = {**before}
        if config is not None:
            after["config"] = self._clean_config(config)
        if no_approval is not None:
            after["no_approval"] = bool(no_approval)
        if block["type"] == "mcp":
            after["config"]["url"] = self._mcp_url(after["config"].get("url"))
            after["no_approval"] = False
        if after == before:
            return {"entry_id": None, "name": name}
        self.engine.registry.save_instance(name, block["type"], after["config"], after["no_approval"])
        changed = [k for k in ("config", "no_approval") if after[k] != before[k]]
        if block["type"] == "mcp" and after["config"].get("url") != before["config"].get("url"):
            changed = ["a new server address, so its sign-in, token and tool choices start over"]
            self.engine.resolve_attention("mcp_tools", name)  # news of the old address's tools
        entry_id = self.engine.journal.create(
            kind="config", plugin=name, tool="plugin.config", tier="reversible", decision="run", status="done",
            before=before, after=after, summary=f"Changed plugin {name}: {', '.join(changed)}")
        if block["type"] == "mcp":
            self._mcp_try_sync(name)
        return {"entry_id": entry_id, "name": name}

    def remove(self, name: str) -> dict:
        """Removes the plugin and its credentials. Its journal entries stay; it can't be reverted, since
        the credentials are gone. Its data folder is set aside (_set_aside_data), not deleted."""
        block = self._instance_block(name)
        self.engine.registry.delete_instance(name)  # closes it first: nothing of it has its folder open
        self.engine.library.purge(name)  # its items leave search at once
        self.engine.vault.delete(name)
        self.engine.resolve_attention("plugin", name)
        self.engine.resolve_attention("mcp_tools", name)
        kept = self._set_aside_data(name)
        entry_id = self.engine.journal.create(
            kind="config", plugin=name, tool="plugin.remove", tier="irreversible", decision="run", status="done",
            before={"type": block["type"], "config": block.get("config") or {}}, after=None,
            summary=f"Removed plugin {name} and its credentials"
                    + (f"; what it kept (a mail archive, a file index) is in {kept}" if kept else ""))
        return {"entry_id": entry_id, "data_kept_in": kept}

    def _set_aside_data(self, name: str) -> str | None:
        """A removed plugin's folder (data/plugins/<name>: a mail archive, a file index, logins) renamed to
        <name>.removed-<when> beside it, so a plugin added later under the same name starts empty instead of
        opening what this one kept. Nothing is deleted: the owner deletes the folder when it isn't wanted
        (it's in the backups until then). Returns where it went, relative to the data folder."""
        plugins = Path(self.engine.config["data_dir"]) / "plugins"
        folder = plugins / name
        if folder.is_symlink() or not folder.is_dir():
            return None
        target = plugins / f"{name}.removed-{clock.now().strftime('%Y%m%d-%H%M%S')}"
        try:
            folder.rename(target)  # within data/plugins: needs only that folder's permissions, also under privsep
        except OSError as exc:
            log.error("couldn't set aside %s after removing the plugin: %s", folder, exc)
            return None
        return f"plugins/{target.name}"

    def _check_credential(self, key: Any, value: Any) -> None:
        if not isinstance(key, str) or not self.CREDENTIAL_RE.match(key):
            raise Denied(f"bad credential name {key!r}", "invalid")
        if value is not None and (not isinstance(value, str) or len(value) > 10_000):
            raise Denied("a credential is a string", "invalid")

    def set_credential(self, name: str, key: str, value: str | None) -> dict:
        """Store (or with None, delete) one credential. The value never reaches the journal or the app again."""
        if name not in self.engine.registry.configured():
            raise Denied(f"no plugin named {name}", "unknown_plugin")
        self._check_credential(key, value)
        if value:
            self.engine.vault.set(name, key, value)
        else:
            self.engine.vault.delete(name, key)
        self.engine.registry.invalidate(name)
        entry_id = self.engine.journal.create(
            kind="config", plugin=name, tool="credential.set", tier="irreversible", decision="run", status="done",
            args={"key": key, "removed": not value},
            summary=f"{'Removed' if not value else 'Set'} {name} credential {key}")
        if self.engine.registry.is_mcp(name):
            self._mcp_try_sync(name)
        return {"entry_id": entry_id}

    # ------------------------------------------------------------------ MCP servers

    @staticmethod
    def _mcp_url(url: Any) -> str:
        try:
            return check_mcp_url(url)
        except PluginError as exc:
            raise Denied(str(exc), "invalid") from None

    def _mcp_instance(self, name: str):
        if not self.engine.registry.is_mcp(name):
            raise Denied(f"{name} isn't an MCP server", "invalid")
        return self.engine.registry.instance(name)

    def _mcp_try_sync(self, name: str) -> None:
        """Look at a server right after it was added or changed: list its tools, or learn that it wants a
        sign-in first. A failure here is normal (not signed in yet) and shows on its card."""
        try:
            self.engine.registry.invalidate(name)
            self.engine.registry.instance(name).sync()
        except Exception as exc:  # noqa: BLE001 - the card shows what went wrong
            log.info("first look at MCP server %s: %s", name, exc)

    def mcp_sync(self, name: str) -> dict:
        """Fetch the server's tool list now (the worker also does it on every plugin check)."""
        plugin = self._mcp_instance(name)
        try:
            changes = plugin.sync()
        except PluginError as exc:
            raise Denied(str(exc), "mcp") from None
        self.engine.resolve_attention("plugin", name)
        return changes

    def mcp_seen(self, name: str) -> dict:
        """The owner has looked at what changed in a server's tool list: the marks and the notice go."""
        self._mcp_instance(name)
        self.engine.registry.mcp.store.clear_news(name)
        self.engine.resolve_attention("mcp_tools", name)
        return {"ok": True}

    MCP_RULE_WORDS = {("allowed", True): "runs without asking you", ("allowed", False): "asks you first again",
                      ("treat_as", "read"): "is treated as a read", ("treat_as", "write"): "is treated as a write",
                      ("treat_as", None): "follows the server's label again"}

    def mcp_tool_rule(self, name: str, tool: str, treat_as: Any = "unchanged", allowed: Any = None) -> dict:
        """The owner's choice for one tool of an MCP server: treat it as a read or a write (None: as the
        server labels it), and whether it may run without asking. Journaled, so it can be reverted."""
        plugin = self._mcp_instance(name)
        store = self.engine.registry.mcp.store
        if not isinstance(tool, str):
            raise Denied("tool must be a name", "invalid")
        # a server's tool may itself be called "notion.x": the exact name wins over stripping the prefix
        short = tool if store.row(name, tool) or not tool.startswith(name + ".") else tool.split(".", 1)[1]
        before = store.rule(name, short)
        after = dict(before)
        if treat_as != "unchanged":
            if treat_as not in ("read", "write", None):
                raise Denied("treat_as is read, write or null", "invalid")
            after["treat_as"] = treat_as
        if allowed is not None:
            if not isinstance(allowed, bool):
                raise Denied("allowed is true or false", "invalid")
            after["allowed"] = allowed
        if after["allowed"] and store.is_read({**store.row(name, short), **after}):
            after["allowed"] = False  # a read never asks anyway
        if after == before:
            return {"entry_id": None, "rule": after}
        store.set_rule(name, short, after)
        words = [self.MCP_RULE_WORDS[(k, after[k])] for k in ("treat_as", "allowed") if after[k] != before[k]]
        label = (store.row(name, short)["spec"] or {}).get("title") or short
        entry_id = self.engine.journal.create(
            kind="config", plugin=name, tool="mcp.tool", tier="reversible", decision="run", status="done",
            args={"plugin": name, "tool": short}, before=before, after=after,
            summary=f"{plugin.title}: {label} {' and '.join(words)}")
        return {"entry_id": entry_id, "rule": after}

    # ------------------------------------------------------------------ logins (OAuth, linked devices)

    # login: oauth -- a sign-in page, then the owner pastes back the address it ends on (login_finish).
    # login: link -- the plugin shows a code the owner's phone scans or types (WhatsApp's linked devices); the
    # app asks login_status until it says connected.
    LOGIN_KINDS = ("oauth", "link")

    def _login_plugin(self, name: str, kind: str | None = None):
        self.engine.registry.state(name)  # unknown plugin -> Denied
        login = self.engine.registry.manifest(name).get("login")
        if login not in self.LOGIN_KINDS or (kind and login != kind):
            raise Denied(f"{name} has no login" if login not in self.LOGIN_KINDS else f"{name} doesn't sign in that way",
                         "invalid")
        return self.engine.registry.instance(name)

    def login_status(self, name: str) -> dict:
        try:
            status = self._login_plugin(name).login_status()
        except PluginError as exc:
            return {"connected": False, "ready": False, "error": str(exc)}
        if status.get("connected") and name in self._linking:  # the phone linked since Connect
            self._linking.discard(name)
            self.logged_in(name, status)
        return status

    def login_start(self, name: str, phone: str | None = None) -> dict:
        """oauth: the sign-in page's address. link: the first code; with phone, a pairing code to type
        instead of a QR code to scan."""
        self._login_plugin(name)  # unknown, or no login: Denied
        link = self.engine.registry.manifest(name).get("login") == "link"
        if phone and not link:
            raise Denied(f"{name} signs in on a web page, not with a phone number", "invalid")
        if link:
            self.engine.import_credential_files()  # a sidecar that started a moment ago: take its token now
        plugin = self._login_plugin(name)
        result = plugin.login_start(phone=phone) if phone else plugin.login_start()
        if link:
            self._linking.add(name)
        return result

    def login_finish(self, name: str, response_url: str) -> dict:
        return self.logged_in(name, self._login_plugin(name, "oauth").login_finish(response_url))

    def logged_in(self, name: str, result: dict) -> dict:
        """Journal a finished login (also the shell's device code login, which has no response URL)."""
        self.engine.journal.create(kind="config", plugin=name, tool="plugin.login", tier="irreversible", decision="run",
                            status="done", summary=f"Connected {name} to {result.get('account') or 'an account'}")
        return result

    def logout(self, name: str) -> dict:
        self._linking.discard(name)
        result = self._login_plugin(name).logout()
        self.engine.journal.create(kind="config", plugin=name, tool="plugin.logout", tier="irreversible", decision="run",
                            status="done", summary=f"Disconnected {name}")
        return result

    # ------------------------------------------------------------------ switches, and what a change loosens

    MODE_WORDS = {"off": "off", "ask": "asks you first", "auto": "runs without asking you"}

    def switch(self, instance: str, enabled: bool | None = None, read_only: bool | None = None,
                   tool: str | None = None, tool_enabled: bool | None = None, mode: str | None = None,
                   confirm: Callable[[], Any] | None = None) -> dict:
        """Switch a plugin on or off, read-only, or one of its tools. `mode` is a tool's position: off,
        ask (every call waits for the owner) or auto (runs on its own; a send only while every check
        passes). Reads are off or auto. A choice that matches the tool's default isn't stored, so the
        plugin's own no_approval keeps deciding for that tool.

        `confirm` runs before a change that lets a send run without asking where it couldn't before
        (sends_loosen): the owner API's fresh passkey check, which raises if there was none.

        Read-only is a shortcut in the plugin's settings for "every write Off", and the tool rows show it so:
        switching on one write while it is on keeps the other writes Off one by one, and switching it off
        when every write is also Off one by one turns them back to their own positions."""
        before = self.engine.registry.state(instance)
        after = {**before, "disabled_tools": list(before["disabled_tools"]),
                 "tool_approval": dict(before.get("tool_approval") or {})}
        if mode is not None:
            if tool is None or tool_enabled is not None:
                raise Denied("mode needs tool, and not tool_enabled", "invalid")
            if mode not in self.MODE_WORDS:
                raise Denied("mode is off, ask or auto", "invalid")
        words = []
        if enabled is not None:
            after["enabled"] = bool(enabled)
            words.append("on" if enabled else "off")
        if read_only is not None:
            after["read_only"] = bool(read_only)
            writes = set(self.engine.registry.write_names(instance))
            if not read_only and writes and writes <= set(after["disabled_tools"]):
                after["disabled_tools"] = sorted(set(after["disabled_tools"]) - writes)
            words.append("read-only" if read_only else "read-write")

        def write_on(short: str) -> None:
            """A write switched on under read-only: the shortcut goes, every other write stays Off."""
            writes = set(self.engine.registry.write_names(instance))
            if after["read_only"] and short in writes:
                after["read_only"] = False
                after["disabled_tools"] = sorted(set(after["disabled_tools"]) | (writes - {short}))

        if tool is not None and tool_enabled is not None:
            short = tool.split(".", 1)[1] if tool.startswith(instance + ".") else tool
            names = {t["name"] for t in self.engine.registry.manifest(instance).get("tools", [])} | \
                    {r["name"] for r in self.engine.registry.manifest(instance).get("reads", [])}
            if short not in names:
                raise Denied(f"{instance} has no tool {short}", "unknown_tool")
            if tool_enabled:
                write_on(short)
            disabled = set(after["disabled_tools"])
            disabled.discard(short) if tool_enabled else disabled.add(short)
            after["disabled_tools"] = sorted(disabled)
            words.append(f"{short} {'on' if tool_enabled else 'off'}")
        if tool is not None and mode is not None:
            short = tool.split(".", 1)[1] if tool.startswith(instance + ".") else tool
            manifest = self.engine.registry.manifest(instance)
            read = next((r for r in manifest.get("reads", []) if r["name"] == short), None)
            spec = next((t for t in manifest.get("tools", []) if t["name"] == short), None)
            if read is None and spec is None:
                raise Denied(f"{instance} has no tool {short}", "unknown_tool")
            if mode != "off" and self.engine.registry.is_mcp(instance) and spec is not None:
                raise Denied("an MCP server's tool asks or runs by its own rule (/owner/mcp/.../tools/...)", "invalid")
            if read is not None and mode == "ask":
                raise Denied("a read answers the agent at once, so it can't ask you first: it's on or off", "invalid")
            if spec is not None and mode == "auto" and spec.get("tier") == "payment":
                raise Denied("payments always ask you", "invalid")
            if mode != "off":
                write_on(short)
            disabled = set(after["disabled_tools"])
            disabled.add(short) if mode == "off" else disabled.discard(short)
            after["disabled_tools"] = sorted(disabled)
            if spec is not None and mode != "off":
                if mode == self.engine.registry.default_mode(instance, spec):
                    after["tool_approval"].pop(short, None)
                else:
                    after["tool_approval"][short] = mode
            words.append(f"{short} {'on' if read is not None and mode == 'auto' else self.MODE_WORDS[mode]}")
        if after == before:
            return {"entry_id": None, "state": after}
        if confirm is not None and self.sends_loosen(instance, before, after):
            confirm()
        self.engine.registry.set_state(instance, after)
        if after["enabled"]:  # the owner looked at a plugin an agent set up and switched it on
            self.db.exec("DELETE FROM settings WHERE key=?", (f"set_up_by:{instance}",))
            self.engine.resolve_attention("setup", instance)
        entry_id = self.engine.journal.create(kind="config", plugin=instance, tool="plugin.state", args={"plugin": instance},
                                       tier="reversible", decision="run", status="done", before=before, after=after,
                                       summary=f"Plugin {instance}: {', '.join(words) or 'no change'}")
        return {"entry_id": entry_id, "state": after}

    LOOSENESS = {"write": 0, None: 1, "read": 2}  # how freely an MCP tool runs, by treat_as

    def sends_unasked(self, instance: str, short: str, state: dict) -> bool:
        """Under this plugin state, would this tool's sends run without asking the owner? Only while the
        plugin is on, not read-only and the tool not Off (else it can't run at all); then the owner's Ask me
        or Auto on the tool decides, else the plugin's no_approval, or for an MCP server the owner's Always
        allow. Payments always ask."""
        if not state.get("enabled") or state.get("read_only") or short in state.get("disabled_tools", []):
            return False
        spec = next((t for t in self.engine.registry.manifest(instance).get("tools", []) if t["name"] == short), {})
        if spec.get("tier") != "irreversible":
            return False
        if self.engine.registry.is_mcp(instance):
            return self.engine.registry.mcp.store.allowed(instance, short)
        choice = (state.get("tool_approval") or {}).get(short)
        return choice == "auto" if choice else self.engine.registry.default_mode(instance, spec) == "auto"

    def unasked_sends(self, instance: str, state: dict) -> set[str]:
        """The tools whose sends run without asking the owner under this plugin state."""
        return {t["name"] for t in self.engine.registry.manifest(instance).get("tools", [])
                if self.sends_unasked(instance, t["name"], state)}

    def sends_loosen(self, instance: str, before: dict, after: dict) -> bool:
        """Does going from `before` to `after` let a tool send without asking that asked (or couldn't run)
        before? Whichever switch does it (a tool set to Auto, read-only off, the tool or the plugin switched
        back on while Auto or no_approval holds), that needs a fresh passkey check, like no_approval itself."""
        return bool(self.unasked_sends(instance, after) - self.unasked_sends(instance, before))

    def revert_loosens(self, entry_id: int) -> bool:
        """Would reverting this entry hand back something that needed a fresh passkey check: a plugin's
        settings (no_approval among them), a tool that sends without asking, or an MCP tool that runs more
        freely than now?"""
        entry = self.engine.journal.get(entry_id)
        if entry is None or entry["kind"] != "config" or entry["status"] != "done":
            return False
        if entry["tool"] == "plugin.config":
            return True
        if entry["tool"] == "plugin.state":
            try:  # the state the revert leaves, against the state now
                now = self.engine.registry.state(entry["plugin"])
                return self.sends_loosen(entry["plugin"], now, self._reverted_state(entry, now)[0])
            except (Denied, KeyError, TypeError):
                return False
        if entry["tool"] == "mcp.tool":
            before, after = entry["before"] or {}, entry["after"] or {}
            return bool(before.get("allowed")) and not after.get("allowed") or \
                self.LOOSENESS.get(before.get("treat_as"), 1) > self.LOOSENESS.get(after.get("treat_as"), 1)
        return False

    @staticmethod
    def _reverted_state(entry: dict, now: dict) -> tuple[dict, bool]:
        """The plugin state that reverting a plugin.state entry leaves, starting from the state `now`: only
        what the entry changed goes back. The flag says whether one of those fields changed again since."""
        before, after = entry["before"], entry["after"]
        target = {**now, "disabled_tools": set(now["disabled_tools"])}
        conflict = False
        for field in ("enabled", "read_only"):
            if before[field] != after[field]:
                conflict |= now[field] != after[field]
                target[field] = before[field]
        switched_off = set(after["disabled_tools"]) - set(before["disabled_tools"])
        switched_on = set(before["disabled_tools"]) - set(after["disabled_tools"])
        conflict |= not switched_off <= target["disabled_tools"] or bool(switched_on & target["disabled_tools"])
        # each tool's Ask me / Auto choice that this entry changed goes back, if nobody changed it since
        was, became = before.get("tool_approval") or {}, after.get("tool_approval") or {}
        approval = dict(now.get("tool_approval") or {})
        for short in set(was) | set(became):
            if was.get(short) != became.get(short):
                conflict |= approval.get(short) != became.get(short)
                approval.pop(short, None) if was.get(short) is None else approval.update({short: was[short]})
        target["tool_approval"] = approval
        target["disabled_tools"] = sorted((target["disabled_tools"] - switched_off) | switched_on)
        return target, conflict

    def revert_config(self, entry: dict, force: bool = False) -> dict:
        """Undo only what this entry changed, and only if nothing changed those fields since."""
        if entry["status"] != "done":
            return {"reverted": [], "skipped": [{"entry_id": entry["id"], "reason": entry["status"]}], "conflicts": [], "failed": []}
        before, after = entry["before"], entry["after"]
        if entry["tool"] == "plugin.state":
            now = self.engine.registry.state(entry["plugin"])
            target, conflict = self._reverted_state(entry, now)
            if conflict and not force:
                return {"reverted": [], "skipped": [],
                        "conflicts": [{"entry_id": entry["id"], "before": before, "after": after, "now": now}], "failed": []}
            self.engine.registry.set_state(entry["plugin"], target)
        elif entry["tool"] == "mcp.tool":
            short = (entry["args"] or {}).get("tool")
            try:
                now = self.engine.registry.mcp.store.rule(entry["plugin"], short)
            except Denied:
                now = None
            if now is None or (now != after and not force):
                return {"reverted": [], "skipped": [], "failed": [],
                        "conflicts": [{"entry_id": entry["id"], "before": before, "after": after, "now": now}]}
            self.engine.registry.mcp.store.set_rule(entry["plugin"], short, before)
        elif entry["tool"] in ("plugin.add", "plugin.config"):
            block = self.engine.registry.configured().get(entry["plugin"])
            now = None if block is None else {
                "type": block["type"], "config": dict(block.get("config") or {}),
                "no_approval": bool(block.get("no_approval"))}
            if now != after and not force:
                return {"reverted": [], "skipped": [], "failed": [],
                        "conflicts": [{"entry_id": entry["id"], "before": before, "after": after, "now": now}]}
            if before is None:  # undo adding it: the plugin goes, its credentials with it, as on removal
                self.engine.registry.delete_instance(entry["plugin"])
                self.engine.library.purge(entry["plugin"])
                self.engine.vault.delete(entry["plugin"])
                self._set_aside_data(entry["plugin"])
            else:
                self.engine.registry.save_instance(entry["plugin"], before["type"], before["config"], before["no_approval"])
        else:
            return {"reverted": [], "skipped": [{"entry_id": entry["id"], "reason": "can't revert"}], "conflicts": [], "failed": []}
        revert_id = self.engine.journal.create(kind="revert", reverts=entry["id"], plugin=entry["plugin"], tool=entry["tool"],
                                        args={"entry": entry["id"]}, tier="reversible", decision="run",
                                        status="done", before=entry["after"], after=entry["before"],
                                        summary=f"Reverted: {entry['summary']}")
        self.engine.journal.update(entry["id"], status="reverted", reverted_by=revert_id)
        return {"reverted": [entry["id"]], "skipped": [], "conflicts": [], "failed": []}
