"""What agents may change about Doorman itself: plugin settings that carry no security weight, new plugins of
the kinds already installed, and switching things off.

Reads:  doorman.plugin_types   the kinds of plugin, what each needs, which settings an agent may change
        doorman.plugins        the plugins set up, their settings and state
Tools:  doorman.configure      change settings a plugin's manifest lists under agent_settings
        doorman.install        set up a plugin of an installed kind (manifest agent_install: true); it starts
                               switched off, and the owner reviews it, adds the sign-in and switches it on
        doorman.disable        switch a plugin, or one of its tools, off; or make a plugin read-only

Never through here: switching anything on, credentials and sign-ins, server addresses and other settings a
manifest doesn't list for agents, sending without approval, the injection guard, trust lists, keys, and
installing plugin code. Every change is a journal entry the owner can revert, marked with the agent's key.
The owner can switch all of this off with `agent_setup: false` in doorman.yaml.
"""

from __future__ import annotations

from typing import Any

from .plugin_api import Denied

READS = ("doorman.plugin_types", "doorman.plugins")
TOOLS = ("doorman.configure", "doorman.install", "doorman.disable")
NEVER_INSTALL = {"mcp"}   # adding one contacts its URL at once; the owner adds MCP servers


class AgentSetup:
    def __init__(self, engine):
        self.engine = engine

    @property
    def enabled(self) -> bool:
        return bool(self.engine.config.get("agent_setup", True))

    def _check(self, session: dict, key: dict, write: bool) -> None:
        self.engine._guard(session, None, write=write)
        if not self.enabled:
            raise Denied("the owner switched agent setup off (agent_setup: false)", "setup_off")
        if write and key["role"] == "reader":
            raise Denied("reader keys can't change Doorman's setup", "role")

    def _manifest(self, plugin_type: str) -> dict:
        kind = self.engine.registry.types.get(plugin_type)
        if kind is None:
            raise Denied(f"no plugin type {plugin_type}", "invalid")
        return kind.manifest

    # ------------------------------------------------------------------ reads

    def read(self, session: dict, key: dict, name: str) -> Any:
        self._check(session, key, write=False)
        if name == "doorman.plugin_types":
            out = []
            for kind in self.engine.registry.available():
                if kind["type"] in NEVER_INSTALL:
                    continue
                manifest = self._manifest(kind["type"])
                out.append({"type": kind["type"], "description": kind["description"], "settings": kind["config"],
                            "agent_settings": list(manifest.get("agent_settings") or []),
                            "agent_narrow": list(manifest.get("agent_narrow") or []),
                            "agent_add_only": list(manifest.get("agent_add_only") or []),
                            "agent_can_install": bool(manifest.get("agent_install")),
                            "credentials": kind["credentials"], "login": kind["login"], "in_use": kind["in_use"]})
            return out
        out = []
        for plugin in self.engine.registry.list():
            manifest = self._manifest(plugin["type"])
            out.append({"name": plugin["name"], "type": plugin["type"], "enabled": plugin["enabled"],
                        "read_only": plugin["read_only"], "disabled_tools": plugin["disabled_tools"],
                        "settings": plugin["config"], "agent_settings": list(manifest.get("agent_settings") or []),
                        "agent_narrow": list(manifest.get("agent_narrow") or []),   # only fewer, never more
                        "agent_add_only": list(manifest.get("agent_add_only") or []),   # only more, never fewer
                        "missing_credentials": plugin["missing_credentials"],
                        "jobs": {name: (job.get("status") or {}).get("summary") for name, job in
                                 self.engine.job_status(plugin["name"]).items()}})
        return out

    # ------------------------------------------------------------------ tools

    def call(self, session: dict, key: dict, name: str, args: dict) -> dict:
        self._check(session, key, write=True)
        if not isinstance(args, dict):
            raise Denied("args must be an object", "invalid")
        if name == "doorman.configure":
            return self.configure(session, key, args)
        if name == "doorman.install":
            return self.install(session, key, args)
        if name == "doorman.disable":
            return self.disable(session, key, args)
        raise Denied(f"unknown tool {name}", "unknown_tool")

    def _journal(self, session: dict, key: dict, **fields) -> int:
        return self.engine.journal.create(kind="config", session_id=session["id"], task_id=session.get("task_id"),
                                          tier="reversible", decision="run", status="done", **fields)

    def configure(self, session: dict, key: dict, args: dict) -> dict:
        name = args.get("plugin")
        changes = args.get("set") or {}
        unset = args.get("unset") or []
        if not isinstance(name, str) or not isinstance(changes, dict) or not isinstance(unset, list):
            raise Denied("configure takes plugin, set ({setting: value}) and/or unset ([setting])", "invalid")
        block = self.engine.registry.configured().get(name)
        if block is None:
            raise Denied(f"no plugin named {name}", "unknown_plugin")
        manifest = self._manifest(block["type"])
        whole, parts = agent_settings(manifest)
        asked = set(changes) | set(unset)
        refused = sorted(asked - whole - set(parts))
        if refused:
            listed = sorted(str(s) for s in manifest.get("agent_settings") or [])
            raise Denied(f"agents can't change {', '.join(refused)} of {name}; they may change: "
                         f"{', '.join(listed) or 'nothing'}. Ask the owner for the rest.", "setting")
        if not asked:
            raise Denied("nothing to change", "invalid")
        before = {"type": block["type"], "config": dict(block.get("config") or {}),
                  "no_approval": bool(block.get("no_approval"))}
        config = {k: v for k, v in before["config"].items() if k not in unset}
        cleaned = self.engine.plugin_setup._clean_config(changes)
        self._only_narrower(name, manifest, before["config"], cleaned, asked)
        config.update(cleaned)
        for k in set(changes) - set(cleaned):  # an empty value means unset
            config.pop(k, None)
        for setting in sorted(asked & set(parts)):  # a mapping of which agents may change some keys only
            value = _some_keys(name, setting, parts[setting], before["config"].get(setting),
                               None if setting in unset else cleaned.get(setting))
            if value:
                config[setting] = value
            else:
                config.pop(setting, None)
        after = {**before, "config": config}
        if after == before:
            return {"status": "done", "entry_id": None, "result": {"plugin": name, "changed": []}}
        self.engine.registry.save_instance(name, block["type"], config, before["no_approval"])
        words = [f"{k}: {before['config'].get(k, '(default)')} → {config.get(k, '(default)')}" for k in sorted(asked)
                 if before["config"].get(k) != config.get(k)]
        entry_id = self._journal(session, key, plugin=name, tool="plugin.config", args={"by": key["name"]},
                                 before=before, after=after,
                                 summary=f"Agent {key['name']} changed plugin {name}: {'; '.join(words)}")
        return {"status": "done", "entry_id": entry_id, "result": {"plugin": name, "changed": words}}

    @staticmethod
    def _only_narrower(name: str, manifest: dict, current: dict, cleaned: dict, asked: set) -> None:
        """Settings the manifest lists under agent_narrow (which calendars, task lists, address books) keep
        things away from agents: an agent may keep fewer of what the owner set, never more, and never clear
        it. Without a value set (everything) any choice is narrower. Settings under agent_add_only (folders
        not to archive) keep things out the other way round: an agent may add to the owner's list, never
        take one out or clear it."""
        for setting in sorted(set(manifest.get("agent_narrow") or []) & asked):
            now = _names(current.get(setting))
            if now is None:
                continue
            wanted = _names(cleaned.get(setting))
            if not wanted or not wanted <= now:
                raise Denied(f"agents may only narrow {setting} of {name} (keep some of: {', '.join(sorted(now))}); "
                             "ask the owner to add one or clear it", "setting")
        for setting in sorted(set(manifest.get("agent_add_only") or []) & asked):
            now = _names(current.get(setting))
            if now is not None and not now <= (_names(cleaned.get(setting)) or set()):
                raise Denied(f"agents may only add to {setting} of {name} (keep all of: {', '.join(sorted(now))}); "
                             "ask the owner to take one out or clear it", "setting")

    def install(self, session: dict, key: dict, args: dict) -> dict:
        plugin_type, name, config = args.get("type"), args.get("name"), args.get("settings") or {}
        if not isinstance(plugin_type, str) or plugin_type in NEVER_INSTALL:
            raise Denied("give the type of an installed plugin (doorman.plugin_types)", "invalid")
        manifest = self._manifest(plugin_type)
        if not manifest.get("agent_install"):
            raise Denied(f"agents can't set up {plugin_type} plugins; ask the owner", "setting")
        if not isinstance(name, str) or not self.engine.plugin_setup.NAME_RE.match(name):
            raise Denied("a plugin name is lower-case letters, digits and _, starting with a letter", "invalid")
        if name in self.engine.registry.configured() or name in ("upload", "doorman"):
            raise Denied(f"there is already a plugin named {name}", "invalid")
        if not isinstance(config, dict):
            raise Denied("settings must be an object", "invalid")
        unknown = sorted(set(config) - set(manifest.get("config") or {}))
        if unknown:
            raise Denied(f"{plugin_type} has no settings {', '.join(unknown)}", "invalid")
        config = self.engine.plugin_setup._clean_config(config)
        self.engine.registry.save_instance(name, plugin_type, config, False)
        self.engine.registry.set_state(name, {"enabled": False, "read_only": False, "disabled_tools": []})
        self.engine.db.set_setting(f"set_up_by:{name}", key["name"])
        entry_id = self._journal(session, key, plugin=name, tool="plugin.add", args={"by": key["name"]}, before=None,
                                 after={"type": plugin_type, "config": config, "no_approval": False},
                                 summary=f"Agent {key['name']} set up plugin {name} ({plugin_type}), switched off")
        needs = list(manifest.get("credentials") or [])
        step = ", connect it" if manifest.get("login") else f", add {', '.join(needs)}" if needs else ""
        self.engine.attention("setup", name, f"Your agent set up {name}",
                              f"A {plugin_type} plugin, switched off. Check its settings{step}, then switch it on "
                              "if you want it.",
                              url=f"{self.engine.public_url}/app/#/plugins", priority=3)
        return {"status": "done", "entry_id": entry_id,
                "result": {"plugin": name, "enabled": False,
                           "next": "The owner reviews it in the app, adds the sign-in and switches it on. Until "
                                   "then it does nothing."}}

    def disable(self, session: dict, key: dict, args: dict) -> dict:
        name, tool, read_only = args.get("plugin"), args.get("tool"), args.get("read_only")
        if not isinstance(name, str):
            raise Denied("disable takes plugin, and optionally tool or read_only: true", "invalid")
        before = self.engine.registry.state(name)
        after = {**before, "disabled_tools": list(before["disabled_tools"])}
        if tool is not None:
            short = tool.split(".", 1)[1] if isinstance(tool, str) and tool.startswith(name + ".") else tool
            names = {t["name"] for t in self.engine.registry.manifest(name).get("tools", [])} | \
                    {r["name"] for r in self.engine.registry.manifest(name).get("reads", [])}
            if short not in names:
                raise Denied(f"{name} has no tool {tool}", "unknown_tool")
            after["disabled_tools"] = sorted(set(after["disabled_tools"]) | {short})
            what = f"{short} off"
        elif read_only is True:
            after["read_only"] = True
            what = "read-only"
        else:
            after["enabled"] = False
            what = "off"
        if after == before:
            return {"status": "done", "entry_id": None, "result": {"plugin": name, "state": after}}
        self.engine.registry.set_state(name, after)
        entry_id = self._journal(session, key, plugin=name, tool="plugin.state", args={"plugin": name, "by": key["name"]},
                                 before=before, after=after, summary=f"Agent {key['name']}: plugin {name} {what}")
        return {"status": "done", "entry_id": entry_id, "result": {"plugin": name, "state": after}}


def agent_settings(manifest: dict) -> tuple[set[str], dict[str, set[str]]]:
    """What a manifest's agent_settings lets agents change: whole settings, and for a mapping listed by its
    keys (`folders.drafts`), {setting: those keys}. The mapping's other keys stay the owner's: mail's
    `folders.sent` decides whose mail counts as "you wrote to them before" (known_recipients)."""
    whole: set[str] = set()
    parts: dict[str, set[str]] = {}
    for entry in manifest.get("agent_settings") or []:
        setting, dot, sub = str(entry).partition(".")
        if dot:
            parts.setdefault(setting, set()).add(sub)
        else:
            whole.add(setting)
    return whole, {k: v for k, v in parts.items() if k not in whole}


def _some_keys(name: str, setting: str, allowed: set[str], current: Any, value: Any) -> dict:
    """A mapping setting after an agent changed the keys it may (`allowed`): those keys from `value`, merged
    over the owner's mapping (a key set to null or "" goes; `value` None takes every allowed key out); the
    other keys stay as the owner left them."""
    if current is not None and not isinstance(current, dict):
        raise Denied(f"{setting} of {name} isn't a mapping; ask the owner", "setting")
    out = dict(current or {})
    if value is None:
        return {k: v for k, v in out.items() if k not in allowed}
    keys = ", ".join(f"{setting}.{k}" for k in sorted(allowed))
    if not isinstance(value, dict):
        raise Denied(f"{setting} is a mapping; agents may set {keys}", "invalid")
    refused = sorted(set(map(str, value)) - allowed)
    if refused:
        raise Denied(f"agents may change only {keys} of {name}; {', '.join(f'{setting}.{k}' for k in refused)} "
                     "is the owner's. Ask the owner for that.", "setting")
    for sub, v in value.items():
        if v is None or v == "":
            out.pop(sub, None)
        elif isinstance(v, (str, int, float, bool)):
            out[sub] = v
        else:
            raise Denied(f"{setting}.{sub} takes a single value", "invalid")
    return out


def _names(value) -> set[str] | None:
    """A list setting as a set of names (one name typed without brackets counts as a list); None unset."""
    if value is None or value == "":
        return None
    return {str(v) for v in value} if isinstance(value, list) else {str(value)}
