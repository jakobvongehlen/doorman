"""Finds plugins, keeps their on/off state, and hands out tool and read objects."""

from __future__ import annotations

import copy
import difflib
import errno
import importlib.util
import logging
import os
import re
import threading
from pathlib import Path
from stat import S_ISREG
from typing import Any

import yaml

from .mcp import McpType
from .plugin_api import BasePlugin, Denied, PluginContext, PluginError
from .plugin_host import RemotePlugin, Spawner, harden_data_dir
from . import clock, manifest_check
from .util import dumps, loads
from .config import archive_settings

BUILTIN_DIR = Path(__file__).parent / "plugins"
# what a new Doorman starts with (engine.py, on a database made just now): its notes, and the file archive in
# data/archive. The owner removes either in the app like any other plugin.
STARTER_PLUGINS: dict[str, dict] = {
    "notes": {"enabled": True},
    "files": {"enabled": True, "config": {"ocr": False}},
}
log = logging.getLogger("doorman.registry")
CREDENTIAL_FILE_MAX = 4096                 # a token, not a document
CREDENTIAL_TOKEN = re.compile(r"[\x21-\x7e]+")   # printable ASCII, no spaces
_YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)  # libyaml: ten times faster than pure Python
_manifests: dict[Path, tuple[tuple[int, int], dict]] = {}


def load_manifest(path: Path) -> dict:
    """A manifest.yaml, parsed once per process and again only when the file changes. Each caller gets its
    own copy. Every engine (and so every test) reads all of them, and parsing was most of its start-up."""
    stat = path.stat()
    stamp = (stat.st_mtime_ns, stat.st_size)
    cached = _manifests.get(path)
    if cached is None or cached[0] != stamp:
        cached = (stamp, yaml.load(path.read_text(), Loader=_YAML_LOADER) or {})
        _manifests[path] = cached
    return copy.deepcopy(cached[1])


def declared_events(manifest: dict) -> list[dict]:
    """A manifest's `events:`, each as {name, description, fields}. A plain name (`events: [new_mail]`) still
    works; it just tells the agent less."""
    out = []
    for entry in manifest.get("events") or []:
        if isinstance(entry, str):
            out.append({"name": entry, "description": "", "fields": []})
        else:
            out.append({"name": str(entry["name"]), "description": str(entry.get("description") or "").strip(),
                        "fields": [str(f) for f in entry.get("fields") or []]})
    return out


def polls_events(manifest: dict) -> bool:
    """Whether the worker asks the plugin's poll_events: some declared event comes from no job. A plugin
    whose events all come from jobs isn't woken every few minutes for nothing."""
    return any(isinstance(e, str) or (isinstance(e, dict) and not e.get("job")) for e in manifest.get("events") or [])


def merged_manifest(path: Path) -> dict:
    """A plugin folder's manifest, with `extends: mail_imap` taking that plugin's manifest first (the keys
    given here replace its keys)."""
    manifest = load_manifest(path / "manifest.yaml")
    if isinstance(manifest, dict) and manifest.get("extends"):
        base_path = path.parent / str(manifest["extends"]) / "manifest.yaml"
        if not base_path.is_file():
            raise PluginError(f"extends: {manifest['extends']}, but there's no {base_path}")
        manifest = {**load_manifest(base_path), **manifest}
    return manifest


class PluginType:
    def __init__(self, path: Path):
        """Raises PluginError (or a YAML error) for a manifest that can't work: see manifest_check.py.
        Unknown keys are only logged, as warnings."""
        self.path = path
        self.manifest = merged_manifest(path)
        errors, self.warnings = manifest_check.check(self.manifest)
        if errors:
            raise PluginError("; ".join(errors))
        for warning in self.warnings:
            log.warning("%s: %s", path / "manifest.yaml", warning)
        self.name = self.manifest["name"]
        self._cls: type[BasePlugin] | None = None

    @property
    def builtin(self) -> bool:
        return self.path.resolve().parent == BUILTIN_DIR.resolve()

    def load_class(self) -> type[BasePlugin]:
        if self._cls is None:
            module_name = f"doorman_plugin_{self.name}"
            spec = importlib.util.spec_from_file_location(module_name, self.path / "plugin.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self._cls = module.Plugin
        return self._cls

    def manifest_for(self, instance: str, block: dict) -> dict:
        """The manifest of one instance. The same for every instance of a plugin directory; an MCP
        server's (McpType) comes from its tool list."""
        return self.manifest

    def create(self, ctx: PluginContext, manifest: dict) -> BasePlugin:
        return self.load_class()(ctx, manifest)


class CredentialFileRefused(Exception):
    """A credential file that isn't a plain, small file holding one token."""


def read_credential_file(path: str) -> tuple[str, tuple[int, int]]:
    """The token another container left for Doorman in a volume both mount (`credential_files:`), and the
    file's (mtime, size). That container controls what is there, so nothing on the way is trusted: every
    folder of the path is opened without following a link, so a link anywhere (to the vault key, to
    /dev/zero, a folder swapped for one) refuses the file; it must be a regular file (a FIFO would block
    Doorman's worker, which reads it), at most 4 KB, and one token. FileNotFoundError when there's none."""
    parts = path.split("/")
    if not path.startswith("/") or any(part in (".", "..") for part in parts):
        raise CredentialFileRefused("not an absolute path")
    parts = [part for part in parts if part]
    if not parts:
        raise CredentialFileRefused("not a file")
    folder = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in parts[:-1]:
            try:
                inner = os.open(name, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=folder)
            except NotADirectoryError:
                raise CredentialFileRefused(f"{name} on the way is a link or a file, not a folder") from None
            os.close(folder)
            folder = inner
        try:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC,
                         dir_fd=folder)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENXIO):
                raise CredentialFileRefused("a link or a socket, not a file") from None
            raise
    finally:
        os.close(folder)
    try:
        info = os.fstat(fd)
        if not S_ISREG(info.st_mode):
            raise CredentialFileRefused("not a regular file")
        if info.st_size > CREDENTIAL_FILE_MAX:
            raise CredentialFileRefused(f"larger than {CREDENTIAL_FILE_MAX} bytes")
        data = os.read(fd, CREDENTIAL_FILE_MAX + 1)
    finally:
        os.close(fd)
    value = data.decode("ascii", "replace").strip()
    if len(data) > CREDENTIAL_FILE_MAX or not CREDENTIAL_TOKEN.fullmatch(value):
        raise CredentialFileRefused("not a token (printable ASCII without spaces, at most 4 KB)")
    return value, (info.st_mtime_ns, info.st_size)


class Registry:
    starter = STARTER_PLUGINS  # tests start without them (conftest.py)

    def __init__(self, config, db, vault, redactor, resolve_ref, extract=None, embed=None):
        self.config = config
        self.extract = extract
        self.embed = embed
        self.db = db
        self.vault = vault
        self.redactor = redactor
        self.resolve_ref = resolve_ref
        self.types: dict[str, PluginType] = {}
        self.instances: dict[str, BasePlugin] = {}
        self.lock = threading.RLock()
        self._vault_seen = vault.version()
        self._credential_files_seen: dict[tuple[str, str], tuple] = {}
        self.discover()
        self.mcp = McpType(db, vault)  # MCP servers are part of Doorman, not a plugin directory
        self.types["mcp"] = self.mcp
        if self.config.get("plugin_sandbox", True):
            harden_data_dir(Path(self.config["data_dir"]))
            Spawner.get()  # takes the root process's socket out of the environment right away

    def isolated(self, block: dict) -> bool:
        """Whether a plugin runs in its own locked-down process (plugin_host.py). MCP servers are the
        doorman's own code talking to a remote server, so they stay in Doorman."""
        return (bool(self.config.get("plugin_sandbox", True)) and block.get("sandbox") is not False
                and not isinstance(self.types.get(block["type"]), McpType))

    # discovery and configuration

    def discover(self) -> None:
        """Every plugin folder. One whose manifest can't work is left out, logged and kept in `broken`
        (folder -> what's wrong), which the worker lists under Needs attention; Doorman starts without it."""
        self.broken: dict[str, str] = {}
        dirs = [BUILTIN_DIR] + [Path(p) for p in self.config.get("plugin_paths", [])]
        for base in dirs:
            if not base.exists():
                continue
            for path in sorted(base.iterdir()):
                if (path / "manifest.yaml").exists() and (path / "plugin.py").exists():
                    try:
                        plugin_type = PluginType(path)
                    except Exception as exc:  # noqa: BLE001 - YAML, a missing name, ...: skip this one plugin
                        self.broken[str(path)] = f"{type(exc).__name__}: {exc}" if not isinstance(exc, PluginError) \
                            else str(exc)
                        log.error("plugin %s left out: %s", path, self.broken[str(path)])
                        continue
                    self.types[plugin_type.name] = plugin_type

    def configured(self) -> dict[str, dict]:
        """Instance name -> its block (type, config, no_approval): the plugins set up in the owner app, kept in
        the database, in the order they were added. doorman.yaml's `plugin_sandbox_overrides` for a name
        becomes its block's `sandbox` (what its process may touch beyond its manifest)."""
        out = {}
        overrides = self.config.get("plugin_sandbox_overrides") or {}
        for row in self.db.all("SELECT * FROM plugin_instances ORDER BY created, rowid"):
            name, settings = row["name"], loads(row["config"], {})
            if row["type"] == "files":  # without a root: an archive in the data dir
                data_dir = Path(self.config["data_dir"])
                base = self.config.path.parent if getattr(self.config, "path", None) else data_dir.parent
                settings = archive_settings(name, settings, base, data_dir)
            block = {"type": row["type"], "config": settings, "no_approval": bool(row["no_approval"])}
            if name in overrides:
                block["sandbox"] = overrides[name]
            if block["type"] not in self.types:
                log.warning("plugin %s: unknown type %s", name, block["type"])
                continue
            out[name] = block
        return out

    def event_sources(self) -> list[str]:
        """Instances whose manifest declares events poll_events returns: the worker asks them for new ones
        (engine.poll_triggers). Events a job returns come with the job's run instead. MCP servers declare
        none."""
        return [name for name, block in self.configured().items()
                if not isinstance(self.types[block["type"]], McpType) and polls_events(self.types[block["type"]].manifest)]

    def manifest(self, instance: str) -> dict:
        block = self.configured()[instance]
        return self.types[block["type"]].manifest_for(instance, block)

    def is_mcp(self, instance: str | None) -> bool:
        return (self.configured().get(instance) or {}).get("type") == "mcp" if instance else False

    def no_approval(self, instance: str, tool: str | None = None) -> bool:
        """Whether a send of this tool runs without asking. The owner's choice for the tool wins ("Ask me" or
        "Auto" on its row); without one, `no_approval: true` on the plugin lets its irreversible tools run.
        Payments never do, and the plugin switch leaves out a tool its manifest marks `always_approve`
        (sending files, public links). An MCP server has no such switch; the owner allows its tools one by
        one. The engine also asks whenever one of the send's checks fails."""
        short = tool.split(".", 1)[1] if tool and "." in tool else tool
        if self.is_mcp(instance):
            return bool(short) and self.mcp.store.allowed(instance, short)
        spec = next((t for t in self.manifest(instance).get("tools", []) if t["name"] == short), {}) if short else {}
        if spec.get("tier") == "payment":
            return False
        choice = self.tool_choice(instance, short) if short else None
        if choice is not None:
            return choice == "auto" and spec.get("tier") == "irreversible"
        if not (self.configured().get(instance) or {}).get("no_approval"):
            return False
        return tool is None or not spec.get("always_approve")

    def tool_choice(self, instance: str, short: str) -> str | None:
        """The owner's "ask" or "auto" for one tool, or None: the tool does what its kind does by default."""
        return self.state(instance)["tool_approval"].get(short)

    def asks_first(self, instance: str, tool: str) -> bool:
        """The owner set this tool to "Ask me": even its undoable calls wait for approval."""
        short = tool.split(".", 1)[1] if "." in tool else tool
        return not self.is_mcp(instance) and self.tool_choice(instance, short) == "ask"

    def default_mode(self, instance: str, spec: dict, kind: str = "tool") -> str:
        """What a tool does when the owner hasn't chosen: reads and undoable writes run on their own
        ("auto"), sends and payments ask, unless the plugin has `no_approval` (not for payments or
        `always_approve` tools)."""
        tier = "read" if kind == "read" else spec.get("tier", "reversible")
        if tier in ("read", "reversible"):
            return "auto"
        if tier == "irreversible" and (self.configured().get(instance) or {}).get("no_approval") \
                and not spec.get("always_approve"):
            return "auto"
        return "ask"

    def tool_mode(self, instance: str, short: str, state: dict | None = None) -> str:
        """off, ask or auto: what the owner sees on the tool's row. Read-only means every write is off."""
        state = state or self.state(instance)
        if short in state["disabled_tools"]:
            return "off"
        manifest = self.manifest(instance)
        read = next((r for r in manifest.get("reads", []) if r["name"] == short), None)
        if read is not None:
            return "auto"
        if state["read_only"]:
            return "off"
        spec = next((t for t in manifest.get("tools", []) if t["name"] == short), {})
        return state.get("tool_approval", {}).get(short) or self.default_mode(instance, spec)

    def state(self, instance: str) -> dict:
        block = self.configured().get(instance)
        if block is None:
            raise Denied(f"no plugin named {instance}", "unknown_plugin")
        row = self.db.one("SELECT * FROM plugin_state WHERE name=?", (instance,))
        if row is None:
            return {"enabled": False, "read_only": False, "disabled_tools": [], "tool_approval": {}}
        return {"enabled": bool(row["enabled"]), "read_only": bool(row["read_only"]),
                "disabled_tools": loads(row["disabled_tools"], []),
                "tool_approval": loads(row["tool_approval"], {}) or {}}

    def set_state(self, instance: str, state: dict) -> None:
        self.db.exec(
            "INSERT INTO plugin_state(name, enabled, read_only, disabled_tools, tool_approval) VALUES(?,?,?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET enabled=excluded.enabled, read_only=excluded.read_only, "
            "disabled_tools=excluded.disabled_tools, tool_approval=excluded.tool_approval",
            (instance, int(state["enabled"]), int(state["read_only"]), dumps(sorted(state["disabled_tools"])),
             dumps(dict(sorted((state.get("tool_approval") or {}).items())))),
        )
        if not state["enabled"]:
            self.invalidate(instance)

    def cursor(self, instance: str) -> str | None:
        row = self.db.one("SELECT cursor FROM plugin_state WHERE name=?", (instance,))
        return row["cursor"] if row else None

    def set_cursor(self, instance: str, cursor: str | None) -> None:
        state = self.state(instance)
        self.set_state(instance, state)
        self.db.exec("UPDATE plugin_state SET cursor=? WHERE name=?", (cursor, instance))

    # instances

    def _save_credential(self, name: str, key: str, value: str | None) -> None:
        if value is None:
            self.vault.delete(name, key)
        else:
            self.vault.set(name, key, value)
        self._vault_seen = self.vault.version()  # our own change; the instance already knows it

    def _check_vault(self) -> None:
        """Another process (doorman-admin vault set / login) changed credentials: rebuild the instances."""
        version = self.vault.version()
        if version != self._vault_seen:
            self._vault_seen = version
            for name in list(self.instances):
                self.invalidate(name)

    def instance(self, name: str) -> BasePlugin:
        with self.lock:
            self._check_vault()
            if name in self.instances:
                return self.instances[name]
            block = self.configured().get(name)
            if block is None:
                raise Denied(f"no plugin named {name}", "unknown_plugin")
            plugin_type = self.types[block["type"]]
            manifest = plugin_type.manifest_for(name, block)  # first: an MCP server may drop old credentials
            data_dir = Path(self.config["data_dir"]) / "plugins" / name
            data_dir.mkdir(parents=True, exist_ok=True)
            ctx = PluginContext(
                instance=name,
                config=dict(block.get("config") or {}),
                credentials=self.vault.get(name),
                data_dir=data_dir,
                resolve_ref=self.resolve_ref,
                redactor=self.redactor,
                owner_identities={v.lower() for v in self.config.get("owner", {}).get("identities", [])},
                log=logging.getLogger(f"doorman.plugin.{name}"),
                save_credential=lambda key, value, _name=name: self._save_credential(_name, key, value),
                extract=self.extract,
                embed=self.embed,
            )
            if self.isolated(block):
                plugin = RemotePlugin(self, name, plugin_type, block, manifest, ctx)
            else:
                plugin = plugin_type.create(ctx, manifest)
            self.instances[name] = plugin
            return plugin

    def import_credential_files(self) -> list[tuple[str, str]]:
        """Credentials that a plugin shipped with Doorman reads from a file Doorman's host provides, e.g. the
        WhatsApp sidecar's token in the volume both containers mount (`credential_files:` in its manifest).
        A file that exists and differs from the vault wins, since it is what the other side uses. Only
        built-in manifests may name files: another plugin could name any file Doorman can read. The other
        container controls the file, so it is read with care (read_credential_file); one that isn't a plain
        token is left out and logged once. Returns the (instance, key) pairs it changed."""
        changed = []
        version = self.vault.version()
        for name, block in self.configured().items():
            plugin_type = self.types.get(block["type"])
            if not isinstance(plugin_type, PluginType) or not plugin_type.builtin:
                continue
            for key, path in (plugin_type.manifest.get("credential_files") or {}).items():
                try:
                    value, stamp = read_credential_file(str(path))
                except FileNotFoundError:
                    continue
                except (OSError, CredentialFileRefused) as exc:
                    refused = ("refused", str(exc))
                    if self._credential_files_seen.get((name, key)) != refused:
                        log.warning("%s: not taking %s from %s: %s", name, key, path, exc)
                        self._credential_files_seen[(name, key)] = refused
                    continue
                seen = (*stamp, version)
                if self._credential_files_seen.get((name, key)) == seen:
                    continue  # nothing changed since the last look: skip opening the vault
                if self.vault.get(name).get(key) != value:
                    self.vault.set(name, key, value)
                    self.invalidate(name)
                    changed.append((name, key))
                    version = self.vault.version()
                    seen = (*stamp, version)
                self._credential_files_seen[(name, key)] = seen
        return changed

    def invalidate(self, name: str) -> None:
        with self.lock:
            plugin = self.instances.pop(name, None)
        if plugin:
            try:
                plugin.close()
            except Exception:  # noqa: BLE001 - closing must never break a state change
                log.exception("closing %s", name)

    # lookups used by the engine

    def split(self, full_name: str, kind: str = "tool") -> tuple[str, str]:
        if "." not in full_name:
            raise Denied(f"unknown {kind} {full_name}{self.hint(full_name, kind)}", f"unknown_{kind}")
        instance, short = full_name.split(".", 1)
        return instance, short

    def names(self, kind: str) -> list[str]:
        """Every tool ("tool") or read ("read") of the switched-on plugins, as agents name them."""
        out = []
        for instance in self.configured():
            try:
                if not self.state(instance)["enabled"]:
                    continue
                manifest = self.manifest(instance)
            except (Denied, PluginError, KeyError):
                continue
            out += [f"{instance}.{entry['name']}" for entry in manifest.get("tools" if kind == "tool" else "reads", [])]
        return out

    def hint(self, wanted: str, kind: str) -> str:
        """For an unknown name: a read called as a tool (or the other way round), else close names."""
        other = "read" if kind == "tool" else "tool"
        if wanted in self.names(other):
            return f"; {wanted} is a {other}: doorman {'read' if other == 'read' else 'call'} {wanted}"
        close = difflib.get_close_matches(wanted, self.names(kind), n=3, cutoff=0.6)
        if not close and "." in wanted:  # mial.send: the plugin's name is off, the rest is right
            short = wanted.split(".", 1)[1]
            close = [n for n in self.names(kind) if n.split(".", 1)[1] == short][:3]
        return f"; did you mean {' or '.join(close)}?" if close else "; doorman caps --brief lists them"

    def _state_for(self, instance: str, full_name: str, kind: str) -> dict:
        try:
            return self.state(instance)
        except Denied as exc:
            if exc.code != "unknown_plugin":
                raise
            raise Denied(f"no plugin named {instance}{self.hint(full_name, kind)}", "unknown_plugin") from None
    def write_names(self, instance: str) -> list[str]:
        return [t["name"] for t in self.manifest(instance).get("tools", [])]

    def all_writes_off(self, instance: str, state: dict) -> bool:
        """Read-only as the owner sees it in the plugin's settings: the shortcut is on, or every write is Off
        one by one. A plugin without writes isn't read-only; it has nothing to switch."""
        names = self.write_names(instance)
        return bool(state["read_only"]) or (bool(names) and set(names) <= set(state["disabled_tools"]))

    # Denials name the one place the owner changes them: the plugin's settings in the owner app (Plugins).

    def find_tool(self, full_name: str):
        instance, short = self.split(full_name)
        state = self._state_for(instance, full_name, "tool")
        if not state["enabled"]:
            raise Denied(f"{instance} is switched off in the owner app (Plugins)", "plugin_disabled")
        if state["read_only"]:
            raise Denied(f"{full_name} is Off in {instance}'s settings: {instance} is read-only (Plugins → Tools)",
                         "plugin_read_only")
        if short in state["disabled_tools"]:
            raise Denied(f"{full_name} is Off in {instance}'s settings (Plugins → Tools)", "tool_disabled")
        plugin = self.instance(instance)
        tool = plugin.tools.get(short)
        if tool is None:
            raise Denied(f"unknown tool {full_name}{self.hint(full_name, 'tool')}", "unknown_tool")
        return instance, plugin, tool

    def tool_for_revert(self, instance: str, short: str):
        """Reverts work even while a plugin is switched off."""
        plugin = self.instance(instance)
        tool = plugin.tools.get(short)
        if tool is None:
            raise PluginError(f"plugin {instance} no longer has tool {short}")
        return plugin, tool

    def find_read(self, full_name: str):
        instance, short = self.split(full_name, "read")
        state = self._state_for(instance, full_name, "read")
        if not state["enabled"]:
            raise Denied(f"{instance} is switched off in the owner app (Plugins)", "plugin_disabled")
        if short in state["disabled_tools"]:
            raise Denied(f"{full_name} is Off in {instance}'s settings (Plugins → Tools)", "tool_disabled")
        spec = next((r for r in self.manifest(instance).get("reads", []) if r["name"] == short), None)
        if spec is None:
            raise Denied(f"unknown read {full_name}{self.hint(full_name, 'read')}", "unknown_read")
        return instance, self.instance(instance), spec

    # instances, as the owner app sets them up

    def save_instance(self, name: str, plugin_type: str, config: dict, no_approval: bool) -> None:
        with self.db.tx() as conn:
            conn.execute(
                "INSERT INTO plugin_instances(name, type, config, no_approval, created) VALUES(?,?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET type=excluded.type, config=excluded.config, "
                "no_approval=excluded.no_approval", (name, plugin_type, dumps(config), int(no_approval), clock.iso()))
        self.invalidate(name)

    def put_plugin(self, name: str, block: dict) -> None:
        """A plugin from one block: type (default: the name), config, no_approval, and the switches enabled,
        read_only, disabled_tools and tool_approval. For the starter plugins, the demo and tests. A plugin
        whose switches are set already keeps them."""
        block = dict(block or {})
        self.save_instance(name, block.get("type") or name, dict(block.get("config") or {}),
                           bool(block.get("no_approval")))
        if self.db.one("SELECT 1 FROM plugin_state WHERE name=?", (name,)) is None:
            self.set_state(name, {
                "enabled": bool(block.get("enabled", False)), "read_only": bool(block.get("read_only", False)),
                "disabled_tools": list(block.get("disabled_tools") or []),
                "tool_approval": {k: v for k, v in dict(block.get("tool_approval") or {}).items()
                                  if v in ("ask", "auto")}})

    def add_starter_plugins(self) -> None:
        for name, block in self.starter.items():
            self.put_plugin(name, block)

    def delete_instance(self, name: str) -> None:
        if self.is_mcp(name):
            self.mcp.store.delete(name)
        self.db.exec("DELETE FROM plugin_instances WHERE name=?", (name,))
        self.db.exec("DELETE FROM plugin_state WHERE name=?", (name,))
        self.invalidate(name)

    def available(self) -> list[dict[str, Any]]:
        """Every plugin type, with what setting one up takes. A type in use can run again under another name
        (two mailboxes); in_use says whether it already does."""
        used = {block["type"] for block in self.configured().values()}
        return [{"type": name, "description": t.manifest.get("description", ""),
                 "credentials": t.manifest.get("credentials", []), "config": t.manifest.get("config", {}),
                 "login": t.manifest.get("login"), "login_provider": t.manifest.get("login_provider"),
                 "setup": t.manifest.get("setup", []), "in_use": name in used}
                for name, t in sorted(self.types.items())]

    def list(self) -> list[dict[str, Any]]:
        out = []
        for instance, block in self.configured().items():
            manifest = self.types[block["type"]].manifest_for(instance, block)
            state = self.state(instance)
            out.append({
                "name": instance,
                "type": block["type"],
                "version": manifest.get("version"),
                "description": manifest.get("description", ""),
                **state,
                "read_only": self.all_writes_off(instance, state),
                "reads": [{"name": f"{instance}.{r['name']}", "description": r.get("description", ""),
                           "trust": r.get("trust", "third_party"), "private": bool(r.get("private")),
                           "raw": bool(r.get("raw")), "params": r.get("params", {})}
                          for r in manifest.get("reads", [])],
                "tools": [{"name": f"{instance}.{t['name']}", "description": t.get("description", ""),
                           "tier": t.get("tier", "reversible"), "params": t.get("params", {}),
                           "destinations": t.get("destinations", []),
                           "enabled": t["name"] not in state["disabled_tools"] and not state["read_only"],
                           # ask: every call waits for the owner; auto: runs on its own (a send only
                           # while every check passes)
                           "approval": state["tool_approval"].get(t["name"]) or self.default_mode(instance, t),
                           "default_approval": self.default_mode(instance, t),
                           # can_send: true, or when it becomes a send ("on a shared list")
                           **({"can_send": True} if t.get("can_send") else {}),
                           **({"sends_when": t["can_send"]} if isinstance(t.get("can_send"), str) else {})}
                          for t in manifest.get("tools", [])],
                "login": manifest.get("login"),
                "login_provider": manifest.get("login_provider") or ("Google" if manifest.get("login") else None),
                "jobs": list(manifest.get("jobs") or []),
                "events": declared_events(manifest),
                "set_up_by": self.db.get_setting(f"set_up_by:{instance}"),   # an agent's key (agent_setup.py)
                "searchable": isinstance(manifest.get("index"), dict),  # it feeds the search index
                # how to get one item by its ref (doorman meta, doorman ask, the reader): {read, param, ...}
                "item": dict(manifest["item"]) if isinstance(manifest.get("item"), dict) else None,
                "no_approval": bool(block.get("no_approval")),
                "config": dict(block.get("config") or {}),
                "config_help": manifest.get("config", {}),
                "setup": manifest.get("setup", []),
                "credentials_set": sorted(self.vault.get(instance)),
                "credentials": manifest.get("credentials", []),
                "optional_credentials": manifest.get("optional_credentials", []),
                "missing_credentials": [c for c in manifest.get("credentials", [])
                                        if c not in self.vault.get(instance)],
                **({"mcp": self.mcp.card(instance, block)} if block["type"] == "mcp" else {}),
            })
        return out
