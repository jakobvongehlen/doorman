"""Checks a plugin's manifest when Doorman loads it, and for `doorman-admin plugin check`.

Errors are what would break the plugin later or quietly leave it out: no name, a parameter schema that isn't
valid JSON Schema, an `index:`, `agenda:`, `recent:`, `contacts:`, `ref_read:` or `item:` naming a read that
doesn't exist, an unknown tier. A plugin with errors isn't loaded; Doorman starts without it and lists it under
Needs attention. Warnings are keys Doorman doesn't know, usually typos (`serach:`), each with the closest
key it does know; the plugin loads anyway. Built-in manifests have neither (tests/test_plugin_checks.py).

docs/writing-plugins.md lists every key."""

from __future__ import annotations

import difflib
import re
from typing import Any

import jsonschema

from .plugin_api import TIERS

TOP_KEYS = frozenset({
    "name", "version", "description", "extends", "credentials", "optional_credentials", "credential_files",
    "config", "setup", "login", "login_provider", "network", "sandbox", "agent_settings", "agent_narrow",
    "agent_add_only", "agent_install", "reads", "tools", "events", "jobs", "item", "ref_read", "index", "agenda", "recent", "contacts",
    "copy_to_archive", "known_recipients"})
READ_KEYS = frozenset({"name", "description", "trust", "raw", "private", "params", "scan_items", "not_scanned"})
TOOL_KEYS = frozenset({"name", "description", "tier", "params", "destinations", "editable", "ref_fields",
                       "can_send", "always_approve", "amount_field", "caller_arg", "based_on_arg"})
ITEM_KEYS = frozenset({"read", "param", "attachments", "context", "events"})
JOB_KEYS = frozenset({"name", "every_minutes", "budget_seconds", "off_when"})
# job: the job whose runs return it (else poll_events does); read: the read whose switch gates its text
EVENT_KEYS = frozenset({"name", "description", "fields", "job", "read"})
SANDBOX_KEYS = frozenset({"user", "filesystem", "read", "write", "network", "call_timeout_seconds"})
# keys that name one of the plugin's reads: Doorman's reads across plugins (and the owner app's contact list),
# and attaching by reference
READ_REFS = ("agenda", "recent", "contacts", "ref_read")
INDEX_KEYS = frozenset({"read", "kinds", "every_minutes", "needs", "settings", "security_senders"})
KINDS = ("mail", "file", "note", "event", "task", "chat")
# what a plugin's known_recipients() answers from (policy.Policy.known_destinations)
KNOWN_RECIPIENTS = ("contacts", "sent_mail")
NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")


def _unknown(keys, known: frozenset, where: str) -> list[str]:
    out = []
    for key in keys:
        if key in known:
            continue
        close = difflib.get_close_matches(str(key), sorted(known), n=1, cutoff=0.6)
        out.append(f"{where}: unknown key {key!r}" + (f"; did you mean {close[0]!r}?" if close else ""))
    return out


def _schema_errors(schema: Any, where: str) -> list[str]:
    if schema is None:
        return []
    if not isinstance(schema, dict):
        return [f"{where}: params must be a JSON Schema object, not {type(schema).__name__}"]
    try:
        jsonschema.validators.validator_for(schema).check_schema(schema)
    except jsonschema.SchemaError as exc:
        path = "/".join(str(p) for p in exc.absolute_path)
        return [f"{where}: params isn't a valid JSON Schema{' at ' + path if path else ''}: {exc.message}"]
    return []


def _param_names(spec: dict) -> set[str]:
    return set(((spec.get("params") or {}).get("properties") or {}) if isinstance(spec.get("params"), dict) else {})


def _entries(manifest: dict, key: str, errors: list[str]) -> list[dict]:
    """`reads:` or `tools:`, each a mapping with a name; what isn't is an error."""
    value = manifest.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        errors.append(f"{key} must be a list")
        return []
    out, seen = [], set()
    for entry in value:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            errors.append(f"{key}: each entry needs a name: {entry!r}"[:200])
            continue
        if entry["name"] in seen:
            errors.append(f"{key}: {entry['name']} is listed twice")
        seen.add(entry["name"])
        out.append(entry)
    return out


def check(manifest: Any) -> tuple[list[str], list[str]]:
    """(errors, warnings) for a manifest, after `extends:` was merged in."""
    if not isinstance(manifest, dict):
        return ["the manifest must be a mapping of keys to values"], []
    errors: list[str] = []
    warnings = _unknown(manifest, TOP_KEYS, "manifest")
    name = manifest.get("name")
    if not isinstance(name, str) or not name:
        errors.append("name is missing: every manifest needs `name: <plugin type>`")
    elif not NAME_RE.match(name):
        errors.append(f"name {name!r} must be lower case letters, digits and _ (it starts tool names: {name}.send)")
    reads = _entries(manifest, "reads", errors)
    tools = _entries(manifest, "tools", errors)
    read_names = {r["name"] for r in reads}
    events = {e if isinstance(e, str) else e.get("name") for e in manifest.get("events") or []
              if isinstance(e, (str, dict))}

    for spec in reads:
        where = f"read {spec['name']}"
        warnings += _unknown(spec, READ_KEYS, where)
        if spec.get("trust", "third_party") not in ("owner", "third_party"):
            errors.append(f"{where}: trust must be owner or third_party, not {spec.get('trust')!r}")
        skip = spec.get("not_scanned")
        if skip is not None and not (isinstance(skip, list) and all(isinstance(f, str) and f for f in skip)):
            errors.append(f"{where}: not_scanned is a list of field names (not_scanned: [id, link])")
        errors += _schema_errors(spec.get("params"), where)
    for spec in tools:
        where = f"tool {spec['name']}"
        warnings += _unknown(spec, TOOL_KEYS, where)
        if spec.get("tier", "reversible") not in TIERS:
            errors.append(f"{where}: unknown tier {spec.get('tier')!r} (one of {', '.join(TIERS)})")
        errors += _schema_errors(spec.get("params"), where)
        params = _param_names(spec)
        for key in ("editable", "ref_fields"):
            for field in spec.get(key) or []:
                if str(field).split(".", 1)[0] not in params:
                    errors.append(f"{where}: {key} names {field}, which isn't one of its params")
        for key in ("caller_arg", "based_on_arg"):
            if spec.get(key) and spec[key] not in params:
                errors.append(f"{where}: {key} names {spec[key]}, which isn't one of its params")
        for dest in spec.get("destinations") or []:
            if not (isinstance(dest, dict) and dest.get("field") and dest.get("kind")):
                errors.append(f"{where}: a destination is {{field, kind}}: {dest!r}")

    for key in READ_REFS:
        value = manifest.get(key)
        if value is not None and value not in read_names:
            close = difflib.get_close_matches(str(value), sorted(read_names), n=1, cutoff=0.6)
            errors.append(f"{key}: {value} isn't one of the plugin's reads"
                          + (f"; did you mean {close[0]}?" if close else f" ({', '.join(sorted(read_names)) or 'none'})"))

    index = manifest.get("index")
    if index is not None:
        if not isinstance(index, dict) or not index.get("read"):
            errors.append("index must be a mapping with the read that gates the items' text: {read, kinds, every_minutes}")
        else:
            warnings += _unknown(index, INDEX_KEYS, "index")
            if index["read"] not in read_names:
                errors.append(f"index: read {index['read']} isn't one of the plugin's reads "
                              f"({', '.join(sorted(read_names)) or 'none'})")
            bad = [k for k in index.get("kinds") or [] if k not in KINDS]
            if bad:
                errors.append(f"index: kinds must be among {', '.join(KINDS)}, not {', '.join(map(str, bad))}")
            settings = index.get("settings")
            if settings is not None and not (isinstance(settings, list) and all(isinstance(s, str) for s in settings)):
                errors.append("index: settings is a list of the settings that change what the plugin feeds")
            if not isinstance(index.get("security_senders", True), bool):
                errors.append("index: security_senders is false when what the plugin feeds doesn't depend on them")
            needs = index.get("needs")
            if needs is not None and not isinstance(needs, dict):
                errors.append("index: needs is a mapping of a kind (or attachment) to the read that returns it")
            for what, names in (needs or {}).items() if isinstance(needs, dict) else ():
                if what not in (*KINDS, "attachment"):
                    errors.append(f"index: needs names {what}, which is neither a kind nor attachment")
                for name in names if isinstance(names, list) else [names]:
                    if name not in read_names:
                        errors.append(f"index: needs {what}: {name} isn't one of the plugin's reads")

    known = manifest.get("known_recipients")
    if known is not None and known not in KNOWN_RECIPIENTS:
        errors.append(f"known_recipients: {known!r} must be one of {', '.join(KNOWN_RECIPIENTS)}")

    item = manifest.get("item")
    if item is not None:
        if not isinstance(item, dict):
            errors.append("item must be a mapping: {read, param, ...}")
        else:
            warnings += _unknown(item, ITEM_KEYS, "item")
            for key in ("read", "attachments"):
                if item.get(key) is not None and item[key] not in read_names:
                    errors.append(f"item.{key}: {item[key]} isn't one of the plugin's reads")
            if not item.get("read") or not item.get("param"):
                errors.append("item needs read and param (the read's parameter that takes the ref's path)")
            else:
                spec = next((r for r in reads if r["name"] == item["read"]), {})
                params = _param_names(spec)
                for key in ("param", "context"):
                    if item.get(key) and spec and item[key] not in params:
                        errors.append(f"item.{key}: {item['read']} has no parameter {item[key]}")
            for event in item.get("events") or []:
                if event not in events:
                    errors.append(f"item.events: {event} isn't among the plugin's events")

    for entry in manifest.get("events") or []:
        if not (isinstance(entry, str) or (isinstance(entry, dict) and isinstance(entry.get("name"), str)
                                           and isinstance(entry.get("fields") or [], list))):
            errors.append(f"an event is a name or {{name, description, fields}}: {entry!r}"[:200])
            continue
        if isinstance(entry, str):
            continue
        where = f"event {entry['name']}"
        warnings += _unknown(entry, EVENT_KEYS, where)
        job_names = {j.get("name") for j in manifest.get("jobs") or [] if isinstance(j, dict)}
        if entry.get("job") is not None and entry["job"] not in job_names:
            errors.append(f"{where}: job {entry['job']} isn't one of the plugin's jobs "
                          f"({', '.join(sorted(map(str, job_names))) or 'none'})")
        if entry.get("read") is not None and entry["read"] not in read_names:
            errors.append(f"{where}: read {entry['read']} isn't one of the plugin's reads")

    config = manifest.get("config")
    if config is not None and not isinstance(config, dict):
        errors.append("config must be a mapping of setting names to what they mean")
    for setting in manifest.get("agent_settings") or []:
        # `folders.drafts`: one key of a mapping setting, the mapping's other keys stay the owner's
        if str(setting).partition(".")[0] not in (config or {}):
            errors.append(f"agent_settings: {setting} isn't one of the settings under config")
    for key in ("agent_narrow", "agent_add_only"):
        for setting in manifest.get(key) or []:
            if setting not in (manifest.get("agent_settings") or []):
                errors.append(f"{key}: {setting} isn't one of the agent_settings")

    for job in manifest.get("jobs") or []:
        if not isinstance(job, dict) or not isinstance(job.get("name"), str):
            errors.append(f"jobs: each job needs a name: {job!r}"[:200])
        else:
            warnings += _unknown(job, JOB_KEYS, f"job {job['name']}")
    if isinstance(manifest.get("sandbox"), dict):
        warnings += _unknown(manifest["sandbox"], SANDBOX_KEYS, "sandbox")
    return errors, warnings


def check_code(plugin_cls: type, manifest: dict) -> list[str]:
    """What the plugin's class must have for its manifest: a class for every tool, an entry in READS for
    every read, and every READS method. Needs plugin.py imported, so `doorman-admin plugin check` does it
    (and BasePlugin does when an instance is made, in the plugin's own process)."""
    errors = []
    for spec in manifest.get("tools") or []:
        if isinstance(spec, dict) and spec.get("name") not in getattr(plugin_cls, "TOOLS", {}):
            errors.append(f"tool {spec.get('name')} has no class in Plugin.TOOLS")
    reads = getattr(plugin_cls, "READS", {})
    for spec in manifest.get("reads") or []:
        if isinstance(spec, dict) and spec.get("name") not in reads:
            errors.append(f"read {spec.get('name')} has no entry in Plugin.READS")
    for name, method in reads.items():
        if not callable(getattr(plugin_cls, method, None)):
            errors.append(f"READS[{name!r}] names {method}, which Plugin doesn't have")
    return errors

