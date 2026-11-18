"""What an agent key may read and do (GET /v1/capabilities, doorman caps), its brief form, and its version.

The version is a short hash of what the capabilities say; the worker compares it per key and puts
caps_changed into the key's feed when it moves (feed.py)."""

from typing import Any

from . import crossread
from .agent_setup import READS as SETUP_READS, TOOLS as SETUP_TOOLS
from .engine import RECORD_ACTIONS, RECORD_CATEGORIES
from .owner_questions import OPEN_PER_KEY
from .structure import ANSWER_CHARS
from .util import canonical, sha256_hex


def caps_for(engine, key: dict, session: dict, off: dict | None = None) -> dict:
    """What this key may read and do in this session. `off`, when given, collects the reads and tools the
    owner switched off one by one (the brief form lists them as off)."""
    plugins = []
    for plugin in engine.registry.list():
        if not plugin["enabled"]:
            continue
        writable = not plugin["read_only"] and key["role"] != "reader"
        reads = [r for r in plugin["reads"] if r["name"].split(".", 1)[1] not in plugin["disabled_tools"]]
        if key["role"] == "actor" and engine.config["reader_actor_split"]:
            reads = [r for r in reads if not r["raw"]]
        if off is not None:
            off[plugin["name"]] = {"reads": [r for r in plugin["reads"] if r not in reads and not
                                             (r["raw"] and key["role"] == "actor" and engine.config["reader_actor_split"])],
                                   "tools": [t for t in plugin["tools"] if not t["enabled"]] if writable else []}
        plugins.append({
            "name": plugin["name"], "description": plugin["description"], "read_only": not writable,
            "reads": reads,
            "tools": [t for t in plugin["tools"] if t["enabled"]] if writable else [],
            "events": plugin["events"],
            # its items can be looked up by ref: doorman meta, doorman ask, and the reader's records
            "item": plugin["item"],
        })
    has_reader = engine.db.one("SELECT 1 FROM agent_keys WHERE role='reader' AND revoked=0") is not None
    caps = {
        "role": key["role"], "session": session["id"], "task_id": session["task_id"],
        "paused": engine.killed(),
        "key_paused": bool(engine.auth.paused(key["id"])),  # this key only, by a honeytoken, until the owner resumes it
        "reader_actor_split": engine.config["reader_actor_split"],
        "records": {"categories": RECORD_CATEGORIES, "actions": RECORD_ACTIONS},
        # doorman ask: whether a reader is set up to answer questions about an item
        "questions": {"enabled": has_reader and key["role"] != "reader", "answer_chars": ANSWER_CHARS},
        # doorman ask-owner: a question to the owner, answered in their inbox (owner_questions.py)
        "ask_owner": {"enabled": key["role"] != "reader", "open_max": OPEN_PER_KEY},
        **({"reader": {"events_cursor": (engine.reader_status(key["id"]) or {}).get("events_cursor")}}
           if key["role"] == "reader" else {}),
        # network watch: the agent's traffic goes through Doorman's proxy (doorman egress request, blocked)
        "egress": {"enabled": engine.egress.enabled()},
        "uploads": {"max_mb": (engine.config.get("uploads") or {}).get("max_mb", 25)},
        "guard": {"enabled": engine.guard.enabled},
        "events": {"keep_days": engine.config.get("events_days", 7),
                   "poll_minutes": engine.config.get("trigger_poll_minutes", 5),
                   "text": not (key["role"] == "actor" and engine.config["reader_actor_split"])},
        # the sources this key can read: an actor under the split doesn't get the raw ones
        "search": {"sources": [{"name": s["name"], "kinds": [k for k in s["kinds"] if k not in s["skip_kinds"]]}
                               for s in engine.search.sources(session, key["role"])]},
        "agenda": {"sources": [s["name"] for s in crossread.sources(engine, "agenda", key["role"])]},
        "recent": {"sources": [s["name"] for s in crossread.sources(engine, "recent", key["role"])]},
        "plugins": plugins,
        "setup": {"enabled": engine.setup.enabled and key["role"] != "reader", "reads": list(SETUP_READS),
                  "tools": list(SETUP_TOOLS)},
    }
    return {"version": caps_version(caps), **caps}


# change often and say nothing about what's there (reader: how far doorman-reader got in the feed)
CAPS_VOLATILE = ("session", "task_id", "paused", "key_paused", "reader")


def caps_version(caps: dict) -> str:
    """A short hash of what the capabilities say: equal versions, equal capabilities."""
    return sha256_hex(canonical({k: v for k, v in caps.items() if k not in CAPS_VOLATILE}))[:12]


def caps_outline(caps: dict) -> dict:
    """What a change in the capabilities is told by: per plugin whether it is read-only, its reads, and its
    tools with how each runs (ask, auto); plus the switches outside plugins. Descriptions and parameters
    are left out: they change with an update and say nothing about what the agent may do."""
    return {
        "plugins": {p["name"]: {"read_only": p["read_only"], "reads": sorted(r["name"] for r in p["reads"]),
                                "tools": {t["name"]: t.get("approval") for t in p["tools"]}}
                    for p in caps.get("plugins", [])},
        "setup": bool((caps.get("setup") or {}).get("enabled")),
        "questions": bool((caps.get("questions") or {}).get("enabled")),
    }


MODE_WORDS = {"ask": "asks you first", "auto": "runs without asking"}


def caps_changes(before: dict | None, after: dict) -> list[str] | None:
    """The difference of two caps_outline()s in words, one line each ("mail: send switched off", "contacts
    added"). Empty when only descriptions or parameters moved (an update); None when nothing is known from
    before (the first change after an upgrade to this version)."""
    if not before:
        return None
    lines = []
    old, new = before.get("plugins", {}), after.get("plugins", {})
    lines += [f"{name} added" for name in new if name not in old]
    lines += [f"{name} removed" for name in old if name not in new]
    for name in (n for n in new if n in old):
        was, now = old[name], new[name]
        if was["read_only"] != now["read_only"]:
            lines.append(f"{name}: read-only" if now["read_only"] else f"{name}: may write again")
        short = lambda full: full.split(".", 1)[-1]  # noqa: E731 - mail.send -> send
        on = [short(r) for r in now["reads"] if r not in was["reads"]]
        off = [short(r) for r in was["reads"] if r not in now["reads"]]
        lines += [f"{name}: reading {', '.join(on)} switched on"] if on else []
        lines += [f"{name}: reading {', '.join(off)} switched off"] if off else []
        if was["read_only"] == now["read_only"]:  # else the tools all came or went with it
            on = [short(t) for t in now["tools"] if t not in was["tools"]]
            off = [short(t) for t in was["tools"] if t not in now["tools"]]
            lines += [f"{name}: {', '.join(on)} switched on"] if on else []
            lines += [f"{name}: {', '.join(off)} switched off"] if off else []
        for tool, mode in now["tools"].items():
            if tool in was["tools"] and was["tools"][tool] != mode and mode in MODE_WORDS:
                lines.append(f"{name}: {short(tool)} now {MODE_WORDS[mode]}")
    for flag, words in (("setup", "setting up plugins"), ("questions", "asking the reader")):
        if before.get(flag) != after.get(flag):
            lines.append(f"{words} switched {'on' if after.get(flag) else 'off'}")
    return lines


def one_line(text: Any, limit: int = 100) -> str:
    """A description's first sentence, at most `limit` characters."""
    text = " ".join(str(text or "").split())
    depth = 0
    for i, char in enumerate(text):  # the first full stop outside brackets, before a space or the end
        depth += (char == "(") - (char == ")")
        if char in ".!?" and depth <= 0 and text[i + 1:i + 2] in ("", " "):
            text = text[:i]
            break
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


TOOL_KINDS = {"reversible": "write", "irreversible": "send", "payment": "pay"}


def arg_names(schema: dict | None) -> str:
    """A schema's parameter names for the brief form: the required ones first, the rest with a ?."""
    props = list((schema or {}).get("properties") or {})
    required = [p for p in (schema or {}).get("required") or [] if p in props]
    return ", ".join(required + [f"{p}?" for p in props if p not in required])


def may_ask(tool: dict) -> str:
    """For a write that becomes a send for some calls: when it does, so an agent knows before it calls that
    the call may wait for the owner and can't be undone ("may ask the owner: on a shared list")."""
    return "may ask the owner and then can't be undone: " + (tool.get("sends_when") or "when it reaches others")


def brief_caps(caps: dict, off: dict) -> dict:
    """The capabilities in a line per read and tool, without parameter schemas: name, its parameters' names
    (args: required first, optional with a ?), what it does, and its mode (read: on or off; tools: auto, ask or off). kind: write (undoable), send (can't be undone), pay;
    write+send for a write that becomes a send when it notifies others (a calendar invitation)."""
    plugins = []
    for plugin in caps["plugins"]:
        hidden = off.get(plugin["name"]) or {"reads": [], "tools": []}
        reads = [{"name": r["name"], "args": arg_names(r.get("params")), "mode": "on",
                  "about": one_line(r["description"])} for r in plugin["reads"]]
        reads += [{"name": r["name"], "args": arg_names(r.get("params")), "mode": "off",
                   "about": one_line(r["description"])} for r in hidden["reads"]]
        tools = [{"name": t["name"], "args": arg_names(t.get("params")),
                  "kind": TOOL_KINDS.get(t["tier"], t["tier"]) + ("+send" if t.get("can_send") else ""),
                  "mode": t.get("approval") or "ask", "about": one_line(t["description"]),
                  **({"may_ask": may_ask(t)} if t.get("can_send") else {})} for t in plugin["tools"]]
        tools += [{"name": t["name"], "args": arg_names(t.get("params")), "kind": TOOL_KINDS.get(t["tier"], t["tier"]),
                   "mode": "off", "about": one_line(t["description"])} for t in hidden["tools"]]
        plugins.append({"name": plugin["name"], "about": one_line(plugin["description"]),
                        "read_only": plugin["read_only"], "events": [e["name"] for e in plugin["events"]],
                        "reads": reads, "tools": tools})
    return {"version": caps["version"], "role": caps["role"], "session": caps["session"], "task_id": caps["task_id"],
            "paused": caps["paused"], "key_paused": caps["key_paused"], "search": [s["name"] for s in caps["search"]["sources"]],
            "agenda": caps["agenda"]["sources"],
            "recent": caps["recent"]["sources"],
            "setup": caps["setup"]["reads"] + caps["setup"]["tools"] if caps["setup"]["enabled"] else [],
            "plugins": plugins}
