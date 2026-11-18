"""The WebAuthn challenge for an approval is derived from the exact payload.

Signing it with a passkey therefore approves that payload and nothing else.

Also what an approval's push shows, and whether its Accept button may approve in place.
"""

import hashlib

BODY_KEYS = ("body", "text", "message")  # where sends keep the text that goes out (mail, chat, note copy)
BODY_LINES = 3
BODY_CHARS = 280
SUMMARY_CHARS = 900  # the notifier clips the whole body at 1000 characters and the JSON at 3000 bytes


def approval_challenge(approval_id: int, payload_hash: str, nonce: str) -> bytes:
    return hashlib.sha256(f"doorman-approval:{approval_id}:{payload_hash}:{nonce}".encode()).digest()


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _first_lines(text: str) -> str:
    lines = [line.strip() for line in str(text).splitlines() if line.strip()]
    head = "\n".join(lines[:BODY_LINES]) + (" …" if len(lines) > BODY_LINES else "")
    return _clip(head, BODY_CHARS)


def _texts(entry: dict) -> list[str]:
    """The texts a send carries out: what the agent wrote (a mail's body, a chat message) and what its
    arguments only point at (the note a copy sends)."""
    args = entry.get("args") or {}
    written = next((args[k] for k in BODY_KEYS if isinstance(args.get(k), str) and args[k].strip()), None)
    pointed = (entry.get("outgoing") or {}).get("text")
    pointed = pointed if isinstance(pointed, str) and pointed.strip() and pointed != written else None
    return [text for text in (written, pointed) if text]


def notice_text(entries: list[dict]) -> str:
    """What the push says about an approval: per send its summary (recipient and subject for mail), then
    the first lines of each text that goes out. `entries` are entry views (Engine.entry_view)."""
    return _clip(_notice(entries), SUMMARY_CHARS)


def _notice(entries: list[dict]) -> str:
    parts = []
    for entry in entries:
        outgoing = entry.get("outgoing") or {}
        lines = [str(entry.get("summary") or entry.get("tool") or "")]
        if outgoing.get("title"):
            lines.append(f"{outgoing.get('label') or 'Content'}: {outgoing['title']}")
        lines.extend(_first_lines(text) for text in _texts(entry))
        parts.append("\n".join(line for line in lines if line))
    return "\n\n".join(parts)


def warnings(entry: dict) -> bool:
    """True when the approval screen shows a warning for this send (as the app's approvalWarnings does):
    a destination that doesn't come from the owner, a key a honeytoken paused, or any other failed check."""
    if entry.get("untrusted_destinations") or entry.get("key_paused"):
        return True
    return any(not check.get("ok") for check in (entry.get("checks") or {}).get("checks", []))


def accept_in_place(entries: list[dict], approval_passkey: bool) -> bool:
    """Whether Accept on the push may approve without opening the app. Only when a tap in the app would
    approve it too: one send, no warnings, not a payment, not an MCP tool. Everything else opens the
    approval screen. A long text or an attachment doesn't stop it (the owner's call, 7 Nov): the push shows
    the first lines, and whoever wants to see more taps the push instead of Accept."""
    if approval_passkey or len(entries) != 1:
        return False
    entry = entries[0]
    return (entry.get("status") == "waiting_approval" and entry.get("tier") != "payment"
            and not entry.get("mcp") and not warnings(entry))


RECIPIENT_KEYS = ("to", "recipient", "recipients", "chat_name", "chat", "phone", "iban", "attendees")
TITLE_CHARS = 80


def _recipients(entry: dict) -> str | None:
    """Who a send goes to, as the app's card names them: the first recipient field that is set."""
    args = entry.get("args") or {}
    for key in RECIPIENT_KEYS:
        value = args.get(key)
        if isinstance(value, list) and value:
            return ", ".join(str(v) for v in value)
        if isinstance(value, str) and value:
            return value
    return None


def notice_title(entries: list[dict]) -> str:
    """The push's title: what is at stake, so the owner can judge it from the lock screen. A new recipient
    comes first (it is the thing to look at twice), then a payment, then who a send goes to. `entries` are
    entry views (Engine.entry_view)."""
    new = [d.get("value") for e in entries for d in e.get("untrusted_destinations") or [] if d.get("value")]
    if new:
        more = f" and {len(set(new)) - 1} more" if len(set(new)) > 1 else ""
        return _clip(f"New recipient: {new[0]}{more}", TITLE_CHARS)
    if len(entries) == 1:
        entry = entries[0]
        args = entry.get("args") or {}
        if entry.get("tier") == "payment":
            amount = args.get("amount")
            to = args.get("name") or args.get("iban")
            if isinstance(amount, (int, float)) and not isinstance(amount, bool):
                amount = f"{amount:.2f}"
            return _clip(f"Pay {amount} € to {to}" if amount is not None and to else "Payment waiting for you", TITLE_CHARS)
        mcp = entry.get("mcp")
        if mcp:
            return _clip(f"Run {mcp.get('title') or mcp.get('tool')} on {mcp.get('server')}", TITLE_CHARS)
        if entry.get("tier") == "reversible":
            return _clip(f"Change waiting: {entry.get('summary') or entry.get('tool')}", TITLE_CHARS)
        to = _recipients(entry)
        return _clip(f"Send to {to}" if to else str(entry.get("summary") or "A send is waiting for you"), TITLE_CHARS)
    people = {_recipients(e) for e in entries}
    if len(people) == 1 and None not in people:
        return _clip(f"{len(entries)} sends to {people.pop()}", TITLE_CHARS)
    return f"{len(entries)} sends waiting for you"


GROUP_SECONDS = 60  # sends of one task asked for within this long of the first share one push
GROUP_MAX = 20      # a bigger burst starts a new push (and buzzes once more) rather than grow without end


def group_title(entries: list[dict], task_id: int | None) -> str:
    """The title of one push for several approvals of a task: how many, which task, and the stake (a new
    recipient first, else who they go to). `entries` are the entry views of every approval in the group."""
    sends = [e for e in entries if e.get("tier") != "reversible"]
    what = f"{len(entries)} sends" if sends else f"{len(entries)} changes"
    head = f"{what} from task {task_id}" if task_id else f"{what} from the agent"
    new = list(dict.fromkeys(d.get("value") for e in entries for d in e.get("untrusted_destinations") or []
                             if d.get("value")))
    if any(e.get("key_paused") for e in entries):
        return _clip(f"{head}: its key is paused", TITLE_CHARS)
    if len(new) == 1:
        return _clip(f"{head}: new recipient {new[0]}", TITLE_CHARS)
    if new:
        return _clip(f"{head}: {len(new)} new recipients", TITLE_CHARS)
    if any(e.get("tier") == "payment" for e in entries):
        return _clip(f"{head}, with a payment", TITLE_CHARS)
    people = list(dict.fromkeys(p for p in (_recipients(e) for e in sends) if p))
    return _clip(f"{head} to {', '.join(people)}" if people else head, TITLE_CHARS)


def group_text(entries: list[dict]) -> str:
    """The body of a grouped push: one line per send (its summary) and where to read each in full: the
    review screen, which a tap on the push opens."""
    tail = "\n\nOpen Doorman to read each one in full."
    lines = [_clip(str(e.get("summary") or e.get("tool") or ""), 120) for e in entries]
    return _clip("\n".join(f"· {line}" for line in lines if line), SUMMARY_CHARS - len(tail)) + tail
