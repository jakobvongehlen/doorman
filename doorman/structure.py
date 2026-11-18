"""What an agent may know about an item without its text: validated structural fields.

Under the reader/actor split an actor key can't read raw third-party content, yet it needs ids,
addresses, attachment parts and timestamps to act on an item (answer a mail, file an attachment, write in
a chat). `project()` turns an item, as a plugin's read returns it, into a fixed set of fields, each
checked against a strict pattern. A value that doesn't match is dropped, not cut, so nothing a stranger
wrote as prose comes through:

- **kept**: ids (message, chat, the message replied to), addresses and chat ids, timestamps, sizes,
  part numbers, MIME types, file extensions, flags, and the owner's own folder names, tags and paths;
- **never**: subjects, bodies, message text, display names, chat names, attachment file names. Those are
  the sender's words, and the classic place to put an instruction for an AI. The reader's records and
  answers (`doorman records`, `doorman ask`) say what an item is about instead.

The same patterns check the reader's answers to questions (ANSWER_SCHEMA), so its structured fields
can't carry prose either.
"""

from __future__ import annotations

import re
from typing import Any

EMAIL = r"[A-Za-z0-9._%+'=-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}"
JID = r"[0-9A-Za-z.:-]{1,64}@(?:s\.whatsapp\.net|g\.us|lid)"   # a WhatsApp person or group
GUID = r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"  # a Microsoft user
ID = r"[A-Za-z0-9._%+=:@/$#!&*?^{|}~-]{1,300}"                   # Message-IDs, chat ids, Graph ids: no spaces
DATETIME = r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})?)?"
MIME = r"[a-z0-9][a-z0-9.+-]{0,40}/[a-z0-9][a-z0-9.+-]{0,80}"
OWNER_TEXT = r"[^\x00-\x1f\x7f​-‏‪-‮⁦-⁩]"  # no control or direction characters

PATTERNS = {name: re.compile(f"^(?:{value})$") for name, value in {
    "email": EMAIL, "participant": f"{EMAIL}|{JID}|{GUID}", "id": ID, "datetime": DATETIME, "mime": MIME,
    "ext": r"[a-z0-9]{1,8}", "flag": r"\\?[A-Za-z0-9$_-]{1,40}", "token": r"[a-z][a-z0-9_-]{0,30}",
    "folder": f"{OWNER_TEXT}{{1,200}}", "path": f"{OWNER_TEXT}{{1,500}}", "tag": f"{OWNER_TEXT}{{1,60}}",
    "ref": f"[a-z][a-z0-9_]*:{OWNER_TEXT}{{1,600}}",
}.items()}

MAX_LIST = 50  # addresses, attachments, context messages per item


def matches(kind: str, value: Any) -> bool:
    return isinstance(value, str) and bool(PATTERNS[kind].match(value))


def _strings(value: Any, kind: str) -> list[str]:
    values = value if isinstance(value, list) else [value]
    return [v for v in values[:MAX_LIST] if matches(kind, v)]


def _number(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 10**13 else None


def extension(name: Any) -> str | None:
    """A file name's extension (`pdf`), the one part of a name that says what the file is."""
    if not isinstance(name, str) or "." not in name:
        return None
    ext = name.rsplit(".", 1)[1].strip().lower()
    return ext if matches("ext", ext) else None


def _attachment(value: Any) -> dict | None:
    if isinstance(value, str):  # Teams lists attachments by name only
        ext = extension(value)
        return {"ext": ext} if ext else {}
    if not isinstance(value, dict):
        return None
    out: dict[str, Any] = {}
    for key in ("part", "size"):
        if _number(value.get(key)) is not None:
            out[key] = value[key]
    if matches("ref", value.get("ref")):
        out["ref"] = value["ref"]
    kind = value.get("type").lower() if isinstance(value.get("type"), str) else None
    if matches("mime", kind):
        out["type"] = kind
    ext = extension(value.get("name") or value.get("filename"))
    if ext:
        out["ext"] = ext
    if value.get("quarantined") is True:
        out["quarantined"] = True
    return out


def project(item: Any, depth: int = 0) -> dict:
    """The structural fields of one item; see the module's docstring for what's kept."""
    if not isinstance(item, dict):
        return {}
    out: dict[str, Any] = {}
    for key in ("id", "message_id", "chat", "chat_id", "in_reply_to", "reaction_to", "thread_id",
                "conversation_id"):
        if matches("id", item.get(key)):
            out[key] = item[key]
    if matches("ref", item.get("ref")):
        out["ref"] = item["ref"]
    for key in ("sender", "from_id"):
        if matches("participant", item.get(key)):
            out[key] = item[key]
    for key in ("from", "to", "cc", "reply_to"):
        value = item.get(key)
        if key == "reply_to" and isinstance(value, str) and not matches("email", value):
            if matches("id", value):  # WhatsApp: the message this one quotes
                out["reply_to"] = value
            continue
        if isinstance(value, (list, str)):
            found = _strings(value, "email")
            if found:
                out[key] = found
    for key in ("date", "ts", "sent", "modified", "deleted_on_server"):
        value = item.get(key)
        if matches("datetime", value) or (_number(value) is not None and key == "ts"):
            out[key] = value
    for key in ("unread", "from_me", "edited", "deleted", "quarantined"):
        if isinstance(item.get(key), bool):
            out[key] = item[key]
    if _number(item.get("size")) is not None:
        out["size"] = item["size"]
    kind = item.get("type").lower() if isinstance(item.get("type"), str) else None
    if matches("mime", kind):
        out["type"] = kind
    # the owner's own words: folders they made, tags they gave, where they keep a file
    if matches("folder", item.get("folder")):
        out["folder"] = item["folder"]
    if matches("path", item.get("path")):
        out["path"] = item["path"]
        if extension(item["path"]):
            out["ext"] = extension(item["path"])
    for key, kind in (("flags", "flag"), ("tags", "tag")):
        if isinstance(item.get(key), list):
            out[key] = _strings(item[key], kind)
    if isinstance(item.get("attachments"), list):
        out["attachments"] = [a for a in (_attachment(v) for v in item["attachments"][:MAX_LIST]) if a is not None]
    media = item.get("media")
    if isinstance(media, dict):
        out["media"] = {k: v for k, v in (("type", media.get("type") if matches("token", media.get("type")) else None),
                                          ("ext", extension(media.get("filename")))) if v}
    if depth == 0 and isinstance(item.get("context"), list):  # earlier messages in the chat: who and when
        out["context"] = [project(m, 1) for m in item["context"][:MAX_LIST] if isinstance(m, dict)]
    return out


# ---------------------------------------------------------------- questions to the reader

QUESTION_CHARS = 500
ANSWER_CHARS = 600
ANSWER_ERRORS = {  # what a reader may say instead of an answer; nothing free-form
    "held_back": "Doorman's injection guard holds this item back; the owner can release it.",
    "not_found": "The item isn't there (any more).",
    "unreadable": "The reader couldn't read this item.",
    "model_failed": "The reader's model didn't give a usable answer.",
}
PARTICIPANT_ROLES = ["from", "reply_to", "to", "cc", "sender"]

QUESTION_SCHEMA = {
    "type": "object",
    "properties": {
        "ref": {"type": "string", "pattern": PATTERNS["ref"].pattern},
        "question": {"type": "string", "minLength": 3, "maxLength": QUESTION_CHARS},
    },
    "required": ["ref", "question"],
    "additionalProperties": False,
}

ANSWER_SCHEMA = {
    "type": "object",
    "properties": {
        "answer": {"type": "string", "minLength": 1, "maxLength": ANSWER_CHARS},
        "attachments": {"type": "array", "maxItems": 20, "items": {
            "type": "object",
            "properties": {
                "part": {"type": "integer", "minimum": 1, "maximum": 999},
                # the sender's file name: the agent gets it spotlighted and guard-scanned, like the answer
                "name": {"type": "string", "pattern": f"^{OWNER_TEXT}{{1,120}}$"},
                "type": {"type": "string", "pattern": PATTERNS["mime"].pattern},
                "size": {"type": "integer", "minimum": 0},
                "ref": {"type": "string", "pattern": PATTERNS["ref"].pattern},
            },
            "required": ["part"], "additionalProperties": False}},
        "participants": {"type": "array", "maxItems": MAX_LIST, "items": {
            "type": "object",
            "properties": {"role": {"enum": PARTICIPANT_ROLES},
                           "id": {"type": "string", "pattern": PATTERNS["participant"].pattern}},
            "required": ["role", "id"], "additionalProperties": False}},
        "message_id": {"type": "string", "pattern": PATTERNS["id"].pattern},
        "chat_id": {"type": "string", "pattern": PATTERNS["id"].pattern},
        "in_reply_to": {"type": "string", "pattern": PATTERNS["id"].pattern},
        "dates": {"type": "array", "maxItems": 10, "items": {"type": "string", "pattern": PATTERNS["datetime"].pattern}},
        "amounts": {"type": "array", "maxItems": 10, "items": {
            "type": "object",
            "properties": {"amount": {"type": "number"}, "currency": {"type": "string", "pattern": "^[A-Z]{3}$"}},
            "required": ["amount"], "additionalProperties": False}},
    },
    "required": ["answer"],
    "additionalProperties": False,
}
