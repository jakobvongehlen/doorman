"""Small helpers: canonical JSON, hashing, tokens, destination extraction."""

import hashlib
import json
import re
import secrets
from typing import Any, Iterator

UPLOAD = "upload"  # upload:<sha256>: a file an agent uploaded (POST /v1/uploads); not a plugin


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(text: str | bytes) -> str:
    if isinstance(text, str):
        text = text.encode()
    return hashlib.sha256(text).hexdigest()


def new_token(prefix: str = "") -> str:
    return prefix + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    # "broker-token:" is from before the rename to Doorman; stored key and session hashes depend on it
    return sha256_hex("broker-token:" + token)


def dumps(value: Any) -> str | None:
    return None if value is None else json.dumps(value, ensure_ascii=False, default=str)


def loads(text: str | None, default: Any = None) -> Any:
    return default if text is None else json.loads(text)


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")
PHONE_RE = re.compile(r"\+\d[\d /-]{6,}\d")


def normalize(kind: str, value: str) -> str:
    value = str(value).strip()
    if kind == "iban":
        return value.replace(" ", "").upper()
    if kind == "phone":
        return "+" + re.sub(r"\D", "", value)
    if kind == "url":
        match = re.match(r"(https?://)([^/]+)(.*)", value, re.I)
        if match:
            return match.group(1).lower() + match.group(2).lower() + match.group(3)
        return value
    return value.lower()


def extract_destinations(text: str) -> Iterator[tuple[str, str]]:
    """Find values in free text that could later be used as a destination."""
    for match in EMAIL_RE.finditer(text):
        yield "email", normalize("email", match.group())
    for match in IBAN_RE.finditer(text):
        yield "iban", normalize("iban", match.group())
    for match in URL_RE.finditer(text):
        yield "url", normalize("url", match.group())
    for match in PHONE_RE.finditer(text):
        yield "phone", normalize("phone", match.group())


def walk_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from walk_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from walk_strings(item)


def get_path(data: dict, path: str) -> Any:
    """Read a dotted path; a list along the way is expanded."""
    current: Any = data
    for part in path.split("."):
        if isinstance(current, list):
            current = [item.get(part) if isinstance(item, dict) else None for item in current]
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def safe_filename(name: Any) -> str:
    """A plain file name for an attachment or a saved copy: no folders, no control characters, not empty."""
    text = str(name or "").replace("\\", "/").rsplit("/", 1)[-1]
    text = "".join(ch for ch in text if ch.isprintable()).strip().lstrip(".")
    return text[:200] or "file"
