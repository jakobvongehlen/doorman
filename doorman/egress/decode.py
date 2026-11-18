"""The texts inside an outgoing request, so the proxy can fingerprint them and look for honeytokens.

An agent that wants data out unseen won't paste it in plain sight: it base64s it into a query parameter,
hex-encodes it into a header, gzips it into a form field or wraps it in JSON. So besides the plain parts
(the URL's path and query, the headers that can carry data, the body as text, JSON strings, form fields,
multipart parts) this unpacks the usual encodings: base64 and base64url, hex, percent-encoding, gzip and
zlib, and encodings of encodings until nothing new comes out (MAX_DEPTH levels at most).

Bytes are read in the charset they declare or start with (a byte-order mark: UTF-8, UTF-16, UTF-32), else
as UTF-8, with stray bytes replaced rather than failing the whole text, and as Latin-1 when that reads
better. Control characters are dropped first, so text with a \\x01 or NUL between its characters (or UTF-16
without a byte-order mark) still reads as text. It counts as text when at least 85% of it is printable (and,
in a one-byte charset, mostly ASCII). Bytes that don't read as text as a whole (an image, an archive, or
text hidden between random bytes) give their printable runs of MIN_RUN characters or more, so a secret
can't be hidden by padding it with noise, while random bytes almost never have such a run: a JWT's
signature, an image or a session token adds nothing, and the fingerprints aren't diluted by noise.

All of it runs inside the proxy on every request with a body or a long URL, so the cost is capped: the
texts together never exceed MAX_SCAN_BYTES characters (a gzip bomb inflates no further than what is left of
that), at most MAX_RUNS encoded-looking runs are tried per request, and nothing is unpacked past MAX_DEPTH.
The caller's HTTP library has already undone the Content-Encoding.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import json
import re
import zlib
from collections import deque
from collections.abc import Iterator
from functools import lru_cache
from itertools import islice
from urllib.parse import unquote, unquote_to_bytes, urlsplit

from .fingerprint import normalize, strings_of

MAX_SCAN_BYTES = 16 * 1024 * 1024  # characters of text, all texts of one request together
MAX_DEPTH = 6                      # encodings inside encodings, no deeper
MAX_RUNS = 10_000                  # encoded-looking runs tried per request
TEXT_SHARE = 0.85                  # printable share of decoded bytes that makes them text
ASCII_SHARE = 0.85                 # in a one-byte charset (random bytes are ~50% ASCII there)
MIN_RUN = 32                       # printable run taken from bytes that aren't text as a whole
HONEYTOKEN_SPREAD = 8              # tokens this long (normalized) are also found spread out or datamarked

# never scanned: digits that mitmproxy checks. Every other header is the agent's to write (Host, User-Agent,
# cookies, Sec-*), and the values real clients send there are too short to give a print anyway.
SKIP_HEADERS = frozenset({"content-length"})

# base64 and base64url, MIME line breaks allowed: 32 characters are 24 bytes, the shortest worth decoding
_B64 = re.compile(r"[A-Za-z0-9+/_\-\r\n]{32,}={0,2}")
_B64_SPLIT = re.compile(r"[/\r\n]+")
_HEX = re.compile(r"[0-9A-Fa-f]{48,}")
_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_URLSAFE = str.maketrans("-_", "+/")
# dropped before anything else: C0 and C1 controls other than tab and line breaks, and the byte-order mark
_CONTROLS = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f﻿]+")
_C0_BYTES = bytes(b for b in range(32) if b not in (9, 10, 13)) + b"\x7f"
_LOW_BYTES = bytes(range(128))
_DROP_ASCII = dict.fromkeys(range(128))
_RUN = re.compile("[^�\x80-\x9f﻿]{%d,}" % MIN_RUN)
_CHARSET = re.compile(r'charset\s*=\s*"?([A-Za-z0-9._:-]+)', re.I)
_BOMS = ((codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"), (codecs.BOM_UTF8, "utf-8-sig"),
         (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"))
_BOUNDARY = re.compile(r'boundary="?([^";]+)"?', re.I)
_JSON_START = re.compile(r"\s*[\[{]")


def charset_of(content_type: str | None) -> str | None:
    """The codec a Content-Type names (`charset=`), if Python knows it."""
    found = _CHARSET.search(content_type or "")
    return _codec(found.group(1)) if found else None


@lru_cache(maxsize=64)
def _codec(name: str) -> str | None:
    try:
        return codecs.lookup(name).name
    except (LookupError, ValueError):
        return None


@lru_cache(maxsize=64)
def _one_byte(codec: str) -> bool:
    """Every byte one character (Latin-1, cp1252, KOI8-R...), unlike UTF-8 or the CJK codecs."""
    return len(b"\xc3\xa4".decode(codec, "replace")) == 2


def _decode(data: bytes, codec: str, final: bool) -> str:
    if final:
        return data.decode(codec, "replace")
    # cut off at a limit: a character split at the end is fine
    return codecs.getincrementaldecoder(codec)("replace").decode(data, final=False)


def _reads_as_text(text: str, one_byte: bool) -> bool:
    """`text` (C0 controls already dropped) is mostly printable; in a one-byte charset also mostly ASCII.
    The cheap counts come first: random bytes fail one of them without a per-character pass."""
    if not text or not text.strip():
        return False
    allowed = len(text) * (1 - TEXT_SHARE)
    bad = text.count("�")
    if bad > allowed:
        return False
    non_ascii = len(text) - len(text.encode("ascii", "ignore"))
    if one_byte and non_ascii > len(text) * (1 - ASCII_SHARE):
        return False
    if non_ascii:
        rest = text.translate(_DROP_ASCII).replace("�", "")
        if not rest.isprintable():
            bad += sum(1 for c in rest if not c.isprintable() and not c.isspace())
    return bad <= allowed


def _as_text(data: bytes, final: bool = True, charset: str | None = None) -> str | None:
    """The bytes as text, or their printable runs, or None."""
    codec = next((name for bom, name in _BOMS if data.startswith(bom)), None)
    declared = codec is None and charset is not None
    codec = codec or charset or "utf-8"
    if codec.startswith(("utf-16", "utf-32")):  # NUL bytes belong to the characters here
        text = _CONTROLS.sub("", _decode(data, codec, final))
        return text if _reads_as_text(text, False) else None
    raw = data.translate(None, _C0_BYTES)  # C0 controls: one byte each in every charset read here
    text = _decode(raw, codec, final)
    if _reads_as_text(text, _one_byte(codec)):
        return _CONTROLS.sub("", text)
    if codec == "utf-8" and not declared and len(raw.translate(None, _LOW_BYTES)) <= len(raw) * (1 - ASCII_SHARE):
        latin = raw.decode("latin-1")
        if _reads_as_text(latin, True):
            return _CONTROLS.sub("", latin)
    if codec != "utf-8":
        text = _decode(raw, "utf-8", final)
    runs = _RUN.findall(text)  # bytes that aren't UTF-8 are U+FFFD now and end a run
    return "\n".join(runs) or None


def _inflate(data: bytes, limit: int) -> bytes | None:
    if data[:2] == b"\x1f\x8b":
        wbits = 31  # gzip
    elif len(data) >= 2 and data[0] & 0x0F == 8 and data[0] >> 4 <= 7 and (data[0] << 8 | data[1]) % 31 == 0:
        wbits = 15  # zlib
    else:
        return None
    try:
        return zlib.decompressobj(wbits).decompress(data, max(limit, 1))
    except zlib.error:
        return None


def _text_of_bytes(data: bytes, limit: int, charset: str | None = None) -> str | None:
    """Bytes as text, inflating gzip or zlib first, as often as it is wrapped (to at most `limit` bytes)."""
    inflated = False
    for _ in range(MAX_DEPTH):
        out = _inflate(data, limit)
        if out is None:
            break
        data, inflated = out, True
    if inflated:
        return _as_text(data, final=len(data) < limit, charset=charset)
    return _as_text(data[:limit], final=len(data) <= limit, charset=charset)


def _base64(run: str) -> bytes | None:
    s = run.replace("\r", "").replace("\n", "").rstrip("=")
    if "-" in s or "_" in s:
        if "+" in s or "/" in s:
            return None  # both alphabets at once: not one base64 string
        s = s.translate(_URLSAFE)
    s = s[:-1] if len(s) % 4 == 1 else s
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _hex(run: str) -> list[bytes]:
    runs = [run] if len(run) % 2 == 0 else [run[:-1], run[1:]]
    return [bytes.fromhex(r) for r in runs]


class _Scan:
    def __init__(self) -> None:
        self.left = MAX_SCAN_BYTES
        self.runs = MAX_RUNS
        self.texts: list[str] = []
        self.seen: set[str] = set()
        self.todo: deque[tuple[str, int]] = deque()

    def add(self, text: str, depth: int) -> None:
        if not text or self.left <= 0:
            return
        if _JSON_START.match(text):  # JSON: its strings, unescaped, not the raw text
            try:
                data = json.loads(text)
            except (ValueError, RecursionError):  # nested past the parser's limit: read as text
                data = None
            if isinstance(data, (dict, list)):
                for s in strings_of(data):
                    self.add(s, depth)
                return
        text = text[:self.left]
        if text in self.seen:
            return
        self.seen.add(text)
        self.texts.append(text)
        self.left -= len(text)
        self.todo.append((text, depth))

    def run(self) -> list[str]:
        while self.todo and self.left > 0:
            text, depth = self.todo.popleft()
            if depth < MAX_DEPTH:
                for found in self._decoded(text):
                    self.add(found, depth + 1)
                    if self.left <= 0:
                        break
        return self.texts

    def _decoded(self, text: str) -> Iterator[str]:
        """Texts hidden in `text` by one layer of encoding."""
        if len(list(islice(_PERCENT.finditer(text), 3))) == 3:
            found = _text_of_bytes(unquote_to_bytes(text), self.left)
            if found and found != text:
                yield found
        for match in _B64.finditer(text):
            if not self._budget():
                return
            run = match.group(0)
            found = self._decode(_base64(run))
            if found:
                yield found
            elif _B64_SPLIT.search(run.rstrip("=")):
                # glued to a path, or lines that aren't one string: the pieces on their own
                for piece in _B64_SPLIT.split(run):
                    if len(piece) >= 32 and (found := self._decode(_base64(piece))):
                        yield found
        for match in _HEX.finditer(text):
            if not self._budget():
                return
            for raw in _hex(match.group(0)):
                if found := self._decode(raw):
                    yield found
                    break

    def _budget(self) -> bool:
        self.runs -= 1
        return self.runs >= 0 and self.left > 0

    def _decode(self, raw: bytes | None) -> str | None:
        return _text_of_bytes(raw, self.left) if raw else None


def _url_text(url: str) -> str:
    try:
        parts = urlsplit(url)
        path = parts.path + ("?" + parts.query if parts.query else "")
    except ValueError:
        path = url
    return unquote(path)


def _parts(body: bytes, boundary: str) -> Iterator[tuple[str, bytes]]:
    """(content type, payload) of each part of a multipart body."""
    for chunk in body.split(b"--" + boundary.encode())[1:]:
        if chunk.startswith(b"--"):
            break
        head, sep, payload = chunk.partition(b"\r\n\r\n")
        if not sep:
            head, sep, payload = chunk.partition(b"\n\n")
        if not sep:
            continue
        payload = payload[:-2] if payload.endswith(b"\r\n") else payload.removesuffix(b"\n")
        ctype = ""
        for line in head.decode("latin-1").splitlines():
            name, _, value = line.partition(":")
            if name.strip().lower() == "content-type":
                ctype = value.strip()
        yield ctype, payload


def _body(scan: _Scan, body: bytes, content_type: str, nesting: int = 0) -> None:
    if not body or scan.left <= 0:
        return
    body = body[:scan.left]
    ctype = content_type.split(";")[0].strip().lower()
    boundary = _BOUNDARY.search(content_type)
    if ctype.startswith("multipart/") and boundary and nesting < 4:
        for part_type, payload in _parts(body, boundary.group(1)):
            _body(scan, payload, part_type, nesting + 1)
        return
    text = _text_of_bytes(body, scan.left, charset_of(content_type))
    if text is None:
        return  # binary: an image, an archive
    if ctype == "application/x-www-form-urlencoded":
        # each field's name and value (the agent writes both; a field may have no "=" at all); "+" stays "+"
        # (parse_qsl would make it a space and break base64 sent unescaped), which costs nothing:
        # normalization drops it like a space
        for field in text.split("&"):
            name, _, value = field.partition("=")
            scan.add(unquote(name), 0)
            scan.add(unquote(value), 0)
        return
    scan.add(text, 0)


def texts_of_request(url: str, headers: list[tuple[str, str]], body: bytes, content_type: str = "") -> list[str]:
    """Every text a request carries: URL path and query, headers that can carry data, body, and what's
    hidden inside them in base64, base64url, hex, percent-encoding, gzip or zlib (up to MAX_DEPTH deep)."""
    scan = _Scan()
    scan.add(_url_text(url), 0)
    for name, value in headers:
        name = name.lower()
        if name not in SKIP_HEADERS:
            scan.add(value, 0)
    _body(scan, body, content_type)
    return scan.run()


def honeytoken_hits(texts: list[str], tokens: list[str]) -> list[str]:
    """The tokens found in the texts: as they are (ignoring case), and tokens of HONEYTOKEN_SPREAD or more
    normalized characters also with spaces, punctuation or datamarks put between their characters."""
    tokens = [t for t in dict.fromkeys(tokens) if t and t.strip()]
    if not tokens:
        return []
    folded = [t.casefold() for t in texts]
    spread = {t: n for t in tokens if len(n := normalize(t)) >= HONEYTOKEN_SPREAD}
    normalized = [normalize(t) for t in texts] if spread else []
    hits = []
    for token in tokens:
        low = token.casefold()
        if any(low in f for f in folded) or (token in spread and any(spread[token] in n for n in normalized)):
            hits.append(token)
    return hits
