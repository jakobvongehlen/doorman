"""The owner's address books over CardDAV (Nextcloud Contacts, Radicale), read-only.

Only books the owner owns are read. A book another user shares (Nextcloud lists it in your home with its
owner's principal) and Nextcloud's system address book (every user on the server, each filling in their own
card) are other people's data, and the manifest's `trust: owner` would be wrong for them, so they are listed
by `books` and never read.

Each book is fetched whole with one REPORT and kept in memory until its ctag changes, so a search costs one
PROPFIND while nothing changed. The vCard parser below reads only what the reads return (FN, N, EMAIL, TEL,
ORG, TITLE, NOTE, BDAY, UID); vCard 2.1's quoted-printable and bare TYPE parameters included.

The same cards tell Doorman who the owner knows (known_recipients): a send to an address or number in one of
the owner's own books has no "new recipient" warning. That check reuses the cards for a minute without asking
the server, so a burst of sends costs at most one PROPFIND."""

import copy
import quopri
import re
import threading
import time
import unicodedata
from urllib.parse import unquote, urljoin, urlsplit
from xml.etree import ElementTree

import httpx

from doorman.plugin_api import BasePlugin, PluginError

DAV, CARD, CS, OC = "DAV:", "urn:ietf:params:xml:ns:carddav", "http://calendarserver.org/ns/", "http://owncloud.org/ns"
NOTE_CHARS = 4000
KNOWN_FRESH_SECONDS = 60   # known_recipients trusts cards checked this recently without a PROPFIND
WHATSAPP_JID = re.compile(r"^(\d{6,})@s\.whatsapp\.net$")
SEARCH_KEYS = ("id", "name", "emails", "phones", "organisation", "title", "birthday", "book", "ref")

PROPFIND_PRINCIPAL = (f'<d:propfind xmlns:d="{DAV}"><d:prop><d:current-user-principal/></d:prop></d:propfind>')
PROPFIND_HOME = (f'<d:propfind xmlns:d="{DAV}" xmlns:card="{CARD}"><d:prop><card:addressbook-home-set/>'
                 '</d:prop></d:propfind>')
PROPFIND_BOOKS = (f'<d:propfind xmlns:d="{DAV}" xmlns:cs="{CS}" xmlns:oc="{OC}"><d:prop><d:resourcetype/>'
                  '<d:displayname/><cs:getctag/><d:sync-token/><d:owner/><oc:owner-principal/></d:prop></d:propfind>')
REPORT_ALL = (f'<card:addressbook-query xmlns:d="{DAV}" xmlns:card="{CARD}"><d:prop><d:getetag/>'
              '<card:address-data/></d:prop></card:addressbook-query>')


# ------------------------------------------------------------------------------------------ vCard


def _split_outside_quotes(text: str, sep: str, limit: int = -1) -> list[str]:
    parts, current, quoted = [], [], False
    for ch in text:
        if ch == '"':
            quoted = not quoted
        if ch == sep and not quoted and limit != 0:
            parts.append("".join(current))
            current = []
            limit -= 1
            continue
        current.append(ch)
    parts.append("".join(current))
    return parts


def _unescape(value: str) -> str:
    return re.sub(r"\\(.)", lambda m: "\n" if m.group(1) in "nN" else m.group(1), value)


def _components(value: str) -> list[str]:
    """A structured value (N, ORG) split at its unescaped semicolons."""
    return [_unescape(p) for p in re.split(r"(?<!\\);", value)]


def _lines(text: str) -> list[str]:
    """Unfolded lines: a line starting with a space or tab continues the one before it, and a
    quoted-printable line ending in `=` (vCard 2.1) goes on in the next."""
    out: list[str] = []
    for raw in re.split(r"\r\n|\r|\n", text):
        if raw[:1] in (" ", "\t") and out:
            out[-1] += raw[1:]
        elif out and out[-1].endswith("=") and "QUOTED-PRINTABLE" in out[-1].split(":", 1)[0].upper():
            out[-1] += raw
        else:
            out.append(raw)
    return out


def parse_line(line: str) -> tuple[str, dict[str, list[str]], str] | None:
    """(NAME, {PARAM: [values]}, value) for one content line, the group prefix (item1.) dropped."""
    parts = _split_outside_quotes(line, ":", 1)
    if len(parts) != 2:
        return None
    head, value = parts
    name, *raw_params = _split_outside_quotes(head, ";")
    params: dict[str, list[str]] = {}
    for param in raw_params:
        key, eq, values = param.partition("=")
        if not eq:  # vCard 2.1: ;WORK;INTERNET
            key, values = "TYPE", key
        params.setdefault(key.strip().upper(), []).extend(
            v.strip().strip('"') for v in _split_outside_quotes(values, ","))
    if params.get("ENCODING", [""])[0].upper() == "QUOTED-PRINTABLE":
        charset = (params.get("CHARSET") or ["utf-8"])[0]
        try:
            value = quopri.decodestring(value.encode("latin-1", "replace")).decode(charset, "replace")
        except LookupError:
            value = quopri.decodestring(value.encode("latin-1", "replace")).decode("utf-8", "replace")
    return name.rsplit(".", 1)[-1].strip().upper(), params, value


def _kinds(params: dict) -> tuple[str, bool]:
    """The TYPE parameter as a short label (work, cell) and whether it is the preferred one."""
    types = [t.lower() for v in params.get("TYPE", []) for t in v.split(",") if t]
    pref = "pref" in types or bool(params.get("PREF"))
    label = ",".join(t for t in types if t not in ("pref", "internet", "voice", "x400"))
    return label, pref


def birthday(value: str, params: dict) -> str | None:
    """ISO: 1990-03-15, or --03-15 without a year (vCard 4's --0315, Apple's year 1604)."""
    value = value.strip()
    match = re.match(r"^(\d{4})-?(\d{2})-?(\d{2})", value)
    if match:
        year, month, day = match.groups()
        omit = (params.get("X-APPLE-OMIT-YEAR") or [""])[0]
        return f"--{month}-{day}" if year == omit or year == "1604" else f"{year}-{month}-{day}"
    match = re.match(r"^--(\d{2})-?(\d{2})$", value)
    if match:
        return f"--{match.group(1)}-{match.group(2)}"
    return value[:40] or None


def parse_vcard(lines: list[str]) -> dict:
    """One card's fields, as the reads return them."""
    card = {"uid": None, "name": "", "first": "", "last": "", "emails": [], "phones": [], "organisation": "",
            "title": "", "birthday": None, "note": ""}
    emails, phones = [], []
    for line in lines:
        parsed = parse_line(line)
        if parsed is None:
            continue
        name, params, value = parsed
        if name == "FN":
            card["name"] = _unescape(value).strip()
        elif name == "N":
            parts = _components(value) + ["", "", "", "", ""]
            card["last"], card["first"] = parts[0].strip(), parts[1].strip()
            card["_n"] = " ".join(p.strip() for p in (parts[3], parts[1], parts[2], parts[0], parts[4]) if p.strip())
        elif name == "EMAIL":
            address = re.sub(r"^mailto:", "", _unescape(value).strip(), flags=re.I)
            if address:
                label, pref = _kinds(params)
                emails.append((not pref, {"address": address, "type": label}))
        elif name == "TEL":
            number = re.sub(r"^tel:", "", _unescape(value).strip(), flags=re.I)
            if number:
                label, pref = _kinds(params)
                phones.append((not pref, {"number": number, "type": label}))
        elif name == "ORG":
            card["organisation"] = " / ".join(p.strip() for p in _components(value) if p.strip())
        elif name == "TITLE":
            card["title"] = _unescape(value).strip()
        elif name == "NOTE":
            card["note"] = _unescape(value).strip()[:NOTE_CHARS]
        elif name == "BDAY":
            card["birthday"] = birthday(value, params)
        elif name == "UID":
            card["uid"] = _unescape(value).strip() or None
    # preferred first, otherwise in the card's order (sorted() is stable)
    card["emails"] = [e for _, e in sorted(emails, key=lambda p: p[0])]
    card["phones"] = [p for _, p in sorted(phones, key=lambda p: p[0])]
    full_name = card.pop("_n", "")
    card["name"] = card["name"] or full_name or card["organisation"] or \
        (card["emails"][0]["address"] if card["emails"] else "")
    return card


def parse_vcards(text: str) -> list[dict]:
    """Every card in a vCard text (usually one per resource); a card inside a card (AGENT) is skipped."""
    cards, current, depth = [], None, 0
    for line in _lines(text):
        upper = line.strip().upper()
        if upper == "BEGIN:VCARD":
            depth += 1
            if depth == 1:
                current = []
            continue
        if upper == "END:VCARD":
            depth -= 1
            if depth == 0 and current is not None:
                cards.append(parse_vcard(current))
                current = None
            continue
        if depth == 1 and current is not None:
            current.append(line)
    return cards


# ------------------------------------------------------------------------------------------ search


def fold(text: str) -> str:
    """Lower case without accents, so `jose` finds José."""
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c)).casefold()


def digits(text: str) -> str:
    return re.sub(r"\D", "", text)


def matches(card: dict, query: str) -> bool:
    """Every word of the query is in the name, an address, the organisation or the title; or the query is a
    number that is part of one of the card's numbers, in any format (06 1234 5678 finds +31 6 12345678)."""
    if re.fullmatch(r"[\d\s+()./-]+", query) and len(digits(query)) >= 3:
        wanted = digits(query).lstrip("0")
        return bool(wanted) and any(wanted in digits(p["number"]) for p in card["phones"])
    haystack = fold(" ".join([card["name"], card["first"], card["last"], card["organisation"], card["title"],
                              *(e["address"] for e in card["emails"])]))
    return all(word in haystack for word in fold(query).split())


def same_number(wanted: str, number: str) -> bool:
    """Whether a card's number (as typed: +31 6 1234 5678, 0031..., 06 1234 5678) is this one in
    international digits (31612345678, as a phone destination or a WhatsApp chat has it). A national number
    (one leading 0) has no country code, so any code of one to three digits in front of it matches."""
    have = digits(number)
    if not wanted or not have:
        return False
    if number.strip().startswith("+") or have == wanted:
        return have == wanted
    if have.startswith("00"):
        return have[2:] == wanted
    national = have[1:] if have.startswith("0") else ""
    return len(national) >= 6 and wanted.endswith(national) and 1 <= len(wanted) - len(national) <= 3


def rank(card: dict, query: str) -> tuple:
    name, wanted = fold(card["name"]), fold(query).strip()
    return (0 if wanted and name.startswith(wanted) else 1 if wanted and wanted in name else 2, name)


# ------------------------------------------------------------------------------------------ the plugin


def _text(element, path: str) -> str:
    found = element.find(path)
    return (found.text or "").strip() if found is not None else ""


class Plugin(BasePlugin):
    TOOLS = {}
    READS = {"books": "read_books", "search": "read_search", "get": "read_get"}

    def __init__(self, ctx, manifest):
        super().__init__(ctx, manifest)
        self._lock = threading.Lock()
        self._home: str | None = None
        self._principal: str | None = None
        self._cache: dict[str, tuple[str | None, list[dict]]] = {}  # book href -> (ctag, cards)
        self._checked = 0.0  # when cards() last compared every book's ctag with the server (monotonic)

    # connection

    def url(self) -> str:
        url = (self.config.get("url") or "").strip()
        if not url:
            raise PluginError(f"{self.ctx.instance}: set config.url")
        if url.startswith("http://") and not self.config.get("allow_http"):
            raise PluginError(f"{self.ctx.instance}: {url} isn't https; set allow_http: true for a server on "
                              "your own network")
        return url if url.endswith("/") else url + "/"

    def request(self, method: str, url: str, body: str, depth: str) -> ElementTree.Element:
        auth = (self.credentials.get("username") or "", self.credentials.get("password") or "")
        try:
            with httpx.Client(auth=auth, timeout=30, follow_redirects=True) as client:
                response = client.request(method, url, content=body.encode(), headers={
                    "Depth": depth, "Content-Type": "application/xml; charset=utf-8"})
        except httpx.HTTPError as exc:
            raise PluginError(f"CardDAV server unreachable: {exc}") from None
        if response.status_code == 401:
            raise PluginError("CardDAV login refused: check username and password (Nextcloud: an app password)")
        if response.status_code >= 400:
            raise PluginError(f"CardDAV {method} {urlsplit(url).path}: HTTP {response.status_code}")
        try:
            return ElementTree.fromstring(response.content)
        except ElementTree.ParseError:
            raise PluginError(f"CardDAV {method} {urlsplit(url).path}: the answer isn't XML") from None

    def _href(self, root: ElementTree.Element, prop: str, base: str) -> str | None:
        href = root.find(f".//{{{DAV}}}{prop}/{{{DAV}}}href") if prop else None
        return urljoin(base, href.text.strip()) if href is not None and href.text else None

    def home(self) -> str:
        """The address book home: the URL's principal (current-user-principal), then its
        addressbook-home-set. A URL that is already a principal or a home works too."""
        if self._home is None:
            url = self.url()
            principal = self._href(self.request("PROPFIND", url, PROPFIND_PRINCIPAL, "0"),
                                   "current-user-principal", url) or url
            root = self.request("PROPFIND", principal, PROPFIND_HOME, "0")
            home = root.find(f".//{{{CARD}}}addressbook-home-set/{{{DAV}}}href")
            self._principal = urlsplit(principal).path.rstrip("/")
            self._home = urljoin(principal, home.text.strip()) if home is not None and home.text else principal
        return self._home

    def all_books(self) -> list[dict]:
        """Every address book in the home: {name, href, ctag, shared_by}. shared_by is None for the owner's
        own books, else whose book it is ("system" for Nextcloud's address book of every user)."""
        home = self.home()
        found, names = [], set()
        for response in self.request("PROPFIND", home, PROPFIND_BOOKS, "1").findall(f"{{{DAV}}}response"):
            href = _text(response, f"{{{DAV}}}href")
            if response.find(f".//{{{DAV}}}resourcetype/{{{CARD}}}addressbook") is None or not href:
                continue
            segment = unquote(href.rstrip("/").rsplit("/", 1)[-1])
            name = _text(response, f".//{{{DAV}}}displayname") or segment
            if name in names:
                name = f"{name} ({segment})"
            names.add(name)
            ctag = _text(response, f".//{{{CS}}}getctag") or _text(response, f".//{{{DAV}}}sync-token") or None
            found.append({"name": name, "href": urljoin(home, href), "ctag": ctag,
                          "shared_by": self._sharer(response, segment)})
        return found

    def _sharer(self, response, segment: str) -> str | None:
        """Whose book this is, when it isn't the owner's: Nextcloud says so in oc:owner-principal (and
        names shared books <name>_shared_by_<user>); DAV:owner where servers give it."""
        owner = _text(response, f".//{{{OC}}}owner-principal") or _text(response, f".//{{{DAV}}}owner/{{{DAV}}}href")
        path = unquote(urlsplit(owner).path).strip("/").split("remote.php/dav/")[-1]
        if "z-server-generated--system" in segment or path.startswith("principals/system"):
            return "system"
        if path:
            mine = (self._principal or "").strip("/").split("/")
            theirs = path.split("/")
            if mine[-len(theirs):] != theirs:
                return theirs[-1]
        if "_shared_by_" in segment:
            return segment.rsplit("_shared_by_", 1)[-1]
        return None

    def books(self) -> list[dict]:
        """The books to read: the owner's own, narrowed to config.books when it names some."""
        wanted = self.config.get("books")
        if isinstance(wanted, str):  # one name, typed without brackets
            wanted = [wanted]
        return [b for b in self.all_books() if b["shared_by"] is None and (wanted is None or b["name"] in wanted)]

    def cards(self, max_age: float = 0) -> list[dict]:
        """Every card in the books to read, each with its book; a book is fetched again only when its ctag
        moved (or the server gives none). With max_age, cards checked against the server that many seconds
        ago or less are used as they are."""
        out = []
        with self._lock:
            if max_age and self._cache and time.monotonic() - self._checked < max_age:
                return copy.deepcopy([card for _, cards in self._cache.values() for card in cards])
            books = self.books()
            for book in books:
                cached = self._cache.get(book["href"])
                if cached is None or cached[0] is None or cached[0] != book["ctag"]:
                    cached = (book["ctag"], self._fetch(book))
                    self._cache[book["href"]] = cached
                out += cached[1]
            for href in set(self._cache) - {b["href"] for b in books}:
                del self._cache[href]
            self._checked = time.monotonic()
        return copy.deepcopy(out)  # in Doorman's own process (no sandbox) a caller mustn't change the cache

    def _fetch(self, book: dict) -> list[dict]:
        cards = []
        for response in self.request("REPORT", book["href"], REPORT_ALL, "1").findall(f"{{{DAV}}}response"):
            data = response.find(f".//{{{CARD}}}address-data")
            if data is None or not data.text:
                continue
            href = _text(response, f"{{{DAV}}}href")
            fallback = unquote(href.rstrip("/").rsplit("/", 1)[-1]).removesuffix(".vcf")
            for card in parse_vcards(data.text):
                card["id"] = card.pop("uid") or fallback
                card["book"] = book["name"]
                card["ref"] = f"{self.ctx.instance}:{card['id']}"
                cards.append(card)
        return cards

    def check(self):
        self._home = None  # a moved server or new login shows up here
        try:
            books = self.all_books()
        except PluginError as exc:
            return str(exc)
        wanted = self.config.get("books")
        wanted = [wanted] if isinstance(wanted, str) else wanted or []
        shared = [b["name"] for b in books if b["shared_by"] and b["name"] in wanted]
        missing = [n for n in wanted if n not in {b["name"] for b in books}]
        problems = []
        if shared:
            problems.append(f"shared with you, so never read: {', '.join(shared)}")
        if missing:
            problems.append(f"not on the server: {', '.join(missing)}")
        return "; ".join(problems) or None

    # reads

    def read_books(self, params):
        used = {b["href"] for b in self.books()}
        return [{"name": b["name"], "used": b["href"] in used,
                 **({"shared_by": b["shared_by"]} if b["shared_by"] else {})} for b in self.all_books()]

    def read_search(self, params):
        query = (params.get("query") or "").strip()
        limit = int(params.get("limit") or 20)
        found = [c for c in self.cards() if (not query or matches(c, query))
                 and (c["emails"] or not params.get("with_email"))]
        found.sort(key=lambda c: rank(c, query))
        return {"contacts": [{k: c[k] for k in SEARCH_KEYS if c.get(k) not in (None, "", [])}
                             for c in found[:limit]], "more": len(found) > limit}

    def read_get(self, params):
        for card in self.cards():
            if card["id"] == params["id"]:
                return card
        raise PluginError(f"no contact with id {params['id']}")

    # for Doorman's recipient check

    def known_recipients(self, destinations):
        """Which of these [kind, value] destinations are in the owner's own books: {value: {"name": ...}}.
        An email address matches in any case; a phone number or a WhatsApp chat (<number>@s.whatsapp.net)
        matches a card's number by its digits (same_number). Shared and system books are never read, so
        they never count."""
        cards = self.cards(max_age=KNOWN_FRESH_SECONDS)
        found = {}
        for kind, value in destinations:
            wanted = str(value or "").lower()
            if kind == "email":
                card = next((c for c in cards if any(e["address"].lower() == wanted for e in c["emails"])), None)
            elif kind in ("phone", "chat"):
                jid = WHATSAPP_JID.match(wanted)
                number = digits(wanted) if kind == "phone" else jid.group(1) if jid else ""
                card = next((c for c in cards if number and any(same_number(number, p["number"])
                                                                for p in c["phones"])), None)
            else:
                card = None
            if card is not None:
                found[value] = {"name": card["name"]}
        return found
