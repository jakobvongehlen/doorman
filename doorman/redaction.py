"""Masks one-time codes and account-recovery links before an agent sees them.

A code is only worth anything to someone who has started a login or reset with the owner's address, which
an injected agent on the open web can do, so codes are masked wherever text from outside reaches an agent:
reads, search rows, `recent`, events. How much is masked is the owner's choice (`redaction.codes`):

- `basic` (default): a code word, then the number on the same line ("Your code is 123456"), and links to
  reset or verify an account. Postal codes, course codes, phone numbers and the like stay.
- `strict`: also the code first ("123456 is your Instagram code"), "Use 482913 to sign in", letter codes
  after passcode words, a code on a line of its own, token links in sign-in mail, and every code-shaped
  token (subject included) of an item from a security sender (redaction.security_senders).
- `off`: nothing is masked, and mail from security senders isn't withheld either; the agent can read
  codes, for example to finish a login the owner asked for.

In every mode ids, refs and timestamps are never touched.
"""

import fnmatch
import re
from typing import Any

CODE_WORDS = (
    r"code|otp|tan|pin|passcode|verification|verify|security code|login code|"
    r"bestätigungscode|sicherheitscode|einmalcode|einmalpasswort|anmeldecode|freigabecode|"
    r"verificatiecode|beveiligingscode|inlogcode|toegangscode"
)
# words that name something other than a secret code, so "Postal code 3584 CS" and "course code 201400123" stay
NOT_SECRET = ("postal", "zip", "post", "area", "course", "country", "dress", "source", "colour", "color",
              "promo", "discount", "voucher", "coupon", "tax", "product", "article", "item")
# checked on the word before a match, not as lookbehinds in the pattern: three dozen lookbehinds at every
# position made a 2 MB text take seconds
_WORD_BEFORE = re.compile(r"(\w+)[ -]$")
# any code word at all: most texts have none, and then the code patterns needn't run
ANY_CODE_WORD = re.compile(r"(?i)code|otp|password|tan\b|pin\b|verif|einmal|use\b|enter\b|type\b|gebruik|voer|verwende|gib|nutze")
# a keyword, then the code: digits on the same line, or on a line of their own ("Your code\n\n482913");
# never the start of a longer number, such as a phone number after a name like Tan
_CODE_AFTER = r"(\d[\d ]{2,10}\d)(?![.,:/-]?\d)(?! \d)"
CODE_RE = re.compile(rf"(?i)\b({CODE_WORDS})\b(?! of\b)([^\d\n]{{0,30}}|[^\w\n]*\n\s*){_CODE_AFTER}")
# basic mode: the code on the same line as its word only
CODE_SAME_LINE_RE = re.compile(rf"(?i)\b({CODE_WORDS})\b(?! of\b)([^\d\n]{{0,30}}){_CODE_AFTER}")
# words that only ever introduce a secret, so the code after them may have letters too: "passcode: AB12CD"
STRONG_WORDS = (
    r"passcode|one-time code|one-time password|otp|verification code|security code|login code|sign-in code|"
    r"confirmation code|access code|guard code|your code|bestätigungscode|sicherheitscode|einmalcode|"
    r"einmalpasswort|anmeldecode|freigabecode|verificatiecode|beveiligingscode"
)
ALNUM_CODE_RE = re.compile(
    rf"(?i)\b({STRONG_WORDS})\b([^\w\n]{{0,6}}(?:is|ist|lautet|=)?[^\w\n]{{0,4}})"
    r"(?-i:(?=[A-Z0-9-]*\d)(?=[A-Z0-9-]*[A-Z])[A-Z0-9][A-Z0-9-]{3,10}[A-Z0-9])\b"
)
# the code first: "123456 is your Google verification code", "482913 ist dein Bestätigungscode", or right
# before the code word: "123 456 – Microsoft security code" (not a year there: "2026 PIN rules")
_CODE_ALONE = r"(?<![\d.,:/])(?<!\d-)\b(?:\d{4,8}|\d{3}[ -]\d{3})\b(?![.,:/-]?\d)"
CODE_FIRST_RE = re.compile(
    rf"(?i){_CODE_ALONE}(?=\s+(?:is|ist|est|es)\s+(?:your|dein|ihr|je|uw|votre|tu)\b[^\d\n]{{0,30}}"
    rf"\b(?:{CODE_WORDS})\b(?! of\b))"
    rf"|(?!(?:19|20)\d\d\b){_CODE_ALONE}(?=[\s:–—-]{{1,3}}(?:\w+\s+){{0,2}}(?:{CODE_WORDS})\b(?! of\b))"
)
# "Use 482913 to sign in", "Enter 4829 to verify", "Gib 482913 ein, um dich anzumelden"
USE_CODE_RE = re.compile(
    r"(?i)\b(use|enter|type|gebruik|voer|verwende|gib|nutze)(\s+)(\d{4,8}|\d{3}[ -]\d{3})\b(?![.,:/-]?\d)"
    r"(?=[^\d\n]{0,40}\b(sign|log|verify|confirm|reset|activate|recover|anmeld|bestätig|inlog|bevestig))"
)
RECOVERY_URL_RE = re.compile(
    r"https?://\S*(reset|password|passwort|recover|verify|verification|token=|otp|magic|signin|login)\S*", re.I
)
# an item about signing in to an account: links in it with an opaque token are magic links
AUTH_CONTEXT_RE = re.compile(
    r"(?i)\b(?:sign[ -]?in|log[ -]?in|verify your|confirm your (?:e-?mail|account|address|registration|sign)|"
    r"reset your|activate your|magic link|one-time|verification code|security code|login code|"
    r"bestätigungscode|anmelden|bestätige|verificatiecode|inloggen|bevestig je)"
)
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+")
OPAQUE_RE = re.compile(r"(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{10,}")
# from a security sender: any token shaped like a code, but not a year, a date, a time or an amount
SENDER_CODE_RE = re.compile(
    r"(?<![\d.,:/-])\b(?!(?:19|20)\d\d\b)(\d{4,8}|\d{3}[ -]\d{3})\b(?![.,:/-]?\d)"
    r"|\b(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{5,12}\b"
)
SENDER_KEYS = ("from", "sender", "sender_name")
# identifiers the agent passes back and timestamps: never changed, or a message couldn't be opened by its id
ID_KEYS = {"id", "ref", "refs", "uid", "etag", "message_id", "thread_id", "in_reply_to", "sha256", "upload", "path",
           "folder", "mailbox", "date", "sent", "received", "start", "end", "due", "created", "modified", "updated",
           "ts", "when"}


def _keyword_code(match: re.Match) -> str:
    """CODE_RE's replacement, unless the word before names something that isn't a secret ("postal code")."""
    before = _WORD_BEFORE.search(match.string[max(0, match.start() - 12):match.start()])
    if before and before.group(1).lower() in NOT_SECRET:
        return match.group(0)
    return f"{match.group(1)}{match.group(2)}[code redacted]"


def _opaque_link(url: str) -> bool:
    """A link that carries a token: a path or query segment of 10+ characters mixing letters and digits."""
    rest = url.split("://", 1)[-1]
    path = rest.split("/", 1)[1] if "/" in rest else ""
    return any(OPAQUE_RE.fullmatch(part) for part in re.split(r"[/?&=#.]", path) if part)


MODES = ("off", "basic", "strict")


class Redactor:
    def __init__(self, config):
        section = config.get("redaction", {}) or {}
        self.security_senders = [s.lower() for s in section.get("security_senders", [])]
        self.codes = section.get("codes", "basic")
        if self.codes is False:  # YAML reads a bare `off` as false
            self.codes = "off"
        if self.codes not in MODES:
            raise ValueError(f"redaction.codes must be one of {', '.join(MODES)}, not {self.codes!r}")
        if self.codes == "off":  # mail from security senders isn't withheld either (mail_imap asks us)
            self.security_senders = []

    def is_security_sender(self, address: str | None) -> bool:
        if not address:
            return False
        address = address.lower()
        match = re.search(r"<([^>]+)>", address)
        if match:
            address = match.group(1)
        return any(fnmatch.fnmatch(address.strip(), pattern) for pattern in self.security_senders)

    def _from_security_sender(self, item: dict) -> bool:
        for key in SENDER_KEYS:
            value = item.get(key)
            for address in value if isinstance(value, list) else str(value or "").split(","):
                if isinstance(address, str) and self.is_security_sender(address):
                    return True
        return False

    def text(self, text: str, security: bool = False, auth: bool = False) -> str:
        """`security`: the text comes from a security sender, so every code-shaped token goes (strict).
        `auth`: it belongs to an item about signing in, so links with a token go too (strict)."""
        if self.codes == "off":
            return text
        strict = self.codes == "strict"
        if ANY_CODE_WORD.search(text):
            text = (CODE_RE if strict else CODE_SAME_LINE_RE).sub(_keyword_code, text)
            if strict:
                text = ALNUM_CODE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[code redacted]", text)
                text = CODE_FIRST_RE.sub("[code redacted]", text)
                text = USE_CODE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[code redacted]", text)
        text = RECOVERY_URL_RE.sub("[link redacted]", text)
        if not strict:
            return text
        if security or auth or AUTH_CONTEXT_RE.search(text):
            text = URL_RE.sub(lambda m: "[link redacted]" if _opaque_link(m.group(0)) else m.group(0), text)
        if security:
            text = SENDER_CODE_RE.sub("[code redacted]", text)
        return text

    def value(self, data: Any, security: bool = False, auth: bool = False) -> Any:
        """Redacts every string in `data` but identifiers the agent passes back (ids, refs, paths). An item (a
        dict) from a security sender, or one whose text is about signing in, passes that on to all its
        strings: the code in a subject, the link in a preview."""
        if isinstance(data, str):
            return self.text(data, security, auth)
        if isinstance(data, list):
            return [self.value(item, security, auth) for item in data]
        if isinstance(data, dict) and self.codes != "strict":
            return {key: item if _identifier(key) else self.value(item) for key, item in data.items()}
        if isinstance(data, dict):
            security = security or self._from_security_sender(data)
            auth = auth or any(isinstance(v, str) and AUTH_CONTEXT_RE.search(v) for v in data.values())
            return {key: item if _identifier(key) else self.value(item, security, auth)
                    for key, item in data.items()}
        return data


def _identifier(key) -> bool:
    key = str(key)
    return key in ID_KEYS or key.endswith(("_id", "_ref", "_path"))
