"""Pseudonyms for sensitive content: what agents (and so the model provider) get instead of doctor's
appointments and the like.

Rules are word lists with a label ("Gesundheit"). Two ways a rule hits:

- **Item:** a word in an item's header (title, subject, name, location, sender) hides the whole item.
  Every text field becomes a placeholder like `[Gesundheit PSN-3F2A9C1B]`; ids, times, folders and flags
  stay, so the agent still sees that 11:15-11:30 is taken and can move the event.
- **Sentence:** a word in free text (a mail body, a description) of an item that wasn't hidden replaces
  just that sentence.

`where: headers` limits a rule to the first kind (e.g. "Dr.", which also stands in academics' mail
signatures), `plugins:` to some plugin types. Placeholders are stable: the same text always gets the same
token, keyed with a secret of this doorman, so agents can refer to "[Gesundheit PSN-…]" across reads.

On the way back: a reversible write may carry placeholders (moving a hidden event, or keeping its
title); they turn back into the original text before the plugin runs. A send may not carry one, so an
agent can't mail the hidden text to someone by quoting the placeholder. The owner app always shows the
real text; only the agent API sees placeholders.

Text put back that way stays hidden wherever it turns up again: a calendar's "Dr. Müller" written into a
mail draft's subject or a kept file isn't caught by that plugin's rules ("Dr." counts in calendars only),
so every original a write restored is remembered (table pseudonyms_restored) and replaced by its
placeholder in everything an agent gets, whatever the plugin.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
from dataclasses import dataclass, field
from typing import Any

from . import clock

TOKEN_RE = re.compile(r"\[[^\[\]\n]{0,40}?(PSN-[0-9A-F]{8})\]|(PSN-[0-9A-F]{8})")
HEADER_KEYS = {"summary", "subject", "title", "name", "topic", "location", "from", "sender", "organizer"}
# structure the agent needs to work with a hidden item; never pseudonymized
KEEP_KEYS = {"id", "ref", "uid", "message_id", "chat_id", "team_id", "channel_id", "calendar", "book", "folder",
             "flags", "unread", "start", "end", "date", "sent", "created", "updated", "modified", "due", "all_day",
             "status", "recurring", "recurring_id", "etag", "kind", "type", "size", "timezone", "time_zone",
             "access", "shared", "primary", "read_only", "completed", "priority", "link", "entry_id",
             "approval_id", "index", "tier", "decision", "list", "ts", "tool", "plugin", "source", "day"}
CALENDARS = ["google_calendar", "caldav", "ics"]
RESTORED_MIN_CHARS = 3   # a restored original shorter than this ("Mo") isn't looked for in other text

# Whole words, case-insensitive; *x* matches inside words (Zahnarzttermin), x* at a word start.
HEALTH_WORDS = [
    # German
    "*arzt*", "*ärzt*", "*klinik*", "Krankenhaus*", "Notaufnahme", "*therapie*", "*therapeut*", "Physio*",
    "Psychiater*", "Psychologin", "Psychologe", "Krankschreibung", "Arbeitsunfähigkeit*", "Impfung", "Impftermin",
    "Blutabnahme", "Befund*", "Diagnose", "MRT", "Röntgen*", "Apotheke*", "Orthopäd*", "Gynäkolog*",
    "Dermatolog*", "Kardiolog*", "Neurolog*", "Urolog*", "Radiolog*", "Zahnreinigung", "Vorsorgeuntersuchung",
    # English
    "doctor", "doctor's", "dentist*", "physician*", "*therapist*", "therapy", "hospital*", "clinic",
    "pharmacy", "prescription*", "psychiatrist*", "vaccination", "medical appointment",
    # Dutch
    "huisarts*", "tandarts*", "ziekenhuis*", "fysio*", "dokter*", "apotheek*", "psycholoog", "therapeut*",
]
DEFAULT_RULES = [
    {"label": "Gesundheit", "words": HEALTH_WORDS, "where": "all"},
    # "Dr." in calendar titles means an appointment; in mail it's mostly a signature, so not there
    {"label": "Gesundheit", "words": ["Dr.", "Dr. med.", "Dr. med. dent."], "where": "headers",
     "plugins": CALENDARS},
]


def _word_pattern(word: str) -> str:
    inner = r"\s+".join(re.escape(part) for part in word.strip("*").split())
    start = "" if word.startswith("*") else r"(?<!\w)"
    end = "" if word.endswith("*") or word.endswith(".") else r"(?!\w)"
    return f"{start}{inner}{end}"


@dataclass
class Rule:
    label: str
    words: list[str]
    where: str = "all"                   # all | headers
    plugins: list[str] | None = None     # plugin types; None = every plugin
    pattern: re.Pattern = field(init=False)

    def __post_init__(self):
        self.pattern = re.compile("|".join(_word_pattern(w) for w in self.words if w.strip("* ")), re.I)

    def applies(self, plugin_type: str | None, header: bool) -> bool:
        if self.where == "headers" and not header:
            return False
        return self.plugins is None or plugin_type in self.plugins


class Pseudonymizer:
    def __init__(self, config: dict, db):
        self.db = db
        self.config = config.get("pseudonymize") or {}
        self._secret: bytes | None = None
        self._known: set[str] = set()      # tokens already stored
        self._pending: list[tuple] = []    # new ones, written in one transaction per hide()/text()
        self._lock = threading.Lock()      # the agent API hides from several threads
        # text a write put back: (one pattern for all of it, original -> placeholder), swapped as a whole
        self._restored: tuple[re.Pattern | None, dict[str, str]] = (None, {})
        self.reload()
        self._load_restored()

    # ------------------------------------------------------------------ settings

    def reload(self) -> None:
        """doorman.yaml gives the base; the owner app can switch it off and add words (settings table)."""
        stored = self.db.get_setting("pseudonymize_enabled")
        self.enabled = (stored == "1") if stored is not None else bool(self.config.get("enabled", True))
        base = self.config.get("rules")
        rules = [Rule(**r) for r in (DEFAULT_RULES if base is None else base)]
        extra = [w.strip() for w in (self.db.get_setting("pseudonymize_words") or "").split("\n") if w.strip()]
        if extra:
            rules.append(Rule(label="Privat", words=extra, where="all"))
        self.rules = [r for r in rules if r.words]
        self.extra_words = extra

    def settings(self) -> dict:
        return {"enabled": self.enabled, "extra_words": self.extra_words,
                "rules": [{"label": r.label, "words": r.words, "where": r.where, "plugins": r.plugins}
                          for r in self.rules if not (r.label == "Privat" and r.words == self.extra_words)]}

    def save(self, enabled: bool, extra_words: list[str]) -> None:
        self.db.set_setting("pseudonymize_enabled", "1" if enabled else "0")
        self.db.set_setting("pseudonymize_words", "\n".join(w.strip() for w in extra_words if w.strip()))
        self.reload()

    # ------------------------------------------------------------------ tokens

    @property
    def secret(self) -> bytes:
        if self._secret is None:
            value = self.db.get_setting("pseudonym_secret")
            if not value:
                value = secrets.token_hex(32)
                self.db.set_setting("pseudonym_secret", value)
            self._secret = bytes.fromhex(value)
        return self._secret

    def token(self, label: str, original: str) -> str:
        token = "PSN-" + hmac.new(self.secret, original.encode(), hashlib.sha256).hexdigest()[:8].upper()
        with self._lock:
            if token not in self._known:
                self._pending.append((token, original, label, clock.iso()))
                self._known.add(token)
        return f"[{label} {token}]"

    def _flush(self) -> None:
        with self._lock:
            pending, self._pending = self._pending, []
        if pending:
            with self.db.tx() as conn:
                conn.executemany("INSERT OR IGNORE INTO pseudonyms(token, original, label, created) VALUES(?,?,?,?)",
                                 pending)

    # ------------------------------------------------------------------ hiding

    def _hit(self, text: str, plugin_type: str | None, header: bool) -> Rule | None:
        for rule in self.rules:
            if rule.applies(plugin_type, header) and rule.pattern.search(text):
                return rule
        return None

    def _header_hit(self, item: dict, plugin_type: str | None) -> Rule | None:
        for key in HEADER_KEYS & item.keys():
            values = item[key] if isinstance(item[key], list) else [item[key]]
            for value in values:
                if isinstance(value, str):
                    rule = self._hit(value, plugin_type, header=True)
                    if rule:
                        return rule
        return None

    def _mask_all(self, value: Any, label: str, key: str | None = None) -> Any:
        if key in KEEP_KEYS:
            return value
        if isinstance(value, str):
            return self.token(label, value) if value.strip() else value
        if isinstance(value, list):
            return [self._mask_all(v, label) for v in value]
        if isinstance(value, dict):
            return {k: self._mask_all(v, label, k) for k, v in value.items()}
        return value

    def text(self, text: str, plugin_type: str | None = None) -> str:
        """Free text: every sentence with a sensitive word becomes a placeholder."""
        out = self._text(text, plugin_type)
        self._flush()
        return out

    def _text(self, text: str, plugin_type: str | None = None) -> str:
        if not self.enabled or not text:
            return text
        text = self._mask_restored(text)
        out, last = [], 0
        for sentence in re.finditer(r"[^.!?\n]+[.!?]*", text):
            rule = self._hit(sentence.group(0), plugin_type, header=False)
            if rule:
                lead = len(sentence.group(0)) - len(sentence.group(0).lstrip())
                out.append(text[last:sentence.start() + lead])
                out.append(self.token(rule.label, sentence.group(0).strip()))
                last = sentence.end()
        return "".join(out) + text[last:] if out else text

    def summary(self, text: str, states: list[Any], plugin_type: str | None = None) -> str:
        """A journal summary ("Moved “Zahnarzt” to 17:00") as an agent may see it: the private values of the
        object it is about (its title, place) become their placeholders, the rest stays readable. A sensitive
        word left after that hides its sentence, as in any free text."""
        if not self.enabled or not text:
            return text
        for state in states:
            if not isinstance(state, dict):
                continue
            rule = self._header_hit(state, plugin_type)
            if rule is None:
                continue
            values = [v for k in HEADER_KEYS & state.keys()
                      for v in (state[k] if isinstance(state[k], list) else [state[k]])]
            for value in sorted({v.strip() for v in values if isinstance(v, str) and v.strip()}, key=len,
                                reverse=True):
                if value in text:
                    text = text.replace(value, self.token(rule.label, value))
        return self.text(text, plugin_type)

    def _hide(self, value: Any, plugin_type: str | None, key: str | None = None) -> tuple[Any, bool]:
        if key in KEEP_KEYS:
            return value, False
        if isinstance(value, dict):
            rule = self._header_hit(value, plugin_type)
            if rule:
                return self._mask_all(value, rule.label), True
            out, hidden = {}, False
            for k, v in value.items():
                out[k], h = self._hide(v, plugin_type, k)
                hidden = hidden or h
            return out, hidden
        if isinstance(value, list):
            pairs = [self._hide(v, plugin_type) for v in value]
            return [v for v, _ in pairs], any(h for _, h in pairs)
        if isinstance(value, str):
            hidden = self._text(value, plugin_type)
            return hidden, hidden != value
        return value, False

    def hidden_word(self, text: str, plugin_types: Any) -> bool:
        """Whether a rule would hide `text` (a word to search for, a sender to filter by) in an item of any of
        these plugin types: search leaves it out, so a hidden word can't be found."""
        if not self.enabled or not isinstance(text, str) or not text.strip():
            return False
        return any(self._hit(text, t, header=True) for t in plugin_types)

    def hides_item(self, item: Any, plugin_type: str | None = None) -> bool:
        """Whether a header rule (title, subject, name, sender...) hides this item whole."""
        return self.enabled and isinstance(item, dict) and self._header_hit(item, plugin_type) is not None

    def hide(self, data: Any, plugin_type: str | None = None) -> tuple[Any, list[int]]:
        """What an agent may see of `data`, and which top-level items (list indices) were changed."""
        if not self.enabled:
            return data, []
        try:
            if isinstance(data, list):
                pairs = [self._hide(v, plugin_type) for v in data]
                return [v for v, _ in pairs], [i for i, (_, h) in enumerate(pairs) if h]
            value, hidden = self._hide(data, plugin_type)
            return value, [0] if hidden else []
        finally:
            self._flush()

    # ------------------------------------------------------------------ restoring

    def tokens_in(self, value: Any) -> list[str]:
        if isinstance(value, str):
            return [m.group(1) or m.group(2) for m in TOKEN_RE.finditer(value)]
        if isinstance(value, list):
            return [t for v in value for t in self.tokens_in(v)]
        if isinstance(value, dict):
            return [t for v in value.values() for t in self.tokens_in(v)]
        return []

    def restore(self, value: Any, remember: bool = False) -> Any:
        """Placeholders back to the original text: for the owner's eyes, and for reversible writes. A write
        passes `remember`: the originals it puts back stay hidden from agents wherever they turn up again
        (_mask_restored), since the plugin written to may have no rule that would hide them."""
        put_back: dict[str, tuple[str, str]] = {}
        out = self._restore(value, put_back)
        if remember and put_back:
            self._remember(put_back)
        return out

    def _restore(self, value: Any, put_back: dict) -> Any:
        if isinstance(value, str):
            def back(m: re.Match) -> str:
                token = m.group(1) or m.group(2)
                row = self.db.one("SELECT original, label FROM pseudonyms WHERE token=?", (token,))
                if not row:
                    return m.group(0)
                put_back[token] = (row["original"], row["label"])
                return row["original"]
            return TOKEN_RE.sub(back, value)
        if isinstance(value, list):
            return [self._restore(v, put_back) for v in value]
        if isinstance(value, dict):
            return {k: self._restore(v, put_back) for k, v in value.items()}
        return value

    # ------------------------------------------------------------------ text a write put back

    def _remember(self, put_back: dict[str, tuple[str, str]]) -> None:
        new = {token: v for token, v in put_back.items() if v[0] not in self._restored[1]}
        if not new:
            return
        with self.db.tx() as conn:
            conn.executemany("INSERT OR IGNORE INTO pseudonyms_restored(token, created) VALUES(?,?)",
                             [(token, clock.iso()) for token in new])
        with self._lock:
            mapping = {**self._restored[1], **{original: f"[{label} {token}]"
                                              for token, (original, label) in new.items()}}
            self._restored = (self._pattern(mapping), mapping)

    def _load_restored(self) -> None:
        rows = self.db.all("SELECT p.token, p.original, p.label FROM pseudonyms_restored r "
                           "JOIN pseudonyms p ON p.token = r.token")
        mapping = {r["original"]: f"[{r['label']} {r['token']}]" for r in rows}
        with self._lock:
            self._restored = (self._pattern(mapping), mapping)

    @staticmethod
    def _pattern(restored: dict[str, str]) -> re.Pattern | None:
        """One pattern for every restored original, longest first; a whole word where it starts or ends with
        one, so "Praxis" doesn't hide part of "Praxistest"."""
        parts = []
        for original in sorted((o for o in restored if len(o.strip()) >= RESTORED_MIN_CHARS), key=len, reverse=True):
            start = r"(?<!\w)" if re.match(r"\w", original) else ""
            end = r"(?!\w)" if re.search(r"\w$", original) else ""
            parts.append(f"{start}{re.escape(original)}{end}")
        return re.compile("|".join(parts)) if parts else None

    def _mask_restored(self, text: str) -> str:
        pattern, mapping = self._restored
        if pattern is None or not text:
            return text
        return pattern.sub(lambda m: mapping.get(m.group(0), m.group(0)), text)
