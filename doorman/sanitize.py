"""Cleaning third-party text in code, before any model sees it: the cheap first layer under the guard.

- HTML becomes text without what a reader can't see: comments, <script>/<style>/<head>, and elements
  hidden by inline style or a simple <style> rule (display:none, visibility:hidden, opacity:0, font-size
  of a pixel or less, text in the background's colour, zero-size boxes with overflow hidden, text pushed
  off-screen, mso-hide:all), or by the `hidden` attribute.
- Unicode tricks go: zero-width characters, bidi overrides and isolates, variation selectors, and the
  "tag" characters (U+E0000-E007F) that spell out invisible ASCII. A run of tag characters becomes
  "[hidden text removed]" so the owner and the agent see that something was there. Then NFKC folds
  look-alike forms (full-width letters, ligatures, mathematical letters) into plain ones.
- Office documents lose what Word or LibreOffice don't show: hidden runs, deleted tracked changes, field
  codes, tiny or white text, and comments (extract.py). Document properties and PDF annotations are never
  read in the first place.
- A PDF whose text layer is much longer than what OCR reads off the rendered page has text nobody can see
  (white, tiny, behind something, off the page). That can't be cut out, so it is flagged (pdf_mismatch),
  and the guard holds the attachment back for the owner.

Identifiers (id, ref, path, url, ...) are left exactly as they are: the agent passes them back, and a
"cleaned" Message-ID or an NFC-composed file name wouldn't be found again.
"""

from __future__ import annotations

import re
import unicodedata
from html.parser import HTMLParser
from typing import Any

HIDDEN_MARK = "[hidden text removed]"

# keys whose values the agent hands back to Doorman, so they must stay byte for byte
ID_KEYS = {"id", "ref", "refs", "path", "uid", "url", "href", "link", "etag", "message_id", "thread_id",
           "folder", "mailbox", "calendar", "part", "sha256", "upload", "web_url", "webUrl"}

_TAGS = re.compile("[\U000E0000-\U000E007F]+")
# zero-width and joiners, bidi marks/embeddings/overrides/isolates, invisible operators, BOM, soft hyphen,
# Mongolian vowel separator and free variation selectors, Hangul fillers, interlinear annotation, musical
# formatting, variation selectors (both blocks), the rest of the tag plane
_INVISIBLE = re.compile(
    "[­͏؜ᅟᅠ឴឵᠋-᠏​-‏‪-‮⁠-⁯"
    "ㅤ︀-️﻿ﾠ￹-￻\U0001d173-\U0001d17a\U000e0080-\U000e0fff]")


def clean_text(text: str) -> tuple[str, dict]:
    """(clean text, {invisible: n, tag_text: decoded ASCII smuggled in tag characters})."""
    report: dict[str, Any] = {}
    smuggled = []

    def tags(match: re.Match) -> str:
        smuggled.append("".join(chr(ord(c) - 0xE0000) for c in match.group(0) if 0xE0020 <= ord(c) <= 0xE007E))
        return HIDDEN_MARK
    text = _TAGS.sub(tags, text)
    text, n = _INVISIBLE.subn("", text)
    if n:
        report["invisible"] = n
    if smuggled:
        report["tag_text"] = " / ".join(s for s in smuggled if s)[:2000]
    return unicodedata.normalize("NFKC", text), report


def _is_id_key(key: str) -> bool:
    return key in ID_KEYS or key.endswith(("_id", "_ref", "_url", "_path"))


def clean_value(data: Any) -> tuple[Any, dict]:
    """clean_text on every string in a JSON-like value, except identifiers. The report adds up."""
    total: dict[str, Any] = {}

    def add(report: dict) -> None:
        if report.get("invisible"):
            total["invisible"] = total.get("invisible", 0) + report["invisible"]
        if report.get("tag_text"):
            total["tag_text"] = ((total.get("tag_text", "") + " / ") if total.get("tag_text") else "") + \
                report["tag_text"]

    def walk(value: Any, key: str | None) -> Any:
        if isinstance(value, str):
            if key is not None and _is_id_key(key):
                return value
            text, report = clean_text(value)
            add(report)
            return text
        if isinstance(value, dict):
            return {k: walk(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v, key) for v in value]
        return value

    return walk(data, None), total


# ---------------------------------------------------------------------- HTML

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track",
        "wbr", "basefont", "frame", "keygen"}
DROP = {"script", "style", "head", "title", "template", "noscript", "object", "iframe", "frameset", "noframes",
        "canvas", "audio", "video"}
BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote", "pre", "ul",
         "ol", "dl", "dt", "dd", "section", "article", "header", "footer", "hr", "address", "center", "form",
         "fieldset", "figure", "figcaption", "caption", "tbody", "thead", "tfoot", "main", "nav", "aside"}
CELL = {"td", "th"}

NAMED_COLORS = {
    "white": (255, 255, 255), "black": (0, 0, 0), "red": (255, 0, 0), "green": (0, 128, 0), "blue": (0, 0, 255),
    "yellow": (255, 255, 0), "gray": (128, 128, 128), "grey": (128, 128, 128), "silver": (192, 192, 192),
    "whitesmoke": (245, 245, 245), "snow": (255, 250, 250), "ivory": (255, 255, 240), "ghostwhite": (248, 248, 255),
    "floralwhite": (255, 250, 240), "linen": (250, 240, 230), "seashell": (255, 245, 238),
    "aliceblue": (240, 248, 255), "azure": (240, 255, 255), "mintcream": (245, 255, 250),
    "lightgray": (211, 211, 211), "lightgrey": (211, 211, 211), "gainsboro": (220, 220, 220),
    "navy": (0, 0, 128), "maroon": (128, 0, 0), "purple": (128, 0, 128), "teal": (0, 128, 128),
    "olive": (128, 128, 0), "lime": (0, 255, 0), "aqua": (0, 255, 255), "cyan": (0, 255, 255),
    "fuchsia": (255, 0, 255), "magenta": (255, 0, 255), "orange": (255, 165, 0),
}
TRANSPARENT = "transparent"


def parse_color(value: str | None) -> tuple[int, int, int] | str | None:
    """(r, g, b), "transparent", or None when it can't be read."""
    if not value:
        return None
    value = value.strip().lower().replace("!important", "").strip()
    if value in ("transparent",):
        return TRANSPARENT
    if value in NAMED_COLORS:
        return NAMED_COLORS[value]
    match = re.fullmatch(r"#?([0-9a-f]{3,8})", value)
    if match and len(match.group(1)) in (3, 4, 6, 8):
        h = match.group(1)
        if len(h) in (3, 4):
            h = "".join(c * 2 for c in h)
        if len(h) == 8 and int(h[6:8], 16) < 26:
            return TRANSPARENT
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    match = re.fullmatch(r"rgba?\(\s*([\d.]+)%?[\s,]+([\d.]+)%?[\s,]+([\d.]+)%?(?:[\s,/]+([\d.]+%?))?\s*\)", value)
    if match:
        alpha = match.group(4)
        if alpha is not None:
            a = float(alpha.rstrip("%")) / (100 if alpha.endswith("%") else 1)
            if a < 0.1:
                return TRANSPARENT
        return tuple(min(255, int(float(match.group(i)))) for i in (1, 2, 3))  # type: ignore[return-value]
    return None


def _close(a: tuple[int, int, int], b: tuple[int, int, int]) -> bool:
    return sum(abs(x - y) for x, y in zip(a, b)) < 40


def _style(text: str | None) -> dict[str, str]:
    out = {}
    for decl in (text or "").split(";"):
        name, sep, value = decl.partition(":")
        if sep:
            out[name.strip().lower()] = value.strip().lower()
    return out


def _length(value: str | None) -> float | None:
    """A CSS length in px (roughly), or None."""
    if value is None:
        return None
    match = re.match(r"\s*(-?[\d.]+)\s*(px|pt|em|rem|%|)?", value.replace("!important", ""))
    if not match:
        return None
    number = float(match.group(1))
    unit = match.group(2) or "px"
    return number * {"px": 1, "pt": 1.33, "em": 16, "rem": 16, "%": 0.16}[unit]


def hides(style: dict[str, str]) -> str | None:
    """Why an element with this style is invisible, or None."""
    if style.get("display", "").startswith("none"):
        return "display:none"
    if style.get("visibility", "").split(" ")[0] in ("hidden", "collapse"):
        return "visibility:hidden"
    if style.get("mso-hide", "").startswith("all"):
        return "mso-hide:all"
    opacity = _length(style.get("opacity"))
    if opacity is not None and "%" not in style.get("opacity", "") and opacity < 0.1:
        return "opacity:0"
    size = _length(style.get("font-size"))
    if size is not None and size <= 1:
        return "font-size:0"
    overflow = style.get("overflow", "") + style.get("overflow-x", "") + style.get("overflow-y", "")
    if "hidden" in overflow or "clip" in overflow:
        for dim in ("height", "max-height", "width", "max-width", "line-height"):
            value = _length(style.get(dim))
            if value is not None and value <= 1:
                return f"{dim}:0"
    for side in ("left", "top", "right", "margin-left", "margin-top", "text-indent"):
        value = _length(style.get(side))
        if value is not None and value <= -500:
            return "off-screen"
    clip = style.get("clip", "") + style.get("clip-path", "")
    if re.search(r"rect\(\s*0(px)?[\s,]+0(px)?[\s,]+0(px)?[\s,]+0(px)?\s*\)|inset\(\s*(50|100)%", clip):
        return "clipped"
    return None


def _style_rules(css: str) -> dict[str, dict[str, str]]:
    """Simple selectors from <style> blocks (.class, #id, tag, tag.class), each with its declarations."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    css = re.sub(r"@media[^{]*\{((?:[^{}]*\{[^{}]*\})*)\s*\}", r"\1", css)  # rules inside @media apply too
    rules: dict[str, dict[str, str]] = {}
    for selectors, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        declarations = _style(body)
        for selector in selectors.split(","):
            selector = selector.strip().lower()
            if re.fullmatch(r"[a-z0-9]*([.#][\w-]+)?", selector) and selector:
                rules.setdefault(selector, {}).update(declarations)
    return rules


class _Text(HTMLParser):
    def __init__(self, rules: dict[str, dict[str, str]]):
        super().__init__(convert_charrefs=True)
        self.rules = rules
        self.out: list[str] = []
        # per open element: (tag, hidden, colour, background)
        self.stack: list[tuple[str, bool, Any, Any]] = []
        self.report: dict[str, int] = {}

    def _count(self, why: str) -> None:
        self.report[why] = self.report.get(why, 0) + 1

    def _newline(self) -> None:
        while self.out and not self.out[-1].strip(" \t"):  # spaces at a line's end, or an empty chunk
            self.out.pop()
        if self.out and not self.out[-1].endswith("\n"):
            self.out.append("\n")

    def _hidden(self) -> bool:
        return bool(self.stack) and self.stack[-1][1]

    def handle_comment(self, data: str) -> None:
        if data.strip():
            self._count("comment")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag == "body":  # a <head> nobody closed must not swallow the message
            heads = [i for i, entry in enumerate(self.stack) if entry[0] == "head"]
            if heads:
                del self.stack[heads[0]:]
        parent_hidden = self._hidden()
        color = self.stack[-1][2] if self.stack else (0, 0, 0)
        background = self.stack[-1][3] if self.stack else (255, 255, 255)
        style: dict[str, str] = {}
        for selector in [tag] + [f".{c}" for c in attr.get("class", "").lower().split()] + \
                [f"{tag}.{c}" for c in attr.get("class", "").lower().split()] + \
                ([f"#{attr['id'].lower()}"] if attr.get("id") else []):
            style.update(self.rules.get(selector, {}))
        style.update(_style(attr.get("style")))
        if attr.get("color"):
            style.setdefault("color", attr["color"])
        if attr.get("bgcolor"):
            style.setdefault("background-color", attr["bgcolor"])
        own_color = parse_color(style.get("color"))
        own_background = parse_color(style.get("background-color") or
                                     (style.get("background", "").split() or [None])[0])
        if own_color is not None:
            color = own_color
        if own_background not in (None, TRANSPARENT):
            background = own_background
        elif "url(" in style.get("background", "") + style.get("background-image", "") or attr.get("background"):
            background = None  # an image behind the text: its colour is unknown, so is the contrast
        hidden = parent_hidden
        if not hidden:
            why = "hidden attribute" if "hidden" in attr else ("dropped" if tag in DROP else hides(style))
            if why:
                hidden = True
                if why != "dropped":
                    self._count(why)
        if tag == "br" and not hidden:
            self.out.append("\n")
        elif tag in BLOCK and not hidden:
            self._newline()
        if tag in CELL and not hidden:
            self.out.append("\t")
        if tag in VOID:
            return
        self.stack.append((tag, hidden, color, background))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag in VOID:
            return
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                hidden = self.stack[i][1]
                del self.stack[i:]
                if tag in BLOCK and not hidden:
                    self._newline()
                return

    def handle_data(self, data: str) -> None:
        hidden = self._hidden()
        if not hidden and data.strip() and self.stack:
            # colours are judged where the text is: a dark table can hold light text
            _, _, color, background = self.stack[-1]
            if color == TRANSPARENT:
                hidden = True
                self._count("transparent text")
            elif isinstance(color, tuple) and isinstance(background, tuple) and _close(color, background):
                hidden = True
                self._count("text in background colour")
        if hidden:
            if data.strip():
                self.report["hidden_chars"] = self.report.get("hidden_chars", 0) + len(data.strip())
            return
        if not any(entry[0] in ("pre", "textarea") for entry in self.stack):
            data = re.sub(r"[ \t\r\n\f]+", " ", data)  # as a browser shows it: line breaks come from tags
        self.out.append(data)


def html_to_text(markup: str) -> tuple[str, dict]:
    """The text a person sees in this HTML, and what was left out: {why: count, hidden_chars: n}."""
    css = "\n".join(re.findall(r"(?is)<style[^>]*>(.*?)</style>", markup))
    parser = _Text(_style_rules(css))
    try:
        parser.feed(markup)
        parser.close()
    except Exception:  # noqa: BLE001 - html.parser rarely gives up; fall back to dropping every tag
        text = re.sub(r"<[^>]+>", " ", re.sub(r"(?is)<!--.*?-->|<(script|style|head)\b.*?</\1>", "", markup))
        return _tidy(text), {"unparsed": 1}
    return _tidy("".join(parser.out)), parser.report


def _tidy(text: str) -> str:
    text = text.replace("\xa0", " ")
    text = re.sub(r"[ \t\r\f\v]+", lambda m: "\t" if "\t" in m.group(0) else " ", text)
    text = re.sub(r"[ \t]*\n[ \t]*", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def describe(report: dict) -> str | None:
    """A short line for the agent about what was taken out, or None."""
    hidden = {k: v for k, v in report.items() if k not in ("hidden_chars", "invisible", "tag_text", "unparsed")}
    parts = []
    if hidden:
        parts.append(f"{sum(hidden.values())} hidden part{'s' if sum(hidden.values()) != 1 else ''} of the HTML "
                     f"({', '.join(sorted(hidden))})")
    if report.get("invisible"):
        parts.append(f"{report['invisible']} invisible characters")
    if report.get("tag_text"):
        parts.append("text hidden in Unicode tag characters")
    return ("removed before you got it: " + "; ".join(parts)) if parts else None


# ---------------------------------------------------------------------- PDF: what you see vs what's extracted

def pdf_mismatch(extracted: str, seen: str, ratio: float = 1.6, slack: int = 200) -> bool:
    """True when the text layer holds clearly more than OCR can read off the rendered page."""
    count = lambda s: len(re.findall(r"\w", s))  # noqa: E731
    return count(extracted) > ratio * count(seen) + slack
