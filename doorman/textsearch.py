"""Search over archived text (the mail archive, the file archive): stems, close spellings, merging ranked
lists, snippets, and vectors for semantic search.

- **Stems** (Snowball): each message is stemmed in its own language (German, Dutch or English, guessed from
  common words), so "Rechnungen" finds "Rechnung" and "betalingen" finds "betaling". A query word is
  stemmed in all three languages and any of them may match.
- **Close spellings** (rapidfuzz): words in the index one or two letters from a query word, for typos in
  the query and OCR misreads in the mail ("Rechnurg").
- **Reciprocal rank fusion** merges the ranked lists (exact words, stems, close spellings, parts of words,
  meaning) into one order without comparing their scores.
"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from typing import Callable

LANGUAGES = ("german", "dutch", "english")
STOPWORDS = {
    "german": set("der die das und ist nicht mit für auf ich sie es ein eine zu den von wir ihr bitte dass auch "
                  "im dem wird sind haben noch nach bei aus oder wie sehr vielen dank gerne grüße".split()),
    "dutch": set("de het een en is niet met voor op ik zij je van wij jullie u dat ook zijn naar bij om aan "
                 "wordt hebben nog uit dan maar graag groet groeten bedankt vriendelijke".split()),
    "english": set("the and is not with for on i you it a to of we your please that also be are this have will "
                   "from at by or as thanks regards best kind dear".split()),
}
WORD = re.compile(r"\w+", re.UNICODE)
RRF_K = 60


def language(words: list[str]) -> str:
    """German, Dutch or English, from how many of each one's common words appear (German when unsure)."""
    counts = {lang: 0 for lang in LANGUAGES}
    for word in words[:600]:
        for lang in LANGUAGES:
            if word in STOPWORDS[lang]:
                counts[lang] += 1
    best = max(LANGUAGES, key=lambda lang: (counts[lang], lang == "german"))
    return best if counts[best] else "german"


@lru_cache(maxsize=4)
def _stemmer(lang: str):
    import snowballstemmer

    return snowballstemmer.stemmer(lang)


@lru_cache(maxsize=200_000)
def stem(word: str, lang: str) -> str:
    return _stemmer(lang).stemWord(word)


def stemmed_text(text: str) -> str:
    """The text as stems, in its own language: what the stems index holds."""
    words = WORD.findall((text or "").lower())
    if not words:
        return ""
    lang = language(words)
    return " ".join(stem(w, lang) if not w.isdigit() else w for w in words)


def query_stems(term: str) -> list[str]:
    """A query word's stems in every language, most likely first, without duplicates."""
    word = term.lower()
    out = []
    for lang in LANGUAGES:
        s = stem(word, lang)
        if s and s not in out:
            out.append(s)
    return out


def close_spellings(term: str, vocabulary: list[tuple[str, int]], limit: int = 3) -> list[str]:
    """Words of the index (term, how many messages have it) one letter from `term` (two from 8 letters on),
    the most common first."""
    from rapidfuzz.distance import Levenshtein
    from rapidfuzz import process

    word = term.lower()
    if len(word) < 4:
        return []
    allowed = 1 if len(word) <= 7 else 2
    pool = [(t, n) for t, n in vocabulary if t != word and abs(len(t) - len(word)) <= allowed]
    if not pool:
        return []
    found = process.extract(word, [t for t, _ in pool], scorer=Levenshtein.distance, score_cutoff=allowed,
                            limit=50)
    ranked = sorted(found, key=lambda hit: (hit[1], -pool[hit[2]][1]))
    return [hit[0] for hit in ranked[:limit]]


def fuse(lists: list[tuple[list[int], float]], k: int = RRF_K) -> list[int]:
    """Reciprocal rank fusion: (ranked ids, weight) lists into one order. An id ranked high in several lists
    comes first."""
    scores: dict[int, float] = {}
    for ids, weight in lists:
        for rank, item in enumerate(ids):
            scores[item] = scores.get(item, 0.0) + weight / (k + rank + 1)
    return sorted(scores, key=lambda item: -scores[item])


# ------------------------------------------------------------------ queries and snippets


@lru_cache(maxsize=4096)
def _fold_char(ch: str) -> str:
    base = unicodedata.normalize("NFKD", ch)
    base = "".join(c for c in base if not unicodedata.combining(c)) or ch
    return base[0].lower() if len(base[0].lower()) == 1 else ch


# Latin script (with its accents) folded by str.translate, in C; other characters one at a time
_FOLD_TABLE = {i: _fold_char(chr(i)) for i in range(0x250) if _fold_char(chr(i)) != chr(i)}


def fold(text: str) -> str:
    """Lowercase without accents, one character for one character, so a position in the folded text is the
    same position in the original."""
    out = text.translate(_FOLD_TABLE)
    if not out or out.isascii() or max(out) < "ɐ":
        return out
    return "".join(c if c < "ɐ" else _fold_char(c) for c in out)


MAX_TERMS = 12           # words and phrases of one query that are searched; the rest are left out (a note says so)
MAX_CLOSE_TERMS = 4      # of those, how many get close spellings looked up (a scan of the index's words each)


def terms_of(query: str) -> list[tuple[str, bool]]:
    """(term, prefix) pairs: words and "quoted phrases"; a trailing * makes a prefix search. The same word
    twice counts once."""
    out = []
    for phrase, word in re.findall(r'"([^"]+)"|(\S+)', query):
        text = (phrase or word).replace('"', "").strip()
        prefix = bool(word) and text.endswith("*")
        text = text.rstrip("*").strip()
        if text and re.search(r"\w", text) and (text, prefix) not in out:
            out.append((text, prefix))
    return out


def snippet(text: str, terms: list[str], before: int = 80, after: int = 160) -> str | None:
    """The text around the first of the terms (accents and case ignored), or None if none occurs."""
    low = fold(text or "")
    found = [h for h in (low.find(fold(t)) for t in terms if t) if h >= 0]
    if not found:
        return None
    at = min(found)
    start, end = max(0, at - before), min(len(text), at + after)
    return ("…" if start else "") + re.sub(r"\s+", " ", text[start:end]).strip() + ("…" if end < len(text) else "")


def opening(text: str, length: int = 200) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text[:length] + ("…" if len(text) > length else "")


def _quote(term: str) -> str:
    return '"' + term.replace('"', "") + '"'


def rank(terms: list[tuple[str, bool]], limit: int, words: Callable[[str], list], stems: Callable[[str], list],
         vocabulary: Callable[[str], list[tuple[str, int]]], grams: Callable[[str], list] | None = None,
         meaning: Callable[[], list[tuple]] | None = None, allow: Callable[[str], bool] | None = None) -> dict:
    """One ranked search over several indexes; {order, terms (to show snippets for), close, meaning, near}.

    words(match) and stems(match) run an FTS5 MATCH on the whole-word and the stems index and return ids,
    best first; grams(match) on a trigram index (parts of words); vocabulary(first letter) lists the
    whole-word index's terms with how many documents have them; meaning() returns [(id, part, similarity)],
    best first, already filtered. Exact words and stems always run; parts of words and close spellings only
    when those find fewer than `limit`; meaning when given. Reciprocal rank fusion merges them. `close` says
    which close spellings were searched ({term: [spellings]}); allow(word) False keeps a spelling out (a word
    hidden from the agent). The caller caps the terms (MAX_TERMS); close spellings are looked up for the first
    MAX_CLOSE_TERMS words, with the index's words read once per first letter.

    meaning() returns [(id, part, z, clear)], most standing out first (VectorCache.nearest): the clear ones
    are merged; the others, the closest when little stands out clearly, come back as `near` for the caller
    to add after the rest. `meaning` maps every id found by meaning to (part, z)."""
    single = [(t, p) for t, p in terms if not p and " " not in t][:MAX_CLOSE_TERMS]
    exact = words(" ".join(_quote(t) + ("*" if p else "") for t, p in terms))
    stem_parts, shown = [], [t for t, _ in terms]
    for t, prefix in terms:
        if prefix or " " in t:  # phrases and prefixes match as written
            stem_parts.append(_quote(t) + ("*" if prefix else ""))
            continue
        variants = query_stems(t)
        stem_parts.append("(" + " OR ".join(_quote(v) for v in variants) + ")")
        shown += [v for v in variants if len(v) >= 3]
    stemmed = stems(" ".join(stem_parts))
    lists = [(exact, 1.0), (stemmed, 0.9)]
    close: dict[str, list[str]] = {}
    if len(set(exact) | set(stemmed)) < limit:
        if grams is not None and all(len(t) >= 3 for t, _ in terms):
            lists.append((grams(" ".join(_quote(t) for t, _ in terms)), 0.5))
        known: dict[str, list[tuple[str, int]]] = {}  # the index's words, read once per first letter
        for t, _ in single:
            first = fold(t)[:1]
            if first not in known:
                known[first] = vocabulary(first)
            found = [v for v in close_spellings(fold(t), known[first]) if allow is None or allow(v)]
            if found:
                close[t] = found
        if close:
            expression = " ".join("(" + " OR ".join(_quote(v) for v in [t, *close[t]]) + ")" if t in close
                                  else _quote(t) + ("*" if p else "") for t, p in terms)
            lists.append((words(expression), 0.6))
            shown += [v for vs in close.values() for v in vs]
    by_meaning = meaning() if meaning else []
    clear = [x for x in by_meaning if x[3]][:limit]
    near = [x for x in by_meaning if not x[3]][:limit]
    if clear:
        lists.append(([key for key, *_ in clear], 1.0))
    return {"order": fuse(lists)[:limit], "terms": list(dict.fromkeys(shown)), "close": close,
            "meaning": {key: (part, z) for key, part, z, _ in clear + near}, "near": [x[0] for x in near]}


def any_term(terms: list[tuple[str, bool]]) -> dict[str, str]:
    """FTS5 MATCH expressions per index (words, stems, grams) for "any one of the terms", the way rank looks
    each up: a word or prefix, its stems, a part of a word."""
    stems = [_quote(t) + ("*" if p else "") if p or " " in t else " OR ".join(_quote(v) for v in query_stems(t))
             for t, p in terms]
    out = {"words": " OR ".join(_quote(t) + ("*" if p else "") for t, p in terms),
           "stems": " OR ".join(f"({s})" for s in stems if s),
           "grams": " OR ".join(_quote(t) for t, _ in terms if len(t) >= 3)}
    return {table: match for table, match in out.items() if match}


def close_note(close: dict[str, list[str]]) -> str | None:
    """What a search says about the close spellings it searched, or None."""
    if not close:
        return None
    return "also searched close spellings: " + "; ".join(f"{t} → {', '.join(vs)}" for t, vs in close.items())


# ------------------------------------------------------------------ chunks, passages, sameness

CHUNK_CHARS = 800        # text per vector and per passage (~200 tokens)
CHUNK_OVERLAP = 100      # each chunk repeats the end of the one before, so a sentence on the seam is whole once
MAX_CHUNKS = 40          # per text (a body, an attachment, a file): ~28,000 characters, about ten pages
SAME_MIN_CHARS = 200     # shorter texts are too alike to call two of them the same document


def flat(text: str) -> str:
    """The text with every run of whitespace as one space: what chunks and passages are cut from."""
    return " ".join((text or "").split())


def chunks(text: str, size: int = CHUNK_CHARS, overlap: int = CHUNK_OVERLAP, cap: int = MAX_CHUNKS) -> list[tuple[int, int]]:
    """(start, end) of each chunk of a flat text: about `size` characters, ending at a space where one is
    near, each starting `overlap` before the last one ended (at a word's start). The same text always gives
    the same chunks, so a vector's chunk number finds its passage again. At most `cap`; none for no text."""
    out: list[tuple[int, int]] = []
    start, n = 0, len(text)
    while start < n and len(out) < cap:
        end = min(n, start + size)
        if end < n:
            space = text.rfind(" ", start + size * 3 // 4, end)
            end = space if space > start else end
        out.append((start, end))
        if end >= n:
            break
        nxt = max(start + 1, end - overlap)
        space = text.find(" ", nxt, end)
        start = space + 1 if 0 <= space < end - 1 else nxt
    return out


def chunk_texts(title: str, text: str, cap: int = MAX_CHUNKS) -> list[str]:
    """What gets embedded for a document: its chunks, the first with the title in front (a title alone when
    there's no text)."""
    body = flat(text)
    spans = chunks(body, cap=cap)
    if not spans:
        return [flat(title)]
    return [(f"{flat(title)}\n" if i == 0 and title else "") + body[s:e] for i, (s, e) in enumerate(spans)]


def passage_of(text: str, span: tuple[int, int]) -> str:
    """One chunk of a flat text as a passage, with … where the text goes on."""
    start, end = span
    return ("…" if start > 0 else "") + text[start:end].strip() + ("…" if end < len(text) else "")


def best_chunk(text: str, terms: list[str], cap: int = MAX_CHUNKS) -> tuple[int, int] | None:
    """The chunk of a flat text where the most of `terms` occur (accents and case ignored; a term counts
    once per occurrence, a term found at all counts extra), the first one when none does. None for no text.
    Only the chunked start of the text is folded and looked at (MAX_CHUNKS chunks, ~28,000 characters):
    a part of 300,000 characters costs no more than that."""
    spans = chunks(text, cap=cap)
    if not spans:
        return None
    wanted = [fold(t) for t in terms if t and len(t) >= 2]
    if not wanted:
        return spans[0]
    low = fold(text[:spans[-1][1]])

    def score(span):
        piece = low[span[0]:span[1]]
        counts = [piece.count(t) for t in wanted]
        return sum(3 for c in counts if c) + sum(counts)

    return max(spans, key=lambda s: (score(s), -s[0]))


def passage(text: str, terms: list[str], chunk: int | None = None) -> str | None:
    """The passage of a text to show with a hit: the chunk a vector matched (`chunk`), else the chunk with
    most of the terms. Chunks don't depend on the query, so the same passage comes back for other words that
    find it (and the guard's verdict on it is cached). None for a text without words."""
    body = flat(text)
    spans = chunks(body)
    if not spans:
        return None
    terms = [t for t in terms if t][:MAX_TERMS * 4]
    if chunk is not None and 0 <= chunk < len(spans):
        span = spans[chunk]
        if not terms or any(fold(t) in fold(body[span[0]:span[1]]) for t in terms):
            return passage_of(body, span)
        # the vector's chunk has none of the words: show where the words are, if they're anywhere
        found = best_chunk(body, terms)
        if found and any(fold(t) in fold(body[found[0]:found[1]]) for t in terms):
            return passage_of(body, found)
        return passage_of(body, span)
    return passage_of(body, best_chunk(body, terms) or spans[0])


def same_key(text: str) -> str | None:
    """A key two copies of one document share (a PDF attached to a mail and saved in the files, a course
    file copied twice): a hash of the text with spaces, case and accents evened out. None for short texts."""
    import hashlib

    body = fold(flat(text)).casefold()  # casefold: ß and SS alike
    if len(body) < SAME_MIN_CHARS:
        return None
    return "text:" + hashlib.sha256(body.encode()).hexdigest()[:24]


# ------------------------------------------------------------------ vectors


MEANING_MIN_Z = 3.75        # a hit by meaning stands this many standard deviations above texts of its length
MEANING_MIN_VECTORS = 50    # below this, too few vectors to trust their spread: a lower bar
MEANING_SMALL_Z = 1.0
MEANING_LENGTH_UPTO = 100   # up to this many characters, a text's length moves its similarity to any query
MEANING_NEAR_Z = 3.25       # when fewer than MEANING_NEAR_WHEN hits stand out clearly, the closest above this
MEANING_NEAR_MAX = 5        # (at most this many) come after the rest, each with its score
MEANING_NEAR_WHEN = 3


def meaning_z(sims, chars):
    """How far each similarity stands out (standard deviations) from what texts of its length get.

    A short query is closer to every short text than to long ones: "Frist" sits nearer to a calendar entry
    called "Free time" than to most mails, so against the whole index every short title stood out. The
    similarities' trend over the log of the length (counted up to MEANING_LENGTH_UPTO characters) is taken
    out first. It needs MEANING_MIN_VECTORS texts on each side of that length: with only a few long ones,
    say the three mails about the query among calendar entries, their closeness would pass for an effect of
    length. Otherwise it's the plain z over the index. numpy arrays in, an array out."""
    import numpy as np

    sims = sims.astype(np.float64)
    short = int((chars < MEANING_LENGTH_UPTO).sum())
    x = np.log1p(np.minimum(chars, MEANING_LENGTH_UPTO).astype(np.float64))
    dx = x - x.mean()
    spread = float((dx * dx).mean())
    both = min(short, len(chars) - short) >= MEANING_MIN_VECTORS
    slope = float((dx * (sims - sims.mean())).mean()) / spread if both and spread > 1e-12 else 0.0
    rest = sims - sims.mean() - slope * dx
    sd = float(rest.std())
    return rest / sd if sd > 1e-9 else np.zeros_like(rest)  # all as close: none stands out


class VectorCache:
    """Every stored vector in memory for search (float16, 768 bytes each), topped up with rows added since.
    fetch(after_id) returns rows (id, key, part, vec bytes, characters of the text embedded) with id >
    after_id, oldest first."""

    def __init__(self):
        self.cache: dict | None = None

    def invalidate(self) -> None:
        self.cache = None

    def keys(self) -> set:
        return set(self.cache["keys"]) if self.cache else set()

    def load(self, fetch: Callable[[int], list]) -> dict:
        import numpy as np

        cache = self.cache or {"last": 0, "keys": [], "parts": [], "matrix": np.zeros((0, 0), np.float16),
                               "chars": np.zeros(0, np.int32)}
        rows = fetch(cache["last"])
        if rows:
            fresh = np.stack([np.frombuffer(r[3], dtype="<f2") for r in rows])
            cache = {"last": rows[-1][0], "keys": cache["keys"] + [r[1] for r in rows],
                     "parts": cache["parts"] + [r[2] for r in rows],
                     "matrix": fresh if cache["matrix"].size == 0 else np.concatenate([cache["matrix"], fresh]),
                     "chars": np.concatenate([cache["chars"], np.array([r[4] for r in rows], np.int32)])}
        self.cache = cache
        return cache

    def nearest(self, fetch: Callable[[int], list], query: bytes, limit: int, min_z: float | None = None,
                near_z: float | None = None) -> list[tuple]:
        """[(key, part, z, clear)], the most standing out first, one entry per key (its best part).

        z: how many standard deviations the similarity stands out from what texts of its length get
        (meaning_z). Where similarities sit depends on the model and the query (around 0.5 for anything, 0.7
        for the best hit with Granite 107M), so a fixed cut-off can't tell a match from noise, while a clear
        margin over the crowd can. clear: above min_z (3.75: in a test set with a calendar's short titles,
        four in five queries keep their right document as a hit by meaning, and a nonsense query has 0.5
        hits; tests/embedding_eval). near_z: also the ones above it, not clear, for when little stands out.
        Without min_z, every vector. With fewer than MEANING_MIN_VECTORS vectors the spread says less: the
        plain z over the index, clear above MEANING_SMALL_Z, none near."""
        import numpy as np

        q = np.frombuffer(query, dtype="<f2").astype(np.float32)
        cache = self.load(fetch)
        if cache["matrix"].size == 0:
            return []
        sims = np.empty(len(cache["keys"]), np.float32)
        for start in range(0, len(sims), 20000):  # float32 a block at a time, not the whole matrix at once
            sims[start:start + 20000] = cache["matrix"][start:start + 20000].astype(np.float32) @ q
        if len(sims) >= MEANING_MIN_VECTORS:
            z = meaning_z(sims, cache["chars"])
        else:
            sd = float(sims.std())
            z = (sims - sims.mean()) / sd if sd > 1e-9 else np.zeros(len(sims))  # all as close: none stands out
            if min_z is not None:
                min_z, near_z = MEANING_SMALL_Z, None
        if min_z is None:
            passing = np.arange(len(sims))
        else:
            passing = np.flatnonzero(z > min(min_z, near_z if near_z is not None else min_z))
        best: dict = {}
        for i in passing[np.argsort(-z[passing])][: limit * 8]:
            key = cache["keys"][i]
            if key not in best:
                best[key] = (cache["parts"][i], float(z[i]), min_z is None or bool(z[i] > min_z))
        return [(k, p, score, clear) for k, (p, score, clear) in best.items()]


def unpack(result: dict) -> "list":
    """The vectors of an embed result as float16 rows (numpy)."""
    import numpy as np

    return np.frombuffer(result["vectors"], dtype="<f2").reshape(-1, int(result["dim"]))
