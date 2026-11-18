"""Fingerprints of text: how the proxy recognises data Doorman served without Doorman sending it the data.

Doorman fingerprints everything an agent reads; the proxy fingerprints what the agent sends out and asks
Doorman how many prints the two share. Only hashes cross between them, so the content stays where it is.

The method is winnowing (Schleimer, Wilkerson, Aiken 2003): hash every run of K normalized characters
(a "gram"), slide a window of W hashes over them and keep each window's smallest. Two texts sharing a
stretch of at least W + K - 1 = 35 normalized characters are then certain to share a print, and a text
keeps only about 2 / (W + 1) of its grams, so the table of what the agent read stays small.

Normalization makes the agent's copy and the original look alike again: NFKC folds look-alike forms,
casefold drops case, and only letters and digits stay, so spacing, punctuation, line breaks and the
spotlight datamark ("ˆ", U+02C6, a modifier letter, category Lm) don't matter. Text shorter than K
normalized characters (a subject, a name) gives no prints at all: it is too short to tell apart from
anything else, and it would otherwise match everything.
"""

from __future__ import annotations

import hashlib
import unicodedata
from collections import deque
from collections.abc import Iterator
from typing import Any

K = 24  # normalized characters per gram
W = 12  # winnowing window, in grams


class _Keep(dict):
    """A str.translate table filled on demand: letters and digits map to themselves, the rest to None."""

    def __missing__(self, code: int) -> int | None:
        category = unicodedata.category(chr(code))
        value = code if category[0] in "LN" and category != "Lm" else None
        self[code] = value
        return value


_KEEP = _Keep()


def normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text).casefold().translate(_KEEP)


def _hash(gram: str) -> int:
    # the first 8 bytes as a signed int, so it fits an SQLite INTEGER
    return int.from_bytes(hashlib.blake2b(gram.encode()).digest()[:8], "big", signed=True)


def winnow(norm: str) -> list[int]:
    """The prints of already normalized text, each once, in the order they first occur: a stretch of the text
    has its prints next to each other (the proxy splits long lists for Doorman along that order)."""
    if len(norm) < K:
        return []
    hashes = [_hash(norm[i:i + K]) for i in range(len(norm) - K + 1)]
    if len(hashes) <= W:
        return [min(hashes)]
    out: dict[int, None] = {}
    window: deque[int] = deque()  # positions, their hashes increasing; the front is the window's minimum
    for i, h in enumerate(hashes):
        while window and hashes[window[-1]] >= h:  # >=: on a tie the rightmost position wins
            window.pop()
        window.append(i)
        if window[0] <= i - W:
            window.popleft()
        if i >= W - 1:
            out[hashes[window[0]]] = None
    return list(out)


def prints(text: str) -> set[int]:
    return set(winnow(normalize(text)))


def strings_of(data: Any) -> Iterator[str]:
    """Every str value in nested dicts, lists and tuples, in order; dict keys are skipped."""
    stack = [iter((data,))]  # a stack of iterators, so deep nesting can't hit the recursion limit
    while stack:
        for item in stack[-1]:
            if isinstance(item, str):
                yield item
            elif isinstance(item, dict):
                stack.append(iter(item.values()))
                break
            elif isinstance(item, (list, tuple)):
                stack.append(iter(item))
                break
        else:
            stack.pop()


def prints_of_data(data: Any) -> set[int]:
    out: set[int] = set()
    for text in strings_of(data):
        out |= prints(text)
    return out


def estimate_chars(n: int) -> int:
    """About how many characters n shared prints stand for: one print per (W + 1) / 2 grams."""
    return n * (W + 1) // 2
