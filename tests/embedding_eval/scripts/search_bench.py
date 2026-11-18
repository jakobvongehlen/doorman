"""The whole search on the test set, as an agent gets it: the documents in a real index (doorman/library.py:
words, stems, parts of words, close spellings, meaning, merged as Doorman merges them) with the real model,
and each query's first 10 results scored. Each variant sets textsearch's MEANING_* constants.
Usage: python -I search_bench.py <testset.json> <model dir> <work dir>

Scored per query: empty (no results), first (the first is relevant), found (a relevant one among the 10),
only near (found only among the closest by meaning, after the clear hits), MRR, and the wrong results per
query, clear and near; for the nonsense queries the results per query, clear and near. The any-word fallback
(engine.search.any_word) isn't part of it: it needs plugins."""
import json
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from doorman import textsearch  # noqa: E402
from doorman.embed_worker import Embedder  # noqa: E402
from doorman.library import Library  # noqa: E402

VARIANTS = [
    ("without the closest by meaning", {"MEANING_NEAR_MAX": 0}),
    ("Doorman's settings", {}),
    ("closest from z 3.0", {"MEANING_NEAR_Z": 3.0}),
    ("closest from z 2.5", {"MEANING_NEAR_Z": 2.5}),
    ("closest even with 3+ clear hits", {"MEANING_NEAR_WHEN": 10}),
    ("no cut-off at all", {"MEANING_MIN_Z": -100.0, "MEANING_NEAR_MAX": 0}),
]
KIND = {"mail": "mail", "letter": "mail", "pdf": "file", "calendar": "event", "whatsapp": "chat", "note": "note"}


class Model:
    """Doorman's embedder as the index uses it, in this process, each text embedded once."""

    def __init__(self, model_dir: str):
        self.embedder, self.done = Embedder(Path(model_dir), 512), {}

    def embed(self, texts, background=False):
        for text in texts:
            if text not in self.done:
                self.done[text] = self.embedder.embed(text)
        vectors = np.stack([self.done[t] for t in texts]).astype("<f2").tobytes() if texts else b""
        return {"model": "bench", "dim": 384, "vectors": vectors}


def main(argv):
    data = json.load(open(argv[1]))
    work = Path(argv[3])
    work.mkdir(parents=True, exist_ok=True)
    for old in work.glob("*.db*"):
        old.unlink()
    library = Library(work / "index.db", Model(argv[2]))
    for doc in data["docs"]:  # the first line is the title, as a calendar entry's or a mail's subject
        first, _, rest = doc["text"].partition("\n")
        kind = KIND.get(doc["kind"]) or ("event" if doc["id"].startswith("short_") else "note")
        library.put("eval", {"key": doc["id"], "title": first[:150], "text": rest, "kind": kind, "date": "2026-01-01"})
    start = time.time()
    while library.run(time.monotonic() + 120).get("more"):
        pass
    print(f"{len(data['docs'])} documents indexed in {time.time() - start:.0f}s; {len(data['queries'])} queries, "
          f"{len(data['nonsense'])} nonsense; the first 10 results")
    print(f"{'':34} {'empty':>5} {'first':>5} {'found':>5} {'only near':>9} {'MRR':>5} {'wrong':>5} {'near':>5}"
          f" | nonsense: {'clear':>5} {'near':>5}")
    defaults = {name: getattr(textsearch, name) for name in
                ("MEANING_MIN_Z", "MEANING_NEAR_Z", "MEANING_NEAR_MAX", "MEANING_NEAR_WHEN")}
    for label, settings in VARIANTS:
        for name, value in {**defaults, **settings}.items():
            setattr(textsearch, name, value)
        empty = first = found = only_near = mrr = wrong = wrong_near = 0
        for query in data["queries"]:
            hits = library.search({"query": query["q"]}, ["eval"], 10)["hits"][:10]
            relevant = set(query["rel"])
            places = [i for i, h in enumerate(hits) if h["key"] in relevant]
            empty += not hits
            first += bool(places) and places[0] == 0
            found += bool(places)
            only_near += bool(places) and all(hits[i]["near"] for i in places)
            mrr += 1 / (places[0] + 1) if places else 0
            wrong += sum(h["key"] not in relevant and not h["near"] for h in hits)
            wrong_near += sum(h["key"] not in relevant and h["near"] for h in hits)
        clear = near = 0
        for query in data["nonsense"]:
            hits = library.search({"query": query}, ["eval"], 10)["hits"][:10]
            clear += sum(not h["near"] for h in hits)
            near += sum(h["near"] for h in hits)
        n, m = len(data["queries"]), len(data["nonsense"])
        print(f"{label:34} {empty / n:5.2f} {first / n:5.2f} {found / n:5.2f} {only_near / n:9.2f} {mrr / n:5.2f} "
              f"{wrong / n:5.2f} {wrong_near / n:5.2f} | {'':9} {clear / m:5.2f} {near / m:5.2f}")
    library.close()


if __name__ == "__main__":
    main(sys.argv)
