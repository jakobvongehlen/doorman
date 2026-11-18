"""Writes testset.json from testset_docs.py, testset_queries.py, testset_filler.py. Usage: build_testset.py <out.json>"""
import json, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from testset_docs import DOCS
from testset_queries import QUERIES, NONSENSE
from testset_filler import filler, short_titles

docs = [dict(id=i, lang=l, kind=k, text=t.strip()) for i, l, k, t in DOCS]
ids = [d["id"] for d in docs]
assert len(ids) == len(set(ids)), "duplicate ids"
known = set(ids)
lang = {d["id"]: d["lang"] for d in docs}
for q, ql, typ, rel in QUERIES:
    for r in rel:
        assert r in known, (q, r)
    assert typ in ("kw", "same", "xl", "para", "q"), typ
fill = [dict(id=i, lang=l, kind=k, text=t) for i, l, k, t in filler() + short_titles()]
out = {"docs": docs + fill,
       "queries": [dict(q=q, lang=ql, type=typ, rel=rel) for q, ql, typ, rel in QUERIES],
       "nonsense": NONSENSE}
json.dump(out, open(sys.argv[1], "w"), ensure_ascii=False, indent=1)
lens = [len(d["text"]) for d in docs]
print(f"labelled docs {len(docs)} (chars {min(lens)}-{max(lens)}, mean {sum(lens)/len(lens):.0f}); filler {len(fill)}; queries {len(QUERIES)}; nonsense {len(NONSENSE)}")
from collections import Counter
print("docs by lang", Counter(d["lang"] for d in docs), "filler by lang", Counter(d["lang"] for d in fill))
print("queries by type", Counter(t for _, _, t, _ in QUERIES), "by lang", Counter(l for _, l, _, _ in QUERIES))
pairs = Counter(f"{ql}->{lang[r]}" for _, ql, _, rel in QUERIES for r in rel)
print("query->relevant doc language pairs", dict(pairs))
short = [d["id"] for d in docs if len(d["text"]) < 300]
print("labelled docs under 300 chars:", short)
