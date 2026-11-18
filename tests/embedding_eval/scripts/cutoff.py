"""Cut-off analysis from saved vectors (no model needed).
Usage: python -I cutoff.py <testset.json> <results dir> <name> [dim]

z is Doorman's (textsearch.meaning_z): how far a similarity stands out from what texts of its length get.
For thresholds t: share of queries whose best relevant doc has z >= t ("kept"), and the noise rate: share of
(query, non-relevant doc) pairs with z >= t, over the 80 real queries (non-relevant docs include the deliberate
near-miss distractors) and over the nonsense queries. The top z of a noise query is a maximum over the index, so
it grows with index size; the per-document noise rate does not, so expected noise hits per query in a 100k-chunk
index ~ rate x 100k (rough: the tail is estimated from ~35k pairs)."""
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from doorman.textsearch import meaning_z  # noqa: E402

data = json.load(open(sys.argv[1]))
z = np.load(f"{sys.argv[2]}/{sys.argv[3]}.npz")
dim = int(sys.argv[4]) if len(sys.argv) > 4 else z["docs"].shape[1]


def norm(m):
    m = m[:, :dim]
    return m / np.linalg.norm(m, axis=1, keepdims=True)


D, Q, N = norm(z["docs"]), norm(z["queries"]), norm(z["nonsense"])
index = {d["id"]: i for i, d in enumerate(data["docs"])}
chars = np.array([len(d["text"]) for d in data["docs"]])
best_rel, noise_q, noise_n = [], [], []
for qi, q in enumerate(data["queries"]):
    s = D @ Q[qi]
    zs = meaning_z(s, chars)
    rel = [index[r] for r in q["rel"]]
    best_rel.append(zs[rel].max())
    mask = np.ones(len(zs), bool)
    mask[rel] = False
    noise_q.append(zs[mask])
for ni in range(len(N)):
    s = D @ N[ni]
    noise_n.append(meaning_z(s, chars))
best_rel = np.array(best_rel)
noise_q, noise_n = np.concatenate(noise_q), np.concatenate(noise_n)
print(f"{sys.argv[3]} dim {dim}: {len(best_rel)} queries, {len(noise_q)} query/non-relevant pairs, {len(noise_n)} nonsense pairs")
print("   t   kept  noise/doc(real q)  per q @100k   noise/doc(nonsense)  per q @100k")
for t in [3.0, 3.25, 3.5, 3.6, 3.7, 3.75, 3.8, 3.9, 4.0, 4.25, 4.5, 5.0]:
    kept = (best_rel >= t).mean()
    rq, rn = (noise_q >= t).mean(), (noise_n >= t).mean()
    print(f"{t:5.2f}  {kept:4.2f}   {rq:9.5f}         {rq * 1e5:7.0f}      {rn:9.5f}          {rn * 1e5:7.0f}")
