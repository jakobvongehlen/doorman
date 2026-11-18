# Embedding model check

How Doorman's embedding model was chosen (9 Nov 2026), and how to check a candidate again. A synthetic test
set in German, Dutch and English shaped like the owner's data (mail, invoices, contracts, course
material, notes, calendar entries, chats): 82 labelled documents, 467 fillers (125 of them calendar
entries that are only a short title, as most of a real calendar is), 84 queries (same language, across
languages, paraphrases, keywords, questions) and 12 nonsense queries. No real personal data.

```sh
tests/embedding_eval/scripts/fetch.py <repo> <revision> <model dir> <path in repo>...   # pinned, sha256 printed
tests/embedding_eval/scripts/run.sh <spec name> <model dir>    # specs: scripts/specs.json (pooling, prefixes)
```

`run.sh` rebuilds `data/testset.json`, measures R@1, R@5, MRR per query type, how far relevant hits stand
out from the index (z) against the nonsense queries' best hits, seconds per 200 and 512 tokens on one
thread, and the process's memory, then prints the cut-off table for `textsearch.MEANING_MIN_Z`.
`summarize.py` compares every result in `results/`; `memprobe.py` measures the worker's memory with its
ONNX Runtime options. Load one model at a time: the box has little memory.
`eval.py` waits (up to an hour) until 900 MB are free; with the demo and its model running they never are,
so stop the demo first.

What was measured (one thread, a Haswell CPU without VNNI):

| Model | R@1 | MRR | across languages | s per 200 tokens | MB while running | download |
|---|---|---|---|---|---|---|
| **Granite 107M multilingual r1, uint8 (chosen)** | 0.80 | 0.86 | 0.87 | 0.08 | ~500 | 124 MB |
| Granite 97M r2, IBM's fp32 | 0.80 | 0.86 | 0.87 | 0.21 | ~710 | 415 MB |
| Granite 97M r2, int8 (before) | 0.47 | 0.55 | 0.54 | 0.23 | ~500 | 187 MB |
| multilingual-e5-small | 0.65 | 0.74 | 0.60 | 0.16 | ~500 | 135 MB |
| gte-multilingual-base, 384 dims | 0.91 | 0.95 | 0.96 | 0.8–1.07 | ~750 | 357 MB |

Signed int8 builds lose most of their quality on CPUs without VNNI (onnx-community's int8 Granite r2 scored
every pair ~0.99); check a quantized file against its fp32 original before trusting it. gte and
EmbeddingGemma 2 rank best but are 3–4 times too slow for embedding a whole archive on this box.

## The cut-off by meaning (9 Nov, the short titles added)

The model table above was measured before the short titles were in the set. They showed what the real
archive did: against the plain spread of the whole index, a short query stood out at every short title
("Frist" → "Free time", "Frisör"; "rent" → 28 calendar entries), and their spread hid real matches in
mails. `textsearch.meaning_z` takes the similarities' trend over the log of the length (up to 100
characters) out first; without texts that short it's the plain z. Granite 107M uint8 on this set:

| cut-off at 3.75 | kept | first hit right | other hits per query | per nonsense query |
|---|---|---|---|---|
| plain z over the index | 0.45 | 0.71 | 0.39 | 0.17 |
| by length, all lengths | 0.79 | 0.80 | 0.95 | 0.42 |
| by length up to 100 characters (Doorman) | 0.81 | 0.78 | 0.93 | 0.50 |
| short texts against short ones only | 0.76 | 0.79 | 0.65 | 0.08 |

Short against short dropped the right short hits on the demo ("dentist" found no "Zahnarzt"); by length over
all lengths cost 4 points on the set without short titles, up to 100 characters nothing. At 4.0, a nonsense
query gets 0.08 hits, but on a set without short texts 6 points fewer queries keep their document.

## The whole search (9 Nov): `search_bench.py`

`scripts/search_bench.py <testset.json> <model dir> <work dir>` puts the test set into a real index
(doorman/library.py) and scores the first 10 results of each query as an agent gets them: words, stems,
parts of words, close spellings and meaning merged, with each variant of textsearch's `MEANING_*`
settings. Doorman's: the cut-off at 3.75 by length, meaning hits ranked by that score, and when fewer than
3 hits stand out clearly, up to 5 of the closest from 3.25 after them, each with its `meaning_score`.

| set with short titles (84 queries) | empty | first right | right among 10 | wrong, clear | wrong, closest | nonsense: clear / closest |
|---|---|---|---|---|---|---|
| without the closest | 0.14 | 0.74 | 0.80 | 0.75 | 0 | 0.33 / 0 |
| **Doorman's settings** | 0.05 | 0.76 | 0.86 | 0.75 | 0.75 | 0.33 / 1.0 |
| the closest from 3.0 | 0.02 | 0.76 | 0.87 | 0.75 | 1.48 | 0.33 / 2.2 |
| the closest from 2.5 | 0.00 | 0.76 | 0.90 | 0.75 | 2.94 | 0.33 / 4.9 |
| no cut-off at all | 0.00 | 0.76 | 0.95 | 8.39 | 0 | 10 / 0 |

On the set without short titles: right among 10 0.76 → 0.85, first right 0.72 → 0.78, for 0.70 of the
closest per query that are wrong and 0.33 per nonsense query. Ranking meaning hits by the score instead of
the similarity put the right one first for 74 queries instead of 71 on the set with short titles, the
same on the other. No cut-off finds the most, but 8 of 10 results are wrong and a nonsense query always
gets 10: an agent can't tell that nothing is there.
