"""Embedding model eval for Doorman's semantic search.

Usage: python -I eval.py <specs.json> <name> <model dir> <testset.json> <results dir> [--quick]

Loads ONE model the way embed_worker.py does (onnxruntime CPU, 1 intra-op thread, no mem arena, HF tokenizers,
one text at a time, no padding), embeds the corpus and the queries, and writes <results dir>/<name>.json
(metrics), <name>.npz (vectors) and <name>.txt (per-query ranks, for reading the misses).

Spec keys (specs.json[name]): onnx, tokenizer, pooling ("graph" | "cls" | "mean"), output (name, default
first output), query_prefix, doc_prefix, dims (list; first = native, others = Matryoshka truncations),
max_tokens (default 512), static (model2vec-style graph taking input_ids + offsets).
"""
from __future__ import annotations

import json
import os
import resource
import statistics
import sys
import time
from pathlib import Path


def cgroup_headroom_mb() -> float:
    try:
        limit = int(Path("/sys/fs/cgroup/memory.max").read_text())
        stat = dict(line.split() for line in Path("/sys/fs/cgroup/memory.stat").read_text().splitlines())
        used = int(stat["anon"]) + int(stat.get("shmem", 0)) + int(stat.get("kernel", 0))
        return (limit - used) / 2**20
    except Exception:
        return 1e9


def host_available_mb() -> float:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) / 1024
    return 1e9


def wait_for_memory(need_mb: float = 900, max_wait: float = 3600) -> None:
    start = time.time()
    while True:
        cg, host = cgroup_headroom_mb(), host_available_mb()
        if cg >= need_mb and host >= need_mb:
            print(f"memory ok: cgroup headroom {cg:.0f} MB, host available {host:.0f} MB", flush=True)
            return
        if time.time() - start > max_wait:
            raise SystemExit(f"gave up waiting for memory (cgroup {cg:.0f} MB, host {host:.0f} MB)")
        print(f"waiting for memory: cgroup headroom {cg:.0f} MB, host available {host:.0f} MB", flush=True)
        time.sleep(20)


def rss_mb() -> tuple[float, float]:
    cur = peak = 0.0
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            cur = int(line.split()[1]) / 1024
        elif line.startswith("VmSwap:") and int(line.split()[1]) > 10240:
            print(f"WARNING: process swapped {int(line.split()[1]) // 1024} MB, timings unreliable", flush=True)
        elif line.startswith("VmHWM:"):
            peak = int(line.split()[1]) / 1024
    return cur, peak


class Model:
    def __init__(self, spec: dict, model_dir: Path):
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self.np = np
        self.spec = spec
        ort.set_default_logger_severity(3)
        options = ort.SessionOptions()
        options.log_severity_level = 3
        options.intra_op_num_threads = 1
        options.inter_op_num_threads = 1
        options.enable_cpu_mem_arena = False
        options.enable_mem_pattern = False
        t0 = time.perf_counter()
        self.session = ort.InferenceSession(str(model_dir / spec["onnx"]), options, providers=["CPUExecutionProvider"])
        self.load_seconds = time.perf_counter() - t0
        self.inputs = {i.name: i for i in self.session.get_inputs()}
        outs = [o.name for o in self.session.get_outputs()]
        self.output = spec.get("output") or outs[0]
        self.output_index = outs.index(self.output)
        self.tokenizer = Tokenizer.from_file(str(model_dir / spec["tokenizer"]))
        self.max_tokens = int(spec.get("max_tokens", 512))
        self.tokenizer.enable_truncation(self.max_tokens)
        self.tokenizer.no_padding()
        self.io = {"inputs": {k: (v.type, v.shape) for k, v in self.inputs.items()},
                   "outputs": {o.name: o.shape for o in self.session.get_outputs()}}

    def ids(self, text: str) -> list[int]:
        return self.tokenizer.encode(text or " ").ids

    def run_ids(self, ids: list[int]):
        np = self.np
        if self.spec.get("static"):
            feeds = {"input_ids": np.array(ids, dtype=np.int64), "offsets": np.array([0], dtype=np.int64)}
            feeds = {k: v for k, v in feeds.items() if k in self.inputs}
        else:
            batch = np.array([ids], dtype=np.int64)
            feeds = {"input_ids": batch}
            if "attention_mask" in self.inputs:
                feeds["attention_mask"] = np.ones_like(batch)
            if "token_type_ids" in self.inputs:
                feeds["token_type_ids"] = np.zeros_like(batch)
            if "position_ids" in self.inputs:
                feeds["position_ids"] = np.arange(len(ids), dtype=np.int64)[None, :]
            for name, inp in self.inputs.items():   # multimodal graphs (EmbeddingGemma 2): no media
                if name.endswith("_features"):
                    feeds[name] = np.zeros((0, int(inp.shape[-1])), dtype=np.float32)
        out = self.session.run([self.output], feeds)[0]
        pooling = self.spec.get("pooling", "graph")
        if pooling == "cls":
            vec = out[0, 0]
        elif pooling == "mean":
            vec = out[0].mean(axis=0)
        else:
            if out.ndim == 3:
                raise SystemExit(f"output {self.output} is per token; set pooling cls/mean or the pooled output")
            vec = out[0] if out.ndim == 2 else out
        return np.asarray(vec, dtype=np.float32).reshape(-1)

    def embed(self, text: str, prefix: str = ""):
        return self.run_ids(self.ids(prefix + text))


def evaluate(doc_vecs, query_vecs, nonsense_vecs, docs, queries, dim: int) -> dict:
    import numpy as np

    def norm(m):
        m = m[:, :dim]
        return m / np.linalg.norm(m, axis=1, keepdims=True)

    D, Q, N = norm(doc_vecs), norm(query_vecs), norm(nonsense_vecs)
    ids = [d["id"] for d in docs]
    index = {d: i for i, d in enumerate(ids)}
    lang = {d["id"]: d["lang"] for d in docs}
    per_query, pair_hits = [], {}
    S = Q @ D.T
    for qi, q in enumerate(queries):
        sims = S[qi]
        order = np.argsort(-sims)
        rank = np.empty(len(order), int)
        rank[order] = np.arange(1, len(order) + 1)
        rel = [index[r] for r in q["rel"]]
        rel_ranks = sorted(int(rank[r]) for r in rel)
        mean, sd = float(sims.mean()), float(sims.std())
        best_rel = max(float(sims[r]) for r in rel)
        top = int(order[0])
        per_query.append({
            "q": q["q"], "type": q["type"], "lang": q["lang"], "rel_ranks": rel_ranks,
            "hit1": rel_ranks[0] == 1, "hit5": rel_ranks[0] <= 5,
            "recall5": sum(r <= 5 for r in rel_ranks) / min(len(rel), 5),
            "rr": 1.0 / rel_ranks[0], "z_rel": (best_rel - mean) / sd, "z_top": (float(sims[top]) - mean) / sd,
            "sim_rel": best_rel, "sim_top": float(sims[top]), "mean": mean, "sd": sd,
            "top3": [ids[i] for i in order[:3]],
        })
        for r in q["rel"]:
            key = f"{q['lang']}->{lang[r]}"
            pair_hits.setdefault(key, []).append(int(rank[index[r]]))
    SN = N @ D.T
    nonsense = []
    for ni in range(len(N)):
        sims = SN[ni]
        top = int(np.argmax(sims))
        nonsense.append({"z_top": float((sims[top] - sims.mean()) / sims.std()), "sim_top": float(sims[top]),
                         "top": ids[top], "mean": float(sims.mean())})

    def agg(rows):
        return {"n": len(rows), "R@1": statistics.mean(r["hit1"] for r in rows),
                "hit@5": statistics.mean(r["hit5"] for r in rows),
                "recall@5": statistics.mean(r["recall5"] for r in rows), "MRR": statistics.mean(r["rr"] for r in rows)}

    by_type = {t: agg([r for r in per_query if r["type"] == t]) for t in sorted({r["type"] for r in per_query})}
    pairs = {k: {"n": len(v), "in_top5": statistics.mean(x <= 5 for x in v), "in_top10": statistics.mean(x <= 10 for x in v)}
             for k, v in sorted(pair_hits.items())}
    z_rel = sorted(r["z_rel"] for r in per_query)
    z_non = sorted(n["z_top"] for n in nonsense)
    # relevant z: only where the best relevant doc is also the top hit (what the cut-off would keep)
    z_rel_hit1 = sorted(r["z_rel"] for r in per_query if r["hit1"])

    def frac_at_least(vals, t):
        return sum(v >= t for v in vals) / len(vals) if vals else 0.0

    thresholds = {f"{t:.1f}": {"rel_kept": frac_at_least(z_rel, t), "nonsense_kept": frac_at_least(z_non, t)}
                  for t in [2.5, 3.0, 3.5, 4.0, 4.5, 5.0, 5.5, 6.0]}
    # cut-off that keeps no nonsense query, and the share of relevant kept there
    zero_fp = max(z_non) + 1e-6
    return {
        "dim": dim, "overall": agg(per_query), "by_type": by_type, "pairs": pairs,
        "z": {"rel_median": statistics.median(z_rel), "rel_p10": z_rel[len(z_rel) // 10], "rel_min": z_rel[0],
              "rel_hit1_median": statistics.median(z_rel_hit1) if z_rel_hit1 else None,
              "nonsense_median": statistics.median(z_non), "nonsense_max": max(z_non),
              "rel_kept_above_nonsense_max": frac_at_least(z_rel, zero_fp),
              "thresholds": thresholds},
        "cos": {"query_mean_sim": statistics.mean(r["mean"] for r in per_query),
                "top_sim_median": statistics.median(r["sim_top"] for r in per_query),
                "nonsense_top_sim_median": statistics.median(n["sim_top"] for n in nonsense)},
        "per_query": per_query, "nonsense": nonsense,
    }


def main(argv):
    quick = "--quick" in argv
    argv = [a for a in argv if not a.startswith("--")]
    specs, name, model_dir, testset, results = argv[1], argv[2], Path(argv[3]), argv[4], Path(argv[5])
    spec = json.load(open(specs))[name]
    data = json.load(open(testset))
    docs, queries, nonsense = data["docs"], data["queries"], data["nonsense"]
    results.mkdir(parents=True, exist_ok=True)
    import numpy as np

    wait_for_memory()
    rss0 = rss_mb()[0]
    model = Model(spec, model_dir)
    rss_loaded = rss_mb()[0]
    print(f"[{name}] loaded in {model.load_seconds:.1f}s, RSS {rss_loaded:.0f} MB (python+numpy+ort before: {rss0:.0f} MB)", flush=True)
    print("io:", model.io, flush=True)
    qp, dp = spec.get("query_prefix", ""), spec.get("doc_prefix", "")

    # speed: fixed-length inputs built from the corpus with this model's tokenizer
    long_text = " ".join(d["text"] for d in docs[:30])
    speed = {}
    for n in (200, 512):
        model.tokenizer.enable_truncation(n)
        ids = model.ids(long_text)
        model.tokenizer.enable_truncation(model.max_tokens)
        model.run_ids(ids)  # warm-up
        times = []
        for _ in range(7 if n == 200 else 4):
            t0 = time.perf_counter()
            model.run_ids(ids)
            times.append(time.perf_counter() - t0)
        speed[f"s_per_{n}_tokens"] = {"min": min(times), "median": statistics.median(times), "tokens": len(ids)}
        print(f"[{name}] {len(ids)} tokens: min {min(times):.3f}s median {statistics.median(times):.3f}s", flush=True)
    load1 = os.getloadavg()[0]

    t0 = time.perf_counter()
    doc_vecs, doc_tokens = [], []
    for i, d in enumerate(docs):
        doc_tokens.append(len(model.ids(dp + d["text"])))
        doc_vecs.append(model.embed(d["text"], dp))
        if quick and i > 40:
            break
    corpus_seconds = time.perf_counter() - t0
    if quick:
        docs = docs[: len(doc_vecs)]
    qtimes, query_vecs = [], []
    for q in queries:
        t1 = time.perf_counter()
        query_vecs.append(model.embed(q["q"], qp))
        qtimes.append(time.perf_counter() - t1)
    nonsense_vecs = [model.embed(q, qp) for q in nonsense]
    rss_now, rss_peak = rss_mb()
    swapped = [int(l.split()[1]) // 1024 for l in Path("/proc/self/status").read_text().splitlines() if l.startswith("VmSwap:")][0]
    peak_ru = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    D, Q, N = np.stack(doc_vecs), np.stack(query_vecs), np.stack(nonsense_vecs)
    np.savez_compressed(results / f"{name}.npz", docs=D, queries=Q, nonsense=N)
    if quick:
        print("quick run: doc vectors", D.shape, "norms", np.linalg.norm(D, axis=1)[:5])
        return 0
    native = D.shape[1]
    dims = spec.get("dims") or [native]
    evals = {str(d): evaluate(D, Q, N, docs, queries, d) for d in dims}
    model_bytes = sum(f.stat().st_size for f in model_dir.iterdir() if f.is_file())
    out = {
        "name": name, "spec": spec, "io": model.io, "native_dim": native, "files_bytes": model_bytes,
        "load_seconds": model.load_seconds, "rss_after_load_mb": rss_loaded, "rss_peak_mb": max(rss_peak, peak_ru),
        "rss_end_mb": rss_now, "swapped_mb": swapped, "speed": speed, "loadavg_during_speed": load1,
        "corpus_seconds": corpus_seconds, "corpus_docs": len(docs), "corpus_tokens_mean": statistics.mean(doc_tokens),
        "query_seconds_median": statistics.median(qtimes), "query_seconds_max": max(qtimes),
        "evals": evals,
    }
    json.dump(out, open(results / f"{name}.json", "w"), indent=1, default=float)
    with open(results / f"{name}.txt", "w") as fh:
        for d, ev in evals.items():
            fh.write(f"=== dim {d}\n")
            for r in ev["per_query"]:
                mark = "OK " if r["hit1"] else ("ok5" if r["hit5"] else "MISS")
                fh.write(f"{mark} [{r['type']:4s} {r['lang']}] {r['q'][:55]:55s} ranks={r['rel_ranks'][:4]} z_rel={r['z_rel']:.2f} top3={r['top3']}\n")
            for q, n in zip(nonsense, ev["nonsense"]):
                fh.write(f"NONSENSE {q:35s} z_top={n['z_top']:.2f} sim={n['sim_top']:.3f} top={n['top']}\n")
    for d, ev in evals.items():
        o, z = ev["overall"], ev["z"]
        print(f"[{name} d={d}] R@1 {o['R@1']:.3f} recall@5 {o['recall@5']:.3f} hit@5 {o['hit@5']:.3f} MRR {o['MRR']:.3f} | "
              f"z rel med {z['rel_median']:.2f} p10 {z['rel_p10']:.2f} | nonsense med {z['nonsense_median']:.2f} max {z['nonsense_max']:.2f} | "
              f"rel kept above nonsense max {z['rel_kept_above_nonsense_max']:.2f} | cos mean {ev['cos']['query_mean_sim']:.3f} top {ev['cos']['top_sim_median']:.3f}")
        print("   by type:", {t: (round(v['R@1'], 2), round(v['MRR'], 2)) for t, v in ev["by_type"].items()})
        print("   pairs in top5:", {k: round(v['in_top5'], 2) for k, v in ev["pairs"].items()})
    print(f"[{name}] corpus {len(docs)} docs ({statistics.mean(doc_tokens):.0f} tokens mean) in {corpus_seconds:.0f}s; "
          f"query median {statistics.median(qtimes)*1000:.0f} ms; RSS after load {rss_loaded:.0f} MB, peak {max(rss_peak, peak_ru):.0f} MB; loadavg {load1:.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
