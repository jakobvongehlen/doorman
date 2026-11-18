"""Table of all results: python -I summarize.py <results dir> [download sizes json]"""
import json
import sys
from pathlib import Path

rows = []
sizes = json.load(open(sys.argv[2])) if len(sys.argv) > 2 else {}
for p in sorted(Path(sys.argv[1]).glob("*.json")):
    r = json.loads(p.read_text())
    for dim, ev in r["evals"].items():
        o, z, bt = ev["overall"], ev["z"], ev["by_type"]
        xl_pairs = [v for k, v in ev["pairs"].items() if k.split("->")[0] != k.split("->")[1]]
        xl5 = sum(v["in_top5"] * v["n"] for v in xl_pairs) / sum(v["n"] for v in xl_pairs)
        rows.append({
            "model": r["name"] + ("" if int(dim) == r["native_dim"] else f" @{dim}"),
            "R@1": o["R@1"], "R@5": o["recall@5"], "hit@5": o["hit@5"], "MRR": o["MRR"],
            "kw": bt["kw"]["MRR"], "same": bt["same"]["MRR"], "xl": bt["xl"]["MRR"], "para": bt["para"]["MRR"], "q": bt["q"]["MRR"],
            "xl_pair@5": xl5,
            "z_rel_med": z["rel_median"], "z_rel_p10": z["rel_p10"], "z_non_med": z["nonsense_median"], "z_non_max": z["nonsense_max"],
            "keep>=3.5": z["thresholds"]["3.5"]["rel_kept"], "non>=3.5": z["thresholds"]["3.5"]["nonsense_kept"],
            "sep": z["rel_kept_above_nonsense_max"],
            "s/200": r["speed"]["s_per_200_tokens"]["min"], "s/512": r["speed"]["s_per_512_tokens"]["min"],
            "q_ms": r["query_seconds_median"] * 1000, "rss_peak": r["rss_peak_mb"], "rss_load": r["rss_after_load_mb"],
            "dl_MB": sizes.get(r["name"], 0) / 1e6,
        })
cols = list(rows[0].keys())
fmt = {"model": "{:34s}", "q_ms": "{:5.0f}", "rss_peak": "{:6.0f}", "rss_load": "{:6.0f}", "dl_MB": "{:5.0f}"}
print(" ".join(f"{c:>34s}" if c == "model" else f"{c:>6s}" for c in cols))
for row in sorted(rows, key=lambda x: -x["MRR"]):
    print(" ".join((fmt.get(c, "{:6.2f}")).format(row[c]).rjust(34 if c == "model" else 6) for c in cols))
