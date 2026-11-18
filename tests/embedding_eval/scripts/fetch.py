"""Download pinned files from a HF repo and check sha256 against the hub's LFS metadata.
Usage: fetch.py <repo> <revision> <dest dir> <repo path>[=<local name>] ...
Writes <dest>/manifest.json: {local name: {path, sha256, size}} (sha256 computed locally for every file)."""
import hashlib, json, sys, urllib.request
from pathlib import Path
repo, rev, dest = sys.argv[1], sys.argv[2], Path(sys.argv[3])
dest.mkdir(parents=True, exist_ok=True)
meta = json.load(urllib.request.urlopen(f"https://huggingface.co/api/models/{repo}/revision/{rev}?blobs=true", timeout=60))
assert meta["sha"].startswith(rev) or rev == meta["sha"], (meta["sha"], rev)
sibs = {s["rfilename"]: s for s in meta["siblings"]}
manifest = json.loads((dest / "manifest.json").read_text()) if (dest / "manifest.json").exists() else {}
manifest["_repo"], manifest["_revision"] = repo, meta["sha"]
for arg in sys.argv[4:]:
    path, _, local = arg.partition("=")
    local = local or Path(path).name
    s = sibs[path]
    want = (s.get("lfs") or {}).get("sha256")
    out = dest / local
    url = f"https://huggingface.co/{repo}/resolve/{meta['sha']}/{path}"
    h = hashlib.sha256(); size = 0
    with urllib.request.urlopen(url, timeout=120) as r, open(out, "wb") as f:
        while True:
            b = r.read(1 << 20)
            if not b:
                break
            h.update(b); f.write(b); size += len(b)
    got = h.hexdigest()
    if want and got != want:
        out.unlink(); raise SystemExit(f"sha256 mismatch for {path}: {got} != {want}")
    if s.get("size") and size != s["size"]:
        out.unlink(); raise SystemExit(f"size mismatch for {path}: {size} != {s['size']}")
    manifest[local] = {"path": path, "sha256": got, "size": size}
    print(f"{local}: {path} {size:,} {got} {'(lfs sha ok)' if want else '(not lfs; sha computed)'}")
(dest / "manifest.json").write_text(json.dumps(manifest, indent=1))
