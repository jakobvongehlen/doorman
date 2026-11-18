"""List a HF repo's files (size, sha256), license, commit sha. Usage: hfinfo.py repo [filter-substring]"""
import json, sys, urllib.request
repo = sys.argv[1]; flt = sys.argv[2] if len(sys.argv) > 2 else ""
try:
    d = json.load(urllib.request.urlopen(f"https://huggingface.co/api/models/{repo}/revision/main?blobs=true", timeout=30))
except Exception as e:
    print(repo, "ERROR", e); sys.exit()
card = d.get("cardData") or {}
print(f"== {repo} sha={d.get('sha')} license={card.get('license')} {card.get('license_name','')} lastmod={d.get('lastModified')} downloads={d.get('downloads')} pipeline={d.get('pipeline_tag')} lib={d.get('library_name')}")
for s in d["siblings"]:
    name = s["rfilename"]
    if flt and not any(f in name for f in flt.split(",")):
        continue
    print(f"   {name:60s} {s.get('size') or 0:>12,d} {(s.get('lfs') or {}).get('sha256','')}")
