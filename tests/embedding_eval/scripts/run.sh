#!/bin/sh
# Repeatable embedding check. Usage: scripts/run.sh <spec name> <model dir>
#   (specs in scripts/specs.json; models downloaded with scripts/fetch.py <repo> <revision> <dir> <path>...)
# Rebuilds data/testset.json from the three testset_*.py files, evaluates one model, prints the cut-off table.
set -e
HERE=$(cd "$(dirname "$0")/.." && pwd)
PY=${PY:-$(cd "$HERE/../.." && pwd)/.venv/bin/python}
python3 -I "$HERE/scripts/build_testset.py" "$HERE/data/testset.json"
"$PY" -I "$HERE/scripts/eval.py" "$HERE/scripts/specs.json" "$1" "$2" "$HERE/data/testset.json" "$HERE/results"
"$PY" -I "$HERE/scripts/cutoff.py" "$HERE/data/testset.json" "$HERE/results" "$1"
