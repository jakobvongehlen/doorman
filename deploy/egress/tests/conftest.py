"""The proxy's tests run in their own environment with mitmproxy 12.3.1 (~/.venvs/egress here, the image's
pip install elsewhere): `python -m pytest deploy/egress/tests`. The repo root goes on sys.path so the shared
core imports as doorman.egress.*, as it does in the image, and deploy/egress for addon and doorman_client."""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
for path in (HERE.parent.parent.parent, HERE.parent):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
