"""A helper process for test_worker_env: answers every request with its environment."""

import os
import sys

from doorman.worker_process import respond

respond({"ready": True})
for _ in sys.stdin:
    respond({"env": dict(os.environ)})
