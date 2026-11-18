"""The document extractor's own process:

    python -m doorman.extract_worker <dpi> <max OCR pages> [sandbox] [mem=<MB>]

Requests are JSON lines {"name", "content" (base64), "content_type", "ocr", "limit"}; answers are
{"text", "pages"?, "ocr_pages"?, "note"?}. Locked down before anything parses a document: it reads Python
and its packages (the OCR models ship inside rapidocr), writes nothing, and has no network. `mem=` caps its
address space (RLIMIT_AS), so a document that gets past extract.py's size checks runs out of memory here, as
a note on that document, not on the host.
"""

from __future__ import annotations

import base64
import json
import os
import resource
import sys

from .worker_process import lock_down, respond


def main(argv: list[str]) -> int:
    dpi, max_ocr_pages = int(argv[1]), int(argv[2])
    flags = argv[3:]
    sys.stdout = sys.stderr  # stdout is the channel; stray prints go to Doorman's log
    for flag in flags:
        if flag.startswith("mem="):
            limit = int(flag[4:]) * 1024 * 1024
            if limit > 0:
                resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    if "sandbox" in flags and not lock_down(["/proc/cpuinfo", "/sys/devices/system/cpu"], "text extractor"):
        return 1
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    from .extract import OCR, check_mode, extract

    ocr = OCR()
    respond({"ready": True, "pid": os.getpid()})
    for line in sys.stdin:
        try:
            request = json.loads(line)
            content = base64.b64decode(request["content"])
            respond(extract(str(request.get("name") or ""), content, request.get("content_type"), ocr,
                            dpi=dpi, max_ocr_pages=max_ocr_pages, limit=int(request.get("limit") or 2_000_000),
                            read_scans=bool(request.get("ocr", True)),
                            check_pdf=check_mode(request.get("check_pdf", True))))
        except Exception as exc:  # noqa: BLE001
            respond({"error": f"{type(exc).__name__}: {exc}"})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
