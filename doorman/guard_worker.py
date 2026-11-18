"""The injection scanner's own process:
python -m doorman.guard_worker <model dir> <window> <overlap> <threads> [sandbox].

Doorman starts it when it first needs a scan and stops it when it has been idle for a while, so the model's
memory (about 800 MB with the FP16 build) is only taken while scans happen. A crash here can't take Doorman
down; Doorman lets text through unscanned and lists the problem.

Protocol: JSON lines. Doorman writes {"texts": [...]}; the worker answers {"results": [{"score", "start",
"end"}, ...]} with one result per text: the highest window score, and the character span of that window
(so the owner can see what tripped it). The first line the worker writes is {"ready": true} or {"error": ...}.

Long texts are split into windows of `window` tokens that overlap by `overlap` tokens, and every window is
scored, so an injection on page 5 isn't cut off. The model was trained on up to 2,048 tokens, but its
attention costs grow with the square of the length: 512-token windows are 2.5x cheaper per token here.

`threads`: onnxruntime's threads for one window (guard.py picks them). Measured Nov 2026, seconds per 1,000
characters: the laptop (Ryzen 5 3500U, 4 cores) 0.86 with 1 thread, 0.70 with 2, 0.49 with 4, 0.58 with 6;
the VPS (4 vCPUs, one thread each) 0.62 with 1, 0.48 with 2, 0.63 with 4. The threads wait for work asleep,
not spinning: as fast here, and an idle scanner leaves the CPUs to Doorman and the agent.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .worker_process import lock_down, respond


class Scanner:
    def __init__(self, model_dir: Path, window: int, overlap: int, threads: int = 1):
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self.np = np
        ort.set_default_logger_severity(3)  # errors only: no telemetry or GPU-discovery warnings in the log
        options = ort.SessionOptions()
        options.log_severity_level = 3
        options.intra_op_num_threads = max(1, threads)
        options.inter_op_num_threads = 1
        options.add_session_config_entry("session.intra_op.allow_spinning", "0")
        options.enable_cpu_mem_arena = False  # give memory back after a long document
        self.session = ort.InferenceSession(str(model_dir / "model.onnx"), options,
                                            providers=["CPUExecutionProvider"])
        self.inputs = {i.name for i in self.session.get_inputs()}
        self.tokenizer = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
        self.tokenizer.no_truncation()
        self.tokenizer.no_padding()
        config = json.loads((model_dir / "config.json").read_text())
        labels = {int(k): str(v).lower() for k, v in (config.get("id2label") or {}).items()}
        self.injection = next((i for i, name in labels.items() if "inject" in name), 1)
        empty = self.tokenizer.encode("").ids  # the special tokens around every input: <bos> ... <eos>
        self.prefix, self.suffix = empty[:1], empty[1:]
        self.window = max(32, window - len(empty))
        self.step = max(1, self.window - max(0, min(overlap, self.window // 2)))

    def _score(self, ids: list[int]) -> float:
        np = self.np
        batch = np.array([self.prefix + ids + self.suffix], dtype=np.int64)
        feeds = {"input_ids": batch, "attention_mask": np.ones_like(batch)}
        logits = self.session.run(None, {k: v for k, v in feeds.items() if k in self.inputs})[0][0]
        logits = logits.astype(np.float64)
        probs = np.exp(logits - logits.max())
        return float(probs[self.injection] / probs.sum())

    def scan(self, text: str) -> dict:
        encoding = self.tokenizer.encode(text, add_special_tokens=False)
        ids, offsets = encoding.ids, encoding.offsets
        if not ids:
            return {"score": 0.0, "start": 0, "end": 0}
        best = {"score": -1.0, "start": 0, "end": 0}
        start = 0
        while True:
            end = min(len(ids), start + self.window)
            score = self._score(ids[start:end])
            if score > best["score"]:
                best = {"score": score, "start": offsets[start][0], "end": offsets[end - 1][1]}
            if end >= len(ids):
                return best
            start += self.step


def main(argv: list[str]) -> int:
    model_dir, window, overlap, threads = Path(argv[1]), int(argv[2]), int(argv[3]), int(argv[4])
    sys.stdout = sys.stderr  # stdout is the channel; stray prints go to Doorman's log
    # before onnxruntime starts any thread: it reads Python and the model, writes nothing, no network
    if len(argv) > 5 and argv[5] == "sandbox" and \
            not lock_down([str(model_dir), "/proc/cpuinfo", "/sys/devices/system/cpu"], "scanner"):
        return 1
    try:
        scanner = Scanner(model_dir, window, overlap, threads)
    except Exception as exc:  # noqa: BLE001 - reported to Doorman, which lists it
        respond({"error": f"{type(exc).__name__}: {exc}"})
        return 1
    respond({"ready": True, "pid": os.getpid()})
    for line in sys.stdin:
        try:
            request = json.loads(line)
            respond({"results": [scanner.scan(str(t)) for t in request.get("texts", [])]})
        except Exception as exc:  # noqa: BLE001
            respond({"error": f"{type(exc).__name__}: {exc}"})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
