"""The embedding model's own process: python -m doorman.embed_worker <model dir> <max tokens> [sandbox].

Granite Embedding 107M multilingual (r1, XLM-RoBERTa, uint8 ONNX for AVX2): the graph gives every token's
hidden state, and the first one (CLS) is the text's vector, 384 dimensions, no instruction prefix, at most
512 tokens. One text at a time (no padding, the least memory): about 0.08 s for 200 tokens and 0.3 s for
512 on one core of a small VPS. With its tokenizer it takes about 450 to 500 MB; Doorman stops it when idle.

Protocol: JSON lines. Doorman writes {"texts": [...]}; the worker answers {"vectors": "<base64 float16,
normalized, len(texts) x 384>"}. The first line is {"ready": true, "dim": 384} or {"error": ...}.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

from .worker_process import lock_down, respond


class Embedder:
    def __init__(self, model_dir: Path, max_tokens: int):
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self.np = np
        ort.set_default_logger_severity(3)
        options = ort.SessionOptions()
        options.log_severity_level = 3
        options.intra_op_num_threads = 1
        options.inter_op_num_threads = 1
        options.enable_cpu_mem_arena = False   # give memory back after a long text
        options.enable_mem_pattern = False
        self.session = ort.InferenceSession(str(model_dir / "model.onnx"), options, providers=["CPUExecutionProvider"])
        self.inputs = {i.name for i in self.session.get_inputs()}
        output = self.session.get_outputs()[0]
        self.output = output.name   # last_hidden_state [batch, tokens, 384]; a pooled [batch, 384] works too
        self.pooled = len(output.shape) == 2
        self.dim = int(output.shape[-1])
        self.tokenizer = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
        self.tokenizer.enable_truncation(min(max_tokens, 512))  # 512 positions, <s> and </s> included
        self.tokenizer.no_padding()

    def embed(self, text: str):
        np = self.np
        ids = self.tokenizer.encode(text or " ").ids
        batch = np.array([ids], dtype=np.int64)
        feeds = {"input_ids": batch, "attention_mask": np.ones_like(batch)}
        out = self.session.run([self.output], {k: v for k, v in feeds.items() if k in self.inputs})[0]
        vector = (out[0] if self.pooled else out[0, 0]).astype(np.float32)  # CLS: the first token's state
        norm = float(np.linalg.norm(vector)) or 1.0
        return (vector / norm).astype(np.float16)


def main(argv: list[str]) -> int:
    model_dir, max_tokens = Path(argv[1]), int(argv[2])
    sys.stdout = sys.stderr
    if len(argv) > 3 and argv[3] == "sandbox" and \
            not lock_down([str(model_dir), "/proc/cpuinfo", "/sys/devices/system/cpu"], "embedding model"):
        return 1
    try:
        model = Embedder(model_dir, max_tokens)
    except Exception as exc:  # noqa: BLE001 - reported to Doorman
        respond({"error": f"{type(exc).__name__}: {exc}"})
        return 1
    respond({"ready": True, "dim": model.dim, "pid": os.getpid()})
    np = model.np
    for line in sys.stdin:
        try:
            texts = [str(t) for t in json.loads(line).get("texts", [])]
            vectors = np.stack([model.embed(t) for t in texts]) if texts else np.zeros((0, model.dim), np.float16)
            respond({"vectors": base64.b64encode(vectors.astype("<f2").tobytes()).decode(), "dim": model.dim})
        except Exception as exc:  # noqa: BLE001
            respond({"error": f"{type(exc).__name__}: {exc}"})
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
