"""Re-save an ONNX model with its weights in an external data file, using onnxruntime only (no onnx package).
Usage: python -I extdata.py <in.onnx> <out.onnx>   (writes <out.onnx> and <out.onnx>.data next to it)
Basic graph optimisations only (hardware-independent), so the result is portable."""
import os
import sys

import onnxruntime as ort

src, dst = sys.argv[1], sys.argv[2]
o = ort.SessionOptions()
o.intra_op_num_threads = 1
o.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_BASIC
o.optimized_model_filepath = dst
o.add_session_config_entry("session.optimized_model_external_initializers_file_name", os.path.basename(dst) + ".data")
o.add_session_config_entry("session.optimized_model_external_initializers_min_size_in_bytes", "1024")
ort.InferenceSession(src, o, providers=["CPUExecutionProvider"])
print("wrote", dst, os.path.getsize(dst), dst + ".data", os.path.getsize(dst + ".data"))
