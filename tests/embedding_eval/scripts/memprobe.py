"""RSS of an embed worker: python -I memprobe.py <onnx> <tokenizer.json> [order=session|tok] [trim=0|1] [prepack=0|1]
Mirrors embed_worker.py's session options; trim=1 calls glibc malloc_trim(0) after each load step."""
import ctypes, sys, time
from pathlib import Path
def rss():
    d = {l.split(':')[0]: int(l.split()[1]) // 1024 for l in Path('/proc/self/status').read_text().splitlines() if l.startswith(('VmRSS', 'VmHWM', 'RssAnon', 'RssFile', 'VmSwap'))}
    return d
onnx, tok = sys.argv[1], sys.argv[2]
args = dict(a.split('=') for a in sys.argv[3:])
trim = args.get('trim') == '1'
def do_trim():
    if trim:
        ctypes.CDLL('libc.so.6').malloc_trim(0)
import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer
ort.set_default_logger_severity(3)
print('after import', rss())
def load_session():
    o = ort.SessionOptions(); o.intra_op_num_threads = 1; o.inter_op_num_threads = 1
    o.enable_cpu_mem_arena = False; o.enable_mem_pattern = False; o.log_severity_level = 3
    if args.get('prepack') == '0':
        o.add_session_config_entry('session.disable_prepacking', '1')
    s = ort.InferenceSession(onnx, o, providers=['CPUExecutionProvider']); do_trim()
    print('after session', rss()); return s
def load_tok():
    t = Tokenizer.from_file(tok); t.enable_truncation(512); t.no_padding(); do_trim()
    print('after tokenizer', rss()); return t
if args.get('order', 'session') == 'tok':
    t = load_tok(); s = load_session()
else:
    s = load_session(); t = load_tok()
ids = t.encode(' '.join(['Die Vorlesung Statistik II am Donnerstag entfällt wegen Krankheit, the lecture is cancelled.'] * 60)).ids
names = {i.name for i in s.get_inputs()}
b = np.array([ids], dtype=np.int64)
feeds = {k: v for k, v in {'input_ids': b, 'attention_mask': np.ones_like(b), 'token_type_ids': np.zeros_like(b)}.items() if k in names}
ts = []
for _ in range(3):
    t0 = time.perf_counter(); out = s.run(None, feeds); ts.append(time.perf_counter() - t0)
do_trim()
print(f'after 3x {len(ids)} tokens ({min(ts):.3f}s)', rss())
