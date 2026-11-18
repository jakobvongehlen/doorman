"""What keeps plugins and the helper processes (extractor, guard, embedder) apart from Doorman, and Doorman from
what a sidecar puts in a shared volume: the closed network's corners, files read from another container,
helpers that can't lock themselves down."""

import ctypes
import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from doorman import sandbox
from doorman.plugin_host import harden_data_dir
from doorman.worker_process import Worker, WorkerUnavailable, share_with_helper
from conftest import make_engine

ROOT = Path(__file__).resolve().parent.parent


def has_libseccomp() -> bool:
    try:
        ctypes.CDLL("libseccomp.so.2")
        return True
    except OSError:
        return False


needs_sandbox = pytest.mark.skipif(sandbox.landlock_abi() < 4 or not has_libseccomp(),
                                   reason="needs Landlock 4 (Linux 6.7+) and libseccomp")

# ------------------------------------------------------------------ the closed network

# Runs in a fresh process: locks itself down with the network closed, then tries every way to a TCP listener
# that Landlock's connect() check doesn't see, and what a plugin legitimately does with sockets.
NETWORK_PROBE = r"""
import ctypes, json, os, socket, struct, sys
from doorman import sandbox

port = int(sys.argv[1])
target = ("127.0.0.1", port)
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
sandbox.lock_down(None, [], close_network=True, forbidden=[])

def raw_socket(family, kind, protocol):
    fd = libc.syscall(ctypes.c_long(41), ctypes.c_long(family), ctypes.c_long(kind), ctypes.c_long(protocol))
    if fd < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return socket.socket(fileno=fd)

def sendmmsg_fastopen():
    sock = socket.socket()
    address = struct.pack("=H", socket.AF_INET) + struct.pack("!H4s8x", port, socket.inet_aton("127.0.0.1"))
    name, data = ctypes.create_string_buffer(address, len(address)), ctypes.create_string_buffer(b"x", 1)
    class IOVec(ctypes.Structure):
        _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
    class MsgHdr(ctypes.Structure):
        _fields_ = [("name", ctypes.c_void_p), ("namelen", ctypes.c_uint32), ("iov", ctypes.c_void_p),
                    ("iovlen", ctypes.c_size_t), ("control", ctypes.c_void_p), ("controllen", ctypes.c_size_t),
                    ("flags", ctypes.c_int)]
    class MMsgHdr(ctypes.Structure):
        _fields_ = [("hdr", MsgHdr), ("len", ctypes.c_uint)]
    iov = IOVec(ctypes.cast(data, ctypes.c_void_p), 1)
    message = MMsgHdr(MsgHdr(ctypes.cast(name, ctypes.c_void_p), len(address),
                             ctypes.cast(ctypes.pointer(iov), ctypes.c_void_p), 1, None, 0, 0), 0)
    number = {"x86_64": 307, "aarch64": 269}[os.uname().machine]
    if libc.syscall(ctypes.c_long(number), ctypes.c_long(sock.fileno()), ctypes.byref(message), ctypes.c_long(1),
                    ctypes.c_long(0x20000000)) < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))

def fastopen_connect():
    sock = socket.socket()
    sock.setsockopt(socket.IPPROTO_TCP, 30, 1)
    sock.connect(target)
    sock.send(b"x")

attempts = {
    "connect": lambda: socket.socket().connect(target),
    "mptcp": lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262).connect(target),
    "mptcp_v6": lambda: socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 262),
    "sctp": lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132),
    "fastopen_sendto": lambda: socket.socket().sendto(b"x", 0x20000000, target),
    "fastopen_sendmsg": lambda: socket.socket().sendmsg([b"x"], [], 0x20000000, target),
    "fastopen_sendmmsg": sendmmsg_fastopen,
    "fastopen_connect": fastopen_connect,
    "udp": lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
    "udp_upper_bits": lambda: raw_socket(0x100000002, socket.SOCK_DGRAM, 0),
    "mptcp_upper_bits": lambda: raw_socket(socket.AF_INET, socket.SOCK_STREAM, 0x100000000 | 262).connect(target),
    "listen_without_bind": lambda: socket.socket().listen(1),
    "bind": lambda: socket.socket().bind(("127.0.0.1", 0)),
}
legit = {
    "tcp_socket": lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC,
                                        socket.IPPROTO_TCP),
    "tcp6_socket": lambda: socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0),
    "nodelay": lambda: socket.socket().setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
    "unix_pair": lambda: [s.sendall(b"x") for s in socket.socketpair()],
    "unix_socket": lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM),
}
out = {}
for name, attempt in {**attempts, **legit}.items():
    try:
        attempt()
        out[name] = "ok"
    except OSError as exc:
        out[name] = f"errno {exc.errno}"
print(json.dumps(out))
"""


@needs_sandbox
def test_a_closed_network_has_no_way_around_landlock():
    """Landlock 4 to 6 check connect() and bind() on plain TCP sockets only. MPTCP and SCTP stream sockets,
    TCP Fast Open (sendto with MSG_FASTOPEN connects without connect()) and listen() on an unbound socket went
    past it; socket() with the upper bits of its arguments set went past the old seccomp rules."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    listener.settimeout(0.5)
    done = subprocess.run([sys.executable, "-c", NETWORK_PROBE, str(listener.getsockname()[1])], cwd=ROOT,
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    out = json.loads(done.stdout)
    accepted = 0
    try:
        while True:
            listener.accept()[0].close()
            accepted += 1
    except (socket.timeout, BlockingIOError):
        pass
    finally:
        listener.close()
    assert accepted == 0
    refused = {name: result for name, result in out.items()
               if name not in ("tcp_socket", "tcp6_socket", "nodelay", "unix_pair", "unix_socket")}
    assert all(result.startswith("errno") for result in refused.values()), refused
    assert out["tcp_socket"] == out["tcp6_socket"] == out["nodelay"] == out["unix_pair"] == "ok", out
    assert out["unix_socket"] == "ok", out


# ------------------------------------------------------------------ files another container controls

def whatsapp_with_token_at(tmp_path, token_file):
    engine = make_engine(tmp_path, plugins={"whatsapp": {"enabled": True}})
    engine.registry.types["whatsapp"].manifest["credential_files"] = {"sidecar_token": str(token_file)}
    return engine


def import_within(engine, seconds=5.0) -> list:
    """import_credential_files in a thread: a FIFO used to block Doorman's worker for good."""
    out: list = []
    thread = threading.Thread(target=lambda: out.append(engine.registry.import_credential_files()), daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), "reading the credential file blocked"
    return out[0]


def test_the_sidecars_token_file_is_a_plain_small_file_and_nothing_else(tmp_path, caplog):
    """The WhatsApp sidecar controls the volume its token file is in. A link there to the vault key would make
    Doorman store the key as the token and send it to the sidecar as a Bearer header; a FIFO would block the
    worker; /dev/zero would eat memory."""
    volume = tmp_path / "volume"
    volume.mkdir()
    token_file = volume / "token"
    engine = whatsapp_with_token_at(tmp_path, token_file)
    secret = tmp_path / "data" / "vault.key"
    secret.write_text("the-vault-key\n")

    def stored():
        return engine.vault.get("whatsapp").get("sidecar_token")

    token_file.symlink_to(secret)
    assert import_within(engine) == [] and stored() is None
    token_file.unlink()
    token_file.symlink_to("/dev/zero")
    assert import_within(engine) == [] and stored() is None
    token_file.unlink()
    os.mkfifo(token_file)
    assert import_within(engine) == [] and stored() is None
    token_file.unlink()
    token_file.write_text("x" * 5000)
    assert import_within(engine) == [] and stored() is None
    token_file.write_text("two words\n")
    assert import_within(engine) == [] and stored() is None
    assert import_within(engine) == []
    assert sum("not taking sidecar_token" in r.getMessage() for r in caplog.records) == 4  # once per problem

    # a folder on the way swapped for a link: the file behind it isn't read either
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "token").write_text("from-elsewhere\n")
    (volume / "sub").symlink_to(elsewhere)
    engine.registry.types["whatsapp"].manifest["credential_files"] = {"sidecar_token": str(volume / "sub" / "token")}
    assert import_within(engine) == [] and stored() is None

    engine.registry.types["whatsapp"].manifest["credential_files"] = {"sidecar_token": str(token_file)}
    token_file.write_text("generated-token-1\n")
    assert import_within(engine) == [("whatsapp", "sidecar_token")] and stored() == "generated-token-1"


# ------------------------------------------------------------------ helper processes

@pytest.mark.parametrize("module, args, what", [
    ("doorman.extract_worker", ["200", "20", "sandbox", "mem=0"], "text extractor"),
    ("doorman.guard_worker", ["/nonexistent-model", "512", "64", "1", "sandbox"], "scanner"),
    ("doorman.embed_worker", ["/nonexistent-model", "512", "sandbox"], "embedding model"),
])
def test_a_helper_that_cant_lock_itself_down_doesnt_start(module, args, what):
    """The extractor, the scanner and the embedding model parse a stranger's bytes. They used to go on without
    the sandbox when the kernel couldn't give it; now they refuse, as a plugin does."""
    with pytest.raises(WorkerUnavailable, match=f"the {what} can't lock itself down, so it doesn't start: "
                                                "this kernel has no Landlock"):
        Worker("tests.no_landlock_child", [module, *args], what).start(timeout=60)


def test_the_extractor_says_why_it_read_nothing(monkeypatch):
    from doorman import extractor

    real = extractor.Worker
    monkeypatch.setattr(extractor, "Worker", lambda module, args, what, **kw:
                        real("tests.no_landlock_child", [module, *args], what, **kw))
    reader = extractor.Extractor({"plugin_sandbox": True})
    out = reader.extract("note.txt", b"hello", "text/plain")
    assert out["text"] == "" and "can't lock itself down" in out["note"] and "plugin_sandbox: false" in out["note"]
    assert "can't lock itself down" in reader.last_error


def test_a_helpers_model_is_readable_for_its_own_user_and_nothing_else_opens_up(tmp_path):
    data = tmp_path / "data"
    model = data / "models" / "some-model"
    model.mkdir(parents=True, mode=0o700)
    (data / "models").chmod(0o700)
    (model / "model.onnx").write_bytes(b"weights")
    (model / "model.onnx").chmod(0o600)
    (model / "elsewhere").symlink_to(data / "vault.key")
    (data / "vault.key").write_text("secret")
    (data / "vault.key").chmod(0o600)
    harden_data_dir(data)
    share_with_helper(model)
    mode = lambda path: oct(path.stat().st_mode & 0o777)  # noqa: E731
    assert (mode(data), mode(data / "models"), mode(model)) == ("0o711", "0o711", "0o755")
    assert mode(model / "model.onnx") == "0o644"
    assert mode(data / "vault.key") == "0o600"  # the link in the model's folder was left alone
    harden_data_dir(data)  # the next start keeps the models folder passable
    assert mode(data / "models") == "0o711"
