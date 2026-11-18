"""The egress observer: which process in the agent's container opened a connection, and the tripwire on the decoy
keys (doorman/egress/observer.py). Runs against a fake /proc tree in the kernel's formats, with real inotify."""

import ipaddress
import json
import os
import threading
import time
import urllib.error
import urllib.request

import pytest

from doorman.egress import observer

HEAD = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
HEAD6 = ("  sl  local_address                         remote_address                        st tx_queue rx_queue "
         "tr tm->when retrnsmt   uid  timeout inode\n")


def kernel_hex(ip: str) -> str:
    # /proc/net/tcp prints each 32-bit word of the address in host (little-endian) order
    packed = ipaddress.ip_address(ip).packed
    return "".join(packed[i:i + 4][::-1].hex().upper() for i in range(0, len(packed), 4))


def row(n: int, local: str, remote: str, inode: int, state: str = "01") -> str:
    return (f"{n:4}: {local} {remote} {state} 00000000:00000000 00:00000000 00000000  1000        0 {inode} 1 "
            f"0000000000000000 20 4 30 10 -1\n")


def process(proc, pid: int, ppid: int, comm: str, argv: list[str], exe: str | None, fds: dict[int, str]):
    d = proc / str(pid)
    (d / "fd").mkdir(parents=True)
    (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
    (d / "stat").write_text(f"{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 4194560 120 0 0 0 0 0 0 0 20 0 1 0\n")
    if exe:
        os.symlink(exe, d / "exe")
    for fd, target in fds.items():
        os.symlink(target, d / "fd" / str(fd))


@pytest.fixture
def proc(tmp_path):
    root = tmp_path / "proc"
    process(root, 1, 0, "hermes", ["hermes", "gateway", "run"], "/usr/local/bin/hermes",
            {0: "/dev/null", 5: "socket:[777]"})
    process(root, 42, 1, "bash -c (x)", ["/bin/bash", "-c", "curl -s https://example.org/x | jq ."], "/bin/bash",
            {0: "pipe:[11]", 4: "socket:[23456]"})
    process(root, 77, 42, "curl", ["curl", "-s", "https://example.org/x"], "/usr/bin/curl",
            {0: "/dev/null", 1: "pipe:[11]", 3: "socket:[12345]"})
    process(root, 78, 42, "sleep", ["sleep", "x" * 400], None, {})  # no exe link readable, long argv
    (root / "self").mkdir()  # not a pid: ignored
    net = root / "1" / "net"
    net.mkdir()
    (net / "tcp").write_text(HEAD
                             + row(0, "0100007F:1F90", "00000000:0000", 777, state="0A")
                             + row(1, "0200200A:A1B2", "5DB8D822:01BB", 12345)
                             + row(2, "0200200A:A1B3", "5DB8D822:01BB", 0, state="06"))  # TIME_WAIT: no inode
    (net / "tcp6").write_text(HEAD6
                              + row(0, kernel_hex("fd00::2") + ":C3D4", kernel_hex("2606:2800:220:1::1946") + ":01BB",
                                    23456)
                              + row(1, kernel_hex("::ffff:10.32.0.2") + ":B000",
                                    kernel_hex("::ffff:93.184.215.14") + ":0050", 12345))
    return str(root)


def test_kernel_hex_matches_the_plan():
    assert kernel_hex("34.216.184.93") == "5DB8D822"


def test_lookup_finds_process_and_chain(proc):
    found = observer.lookup(proc, 0xA1B2, "34.216.184.93", 443)
    assert found == {
        "pid": 77, "exe": "/usr/bin/curl", "cmdline": "curl -s https://example.org/x",
        "chain": [{"pid": 42, "cmdline": "/bin/bash -c curl -s https://example.org/x | jq ."},
                  {"pid": 1, "cmdline": "hermes gateway run"}],
    }
    # the remote end has to match too, not only the local port
    assert observer.lookup(proc, 0xA1B2, "34.216.184.94", 443) is None
    assert observer.lookup(proc, 0xA1B2, "34.216.184.93", 80) is None


def test_lookup_tcp6(proc):
    found = observer.lookup(proc, 0xC3D4, "2606:2800:220:1::1946", 443)
    assert found["pid"] == 42 and found["exe"] == "/bin/bash"
    assert found["chain"] == [{"pid": 1, "cmdline": "hermes gateway run"}]
    # an IPv4 connection from a dual-stack socket shows up in tcp6 as ::ffff:a.b.c.d
    assert observer.lookup(proc, 0xB000, "93.184.215.14", 80)["pid"] == 77


def test_lookup_none_when_no_socket(proc):
    assert observer.lookup(proc, 0x1234, "34.216.184.93", 443) is None
    assert observer.lookup(proc, 0xA1B3, "34.216.184.93", 443) is None  # TIME_WAIT, inode 0
    assert observer.lookup(proc, 0xA1B2, "not an ip", 443) is None
    assert observer.lookup(proc + "/missing", 0xA1B2, "34.216.184.93", 443) is None


def test_lookup_socket_without_process(proc, tmp_path):
    os.remove(os.path.join(proc, "77", "fd", "3"))
    assert observer.lookup(proc, 0xA1B2, "34.216.184.93", 443) is None


def test_cmdline_is_cut_and_exe_may_be_missing(proc):
    info = observer.process_info(proc, 78)
    assert info["exe"] is None and len(info["cmdline"]) == 300 and info["cmdline"].startswith("sleep xxx")
    assert info["chain"][0]["pid"] == 42


def get(url: str) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_serve_lookup_endpoint(proc):
    server = observer.make_server(proc, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        assert get(base + "/health") == (200, {"ok": True, "tripwire": None})  # no decoy file to watch
        status, body = get(base + f"/lookup?port={0xA1B2}&dst=34.216.184.93:443")
        assert status == 200 and body["pid"] == 77 and body["chain"][-1]["pid"] == 1
        status, body = get(base + f"/lookup?port={0xC3D4}&dst=[2606:2800:220:1::1946]:443")
        assert status == 200 and body["pid"] == 42
        assert get(base + "/lookup?port=1&dst=34.216.184.93:443") == (404, {})
        assert get(base + "/lookup?port=x&dst=34.216.184.93:443")[0] == 400
        assert get(base + "/lookup?port=1")[0] == 400
        assert get(base + "/nope")[0] == 404
    finally:
        server.shutdown()
        server.server_close()


# ---- the decoy tripwire (real inotify on a fake /proc/1/root) ----------------------------------------------------

DECOY = "/opt/data/.config/secrets/api-keys.env"

FIB_TRIE = """Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 172.29.0.0/24 2 0 2
        |-- 172.29.0.0
           /24 link UNICAST
        |-- 172.29.0.130
           /32 host LOCAL
        |-- 172.29.0.255
           /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        |-- 127.0.0.1
           /32 host LOCAL
     |-- 172.29.0.130
        /32 host LOCAL
"""


@pytest.fixture
def agent_root(tmp_path):
    """A fake proc root whose 1/root holds the agent's file system with the decoy file (0444)."""
    proc = tmp_path / "proc"
    secrets = proc / "1" / "root" / "opt" / "data" / ".config" / "secrets"
    secrets.mkdir(parents=True)
    write_decoy(secrets / "api-keys.env", "OPENAI_API_KEY=sk-proj-one\n")
    (proc / "1" / "net").mkdir()
    (proc / "1" / "net" / "fib_trie").write_text(FIB_TRIE)
    return proc, secrets


def write_decoy(path, content):
    """As the proxy writes it: a temporary file in the folder, 0444, renamed over the old one."""
    tmp = path.parent / f".{path.name}.tmp"
    tmp.write_text(content)
    os.chmod(tmp, 0o444)
    os.replace(tmp, path)


def watching(proc, **kw):
    events = observer.EventLog(start=0)
    watch = observer.DecoyWatch(str(proc), DECOY, events, **kw)
    return watch, events


def names(events):
    return [e["event"] for e in events.since(0)["events"]]


def pump(watch, events, until=None, seconds=1.0):
    """Runs the watcher in this thread until `until(event names)` or `seconds` pass; returns the names."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        watch.step(0.05)
        if until and until(names(events)):
            break
    return names(events)


def test_reading_the_decoy_file_fires_open_then_access(agent_root):
    proc, secrets = agent_root
    watch, events = watching(proc)
    assert watch.arm()
    assert pump(watch, events, seconds=0.3) == []  # arming opened nothing
    with open(secrets / "api-keys.env") as f:
        f.read()
    assert pump(watch, events, until=lambda n: "access" in n) == ["open", "access"]
    first, second = events.since(0)["events"]
    assert first["path"] == DECOY and first["client_ip"] == "172.29.0.130"
    assert second["seq"] == first["seq"] + 1 and second["ts"] >= first["ts"]


def test_listing_the_folder_fires_dir_open_only(agent_root):
    proc, secrets = agent_root
    watch, events = watching(proc)
    assert watch.arm()
    os.listdir(secrets)
    assert pump(watch, events, until=bool) == ["dir_open"]
    assert events.since(0)["events"][0]["path"] == os.path.dirname(DECOY)
    os.stat(secrets / "api-keys.env")  # a stat (ls -l) opens nothing
    assert pump(watch, events, seconds=0.3) == ["dir_open"]


def test_replacing_the_file_rearms_without_an_alarm(agent_root):
    proc, secrets = agent_root
    watch, events = watching(proc)
    assert watch.arm()
    old = watch.file_wd
    write_decoy(secrets / "api-keys.env", "OPENAI_API_KEY=sk-proj-two\n")
    assert pump(watch, events, seconds=0.5) == []
    assert watch.armed and watch.file_wd != old
    with open(secrets / "api-keys.env") as f:
        f.read()
    assert pump(watch, events, until=lambda n: "access" in n) == ["open", "access"]


def test_an_open_before_the_new_file_is_watched_still_counts(agent_root):
    """New keys renamed over the file (or switched on again) and opened before the observer sets the new
    file's watch: only the folder's watch saw the open, and that is enough."""
    proc, secrets = agent_root
    watch, events = watching(proc, rearm_every=0.2)
    assert watch.arm()
    write_decoy(secrets / "api-keys.env", "OPENAI_API_KEY=sk-proj-two\n")
    with open(secrets / "api-keys.env") as f:  # before the watcher handled the rename
        f.read()
    assert pump(watch, events, until=lambda n: "access" in n) == ["open", "access"]
    assert watch.armed
    os.remove(secrets / "api-keys.env")  # switched off ...
    pump(watch, events, seconds=0.3)
    write_decoy(secrets / "api-keys.env", "X=3\n")  # ... and on again, opened at once
    (secrets / "api-keys.env").read_text()
    assert pump(watch, events, until=lambda n: n.count("access") == 2, seconds=2) == ["open", "access"] * 2


def test_one_open_seen_by_both_watches_is_one_event(agent_root, monkeypatch):
    monkeypatch.setattr(observer, "REPEAT_WITHIN", 0)  # the event log merges nothing: only the pairing counts
    proc, secrets = agent_root
    watch, events = watching(proc)
    assert watch.arm()
    for _ in range(3):  # the file's own watch and its folder's both report each open and read
        with open(secrets / "api-keys.env") as f:
            f.read()
    assert pump(watch, events, until=lambda n: len(n) >= 6, seconds=1) == ["open", "access"] * 3
    assert pump(watch, events, seconds=0.2) == ["open", "access"] * 3
    # by hand, in either order; the folder's watch alone still counts, the proxy's temporary file doesn't
    log = observer.EventLog(start=0)
    by_hand = observer.DecoyWatch(str(proc), DECOY, log)
    by_hand.file_wd, by_hand.dir_wd = 1, 2
    for wd, mask, name in ((2, observer.IN_OPEN, "api-keys.env"), (1, observer.IN_OPEN, ""),
                           (1, observer.IN_ACCESS, ""), (2, observer.IN_ACCESS, "api-keys.env"),
                           (2, observer.IN_OPEN, ".api-keys.env.7.tmp"), (2, observer.IN_OPEN, "api-keys.env")):
        by_hand.handle(wd, mask, name)
    by_hand._inotify.close()
    assert [e["event"] for e in log.since(0)["events"]] == ["open", "access", "open"]


def test_a_missing_file_is_watched_once_it_appears(agent_root):
    proc, secrets = agent_root
    os.remove(secrets / "api-keys.env")
    watch, events = watching(proc, rearm_every=0.2)
    assert not watch.arm() and watch.dir_wd is not None and watch.file_wd is None
    assert "No such file" in watch.last_error
    write_decoy(secrets / "api-keys.env", "X=1\n")  # appears (the proxy wrote the keys)
    pump(watch, events, seconds=0.3)
    assert watch.armed and names(events) == []
    os.remove(secrets / "api-keys.env")  # removed (decoys switched off): no alarm, waits for it again
    pump(watch, events, seconds=0.3)
    assert watch.file_wd is None and names(events) == []
    write_decoy(secrets / "api-keys.env", "X=2\n")
    pump(watch, events, seconds=0.3)
    assert watch.armed
    with open(secrets / "api-keys.env") as f:
        f.read()
    assert pump(watch, events, until=lambda n: "access" in n) == ["open", "access"]


def test_a_missing_folder_is_tried_again(agent_root, monkeypatch):
    proc, secrets = agent_root
    hidden = proc / "1" / "root-later"
    os.rename(proc / "1" / "root", hidden)  # the agent restarting: nothing at the path yet
    watch, events = watching(proc, rearm_every=0.1)
    assert not watch.arm() and watch.dir_wd is None
    tries = []
    real_arm = watch.arm
    monkeypatch.setattr(watch, "arm", lambda: tries.append(1) or real_arm())
    pump(watch, events, seconds=0.35)
    assert len(tries) >= 2 and not watch.armed
    os.rename(hidden, proc / "1" / "root")
    pump(watch, events, seconds=0.3)
    assert watch.armed
    with open(secrets / "api-keys.env") as f:
        f.read()
    assert pump(watch, events, until=lambda n: "access" in n) == ["open", "access"]


def test_a_long_read_is_one_event(agent_root):
    proc, secrets = agent_root
    write_decoy(secrets / "api-keys.env", "K=" + "x" * 200_000 + "\n")
    watch, events = watching(proc)
    assert watch.arm()
    with open(secrets / "api-keys.env", "rb", buffering=0) as f:
        while f.read(4096):
            pass
    assert pump(watch, events, seconds=0.3) == ["open", "access"]


def test_the_watcher_thread_starts_and_stops(agent_root):
    proc, secrets = agent_root
    watch, events = watching(proc)
    thread = watch.start()
    try:
        deadline = time.monotonic() + 2
        while not watch.armed and time.monotonic() < deadline:
            time.sleep(0.02)
        assert watch.armed
        time.sleep(0.2)
        assert names(events) == []
        (secrets / "api-keys.env").read_text()
        deadline = time.monotonic() + 2
        while "access" not in names(events) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert names(events) == ["open", "access"]
    finally:
        watch.stop()
        thread.join(3)
    assert not thread.is_alive()


def test_agent_ip_from_fib_trie_or_override(agent_root, tmp_path):
    proc, secrets = agent_root
    assert observer.agent_ip(str(proc)) == "172.29.0.130"
    assert observer.agent_ip(str(proc), "10.0.0.9") == "10.0.0.9"
    assert observer.agent_ip(str(tmp_path / "nothing")) is None
    (proc / "1" / "net" / "fib_trie").write_text("Main:\n  |-- 127.0.0.1\n     /32 host LOCAL\n")
    assert observer.agent_ip(str(proc)) is None
    watch, events = watching(proc, ip_override="172.29.0.200")
    assert watch.arm()
    os.listdir(secrets)
    pump(watch, events, until=bool)
    assert events.since(0)["events"][0]["client_ip"] == "172.29.0.200"


def test_event_log_pages_and_merges_repeats():
    log = observer.EventLog(maxlen=5, start=100)
    assert log.add("open", DECOY, "172.29.0.130", ts=1000.0)["seq"] == 101
    assert log.add("access", DECOY, "172.29.0.130", ts=1000.1)["seq"] == 102
    assert log.add("access", DECOY, "172.29.0.130", ts=1001.0) is None  # the same read going on
    assert log.add("access", DECOY, "172.29.0.130", ts=1003.0)["seq"] == 103
    for n in range(4):
        log.add("dir_open", f"/d{n}", None, ts=1010.0 + n)
    page = log.since(0)
    assert [e["seq"] for e in page["events"]] == [103, 104, 105, 106, 107] and page["next"] == 107  # bounded
    later = log.since(105)
    assert [e["seq"] for e in later["events"]] == [106, 107] and later["next"] == 107
    assert log.since(107) == {"events": [], "next": 107}
    assert [e["seq"] for e in log.since(5000)["events"]] == [103, 104, 105, 106, 107]  # the observer restarted
    two = log.since(0, limit=2)
    assert [e["seq"] for e in two["events"]] == [103, 104] and two["next"] == 104
    assert observer.EventLog().last >= int(time.time() * 1000) - 1000  # numbers grow across restarts


def test_serve_events_endpoint(proc):
    events = observer.EventLog(start=0)
    events.add("open", DECOY, "172.29.0.130", ts=1.0)
    events.add("access", DECOY, "172.29.0.130", ts=1.5)
    server = observer.make_server(proc, "127.0.0.1", 0, events)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        status, body = get(base + "/events?since=0")
        assert status == 200 and [e["event"] for e in body["events"]] == ["open", "access"]
        assert body["events"][0] == {"seq": 1, "ts": 1.0, "event": "open", "path": DECOY,
                                     "client_ip": "172.29.0.130"}
        assert body["next"] == 2
        assert get(base + "/events?since=2") == (200, {"events": [], "next": 2})
        assert get(base + "/events?since=1")[1]["events"][0]["event"] == "access"
        assert get(base + "/events?since=x")[0] == 400
        assert get(base + f"/lookup?port={0xA1B2}&dst=34.216.184.93:443")[0] == 200  # lookups still work
    finally:
        server.shutdown()
        server.server_close()
    bare = observer.make_server(proc, "127.0.0.1", 0)  # no tripwire: no events, never an error
    threading.Thread(target=bare.serve_forever, daemon=True).start()
    try:
        assert get(f"http://127.0.0.1:{bare.server_address[1]}/events?since=7") == (200, {"events": [], "next": 7})
    finally:
        bare.shutdown()
        bare.server_close()


def test_health_says_whether_the_tripwire_is_armed(agent_root, monkeypatch):
    proc, secrets = agent_root
    watch, events = watching(proc, rearm_every=0.1)
    server = observer.make_server(str(proc), "127.0.0.1", 0, events, watch)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def tripwire(until=None):
        deadline = time.monotonic() + 2
        while True:
            body = get(base + "/health")[1]
            if until is None or until(body["tripwire"]) or time.monotonic() > deadline:
                return body["tripwire"]
            time.sleep(0.02)

    try:
        assert tripwire() == {"armed": False, "last_error": "the watch isn't running", "path": DECOY}
        watch.start()
        assert tripwire(lambda t: t["armed"]) == {"armed": True, "last_error": None, "path": DECOY}
        os.remove(secrets / "api-keys.env")  # decoy keys switched off, or AGENT_HOME isn't the agent's home
        off = tripwire(lambda t: not t["armed"] and t["last_error"])  # the watch drops, then the error is set
        assert off["armed"] is False and "No such file" in off["last_error"]
        write_decoy(secrets / "api-keys.env", "X=1\n")
        assert tripwire(lambda t: t["armed"])["armed"] is True
        # the watch failing doesn't end its thread quietly: health says so, and it tries again
        monkeypatch.setattr(watch._inotify, "read", lambda timeout: 1 / 0)
        broken = tripwire(lambda t: not t["armed"] and "failed" in (t["last_error"] or ""))
        assert broken["armed"] is False and "the watch failed" in broken["last_error"]
        monkeypatch.undo()
        assert tripwire(lambda t: t["armed"])["armed"] is True
    finally:
        watch.stop()
        server.shutdown()
        server.server_close()
