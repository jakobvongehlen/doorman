"""Locks a plugin's process down before the plugin's code loads.

Two Linux kernel features. A process applies both to itself, without root and inside Docker's default
profile. Neither can be lifted afterwards, and every process the plugin starts inherits them.

- Landlock limits files: the plugin reads Python and its own code, and reads and writes its own folder.
  The vault, the database, doorman.yaml and other plugins' folders can't be opened, whatever their
  permissions say. With the network closed it also may not open or accept TCP connections (Landlock 4,
  Linux 6.7); Doorman opens the connections the plugin is allowed and hands them over.
- seccomp refuses system calls a plugin never needs: looking into other processes (ptrace,
  process_vm_readv), mounting, new namespaces, kernel keyrings, BPF, io_uring and the like, which is
  also most of what kernel exploits go through. With the network closed, only local (Unix) sockets and
  plain TCP sockets can be created: no UDP, raw sockets, netlink, MPTCP or SCTP. It also refuses what
  connects or listens past Landlock's check: TCP Fast Open and listen() (which on a socket without an
  address takes a free port; seccomp can't tell a Unix socket from a TCP one there, so it refuses both).

Not covered with the network closed: connecting to a Unix socket by its path, which Landlock (up to ABI 6
at least) doesn't check; file permissions and the plugin's own user still do. `network: any` leaves the
network open.

Both apply to the calling thread only, so they must run before the process starts any thread.
"""

from __future__ import annotations

import ctypes
import errno
import os
import stat
import sys
import sysconfig
import threading
from pathlib import Path


class SandboxError(Exception):
    """The kernel can't give the protection asked for; the plugin doesn't start."""


_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long

# ------------------------------------------------------------------ Landlock

_SYS_CREATE_RULESET, _SYS_ADD_RULE, _SYS_RESTRICT_SELF = 444, 445, 446  # the same on x86_64 and arm64
_CREATE_RULESET_VERSION = 1
_RULE_PATH_BENEATH = 1

FS_EXECUTE = 1 << 0
FS_WRITE_FILE = 1 << 1
FS_READ_FILE = 1 << 2
FS_READ_DIR = 1 << 3
FS_MAKE_CHAR = 1 << 6
FS_MAKE_BLOCK = 1 << 11
FS_REFER = 1 << 13     # ABI 2
FS_TRUNCATE = 1 << 14  # ABI 3
FS_IOCTL_DEV = 1 << 15  # ABI 5
NET_BIND_TCP = 1 << 0  # ABI 4
NET_CONNECT_TCP = 1 << 1
SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0  # ABI 6
SCOPE_SIGNAL = 1 << 1

READ = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR
FILE_RIGHTS = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV  # those a file (not a folder) takes


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64),
                ("scoped", ctypes.c_uint64)]


class _PathBeneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def _syscall(number: int, *args) -> int:
    result = _libc.syscall(ctypes.c_long(number), *args)
    if result < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return int(result)


def landlock_abi() -> int:
    """The Landlock version this kernel has; 0 when it has none (or it is switched off)."""
    result = _libc.syscall(ctypes.c_long(_SYS_CREATE_RULESET), None, ctypes.c_size_t(0),
                           ctypes.c_uint32(_CREATE_RULESET_VERSION))
    return int(result) if result > 0 else 0


def _fs_rights(abi: int) -> int:
    rights = (1 << 13) - 1
    if abi >= 2:
        rights |= FS_REFER
    if abi >= 3:
        rights |= FS_TRUNCATE
    if abi >= 5:
        rights |= FS_IOCTL_DEV
    return rights


def _allow(ruleset: int, path: str, access: int) -> None:
    try:
        fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except FileNotFoundError:
        return
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            access &= FILE_RIGHTS
        rule = _PathBeneath(access, fd)
        _syscall(_SYS_ADD_RULE, ctypes.c_int(ruleset), ctypes.c_int(_RULE_PATH_BENEATH), ctypes.byref(rule),
                 ctypes.c_uint32(0))
    finally:
        os.close(fd)


def no_new_privs() -> None:
    """From here on, no program this process starts gains rights (setuid binaries stay plain)."""
    if _libc.prctl(ctypes.c_int(38), ctypes.c_ulong(1), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)):
        err = ctypes.get_errno()
        raise SandboxError(f"can't set no_new_privs: {os.strerror(err)}")


def restrict_files(read: list[str] | None, write: list[str] | None, *, close_network: bool) -> int:
    """Only `read` (read and run) and `write` (everything) stay reachable; read=None leaves files alone
    and only closes the network. Returns the Landlock version used."""
    abi = landlock_abi()
    if abi < 1:
        raise SandboxError("this kernel has no Landlock (Linux 5.13+, with landlock among the LSMs)")
    if close_network and abi < 4:
        raise SandboxError(f"closing the network needs Landlock 4 (Linux 6.7+); this kernel has {abi}")
    handled_fs = _fs_rights(abi) if read is not None else 0
    attr = _RulesetAttr(handled_fs, (NET_BIND_TCP | NET_CONNECT_TCP) if close_network else 0,
                        (SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL) if abi >= 6 else 0)
    size = 24 if abi >= 6 else 16 if abi >= 4 else 8
    if not handled_fs and not attr.handled_access_net and not attr.scoped:
        return abi
    ruleset = _syscall(_SYS_CREATE_RULESET, ctypes.byref(attr), ctypes.c_size_t(size), ctypes.c_uint32(0))
    try:
        if handled_fs:
            for path in read or []:
                _allow(ruleset, path, READ & handled_fs)
            for path in write or []:
                _allow(ruleset, path, handled_fs & ~(FS_MAKE_CHAR | FS_MAKE_BLOCK))
            for path in DEVICES:
                _allow(ruleset, path, (FS_READ_FILE | FS_WRITE_FILE | FS_IOCTL_DEV) & handled_fs)
        no_new_privs()
        _syscall(_SYS_RESTRICT_SELF, ctypes.c_int(ruleset), ctypes.c_uint32(0))
    finally:
        os.close(ruleset)
    return abi


# ------------------------------------------------------------------ seccomp (through libseccomp)

_ACT_ALLOW = 0x7FFF0000
_CMP_EQ, _CMP_GT, _CMP_MASKED_EQ = 4, 6, 7
AF_UNIX, AF_INET, AF_INET6 = 1, 2, 10
_SOCK_TYPES_REFUSED = (2, 3, 4, 5, 6, 10)  # dgram, raw, rdm, seqpacket, dccp, packet: TCP only
IPPROTO_TCP, TCP_FASTOPEN_CONNECT, MSG_FASTOPEN = 6, 30, 0x20000000
_INT = 0xFFFFFFFF  # seccomp sees 64-bit registers; the kernel reads socket()'s and setsockopt()'s ints as 32 bits
_CLONE_NAMESPACES = (0x00020000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000)

# Refused for every plugin. Docker's own profile already refuses many of these; listing them keeps a
# doorman that runs outside Docker just as tight.
REFUSED = (
    "ptrace", "process_vm_readv", "process_vm_writev", "pidfd_getfd", "kcmp",
    "mount", "umount2", "pivot_root", "chroot", "move_mount", "open_tree", "fsopen", "fsconfig", "fsmount",
    "fspick", "mount_setattr", "unshare", "setns",
    "bpf", "perf_event_open", "userfaultfd", "keyctl", "add_key", "request_key",
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    "kexec_load", "kexec_file_load", "init_module", "finit_module", "delete_module", "reboot",
    "swapon", "swapoff", "acct", "quotactl", "quotactl_fd", "lookup_dcookie", "open_by_handle_at",
    "name_to_handle_at", "syslog", "vhangup", "uselib", "settimeofday", "clock_settime", "clock_adjtime",
    "iopl", "ioperm", "fanotify_init",
)


class _ArgCmp(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int), ("datum_a", ctypes.c_uint64),
                ("datum_b", ctypes.c_uint64)]


def _errno_action(code: int) -> int:
    return 0x00050000 | (code & 0xFFFF)


def _libseccomp():
    try:
        lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    except OSError:
        raise SandboxError("libseccomp isn't installed (apt install libseccomp2)") from None
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_rule_add_array.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint,
                                           ctypes.POINTER(_ArgCmp)]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_load.restype = ctypes.c_int
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    return lib


def restrict_syscalls(*, close_network: bool) -> None:
    lib = _libseccomp()
    ctx = lib.seccomp_init(_ACT_ALLOW)
    if not ctx:
        raise SandboxError("seccomp_init failed")

    def rule(name: str, action: int, *compare: _ArgCmp) -> None:
        number = lib.seccomp_syscall_resolve_name(name.encode())
        if number == -1:  # unknown to this libseccomp: the kernel can't have it either
            return
        array = (_ArgCmp * len(compare))(*compare) if compare else None
        result = lib.seccomp_rule_add_array(ctx, action, number, len(compare), array)
        if result < 0 and number >= 0:
            raise SandboxError(f"seccomp rule for {name}: {os.strerror(-result)}")

    try:
        refuse = _errno_action(errno.EPERM)
        for name in REFUSED:
            rule(name, refuse)
        for flag in _CLONE_NAMESPACES:  # threads and processes, yes; new namespaces, no
            rule("clone", refuse, _ArgCmp(0, _CMP_MASKED_EQ, flag, flag))
        rule("clone3", _errno_action(errno.ENOSYS))  # its flags sit behind a pointer; glibc falls back to clone
        if close_network:
            # Landlock (up to ABI 6 at least) checks only connect() and bind() on plain TCP sockets. What goes
            # past it is refused here: other protocols over stream sockets (MPTCP, SCTP), TCP Fast Open (it
            # connects inside sendto/sendmsg) and listen() on a socket without an address (it takes a free port).
            no_socket = _errno_action(errno.EACCES)
            for arg in (0, 1, 2):  # upper bits set: the kernel ignores them, the rules below wouldn't match
                rule("socket", no_socket, _ArgCmp(arg, _CMP_GT, _INT, 0))
            for family in range(64):
                if family not in (AF_UNIX, AF_INET, AF_INET6):
                    rule("socket", no_socket, _ArgCmp(0, _CMP_EQ, family, 0))
            for family in (AF_INET, AF_INET6):
                for kind in _SOCK_TYPES_REFUSED:
                    rule("socket", no_socket, _ArgCmp(0, _CMP_EQ, family, 0), _ArgCmp(1, _CMP_MASKED_EQ, 0xF, kind))
                # protocol 0 or IPPROTO_TCP only: MPTCP is 262, SCTP 132
                rule("socket", no_socket, _ArgCmp(0, _CMP_EQ, family, 0), _ArgCmp(2, _CMP_GT, IPPROTO_TCP, 0))
                for protocol in range(1, IPPROTO_TCP):
                    rule("socket", no_socket, _ArgCmp(0, _CMP_EQ, family, 0), _ArgCmp(2, _CMP_EQ, protocol, 0))
            for name, flags in (("sendto", 3), ("sendmsg", 2), ("sendmmsg", 3)):
                rule(name, no_socket, _ArgCmp(flags, _CMP_MASKED_EQ, MSG_FASTOPEN, MSG_FASTOPEN))
            rule("setsockopt", no_socket, _ArgCmp(1, _CMP_MASKED_EQ, _INT, IPPROTO_TCP),
                 _ArgCmp(2, _CMP_MASKED_EQ, _INT, TCP_FASTOPEN_CONNECT))
            rule("listen", no_socket)  # it can't tell a TCP socket from a Unix one; plugins only get connections
        result = lib.seccomp_load(ctx)
        if result < 0:
            raise SandboxError(f"seccomp_load failed: {os.strerror(-result)}")
    finally:
        lib.seccomp_release(ctx)


# ------------------------------------------------------------------ what a plugin may read

SYSTEM_READ = ("/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin", "/etc")
DEVICES = ("/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom")


def python_paths() -> list[str]:
    """Python itself and its installed packages, not the folders around them (a checkout may hold a
    data directory next to the code)."""
    paths = {str(Path(p)) for key, p in sysconfig.get_paths().items()
             if key in ("stdlib", "platstdlib", "purelib", "platlib") and p}
    import site

    paths.update(p for p in site.getsitepackages() if p)
    paths.add(str(Path(__file__).resolve().parent))  # Doorman's package: plugin_api, util, the built-in plugins
    return sorted(paths)


def check_paths(paths: list[str], forbidden: list[str]) -> None:
    """None of the allowed paths may contain a forbidden one (Doorman's data directory)."""
    for path in paths:
        allowed = Path(path).resolve()
        for secret in forbidden:
            secret_path = Path(secret).resolve()
            if secret_path == allowed or allowed in secret_path.parents:
                raise SandboxError(f"{path} would let the plugin read {secret}; move the data directory out of it")


def lock_down(read: list[str] | None, write: list[str], *, close_network: bool, forbidden: list[str]) -> dict:
    """The whole sandbox, in order. read=None: files stay open (only for plugins the owner trusts that
    far, like one that drives a browser). Returns what was applied, for the log."""
    if threading.active_count() > 1:
        raise SandboxError("the sandbox must be applied before any thread starts")
    if read is not None:
        read = list(dict.fromkeys([*SYSTEM_READ, *python_paths(), *read]))
        check_paths(read + list(write), forbidden)
        proc_self = os.path.realpath("/proc/self")
        if proc_self.startswith("/proc/"):
            read.append(proc_self)
    abi = restrict_files(read, write if read is not None else None, close_network=close_network)
    restrict_syscalls(close_network=close_network)
    return {"landlock": abi, "files": "limited" if read is not None else "open",
            "network": "closed" if close_network else "open"}


if __name__ == "__main__":  # python -m doorman.sandbox: what this machine supports
    print(f"Landlock version: {landlock_abi() or 'none'}")
    try:
        _libseccomp()
        print("libseccomp: found")
    except SandboxError as exc:
        print(exc)
    sys.exit(0 if landlock_abi() >= 4 else 1)
