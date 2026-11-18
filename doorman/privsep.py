"""The root side of plugin isolation: one Linux user per plugin.

When Doorman is started as root (`doorman-admin serve` in the Docker image), this module stays root
in a small process of its own and runs Doorman itself as Doorman's user. Doorman asks it, over
a private socket, to start a plugin's process; it starts it as that plugin's own user, and nothing else:

- spawn: the plugin runner (`python -m doorman.plugin_runner`), always that program and nothing else,
  as a user from the plugin range (never root, never Doorman's user), in a group of its own, with
  the connections Doorman hands over. The plugin's folder becomes the plugin user's, with group
  doorman and the setgid bit, so Doorman can still read it (backups) and other plugins can't.
- helper: one of the helper processes that parse a stranger's bytes (the text extractor, the guard's
  scanner, the embedding model), each always as its own fixed user (HELPERS), with the pipes Doorman
  hands over. It reads what any user may (Python, the model files Doorman makes readable) and what
  Doorman pipes to it; nothing of Doorman's data, its environment or its memory.
- kill: ends a process group this root process started; nothing else.

It reads no plugin's data and never sees a plugin's credentials: Doorman sends each plugin its
own over that plugin's connection. (The vault key passes through its environment on the way to the
doorman, and is dropped from it once Doorman is started; plugins get an allowlisted environment
only.) What it trusts Doorman with is the choice of user ID inside the
plugin range, which gives no more than Doorman has already.

When Doorman exits, this process stops every plugin and exits with Doorman's code, so Docker's
restart policy sees Doorman's exit. As PID 1 it also reaps orphans (Chromium's children).

    python -m doorman.privsep --user doorman --data-dir /data -- doorman-admin serve
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import pwd
import re
import select
import signal
import socket
import stat
import sys
from pathlib import Path

UID_BASE, UID_COUNT = 20000, 10000  # plugin users: 20000-29999, without an /etc/passwd entry
PYTHON_ARGS = ["-E", "-s", "-B", "-u", "-m"]
RUNNER_ARGS = [*PYTHON_ARGS, "doorman.plugin_runner"]
# helper processes: the module that runs, and the user it runs as (right above the plugin range, also unlisted)
HELPERS = {"extract": ("doorman.extract_worker", 30000), "guard": ("doorman.guard_worker", 30001),
           "embed": ("doorman.embed_worker", 30002)}
HELPER_UIDS = {uid for _, uid in HELPERS.values()}
PACKAGE_PARENT = Path(__file__).resolve().parent.parent
ENV_ALLOWED = {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "PLAYWRIGHT_BROWSERS_PATH", "SSL_CERT_FILE",
               "SSL_CERT_DIR", "HOME", "TMPDIR"}
INSTANCE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
FD_ENV = "DOORMAN_SPAWNER_FD"


class PrivsepError(Exception):
    pass


def doorman_user(name: str | None = None) -> pwd.struct_passwd:
    name = name or os.environ.get("DOORMAN_USER") or "doorman"
    try:
        user = pwd.getpwnam(name) if not name.isdigit() else pwd.getpwuid(int(name))
    except KeyError:
        raise PrivsepError(f"there is no user {name!r} to run Doorman as; create it, or set DOORMAN_USER") from None
    if user.pw_uid == 0:
        raise PrivsepError("Doorman's user can't be root")
    if UID_BASE <= user.pw_uid < UID_BASE + UID_COUNT:
        raise PrivsepError(f"Doorman's user ({user.pw_uid}) lies in the plugin range {UID_BASE}-{UID_BASE + UID_COUNT - 1}")
    if user.pw_uid in HELPER_UIDS:
        raise PrivsepError(f"Doorman's user ({user.pw_uid}) is a helper process's "
                           f"({', '.join(map(str, sorted(HELPER_UIDS)))})")
    return user


def drop_to(user: pwd.struct_passwd) -> None:
    """Become `user` for good: its groups, its IDs, its home. Root can't come back."""
    os.setgroups([])
    os.setresgid(user.pw_gid, user.pw_gid, user.pw_gid)
    os.setresuid(user.pw_uid, user.pw_uid, user.pw_uid)
    if os.geteuid() == 0 or os.getegid() == 0:
        raise PrivsepError("dropping root failed")
    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        raise PrivsepError("root came back after dropping it")
    os.environ.update(HOME=user.pw_dir, USER=user.pw_name, LOGNAME=user.pw_name)


# ------------------------------------------------------------------ a plugin's folder

def _fix_tree(dir_fd: int, uid: int, gid: int) -> None:
    """Whatever in the folder isn't the plugin user's yet (a restored backup, files `doorman-admin login`
    wrote as Doorman's user) becomes its, with group doorman. Never follows a link, so a planted
    symlink can't redirect the chown."""
    for root, dirs, files, root_fd in os.fwalk(".", dir_fd=dir_fd, follow_symlinks=False):
        for name in dirs + files:
            try:
                info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode) or (info.st_uid == uid and info.st_gid == gid):
                    continue
                os.chown(name, uid, gid, dir_fd=root_fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
                    try:
                        os.fchmod(fd, 0o2770)
                    finally:
                        os.close(fd)
                elif stat.S_ISREG(info.st_mode):
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
                    try:
                        owner = info.st_mode & 0o700
                        os.fchmod(fd, owner | (owner >> 3))
                    finally:
                        os.close(fd)
            except OSError:
                continue


def prepare_folder(data_dir: Path, instance: str, uid: int, gid: int) -> None:
    """data_dir/plugins/<instance>, owned by the plugin user, group doorman, setgid: Doorman reads and
    writes it through its group, other plugin users can't enter it. Works on file descriptors, so the
    doorman (which owns data_dir) can't swap a folder for a link between the check and the chown."""
    top = os.open(data_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            os.mkdir("plugins", 0o711, dir_fd=top)
        except FileExistsError:
            pass
        plugins = os.open("plugins", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=top)
    finally:
        os.close(top)
    try:
        try:
            os.mkdir(instance, 0o2770, dir_fd=plugins)
        except FileExistsError:
            pass
        folder = os.open(instance, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=plugins)
    finally:
        os.close(plugins)
    try:
        info = os.fstat(folder)
        if info.st_uid != uid or info.st_gid != gid:
            os.fchown(folder, uid, gid)
        _fix_tree(folder, uid, gid)
        if stat.S_IMODE(info.st_mode) != 0o2770:
            os.fchmod(folder, 0o2770)
            if not os.fstat(folder).st_mode & stat.S_ISGID:  # the kernel drops it silently without CAP_FSETID
                raise PrivsepError("can't give a plugin's folder Doorman's group (the root process needs CAP_FSETID)")
    finally:
        os.close(folder)


# ------------------------------------------------------------------ the root process

class Supervisor:
    def __init__(self, user: pwd.struct_passwd, data_dir: Path, argv: list[str]):
        self.user = user
        self.data_dir = data_dir.resolve()
        self.argv = argv
        self.sock: socket.socket | None = None
        self.doorman_pid = 0
        self.children: dict[int, str] = {}   # plugin or helper pid -> instance, or "helper <name>"
        self.users: dict[int, str] = {}      # uid -> instance, for this run
        self.exit_code: int | None = None

    def start_doorman(self) -> None:
        mine, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        pid = os.fork()
        if pid == 0:  # Doorman
            try:
                mine.close()
                os.set_inheritable(theirs.fileno(), True)
                drop_to(self.user)
                os.environ[FD_ENV] = str(theirs.fileno())
                os.umask(0o077)
                os.execvp(self.argv[0], self.argv)
            except BaseException as exc:  # noqa: BLE001 - the child must never return into the root loop
                print(f"privsep: starting Doorman failed: {exc}", file=sys.stderr)
            os._exit(127)
        theirs.close()
        self.sock, self.doorman_pid = mine, pid
        os.environ.pop("DOORMAN_VAULT_KEY", None)  # Doorman has it; this process starts Doorman only once

    # requests

    def handle(self) -> bool:
        try:
            data, fds, _, _ = socket.recv_fds(self.sock, 65536, 8)
        except (ConnectionResetError, OSError):
            return False
        if not data:
            for fd in fds:
                os.close(fd)
            return False
        try:
            message = json.loads(data)
            if message.get("op") in ("spawn", "helper"):
                handed, fds = fds, []  # spawn and spawn_helper close them, whatever happens
                reply = (self.spawn if message["op"] == "spawn" else self.spawn_helper)(message, handed)
            elif message.get("op") == "kill":
                reply = self.kill(message)
            else:
                reply = {"error": f"unknown request {message.get('op')!r}"}
        except PrivsepError as exc:
            reply = {"error": str(exc)}
        except Exception as exc:  # noqa: BLE001 - a bad request must not end the root process
            reply = {"error": f"{type(exc).__name__}: {exc}"}
        finally:
            for fd in fds:
                try:
                    os.close(fd)
                except OSError:
                    pass
        try:
            self.sock.send(json.dumps(reply).encode())
        except OSError:
            return False
        return True

    def spawn(self, message: dict, fds: list[int]) -> dict:
        try:
            instance, uid = message.get("instance"), message.get("uid")
            if not isinstance(instance, str) or not INSTANCE.match(instance):
                raise PrivsepError("bad plugin name")
            if not isinstance(uid, int) or isinstance(uid, bool) or not UID_BASE <= uid < UID_BASE + UID_COUNT:
                raise PrivsepError(f"user {uid!r} isn't in the plugin range")
            if self.users.setdefault(uid, instance) != instance:
                raise PrivsepError(f"user {uid} belongs to {self.users[uid]} already")
            if len(fds) != 3:
                raise PrivsepError("a plugin needs exactly three connections")
            env = self._env(message)
            prepare_folder(self.data_dir, instance, uid, self.user.pw_gid)
            folder = self.data_dir / "plugins" / instance
            env.update(HOME=str(folder), TMPDIR=str(folder / "tmp"), USER=f"plugin-{instance}")
            main, sockets, err = fds
            null = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
            try:
                pid = os.fork()
                if pid == 0:
                    self._exec(uid, {0: null, 1: err, 2: err, 3: main, 4: sockets},
                               [sys.executable, *RUNNER_ARGS, "3", "4"], env)
            finally:
                os.close(null)
            self.children[pid] = instance
            return {"pid": pid}
        finally:
            for fd in fds:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def spawn_helper(self, message: dict, fds: list[int]) -> dict:
        """One of the helper processes, as its own user: the module and the user come from HELPERS, the
        arguments (a model folder, settings) from Doorman, which gains nothing by choosing them."""
        try:
            name, args = message.get("helper"), message.get("args")
            if name not in HELPERS:
                raise PrivsepError(f"no helper {name!r}")
            if not isinstance(args, list) or len(args) > 8 or \
                    not all(isinstance(a, str) and len(a) <= 4096 and "\x00" not in a for a in args):
                raise PrivsepError("bad helper arguments")
            if len(fds) != 3:
                raise PrivsepError("a helper needs exactly three pipes: its input, its output, its errors")
            module, uid = HELPERS[name]
            env = self._env(message)
            env.update(HOME="/nonexistent", TMPDIR="/tmp", USER=f"doorman-{name}")
            stdin, stdout, err = fds
            pid = os.fork()
            if pid == 0:
                self._exec(uid, {0: stdin, 1: stdout, 2: err}, [sys.executable, *PYTHON_ARGS, module, *args], env)
            self.children[pid] = f"helper {name}"
            return {"pid": pid}
        finally:
            for fd in fds:
                try:
                    os.close(fd)
                except OSError:
                    pass

    @staticmethod
    def _env(message: dict) -> dict:
        env = message.get("env") or {}
        if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
            raise PrivsepError("bad environment")
        return {k: v for k, v in env.items() if k in ENV_ALLOWED}

    def _exec(self, uid: int, fds: dict[int, int], argv: list[str], env: dict) -> None:
        """In the forked child: the descriptors Doorman handed over at fixed numbers (`fds`: number ->
        descriptor), everything else closed, the user's IDs for good, then Python. Never returns."""
        try:
            os.setsid()
            # out of the way first (any of them may sit on a target number), then to the fixed numbers
            moved = {target: fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 64) for target, fd in fds.items()}
            for target, fd in moved.items():
                os.dup2(fd, target)
            # everything else (Doorman's socket, the copies above) closed
            os.closerange(max(fds) + 1, max(os.sysconf("SC_OPEN_MAX"), 4096))
            os.chdir(PACKAGE_PARENT)
            os.setgroups([])
            os.setresgid(uid, uid, uid)   # a group of its own: other plugins' files stay closed to it
            os.setresuid(uid, uid, uid)
            if os.geteuid() == 0 or os.getegid() == 0:
                os._exit(126)
            signal.pthread_sigmask(signal.SIG_SETMASK, [])
            for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGCHLD, signal.SIGPIPE):
                signal.signal(sig, signal.SIG_DFL)
            os.execve(sys.executable, argv, env)
        except BaseException:  # noqa: BLE001 - never back into the root loop
            pass
        os._exit(127)

    def kill(self, message: dict) -> dict:
        pid = message.get("pid")
        if not isinstance(pid, int) or pid not in self.children:
            return {"error": "not a plugin or helper process of this doorman"}
        for target in (lambda: os.killpg(pid, signal.SIGKILL), lambda: os.kill(pid, signal.SIGKILL)):
            try:
                target()
                break
            except ProcessLookupError:
                continue
        return {"ok": True}

    # children

    def reap(self) -> None:
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return
            if pid == 0:
                return
            if pid == self.doorman_pid:
                code = os.waitstatus_to_exitcode(status)
                self.exit_code = code if code >= 0 else 128 - code  # killed by a signal: 128 + its number
            elif pid in self.children:
                try:
                    os.killpg(pid, signal.SIGKILL)  # whatever it started goes with it
                except (ProcessLookupError, PermissionError):
                    pass
                self.children.pop(pid, None)

    def stop_plugins(self) -> None:
        for pid in list(self.children):
            for target in (lambda: os.killpg(pid, signal.SIGKILL), lambda: os.kill(pid, signal.SIGKILL)):
                try:
                    target()
                    break
                except ProcessLookupError:
                    continue

    def run(self) -> int:
        wake_read, wake_write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        signal.set_wakeup_fd(wake_write)

        def forward(signum, _frame):
            if self.doorman_pid:
                try:
                    os.kill(self.doorman_pid, signum)
                except ProcessLookupError:
                    pass

        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, forward)
        signal.signal(signal.SIGCHLD, lambda *_: None)  # wakes select through the wakeup fd
        self.start_doorman()
        open_ = True
        while self.exit_code is None:
            watched = [wake_read] + ([self.sock] if open_ else [])
            try:
                ready, _, _ = select.select(watched, [], [], 5.0)
            except InterruptedError:
                ready = []
            if wake_read in ready:
                try:
                    while os.read(wake_read, 512):
                        pass
                except BlockingIOError:
                    pass
            if open_ and self.sock in ready:
                open_ = self.handle()
            self.reap()
        self.stop_plugins()
        self.reap()
        return self.exit_code


BACKUP_NAME = re.compile(r"^doorman-\d{8}-\d{6}(\.partial)?$")


def claim_backup_dir(path: str | os.PathLike, who: pwd.struct_passwd, *, unclaimed_uid: int = 0) -> bool:
    """backup.dir becomes Doorman's (mode 0700: plugin users mustn't read copies of doorman.db) while root
    owns it and it holds nothing but Doorman's backups. A bind mount reaches the container as root's
    (deploy/backups, made by the host user that is root in a rootless Docker), and Doorman's user then
    can't write a backup into it. Only the folder itself, never through a link, and never one with
    anything else in it, so `backup.dir: /` can't hand over the system. True when it changed the owner."""
    folder = Path(path)
    if not folder.is_absolute():
        raise PrivsepError(f"backup.dir {folder} isn't an absolute path")
    folder.mkdir(parents=True, exist_ok=True)
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if os.fstat(fd).st_uid != unclaimed_uid:  # already someone's (Doorman's, after the first start)
            return False
        other = [name for name in os.listdir(fd) if not BACKUP_NAME.match(name) and name != "lost+found"]
        if other:
            raise PrivsepError(f"backup.dir {folder} holds more than Doorman's backups ({', '.join(sorted(other)[:3])}); "
                               f"make it Doorman's yourself (chown {who.pw_uid}:{who.pw_gid}) or point backup.dir "
                               "at a folder of its own")
        os.fchown(fd, who.pw_uid, who.pw_gid)
        os.fchmod(fd, 0o700)
        return True
    finally:
        os.close(fd)


def supervise(argv: list[str], *, user: str | None = None, data_dir: str | os.PathLike,
              backup_dir: str | os.PathLike | None = None) -> int:
    if os.geteuid() != 0:
        raise PrivsepError("privsep runs as root")
    who = doorman_user(user)
    data = Path(data_dir).resolve()
    data.mkdir(parents=True, exist_ok=True)
    if data.stat().st_uid == 0:  # a fresh volume: Doorman's from now on
        os.chown(data, who.pw_uid, who.pw_gid)
    if backup_dir:
        # a backup folder Doorman can't write to mustn't keep Doorman from starting: the failed backup is
        # listed under Needs attention, with this message in the log
        try:
            if claim_backup_dir(backup_dir, who):
                print(f"privsep: backup.dir {backup_dir} is Doorman's now", file=sys.stderr, flush=True)
        except (OSError, PrivsepError) as exc:
            print(f"privsep: left backup.dir as it is: {exc}", file=sys.stderr, flush=True)
    print(f"privsep: doorman runs as {who.pw_name} ({who.pw_uid}), each plugin as a user of its own "
          f"({UID_BASE}+)", file=sys.stderr, flush=True)
    return Supervisor(who, data, argv).run()


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m doorman.privsep", description=__doc__.split("\n\n")[0])
    parser.add_argument("--user", help="Doorman's user (default $DOORMAN_USER or doorman)")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--backup-dir", help="backup.dir: made Doorman's while root owns it (claim_backup_dir)")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    options = parser.parse_args(args)
    command = options.command[1:] if options.command[:1] == ["--"] else options.command
    if not command:
        parser.error("Doorman's command is missing")
    try:
        return supervise(command, user=options.user, data_dir=options.data_dir, backup_dir=options.backup_dir)
    except PrivsepError as exc:
        print(f"privsep: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
