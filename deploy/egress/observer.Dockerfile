# The egress observer: answers "which process holds the socket from port P to D?" for the proxy. It shares
# the agent's PID namespace (pid: "service:agent") and reads /proc; standard library only, so the image is
# python:3.13-slim plus doorman/egress/ (and doorman/__init__.py, which imports nothing).
FROM python:3.13-slim
# util-linux: setpriv, to drop root before the observer starts
RUN apt-get update && apt-get install -y --no-install-recommends util-linux && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10004 --no-create-home --home-dir /nonexistent observer
WORKDIR /app
COPY doorman/__init__.py doorman/__init__.py
COPY doorman/egress doorman/egress
ENV PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1
EXPOSE 8720
# Starts as root only to become the user observer (uid 10004, no other process has it) with two capabilities
# kept as ambient ones: SYS_PTRACE to read the socket links of the agent's processes and to reach its files
# through /proc/1/root, DAC_READ_SEARCH to list their /proc/<pid>/fd and to look up the decoy keys file in the
# agent's home for the inotify watch (the file itself is 0444; the watch never opens it). Not root and not the agent's uid, so the agent (which shares this PID namespace but has
# no KILL, SETUID or SETGID) can't signal it. Read-only root file system: see compose.egress.yaml.
CMD ["setpriv", "--reuid", "10004", "--regid", "10004", "--clear-groups", \
     "--inh-caps=+sys_ptrace,+dac_read_search", "--ambient-caps=+sys_ptrace,+dac_read_search", "--", \
     "python", "-m", "doorman.egress.observer"]
