# The egress proxy: mitmproxy 12.3.1 with Doorman's addon, the agent container's only way out.
# Build context is the repo root (docker compose does that): it needs doorman/egress/, nothing else of Doorman.
FROM python:3.13-slim

# iptables + iproute2: entrypoint.sh redirects the agent's traffic into mitmproxy; curl: the first GeoIP
# download; util-linux: setpriv, to run mitmproxy without root
RUN apt-get update && apt-get install -y --no-install-recommends iptables iproute2 curl ca-certificates util-linux \
    && rm -rf /var/lib/apt/lists/*
# exactly the tested packages, each checked against its hash (written by deploy/lock.py egress)
COPY deploy/egress/requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock && rm /tmp/requirements.lock \
    && useradd --uid 10003 --no-create-home --home-dir /data egress
WORKDIR /app
COPY doorman/__init__.py doorman/__init__.py
COPY doorman/egress doorman/egress
COPY deploy/egress/addon.py deploy/egress/doorman_client.py deploy/egress/entrypoint.sh ./
ENV PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1
EXPOSE 8080 8053/udp 8053
# starts as root for iptables, then runs mitmdump as the user egress without any capability
ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
