# Network watch: the egress proxy

The acting agent's container gets one way out: this proxy. It logs every connection with the process that
opened it, applies the owner's rules, and reports (or, if the owner chooses, blocks) what carries text the
agent read through Doorman.
Doorman keeps the rules, the fingerprints of what it served, the log and the exceptions; the owner sees and
changes all of it under More → Network in the app.

## How it works

Three containers next to Doorman, in `deploy/compose.egress.yaml`, layered on `compose.yaml` with the agent's
own file (`compose.hermes.yaml`, or a copy of it for another agent):

- **agent** (the wrapper and its hardening in `compose.egress.yaml`; image, command and user in
  `compose.hermes.yaml`): only on the internal network `doorman-egress`
  (172.29.0.0/24), which has no way to the internet, at the fixed address 172.29.0.3 (Doorman knows the
  agent's keys by it, and a quarantine holds for it). `agent-entrypoint.sh` wraps the agent's command: it sets
  the default route and DNS to the proxy (172.29.0.2), adds the proxy's CA to the system trust store (and
  points `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO` at
  it), then starts the agent as `AGENT_USER` (Hermes' own user `hermes` by default; never root) with
  NET_ADMIN, NET_RAW, SETUID, SETGID and SETPCAP gone from its bounding set: nothing the agent runs can change
  the route, sniff or spoof on its network, or become another user. The container has no KILL capability and
  no IPv6. Doorman is on the same network (172.29.0.10, `doorman:8710`), reached directly.
- **egress**: mitmproxy 12.3.1 with `addon.py`. iptables sends the agent's DNS to
  mitmproxy's DNS mode and every TCP connection to its transparent mode; nothing is forwarded, so UDP (QUIC
  included: clients fall back to HTTPS) and IPv6 don't get out. HTTPS is opened with the proxy's own CA.
  The proxy reaches the internet through its own network (`egress-out`), not Doorman's default network, and
  Doorman's proxy API through `doorman-egress-control` (172.29.1.0/24, only the proxy and Doorman), so the
  agent never sees the proxy's token or what it reports.
- **egress-observer**: shares the agent's process view and nothing else (no internet,
  read-only). It runs as its own user (uid 10004) with SYS_PTRACE and DAC_READ_SEARCH as its only
  capabilities, so the agent, which shares its process view, can't signal it. For each connection the proxy
  asks it which process holds the socket; the answer (pid, command line, parents) goes into the log, and
  Doorman ties it to the agent's tool call. It also keeps the tripwire on the decoy keys (below).

Nothing goes out before it is decided: mitmproxy connects upstream only when an allowed request needs it
(`connection_strategy=lazy`, which the addon enforces), and a last check before every upstream connection
refuses addresses and TLS names the rules deny. For every DNS question, connection and HTTP request the
addon decides with `doorman.egress.rules`: exceptions the owner granted (for the agent that asked), the allow
and deny lists, then the categories blocked by default (names that look like data hidden in DNS, countries on
the block list, abuse-heavy top-level domains, uploads to paste, webhook and tunnel services, non-web
connections to bare IPs no lookup led to) and, if the owner chose, "only web traffic". Private addresses
(Doorman's own networks, the LAN) are refused unless the allow list or an exception names that address or
network. A name the agent claims counts only for the address the proxy resolved it to (see Limits).

What the agent sends is scanned: an HTTP request's URL, every header (Host, cookies, the TLS name...),
trailers and body; WebSocket messages; and raw TCP as it passes (a secret split across packets is still
seen). It is unpacked (base64, hex, URL encoding, gzip and zlib, encodings of encodings up to six deep, JSON,
forms, multipart; any charset, text hidden between binary bytes), fingerprinted, and Doorman is asked how
much of it the agent read through Doorman. Only hashes go to Doorman. Enough of it and the request gets a 403
(a WebSocket message is dropped, a raw connection cut), the agent's key is paused and the owner is told. A
honeytoken anywhere blocks, even when Doorman can't be asked. The agent's model API (the `no_scan` list)
isn't scanned: it sees everything the agent read anyway; its log rows carry a hash of the API key used, so
Doorman notices a second key (someone else's account as a drop box). Two things are still looked for there,
as plain text, which costs a few milliseconds: a honeytoken in the URL or a header (a decoy key as `x-api-key`
or `Authorization`) blocks like anywhere else, before a large body can start streaming; and the decoy keys
in a request's body, a WebSocket message or a raw stream mean the agent has them in its conversation, which
counts as reading their file (see "Decoy keys"). The owner's own honeytokens in the body don't count: the
model gets what the agent read, a planted mail included.

A blocked request gets `403` with `X-Doorman-Egress: blocked; rule=<rule>` and a text that says why and how to
ask: `doorman egress request <host> --reason "why"`. A blocked DNS name gets REFUSED; a blocked non-web
connection is closed; an upload too large to check is refused with a 413 before anything reaches the server.
Two blocks say nothing: a honeytoken and a quarantined agent (see "Decoy keys") get a plain `502 Bad Gateway`
(body `Bad Gateway`, no `X-Doorman-Egress`), like an ordinary upstream failure; the log has the real rule.
`doorman egress blocked` lists what was blocked for the agent's key. The rules the proxy adds to Doorman's:
`leak`, `honeytoken`, `quarantine`, `doorman_down`, `private`, `tls_failed`, `error`, `unscanned` (too large
to check), `upgrade` (an HTTP protocol switch to anything but WebSocket), `raw_on_web_port` (data that is
neither TLS nor HTTP on a web port), and `dns_tunnel` also for many new names under one domain.

## Decoy keys

A file of fake API keys sits in the agent's home, `~/.config/secrets/api-keys.env` (Hermes:
`/opt/data/.config/secrets/api-keys.env`): an Anthropic, an OpenAI, an AWS and a GitHub key that look real and
belong to nobody. The agent is told never to touch it. Something that opens it anyway (a prompt injection
looking for credentials, a package's install script, a tool run on the whole home folder) has given itself
away, and the agent is stopped before anything leaves.

- Doorman makes the keys (More → Network → Decoy keys: on or off, "Stop the agent" or "Only tell me", "Make
  new keys"); the proxy writes the file into the volume `agent-config` (`/decoys` in the egress container,
  0444, replaced in one step when the keys change, removed when they are switched off). The agent has the
  volume read-only at `${AGENT_HOME:-/opt/data}/.config/secrets`: it can't change or delete the file. The
  volume's name says nothing about decoys, as the agent can read it in `/proc/self/mountinfo`
  (`deploy_agent-config/_data`); that the folder is a read-only mount of its own stays visible there, which
  no name can hide.
- The observer watches the file and its folder with inotify, through the agent's `/proc/1/root`, and never
  opens the file itself: the file opened or read (`open`, `access`) or the folder listed (`dir_open`). The
  folder's watch sees the file opened too, so new keys are watched from the moment they are in place, before
  the observer has set a watch on the new file; one open seen by both watches is one event. The proxy
  fetches these events every 2 s and hands them to Doorman in order (again while Doorman is down; the number
  of the last one it delivered is kept in `egress-data/tripwire.json`).
- Whether the observer watches the file goes with the proxy's status every minute (the observer's
  `/health`: armed, and its last error). With decoy keys on and the wire not armed in two statuses in a row
  (the observer down or unreachable, the file missing, `AGENT_HOME` not the agent's home), Needs attention
  says "The decoy keys aren't watched" until it is armed again.
- The file opened or read: with "Stop the agent", Doorman pauses the agent's keys and quarantines its address;
  the owner gets a push. With "Only tell me", just the push. The folder listed: a push, nothing paused.
- A key from the file used anywhere (in a request through the proxy, the model API's `x-api-key` and
  `Authorization` included, or in a Doorman tool call) counts as a honeytoken: blocked, the key paused, and
  with "Stop the agent" the address quarantined too.
- The keys in what the agent sends its model API (a request's body, a WebSocket message, a raw stream; not a
  header) mean it read the file, whether the tripwire saw that or not: with "Stop the agent" the request is blocked and the agent stopped as
  above; with "Only tell me" a push (once a day per address: every later call carries them too), and the
  request goes.
- Quarantined, the agent's address gets nothing from the proxy: DNS is REFUSED, every connection is closed as
  it comes in, a request on a connection that was already open gets a `502 Bad Gateway`, raw TCP is cut,
  WebSocket messages are dropped. The model API and the allow list are no exception. Logged with rule
  `quarantine`. The agent's address is fixed (172.29.0.3), so a re-created container is still cut off.
- Nothing the agent sees says why: its key is "paused by the owner", requests fail like a broken upstream.

Put the same rule into Hermes's own instructions (its system prompt or `SOUL.md`), word for word, so the model
hears it from both sides:

> Never open, read, list, copy or search inside ~/.config/secrets/: the keys there aren't yours; touching them
> stops you at once.

What trips it: anything that opens the file or lists its folder, from inside the agent's container or from the
host: `cat`, `cp`, `grep -r` or `find` over the home folder, an editor, a file indexer. `ls -l`, `stat` and
`test -e` don't (they open nothing); the self-test uses only those. Host backups that read Docker's volumes
(`/var/lib/docker/volumes/`) read the file too and trip it: leave the volume `agent-config` (Docker names it
`<project>_agent-config`, e.g. `deploy_agent-config`) out of every backup. There is nothing in it to keep:
Doorman makes the keys and the proxy writes them again.

To let the agent out again: the banner at the top of More → Network → **Let it out again** (with your
passkey), or resume the agent's paused key under More → Agents, which lifts the quarantine that came with it.
The proxy picks the change up with the next policy (within 5 s). Before that, find out what touched the file:
the event's time in the push, and the agent's tool calls and network log around it.

## Setting it up

1. In the app: More → Network → **Set up the proxy**. It shows the proxy token once. Put it in `deploy/.env`
   (start from `deploy/.env.example`) with the setup and the agent's settings:

   ```sh
   COMPOSE_FILE=compose.yaml:compose.egress.yaml:compose.hermes.yaml
   DOORMAN_EGRESS_TOKEN=dme_...
   AGENT_DOORMAN_TOKEN=dmn_...            # the agent's key (More → Agents)
   AGENT_IMAGE=nousresearch/hermes-agent:<a version you checked>
   AGENT_USER=hermes                       # the image's own user (name or uid:gid); never root
   AGENT_HOME=/opt/data                    # that user's home: the decoy keys go into its .config/secrets
   ```

2. In `compose.hermes.yaml`, check the agent's `command:` against the image's own entrypoint and command
   (`docker image inspect <image>`, `Config.Entrypoint` and `Config.Cmd`): the wrapper's `entrypoint:`
   replaces them. Its state is in the volume `hermes-data` at `/opt/data`, writable by `AGENT_USER` (uid
   10000; a named volume takes the image's ownership, a bind mount needs `chown 10000:10000`). The image
   needs `ip` (iproute2) and `setpriv` (util-linux); `curl` for the self-test. Hermes's image has no `ip`,
   so `compose.hermes.yaml` builds it with iproute2 added (`docker compose build --pull agent` after a new
   `AGENT_IMAGE`). An image whose own init does start-up work (Hermes: s6-overlay's `/init` and its stage2
   hook) names that work in `AGENT_BOOTSTRAP`: the wrapper runs it as root after the route and the CA, without
   NET_ADMIN, NET_RAW and SETPCAP and with nothing from the agent's home on `PATH`; `init: true` reaps.
   Hermes's Webapp: profile `webapp` (`COMPOSE_PROFILES=webapp`), a forwarder on `127.0.0.1:9120`, since
   the agent's internal network can't publish a port; see the comment in `compose.hermes.yaml`.

3. On the host, once: the agent reaches the host's own address on its network (172.29.0.1) directly, past
   the proxy, so drop everything from that bridge to the host (the compose file names it `br-doorman-egr`):

   ```sh
   iptables -I INPUT -i br-doorman-egr -j DROP
   ip6tables -I INPUT -i br-doorman-egr -j DROP
   ```

   Make it permanent with the host's firewall (e.g. `/etc/iptables/rules.v4` with iptables-persistent, or an
   nftables `input` rule on `iifname "br-doorman-egr"`). It only concerns packets to the host itself;
   containers on the network still reach each other. (Docker's `com.docker.network.bridge.inhibit_ipv4`
   would leave the bridge without an address instead, but its behaviour on internal networks isn't
   documented, so the compose file doesn't rely on it.)

4. Start it:

   ```sh
   cd deploy
   docker compose up -d --build
   docker compose exec agent sh /egress/selftest.sh
   ```

   Every line should say PASS: the route; no NET_ADMIN, NET_RAW, KILL, SETUID or SETGID for the agent, and
   not root; Doorman reachable; an HTTPS fetch; a blocked webhook upload; a cut bare-IP connection; a refused
   DNS-tunnel name; no UDP; the host's ports 22 and 8711 not reachable at 172.29.0.1; no IPv6; the decoy
   keys in place and their folder read-only (checked without opening them).

5. Tell Doorman which tool call a connection belongs to: install the Hermes plugin
   (`hermes-plugin/doorman-activity`, into the agent's `~/.hermes/plugins/`), or for Claude Code the hook
   `doorman activity hook` on PreToolUse and PostToolUse.

Your own agent instead of Hermes: copy `compose.hermes.yaml` to `compose.myagent.yaml`, set its `image:`,
`command:`, `AGENT_USER` (the image's own user, never root: the wrapper refuses to start the agent as root,
`AGENT_USER=""` included, or with `AGENT_USER` unset; an image without a user needs one added, a Dockerfile
`FROM` it with `RUN useradd -m agent`) and its own volumes, set `AGENT_HOME` in `.env` to that user's home,
and name the copy in `COMPOSE_FILE` instead of `compose.hermes.yaml`. Everything that keeps the agent in (its
network, the wrapper, the capabilities, `sysctls`, `dns`, the CA, the decoy keys, the observer) stays in
`compose.egress.yaml`, so the copy needs none of it.

Settings of the egress container (environment): `DOORMAN_URL` (Doorman on `doorman-egress-control`),
`DOORMAN_EGRESS_TOKEN`, `OBSERVER_URL`, `EGRESS_AGENT_IP` (its address on the agent's network),
`EGRESS_GEOIP=0` (no country table; otherwise DB-IP's free "IP to Country Lite", CC BY 4.0, downloaded monthly
into `egress-data/geoip/`), `EGRESS_LOG_LEVEL` (mitmproxy's terminal log, default `warn`), `EGRESS_DECOY_DIR`
(where the decoy keys file goes, default `/decoys`). Of the observer: `OBSERVER_DECOY_PATH` (the decoy file as
the agent sees it, default `/opt/data/.config/secrets/api-keys.env`; the compose file derives it from
`AGENT_HOME`), `AGENT_IP` (the agent's address, 172.29.0.3 in the compose file; read from its routing
table when unset). `egress-data/` also
holds mitmproxy's CA with its private key (back it up with the rest, keep it out of reach) and the last
policy, which the proxy uses until Doorman answers after a restart.

## Limits

- A client that pins certificates fails against the proxy; the log says so (`tls_failed`). Put the host on
  the passthrough list: its traffic then goes through unread (still logged, still subject to the rules).
- Non-web traffic (SSH, IMAP, a database) is relayed as raw TCP: logged with byte counts, and what the agent
  sends is fingerprinted as it passes (the last 4 KB of a stream are rescanned with each packet), so readable
  text is checked; encrypted protocols (SSH, TLS the proxy doesn't open) give nothing to check. "Only web
  traffic" in the app blocks all of it. On a web port (80, 443, 8080, 8443) data that is neither TLS nor
  HTTP is refused unless the allow list or an exception names the address or a name it has.
- Bodies over 16 MiB aren't held, and fingerprinting stops after 4 million letters and digits per request
  (spaces and punctuation don't count, so padding can't push a secret out). What can't be scanned completely
  follows the owner's setting "unscanned": let through unscanned by default (logged `scanned: false`), or
  blocked (rule `unscanned`) except for hosts on the allow list, with an exception, or on `no_scan`. A raw TCP
  stream counts against the same budget for its whole life.
- More fingerprints than one check takes (200,000) go to Doorman in several calls that overlap, in the order
  of the text, so a passage is whole in one of them.
- The name a connection claims (Host header, TLS SNI) is the agent's to write, so a name only counts where it
  would let something through (allow list, exceptions, not scanned, passthrough) if it vouches for the
  address: the proxy's DNS gave that address out for the name in the last 24 hours, or the proxy's own
  lookup of the name (cached 5 minutes, 1 s at most) returns it. That lookup is a DNS query the agent causes:
  it gets the DNS rules first (a name they refuse isn't looked up), at most 30 a minute per client, in
  threads of its own, logged like the agent's queries. A list entry also applies when it covers a name the
  address really has (`anthropic.com` for an address resolved as `api.anthropic.com`), except when the TLS
  name and the Host header differ (domain fronting: then the Host has to vouch on its own, and `no_scan`
  doesn't apply). Otherwise the connection is decided by its address and the names that address really has,
  and the log row says "the name … doesn't match the address …". Deny rules about names (deny list, data in
  DNS, abuse TLDs, uploads to paste services) apply to the claimed name always, also when an allow or an
  exception by address lets the connection through. A name whose addresses change faster than the agent
  connects (some CDNs) can fail to vouch; the request is then scanned and decided by address.
- DNS: a query that isn't exactly one question is refused; so is a name with a long random label, and more
  than 30 names a client hasn't asked for before under one domain within 5 minutes (further new names under
  it are refused for 10 minutes; names it asked for before keep working). Slower than that, a few bytes per
  name still get out; the log shows the names.
- WebSocket messages from the agent are checked like request bodies; one the proxy can't check is dropped.
  HTTP/2 and HTTP/1 both are. A switch to any other protocol (HTTP 101) gets a 403. HTTP/3 never gets out
  (UDP is dropped).
- When Doorman can't be asked, or doesn't finish a check in time, requests that carry content follow the
  owner's setting `when_doorman_down` (let through by default); requests without content pass. Log records wait (up
  to 5000) until Doorman is back; when that is full, allowed DNS records go first, then other allowed ones, so
  a flood can't push out what was blocked. The status tells Doorman how many were dropped.
- The agent's container keeps a writable root file system (the image may write outside its home, and the
  wrapper adds the proxy's CA to the trust store), and what is written there lasts until the container is
  re-created. The wrapper runs the image's programs as root on every start, so an agent running as root
  could change them and take its capabilities back: that is why it refuses to start the agent as root. A
  user that isn't root can't change them.
- The transparent mode, the iptables rules and the capability drops need a Docker host and can only be tried
  on the server (`selftest.sh`): the addon's tests and a run in mitmproxy's regular mode (`curl -x`) cover the
  rest.

## Development

```sh
python3 -m venv ~/.venvs/egress                                 # an environment of its own, with mitmproxy 12.3.1
~/.venvs/egress/bin/pip install -r deploy/egress/requirements.lock && ~/.venvs/egress/bin/pip install pytest
~/.venvs/egress/bin/python -m pytest deploy/egress/tests
.venv/bin/python deploy/lock.py egress                          # after changing EGRESS_MITMPROXY in lock.py
```

`addon.py` imports the shared core as `doorman.egress.*` (the images copy `doorman/egress/` and nothing
else of Doorman) and is written against mitmproxy 12.3.1's hooks. It also changes two methods of mitmproxy
itself (`DestinationKnown.finish_start`, so allowed non-web connections are opened at once despite the lazy
strategy, and `HttpStream.start_request_stream`, so a body that mustn't go unscanned never starts
streaming); the tests check both against the pinned version. Check them again before moving to another
version.
