# Network watch

Optional. With open web access, anything a task reads through Doorman could leave through the web
without an approval. With network watch, the agent runs in a container whose only way out is Doorman's
egress proxy: every connection is logged with the process and tool call behind it, checked against your
rules, and compared with what the agent read through Doorman.

[deploy/egress/README.md](../deploy/egress/README.md) has the full setup and its limits.

## Setting it up

1. **More → Network → Set up the proxy** (passkey check) shows the proxy token once. Put it in
   `deploy/.env` as `DOORMAN_EGRESS_TOKEN`, with the agent's key (`AGENT_DOORMAN_TOKEN`) and image
   (`AGENT_IMAGE`, pinned), and set
   `COMPOSE_FILE=compose.yaml:compose.egress.yaml:compose.hermes.yaml`.
2. Check `compose.hermes.yaml`'s `command:` against your image. For another agent, copy that file and
   name the copy in `COMPOSE_FILE` instead. The image needs `ip`, `setpriv` and `curl`.
3. `docker compose up -d --build`, then `docker compose exec agent sh /egress/selftest.sh`: every line
   PASS.
4. Install the `doorman-activity` Hermes plugin (`deploy/egress/hermes-plugin/`) or, for Claude Code,
   the `doorman activity hook` on PreToolUse and PostToolUse, so connections are tied to tool calls.
5. On the host, keep the agent's network away from the host itself:
   `iptables -I INPUT -i br-doorman-egr -j DROP` (the self-test checks it).

Things to keep in mind:

- **Never give the agent the Docker socket**, and keep Hermes's terminal backend `local`.
- **The agent never runs as root** behind the proxy; the start script refuses it. The example runs as
  the Hermes image's user `hermes` (uid 10000), so its volumes must be writable for that uid.
- **`deploy/egress-data/`** holds the proxy's CA with its private key: back it up, keep it private.
- **Leave the `agent-config` volume out of host backups.** It holds the decoy keys, and reading it trips
  the wire.
- **Hermes's Webapp:** `COMPOSE_PROFILES=webapp` and `HERMES_WEBAPP_PASSWORD` in `.env`; it is then on
  `127.0.0.1:9120`.

## How it works

**The way out.** The agent's container sits on the internal network `doorman-egress` (172.29.0.0/24)
at a fixed address (172.29.0.3) and has no route to the internet. Its default route and DNS point at the
proxy (172.29.0.2), which runs mitmproxy in transparent mode. Nothing in the agent needs proxy settings:
curl, Python, git and Node connect as usual. UDP (HTTP/3 included) and IPv6 don't get out. The agent
starts without the rights to change the route or spoof addresses.

**Rules.** The proxy decides in this order, under More → Network:

1. an exception you granted, for the asking agent's address only;
2. your allow list;
3. your deny list;
4. categories blocked by default: uploads to paste, webhook and tunnel services; abuse-heavy TLDs; a
   country list (RU, BY, KP and IR to start with); non-web connections to an IP address no name lookup
   led to; DNS names that look like hidden data;
5. otherwise it lets the connection through.

Private addresses are refused unless an entry names them. Web requests (HTTPS included, through the
proxy's own CA) are read; other traffic (SSH, mail, databases) is counted and scanned, or blocked when
you set "Other connections" to Block. A blocked web request gets a 403 that says why and how to ask.

**Leaks.** Everything an agent gets from Doorman is fingerprinted for `match_hours` (24). The proxy
decodes what each request carries (headers, URL, body; base64, hex and gzip inside) and compares. 200
matching characters or more is a leak.

| "Block requests that carry what the agent read" | What happens |
| --- | --- |
| off (default, `leak_action: alert`) | the request goes out, and you get a push and a Needs attention item naming the agent, the host and what was carried |
| on (`leak_action: block`) | the request is blocked, and the keys seen at that address are paused |

A honeytoken in a request always blocks it and pauses the key. Model providers aren't read: they get
everything by design. The API keys used with them are listed under
More → Network, and a second key for the same provider is pushed. An upload over 16 MB is too large to
read and is blocked unless its host is allowed.

**Decoy keys.** A file of fake API keys sits in the agent's container at
`~/.config/secrets/api-keys.env`; the agent's skill tells it never to touch that folder. Opening the
file, or using one of the keys anywhere, pauses the agent's keys and puts its address in quarantine,
where the proxy gives it nothing at all. You get a push and a Needs attention item. More → Network,
"Decoy keys", switches them off, sets "Only tell me", makes new keys, and lifts a quarantine ("Let it
out again").

**When Doorman can't tell.** A request the proxy couldn't check (Doorman down, or an agent that read
more than Doorman fingerprints in an hour) follows `when_doorman_down`: let through by default. If you
block leaks, switch this to `block` too.

**Who and what.** Doorman learns which key uses which address from the key's own calls, and a small
observer looks up the process behind each connection. With the activity hook installed, the log puts
each connection under the tool call that made it; a task's screen lists its connections.

## Asking for an exception

```sh
doorman egress request <host> --reason "…"     # or the MCP tool request_network_access
```

A card in your Inbox shows the target, what blocked it, the agent's reason, the task and what the key
read lately. You allow it **once** (an hour), **for this task**, **always** (onto the allow list, for
every agent, with a fresh passkey check), or deny it. The agent hears `egress_decided`.

## What it doesn't catch

- A careful leak: encrypted, paraphrased, or a few characters at a time.
- A leak through the model provider with your own key.
- Agents on other machines: the proxy watches the agent's container only.
- A program that pins certificates fails unless its host is on the passthrough list, and then it is only
  logged.

The proxy patches two mitmproxy internals and pins mitmproxy 12.3.1; check them before upgrading.
