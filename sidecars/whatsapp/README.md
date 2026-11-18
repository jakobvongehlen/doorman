# WhatsApp sidecar

[wacli](https://github.com/steipete/wacli) (MIT) links to your WhatsApp account as a companion
device, like WhatsApp Web, and keeps a copy of your messages in SQLite. `shim.py` keeps
`wacli sync --follow` running and gives Doorman a small HTTP API on port 8720: chats, messages,
the change log Doorman turns into `new_message` events and its search index, sending a text, and linking
(the QR or pairing code Doorman's app shows). The API is described at the top of `shim.py`. Doorman
holds no WhatsApp session; this container does.

**Unofficial.** WhatsApp's terms don't allow third-party clients, and accounts can be banned. Use
a second number.

**Status:** tested against a real wacli 0.26.0 binary with a store filled the way sync fills it
(`tests/test_whatsapp_wacli.py`), **never linked to a real account**.

## Run it

```sh
cd deploy
docker compose --profile whatsapp up -d
```

Then in Doorman's app: Plugins → whatsapp, set **sidecar_url** to `http://whatsapp:8720`, switch it
on, and tap **Link WhatsApp**. On the phone: WhatsApp → Settings → Linked devices → Link a device, and
scan the code on the card. Or open "Link with your phone number", and type the code the card shows
into the phone (WhatsApp sends it a notification).

There is no token to type. On its first start the shim makes one up and writes it to
`/run/doorman-whatsapp/token` in the `whatsapp-token` volume, which Doorman mounts read-only; Doorman
copies it to its vault within a few seconds (journaled as a credential change). The file is 0600 and
both containers' users have uid 10001. To choose the token yourself, put `SIDECAR_TOKEN=...` into
`.env`: the shim then uses that one and writes it to the file instead. Doorman takes only a plain file
holding one token (printable ASCII without spaces, at most 4 KB); a link, a FIFO or anything larger is
logged and left out, so the sidecar can't make Doorman read another file.

Linking from the shell works too, while the shim runs:

```sh
docker compose exec whatsapp wacli auth                     # scan the QR code
docker compose exec whatsapp wacli auth --phone +49...      # or type the code shown into the phone
```

After linking, the shim starts sync as soon as wacli has fetched the recent history. After linking,
WhatsApp sends roughly the last three months of history. Sync runs with `--presence-mode quiet`, so
your phone keeps ringing for new messages.

Sends go only through the running sync process. When sync isn't running, the shim refuses a send
and Doorman shows it as not sent. If WhatsApp unlinks the device, sync stops and Doorman's Needs
attention says so: tap **Unlink** on the card (it runs `wacli auth logout`), then link again.

## Without Docker

```sh
git clone --branch v0.26.0 https://github.com/steipete/wacli.git && cd wacli
CGO_ENABLED=1 go build -tags sqlite_fts5 -o wacli ./cmd/wacli    # needs Go 1.27 and a C compiler
WACLI=./wacli SIDECAR_TOKEN=$(openssl rand -hex 24) LISTEN=127.0.0.1:8720 python3 -I ../shim.py
# then: doorman-admin vault set whatsapp sidecar_token   (the same token; without Docker there's no shared volume)
```

wacli keeps its store in `$WACLI_STORE_DIR` (default `~/.local/state/wacli`).

## Backup

The session and messages are in the `deploy/whatsapp` volume (`store/session.db`, `store/wacli.db`).
Doorman's backup copies them when Doorman can see that folder. Mount it into the doorman service and
add the path to `backup.extra_paths`.

## Updating wacli

Change `WACLI_VERSION` and `WACLI_COMMIT` in the Dockerfile. Then run the end-to-end test with that
binary: `DOORMAN_TEST_WACLI=/path/to/wacli .venv/bin/python -m pytest tests/test_whatsapp_wacli.py`.
