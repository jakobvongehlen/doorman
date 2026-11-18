# Running Doorman

`./setup.sh` asks how Doorman should run (Docker or Python), where you open the owner app and how you
sign in, then does the steps below for you. Run it again to change the answers: it keeps your data and
never replaces the vault key.

## With Docker

```sh
cd deploy && mkdir -p data && cp doorman.example.yaml data/doorman.yaml   # then edit it
cp .env.example .env                                     # the setup (COMPOSE_FILE) and the keys go here
sed -i "s|^DOORMAN_VAULT_KEY=.*|DOORMAN_VAULT_KEY=$(openssl rand -base64 32 | tr '+/' '-_')|" .env   # a new vault key
docker compose up -d --build
docker compose exec doorman doorman-admin setup-code     # a one-time code for your first passkey
```

- **Vault key.** `DOORMAN_VAULT_KEY` unlocks every stored credential and is never part of a backup. Keep
  it in your password manager. Doorman refuses to start when the key doesn't open the vault.
- **Owner app.** It listens on `127.0.0.1:8711`. Put HTTPS in front of it (a reverse proxy or a tunnel)
  and set `public_url` in `doorman.yaml` to that address before you register a passkey: passkeys are
  bound to it. No HTTPS? [Sign in with a password](#without-https-a-password).
- **Agents.** The agent runs in another container on the `doorman-agent` network and reaches Doorman at
  `http://doorman:8710`. It must never see Doorman's volume or reach the owner app
  ([Connecting agents](agents.md)).
- **File archive.** It lives in `deploy/data/archive/`. For a folder elsewhere, mount it in
  `compose.yaml` and set it as the files plugin's `root` (Plugins → files → Settings).
- **Root.** The container starts as root on purpose: a small root process runs Doorman as the user
  `doorman`, and each plugin and helper process as a user of its own
  ([Plugin isolation](plugins.md#plugin-isolation)).

## With Python, without Docker

Python 3.11 or newer. Plugins still run in a locked-down process of their own (Linux 6.7), but not as a
user of their own, and nothing keeps an agent on the same machine away from Doorman's files. Use it to
try Doorman, or with the agent on another machine.

```sh
python3 -m venv .venv && .venv/bin/pip install -e ".[all]"
.venv/bin/doorman-admin init          # writes doorman.yaml and the data folder
sed -i 's|^public_url:.*|public_url: http://localhost:8711|' doorman.yaml
.venv/bin/doorman-admin setup-code    # a one-time code for your passkey; or: sign-in password
.venv/bin/doorman-admin serve
```

The vault key is made on the first start and kept in `data/vault.key`. Set `DOORMAN_VAULT_KEY` instead
to keep it away from the data it opens; Needs attention reminds you until you do
(`vault_key_file_warn: false` on a dev instance). `owner_listen` and `agent_listen` in `doorman.yaml` say
where the two ports listen.

## Signing in

Doorman signs in with a passkey or with a password, one or the other. A login lasts 12 hours.

```sh
doorman-admin sign-in            # says which it is
doorman-admin sign-in passkey    # switch to a passkey: prints a setup code
doorman-admin sign-in password   # switch to a password: asks for it twice, at least 10 characters
```

Switching logs every device out, and switching to a password removes the passkeys. In Docker, put
`docker compose exec doorman` in front.

### Passkeys

A passkey needs an HTTPS address with a name, or `localhost`. **More → Passkeys → Add a passkey** adds
another one after a passkey check. Every new passkey is announced under Needs attention and with a push
to your other devices, so one added from a phone left unlocked doesn't go unnoticed.

### Without HTTPS: a password

To open the owner app at a plain address like `http://192.168.1.20:8711`, switch to a password, name
your network in `owner_allow_cidrs` in `doorman.yaml`, set `DOORMAN_OWNER_BIND=0.0.0.0` in `.env` and
run `docker compose up -d`. Never add the agent's network (`172.31.0.0/24`).

- Without HTTPS, browsers give no notifications and no home-screen app, and others on the network can
  read the password and everything the app shows.
- Where the app asks for a fresh passkey check, it asks for the password again.
- After five wrong passwords in a row every further try waits: 15 seconds, then twice as long each
  time, up to five minutes. The right password waits too, so someone guessing on your network can keep
  you out. Restarting Doorman ends the wait.
- `approval_passkey: true` doesn't go with a password: Doorman refuses to start with both.

### A lost phone

Remove its passkey on another device (**More → Passkeys → Remove**). That ends the phone's logins and
its notifications at once, and Accept on a notification it already has no longer works.

If you can't log in anywhere:

```sh
doorman-admin logout-all   # every login ends, every device stops getting notifications
doorman-admin setup-code   # then add a passkey and remove the lost one
```

## Notifications

**More → Notifications → Enable on this device.** Doorman sends Web Push itself; there is no push server
to run.

- Set `push.subject` in `doorman.yaml` to a `mailto:` address: Apple refuses pushes without one.
- On an iPhone, add the app to the Home Screen first (iOS 16.4 or later).
- Every device new to Doorman's notifications is announced under Needs attention and with a push to
  your other devices. Not you? Remove it under More → Notifications, and its passkey under
  More → Passkeys.
- Logging out on a device stops its notifications; logging in again brings them back. A login that
  only runs out keeps them.

## Backups

With `backup.dir` set (the example config has `/backups`, which is `deploy/backups` on the host), the
worker makes a backup every night at `backup.schedule` (`03:30` in your `timezone`), keeps the last
`backup.keep` (14) and then runs `backup.copy_command` to copy it off the host. A night it missed is
made up as soon as the worker runs again.

```sh
doorman-admin backup status   # the schedule, the last run and the next
doorman-admin backup          # one now, copied off the host too
doorman-admin restore <backup dir> [--with-config] [--force]   # with Doorman stopped
```

```yaml
backup:
  dir: /backups
  copy_command: rclone copy {path} offsite:doorman/{name}   # or: restic backup {path}
  copy_env: [RCLONE_CONFIG]          # variables it gets from Doorman's environment
  copy_timeout_minutes: 120
```

- **The copy command** is yours; Doorman brings no copy tool. `{path}` is the new backup's directory,
  `{name}` its name (`doorman-20261107-033000`), `{dir}` is `backup.dir`. No shell runs it, so `|`, `;`
  and `$VAR` mean nothing: write a script when you need them. It gets `PATH`, `HOME`, the locale and the
  variables `copy_env` names, never the vault key. Install the tool in the image (a `FROM` your Doorman
  image with `apt-get install rclone`) and mount its configuration.
- **In a backup:** the database, every plugin's data, the encrypted vault and `doorman.yaml`, checked by
  SHA-256, taken while Doorman runs.
- **Not in a backup:** the vault key; the search index, which the plugins fill again after a restore
  ([Search](search.md#looking-after-the-index)); the file archive's files, only their index and tags.
  Back the archive folder up with your other files, or add it to `backup.extra_paths`.
- **Mail originals** (`archive: full`) are hard-linked from the previous backup, so each backup only adds
  new mail. Copy by hand with `rsync -aH`; without `-H` each backup takes full room.
- **Watching it.** More → Status shows the last backup, whether it left the host, and the next one.
  Needs attention lists a failed backup, a failed copy and no good backup for 36 hours.
- **Your own timer.** `schedule: null` turns the nightly run off, for a host timer that runs
  `doorman-admin backup`.
- **A removed plugin** leaves what it kept as `data/plugins/<name>.removed-<when>`, still in the
  backups. Delete it when you no longer want it. To bring it back, stop Doorman, add the plugin again
  under the same name and move the folder back.

## Upgrades

- **The database** carries a schema version. A newer Doorman copies `doorman.db` first
  (`doorman.db.v<old version>-<time>.bak`, next to it; delete it once the new version runs well), then
  migrates it step by step. Plugins' own databases work the same way (`archive.db.v<old version>.bak`).
- **An older Doorman** refuses to start on a newer database. Run the newer version again, or restore a
  backup made before the upgrade. A backup restored into a newer Doorman is migrated on its first start.
- **The search index** isn't migrated: it is made anew.
- **Packages are pinned.** The images install exactly what the tests ran with
  (`deploy/requirements.lock`, `deploy/reader.lock`, with hashes). To update: change `pyproject.toml`,
  run `.venv/bin/python deploy/lock.py` (Python 3.13 on x86_64 Linux), run the tests and commit the
  locks. `tests/test_lock.py` fails while the lock and `pyproject.toml` disagree.

## Keeping an eye on it

- **More → Status:** the worker, the emergency stop, the last backup, waiting tasks, when each agent
  last showed up, each plugin's login, and the last 7 days in numbers.
- **Needs attention**, at the top of the Inbox, lists each problem once and clears it once fixed. It
  also lists silence: no backup for 36 hours (`backup_warn_days`, 7, when you run backups yourself), a
  reader with no round for `reader_silent_minutes` (60), tasks nobody picked up for
  `task_wait_warn_minutes` (60). Set any of them to 0 to turn it off.
- **`GET /health`** on either port answers 200 while the database works and the worker is ticking. The
  compose healthcheck uses it.
- **When Doorman is down** it can't tell you so. Point `health.ping_url` at a dead-man check
  (healthchecks.io, Uptime Kuma): the worker GETs it every 5 minutes, and `<ping_url>/fail` while
  unhealthy. Give the check a period of 5 minutes and a grace time of about 10.

  ```yaml
  health:
    ping_url: https://hc-ping.com/<your check's id>
  ```

## What the database keeps

The worker deletes hourly what is past its time (`retention:` in `doorman.yaml`, in days; 0 keeps that
kind for good):

| Setting | Default | What goes |
| --- | --- | --- |
| `scans_days` | 180 | the injection guard's score per text; a text read again later is scanned again |
| `quarantine_days` | 365 | held-back items you released or kept, counted from your decision |
| `provenance_days` | 90 | where an address an agent saw came from |
| `notifications_days` | 90 | the notices list |
| `attention_days` | 90 | resolved Needs attention items |
| `records_days` | 365 | the reader's records |
| `vacuum_days` | 7 | how often at most it checks whether a VACUUM is worth it |

Outside `retention:`: `read_log_days` (90), `events_days` (7) and `uploads.keep_days` (7). Kept for good:
the journal with its approvals, changesets and tasks, and the privacy placeholders.

## A demo with made-up data

`doorman-admin demo` runs Doorman against local fakes, with no real accounts: a student's mailbox (one
mail with a PDF, one with a prompt injection), a week of events, tasks and contacts, a shared "Flat"
calendar, a timetable feed, notes, files and a fake WhatsApp. It needs `dovecot` and the `demo` extras
(`pip install -e ".[all,demo]"`) and runs as an ordinary user, never as root.

```sh
doorman-admin demo --dir ~/demo-data --background   # first run creates and seeds it; returns once it serves
. ~/demo-data/agent.env                             # DOORMAN_URL, DOORMAN_TOKEN, and `doorman` on PATH
doorman caps --brief && doorman recent && doorman agenda
doorman call mail.send 'to:=["tom.jansen@mail.example"]' subject=Hi body=Hello   # waits for the owner
doorman-admin demo inbox --dir ~/demo-data          # play the owner: what waits
doorman-admin demo approve 1 --dir ~/demo-data      # or --all; deny [--note ...]; release <held id>
doorman-admin demo answer 2 "Wed" --dir ~/demo-data # answer an agent's doorman ask-owner
doorman-admin demo stop --dir ~/demo-data           # stops Doorman and every fake it started
```

- It listens on `127.0.0.1`, six ports from `--port-base` (8730). Without `--background` it runs until
  Ctrl-C.
- Sent mail lands in `outbox/` as `.eml` files; the log is `demo.log`.
- Starting it again on the same directory carries on; delete the directory for a fresh one.
- The owner commands use a token only a demo's `doorman.yaml` has, so they never work on a real Doorman.
- The injection guard uses a keyword stand-in for its model: the planted mail is held back until you
  `release` it.

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install -e ".[all,test]"
.venv/bin/python -m pytest -n 3                  # everything, three at a time: ~2 min
.venv/bin/python -m pytest -n 3 -m "not slow"    # without the OCR tests: ~1 min
.venv/bin/python -m pytest tests/test_jobs.py -x # one file while working on it
.venv/bin/python -m pytest -m "not integration"  # without Radicale and Dovecot
```

- The calendar tests start Radicale; the mail tests need `dovecot` 2.4 and skip without it.
- Tests run plugins inside Doorman's own process so they can use fakes. `DOORMAN_TEST_SANDBOX=1` runs
  them in their own process, where about 70 tests that reach into plugin objects fail by design.
- `tests/test_privsep.py` runs only as root.
- `DOORMAN_GUARD_MODEL_DIR=<folder with model.onnx, tokenizer.json, config.json>` adds one test with
  the injection guard's real model.
- `.github/workflows/ci.yml` runs the tests (with the image's packages, and on Python 3.11 with the
  newest), the proxy's own tests ([deploy/egress/README.md](../deploy/egress/README.md#development)) and
  a build of every image.
- The agent API is documented at `/docs` on port 8710 (OpenAPI).
