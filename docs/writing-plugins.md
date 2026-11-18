# Writing a plugin

A plugin is a folder with a `manifest.yaml` and a `plugin.py`. The ones that ship with Doorman are in
`doorman/plugins/<type>/`. Your own goes into a directory that `plugin_paths` in `doorman.yaml` lists
(`plugin_paths: [/srv/doorman-plugins]`, one folder per plugin). Doorman loads it at its next start, and
the owner adds it in the app like any other ([Setting up plugins](plugins.md#adding-one)).

**Start from `doorman/plugins/notes`:** it has each part once, in under 200 lines.

```sh
doorman-admin plugin check <folder|name>   # the manifest's errors and warnings; exits 1 on an error
```

## The manifest

The manifest lists the plugin's reads, its write tools with their parameter schemas, the settings and
credentials it needs, and the hosts it connects to. Each write tool has a tier:

| Tier | What happens |
| --- | --- |
| `reversible` | runs right away, journaled with before and after, can be undone |
| `irreversible` | a send: waits for the owner's approval, unless the owner chose to let it run without asking |
| `payment` | always waits for the owner's approval, and is refused when it would go over `payments.monthly_budget` (500) |

A tool can raise its tier for a single call by overriding `tier(args)`, as the calendar does when
outside attendees are involved. Doorman ships no payment plugin; `tests/fakes/plugins/fake_bank` is the
stand-in the tier is tested with.

Doorman checks the manifest when it loads the plugin. An unknown key is a warning with the closest key
it knows. A missing `name`, a duplicate read or tool, invalid JSON Schema, or a key that names something
the plugin doesn't have is an error: the plugin is left out and listed under Needs attention.

### Top-level keys

Keys marked *built-in* count only in a manifest that ships with Doorman.

| Key | What it is | Default |
| --- | --- | --- |
| `name` | The plugin type: lower case letters, digits and `_`. Required. | |
| `version`, `description` | Shown on the plugin's card; the description also goes to the agent. | |
| `extends` | A plugin folder next to this one whose manifest this one starts from (`mail_outlook` extends `mail_imap`). | |
| `credentials` | Secrets it needs, kept in the vault. A missing one shows under Needs attention. | `[]` |
| `optional_credentials` | Secrets it can use but doesn't need. | `[]` |
| `credential_files` | *Built-in.* `{credential: file}`: a secret a file on Doorman's host provides (the WhatsApp sidecar's token). | |
| `config` | `{setting: what it means}`. The app offers only the settings listed here. | `{}` |
| `setup` | Steps shown in the owner app when setting it up; `[text](https://…)` is a link. | `[]` |
| `login` | `oauth` (Connect / Disconnect in the app) or `link` (a QR or pairing code). See [Logins](#logins). | none |
| `login_provider` | The name on the Connect button. | `Google` |
| `network` | Hosts it connects to. See [Network](#network). | none |
| `sandbox` | *Built-in.* `user`, `filesystem`, `read`, `write`, `network: any`, `call_timeout_seconds`. | |
| `agent_settings` | Settings an agent may change (`doorman.configure`). `folders.drafts` names one key of a mapping. | `[]` |
| `agent_narrow` | Of those, list settings an agent may only shorten (which calendars, which address books). | `[]` |
| `agent_add_only` | Of those, list settings an agent may only add to (folders not to archive). | `[]` |
| `agent_install` | `true`: an agent may set one up (`doorman.install`); it starts switched off. | `false` |
| `reads`, `tools` | The reads and the write tools; keys below. | `[]` |
| `events` | Event types `poll_events` returns: `{name, description, fields}` or a name. `job: <job>`: that job returns it instead. `read: <read>`: the read whose switch decides whether agents get the event's text. | `[]` |
| `jobs` | Background jobs: `{name, every_minutes, budget_seconds, off_when: {setting: value}}`. | `[]` |
| `copy_to_archive` | Files to copy into the files archive: `[{from, to, setting, after}]`. See [Background work](#background-work). | `[]` |
| `item` | How to read one item by its ref (`doorman meta`, `doorman ask`, the reader): `{read, param}`, plus `attachments`, `context` and `events`. | none |
| `ref_read` | The read whose content a tool may attach by its ref. The plugin's `open_ref` returns the content. | none |
| `index` | The plugin feeds Doorman's search index. See [Feeding search](#feeding-search). | none |
| `agenda`, `recent`, `contacts` | The read for Doorman's agenda, what's-new list and "Trust a contact" list. See [Joining Doorman's own reads](#joining-doormans-own-reads). | none |
| `known_recipients` | `contacts` or `sent_mail`: the plugin tells the recipient check whom the owner knows. | none |

### A read (`reads:`)

| Key | What it is | Default |
| --- | --- | --- |
| `name`, `description` | The read's short name (the agent calls `<instance>.<name>`) and what it returns. | |
| `params` | JSON Schema for its parameters, checked before the read runs. | none |
| `trust` | `third_party`: the data is cleaned, redacted, scanned by the injection guard and taints the session. `owner`: the owner's own data, none of that. | `third_party` |
| `raw` | `true`: full third-party text (a message body). An actor key can't read it. | `false` |
| `private` | `true`: reading it marks the session as having read private data, which a later send is checked against. | `false` |
| `scan_items` | When the read returns a dict, the key that holds its list of items, so the guard holds back single items. | |
| `not_scanned` | Fields the guard leaves out, by path (`id`, `attendees.id`): IDs the service makes. Long random strings score as encoded injections. Never a field a sender fills in. | `[]` |

### A write tool (`tools:`)

| Key | What it is | Default |
| --- | --- | --- |
| `name`, `description` | As for reads. | |
| `params` | JSON Schema for its arguments. | none |
| `tier` | `reversible`, `irreversible` or `payment`. | `reversible` |
| `destinations` | `[{field, kind}]`: which arguments are recipients (`email`, `phone`, `iban`, `chat`, `url`). `field` may be a path (`changes.attendees`). | `[]` |
| `editable` | Arguments the owner may change on the approval screen. | `[]` |
| `ref_fields` | Arguments that take references to other plugins' content (attachments). | `[]` |
| `can_send` | `true`, or better when it happens (`on a shared list`), for a write that becomes a send for some calls. The agent is told before it calls. | `false` |
| `always_approve` | `true`: it asks even when the owner lets the plugin [run its sends without asking](plugins.md#letting-a-plugin-run-its-sends-without-asking). For a tool that is worse to get wrong than the others, one that makes a file public, say. | `false` |
| `amount_field` | For a payment: the argument that holds the amount. | `amount` |
| `caller_arg` | An argument Doorman fills with the calling key's name, whatever the agent passed. | none |
| `based_on_arg` | An argument listing refs the agent says its work was made from. Doorman refuses the call unless the calling key could read each. | none |

### Feeding search

`index: {read, kinds, every_minutes, needs, settings, security_senders}` puts a plugin's items into
Doorman's search index. The plugin doesn't search: it feeds. Doorman calls `index_feed(cursor, budget)`
every `every_minutes` (5), after each of the plugin's jobs and after a write made through it, and keeps
the cursor. The smallest feeding plugin is `tests/fakes/plugins/fake_library`.

The answer is `{items, removed, cursor, more, complete, reset}`:

| Field | Meaning |
| --- | --- |
| `items` | New or changed items since the cursor (below). |
| `removed` | Keys gone since the cursor. |
| `complete` | `true`: the items are everything the plugin has, and anything else of it goes. For small sources. |
| `more` | `true`: call again right away. Stop after about `budget` seconds. |
| `reset` | `true`: this answer begins a pass over everything. Answer a cursor you didn't give (your store was deleted or restored) this way. |

After a pass from the start (cursor `None`, or `reset`), whatever the index still holds of the plugin
that the pass didn't bring is dropped.

An item is `{key, kind, title, date, text | parts, fields}` plus optional keys:

| Key | Meaning |
| --- | --- |
| `kind` | One of the manifest's `kinds`: `mail`, `file`, `note`, `event`, `task`, `chat`. |
| `date` | ISO; what `since`/`until` and newest-first go by. |
| `from`, `to`, `in`, `has_attachment` | The search's filters; `in` is a folder, a calendar, a chat. |
| `parts` | `[{part, name, text}]` for an item with several texts: a mail's body is part 0, each attachment its own part. |
| `ref` | Defaults to `<instance>:<key>`. |
| `same` | A key copies elsewhere share (`mid:<message-id>`). They fold into one hit only when they also read the same. |
| `refs` | Refs of what the item is made of (a chat's day: its messages), so a guard hold on one holds the hit. |
| `fields` | Shown with each hit as they are; keep them short. Give the header fields the item's read gives (`subject`, `from`…), so privacy placeholders hide a hit as they'd hide that read. |
| `hidden_text`, `unchecked` | On a PDF's part: the hidden-text check found something, or hasn't cleared it yet. Read PDFs with `ctx.extract_text(check_pdf="fast")`, and run the OCR check (`check_pdf=True`) in a background job. |

The manifest's other `index` keys:

- `read` names the read that gates the items: while it is switched off, they don't show, and its
  `trust` and `raw` decide the guard and the actor rule for every hit. Usually the read that returns one
  item (`mail.read`).
- `needs: {<kind>: <read>, attachment: <read>}` names further reads a hit needs switched on
  (`task: tasks`; `attachment: attachment` for parts other than 0).
- `settings: [<setting>, …]` names the settings that change what the plugin feeds. When one changes, its
  items leave search and it feeds again from the start. Without the key, every setting counts.
- `security_senders: false` says the feed doesn't depend on `redaction.security_senders`.

### Joining Doorman's own reads

Each key names one of the plugin's reads, which Doorman then asks as an ordinary read:

| Key | The read takes | It returns |
| --- | --- | --- |
| `agenda: events` | `start`, `end` (date-times with an offset, the end exclusive) | entries with `start`, `end`, `all_day`, `summary` or `title`, `location`, `calendar`, and `ref` and `id` or `uid`; an invitation also `organizer` and `response` |
| `recent: recent` | `since` (UTC), `limit` | rows with `sent` or `date`, `chat` or `folder`, `from`, `text` or `subject`, and `ref`, `chat_id` or `id`, `mine`, `unread` |
| `contacts: search` | `query` (empty: everyone), `with_email`, `limit` | `{contacts: [{name, emails: [{address, type}], organisation, ref}], more}`; for the owner app only |

`known_recipients: contacts` or `sent_mail` makes Doorman ask the plugin's
`known_recipients(destinations)` during the recipient check: of these `[kind, value]` pairs, the ones
the owner knows, as `{value: {...}}`. For `contacts`, `{"name": …}` from the owner's own address books
only. For `sent_mail`, `{"messages": [{"id": Message-ID, "date": ISO}]}` from the owner's Sent folder.
Answer from a cache: a call that fails or takes longer than 8 s knows nobody.

## The code

`plugin.py` has a class `Plugin(BasePlugin)` (`doorman/plugin_api.py`) with two tables: `TOOLS` maps each
tool in the manifest to a `Tool` class, `READS` each read to the name of a method. A read method takes
the call's parameters as a dict and returns what the agent gets.

`self.ctx` holds what the plugin was given: `instance` (its name in the app), `config`, `credentials`,
`data_dir` (its folder), `log` and `owner_identities`. A tool reaches the plugin as `self.plugin`.

### A write tool

| Method | What it does |
| --- | --- |
| `execute(args, before)` | Do it, and return `ExecResult(result, after, object_ref, summary)`: `result` goes to the agent, `after` is the object's state now, `summary` is the journal's line. |
| `snapshot(args)` | The object's state before, so it can be undone. Handed to `execute` as `before`. |
| `undo(object_ref, before, after)` | Bring the object back to `before`. Without it the journal has no Revert for the tool. |
| `describe(args)` | One line that says what the call will do, for the journal and the approval. |
| `render_diff(before, after, args)` | How the change looks in the journal. The default compares field by field and leaves out keys starting with `_`. |
| `current(object_ref)` | Optional: read the object now, for drift checks. |
| `preview(args, before)` | Optional: the state the call would leave, for changesets. |

Optional extras:

| Method or attribute | For |
| --- | --- |
| `tier(args)` | The tier of this call when it depends on the arguments. Say when in the manifest's `can_send`. |
| `prepare(args)` | Fill in what the tool works out itself before Doorman checks and journals the call (`mail.reply` adds To, Cc and Subject). What it returns is what the owner approves. Raise `Denied(..., "invalid")` for a bad id. |
| `destinations(args)` | The recipients as `(kind, value)` pairs, when they aren't arguments (`teams.send_chat` gives the chat's members). |
| `trusted_destinations(args)` | Addresses the call's context vouches for: the sender of the mail a send answers. |
| `destination_origins(args)` | Where a destination that isn't the owner's came from (a reply-all's other recipients), shown with the warning. |
| `outgoing(args)` | For a send whose arguments only point at something (a note's id): `{label, title, text}`, what actually goes out. It is hashed into the approval, so return the same content for the same thing. |
| `follow_up(args, result)` | For a send: what the owner can still do once it is out ("Ask anna@example.com to disregard the note."). |
| `verify_sent(args, before, error)` | Check an unknown send: `"sent"`, `"failed"` or `"unknown"`. See below. |
| `undo_fields`, `FIELD_SCOPED_UNDO` | Put back only some fields, or say that `undo` already touches only what the action changed. |
| `ref_for` | Which object an edit works on, so a write that fails halfway can still be reverted. |
| `IGNORE_FIELDS` | Timestamps and the like to leave out of comparisons. |

### Sends: failed or unknown

A send tool raises `NotSent` when it knows nothing went out, so Doorman can say "failed" instead of
"check whether this went out". Any other error leaves the send "unknown".

- `plugin_api.http_json(service, method, url, token=...)` sorts this out for an HTTP service: no token,
  no connection, a failed GET and a 4xx are `NotSent`; a timeout after the body went out, a 5xx and a
  2xx that isn't JSON are unknown. `refused_4xx=False` is for a service that may answer 4xx after doing
  something.
- `before_sending(step)` does the same for a step before a non-HTTP send.
- Once the request that sends went through, don't let a `NotSent` from a later step escape `execute`.
- `verify_sent` is asked 1, 5, 15 and 30 minutes after a send broke off. Keep what the check needs in
  the snapshot under keys starting with `_` (`mail_imap` chooses its Message-ID there). Say `"failed"`
  only on evidence: the owner may send it again.

### Background work

Methods on the plugin:

| Method | What it does |
| --- | --- |
| `check()` | Does the login still work? Runs hourly and feeds Needs attention. |
| `poll_events(cursor)` | What happened since the cursor, as `(events, new_cursor)`; each event is `{"type": …, "ref": …, more fields}`. Asked every `trigger_poll_minutes`. The first poll (cursor `None`) usually only notes where "now" is. Keep fields short. |
| `run_job(name, budget)` | One run of a job the manifest declares. Stop after about `budget` seconds and return `{"summary": …}`; `"more": true` brings the worker back in half a minute. The status may carry `"events": [...]` for what is too heavy to poll; declare those with `job: <job>`. `doorman-admin job <plugin> <job>` runs one slice by hand. |
| `index_feed(cursor, budget)` | See [Feeding search](#feeding-search). |
| `maintenance()` | Upkeep that isn't a job, every `maintenance_interval_minutes` (60) and with `doorman-admin maintain <plugin>`. |
| `open_ref(path)` | With `ref_read:`: `(filename, bytes)` for the ref `<instance>:<path>`. |
| `close()` | Called before the process stops, to close what it holds open. It gets about two seconds, and a crash skips it. |

`copy_to_archive` is manifest-only: files the plugin downloads into its own folder that belong in the
files archive, which the plugin itself can't write. Doorman copies what's new after the jobs and tools
named in `after`: `[{from: downloads, to: Invoices, setting: archive_into, after: [sync, download]}]`.

### Logins

- `login: oauth`: `login_status()` (`{connected, account, ready}`), `login_start()` (`{auth_url,
  redirect_uri, expires_in}`), `login_finish(response_url)` and `logout()`; `interactive_login` for
  `doorman-admin login`. Keep what the login gives with `ctx.save_credential`. `google_calendar` and
  `doorman/ms_login.py` are the examples.
- `login: link`: `login_status()` (with `link`, the code to show, until it says `connected`),
  `login_start(phone=None)` and `logout()`, as the `whatsapp` plugin has them.

### Line protocols

An agent's text that goes into a line protocol needs care: a line break in it ends the command and
starts another, on a connection that is already logged in. httpx, requests and smtplib refuse line
breaks; IMAP libraries don't. Refuse control characters twice: in the manifest
(`not: {pattern: '[\x00-\x1f\x7f]'}` and a `maxLength`; a `^...$` pattern lets a final line break
through) and in code, right before the command. `mail_imap`'s `imap_text` and `SafeIMAPClient` are the
example.

## The sandbox

A plugin runs in its own locked-down process ([Plugin isolation](plugins.md#plugin-isolation)). It gets
what its manifest declares and nothing else.

### Network

`network:` lists every host it connects to. Leave it out or write `[]` and the plugin can't connect
anywhere.

```yaml
network:
  - graph.microsoft.com            # a host, any port
  - "{url}"                        # the plugin's own setting `url`; a URL counts by its host (and port)
  - "{imap_host}:993"              # a setting, one port only
  - "{nextcloud.url}"              # a nested setting
  - "{sidecar_url|http://127.0.0.1:8720}"   # with a default when the setting is empty
  - "*.icloud.com"                 # any host below a domain (not icloud.com itself)
```

- `"{key}"` also reads a credential of that name, for addresses that are themselves secret.
- A host written into the manifest must be a public address unless the plugin ships with Doorman. Hosts
  from the owner's settings may be local.
- **Doorman makes the connections.** Libraries built on Python's `socket` (requests, httpx, imaplib,
  smtplib, caldav) work unchanged. Anything that does its own DNS over UDP, C code that opens sockets
  past Python, and programs the plugin starts (a CLI, a browser) can't connect.
- The plugin can't `listen()`. `socket.socketpair()` works.
- `network: any` counts only in a built-in manifest. For anything else, only the owner can open the
  network.

### Files, environment and credentials

- **Files.** The plugin reads the system, Python and its own code. It reads and writes only
  `ctx.data_dir`, which is also its working folder, `HOME` and `TMPDIR`.
- **Attachments** come only through `ctx.resolve_ref`, and only for references in the arguments of the
  write Doorman is running (`execute`): never in a read, a job or `prepare`.
- **Environment.** `PATH`, the locale, `TZ`, `SSL_CERT_*` and `PLAYWRIGHT_BROWSERS_PATH`, nothing else.
- **Credentials** are in `ctx.credentials`. A new or refreshed one goes back with
  `ctx.save_credential(key, value)`; update `self.credentials` too.

### State

The process can restart at any time: after `plugin_idle_minutes` without calls, after a call longer than
`plugin_call_timeout_seconds`, or after a crash. Keep nothing that must last only in memory. Calls run
in threads of their own.

A database in `ctx.data_dir` is opened with `plugin_api.open_store(path, SCHEMA, MIGRATIONS,
belongs_to=...)`, which gives its layout a version:

- `SCHEMA` is always the newest layout, `CREATE ... IF NOT EXISTS` throughout.
- `MIGRATIONS[n]` brings a store from version n + 1 to n + 2, in one transaction. Append; never change
  one that shipped. A new table or index needs none; a new column does.
- The file is copied beside itself before the first pending migration. A store a newer plugin wrote is
  refused (`StoreTooNew`).
- `belongs_to` names what the store was made for (the mail archive passes its login and server). A store
  made for something else raises `StoreOfAnother`: set it aside with `plugin_api.set_aside(path, why)`
  and open a new one.

### What crosses the process boundary

Arguments and results travel as JSON:

- Dicts, lists, strings, numbers, `bytes`, sets and `ExecResult` arrive as they were sent. Tuples arrive
  as lists. Anything else (a `Path`, a date) arrives as its `str()`.
- `PluginError`, `Denied` and `NotSent` keep their kind. Any other exception becomes a `PluginError`
  under its own name.
- What a tool class can do (`undo`, `current`, `verify_sent`, `IGNORE_FIELDS`…) is read once, when the
  process starts.

### Asking for more

A manifest's own `sandbox:` block counts only for built-in plugins. Any other plugin says in its README
what it needs, and the owner adds it under the plugin's name in `plugin_sandbox_overrides`
([Plugin isolation](plugins.md#plugin-isolation)).

## Testing

- Test through the engine (`Agent(engine).call(...)`, `.read(...)`, both from `tests/conftest.py`)
  rather than by reaching into the plugin object.
- `make_engine(tmp_path, plugin_paths=[...], plugins={name: {"type": ..., "enabled": True, "config":
  {...}}})` gives a test an engine with a plugin from a folder of your own.
- Run the tests once with `DOORMAN_TEST_SANDBOX=1`, which puts the plugin in its own process, network
  list and all.
- `tests/fakes/plugins/fake_probe` shows what a plugin can and can't reach.
