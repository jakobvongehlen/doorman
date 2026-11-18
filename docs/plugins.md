# Setting up plugins

Every service Doorman talks to is a plugin. One type can run several times: two IMAP accounts are two
plugins named, say, `mail` and `work`, both of type `mail_imap`. You switch plugins on or off in the app
and set each tool to [Off, Ask me or Auto](#each-tool-off-ask-me-or-auto). That is the one place that
decides what an agent may do.

## Adding one

**Plugins → Add a plugin**, pick the type, fill in a name, its settings (a list is typed as `[a, b]`)
and its credentials. It runs right away, without a restart.

- **Credentials** go straight into the encrypted vault. The app only ever shows whether each one is
  set. On the host: `doorman-admin vault set <plugin> <key>`.
- **Passkey check.** Every change to a plugin or its credentials asks for your passkey (or password)
  again if the last check is more than 5 minutes old.
- **Revert.** Adding a plugin and changing its settings are journal entries you can revert. Removing a
  plugin deletes its credentials and can't be reverted; what it kept is set aside as
  `data/plugins/<name>.removed-<when>`.
- **Where they live.** In Doorman's database, not in `doorman.yaml`. A new Doorman starts with `notes`
  and `files`.
- **Your own plugin types** come from the folders `plugin_paths` in `doorman.yaml` lists
  ([Writing a plugin](writing-plugins.md)).

## Plugins

| Plugin | What you set | Tested against |
| --- | --- | --- |
| `google_calendar` | `client_id`, `timezone`; vault `client_secret`; then Connect ([below](#google-calendar)) | a stand-in for Google; the real Google for reads and creating events |
| `caldav` | `url`, `owner_emails`, `timezone`, optional `calendars` and `lists` (`[]` turns events or tasks off), `shared_collections`; vault `username`, `password` (Nextcloud: an app password) | Radicale; **not yet a real Nextcloud** |
| `contacts` | `url` (as for `caldav`), optional `books`; vault `username`, `password`. Read-only ([below](#contacts-carddav)) | Radicale; **not yet a real Nextcloud** |
| `ics` | one plugin per feed: `label`, `timezone`; vault `url` (the feed's address, `webcal://` is fine) | a stand-in feed with recurring events and exceptions |
| `mail_imap` | `imap_host`, `smtp_host`, `from_address`; vault `username`, `password`, and `smtp_username`, `smtp_password` if SMTP has a login of its own. `server_files_sent: true` for a server that files sent mail itself (Gmail, Exchange) | Dovecot and an SMTP server |
| `mail_outlook` | `address`, `tenant`; then Connect ([below](#microsoft-365-mail-mail_outlook)) | a real university mailbox (reading, and one approved send) |
| `teams` | `tenant`; then Connect ([below](#microsoft-teams-teams)) | a stand-in for Microsoft; **not yet the real Teams** |
| `nextcloud_notes` | `url`; vault `username`, `password` (an app password) | a stand-in Notes API |
| `notes` | nothing; Doorman's own notes | unit tests |
| `files` | nothing: the archive is `data/archive`; `root` puts it elsewhere. Share links need `nextcloud` (`{url, user, path_prefix}`) and vault `nextcloud_password` | a temporary archive; Nextcloud share links untested |
| `whatsapp` | run the wacli sidecar ([sidecars/whatsapp/README.md](../sidecars/whatsapp/README.md)), set `sidecar_url`, then link it on the card (QR or pairing code) | the sidecar with a real wacli binary; **never linked to a real account** |
| MCP server | `url`; then Connect ([below](#mcp-servers)) | a stand-in MCP server with its own sign-in |

Good to know:

- **Mail deletes** move the message to an **Agent trash** folder, never to the server's Trash, which
  providers empty on their own.
- **Replies.** `mail.reply` answers a message by its id: Doorman fills in To, Cc (with `all`), `Re:` and
  the thread headers. It is a send like `mail.send`. `mail.draft_reply` leaves the same reply in Drafts.
- **Calendar writes that are sends.** A calendar write waits for you when the event has guests other
  than you, when it deletes someone else's invitation (that declines it), or when the calendar or list
  is shared. Everything else is a quiet, undoable write. `shared_calendars` (Google) and
  `shared_collections` (CalDAV) mark more calendars as shared by hand.
- **Answering invitations.** `respond` (`accept`, `decline`, `tentative`) tells the organizer and always
  waits for you. `google_calendar.respond` takes a `comment`; `caldav.respond` answers every occurrence
  of a series and takes none.
- **Files you add yourself** reach search after the next walk of the folder (hourly, or now with
  `doorman-admin maintain files`).
- **Search and the agenda** work across plugins ([Search](search.md)).

## Google Calendar

The app shows these steps with links when you add `google_calendar`. One-time setup in the
[Google Cloud console](https://console.cloud.google.com/), with the Google account whose calendar the
agent should use:

1. Create a project and enable the **Google Calendar API** in it.
2. **Google Auth Platform → Branding:** app name and your address. **Audience:** External, then
   **Publish app**, so it's *In production*. In *Testing*, Google ends the login after 7 days. You need
   no verification for your own use; Google shows an "unverified app" warning at login (Advanced →
   continue).
3. **Clients → Create client → Desktop app.** Put its client ID into the plugin's settings and its
   secret into the credential `client_secret`.
4. **Plugins → Google Calendar → Connect account → Open Google sign-in**, allow access, then copy the
   address of the page Google ends on (it starts with `http://127.0.0.1:8799/` and doesn't load) and
   paste it into the app. `doorman-admin login google_calendar` does the same in a terminal.

Doorman asks for three permissions: events (read and write), the calendar list, and the calendars'
sharing settings (read-only). **Disconnect** revokes the login at Google. Changing a recurring event
changes only that occurrence.

## Contacts (CardDAV)

`contacts` reads your address books: `url` is the server root or your principal (Nextcloud:
`https://cloud.example.com/remote.php/dav/`), the login is `username` and an app password. Agents get
`contacts.search`, `contacts.get` and `contacts.books`. It writes nothing.

- **Only address books you own are read.** Books others share with you, and the server's system address
  book, are listed in `contacts.books` and never read.
- **A send to someone in your books has no "new recipient" warning**
  ([Who counts as yours](how-it-works.md#who-counts-as-yours)), while More → Trust list → "People in
  your contacts" is on.
- **Trust a contact** under More → Trust list adds one of their addresses to the trust list for good.

## Microsoft 365 mail (`mail_outlook`)

For a university or work mailbox where you can't register an app of your own. The plugin signs in as
Thunderbird (its public client ID, no secret); tenants that allow Thunderbird allow this. There is no
proxy to run.

1. Add the plugin with `address` (your mail address) and `tenant` (`university.example`; the default
   `common` also works).
2. On its card: **Connect account → Open Microsoft sign-in.** Microsoft ends on
   `https://localhost/?code=…`, a page that doesn't load: copy its whole address and paste it into the
   app. In a terminal: `doorman-admin login <name>`; with `login_flow: device` it shows a device code
   instead (some tenants block those).

- Your sign-ins show up as "Mozilla Thunderbird" in your account's sign-in log.
- The login expires with your institution's session rules. It then shows under Needs attention and you
  connect again.
- Two tenant settings can still stop it: IMAP switched off for your mailbox (the plugin check reports
  it), and SMTP sending switched off for the tenant (a send fails with `5.7.139`, marked as not sent).
- To use your own app registration, set `client_id` and `redirect_uri`.

## Microsoft Teams (`teams`)

Chats through Microsoft Graph, signed in the same way as `mail_outlook`.

1. Add the plugin with `tenant` (`university.example`; the default `organizations` also works). Leave
   `client_id` empty.
2. On its card: **Connect account → Open Microsoft sign-in**, sign in, and paste back the
   `https://localhost/?code=…` address the browser ends on.
3. Microsoft either asks you to consent or says **Need admin approval**, depending on your
   organization. Admins see the request under Thunderbird's name, not Doorman's.

- **Permissions:** `offline_access User.Read Chat.Read Chat.Create ChatMessage.Send`, which a user may
  grant by themselves.
- **Channels** always need an admin's consent. Until then the channel reads and `teams.post_channel` are
  refused with a message that says so. Once an admin allowed it, add `Team.ReadBasic.All
  Channel.ReadBasic.All ChannelMessage.Read.All ChannelMessage.Send` to `scopes` and connect again.
- **Your own app registration** (Entra ID, "Mobile and desktop applications", redirect
  `http://localhost`): set its id as `client_id`. The default scopes then include channels.

## MCP servers

A service that runs its own MCP server connects without a plugin: **Plugins → Add an MCP server**. Pick
a well-known server (Notion, Linear, GitHub, GitLab, Atlassian, Sentry, Todoist, Airtable, ClickUp,
Intercom, Stripe, Hugging Face) or **Another server** and paste its address, then **Connect account** on
its card. Only remote servers over HTTPS; Doorman never runs a server's code.

- **Settings:** `url`, and `client_id` for a server whose sign-in doesn't let apps register themselves.
  A server that takes an access token instead of a sign-in (GitHub's) gets it as the credential `token`.
- **Reads and writes.** A tool the server labels read-only is a read and runs right away. Every other
  tool is a write and asks you first. Doorman can't undo what a foreign tool does.
- **Never looser by itself.** A tool that shows up later is a write whatever its label says, and a tool
  first seen as a write stays one.
- **You are told when the tools change.** Doorman looks at the server's list every hour (and on **Check
  now**). A new or changed tool is marked on the card and named in a notice in your Inbox. Nothing is
  switched by a change.
- **Auto (Always allow)**, on the tool's row or on a write's approval: that tool runs without asking,
  unless a check fails or the daily limit is reached.
- **Treat as read / write**, for a server whose labels are wrong. Your choice wins.
- **A new address is a new server.** Changing it drops the old sign-in, tool list and your choices.
- **Descriptions are scanned** when the [injection guard](third-party-content.md#the-injection-guard)
  is on.

The well-known servers are a list of addresses (`doorman/mcp/known.py`). Each answered and offered app
registration in November 2026; the sign-in itself was not tried with an account of each service.

## Each tool: Off, Ask me or Auto

Under **Tools** on a plugin's card every tool has a three-way control:

| Position | What it does |
| --- | --- |
| **Off** | The agent can't use it. |
| **Ask me** | Every call waits for your OK, also a change that could be undone. |
| **Auto** | It runs without asking. An undoable change shows in the Journal with Revert. A send goes out only while every check passes and under the daily limit; otherwise it asks after all. |

- **Defaults:** undoable tools start on Auto, sends on Ask me.
- **Reads** answer at once and can't wait for you, so a read is Off or On.
- **Payments** can only be Off or Ask me.
- **Read-only**, at the top of Tools, turns every write Off. Reads keep working.
- **A refused agent is told where to change it:** `google_calendar.create_event is Off in
  google_calendar's settings (Plugins → Tools)`. The journal has the same under "Show denied calls".
- **Loosening needs a recent passkey check:** setting a send to Auto, and any switch that lets a send
  run without asking again. Switches that only tighten need none.

### Letting a plugin run its sends without asking

**Run its sends without asking me**, under a plugin's Settings and credentials (the journal calls it
`no_approval`), does for all of a plugin's sends what Auto does for one: they run as long as every check
passes and fewer than `limits.direct_per_day` (30) ran that way in the last 24 hours. Otherwise it
becomes a normal approval with the reason shown. A tool whose manifest says `always_approve` asks
anyway, and so does every payment. An MCP server has no such switch: you allow its tools one by one.

## Plugin isolation

Each plugin runs in a process of its own, as a Linux user of its own, locked down with Landlock and
seccomp. It gets its own settings and credentials and nothing else: not the vault, not the database, not
another plugin's files. It can reach only the hosts its manifest lists, and the kernel holds it to that.

You can loosen this per plugin in `doorman.yaml`, by the plugin's name. Only there: neither the app nor
an agent can widen a sandbox. It applies after a restart.

```yaml
plugin_sandbox_overrides:
  calendar:                       # a caldav plugin named calendar
    network: ["*.icloud.com"]     # more hosts; `any` opens the network
    user: doorman                 # run as Doorman's user
    filesystem: open              # no Landlock limit on files (the user and seccomp still apply)
    read: [/srv/shared]           # or: more folders it may read; `write:` for ones it may change
    call_timeout_seconds: 600     # how long one call may take (default plugin_call_timeout_seconds, 300)
  notes: false                    # back into Doorman's own process
```

- **Requirements.** The user separation needs Doorman to start as root, which the Docker image does.
  Landlock needs Linux 5.13 (6.7 to close the network). `python -m doorman.sandbox` says what the kernel
  supports.
- **No lockdown, no start.** A plugin or helper process that can't be locked down doesn't start.
  `plugin_sandbox: false` turns the whole thing off.
- **Helper processes** that read strangers' files (the text extractor, the guard's scanner, the
  embedding model) run under the same lockdown, as users of their own.
- **One built-in plugin comes loosened:** `files` runs as Doorman's user, because the archive belongs to
  it.

**What it doesn't cover:** a kernel bug, a plugin abusing the account it legitimately holds, a plugin
describing one action and doing another, and anything a plugin with `network: any` does on the network.
Plugins from other people still need a code review.
