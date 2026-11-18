# Connecting agents

An agent holds one thing: its agent key. It reaches Doorman on the agent port (8710) through the
`doorman` command, the HTTP API (OpenAPI at `/docs`) or MCP (`/mcp`). Every route goes through the same
checks, journal and approvals.

## With the command line

**More → Agents → New agent key** shows the key once, with a message to paste into your agent (Claude
Code, for example) and the same steps as shell commands. The agent downloads its skill and the `doorman`
command from Doorman, sets `DOORMAN_URL` and `DOORMAN_TOKEN`, and runs `doorman caps` to see what it may
do. Set `agent_url` in `doorman.yaml` if agents reach Doorman under another address than the default.

- **An agent that runs all the time** keeps `doorman events --follow` going and hears about your
  decisions, its sends' results and new tasks the moment they happen ([Events](#events)).
- **A one-off agent per task:** let the command line start it for each task you create in the app.

  ```sh
  doorman watch --exec "claude -p {prompt}"
  ```

## Over MCP

The agent port serves `/mcp` (MCP Streamable HTTP) with the agent key as a bearer token. It offers
thirteen tools: `caps`, `read`, `search` (also the agenda), `call`, `undo`, `propose`, `ask`, `ask_owner`,
`request_network_access`, `wait`, `events`, `tasks` and `upload`. The list stays short on purpose: the
agent looks up one tool's parameters with `caps` (`name: …`) when it needs them.

**Local use only.** `/mcp` has no OAuth: it trusts the agent key and nothing else. Don't publish the
agent port; reach it from the same machine (`agent_listen: 127.0.0.1:8710`) or the `doorman-agent`
Docker network.

Claude Code, on the same machine:

```sh
claude mcp add --transport http doorman http://127.0.0.1:8710/mcp --header "Authorization: Bearer dmn_..."
```

or in the project's `.mcp.json`:

```json
{"mcpServers": {"doorman": {"type": "http", "url": "http://127.0.0.1:8710/mcp",
                            "headers": {"Authorization": "Bearer ${DOORMAN_TOKEN}"}}}}
```

Claude Desktop starts its servers as local commands, so put a bridge in between
(`claude_desktop_config.json`):

```json
{"mcpServers": {"doorman": {"command": "npx", "args": ["-y", "mcp-remote", "http://127.0.0.1:8710/mcp",
                            "--allow-http", "--header", "Authorization:${AUTH}"],
                            "env": {"AUTH": "Bearer dmn_..."}}}}
```

`wait` and `events` hold on for at most 45 seconds over MCP, since clients give up on longer calls: call
them again when they come back with nothing.

## Hermes Agent

[Hermes Agent](https://hermes-agent.nousresearch.com/docs/user-guide/features/mcp) connects to `/mcp`
and reads Doorman's skill. Create an agent key (More → Agents, role Solo), then:

1. **The server**, in `~/.hermes/config.yaml`. Hermes's container must be on the `doorman-agent` network.
   Run `/reload-mcp` or restart Hermes; the tools appear as `mcp_doorman_caps`, `mcp_doorman_call` and
   so on.

   ```yaml
   mcp_servers:
     doorman:
       url: http://doorman:8710/mcp        # or http://127.0.0.1:8710/mcp on the same machine
       headers:
         Authorization: "Bearer dmn_..."
       timeout: 120
   ```

2. **The skill**, so Hermes knows the rules. Copy it again after you update Doorman.

   ```sh
   mkdir -p ~/.hermes/skills && cp -r doorman/agent_skill ~/.hermes/skills/doorman
   ```

3. **A cron job every 5 minutes**, since nothing wakes Hermes over MCP by itself. A prompt like:

   > Use the doorman skill. Call Doorman's `events` tool (no `after`, `wait: 0`) and handle what's
   > new: claim and do new tasks, continue errands whose approvals were decided, call `caps` again
   > after `caps_changed`. Then call `events` once more with the `cursor` you got as `after`, so
   > Doorman marks the batch as handled. If there was nothing, stop without a message.

## What an agent works with

### Capabilities

- `doorman caps --brief`: one line per read and tool with its name, whether it is an undoable write or
  a send, its Off / Ask me / Auto position and a one-sentence description.
- `doorman help <name>`: one tool's parameter schema.
- Both carry a `version` that changes when you switch something or connect a plugin, so an agent can
  keep its copy until the version moves. `caps_changed` in the feed says when.
- A misspelt name is refused with the close ones (`did you mean mail.send?`).

### Tasks

You write a task in the app; an agent claims it (`doorman claim`), works, and reports.

- **Lease.** 30 minutes, renewed by every call the agent makes for the task. For a long stretch without
  calls it asks for more (`doorman task renew --minutes`, up to 240). A task not reported on before the
  lease runs out fails, you get a push, and the agent gets `task_cancelled`.
- **Report.** You get a push, "Done: …" or "Failed: …", which opens the task's screen: your text, the
  report, what still waits for you, and every journal entry the task made, each with Revert.
- A task is only its text. What the agent may do is set under each plugin's Tools
  ([Off, Ask me or Auto](plugins.md#each-tool-off-ask-me-or-auto)).

### Events

One request stays open, `GET /v1/events?wait=50` (`doorman events --follow`), and Doorman answers as
soon as something happens. There is no polling.

| From Doorman | Meaning |
| --- | --- |
| `approval_decided` | approved, denied (with your note), edited, or closed because it changed |
| `send_result` | sent, failed or unknown; an unknown one Doorman resolved later gets a second event |
| `approval_expired`, `approval_ask_again` | nobody decided in time; you still want it, so make the same call again |
| `entry_reverted`, `changeset_decided` | you reverted a change; you decided a proposed changeset |
| `task_created`, `task_cancelled`, `reminder_due` | a new task; you closed one or its lease ran out; a reminder the key set is due |
| `owner_answered`, `question_answered` | your answer to `ask-owner`; the reader's answer to `ask` |
| `egress_decided` | your decision on a network access request |
| `caps_changed` | a plugin or tool was switched, set up or removed; `changes` says what |

| From plugins | Meaning |
| --- | --- |
| `new_mail` | mail and Microsoft 365 mail: from, subject |
| `new_message` | WhatsApp and Teams chats: chat, sender, start of the message |
| `new_file` | a file came into the archive or changed |
| `invite_received`, `event_soon` | CalDAV and Google Calendar; `event_soon` fires `soon_minutes` (30) before an entry |

- **The cursor is Doorman's.** Each key sees each event once. The agent passes back the `cursor` of each
  answer as `after`; after a restart the last unacknowledged batch comes again. `peek=true` marks
  nothing.
- **Incoming only:** `wake=incoming` (`doorman events --wait N --incoming`) holds on until a plugin
  event, a `task_created` or a `reminder_due` comes, past the agent's own `approval_decided`.
- **Plugin events are a stranger's text** and go through the same steps as a read
  ([Third-party content](third-party-content.md)). An event is a notice: the agent reads the item by its
  ref before it acts.
- **Your switches apply.** With a plugin's item read Off, its events say only what happened and where;
  with the plugin off they are left out.
- Plugins are asked every `trigger_poll_minutes` (5). Events are kept for `events_days` (7).
- **You see the feed too**, under Journal → Feed, with a line marking how far each agent has read.
- Teams channels aren't watched.

### Following one action

- `doorman wait entry:<id>` (also `changeset:`, `question:`, `owner-question:`, `egress-request:`)
  answers once that action has ended. `doorman call … --wait N` does the same right after a call.
- `doorman status` lists what the key has open: actions waiting for you or going out, sends Doorman
  still checks, open questions, and its task with the lease.

### Asking the owner

```sh
doorman ask-owner "Tue 14:00 or Wed 10:00?" --option "Tue 14:00" --option "Wed 10:00"
```

The question shows as a card in your Inbox, marked as the agent's words, with a push titled "<agent>
asks". You tap an option, type an answer, or dismiss it.

- The agent hears `owner_answered`, or follows it with `doorman wait owner-question:<id>` (exit 0
  answered, 4 dismissed, 5 expired).
- A question nobody answers within 24 hours expires. A key has at most 5 open; reader keys can't ask.
- **A typed answer is owner text.** An address, number or link you type counts as yours in the
  recipient check, for sends by that key in that task. A tapped option doesn't: its text is the agent's.

### Undo

`doorman undo <entry>` (or `--task <id>`) reverts a reversible change the agent's own key made. Never a
send, a setup change, something you approved or set to Ask me, or anything you or another key did. It
never forces past a conflict, and its revert is a journal entry you can revert in turn.

### Files

- `doorman upload` takes a file the agent made and returns `upload:<sha256>` to attach to a send.
  Uploading asks nothing; the send still waits for you. Only the uploading key can use it. A key keeps
  at most 500 MB and 200 files (`uploads.max_total_mb`, `uploads.max_files`), deleted after 7 days
  unused.
- `files.save` copies any ref (a mail attachment, an upload, another plugin's file) into the archive.
  It never overwrites, and undo moves the copy to the trash.
- `doorman keep` (`files.keep`) writes finished work (a summary, a report, a filled-in form) into the
  archive under `Agent/` (`agent_folder`), marked with the key that made it and the refs it was based
  on, where search finds it. `replace` writes over a file an agent kept before, never one of yours.

### Changing the setup

Agents may adjust Doorman within limits (`doorman.configure`, `doorman.install`, `doorman.disable`):

- **Settings** a plugin's manifest allows (`agent_settings`: archive options, folders, calendars, time
  zones). Never server or sender addresses, credentials, sign-ins or the sandbox. Some settings an
  agent can only narrow (which calendars and address books), some it can only add to (folders not to
  archive).
- **New plugins** of a kind that allows it (`agent_install`). They start switched off, and Needs
  attention asks you to check the settings, add the sign-in and switch it on.
- **Switching off** a plugin, one of its tools, or to read-only. Never on.

Each change is a journal entry under the agent's key, which you can revert. Reader keys can't change
anything. `agent_setup: false` in `doorman.yaml` switches all of it off.
