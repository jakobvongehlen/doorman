# How it works

Doorman is three things, plus one extra:

- **Permissions and tools in one place.** Every account is a plugin; each tool is Off, Ask me or Auto,
  set by you in the plugin's Tools panel ([Setting up plugins](plugins.md#each-tool-off-ask-me-or-auto)).
  That panel is the only thing that decides what an agent may do.
- **Credentials outside the agent.** Secrets live in Doorman's encrypted vault. An agent holds only its
  agent key, which works only on the agent network and can be paused or revoked.
- **Isolation.** Doorman runs in its own container, apart from the agent's. Each plugin runs as its own
  Linux user under Landlock and seccomp ([Plugin isolation](plugins.md#plugin-isolation)).
- **Extra: network watch.** An optional egress proxy that is the agent's only way out
  ([Network watch](network-watch.md)).

## What happens to a call

| The call | What Doorman does |
| --- | --- |
| Unknown, malformed or switched off | Denied. The error says where to change it; you get no notification. |
| Carries a honeytoken (a decoy string you planted) | Denied, and the agent's key is paused until you resume it. You get an alert. |
| Reversible | Runs now, journaled with the state before and after, and can be undone. |
| Irreversible (an email, a message, an invitation, a share link) | Waits for your approval. |
| Payment (a tier a plugin can declare; Doorman ships no bank plugin) | Always waits for your approval, within a monthly budget. |

Reads answer at once. What they return passes the steps in
[Third-party content](third-party-content.md) first.

## Approvals

An approval shows what goes out, where it goes, and the task it belongs to ("For task 12 · <your
text>"). A task a trigger or a reminder made says "Not written by you" instead, so a stranger's sentence
never reads as your instruction.

It shows a warning for every check that failed:

- a recipient that doesn't come from you ([below](#who-counts-as-yours)), with the mail it came from
  and a **Trust this address** button;
- an agent that read both outside content and private data shortly before;
- the optional second-opinion model (`reviewer:` in `doorman.yaml`).

**Approving** is a tap in the logged-in app. The tap carries a hash of exactly what the screen showed,
attachments included, so it approves that and nothing else. If what goes out changed since the agent
asked (an edited note, a changed attachment), the approval is closed and the agent has to ask again;
the hash is checked once more right before the send. `approval_passkey: true` makes every approval a
passkey signature instead of a tap.

**After the tap** the app says what happened: "Sent to anna@example.org", "Not sent: <reason>. Nothing
went out", or "It may or may not have gone out. Check your Sent folder". A send that takes longer than
`send_wait_seconds` (3), such as a large upload, shows "Sending…" and reports when it ends.

**Deny** takes an optional note for the agent ("Not this week. Ask me again on Monday.").

**Expired.** An approval nobody decided within `approval_ttl_hours` expires and nothing goes out. Its
screen offers **Ask the agent again**: the agent makes the same call again, and every check runs afresh.

### Who counts as yours

A send's destinations (addresses, numbers, chats, links, IBANs) are checked one by one. One has no "new
recipient" warning when it is:

- in the task text you wrote, or in an answer you typed to the agent's question;
- the sender of the mail, or a member of the chat, being answered;
- on your trust list (More → Trust list), wildcards like `*@example.org` included;
- **in your contacts:** your own address books, never ones others share with you. A phone number matches
  a WhatsApp chat by its digits;
- **someone you wrote to before:** a send you approved that went out, or a mail in your Sent folder.
  Sends that ran without asking don't count, and neither does Sent mail Doorman touched.

The last two are switches on More → Trust list, both on. Switching one on takes a fresh passkey check.
`trust: {contacts: false}` (or `written_before`) in `doorman.yaml` fixes a switch. An IBAN is only ever
known through the trust list.

The approval says why each known recipient counts ("in your contacts (Anna de Vries)", "you wrote to
them before (3 Nov)"). A send without warnings can be accepted from its notification, and a tool set to
Auto may run for it.

### From the notification

The push is titled with what is at stake ("Send to anna@example.org", "New recipient: x@y.com") and
shows the first lines of what goes out.

- **Deny** denies it right there.
- **Accept** approves in place when a tap in the app would: one send, no warning, not a payment, not an
  MCP tool, `approval_passkey` off. Otherwise it opens the approval. A payload that changed after the
  push went out is refused.
- **Several sends from one task** within `push_group_seconds` (60) share one push, with **Accept all**
  and **Deny all** when each could be accepted alone, otherwise **Review**. The review screen shows
  every send in full, with "Deny only this one" on each.
- **iPhones** show no buttons on web notifications; tapping the notification opens the approval.
  **Android** shows them on an expanded notification, also on the lock screen. If that's too loose,
  `approval_passkey: true` turns Accept into "open the app".

Other pushes that ask have buttons too:

| Push | Buttons | The yes acts on the push |
| --- | --- | --- |
| "<agent> asks for network access" | **Allow once** (an hour), **Deny** | yes; For this task and Always are in the app |
| "Changeset to review: <title>" | **Apply all**, **Deny** | when no change carries a warning; a send in it still asks you |
| "Held back: <reason>" (injection guard) | **Release**, **Keep held back** | never: Release opens the item, where its text is shown |

## Stopping an agent

**A paused key.** A honeytoken, or a tripped decoy key under network watch, pauses the agent's key: every
call answers `key_paused` until you resume it under More → Agents, with a passkey check. Sends it asked
for before stay waiting, with a red warning on their cards.

**The emergency stop** (More → Emergency stop, or Stop agents in the Inbox) has two strengths:

- **Pause** refuses every agent call. Sends waiting for approval keep waiting, and you can still decide
  each one. The keys stay, so **Resume** brings the agents straight back. A task's lease doesn't run out
  while paused.
- **Revoke all keys** pauses and revokes every agent key, for a key that may have leaked. You then
  create new keys.

Pausing and revoking need only your logged-in session, so stopping is never slowed down by a passkey
prompt. Resuming asks for a fresh passkey check.

## The journal

Every change is an entry with a diff, like a commit. You can revert one entry, a whole task, or
everything since a point in time. Sent things are skipped: a sent mail can't be unsent.

- **Reverts work per field.** If you changed something else on the object since, that stays. If you
  changed one of the same fields, the revert stops and shows before, agent and now side by side, and
  you decide.
- **Checked afterwards.** Doorman reads the object back; if a field didn't go back, the revert is marked
  failed and you can try again.
- **Agents can undo their own reversible changes** ([Undo](agents.md#undo)).
- **Reads** go into a lighter read log (Journal → Reads): which agent, which read, and the subjects or
  titles of what came back, kept for `read_log_days` (90).
- **Journal → Feed** shows what agents were told ([Events](agents.md#events)).

## When things go wrong

- **A write that fails halfway** keeps its diff and its Revert button if it changed anything.
- **Sends run at most once.** A send the service refused, or that never got that far, is marked failed:
  nothing went out. Anything less clear (a timeout after it was sent, a crash in the middle) is marked
  unknown, never retried, and you're asked to check.
- **Doorman checks unknown sends itself** where the plugin can: mail looks for its Message-ID in your
  folders 1, 5, 15 and 30 minutes later, and tells you and the agent when it went out after all.
- **A crash between approval and send:** the worker sends it after the restart, unless that is more than
  `approval_ttl_hours` after you approved it. Then it's cancelled and you're told.
- **A plugin whose manifest can't work** is left out when Doorman starts and listed under Needs
  attention; the rest runs.
- **Needs attention**, at the top of the Inbox, lists each problem once and pushes it once: failed or
  unknown sends, expired approvals, tasks nobody finished, failed backups, plugins whose login stopped
  working (checked hourly), plugin jobs failing for an hour. Each clears by itself once fixed.

## Known gaps

Doorman lowers what an agent can do without you; it doesn't make an agent safe. Each optional part
lists its own limits: the [injection guard](third-party-content.md#the-injection-guard),
[spotlighting](third-party-content.md#spotlighting), [network watch](network-watch.md#what-it-doesnt-catch),
the [reader/actor split](reader-actor.md#what-the-split-doesnt-do) and
[plugin isolation](plugins.md#plugin-isolation).

- **MCP, as a client:** remote servers only, tools only (no prompts or resources). **As a server**
  (`/mcp`): tools only, answers as JSON (no SSE stream), local agents only (no OAuth).
- **CalDAV** changes to a recurring event touch the whole series (Google Calendar changes one
  occurrence).
- **Sign-in.** A passkey login has no rate limit beyond the passkey itself. A password login waits after
  five wrong tries, for everyone: someone who reaches the owner app can keep you out by guessing.
- **Without HTTPS** the password, the login and the app's traffic cross the network unencrypted, and
  there are no notifications.
- **One process.** The owner app and the agent API run in one process; `owner_allow_cidrs` keeps the
  agent's network away from the owner app.
- **The vault key** is taken out of Doorman's environment once the vault has opened, so nothing Doorman
  starts inherits it. It is still in the container's configuration (`docker inspect`) and in
  `/proc/<pid>/environ`, which root and Doorman's user can read.
- **Memory.** Only the text extractor has a memory cap; the guard's scanner and the embedding model
  don't.
