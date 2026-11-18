# Search

Doorman keeps one search index over everything the plugins hold: every mailbox's archive, the file
archive, notes, calendars and task lists, WhatsApp chats. `doorman search` looks there and nowhere else,
so it is one ranking over all of it and never waits for a server.

## The mail archive

Each mailbox keeps an archive of its own: Doorman downloads its mail once and from then on follows the
server. The server stays the source of truth and the archive never writes back. What it adds is memory:
a message that leaves the mailbox stays findable, marked `deleted_on_server`.

| `archive:` | Keeps |
| --- | --- |
| `index` (default) | metadata and the text of every body and attachment; a message gone from the server can still be found and read |
| `full` | also each original (gzipped `.eml`), so it can be forwarded and its attachments sent on |
| `off` | nothing; the mailbox has no mail in search |

```yaml
  uni_mail:
    type: mail_outlook
    config:
      archive: full
      archive_months: 24             # optional: a rolling window; older mail is dropped as it ages
      archive_skip_folders: [Newsletters]
      archive_ocr: true              # scans read in the background (default)
```

- **Sync** runs every 5 minutes: new mail, what left each folder, then the backfill, newest first. The
  first download runs in the background; the plugin's card shows how far it got.
- **Never archived:** Junk/Spam, Trash, Drafts, the Outbox and the Agent trash. A message moved there
  counts as deleted.
- **Scanned attachments** are read with OCR in a second pass, only while no agent needs the extractor.
- **Security senders' mail** (`redaction.security_senders`) is archived without its text: only subject
  and addresses are searchable.
- **`mail.search`** still asks the server directly, for the current state of a folder.
- **On disk:** `data/plugins/<mailbox>/archive/`. Plain text takes roughly a tenth of a mailbox; `full`
  adds about the mailbox's size. Deleting the folder starts the archive over.
- **An archive belongs to its mailbox** (login and server). Change either and the old archive is set
  aside as `archive.other-mailbox-<when>` and a new one begins.
- `doorman-admin job <mailbox>` runs one sync slice by hand (`--budget 600` for a longer one).

## One search over everything

Plugins feed the index: every few minutes (5 for mail and files, 30 for calendars), after each sync, and
right after a write Doorman made, so a change is searchable within seconds to minutes.

```sh
doorman search "rental contract" kind=file
doorman search steuerbescheid since=2025-01-01 kind=mail
```

| Filter | |
| --- | --- |
| `kind` | `mail`, `file`, `note`, `event`, `task`, `chat` |
| `sources` | plugin names |
| `from`, `to` | sender, recipient |
| `in` | a mail folder, a files folder, a calendar, a chat, a notes category |
| `since`, `until` | by each item's date |
| `has_attachment` | |
| `sort=date` | newest first instead of best first |

Without words it lists the newest items that pass the filters.

- **It finds** whole words, word stems in German, Dutch and English (`Rechnungen` finds `Rechnung`), and
  when those find little, parts of words (`steuer` finds `Einkommensteuerbescheid`) and close spellings.
  With [semantic search](#semantic-search) on, also meaning.
- **Each hit comes with its passage**, about 800 characters around the match, so the agent can answer
  from it, cite the ref, and read the whole item only when it needs more. A passage from a mail's
  attachment makes the hit that attachment's (`mail:<id>#<n>`).
- **Each document once.** The same text in several places (a PDF attached to a mail and saved in the
  files) is one hit, with the other places under `also`.
- **Calendars** hand over entries from `search_past_months` back (24) to 12 months ahead, one item per
  series. **WhatsApp** hands over one item per chat and day.

### What an agent sees

A hit shows what reading the item from its plugin would show, no more:

- A source counts only while its plugin and its read are switched on. Switching either off hides its
  items at once; removing the plugin deletes them.
- Each hit passes the steps in [Third-party content](third-party-content.md): the guard can hold it
  back, and what the privacy placeholders hide can't be found.
- An actor key ([Reader and actor](reader-actor.md)) gets no raw source.
- When a plugin's settings change (fewer calendars, say), its items leave search at once and come back
  under the new settings.

### Looking after the index

The index lives in `data/search/` and is never backed up or repaired, only made anew: after a restore,
after an upgrade that changed its layout, or when it finds itself damaged. Every source then feeds again
from the start, and search says under `sources` which ones aren't through yet.

```sh
doorman-admin index             # how far each source is
doorman-admin index --pull      # ask every source now
doorman-admin index --rebuild   # feed one source, or all, again from the start
doorman-admin index --upkeep    # make stems and vectors for --budget seconds
```

## Semantic search

Optional: finds things by meaning, across languages. **More → Semantic search** switches it on (or
`semantic: {enabled: true}` in `doorman.yaml`) and shows how far each source is. It downloads its model
once: [Granite Embedding 107M multilingual](https://huggingface.co/ibm-granite/granite-embedding-107m-multilingual)
(IBM, Apache 2.0) as a [uint8 ONNX build](https://huggingface.co/gety-ai/granite-embedding-107m-multilingual-onnx),
124 MB, pinned and checked by sha256.

- **Embedding** runs in the background, newest items first, about a tenth of a second per 800
  characters, and only while no agent is searching.
- **Resources:** a locked-down process of its own, about 500 MB while it runs, stopped after 10 idle
  minutes.
- **A hit found by meaning** has to stand out clearly from the rest of the index. It carries its
  `meaning_score`, and `by_meaning` when none of the searched words is in it. When few hits stand out,
  up to five near misses follow them, for the agent to judge.
- **The vectors** are kept apart from the index (`data/search/vectors.db`), so a rebuilt index gets them
  back in minutes without the model. A new model after an upgrade means new vectors, made by themselves.

## The agenda

`doorman agenda --from --to` asks every calendar (`google_calendar`, `caldav`, `ics`) for the same range
and returns one list sorted by start.

- An end date includes its day (`--to 2026-11-09` has the 9th). Times come back in Doorman's `timezone`
  with their offset.
- `--invitations` keeps only the invitations you haven't answered.
- Each part is an ordinary read of that calendar, so switching its `events` read off leaves it out. A
  calendar that fails is reported under `sources` and the others still answer.
- It returns entries as they are, with the `ref` and `id` the calendar's own tools take. It computes
  nothing, such as free slots.
