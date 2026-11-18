# Reader and actor

Every agent key has a role. **Solo is the normal setup:** one agent reads and writes, protected by
cleaning, spotlighting, the recipient checks and your approval of every send.

The reader/actor split is optional hardening for people who want the agent that can act never to see a
stranger's words. You run two keys instead of one (More → Agents → New agent key → Advanced):

| Role | Sees | Can |
| --- | --- | --- |
| solo | everything its plugins give | read, write, send (sends wait for you) |
| reader (`doorman-reader`) | raw mail, chats, files, attachments | file records and answer the actor's questions; nothing else |
| actor | records, answers, an item's structure, events without text, your own data (calendar, notes, file and chat lists) | every write tool; no raw third-party read |

The reader is deliberately not an agent: a small program that makes one fresh model call per item or
question, with no memory, no tools and no web. A hostile mail can at worst spoil its own record or
answer.

## What the actor works with

- **Records** (`doorman records`). The reader files one per mail, WhatsApp message, Teams chat message
  and new file: category, suggested action, a short summary, dates, an amount, and the sender and date
  taken from the item itself. `--source`, `--from`, `--since`, `--until` and `--text` narrow it down.
- **An item's structure** (`doorman meta <ref>`): what it takes to act, without anything a stranger
  wrote. Ids, addresses, timestamps, sizes, attachment numbers and types, flags, and your own folder
  names. No subjects, display names or file names: those are prose a sender chose.
- **Answers** (`doorman ask <ref> "which attachment is the invoice, and what's the amount?"`). The reader
  reads the item, with up to three attachments, and fills a fixed form within seconds. The actor gets
  `question_answered` and fetches it with `doorman answer <id>`. A question nobody answers within an
  hour is given up.
- **Events** with what happened and where (id, time, plugin, type, ref), without text.

Records and answers are third-party text written down by a model, so they reach the actor like any
outside content ([Third-party content](third-party-content.md)). They follow the plugin's switches: with
the plugin or its item read off, its records are left out.

## Running the reader

It works with any OpenAI-compatible API. The text of your mail and chats goes to that host, so pick one
with a data processing agreement that doesn't train on or keep your data.

Create a reader key (**More → Agents → New agent key → Advanced → Reader**), then in `deploy/.env`:

```sh
READER_DOORMAN_TOKEN=dmn_...
READER_API_BASE=https://<host>/v1
READER_API_KEY=...
READER_MODEL=<the host's model name>
```

and start it with `docker compose --profile reader up -d --build`. `doorman-reader --once` runs one
round, answers the questions waiting, and exits. It keeps no state; Doorman remembers how far it got.

| Variable | Default | |
| --- | --- | --- |
| `READER_RESPONSE_FORMAT` | `json_object` | `json_schema` if the host supports it, `none` if neither |
| `READER_SOURCES` | every plugin it can read | comma-separated plugin names (mailboxes, `whatsapp`, `teams`, `files`) |
| `READER_EVERY_MINUTES` | 5 | how often it looks for new items |
| `READER_LOOKBACK_DAYS` | 3 | how far back it looks |
| `READER_PER_SOURCE` | 25 | items per plugin per round; the rest come next round |
| `READER_MAX_CHARS` | 12000 | longer items are cut before they go to the model |
| `READER_SUMMARY_CHARS` | 300 | at most 500 |
| `READER_ANSWER_CHARS` | 400 | length of an answer to a question, at most 600 |
| `READER_ATTACHMENTS` | 3 | attachments it reads for one question |
| `READER_ATTACHMENT_CHARS` | 6000 | text per attachment for a question |
| `READER_QUESTION_WAIT` | 25 | seconds one wait on the question queue lasts (0: questions only at each round) |

## What the split doesn't do

A steered reader can still write a misleading summary or answer. It can't act on it, and your approval
of every send stays the real protection. The split costs a second model, on a host that sees your mail,
and a model call per item. With `reader_actor_split: false`, actor keys read like solo keys.
