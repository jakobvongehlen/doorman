"""Notes stored as JSON files. The reference plugin: every part of the contract, nothing else."""

import json
import secrets

from doorman import clock
from doorman.plugin_api import BasePlugin, ExecResult, NotSent, PluginError, Tool


class NoteTool(Tool):
    """Shared helpers: undo for every notes tool is 'write back the before state'."""

    IGNORE_FIELDS = frozenset({"updated"})

    def current(self, object_ref):
        return self.plugin.load(object_ref)

    def undo(self, object_ref, before, after):
        self.plugin.store(object_ref, before)

    def undo_fields(self, object_ref, fields, now):
        note = self.plugin.load(object_ref)
        if note is None:
            raise PluginError(f"no note {object_ref}")
        self.plugin.store(object_ref, {**note, **fields, "updated": clock.iso()})


class Create(NoteTool):
    def preview(self, args, before):
        return {"title": args["title"], "body": args.get("body", ""), "tags": args.get("tags", [])}

    def execute(self, args, before):
        note_id = secrets.token_hex(4)
        note = {"id": note_id, **self.preview(args, None), "updated": clock.iso()}
        self.plugin.store(note_id, note)
        return ExecResult(result={"id": note_id}, after=note, object_ref=note_id,
                          summary=f"Created note “{args['title']}”")

    def describe(self, args):
        return f"Create note “{args.get('title', '')}”"


class Update(NoteTool):
    def ref_for(self, args):
        return args["id"]

    def snapshot(self, args):
        note = self.plugin.load(args["id"])
        if note is None:
            raise PluginError(f"no note {args['id']}")
        return note

    def preview(self, args, before):
        changed = {k: v for k, v in args.items() if k != "id"}
        return {**before, **changed} if before else None

    def execute(self, args, before):
        note = {**self.preview(args, before), "updated": clock.iso()}
        self.plugin.store(args["id"], note)
        return ExecResult(result={"id": args["id"]}, after=note, object_ref=args["id"],
                          summary=f"Updated note “{note['title']}”")

    def render_diff(self, before, after, args):
        strip = lambda n: {k: v for k, v in (n or {}).items() if k != "updated"} or None  # noqa: E731
        return super().render_diff(strip(before), strip(after), args)

    def describe(self, args):
        return f"Update {_named(self.plugin, args)}"


class Delete(NoteTool):
    def ref_for(self, args):
        return args["id"]

    def snapshot(self, args):
        note = self.plugin.load(args["id"])
        if note is None:
            raise PluginError(f"no note {args['id']}")
        return note

    def preview(self, args, before):
        return None

    def execute(self, args, before):
        self.plugin.store(args["id"], None)
        return ExecResult(result={"id": args["id"]}, after=None, object_ref=args["id"],
                          summary=f"Deleted note “{before['title']}”")

    def describe(self, args):
        return f"Delete {_named(self.plugin, args)}"


def _named(plugin, args) -> str:
    """A note as the owner knows it: by its title, or by its id when it can't be read."""
    try:
        note = plugin.load(str(args.get("id", "")))
    except Exception:  # noqa: BLE001 - a bad id only means there's no title to show
        note = None
    return f"note “{note['title']}”" if note and note.get("title") else f"note {args.get('id')}"


class SendCopy(Tool):
    def execute(self, args, before):
        note = self.plugin.load(args["id"])
        if note is None:
            raise NotSent(f"no note {args['id']}")
        with open(self.ctx.data_dir / "sent.jsonl", "a") as fh:
            fh.write(json.dumps({"to": args["to"], "message": args.get("message", ""), "note": note,
                                 "ts": clock.iso()}) + "\n")
        return ExecResult(result={"sent_to": args["to"]}, summary=f"Sent note “{note['title']}” to {args['to']}")

    def describe(self, args):
        return f"Send {_named(self.plugin, args)} to {args.get('to')}"

    def outgoing(self, args):
        note = self._note(args)
        if note is None:
            return None
        return {"label": "Copy of your note", "title": note.get("title") or "", "text": note.get("body") or ""}

    def _note(self, args):
        try:
            return self.plugin.load(str(args.get("id", "")))
        except Exception:  # noqa: BLE001 - a bad id only means there's nothing to show
            return None

    def follow_up(self, args, result):
        return f"Ask {args.get('to')} to disregard the note."


class Plugin(BasePlugin):
    TOOLS = {"create": Create, "update": Update, "delete": Delete, "send_copy": SendCopy}
    READS = {"list": "read_list", "get": "read_get"}

    def _path(self, note_id: str):
        if not note_id.isalnum():
            raise PluginError("bad note id")
        return self.ctx.data_dir / f"{note_id}.json"

    def load(self, note_id: str) -> dict | None:
        path = self._path(note_id)
        return json.loads(path.read_text()) if path.exists() else None

    def store(self, note_id: str, note: dict | None) -> None:
        path = self._path(note_id)
        if note is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(json.dumps(note, ensure_ascii=False, indent=1))

    def read_list(self, params):
        notes = []
        for path in sorted(self.ctx.data_dir.glob("*.json")):
            note = json.loads(path.read_text())
            if params.get("tag") and params["tag"] not in note.get("tags", []):
                continue
            notes.append({"id": note["id"], "ref": f"{self.ctx.instance}:{note['id']}", "title": note["title"],
                          "tags": note.get("tags", []), "updated": note.get("updated")})
        return notes

    def read_get(self, params):
        note = self.load(params["id"])
        if note is None:
            raise PluginError(f"no note {params['id']}")
        return {**note, "ref": f"{self.ctx.instance}:{note['id']}"}

    def index_feed(self, cursor, budget):
        """Every note for doorman search, each time: a few small files, so handing over all of them with
        `complete` (what isn't here any more leaves the index) is simpler than tracking changes. Doorman
        skips the notes that didn't change. Their text reaches agents through notes.get's switch."""
        items = []
        for path in sorted(self.ctx.data_dir.glob("*.json")):
            note = json.loads(path.read_text())
            tags = note.get("tags", [])
            items.append({"key": note["id"], "kind": "note", "title": note["title"], "text": note.get("body", ""),
                          "date": note.get("updated"), "in": tags[0] if tags else None, "fields": {"tags": tags}})
        return {"items": items, "complete": True}

    def open_ref(self, path):
        note = self.load(path)
        if note is None:
            raise PluginError(f"no note {path}")
        return f"{note['title']}.txt", (note["title"] + "\n\n" + note.get("body", "")).encode()
