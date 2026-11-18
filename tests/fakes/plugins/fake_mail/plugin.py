"""A mailbox in a JSON file under the plugin's data dir. Tests that need some mail plugin (the reader,
the security-review regressions) use it, so they don't depend on a real mail plugin or its server.

Tests fill it with `add()` and look at what went out in `sent()`."""

import json

from doorman.plugin_api import BasePlugin, ExecResult, PluginError, Tool


class Draft(Tool):
    def ref_for(self, args):
        return None

    def current(self, object_ref):
        return self.plugin.load()["messages"].get(object_ref)

    def preview(self, args, before):
        return {"to": args["to"], "subject": args["subject"], "body": args["body"]}

    def execute(self, args, before):
        draft_id = self.plugin.make_draft(args)
        return ExecResult(result={"id": draft_id}, after=self.current(draft_id), object_ref=draft_id,
                          summary=f"Drafted “{args['subject']}”")

    def undo(self, object_ref, before, after):
        box = self.plugin.load()
        box["messages"].pop(object_ref, None)
        self.plugin.save(box)

    def describe(self, args):
        return f"Draft “{args.get('subject')}” to {', '.join(args.get('to', []))}"


class Send(Tool):
    def trusted_destinations(self, args):
        if not args.get("in_reply_to"):
            return set()
        return {self.plugin.message(args["in_reply_to"])["from"]}

    def execute(self, args, before):
        draft_id = self.plugin.make_draft(args)
        box = self.plugin.load()
        box["sent"].append(box["messages"].pop(draft_id))
        self.plugin.save(box)
        return ExecResult(result={"id": draft_id}, object_ref=draft_id, summary=f"Sent “{args['subject']}”")

    def describe(self, args):
        return f"Send “{args.get('subject')}” to {', '.join(args.get('to', []))}"


class Plugin(BasePlugin):
    TOOLS = {"draft": Draft, "send": Send}
    READS = {"search": "read_search", "read": "read_message", "thread": "read_thread",
             "attachment": "read_attachment"}

    @property
    def path(self):
        return self.ctx.data_dir / "mailbox.json"

    def load(self) -> dict:
        if not self.path.exists():
            return {"next": 1, "messages": {}, "sent": []}
        return json.loads(self.path.read_text())

    def save(self, box: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(box))

    # for tests

    def add(self, folder: str, sender: str, subject: str, body: str) -> str:
        box = self.load()
        mid = f"m{box['next']}"
        box["next"] += 1
        box["messages"][mid] = {"id": mid, "folder": folder, "from": sender, "subject": subject, "body": body,
                                "date": f"2026-11-{box['next']:02d}T08:00:00Z", "unread": True, "attachments": []}
        self.save(box)
        return mid

    def attach(self, mid: str, name: str, ctype: str, text: str) -> str:
        """An attachment whose text the attachment read returns; its ref is <instance>:<mid>#<part>."""
        box = self.load()
        message = box["messages"][mid]
        part = len(message["attachments"]) + 1
        ref = f"{self.ctx.instance}:{mid}#{part}"
        message["attachments"].append({"part": part, "ref": ref, "name": name, "type": ctype,
                                       "size": len(text.encode())})
        box.setdefault("parts", {})[ref] = text
        self.save(box)
        return ref

    def update(self, mid: str, **fields) -> None:
        box = self.load()
        box["messages"][mid].update(fields)
        self.save(box)

    def sent(self) -> list[dict]:
        return self.load()["sent"]

    def clear(self) -> None:
        box = self.load()
        box["messages"] = {}
        self.save(box)

    # plumbing

    def message(self, mid: str) -> dict:
        found = self.load()["messages"].get(mid)
        if found is None:
            raise PluginError(f"no message {mid}")
        return found

    def make_draft(self, args: dict) -> str:
        if args.get("in_reply_to"):
            self.message(args["in_reply_to"])
        attachments = [self.ctx.resolve_ref(ref)[0] for ref in args.get("attachments", [])]
        mid = self.add("drafts", sorted(self.ctx.owner_identities or {"me@example.com"})[0], args["subject"],
                       args["body"])
        box = self.load()
        box["messages"][mid].update(to=args["to"], attachments=attachments, unread=False)
        self.save(box)
        return mid

    def read_search(self, params):
        folder = params.get("folder", "inbox")
        items = [m for m in self.load()["messages"].values() if m["folder"] == folder]
        if params.get("unread"):
            items = [m for m in items if m["unread"]]
        items.sort(key=lambda m: m["date"], reverse=True)
        return [{"id": m["id"], "ref": f"{self.ctx.instance}:{m['id']}", "subject": m["subject"], "from": [m["from"]],
                 "date": m["date"], "unread": m["unread"]} for m in items[:params.get("limit", 20)]]

    def read_message(self, params):
        m = self.message(params["id"])
        body = m["body"]
        if self.ctx.redactor.is_security_sender(m["from"]):
            body = "[redacted: message from a security sender]"
        out = {"id": m["id"], "ref": f"{self.ctx.instance}:{m['id']}", "subject": m["subject"], "from": [m["from"]],
               "date": m["date"], "body": body, "attachments": m["attachments"]}
        for key in ("to", "cc", "in_reply_to"):
            if m.get(key):
                out[key] = m[key]
        if m.get("hidden_text"):  # what a real plugin's PDF check reports (extract.pdf_hidden_text)
            out["hidden_text"] = m["hidden_text"]
        return out

    def read_attachment(self, params):
        m = self.message(params["id"])
        found = next((a for a in m["attachments"] if isinstance(a, dict) and a.get("part") == params["part"]), None)
        if found is None:
            raise PluginError(f"message {params['id']} has no attachment #{params['part']}")
        text = self.load().get("parts", {}).get(found["ref"], "")
        return {**found, "id": m["id"], "from": [m["from"]], "text": text[:params.get("max_chars", 20000)]}

    def poll_events(self, cursor):
        """new_mail for each inbox message added since the last poll (ids count up); the first poll only
        notes where "now" is, like mail_imap."""
        box = self.load()
        top = box["next"] - 1
        if cursor is None:
            return [], str(top)
        events = [{"type": "new_mail", "ref": f"{self.ctx.instance}:{m['id']}", "id": m["id"], "from": m["from"],
                   "subject": m["subject"]}
                  for m in sorted(box["messages"].values(), key=lambda m: int(m["id"][1:]))
                  if m["folder"] == "inbox" and int(m["id"][1:]) > int(cursor)]
        return events, str(top)

    def read_thread(self, params):
        folder = params.get("folder", "inbox")
        return {"folder": folder, "messages": [
            {"id": m["id"], "ref": f"{self.ctx.instance}:{m['id']}", "from": [m["from"]], "subject": m["subject"],
             "body": m["body"]} for m in self.load()["messages"].values() if m["folder"] == folder]}
