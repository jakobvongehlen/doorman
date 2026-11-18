"""Nextcloud Notes over the Notes app's REST API (v1). Not tested against a real Nextcloud; tests use a
fake API. Every write is undoable. Deleting moves the note to a trash category: Nextcloud gives a
re-created note a new id, which would break later reverts, so the note is never really removed. The notes'
text goes to Doorman's search index (index_feed), where doorman search finds it."""

from datetime import datetime, timezone

import httpx

from doorman.plugin_api import BasePlugin, ExecResult, PluginError, Tool

API = "/index.php/apps/notes/api/v1"
FIELDS = ("title", "content", "category", "favorite")


class NotFound(PluginError):
    pass


def note_state(note: dict) -> dict:
    return {"id": note["id"], "title": note.get("title", ""), "content": note.get("content", ""),
            "category": note.get("category", ""), "favorite": bool(note.get("favorite")),
            "modified": note.get("modified")}


class NoteTool(Tool):
    IGNORE_FIELDS = frozenset({"modified"})
    FIELD_SCOPED_UNDO = False

    def ref_for(self, args):
        return str(args["id"]) if "id" in args else None

    def snapshot(self, args):
        return self.plugin.note(args["id"])

    def current(self, object_ref):
        try:
            return self.plugin.note(int(object_ref))
        except NotFound:
            return None

    def undo(self, object_ref, before, after):
        if before is None:
            self.plugin.request("DELETE", f"/notes/{int(object_ref)}")
            return
        self.plugin.put(int(object_ref), {k: before[k] for k in FIELDS})

    def undo_fields(self, object_ref, fields, now):
        unknown = set(fields) - set(FIELDS)
        if unknown:
            raise PluginError(f"can't put back {', '.join(sorted(unknown))}")
        self.plugin.put(int(object_ref), fields)

    def render_diff(self, before, after, args):
        strip = (lambda s: {k: v for k, v in s.items() if k not in ("id", "modified")} if s else None)
        return super().render_diff(strip(before), strip(after), args)


class Create(NoteTool):
    def ref_for(self, args):
        return None

    def snapshot(self, args):
        return None

    def preview(self, args, before):
        return {"title": args["title"], "content": args.get("content", ""), "category": args.get("category", ""),
                "favorite": bool(args.get("favorite"))}

    def execute(self, args, before):
        body = {k: args[k] for k in FIELDS if k in args}
        note = note_state(self.plugin.request("POST", "/notes", json=body))
        return ExecResult(result={"id": note["id"]}, after=note, object_ref=str(note["id"]),
                          summary=f"Wrote note “{note['title']}”")

    def describe(self, args):
        return f"Write note “{args.get('title')}”"


class Update(NoteTool):
    def preview(self, args, before):
        return {**before, **args["changes"]}

    def execute(self, args, before):
        note = self.plugin.put(args["id"], args["changes"])
        return ExecResult(result={"id": note["id"]}, after=note, object_ref=str(note["id"]),
                          summary=f"Changed note “{note['title']}”")

    def describe(self, args):
        return f"Change note {args.get('id')}: {', '.join(sorted(args.get('changes', {})))}"


class Append(NoteTool):
    def preview(self, args, before):
        return {**before, "content": self.joined(before["content"], args["text"])}

    @staticmethod
    def joined(content: str, text: str) -> str:
        return content + ("" if not content or content.endswith("\n") else "\n") + text

    def execute(self, args, before):
        note = self.plugin.put(args["id"], {"content": self.joined(before["content"], args["text"])})
        return ExecResult(result={"id": note["id"]}, after=note, object_ref=str(note["id"]),
                          summary=f"Added to note “{note['title']}”")

    def describe(self, args):
        return f"Add to note {args.get('id')}"


class Delete(NoteTool):
    def preview(self, args, before):
        return {**before, "category": self.plugin.trash}

    def execute(self, args, before):
        note = self.plugin.put(args["id"], {"category": self.plugin.trash})
        return ExecResult(result={"id": note["id"], "category": note["category"]}, after=note,
                          object_ref=str(note["id"]), summary=f"Moved note “{note['title']}” to {self.plugin.trash}")

    def describe(self, args):
        return f"Move note {args.get('id')} to {self.plugin.trash}"


class Plugin(BasePlugin):
    TOOLS = {"create": Create, "update": Update, "append": Append, "delete": Delete}
    READS = {"list": "read_list", "get": "read_get", "categories": "read_categories"}
    transport: httpx.BaseTransport | None = None  # tests inject a fake Nextcloud here

    @property
    def trash(self) -> str:
        return self.config.get("trash_category") or "Agent trash"

    def request(self, method: str, path: str, **kwargs):
        url = (self.config.get("url") or "").rstrip("/")
        if not url:
            raise PluginError(f"{self.ctx.instance}: set config.url to your Nextcloud address")
        if not url.startswith("https://") and not self.config.get("allow_http"):
            raise PluginError(f"{self.ctx.instance}: config.url must use https")
        auth = (self.credentials.get("username") or "", self.credentials.get("password") or "")
        headers = {"Accept": "application/json", "OCS-APIRequest": "true", **kwargs.pop("headers", {})}
        try:
            with httpx.Client(base_url=url + API, transport=self.transport, timeout=30, auth=auth) as client:
                response = client.request(method, path, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise PluginError(f"Nextcloud unreachable: {exc}") from exc
        if response.status_code == 404:
            raise NotFound(f"no note at {path}")
        if response.status_code in (401, 403):
            raise PluginError("Nextcloud refused the login; check the username and app password")
        if response.status_code == 412:
            raise PluginError("the note changed on the server in the meantime; read it again")
        if response.status_code >= 400:
            raise PluginError(f"Nextcloud Notes {method} {path} failed with {response.status_code}: {response.text[:200]}")
        return response.json() if response.content else {}

    def note(self, note_id: int) -> dict:
        return note_state(self.request("GET", f"/notes/{int(note_id)}"))

    def put(self, note_id: int, fields: dict) -> dict:
        """Change fields of a note, but only if nobody changed it since we read it (ETag)."""
        current = self.request("GET", f"/notes/{int(note_id)}")
        headers = {"If-Match": f'"{current["etag"]}"'} if current.get("etag") else {}
        return note_state(self.request("PUT", f"/notes/{int(note_id)}", json=fields, headers=headers))

    def check(self):
        try:
            self.request("GET", "/notes", params={"exclude": "content", "chunkSize": 1})
        except PluginError as exc:
            return str(exc)
        return None

    def _all(self, exclude_content: bool, timeout: float = 30) -> list[dict]:
        params = {"exclude": "content"} if exclude_content else {}
        notes = self.request("GET", "/notes", params=params, timeout=timeout)
        return [n for n in notes if n.get("category", "") != self.trash]

    def read_list(self, params):
        out = []
        for n in self._all(exclude_content=True):
            if params.get("category") is not None and n.get("category", "") != params["category"]:
                continue
            out.append({"id": n["id"], "ref": f"{self.ctx.instance}:{n['id']}", "title": n.get("title", ""),
                        "category": n.get("category", ""), "favorite": bool(n.get("favorite")),
                        "modified": n.get("modified")})
        return sorted(out, key=lambda n: -(n["modified"] or 0))

    def index_feed(self, cursor, budget):
        """Every note for doorman search, from one listing with their text (the Notes API gives it), within
        the budget. `complete`: a note deleted, or moved to the trash category, leaves the index."""
        items = []
        for n in self._all(exclude_content=False, timeout=max(5.0, min(30.0, float(budget)))):
            modified = n.get("modified")
            items.append({"key": str(n["id"]), "kind": "note", "title": n.get("title", ""),
                          "text": n.get("content", ""), "in": n.get("category") or None,
                          "date": datetime.fromtimestamp(modified, timezone.utc).isoformat() if modified else None,
                          "fields": {"category": n.get("category", ""), "favorite": bool(n.get("favorite"))}})
        return {"items": items, "complete": True}

    def read_get(self, params):
        note = self.note(params["id"])
        return {**note, "ref": f"{self.ctx.instance}:{note['id']}"}

    def read_categories(self, params):
        counts: dict[str, int] = {}
        for n in self._all(exclude_content=True):
            counts[n.get("category", "")] = counts.get(n.get("category", ""), 0) + 1
        return [{"category": c, "notes": k} for c, k in sorted(counts.items())]

    def open_ref(self, path):
        note = self.note(int(path))
        return f"{note['title'] or 'note'}.md", note["content"].encode()
