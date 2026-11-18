"""A source of Doorman's search index in a few lines: items from the config (and kept ones), all of them
handed over on every feed (complete: true)."""

from doorman.plugin_api import BasePlugin, ExecResult, PluginError, Tool


class Keep(Tool):
    def execute(self, args, before):
        self.plugin.kept[args["key"]] = {"key": args["key"], "title": args["key"], "text": args["text"],
                                         "made_by": args.get("made_by")}
        return ExecResult(result={"key": args["key"], "made_by": args.get("made_by")}, object_ref=args["key"],
                          summary=f"Kept {args['key']}")

    def undo(self, object_ref, before, after):
        self.plugin.kept.pop(object_ref, None)


class Plugin(BasePlugin):
    TOOLS = {"keep": Keep}
    READS = {"get": "read_get"}

    def __init__(self, ctx, manifest):
        super().__init__(ctx, manifest)
        self.kept: dict[str, dict] = {}
        self.feeds = 0

    def items(self):
        return [*(self.config.get("items") or []), *self.kept.values()]

    def index_feed(self, cursor, budget):
        self.feeds += 1
        out = []
        for i in self.items():
            fields = {k: i[k] for k in ("made_by",) if i.get(k)}
            out.append({"key": i["key"], "kind": i.get("kind", "note"), "title": i.get("title", ""),
                        "text": i.get("text", ""), "date": i.get("date"), "from": i.get("from"), "in": i.get("in"),
                        "same": i.get("same"), "fields": fields})
        return {"items": out, "complete": True, "cursor": str(self.feeds)}

    def read_get(self, params):
        found = next((i for i in self.items() if i["key"] == params["key"]), None)
        if found is None:
            raise PluginError(f"no item {params['key']}")
        return found
