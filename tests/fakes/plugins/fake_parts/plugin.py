"""Items from the config handed to Doorman's search index as they are (complete: true), so a test can give
parts, refs and hidden-text flags directly."""

from doorman.plugin_api import BasePlugin, PluginError


class Plugin(BasePlugin):
    READS = {"get": "read_get", "attachment": "read_attachment", "tasks": "read_tasks", "messages": "read_messages"}

    def items(self):
        return list(self.config.get("items") or [])

    def index_feed(self, cursor, budget):
        return {"items": [dict(i) for i in self.items()], "complete": True, "cursor": None}

    def _item(self, key):
        found = next((i for i in self.items() if i["key"] == key), None)
        if found is None:
            raise PluginError(f"no item {key}")
        return found

    def read_get(self, params):
        return self._item(params["key"])

    def read_attachment(self, params):
        part = next((p for p in self._item(params["key"]).get("parts") or [] if p["part"] == params["part"]), None)
        if part is None:
            raise PluginError("no such part")
        return {"ref": f"{self.ctx.instance}:{params['key']}#{params['part']}", **part}

    def read_tasks(self, params):
        return [i for i in self.items() if i.get("kind") == "task"]

    def read_messages(self, params):
        return [i for i in self.items() if i.get("kind") == "chat"]
