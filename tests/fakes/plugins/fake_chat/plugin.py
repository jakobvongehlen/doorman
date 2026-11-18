"""Chats in a JSON file under the plugin's data dir, shaped like the WhatsApp plugin's. Tests fill it with
`add()`; poll_events announces what others wrote since the last poll."""

import json

from doorman.plugin_api import BasePlugin, PluginError


class Plugin(BasePlugin):
    TOOLS = {}
    READS = {"chats": "read_chats", "messages": "read_messages", "message": "read_message"}

    @property
    def path(self):
        return self.ctx.data_dir / "chats.json"

    def load(self) -> dict:
        if not self.path.exists():
            return {"next": 1, "chats": {}, "messages": []}
        return json.loads(self.path.read_text())

    def save(self, store: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(store))

    def add(self, chat: str, name: str, sender: str, sender_name: str, text: str, from_me: bool = False) -> str:
        store = self.load()
        mid = str(store["next"])
        store["next"] += 1
        store["chats"][chat] = name
        store["messages"].append({"id": mid, "chat": chat, "sender": "me" if from_me else sender,
                                  "sender_name": None if from_me else sender_name, "from_me": from_me,
                                  "ts": f"2026-11-05T{8 + int(mid):02d}:00:00Z", "text": text})
        self.save(store)
        return f"{self.ctx.instance}:{chat}/{mid}"

    def _view(self, m: dict) -> dict:
        return {**m, "ref": f"{self.ctx.instance}:{m['chat']}/{m['id']}"}

    def read_chats(self, params):
        return [{"id": chat, "name": name} for chat, name in self.load()["chats"].items()]

    def read_messages(self, params):
        return [self._view(m) for m in reversed(self.load()["messages"]) if m["chat"] == params["chat"]]

    def read_message(self, params):
        chat, _, mid = params["id"].rpartition("/")
        store = self.load()
        in_chat = [m for m in store["messages"] if m["chat"] == chat]
        for i, m in enumerate(in_chat):
            if m["id"] == mid:
                return {**self._view(m), "chat_name": store["chats"].get(chat),
                        "context": [self._view(e) for e in in_chat[max(0, i - params.get("context", 10)):i]]}
        raise PluginError(f"no message {params['id']}")

    def poll_events(self, cursor):
        store = self.load()
        top = store["next"] - 1
        if cursor is None:
            return [], str(top)
        return [{"type": "new_message", "ref": f"{self.ctx.instance}:{m['chat']}/{m['id']}", "chat": m["chat"],
                 "from": m["sender"], "from_name": m["sender_name"], "text": m["text"][:300]}
                for m in store["messages"] if int(m["id"]) > int(cursor) and not m["from_me"]], str(top)
