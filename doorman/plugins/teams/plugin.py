"""Microsoft Teams through Microsoft Graph (delegated permissions). Not tested against Microsoft; tests
use a fake Graph.

Login (doorman/ms_login.py) is OAuth 2.0 authorization code with PKCE for a public client. The browser
ends on a localhost page that doesn't load; you paste its address back into the owner app or
`doorman-admin login` (`login_flow: device` shows a code instead).

Without a client_id it signs in as Thunderbird, like mail_outlook (redirect https://localhost), and asks
only for what chats need, permissions a user may consent to by themselves: offline_access User.Read
Chat.Read Chat.Create ChatMessage.Send. Whether the tenant lets them is the consent test: Microsoft
either asks for consent or says "Need admin approval", and the tenant's admins see the grant under
Thunderbird's name. Channels stay out of that default, because reading channel posts
(ChannelMessage.Read.All) always needs an admin; their reads and post_channel say so instead of failing
at Graph. With an app registration of your own ("Mobile and desktop applications", redirect
http://localhost) the default scopes include channels, as before.

Every message is a send: Teams notifies people at once, so a later delete doesn't take it back.
In an existing chat, its members count as known recipients (like the people in a mail thread you
answer); a 1:1 message to a new address gets the usual "not from you" warning.
"""

import json
from urllib.parse import quote

from doorman.ms_login import THUNDERBIRD, MicrosoftLogin
from doorman.plugin_api import (BasePlugin, Denied, ExecResult, NotSent, PluginError, Tool, http_json, iso_moment,
                                since_param)
from doorman.sanitize import html_to_text

GRAPH = "https://graph.microsoft.com/v1.0"
# signed in as Thunderbird: chats only, nothing that needs an admin
CHAT_SCOPES = "offline_access User.Read Chat.Read Chat.Create ChatMessage.Send"
# with an app registration of your own (and what to add for channels once an admin consented)
CHANNEL_SCOPES = "Team.ReadBasic.All Channel.ReadBasic.All ChannelMessage.Read.All ChannelMessage.Send"
OWN_APP_SCOPES = f"offline_access User.Read Chat.ReadWrite ChatMessage.Send {CHANNEL_SCOPES}"


def q(value: str) -> str:
    return quote(str(value), safe="")


def html_text(body: dict | None) -> str:
    """Teams message bodies are usually HTML; the agent gets plain text."""
    if not body:
        return ""
    content = body.get("content") or ""
    if (body.get("contentType") or "").lower() != "html":
        return content.strip()
    return html_to_text(content)[0]


def _sender(message: dict) -> dict:
    user = ((message.get("from") or {}).get("user") or {})
    return {"name": user.get("displayName"), "id": user.get("id")}


def message_view(m: dict) -> dict:
    return {"id": m["id"], "from": _sender(m)["name"], "sent": m.get("createdDateTime"),
            "subject": m.get("subject"), "text": html_text(m.get("body")),
            "attachments": [a.get("name") for a in m.get("attachments") or [] if a.get("name")]}


class Send(Tool):
    def follow_up(self, args, result):
        return "You can delete it in Teams, but people were notified and may have read it already."

    def post(self, path: str, text: str, subject: str | None = None) -> dict:
        body = {"body": {"contentType": "text", "content": text}}
        if subject:
            body["subject"] = subject
        try:
            return self.plugin.request("POST", path, json=body)
        except NotSent as exc:  # an expired login, no connection, or Graph said no: nothing went out
            raise NotSent(f"Teams didn't take the message: {exc}") from exc


class SendChat(Send):
    def destinations(self, args):
        return [("email", e) for e in self.plugin.chat_member_emails(args["chat_id"])]

    def trusted_destinations(self, args):
        return set(self.plugin.chat_member_emails(args["chat_id"]))  # people you already talk to there

    def execute(self, args, before):
        sent = self.post(f"/chats/{q(args['chat_id'])}/messages", args["text"])
        return ExecResult(result={"id": sent.get("id"), "chat_id": args["chat_id"]}, object_ref=sent.get("id"),
                          summary=f"Wrote in {self.plugin.chat_label(args['chat_id'])}")

    def describe(self, args):
        return f"Write in {self.plugin.chat_label(args['chat_id'])}: “{_short(args.get('text', ''))}”"


class MessagePerson(Send):
    def execute(self, args, before):
        try:
            chat_id = self.plugin.one_on_one(args["to"])
        except PluginError as exc:  # whatever went wrong there, the message itself hasn't left yet
            raise NotSent(f"Teams couldn't open a chat with {args['to']}: {exc}") from exc
        sent = self.post(f"/chats/{q(chat_id)}/messages", args["text"])
        return ExecResult(result={"id": sent.get("id"), "chat_id": chat_id}, object_ref=sent.get("id"),
                          summary=f"Messaged {args['to']} on Teams")

    def describe(self, args):
        return f"Teams message to {args.get('to')}: “{_short(args.get('text', ''))}”"


class PostChannel(Send):
    def tier(self, args):
        self.plugin.need_channels("ChannelMessage.Send")  # before anything waits for the owner
        return super().tier(args)

    def execute(self, args, before):
        base = f"/teams/{q(args['team_id'])}/channels/{q(args['channel_id'])}/messages"
        path = f"{base}/{q(args['reply_to'])}/replies" if args.get("reply_to") else base
        sent = self.post(path, args["text"], None if args.get("reply_to") else args.get("subject"))
        return ExecResult(result={"id": sent.get("id")}, object_ref=sent.get("id"),
                          summary=f"Posted in {self.plugin.channel_label(args['team_id'], args['channel_id'])}")

    def describe(self, args):
        where = self.plugin.channel_label(args["team_id"], args["channel_id"])
        verb = "Reply in" if args.get("reply_to") else "Post in"
        return f"{verb} {where}: “{_short(args.get('text', ''))}”"


def _short(text: str, n: int = 80) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"


class Plugin(MicrosoftLogin, BasePlugin):
    DEFAULT_CLIENT_ID = THUNDERBIRD
    DEFAULT_TENANT = "organizations"   # Graph has Teams chats only for work and school accounts
    DEFAULT_SCOPES = CHAT_SCOPES
    LOGIN_LABEL = "Teams"
    TOOLS = {"send_chat": SendChat, "message_person": MessagePerson, "post_channel": PostChannel}
    READS = {"chats": "read_chats", "recent": "read_recent", "chat_messages": "read_chat_messages", "teams": "read_teams",
             "channels": "read_channels", "channel_messages": "read_channel_messages",
             "chat_message": "read_chat_message"}
    def __init__(self, ctx, manifest):
        super().__init__(ctx, manifest)
        self._me: dict | None = None
        self._labels: dict[str, str] = {}

    # ------------------------------------------------------------------ login (doorman/ms_login.py)

    @property
    def own_app(self) -> bool:
        return bool(self.config.get("client_id"))

    @property
    def scopes(self) -> str:
        return self.config.get("scopes") or (OWN_APP_SCOPES if self.own_app else CHAT_SCOPES)

    @property
    def redirect_uri(self) -> str:
        """Thunderbird's registration allows https://localhost; an own app registration http://localhost."""
        if self.config.get("redirect_uri"):
            return self.config["redirect_uri"]
        return f"http://localhost:{int(self.config.get('redirect_port', 8799))}/" if self.own_app \
            else "https://localhost"

    def need_channels(self, scope: str) -> None:
        """Channels aren't in the default sign-in: say why, instead of a 403 from Graph."""
        if scope not in self.scopes.split():
            raise Denied(f"Teams channels aren't part of this sign-in ({self.ctx.instance}): reading channel posts "
                         "needs ChannelMessage.Read.All, which only your organization's admin can allow. Once they "
                         f"have, add {CHANNEL_SCOPES} to scopes in {self.ctx.instance}'s settings and connect "
                         "again.", "admin_consent")

    def account_from_login(self, body):
        self._me = None
        try:
            return self.me().get("mail") or self.me().get("userPrincipalName")
        except PluginError:
            return None

    def check(self):
        return self.check_login()

    # ------------------------------------------------------------------ Graph

    def request(self, method: str, path: str, **kwargs) -> dict:
        """A Graph call (plugin_api.http_json). An expired login or no connection is NotSent, and so is a
        4xx: Graph refused the request and did nothing."""
        return http_json("Graph", method, GRAPH + path, token=self.access_token, transport=self.transport,
                         hints={403: "this permission may need your admin's consent"}, **kwargs)

    def me(self) -> dict:
        if self._me is None:
            self._me = self.request("GET", "/me", params={"$select": "id,displayName,mail,userPrincipalName"})
        return self._me

    def members(self, chat_id: str) -> list[dict]:
        data = self.request("GET", f"/chats/{q(chat_id)}/members")
        return [{"name": m.get("displayName"), "email": (m.get("email") or "").lower() or None,
                 "id": m.get("userId")} for m in data.get("value", [])]

    def chat_member_emails(self, chat_id: str) -> list[str]:
        mine = (self.me().get("id"), )
        return sorted({m["email"] for m in self.members(chat_id) if m["email"] and m["id"] not in mine})

    def chat_label(self, chat_id: str) -> str:
        if chat_id not in self._labels:
            try:
                chat = self.request("GET", f"/chats/{q(chat_id)}")
                others = [m["name"] for m in self.members(chat_id) if m["id"] != self.me().get("id") and m["name"]]
                self._labels[chat_id] = chat.get("topic") or ("the chat with " + ", ".join(others) if others else "a chat")
            except PluginError:
                self._labels[chat_id] = f"chat {chat_id}"
        return self._labels[chat_id]

    def channel_label(self, team_id: str, channel_id: str) -> str:
        key = f"{team_id}/{channel_id}"
        if key not in self._labels:
            try:
                team = self.request("GET", f"/teams/{q(team_id)}", params={"$select": "displayName"})
                channel = self.request("GET", f"/teams/{q(team_id)}/channels/{q(channel_id)}",
                                       params={"$select": "displayName"})
                self._labels[key] = f"{team.get('displayName')} › {channel.get('displayName')}"
            except PluginError:
                self._labels[key] = f"channel {channel_id}"
        return self._labels[key]

    def one_on_one(self, email: str) -> str:
        """The 1:1 chat with this person; Graph returns the existing one if there is one."""
        me = self.me()
        bind = "https://graph.microsoft.com/v1.0/users('{}')"
        chat = self.request("POST", "/chats", json={"chatType": "oneOnOne", "members": [
            {"@odata.type": "#microsoft.graph.aadUserConversationMember", "roles": ["owner"],
             "user@odata.bind": bind.format(me["id"])},
            {"@odata.type": "#microsoft.graph.aadUserConversationMember", "roles": ["owner"],
             "user@odata.bind": bind.format(email)}]})
        return chat["id"]

    # ------------------------------------------------------------------ reads

    def chat_list(self, limit: int) -> list[dict]:
        """The chats, newest message first, each with its members (but me) and its last message's preview.
        Two Graph calls, one per $expand: Graph documents each expand alone, not both together."""
        order = "lastMessagePreview/createdDateTime desc"
        chats = self.request("GET", "/me/chats", params={"$top": limit, "$expand": "lastMessagePreview",
                                                          "$orderby": order}).get("value", [])
        listed = self.request("GET", "/me/chats", params={"$top": limit, "$expand": "members",
                                                           "$orderby": order}).get("value", [])
        mine = self.me().get("id")
        members = {c["id"]: [m.get("displayName") for m in c.get("members", []) if m.get("userId") != mine]
                   for c in listed}
        return [{**c, "members": members.get(c["id"], [])} for c in chats]

    @staticmethod
    def chat_name(chat: dict) -> str:
        return chat.get("topic") or ", ".join(n for n in chat["members"] if n) or "a chat"

    def read_chats(self, params):
        """Chats, newest message first. Who wrote last and when, but not the text: that comes from
        teams.recent, and this read stays open to actor keys. Still third-party: any member of a group sets
        its topic, and names come from other people."""
        out = []
        for c in self.chat_list(params.get("limit", 20)):
            preview = c.get("lastMessagePreview") or {}
            last = {"sent": preview.get("createdDateTime"), "from": _sender(preview)["name"]} \
                if preview.get("id") else None
            out.append({"id": c["id"], "type": c.get("chatType"), "topic": c.get("topic"),
                        "members": c["members"], "last_message": last})
        return out

    def read_recent(self, params):
        """Each chat's newest message (who, when, the start of the text), newest first. `since` leaves out
        chats whose newest message is older. Chats whose last entry isn't a message (someone was added, the
        message was deleted) are left out."""
        since = since_param(params)
        mine = self.me().get("id")
        out = []
        for c in self.chat_list(params.get("limit", 20)):
            preview = c.get("lastMessagePreview") or {}
            sent = preview.get("createdDateTime") or ""
            if not preview.get("id") or preview.get("isDeleted") or \
                    preview.get("messageType", "message") != "message":
                continue
            if since and (iso_moment(sent) or since) < since:
                break  # newest first: the rest are older still
            sender = _sender(preview)
            out.append({"ref": f"{self.ctx.instance}:{c['id']}/{preview['id']}", "chat_id": c["id"],
                        "chat": self.chat_name(c), "from": sender["name"], "mine": sender["id"] == mine,
                        "sent": sent, "text": _short(html_text(preview.get("body")), 500)})
        return out

    def read_chat_messages(self, params):
        data = self.request("GET", f"/chats/{q(params['chat_id'])}/messages", params={"$top": params.get("limit", 20)})
        return [message_view(m) for m in data.get("value", []) if m.get("messageType", "message") == "message"]

    def read_chat_message(self, params):
        """One chat message (the item a ref points to), with up to 10 earlier messages of the chat, oldest
        first, so the reader sees what it answers."""
        chat_id, _, msg_id = params["id"].rpartition("/")
        m = self.request("GET", f"/chats/{q(chat_id)}/messages/{q(msg_id)}")
        wanted = params.get("context", 10)
        recent = self.request("GET", f"/chats/{q(chat_id)}/messages",
                              params={"$top": 20}).get("value", []) if wanted else []
        sent = m.get("createdDateTime") or ""
        earlier = [message_view(r) for r in recent if r.get("messageType", "message") == "message"
                   and r.get("id") != msg_id and (r.get("createdDateTime") or "") <= sent][:wanted]
        return {**message_view(m), "ref": f"{self.ctx.instance}:{chat_id}/{msg_id}", "chat_id": chat_id,
                "from_id": _sender(m)["id"], "context": earlier[::-1]}

    def poll_events(self, cursor):
        """new_message when a chat's last message changed and someone else wrote it. One Graph call per poll:
        the chat list with each chat's last message, so several messages in a chat between two polls come as
        one event (the newest). The cursor keeps each chat's last message id."""
        data = self.request("GET", "/me/chats", params={"$top": 50, "$expand": "lastMessagePreview",
                                                         "$orderby": "lastMessagePreview/createdDateTime desc"})
        known = json.loads(cursor) if cursor else None
        mine, last, events = self.me().get("id"), {}, []
        for chat in data.get("value", []):
            preview = chat.get("lastMessagePreview") or {}
            if not preview.get("id"):
                continue
            last[chat["id"]] = preview["id"]
            if known is None or known.get(chat["id"]) == preview["id"] or preview.get("isDeleted"):
                continue
            sender = _sender(preview)
            if sender["id"] == mine or preview.get("messageType", "message") != "message":
                continue
            events.append({"type": "new_message", "ref": f"{self.ctx.instance}:{chat['id']}/{preview['id']}",
                           "chat_id": chat["id"], "topic": chat.get("topic"), "from": sender["name"],
                           "text": _short(html_text(preview.get("body")), 300), "sent": preview.get("createdDateTime")})
        return events[::-1], json.dumps(last)  # oldest first

    def read_teams(self, params):
        self.need_channels("Team.ReadBasic.All")
        data = self.request("GET", "/me/joinedTeams", params={"$select": "id,displayName,description"})
        return [{"id": t["id"], "name": t.get("displayName"), "description": t.get("description")}
                for t in data.get("value", [])]

    def read_channels(self, params):
        self.need_channels("Channel.ReadBasic.All")
        data = self.request("GET", f"/teams/{q(params['team_id'])}/channels",
                            params={"$select": "id,displayName,description,membershipType"})
        return [{"id": c["id"], "name": c.get("displayName"), "description": c.get("description"),
                 "private": c.get("membershipType") == "private"} for c in data.get("value", [])]

    def read_channel_messages(self, params):
        self.need_channels("ChannelMessage.Read.All")
        base = f"/teams/{q(params['team_id'])}/channels/{q(params['channel_id'])}/messages"
        data = self.request("GET", base, params={"$top": params.get("limit", 20), "$expand": "replies"})
        out = []
        for m in data.get("value", []):
            if m.get("messageType", "message") != "message":
                continue
            view = message_view(m)
            view["replies"] = [message_view(r) for r in m.get("replies", []) if r.get("messageType", "message") == "message"]
            out.append(view)
        return out
