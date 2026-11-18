"""WhatsApp via the sidecar in sidecars/whatsapp (wacli plus a small HTTP API). Doorman only talks HTTP to it.

doorman search finds chats through Doorman's search index, which this plugin feeds a chat's day at a time
(index_feed); wacli's own full-text search isn't used."""

import json
import re
import time
from datetime import date, datetime, timedelta, timezone
from datetime import time as dtime
from zoneinfo import ZoneInfo

import httpx
import segno

from doorman import clock
from doorman.plugin_api import BasePlugin, ExecResult, PluginError, Tool, http_json, iso_moment, since_param

SEEN_KEEP = 500          # message keys the event cursor remembers, so an edit isn't announced again
BACKFILL_AGE = timedelta(hours=6)  # a stored message older than this when it arrives is history, not news
CONTEXT = 10             # earlier messages the message read includes
PAGE = 500               # messages (or changes) per request to the sidecar: the most it gives
DAY_PAGES = 20           # pages of one chat's day the search index reads at most (10,000 messages)
CHATS_MAX = 1000         # chats the search index reads back, the most the sidecar lists


def _preview(text: str, n: int = 300) -> str:
    """The start of a message, for an event; the agent reads the chat for the rest."""
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"


def _message(m: dict) -> dict:
    """A wacli message, in the shape Doorman shows the agent."""
    out = {"id": m.get("MsgID"), "sender": m.get("SenderJID"), "sender_name": m.get("SenderName") or None,
           "from_me": bool(m.get("FromMe")), "ts": m.get("Timestamp"),
           "text": m.get("Text") or m.get("MediaCaption") or m.get("DisplayText") or ""}
    if m.get("MediaType"):
        out["media"] = {"type": m["MediaType"], "filename": m.get("Filename") or None}
    if m.get("QuotedMsgID"):
        out["reply_to"] = m["QuotedMsgID"]
    if m.get("ReactionToID"):
        out["reaction_to"], out["text"] = m["ReactionToID"], m.get("ReactionEmoji") or ""
    if m.get("Edited"):
        out["edited"] = True
    if m.get("Revoked") or m.get("DeletedAt"):
        out["deleted"], out["text"] = True, ""
    return out


def _stamp(moment: datetime) -> str:
    """RFC 3339 in UTC, as the sidecar takes `after` and `before`."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _qr(code: str) -> dict:
    """A QR code as rows of 0 and 1 (1 dark), for the owner app to draw; without its quiet zone."""
    rows = ["".join("1" if dark else "0" for dark in row) for row in segno.make(code, micro=False).matrix]
    return {"size": len(rows), "rows": rows}


def _link(state: dict) -> dict:
    """The sidecar's linking state, as the owner app shows it (see Link in sidecars/whatsapp/shim.py)."""
    out = {"state": state.get("state") or "idle"}
    if state.get("qr"):
        out["qr"] = _qr(state["qr"])
    if state.get("pair_code"):
        out["pair_code"], out["phone"] = state["pair_code"], state.get("phone")
    if state.get("error"):
        out["error"] = state["error"]
    return out


def _is_news(m: dict) -> bool:
    """Someone else wrote something: not mine, not a reaction, not a deleted or empty placeholder."""
    return not (m.get("FromMe") or m.get("ReactionToID") or m.get("Revoked") or m.get("DeletedAt")
                or not (m.get("Text") or m.get("MediaCaption") or m.get("MediaType")))


class Send(Tool):
    def execute(self, args, before):
        sent = self.plugin.request("POST", "/send", json={"chat": args["chat"], "text": args["text"]})
        return ExecResult(result={"id": sent.get("id"), "to": sent.get("to")},
                          summary=f"WhatsApp to {self.plugin.chat_name(args['chat'])}: {args['text'][:60]}")

    def describe(self, args):
        return f"WhatsApp to {self.plugin.chat_name(args.get('chat', ''))}: {args.get('text', '')[:60]}"

    def follow_up(self, args, result):
        return "You can delete it for everyone in WhatsApp for a while, but it may already have been read."


class Plugin(BasePlugin):
    TOOLS = {"send": Send}
    READS = {"chats": "read_chats", "recent": "read_recent", "messages": "read_messages", "message": "read_message"}
    transport: httpx.BaseTransport | None = None  # tests inject a fake sidecar

    def request(self, method: str, path: str, **kwargs):
        """A call to the sidecar (plugin_api.http_json). It answers 4xx only when nothing went out, so that
        is NotSent, like no connection; a read timeout after the request went in leaves a send unknown."""
        url = self.config.get("sidecar_url", "http://127.0.0.1:8720").rstrip("/")
        return http_json("WhatsApp sidecar", method, url + path, transport=self.transport, timeout=150,
                         headers={"Authorization": f"Bearer {self.credentials.get('sidecar_token', '')}"},
                         hints={401: "the sidecar has another token than Doorman (credential sidecar_token)"},
                         **kwargs)

    def check(self):
        try:
            status = self.request("GET", "/status")
        except PluginError as exc:
            return str(exc)
        if status.get("linked") is False:
            return "WhatsApp isn't linked: Link WhatsApp under Plugins → whatsapp"
        if not status.get("sync_running"):
            return f"WhatsApp sync isn't running. {status.get('last_error') or ''}".strip()
        return None

    # login: link -- the owner's phone links the sidecar as a device; the app shows the sidecar's code

    def login_status(self) -> dict:
        if not self.credentials.get("sidecar_token"):
            return {"connected": False, "ready": False,
                    "error": "No sidecar token yet. Start the sidecar (docker compose --profile whatsapp up -d): "
                             "Doorman takes its token from the volume they share within a few seconds."}
        try:
            status = self.request("GET", "/status")
        except PluginError as exc:
            return {"connected": False, "ready": False, "error": str(exc)}
        if status.get("linked"):
            return {"connected": True, "account": f"+{status['phone']}" if status.get("phone") else None,
                    "sync_running": bool(status.get("sync_running")), "last_error": status.get("last_error") or None}
        return {"connected": False, "ready": True, "link": _link(status.get("link") or {})}

    def login_start(self, phone: str | None = None) -> dict:
        return {"link": _link(self.request("POST", "/link", json={"phone": phone} if phone else {}))}

    def logout(self) -> dict:
        self.request("POST", "/unlink", json={})
        return {"connected": False}

    def chats(self, params: dict | None = None) -> list[dict]:
        return [{"id": c.get("jid"), "name": c.get("name") or None, "kind": c.get("kind"),
                 "last_message": c.get("last_message_ts"), "unread": c.get("unread_count") or 0,
                 "archived": bool(c.get("archived"))} for c in self.request("GET", "/chats", params=params) or []]

    def chat_name(self, jid: str) -> str:
        try:
            for chat in self.chats():
                if chat["id"] == jid and chat.get("name"):
                    return f"{chat['name']} ({jid})"
        except PluginError:
            pass
        return jid

    def read_chats(self, params):
        """Chats, most recent first. `query` matches part of a name or a number: a phone number in any
        format (+49 151 ..., 0049-151...) is matched by its digits against the chat's JID."""
        query = " ".join(str(params.get("query") or "").split())
        needle = re.sub(r"\D", "", query) if re.fullmatch(r"[+\d\s()/.-]+", query) else query.lower()
        needle = needle.lstrip("0") if needle.isdigit() else needle  # 0049...: international prefix
        sidecar = {}
        if needle:
            sidecar["query"] = needle
        if params.get("limit"):
            sidecar["limit"] = params["limit"]
        chats = self.chats(sidecar or None)
        if needle:  # also here: an older sidecar ignores query
            chats = [c for c in chats if needle in (c["name"] or "").lower() or needle in (c["id"] or "").lower()]
        if params.get("limit"):
            chats = chats[: params["limit"]]
        return [{**chat, "ref": f"{self.ctx.instance}:{chat['id']}"} for chat in chats]

    def read_recent(self, params):
        """Each chat's newest message, newest chat first, from `since` on (doorman recent). The sidecar has no
        such list: the chats come newest first with their last message's time, then one message per chat."""
        since = since_param(params)
        out = []
        for chat in self.chats({"limit": params.get("limit", 20)})[: params.get("limit", 20)]:
            last = iso_moment(chat.get("last_message"))
            if since and last and last < since:
                break  # newest first: the rest are older still
            found = self.request("GET", "/messages", params={"chat": chat["id"], "limit": 1})
            if not found:
                continue
            m = _message(found[0])
            out.append({"ref": f"{self.ctx.instance}:{chat['id']}/{m['id']}", "chat_id": chat["id"],
                        "chat": chat.get("name") or chat["id"], "from": m["sender_name"] or m["sender"],
                        "mine": m["from_me"], "sent": m["ts"], "text": _preview(m["text"], 500),
                        **({"unread": chat["unread"]} if chat.get("unread") else {})})
        return out

    def read_messages(self, params):
        found = self.request("GET", "/messages", params={"chat": params["chat"], "limit": params.get("limit", 30)})
        return [{**_message(m), "ref": f"{self.ctx.instance}:{params['chat']}/{m.get('MsgID')}"} for m in found]

    def read_message(self, params):
        """One message (the item a ref points to), with up to CONTEXT messages before it, oldest first, so the
        reader sees what it answers."""
        chat, _, msg_id = params["id"].rpartition("/")
        found = self.request("GET", "/messages", params={"chat": chat, "limit": 200})  # newest first
        for i, m in enumerate(found):
            if m.get("MsgID") == msg_id:
                try:
                    names = {c["id"]: c.get("name") for c in self.chats()}
                except PluginError:
                    names = {}
                earlier = [_message(e) for e in reversed(found[i + 1:i + 1 + params.get("context", CONTEXT)])]
                return {**_message(m), "ref": f"{self.ctx.instance}:{chat}/{msg_id}", "chat": chat,
                        "chat_name": names.get(chat), "context": earlier}
        raise PluginError(f"message {msg_id} isn't among the last 200 in that chat")

    # Doorman's search index: one item per chat and day

    def index_feed(self, cursor, budget):
        """Chat-days for Doorman's search index: one item per chat per day (in config.timezone), its messages
        as lines "HH:MM Sender: text". The cursor is JSON:

            {"cp": wacli's change-log checkpoint,
             "backfill": {"chats": [chat ids still to read], "before": RFC 3339 or null} or null,
             "pending": [[chat id, day], ...]}       # chat-days the change log touched, not fed yet

        The first feed takes a checkpoint, then reads each chat's history backwards, newest chat first, a page
        of /messages at a time (`more` until done). After that only the change log: each chat-day it names
        (a new message, an edit, a deletion) is read again whole and replaces its item, or goes when nothing
        is left of it. wacli keeps its log 30 days; after a longer gap the history is read again, with `reset`,
        so chat-days deleted in the gap leave search once that's through. A sidecar error after some progress
        hands over what came so far; the cursor stays where that went well."""
        deadline = time.monotonic() + float(budget)
        state = json.loads(cursor) if cursor else self._backfill_start()
        state.setdefault("pending", [])
        items: dict[str, dict] = {}
        removed: set[str] = set()
        names: dict[str, str | None] = {}  # the chats' names, asked for once something is fed

        def name_of(chat: str) -> str | None:
            if not names:
                names.update({c["id"]: c.get("name") for c in self.chats({"limit": CHATS_MAX})} or {"": None})
            return names.get(chat)

        steps, restarted = 0, False
        while not steps or time.monotonic() < deadline:  # at least one step, however small the budget
            steps += 1
            try:
                if state.get("backfill"):
                    self._backfill_page(state, name_of, items)
                elif state["pending"]:
                    chat, day = state["pending"][0]
                    self._feed_day(chat, day, name_of, items, removed)
                    state["pending"].pop(0)
                else:
                    changed = self._read_changes(state)
                    if changed is None:  # the checkpoint expired (wacli keeps its log 30 days): read it all again
                        if restarted:  # once per feed, not until the budget is gone
                            raise PluginError("WhatsApp's change log refused the checkpoint it had just given")
                        self.ctx.log.warning("WhatsApp's change log no longer goes back far enough: reading the "
                                             "history again")
                        state, restarted = self._backfill_start(), True
                    elif not changed:
                        break
            except PluginError as exc:
                if not (items or removed):
                    raise
                self.ctx.log.warning("feeding the search index stopped early: %s", exc)
                break
        out = {"items": list(items.values()), "removed": sorted(removed - set(items)), "cursor": json.dumps(state),
               "more": bool(state.get("backfill") or state["pending"])}
        if restarted:  # the history read again whole: what it no longer has goes once that's through
            out["reset"] = True
        return out

    @property
    def zone(self) -> ZoneInfo:
        return ZoneInfo(self.config.get("timezone") or "UTC")

    def _day_start(self, day: str) -> datetime:
        return datetime.combine(date.fromisoformat(day), dtime(), self.zone)

    def _day_of(self, stamp: str | None) -> str:
        return str((clock.parse(stamp) if stamp else clock.now()).astimezone(self.zone).date())

    def _backfill_start(self) -> dict:
        """Where the change log is now (what comes after is read from it), and every chat to read back."""
        checkpoint = self.request("GET", "/changes")["next_checkpoint"]
        chats = [c["id"] for c in self.chats({"limit": CHATS_MAX}) if c.get("id")]
        return {"cp": checkpoint, "backfill": {"chats": chats, "before": None}, "pending": []}

    def _backfill_page(self, state: dict, name_of, items: dict) -> None:
        """One page of the first chat's history, newest first. Each day the page holds whole goes in; the
        oldest day may go on in the next page, so that one is read again with it. A day that fills a page alone
        is read on to its start."""
        fill = state["backfill"]
        if not fill["chats"]:
            state["backfill"] = None
            return
        chat = fill["chats"][0]
        params = {"chat": chat, "limit": PAGE, **({"before": fill["before"]} if fill.get("before") else {})}
        page = self.request("GET", "/messages", params=params)
        days: dict[str, list[dict]] = {}
        for m in page:
            days.setdefault(self._day_of(m.get("Timestamp")), []).append(m)
        if len(page) < PAGE:  # the rest of this chat
            done, fill["chats"], fill["before"] = list(days), fill["chats"][1:], None
        else:
            oldest = self._day_of(page[-1].get("Timestamp"))
            if len(days) == 1:
                days[oldest] = self._day_messages(chat, oldest, page)
                done, fill["before"] = [oldest], _stamp(self._day_start(oldest))
            else:
                done = [d for d in days if d != oldest]
                fill["before"] = _stamp(self._day_start(oldest) + timedelta(days=1))
        for day in done:
            item = self._day_item(chat, day, days[day], name_of)
            if item:
                items[item["key"]] = item

    def _read_changes(self, state: dict) -> bool | None:
        """One page of wacli's change log since the checkpoint: the chat-days it touched become pending. False
        when nothing changed, None when the checkpoint has expired."""
        try:
            page = self.request("GET", "/changes", params={"since": state["cp"], "limit": PAGE})
        except PluginError as exc:
            if "expired checkpoint" in str(exc):
                return None
            raise
        touched = {tuple(p) for p in state["pending"]}
        for change in page.get("changes") or []:
            if change.get("chat_jid"):  # an older sidecar has no message_time: the day it was recorded
                when = change.get("message_time") or change.get("recorded_at")
                touched.add((change["chat_jid"], self._day_of(when)))
        state["cp"] = page["next_checkpoint"]
        state["pending"] = [list(p) for p in sorted(touched, key=lambda p: (p[1], p[0]), reverse=True)]
        return bool(page.get("changes"))

    def _day_messages(self, chat: str, day: str, page: list[dict] | None = None) -> list[dict]:
        """A chat's messages of one day, a page at a time from its end (or on from `page`, its newest), up to
        DAY_PAGES pages. Each page ends a second after the last one's oldest message, so messages of the same
        second aren't lost between pages; one that brings nothing new ends it."""
        start = self._day_start(day)
        after, before = _stamp(start - timedelta(seconds=1)), _stamp(start + timedelta(days=1))
        found: dict[str, dict] = {}
        for _ in range(DAY_PAGES):
            if page is None:
                page = self.request("GET", "/messages", params={"chat": chat, "after": after, "before": before,
                                                                 "limit": PAGE})
            new = [m for m in page if m.get("MsgID") not in found and self._day_of(m.get("Timestamp")) == day]
            found.update((m.get("MsgID"), m) for m in new)
            if len(page) < PAGE or not new:
                break
            before = _stamp(clock.parse(page[-1]["Timestamp"]) + timedelta(seconds=1))
            page = None
        return list(found.values())

    def _feed_day(self, chat: str, day: str, name_of, items: dict, removed: set) -> None:
        item = self._day_item(chat, day, self._day_messages(chat, day), name_of)
        if item:
            items[item["key"]] = item
        else:
            items.pop(f"{chat}/{day}", None)
            removed.add(f"{chat}/{day}")

    def _day_item(self, chat: str, day: str, messages: list[dict], name_of) -> dict | None:
        """A chat's day as one search item, or None when nothing readable is left of it (only reactions, or
        deleted messages)."""
        lines, senders, first, last, refs = [], [], None, None, []
        for m in sorted(messages, key=lambda m: m.get("Timestamp") or ""):
            skip = m.get("ReactionToID") or m.get("Revoked") or m.get("DeletedAt") or m.get("DeletedForMe")
            if skip or not m.get("Timestamp"):
                continue
            shown = _message(m)
            text = " ".join(shown["text"].split())  # one line per message
            media = shown.get("media")
            if media:  # a photo with its caption: "[image: IMG_0042.jpg] Look!"
                name = f": {media['filename']}" if media.get("filename") else ""
                text = f"[{media['type']}{name}] {text}".strip()
            if not text:
                continue
            who = m.get("SenderName") or ("me" if m.get("FromMe") else str(m.get("SenderJID") or "").split("@")[0])
            moment = clock.parse(m["Timestamp"]).astimezone(self.zone)
            lines.append(f"{moment:%H:%M} {who}: {text}")
            if who not in senders:
                senders.append(who)
            if m.get("MsgID"):
                refs.append(f"{self.ctx.instance}:{chat}/{m['MsgID']}")
            first, last = first or m.get("MsgID"), moment
        if not lines:
            return None
        name = (name_of(chat) or next((m["ChatName"] for m in messages if m.get("ChatName")), None)
                or chat.split("@")[0])
        # refs: each message's, so the guard holding one of them back holds back the day's hit
        return {"key": f"{chat}/{day}", "ref": f"{self.ctx.instance}:{chat}/{first}", "kind": "chat", "title": name,
                "date": last.isoformat(), "in": name, "from": ", ".join(senders), "text": "\n".join(lines),
                "refs": refs, "fields": {"chat": name, "chat_id": chat, "day": day, "messages": len(lines)}}

    def poll_events(self, cursor):
        """new_message for each message someone else sent since the last poll, from wacli's change log.

        The cursor holds wacli's checkpoint and the keys already announced: the log has an `upsert` for a
        new message and again for each later change to it (edit, star, read), and history that arrives late
        comes as upserts too, so a message is news only once and only while it is fresh."""
        if cursor is None:  # start from now
            return [], json.dumps({"cp": self.request("GET", "/changes")["next_checkpoint"], "seen": []})
        state = json.loads(cursor)
        seen, checkpoint = list(state.get("seen") or []), state["cp"]
        touched: dict[str, set[str]] = {}
        for _ in range(10):
            try:
                page = self.request("GET", "/changes", params={"since": checkpoint, "limit": 200})
            except PluginError as exc:  # wacli keeps its log 30 days; after a longer gap, start from now
                if "expired checkpoint" not in str(exc):
                    raise
                return [], json.dumps({"cp": self.request("GET", "/changes")["next_checkpoint"], "seen": seen})
            for change in page.get("changes") or []:
                if change.get("operation") == "upsert":
                    touched.setdefault(change["chat_jid"], set()).add(change["msg_id"])
            checkpoint = page["next_checkpoint"]
            if not page.get("has_more"):
                break
        events, after = [], clock.iso(clock.now() - BACKFILL_AGE)
        names = {c["id"]: c.get("name") for c in self.chats()} if touched else {}
        for chat, ids in touched.items():
            fresh = [i for i in ids if f"{chat}/{i}" not in seen]
            if not fresh:
                continue
            for m in self.request("GET", "/messages", params={"chat": chat, "after": after, "limit": 500}):
                key = f"{chat}/{m.get('MsgID')}"
                if m.get("MsgID") not in fresh or key in seen:
                    continue
                seen.append(key)
                if _is_news(m):
                    events.append({"type": "new_message", "ref": f"{self.ctx.instance}:{key}", "chat": chat,
                                   "chat_name": names.get(chat), "from": m.get("SenderJID"),
                                   "from_name": m.get("SenderName") or None,
                                   "text": _preview(_message(m)["text"]), "sent": m.get("Timestamp")})
        events.sort(key=lambda e: clock.parse(e["sent"]) if e["sent"] else clock.now())
        return events, json.dumps({"cp": checkpoint, "seen": seen[-SEEN_KEEP:]})
