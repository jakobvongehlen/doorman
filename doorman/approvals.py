"""Approvals: what waits for the owner's word, and what happens when they give it.

A send (and an undoable write whose tool the owner set to "Ask me") is journaled as waiting and gets an
approval: its entries, a hash of exactly what they would do, and an expiry. The owner approves, denies or
edits it in the app or on the push; the decision is bound to the hash their screen showed. Approved entries
then run off the owner's request (sends.py, engine.execute_entry).
"""

from __future__ import annotations

import logging
import secrets
import threading
from datetime import timedelta
from typing import Any

from . import clock, sanitize
from .approvals_util import (GROUP_MAX, GROUP_SECONDS, accept_in_place, approval_challenge, group_text,
                             group_title, notice_text, notice_title)
from .plugin_api import Denied, PluginError
from .util import canonical, dumps, loads, sha256_hex

log = logging.getLogger("doorman.approvals")

DENY_NOTE_CHARS = 500    # the owner's note on a Deny, for the agent


class Approvals:
    def __init__(self, engine):
        self.engine = engine
        self.db = engine.db
        self._push_groups: dict[int, dict] = {}  # task id -> its current push group (_push_group)
        self._push_lock = threading.Lock()

    UNREADABLE = "unreadable"  # what a send points at couldn't be read (_outgoing_digest)

    def outgoing_digest(self, tool, args: dict | None, strict: bool = False) -> str | None:
        """A hash of what a send that only points at something (notes.send_copy's note) would send right now
        (Tool.outgoing), None when the tool says nothing. The approval hash covers it, so editing the note
        after asking makes the approval stale; execute_entry checks it once more right before the send.
        When the plugin can't tell: UNREADABLE, or with `strict` a Denied that leaves the approval open."""
        if tool is None:
            return None
        try:
            content = tool.outgoing(args or {})
        except Exception as exc:  # noqa: BLE001 - a plugin that can't answer now
            if strict:
                raise Denied(f"couldn't read what this send would send ({type(exc).__name__}); nothing was sent, "
                             "try again in a moment", "unavailable") from None
            return self.UNREADABLE
        return None if content is None else sha256_hex(canonical(content))

    def _payload_hash(self, entry_ids: list[int], strict: bool = False) -> str:
        """What an approval approves: each entry's tool, arguments, attachments (refs) and, for a send that
        points at something, what that is now (_outgoing_digest)."""
        items = []
        for e in (self.engine.journal.get(i) for i in entry_ids):
            item = {"id": e["id"], "tool": e["tool"], "args": e["args"], "refs": (e["checks"] or {}).get("refs", [])}
            outgoing = self.outgoing_digest(self.engine._tool_object(e), e["args"], strict)
            if outgoing is not None:
                item["outgoing"] = outgoing
            items.append(item)
        return sha256_hex(canonical(items))

    def create(self, entry_ids: list[int], changeset_id: int | None = None, notify: bool = True) -> int:
        ttl = float(self.engine.config.get("approval_ttl_hours", 24))
        approval_id = self.db.exec(
            "INSERT INTO approvals(journal_ids, changeset_id, payload_hash, nonce, status, created, expires) "
            "VALUES(?,?,?,?,?,?,?)",
            (dumps(entry_ids), changeset_id, self._payload_hash(entry_ids), secrets.token_hex(16), "pending",
             clock.iso(), clock.iso(clock.now() + timedelta(hours=ttl))),
        )
        if notify:
            self._push(approval_id, entry_ids)
        return approval_id

    def _push_group(self, approval_id: int, task_id: int | None) -> tuple[str, list[int]]:
        """Which push a new approval goes into: the tag to show it under and the approvals that push is
        about. Sends of one task asked for within GROUP_SECONDS of the group's first share its tag, so a
        later push replaces the earlier one on the phone instead of buzzing again. The first push goes out
        at once (a single send is never held back), tagged approval-<id> like any other; the window counts
        from it, so a long stream buzzes at most once a minute. Kept in memory: after a restart the next
        send starts a new group."""
        if task_id is None:
            return f"approval-{approval_id}", [approval_id]
        now = clock.now()
        window = float(self.engine.config.get("push_group_seconds", GROUP_SECONDS))
        with self._push_lock:
            for tid, group in list(self._push_groups.items()):  # nothing to replace after the window
                if (now - group["start"]).total_seconds() > window:
                    del self._push_groups[tid]
            group = self._push_groups.get(task_id)
            if group is None or len(group["ids"]) >= GROUP_MAX:
                group = self._push_groups[task_id] = {"tag": f"approval-{approval_id}", "start": now, "ids": []}
            group["ids"].append(approval_id)
            return group["tag"], list(group["ids"])

    def _push(self, approval_id: int, entry_ids: list[int]) -> None:
        """The push for a new approval: what goes out (summary, first lines of the text) and, for the
        Accept and Decline buttons, the approval's id and payload hash. Accept sends that hash, so a payload
        that changed after the push is refused, as in the app. `accept` says whether Accept may approve in
        place ("tap") or must open the approval screen ("app"). When the same task asked for other sends a
        moment ago that still wait, one push for all of them replaces theirs (_push_group, _push_grouped).
        Pushes for the other things that wait for a yes or no carry `ask` instead (Engine.push_ask)."""
        entries = [self.engine.journal.get(i) for i in entry_ids]
        task_id = next((e["task_id"] for e in entries if e.get("task_id")), None)
        tag, group = self._push_group(approval_id, task_id)
        waiting = [i for i in group if i == approval_id or
                   (self.db.one("SELECT status FROM approvals WHERE id=?", (i,)) or {}).get("status") == "pending"]
        if len(waiting) > 1:
            return self._push_grouped(tag, waiting, task_id)
        title = "Waiting for you" if len(entries) == 1 else f"{len(entries)} sends waiting for you"
        try:
            views = [self.engine.entry_view(e) for e in entries]
            title = notice_title(views)  # the stake: who it goes to, or the new recipient to look at twice
            message = notice_text(views)
            accept = "tap" if accept_in_place(views, bool(self.engine.config.get("approval_passkey"))) else "app"
        except Exception:  # noqa: BLE001 - a broken plugin must not cost the owner the push
            log.exception("building the push for approval %s failed", approval_id)
            message, accept = "\n".join(e["summary"] for e in entries)[:500], "app"
        payload_hash = self.db.one("SELECT payload_hash FROM approvals WHERE id=?", (approval_id,))["payload_hash"]
        # one tag per approval (or per group of a task's sends), so the app can take the push away once the
        # owner decided there
        self.engine.notifier.push(title, message, url=f"{self.engine.public_url}/app/#/approvals/{approval_id}", priority=4,
                           extra={"approval": {"id": approval_id, "hash": payload_hash, "accept": accept},
                                  "tag": tag})

    def _push_grouped(self, tag: str, approval_ids: list[int], task_id: int | None) -> None:
        """One push for several waiting approvals of a task, under the group's tag: "3 sends from task 12"
        and a line for each. Deny all refuses them. When each of them could be accepted from a push of its
        own (accept_in_place), the push carries their payload hashes and Accept all approves them one by
        one, each checked as from its own push. Otherwise (a warning, a payment, the passkey) the button is
        Review and opens the review screen, as a tap on the push always does."""
        entries, hashes, per_approval = [], [], []
        for approval_id in approval_ids:
            row = self.db.one("SELECT journal_ids, payload_hash FROM approvals WHERE id=?", (approval_id,))
            per_approval.append([self.engine.journal.get(i) for i in loads(row["journal_ids"])])
            entries.extend(per_approval[-1])
            hashes.append(row["payload_hash"])
        approval = {"id": approval_ids[0], "ids": approval_ids, "accept": "app"}
        try:
            passkey = bool(self.engine.config.get("approval_passkey"))
            views = [[self.engine.entry_view(e) for e in group] for group in per_approval]
            if all(accept_in_place(group, passkey) for group in views):
                approval = {**approval, "accept": "tap", "hashes": hashes}
            views = [view for group in views for view in group]
            title, message = group_title(views, task_id), group_text(views)
        except Exception:  # noqa: BLE001 - a broken plugin must not cost the owner the push
            log.exception("building the grouped push for approvals %s failed", approval_ids)
            title = f"{len(entries)} sends from task {task_id}"
            message = "\n".join(f"· {e['summary']}" for e in entries)[:500]
            approval = {"id": approval_ids[0], "ids": approval_ids, "accept": "app"}
        ids = ",".join(str(i) for i in approval_ids)
        self.engine.notifier.push(title, message, url=f"{self.engine.public_url}/app/#/review/{ids}", priority=4,
                           extra={"approval": approval, "tag": tag})

    def accept_from_notification(self, approval_id: int) -> bool:
        """Checked again when Accept on a push approves in place: the push's word isn't enough."""
        row = self.db.one("SELECT * FROM approvals WHERE id=?", (approval_id,))
        if row is None or row["status"] != "pending":
            raise self._not_pending(row)  # "already decided" beats "open the app"
        views = [self.engine.entry_view(self.engine.journal.get(i)) for i in loads(row["journal_ids"])]
        return accept_in_place(views, bool(self.engine.config.get("approval_passkey")))

    STATES = {"approved": "approved", "denied": "declined", "edited": "replaced by an edited version",
                       "failed": "closed: the payload changed", "expired": "expired"}

    def _not_pending(self, row: dict | None) -> Denied:
        """Why an approval can't be decided any more, so a late tap (in the app or on a push) can say so."""
        if row is None:
            return Denied("no pending approval with that id", "approval")
        if row["status"] == "expired":
            return Denied("this approval expired; nothing was sent", "expired")
        return Denied(f"already decided: {self.STATES.get(row['status'], row['status'])}", "decided")

    def editable(self, entry: dict) -> list[str]:
        """The fields of a waiting send the owner may change before approving (the manifest's `editable`:
        message text, never recipients)."""
        if not entry.get("plugin") or "." not in (entry.get("tool") or ""):
            return []
        try:
            short = entry["tool"].split(".", 1)[1]
            spec = next((t for t in self.engine.registry.manifest(entry["plugin"]).get("tools", []) if t["name"] == short), {})
        except (KeyError, Denied, PluginError):
            return []
        return list(spec.get("editable") or [])

    def edit(self, approval_id: int, entry_id: int, changes: dict, seen_hash: str | None) -> dict:
        """The owner changes the text of a waiting send. Journal arguments never change, so the edited send
        becomes a new entry that replaces the old one ("superseded", pointing at the new one), and the
        approval is replaced by a new one with a new payload hash. Nothing is sent: the owner approves the
        new version next."""
        if not isinstance(changes, dict) or not changes:
            raise Denied("nothing to change", "invalid")
        with self.engine.lock:
            row = self.db.one("SELECT * FROM approvals WHERE id=?", (approval_id,))
            if row is None or row["status"] != "pending":
                raise Denied("no pending approval with that id", "approval")
            if row["expires"] < clock.iso():
                raise Denied("this approval expired", "expired")
            if not seen_hash or seen_hash != row["payload_hash"]:
                raise Denied("this approval isn't the one you looked at; reload it", "payload_changed")
            entry_ids = loads(row["journal_ids"])
            entry = self.engine.journal.get(entry_id)
            if entry_id not in entry_ids or entry is None or entry["status"] != "waiting_approval":
                raise Denied("that send isn't part of this approval", "invalid")
            editable = self.editable(entry)
            refused = sorted(set(changes) - set(editable))
            if refused:
                raise Denied(f"only {', '.join(editable) or 'nothing'} can be edited here, not {', '.join(refused)}; "
                             "to change who gets it, deny it and tell the agent", "invalid")
            args = {**(entry["args"] or {}), **changes}
            if args == entry["args"]:
                raise Denied("nothing changed", "invalid")
            short = entry["tool"].split(".", 1)[1]
            spec = next(t for t in self.engine.registry.manifest(entry["plugin"]).get("tools", []) if t["name"] == short)
            # only the edited fields: the rest was checked when the agent asked, and a prepared send (a reply)
            # carries fields its agent-facing schema doesn't list
            props = (spec.get("params") or {}).get("properties") or {}
            self.engine._validate({"type": "object", "properties": {k: props[k] for k in changes if k in props}},
                           changes, "edit")
            _, tool = self.engine.registry.tool_for_revert(entry["plugin"], short)
            checks = dict(entry["checks"] or {})
            checks["edited_from"] = entry_id
            checks["outgoing"] = self.outgoing_digest(tool, args)
            new_id = self.engine.journal.create(
                kind="action", session_id=entry["session_id"], task_id=entry["task_id"],
                changeset_id=entry["changeset_id"], plugin=entry["plugin"], tool=entry["tool"], args=args,
                tier=entry["tier"], decision="approval", checks=checks, status="waiting_approval",
                before=entry["before"], summary=tool.describe(args))
            self.engine.journal.update(entry_id, status="superseded", result={"superseded_by": new_id})
            self.db.exec("UPDATE approvals SET status='edited', decided=? WHERE id=?", (clock.iso(), approval_id))
            new_ids = [new_id if i == entry_id else i for i in entry_ids]
            new_approval = self.create(new_ids, changeset_id=row["changeset_id"], notify=False)
        # the agent's entry id now points at the edited one ("superseded"); doorman wait follows it
        self.engine.feed.approval_decided(row, "edited", replaced_by={"approval_id": new_approval, "entry_id": new_id,
                                                                "replaces": entry_id})
        return {"approval_id": new_approval, "entry_id": new_id, "replaces": entry_id}

    def get(self, approval_id: int) -> dict | None:
        row = self.db.one("SELECT * FROM approvals WHERE id=?", (approval_id,))
        if row is None:
            return None
        row["journal_ids"] = loads(row["journal_ids"])
        row["entries"] = [self.engine.entry_view(self.engine.journal.get(i)) for i in row["journal_ids"]]
        row.pop("nonce", None)
        if row["status"] == "expired":
            row["asked_again"] = self.asked_again(approval_id)
        return row

    def challenge(self, approval_id: int) -> bytes:
        row = self.db.one("SELECT * FROM approvals WHERE id=?", (approval_id,))
        if row is None or row["status"] != "pending":
            raise Denied("no pending approval with that id", "approval")
        return approval_challenge(approval_id, row["payload_hash"], row["nonce"])

    def decide(self, approval_id: int, approve: bool, credential_id: str | None = None,
                        seen_hash: str | None = None, method: str | None = None, note: Any = None,
                        wait: float | None = None) -> dict:
        """Approve or deny. `credential_id` is set when a passkey signed the payload; `seen_hash` is the
        payload hash the owner's screen showed, for a plain tap. Either binds the decision to what was shown.
        `note`: on a Deny, the owner's short word for the agent (approvals.reasons; approval_decided and
        doorman status pass it on).

        An approval and its entries become 'approved' in one transaction; the sends then run in a thread of
        their own (sends.py), and this waits for them up to `wait` seconds (send_wait_seconds, 3 by
        default). `results` has each entry's outcome, or "sending" for one still under way: the app follows
        it at GET /owner/approvals/<id>/results. When Accept on a push gets "sending", the outcome comes as a
        push of its own."""
        if note is not None and not isinstance(note, str):
            raise Denied("the note is text", "invalid")
        note = " ".join(sanitize.clean_text(note or "")[0].split())[:DENY_NOTE_CHARS] or None
        row = self.db.one("SELECT * FROM approvals WHERE id=?", (approval_id,))
        if row is None or row["status"] != "pending":
            raise self._not_pending(row)
        if approve and seen_hash is not None and seen_hash != row["payload_hash"]:
            raise Denied("this approval isn't the one you looked at; reload it", "payload_changed")
        entry_ids = loads(row["journal_ids"])
        if row["expires"] < clock.iso():
            self._close(approval_id, entry_ids, "expired")
            raise Denied("this approval expired", "expired")
        if self._payload_hash(entry_ids, strict=approve) != row["payload_hash"]:
            self._close(approval_id, entry_ids, "failed")
            raise Denied("the payload changed after the approval was requested", "payload_changed")
        with self.db.tx() as conn:
            cur = conn.execute(
                "UPDATE approvals SET status=?, decided=?, credential_id=?, method=?, reasons=? "
                "WHERE id=? AND status='pending'",
                ("approved" if approve else "denied", clock.iso(), credential_id, method,
                 None if approve else note, approval_id))
            claimed = cur.rowcount == 1
            if claimed and approve:  # with the decision, so a crash can't leave one without the other
                conn.execute(f"UPDATE journal SET status='approved' WHERE status='waiting_approval' AND id IN "
                             f"({','.join('?' * len(entry_ids))})", tuple(entry_ids))
        if not claimed:  # decided elsewhere in the meantime
            raise self._not_pending(self.db.one("SELECT * FROM approvals WHERE id=?", (approval_id,)))
        if not approve:
            for entry_id in entry_ids:
                self.engine.journal.update(entry_id, status="rejected")
            self.engine.feed.approval_decided(row, "declined", note=note)
            return {"approval_id": approval_id, "status": "denied"}
        self.engine.feed.approval_decided(row, "approved")
        run = self.engine.sends.start(approval_id, entry_ids)
        seconds = float(self.engine.config.get("send_wait_seconds", 3)) if wait is None else wait
        results = self.engine.sends.wait(run, seconds)
        sending = any(r["status"] in ("sending", "running") for r in results)
        if sending and method == "notification":
            self.engine.sends.tell_owner_when_done(run)
        return {"approval_id": approval_id, "status": "approved", "results": results, "sending": sending}

    def deny_note(self, entry_id: int) -> str | None:
        """The owner's note on the Deny of the approval this entry was part of, if they wrote one."""
        row = self.db.one("SELECT a.reasons FROM approvals a, json_each(a.journal_ids) j WHERE j.value=? "
                          "AND a.status='denied' ORDER BY a.id DESC LIMIT 1", (entry_id,))
        return row["reasons"] if row else None

    def _close(self, approval_id: int, entry_ids: list[int], status: str) -> None:
        self.db.exec("UPDATE approvals SET status=?, decided=? WHERE id=?", (status, clock.iso(), approval_id))
        for entry_id in entry_ids:
            self.engine.journal.update(entry_id, status=status if status != "failed" else "rejected")
        row = self.db.one("SELECT * FROM approvals WHERE id=?", (approval_id,))
        if status == "expired":
            self.engine.feed.approval_expired(approval_id, entry_ids, row["changeset_id"])
        else:  # the payload changed after it was asked for: closed, nothing sent
            self.engine.feed.approval_decided(row, "closed", note=None)
        if status == "expired":
            summaries = [self.engine.journal.get(i)["summary"] for i in entry_ids]
            self.engine.attention("approval_expired", approval_id, "An approval expired, so nothing was sent",
                           "\n".join(summaries), url=f"{self.engine.public_url}/app/#/approvals/{approval_id}")

    def asked_again(self, approval_id: int) -> str | None:
        """When the owner asked the agent to ask again for this expired approval, if they did."""
        row = self.db.one("SELECT MIN(ts) AS ts FROM events WHERE plugin IS NULL AND type='approval_ask_again' "
                          "AND ref=?", (f"approval:{approval_id}",))
        return row["ts"] if row else None

    def ask_again(self, approval_id: int) -> dict:
        """The owner still wants a send whose approval expired: the agent that asked hears it
        (approval_ask_again, with the entries) and asks again, which makes a new approval with every check
        run afresh. Nothing is re-sent from here: the old payload was never approved, and its checks are a
        day old. Asking twice tells the agent once."""
        row = self.db.one("SELECT * FROM approvals WHERE id=?", (approval_id,))
        if row is None:
            raise Denied("no such approval", "not_found")
        if row["status"] != "expired":
            raise Denied("only an expired approval can be asked for again", "invalid")
        asked = self.asked_again(approval_id)
        if asked:
            return {"approval_id": approval_id, "asked": asked}
        entry_ids = loads(row["journal_ids"])
        by_key = self.engine.feed._entries_by_key(entry_ids)
        keys = {r["id"]: r for r in self.db.all("SELECT id, revoked FROM agent_keys")}
        live = {k: ids for k, ids in by_key.items() if k in keys and not keys[k]["revoked"]}
        if not live:
            raise Denied("the agent that asked for it has no key any more; give it a new task instead", "invalid")
        if any(self.engine.auth.paused(k) for k in live):
            raise Denied("the key of the agent that asked for this is paused (a honeytoken, a decoy key or a "
                         "leak); resume it first if you trust it", "key_paused")
        task_id = next((e["task_id"] for e in (self.engine.journal.get(i) for i in entry_ids) if e and e["task_id"]), None)
        for key_id, ids in live.items():
            self.engine.feed.emit("approval_ask_again", [key_id], f"approval:{approval_id}", approval_id=approval_id,
                           entry_ids=ids, task_id=task_id, changeset_id=row["changeset_id"])
        self.engine.resolve_attention("approval_expired", approval_id)
        return {"approval_id": approval_id, "asked": self.asked_again(approval_id)}

    def expire(self) -> None:
        for row in self.db.all("SELECT id, journal_ids FROM approvals WHERE status='pending' AND expires<?",
                               (clock.iso(),)):
            self._close(row["id"], loads(row["journal_ids"]), "expired")

    def pending(self) -> list[dict]:
        return [self.get(r["id"]) for r in
                self.db.all("SELECT id FROM approvals WHERE status='pending' ORDER BY id DESC")]

    def cancel_pending(self) -> int:
        rows = self.db.all("SELECT id, journal_ids FROM approvals WHERE status='pending'")
        for row in rows:
            self._close(row["id"], loads(row["journal_ids"]), "cancelled")
        return len(rows)
