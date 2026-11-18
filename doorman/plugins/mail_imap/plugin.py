"""IMAP + SMTP mail. A new connection per operation keeps it simple and robust.

Each mailbox also keeps an archive (archive.py): its own copy of the mailbox's text, which feeds Doorman's
search index (index_feed; doorman search finds mail there) and which reads fall back on when a message is
gone from the server. mail.search asks the server itself."""

import email
import email.policy
import json
import mimetypes
import re
import smtplib
import socket
import ssl
import types
from contextlib import contextmanager
from datetime import date, timedelta
from email.message import EmailMessage
from email.utils import formatdate, getaddresses, make_msgid

from imapclient import IMAPClient
from imapclient import imapclient as imapclient_module

from doorman import clock
from doorman.sanitize import describe, html_to_text
from doorman.plugin_api import BasePlugin, Denied, ExecResult, NotSent, PluginError, Tool, iso_moment, since_param
from doorman.plugins.mail_imap.archive import Archive, attachment_parts, body_text, flags_of
from doorman.plugins.mail_imap.archive import unchecked as archive_unchecked

# errors that prove the server took nothing: refused before the message data went in
SMTP_REFUSED = (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused, smtplib.SMTPAuthenticationError,
                smtplib.SMTPConnectError, smtplib.SMTPHeloError, smtplib.SMTPNotSupportedError,
                ConnectionRefusedError, socket.gaierror, ssl.SSLCertVerificationError)
SPECIAL = {"drafts": b"\\Drafts", "sent": b"\\Sent", "trash": b"\\Trash", "archive": b"\\Archive"}
DEFAULT_FOLDERS = {"drafts": "Drafts", "sent": "Sent", "trash": "Trash", "archive": "Archive"}
REPLY_PREFIX = re.compile(r"^\s*(re|aw|antw)\s*(\[\d+\])?\s*:", re.I)  # English, German, Dutch
MAX_REFERENCES = 20
# a list row's extras: whether it is bulk mail (from the headers below), its attachments and its text's start
LIST_FIELDS = "HEADER.FIELDS (MESSAGE-ID REPLY-TO LIST-ID LIST-UNSUBSCRIBE PRECEDENCE)"
SNIPPET_CHARS = 160
# mail.search bulk:=true/false: IMAP can't search for "has a List-Id" everywhere alike, so the newest messages
# matching the rest are told apart by their headers, at most this many, in steps of BULK_STEP
BULK_SCAN, BULK_STEP = 1000, 200
SNIPPET_FETCH_MAX = 256 * 1024   # a message the archive doesn't have yet is downloaded for that up to this size
GUARD_TEXT_MAX = 20000           # how much of the text behind a snippet the guard scans, like a read (max_chars)
# a server that files sent mail itself (server_files_sent: Exchange, Gmail) does so as it accepts it; a send
# that broke off and isn't there this long after the attempt didn't go out
SENT_FILED_MINUTES = 10
# IMAP is a line protocol, and imapclient quotes only backslash and double quote: a line break in a search
# word, folder name or Message-ID would end the command and start another on the logged-in connection
# (A1 UID SEARCH TEXT "x<CR><LF>A2 UID STORE 1:* +FLAGS (\Deleted)"). Agents' text with a control character
# is refused (imap_text, and the manifest's patterns); SafeIMAPClient refuses any command line that has one.
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
LINE_BREAK = re.compile(rb"[\r\n\x00]")
# a flag or keyword (label): one IMAP atom, so no spaces, brackets or quotes ("x \Deleted" would be two flags)
FLAG = re.compile(r"\\?[^\x00-\x20\x7f(){%*\"\\\]]+")


def imap_text(value, field: str) -> str:
    """An agent's text for an IMAP command, refused when it holds a line break or another control character."""
    value = str(value)
    if CONTROL.search(value):
        raise Denied(f"{field} may not contain line breaks or other control characters", "invalid")
    return value


# the bytes type imapclient always sends as a literal (APPEND's message, from 4.3 on): `literal`, `_literal` before 4.3
LITERAL = getattr(imapclient_module, "literal", None) or imapclient_module._literal


def _no_line_break(arg) -> None:
    if isinstance(arg, str):
        arg = arg.encode("utf-8", "surrogatepass")
    if isinstance(arg, (bytes, bytearray)) and LINE_BREAK.search(arg):
        raise Denied("refused to send an IMAP command with a line break or NUL in it (from a search, a folder "
                     "name or a message id)", "invalid")


class SafeIMAPClient(IMAPClient):
    """IMAPClient that never puts a line break or NUL into a command line, whatever the text came from. Commands
    leave through two doors: imapclient's own (_raw_command: SEARCH, FETCH, ...) and imaplib's (_command: SELECT,
    STORE, COPY, MOVE, APPEND, LOGIN, ...). A message's bytes still go as a literal, which may hold line breaks.
    imapclient checks its arguments itself from 4.3 on (a ValueError); the checks here come first, so a refusal
    is a Denied whatever version is installed."""

    def _raw_command(self, command, args, uid=True):
        for arg in args if isinstance(args, (list, tuple)) else [args]:
            if isinstance(arg, (bytes, bytearray)) and not any(b > 127 for b in arg) \
                    and not isinstance(arg, LITERAL):  # 8-bit text and literals go as literals, not on the line
                _no_line_break(arg)
        return super()._raw_command(command, args, uid)

    def _command_and_check(self, command, *args, **kwargs):  # on the way to imaplib's door
        if command not in ("append", b"append"):  # before 4.3 its message comes along here, and imaplib sends
            for arg in args:                      # that as a literal (its other arguments: checked at the door)
                _no_line_break(arg)
        return super()._command_and_check(command, *args, **kwargs)

    def _create_IMAP4(self):
        imap = super()._create_IMAP4()
        send = imap._command

        def command(_imap, name, *args):
            for arg in args:
                _no_line_break(arg)
            return send(name, *args)

        # imaplib sends APPEND's message separately (imap.literal), not among args. A bound method, as imaplib's
        # own is: _command takes AUTHENTICATE's answer for a callback only when its type is type(self._command),
        # and a plain function here made every XOAUTH2 sign-in fail (tests/test_imap_guard.py)
        imap._command = types.MethodType(command, imap)
        return imap


def is_bulk(raw_headers: bytes) -> bool:
    """A mailing list, newsletter or other mass mail: List-Id, List-Unsubscribe, or Precedence bulk/list/junk."""
    header = email.message_from_bytes(raw_headers or b"", policy=email.policy.compat32)
    precedence = str(header.get("Precedence", "")).strip().lower()
    return bool(header.get("List-Id") or header.get("List-Unsubscribe") or precedence in ("bulk", "list", "junk"))


def snippet(text: str) -> str:
    """The start of a message's text for a list row: quoted lines left out, spaces folded, about 160 characters."""
    lines = [line for line in (text or "").splitlines() if not line.lstrip().startswith(">")]
    flat = " ".join(" ".join(lines).split())
    if len(flat) <= SNIPPET_CHARS:
        return flat
    return (flat[:SNIPPET_CHARS].rsplit(" ", 1)[0] or flat[:SNIPPET_CHARS]) + "…"


def with_snippet(item: dict, text: str) -> None:
    """The row's snippet, and when that is cut short the whole text for the injection guard only
    (`_guard_text`: Doorman scans it with the row and drops it before an agent gets the row)."""
    item["snippet"] = snippet(text)
    if item["snippet"].endswith("…"):
        item["_guard_text"] = text[:GUARD_TEXT_MAX]
READ_CHARS = 20000  # what mail.read returns of a body unless max_chars asks for more (up to 200000)


def reply_subject(subject: str) -> str:
    """"Re: " in front, unless the subject already starts with Re:, AW: or Antw:."""
    subject = " ".join((subject or "").split())
    return subject if REPLY_PREFIX.match(subject) else f"Re: {subject}".rstrip()


def _unique(addresses) -> list[str]:
    return list(dict.fromkeys(a.strip().lower() for a in addresses if a and "@" in a))


def _text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return str(email.header.make_header(email.header.decode_header(value)))


def _addresses(envelope_list) -> list[str]:
    out = []
    for addr in envelope_list or []:
        if addr.mailbox and addr.host:
            out.append(f"{addr.mailbox.decode()}@{addr.host.decode()}".lower())
    return out


_flags = flags_of


class GoneFromServer(PluginError):
    """The message is in the archive but no longer on the server."""


class NoSuchMessage(PluginError):
    """Neither the server nor the archive has a message with that Message-ID."""


class MailTool(Tool):
    def ref_for(self, args):
        return args.get("id")  # move, label, delete: Message-IDs survive moves

    def current(self, object_ref):
        with self.plugin.imap() as client:
            found = self.plugin.locate(client, object_ref)
            return self.plugin.state(client, *found) if found else None


class Draft(MailTool):
    def preview(self, args, before):
        return {"to": args["to"], "cc": args.get("cc", []), "subject": args["subject"], "body": args["body"],
                "attachments": args.get("attachments", [])}

    def execute(self, args, before):
        message = self.plugin.build(args)
        drafts = self.plugin.folder("drafts")
        with self.plugin.imap() as client:
            client.append(drafts, message.as_bytes(), flags=[b"\\Draft", b"\\Seen"])
            found = self.plugin.locate(client, self.plugin.mid(message), hint=drafts)
            state = self.plugin.state(client, *found)
        return ExecResult(result={"id": state["message_id"]}, after=state, object_ref=state["message_id"],
                          summary=f"Drafted “{args['subject']}” to {', '.join(args['to'])}")

    def undo(self, object_ref, before, after):
        with self.plugin.imap() as client:
            if before is None:
                found = self.plugin.locate(client, object_ref)
                if found:
                    self.plugin.expunge(client, *found)
            else:
                self.plugin.restore_raw(client, before)

    def describe(self, args):
        return f"Draft “{args.get('subject')}” to {', '.join(args.get('to', []))}"


class Send(Tool):
    def snapshot(self, args):
        """A send changes nothing here to compare, but its Message-ID is chosen now, before anything goes out:
        Doorman keeps this in the journal, so a send that broke off can be looked for (verify_sent)."""
        return {"_message_id": self.plugin.new_message_id(), "_at": clock.iso()}

    def verify_sent(self, args, before, error):
        """Look for the Message-ID: in Sent first, then in every folder (a copy to yourself counts too). Not
        there: "failed" only when the server files sent mail itself and had time to; otherwise Doorman's
        own copy in Sent was never made (it comes after the server accepted), so absence says nothing."""
        message_id = (before or {}).get("_message_id")
        if not message_id:
            return {"status": "unknown", "detail": "it has no Message-ID to look for"}
        sent = self.plugin.folder("sent")
        with self.plugin.imap() as client:
            found = self.plugin.locate(client, message_id, hint=sent)
        if found:
            return {"status": "sent", "detail": f"Doorman found it in {found[0]}", "result": {"id": message_id}}
        at = iso_moment((before or {}).get("_at"))
        late = at is not None and (clock.now() - at).total_seconds() > SENT_FILED_MINUTES * 60
        if self.plugin.config.get("server_files_sent") and late:
            return {"status": "failed", "detail": f"it isn't in {sent} {SENT_FILED_MINUTES} minutes later, and "
                                                  "your mail server puts every mail it accepts there"}
        return {"status": "unknown", "detail": f"it isn't in {sent} (yet)"}

    def trusted_destinations(self, args):
        if not args.get("in_reply_to"):
            return set()
        with self.plugin.imap() as client:
            found = self.plugin.locate(client, args["in_reply_to"])
            if not found:
                return set()
            state = self.plugin.state(client, *found)
        return set(state["from"] + state["reply_to"])

    def execute(self, args, before):
        try:
            message = self.plugin.build(args, (before or {}).get("_message_id"))
        except PluginError as exc:
            raise NotSent(str(exc)) from exc
        recipients = args["to"] + args.get("cc", []) + args.get("bcc", [])
        try:
            self.plugin.smtp_send(message, recipients)
        except SMTP_REFUSED as exc:
            raise NotSent(f"the mail server refused it: {exc}") from exc
        # the server accepted it: from here on it is sent, and filing problems only add a warning
        result = {"id": self.plugin.mid(message)}
        try:
            with self.plugin.imap() as client:
                if not self.plugin.config.get("server_files_sent"):
                    # build() never writes a Bcc header, so the Sent copy doesn't reveal Bcc recipients
                    client.append(self.plugin.folder("sent"), message.as_bytes(), flags=[b"\\Seen"])
                if args.get("draft_id"):
                    found = self.plugin.locate(client, args["draft_id"], hint=self.plugin.folder("drafts"),
                                               only_hint=True)
                    if found and "\\Draft" in self.plugin.state(client, *found)["flags"]:
                        self.plugin.expunge(client, *found)
        except Exception as exc:  # noqa: BLE001 - the mail is out; don't report the send as failed
            self.ctx.log.warning("sent, but filing it failed: %s", exc)
            result["warning"] = f"sent, but the copy in Sent or the draft cleanup failed: {exc}"
        return ExecResult(result=result, object_ref=self.plugin.mid(message),
                          summary=f"Sent “{args['subject']}” to {', '.join(recipients)}")

    def describe(self, args):
        recipients = args.get("to", []) + args.get("cc", []) + args.get("bcc", [])
        files = f" with {len(args['attachments'])} attachment(s)" if args.get("attachments") else ""
        draft = f", then delete draft {args['draft_id']}" if args.get("draft_id") else ""
        return f"Send “{args.get('subject')}” to {', '.join(recipients)}{files}{draft}"

    def follow_up(self, args, result):
        return f"Send a correction to {', '.join(args.get('to', []))} if needed."


class Answering:
    """What reply and draft_reply share: prepare() turns {id, body, all, cc} into a whole message from the mail
    being answered, before Doorman checks and journals the call. Summaries name the recipients only, never the
    answered mail's subject: that's a stranger's text, and actor keys see summaries."""

    def prepare(self, args):
        return self.plugin.reply_args(args)

    def ref_for(self, args):
        return None  # args["id"] is the mail being answered, not what this writes

    def trusted_destinations(self, args):
        return set((args.get("answered") or {}).get("trusted") or [])

    def destination_origins(self, args):
        answered = args.get("answered") or {}
        seen = {"origin": answered.get("ref"), "trust": "third_party", "label": answered.get("subject"),
                "from": answered.get("from"), "answered": True}
        return {address: seen for address in answered.get("recipients") or []}

    @staticmethod
    def who(args) -> str:
        cc = args.get("cc") or []
        return ", ".join(args.get("to") or []) + (f", cc {', '.join(cc)}" if cc else "")


class Reply(Answering, Send):
    def execute(self, args, before):
        out = super().execute(args, before)
        out.summary = f"Replied to {self.who(args)}"
        return out

    def describe(self, args):
        files = f" with {len(args['attachments'])} attachment(s)" if args.get("attachments") else ""
        return f"Reply{' to all' if args.get('all') else ''}: to {self.who(args)}{files}"


class DraftReply(Answering, Draft):
    def execute(self, args, before):
        out = super().execute(args, before)
        out.summary = f"Drafted a reply to {self.who(args)}"
        return out

    def describe(self, args):
        return f"Draft a reply to {self.who(args)}"


class Move(MailTool):
    FIELD_SCOPED_UNDO = True  # undo moves the message back; flags others changed stay

    def target(self, args):
        return args["folder"]

    def snapshot(self, args):
        with self.plugin.imap() as client:
            found = self.plugin.locate(client, args["id"])
            if not found:
                raise PluginError(f"no message {args['id']}")
            return self.plugin.state(client, *found)

    def preview(self, args, before):
        return {**before, "folder": self.target(args)}

    def execute(self, args, before):
        with self.plugin.imap() as client:
            self.plugin.move(client, before["folder"], args["id"], self.target(args))
            state = self.plugin.state(client, *self.plugin.locate(client, args["id"], hint=self.target(args)))
        self.plugin.archive_touch(state)
        return ExecResult(result={"id": args["id"], "folder": state["folder"]}, after=state, object_ref=args["id"],
                          summary=f"Moved “{before['subject']}” to {state['folder']}")

    def undo(self, object_ref, before, after):
        with self.plugin.imap() as client:
            found = self.plugin.locate(client, object_ref, hint=after["folder"])
            if not found:
                raise PluginError("the message is gone; it can't be moved back")
            self.plugin.move(client, found[0], object_ref, before["folder"])

    def render_diff(self, before, after, args):
        keep = ("folder",)
        pick = (lambda s: {k: s[k] for k in keep} if s else None)
        return [{"sign": " ", "field": "subject", "value": before["subject"]}] + \
            super().render_diff(pick(before), pick(after), args)

    def describe(self, args):
        return f"Move message {args.get('id')} to {self.target(args)}"


class Delete(Move):
    """Moves to the Agent trash folder, never the server's Trash, which providers empty on their own."""

    def target(self, args):
        return self.plugin.agent_trash()

    def describe(self, args):
        return f"Move message {args.get('id')} to {self.plugin.agent_trash_name()}"


class Label(MailTool):
    FIELD_SCOPED_UNDO = True  # only flags change, and only flags are put back

    @staticmethod
    def check_flags(args) -> None:
        for flag in args.get("add", []) + args.get("remove", []):
            if not FLAG.fullmatch(flag):  # flags go out unquoted: "x \Deleted" would set \Deleted too
                raise Denied(f"{flag!r} isn't one flag or keyword: no spaces, brackets, quotes or control "
                             "characters", "invalid")
            # \Deleted plus any expunge, by this doorman or another mail client, would erase the message for good
            if flag.lower() == "\\deleted":
                raise Denied("\\Deleted can't be set or cleared; use mail delete, which moves to the Agent trash",
                             "invalid")

    def tier(self, args):
        self.check_flags(args)
        return super().tier(args)

    def snapshot(self, args):
        return Move.snapshot(self, args)

    def preview(self, args, before):
        flags = (set(before["flags"]) | set(args.get("add", []))) - set(args.get("remove", []))
        return {**before, "flags": sorted(flags)}

    def execute(self, args, before):
        self.check_flags(args)
        with self.plugin.imap() as client:
            folder, uid = self.plugin.locate(client, args["id"], hint=before["folder"])
            client.select_folder(folder)
            if args.get("add"):
                client.add_flags([uid], [f.encode() for f in args["add"]])
            if args.get("remove"):
                client.remove_flags([uid], [f.encode() for f in args["remove"]])
            state = self.plugin.state(client, folder, uid)
        self.plugin.archive_touch(state)
        return ExecResult(result={"id": args["id"], "flags": state["flags"]}, after=state, object_ref=args["id"],
                          summary=f"Labels on “{before['subject']}”: {', '.join(state['flags']) or 'none'}")

    def undo(self, object_ref, before, after):
        with self.plugin.imap() as client:
            folder, uid = self.plugin.locate(client, object_ref, hint=after["folder"])
            client.select_folder(folder)
            client.set_flags([uid], [f.encode() for f in before["flags"]])

    def render_diff(self, before, after, args):
        old, new = set(before["flags"]), set(after["flags"]) if after else set()
        lines = [{"sign": " ", "field": "subject", "value": before["subject"]}]
        lines += [{"sign": "-", "field": "label", "value": f} for f in sorted(old - new)]
        lines += [{"sign": "+", "field": "label", "value": f} for f in sorted(new - old)]
        return lines

    def describe(self, args):
        return f"Label message {args.get('id')}: +{args.get('add', [])} -{args.get('remove', [])}"


class Plugin(BasePlugin):
    TOOLS = {"draft": Draft, "send": Send, "reply": Reply, "draft_reply": DraftReply, "move": Move, "label": Label,
             "delete": Delete}
    READS = {"folders": "read_folders", "search": "read_search", "recent": "read_recent", "read": "read_message",
             "attachment": "read_attachment"}

    def __init__(self, ctx, manifest):
        super().__init__(ctx, manifest)
        self.archive = Archive(self)

    def close(self):
        self.archive.close()

    def run_job(self, name, budget):
        if name != "archive":
            raise PluginError(f"no job {name}")
        return self.archive.run(float(budget))

    def index_feed(self, cursor, budget):
        """The archive's messages for Doorman's search index, as they arrive and change (archive.feed)."""
        return self.archive.feed(cursor, float(budget))

    def known_recipients(self, destinations):
        """Addresses the owner wrote to from this mailbox: mail from one of their own addresses in the Sent
        folder, from the archive (no server round trip once the Sent folder's name is known). Doorman leaves
        out any message one of its own actions touched (policy.py)."""
        addresses = list(dict.fromkeys(str(v).lower() for k, v in destinations if k == "email"))
        if not addresses or not self.archive.on:
            return {}
        return self.archive.sent_to(self.folder("sent"), addresses, self.own_addresses())

    def archive_touch(self, state: dict) -> None:
        try:
            self.archive.touch(state)
        except Exception as exc:  # noqa: BLE001 - the next sync puts it right
            self.ctx.log.warning("archive: couldn't note a change to %s: %s", state.get("message_id"), exc)

    # connections

    @contextmanager
    def imap(self):
        host = self.config.get("imap_host")
        if not host:
            raise PluginError("mail: set config.imap_host")
        security = self.config.get("imap_security", "ssl")
        port = int(self.config.get("imap_port", 993 if security == "ssl" else 143))
        context = ssl.create_default_context()
        client = SafeIMAPClient(host, port=port, ssl=security == "ssl", ssl_context=context, timeout=30)
        try:
            if security == "starttls":
                client.starttls(context)
            self.imap_login(client)
            yield client
        finally:
            try:
                client.logout()
            except Exception:  # noqa: BLE001 - logout errors don't matter
                pass

    def imap_login(self, client: IMAPClient) -> None:
        client.login(self.credentials.get("username", ""), self.credentials.get("password", ""))

    def mailbox(self) -> str | None:
        """Which mailbox this is, "<login> on <server>" in lower case, or None before it's set up: the
        archive keeps to it (Archive._open)."""
        user, host = self.credentials.get("username"), self.config.get("imap_host")
        return f"{user} on {host}".strip().lower() if user and host else None

    def smtp_login(self, smtp: smtplib.SMTP, security: str) -> None:
        user = self.credentials.get("smtp_username", self.credentials.get("username"))
        password = self.credentials.get("smtp_password", self.credentials.get("password"))
        if user and (security != "none" or self.config.get("smtp_login_without_tls")):
            smtp.login(user, password)

    def sender(self) -> str | None:
        return self.config.get("from_address") or self.credentials.get("username")

    def check(self):
        try:
            with self.imap():
                pass
        except Exception as exc:  # noqa: BLE001 - login refused, host gone, TLS trouble
            return f"IMAP login failed: {exc}"
        return None

    def smtp_send(self, message: EmailMessage, recipients: list[str]) -> None:
        host = self.config.get("smtp_host")
        if not host:
            raise PluginError("mail: set config.smtp_host")
        security = self.config.get("smtp_security", "starttls")
        port = int(self.config.get("smtp_port", 465 if security == "ssl" else 587))
        context = ssl.create_default_context()
        smtp_cls = smtplib.SMTP_SSL if security == "ssl" else smtplib.SMTP
        kwargs = {"context": context} if security == "ssl" else {}
        with smtp_cls(host, port, timeout=30, **kwargs) as smtp:
            if security == "starttls":
                smtp.starttls(context=context)
            self.smtp_login(smtp, security)
            smtp.send_message(message, to_addrs=recipients)

    # folders and lookup

    def folder(self, role: str) -> str:
        configured = (self.config.get("folders") or {}).get(role)
        if configured:
            return configured
        if not hasattr(self, "_special"):
            self._special = {}
            try:
                with self.imap() as client:
                    for flags, _, name in client.list_folders():
                        for key, flag in SPECIAL.items():
                            if flag in flags:
                                self._special[key] = name
            except PluginError:
                raise
            except Exception:  # noqa: BLE001 - fall back to the usual names
                pass
        return self._special.get(role, DEFAULT_FOLDERS[role])

    @staticmethod
    def mid(message: EmailMessage) -> str:
        return message["Message-ID"].strip("<> ")

    def locate(self, client: IMAPClient, message_id: str, hint: str | None = None, only_hint: bool = False):
        folders = [hint] if hint else []
        if not only_hint:
            folders += [name for flags, _, name in client.list_folders() if b"\\Noselect" not in flags and name != hint]
        for folder in folders:
            client.select_folder(folder, readonly=True)
            uids = client.search(["HEADER", "Message-ID", f"<{message_id}>"])
            if uids:
                return folder, uids[-1]
        return None

    def state(self, client: IMAPClient, folder: str, uid: int) -> dict:
        client.select_folder(folder, readonly=True)
        data = client.fetch([uid], ["ENVELOPE", "FLAGS", "BODY.PEEK[HEADER.FIELDS (MESSAGE-ID REPLY-TO)]"])[uid]
        return self.state_of_fetch(folder, data, b"BODY[HEADER.FIELDS (MESSAGE-ID REPLY-TO)]")

    @staticmethod
    def state_of_fetch(folder: str, data: dict, header_key: bytes) -> dict:
        """state() from a FETCH answer with ENVELOPE, FLAGS and the Message-ID and Reply-To headers."""
        env = data[b"ENVELOPE"]
        header = email.message_from_bytes(data[header_key], policy=email.policy.default)
        return {
            "message_id": str(header.get("Message-ID", "")).strip("<> "),
            "folder": folder,
            "subject": _text(env.subject),
            "from": _addresses(env.from_),
            "reply_to": [a for _, a in getaddresses([str(header.get("Reply-To", ""))]) if a],
            "to": _addresses(env.to),
            # imapclient gives the Date header in this host's local time, without an offset: add it
            "date": env.date.astimezone().isoformat() if env.date else None,
            "flags": _flags(data[b"FLAGS"]),
        }

    def move(self, client: IMAPClient, source: str, message_id: str, dest: str) -> None:
        found = self.locate(client, message_id, hint=source)
        if not found:
            raise PluginError(f"no message {message_id}")
        folder, uid = found
        client.select_folder(folder)
        if client.has_capability("MOVE"):
            client.move([uid], dest)
        else:
            if not client.has_capability("UIDPLUS"):
                raise PluginError("the server supports neither MOVE nor UIDPLUS, so a move could erase other "
                                  "messages marked deleted; moves are off for this account")
            client.copy([uid], dest)
            self.expunge(client, folder, uid)

    def expunge(self, client: IMAPClient, folder: str, uid: int) -> None:
        """Remove exactly one message. Only UID EXPUNGE: a plain EXPUNGE would also erase every other
        message in the folder that another mail client marked \\Deleted."""
        if not client.has_capability("UIDPLUS"):
            raise PluginError("the server lacks UIDPLUS, so Doorman can't remove a single message safely")
        client.select_folder(folder)
        client.add_flags([uid], [b"\\Deleted"])
        client.expunge([uid])  # UID EXPUNGE

    def agent_trash_name(self) -> str:
        return (self.config.get("folders") or {}).get("agent_trash", "Agent trash")

    def agent_trash(self) -> str:
        """The folder deletes go to; created on first use."""
        name = self.agent_trash_name()
        if not getattr(self, "_agent_trash_ok", False):
            with self.imap() as client:
                if not client.folder_exists(name):
                    client.create_folder(name)
            self._agent_trash_ok = True
        return name

    def restore_raw(self, client: IMAPClient, state: dict) -> None:
        raise PluginError("restoring a deleted draft is not supported")

    # building messages

    def own_addresses(self) -> set[str]:
        """The owner's addresses, which a reply-all leaves out."""
        own = {a.lower() for a in self.ctx.owner_identities}
        candidates = [self.credentials.get("username"), self.config.get("address"), self.config.get("from_address")]
        try:
            candidates.append(self.sender())
        except PluginError:
            pass
        for _, address in getaddresses([c for c in candidates if c]):
            if "@" in address:
                own.add(address.lower())
        return own

    def answered(self, message_id: str) -> dict:
        """The headers a reply needs from the mail it answers: from the server, else from the archive."""
        try:
            state, message = self.fetch_message(message_id)
        except GoneFromServer:
            row = self.archive.message(message_id)
            return {**self.archive.state_of(row), "cc": json.loads(row["cc"] or "[]"), "references": []}
        except NoSuchMessage:
            raise Denied(f"no message {message_id} in {self.ctx.instance}; take the id from search or read",
                         "invalid") from None
        return {**state, "cc": [a for _, a in getaddresses([str(message.get("Cc", ""))]) if a],
                "references": re.findall(r"<([^<>\s]+)>", str(message.get("References", "")))}

    def reply_args(self, args: dict) -> dict:
        """A reply as a whole message: To is the Reply-To (else the sender); with `all`, the mail's other To and
        Cc go in Cc; never the owner's own addresses. When the owner wrote the mail being answered, the reply
        goes to its recipients. Subject "Re: ...", In-Reply-To and References continue the thread."""
        mid = str(args["id"]).strip().strip("<>")
        mail = self.answered(mid)
        own = self.own_addresses()
        sender = _unique(mail["reply_to"] or mail["from"])
        to = [a for a in sender if a not in own] or [a for a in _unique(mail["to"]) if a not in own]
        if not to:
            raise Denied("nobody to reply to: the mail has no sender or recipient besides you", "invalid")
        cc = [a for a in _unique(mail["to"] + mail["cc"]) if a not in own and a not in to] if args.get("all") else []
        from_mail = set(to + cc)
        cc = _unique(cc + list(args.get("cc") or []))
        cc = [a for a in cc if a not in to]
        trusted = _unique(mail["from"] + mail["reply_to"])
        refs = list(dict.fromkeys([r for r in mail["references"] if r != mid] + [mid]))[-MAX_REFERENCES:]
        out = {"id": mid, "all": bool(args.get("all")), "to": to}
        if cc:
            out["cc"] = cc
        out.update({"subject": reply_subject(mail["subject"]), "body": args["body"], "in_reply_to": mid,
                    "references": " ".join(f"<{r}>" for r in refs)})
        if args.get("attachments"):
            out["attachments"] = list(args["attachments"])
        out["answered"] = {"ref": f"{self.ctx.instance}:{mid}", "from": (mail["from"] or [""])[0],
                           "subject": mail["subject"], "date": mail["date"], "trusted": trusted,
                           "recipients": sorted(a for a in from_mail if a not in trusted)}
        return out

    def new_message_id(self) -> str:
        sender = self.sender()
        domain = sender.split("@", 1)[1] if sender and "@" in sender else "doorman"
        return make_msgid(domain=domain).strip("<> ")

    def build(self, args: dict, message_id: str | None = None) -> EmailMessage:
        """The message for args. `message_id`: the one a send chose before it started (Send.snapshot)."""
        message = EmailMessage()
        sender = self.sender()
        message["From"] = sender
        message["To"] = ", ".join(args["to"])
        if args.get("cc"):
            message["Cc"] = ", ".join(args["cc"])
        message["Subject"] = args["subject"]
        message["Date"] = formatdate(localtime=True)
        message["Message-ID"] = f"<{message_id or self.new_message_id()}>"
        if args.get("in_reply_to"):
            message["In-Reply-To"] = f"<{args['in_reply_to']}>"
            message["References"] = args.get("references") or f"<{args['in_reply_to']}>"
        message.set_content(args["body"])
        for ref in args.get("attachments", []):
            filename, content = self.ctx.resolve_ref(ref)
            maintype, subtype = (mimetypes.guess_type(filename)[0] or "application/octet-stream").split("/", 1)
            message.add_attachment(content, maintype=maintype, subtype=subtype, filename=filename)
        return message

    # reads

    def read_folders(self, params):
        with self.imap() as client:
            return [{"name": name} for flags, _, name in client.list_folders() if b"\\Noselect" not in flags]

    def read_search(self, params):
        criteria: list = []
        if params.get("query"):
            criteria += ["TEXT", imap_text(params["query"], "query")]
        if params.get("from"):
            criteria += ["FROM", imap_text(params["from"], "from")]
        if params.get("since"):
            criteria += ["SINCE", date.fromisoformat(params["since"])]
        if params.get("unread"):
            criteria.append("UNSEEN")
        folder = imap_text(params.get("folder", "INBOX"), "folder")
        with self.imap() as client:
            client.select_folder(folder, readonly=True)
            uids = sorted(client.search(criteria or ["ALL"]), reverse=True)
            uids = (self.bulk_or_not(client, uids, params["bulk"], params.get("limit", 20)) if "bulk" in params
                    else uids[: params.get("limit", 20)])
            if not uids:
                return []
            data = client.fetch(uids, ["ENVELOPE", "FLAGS", "RFC822.SIZE", f"BODY.PEEK[{LIST_FIELDS}]"])
            items, unarchived = [], []
            for uid in uids:
                state = self.state_of_fetch(folder, data[uid], f"BODY[{LIST_FIELDS}]".encode())
                item = {"id": state["message_id"], "ref": f"{self.ctx.instance}:{state['message_id']}",
                        **{k: v for k, v in state.items() if k != "message_id"},
                        "unread": "\\Seen" not in state["flags"]}
                if is_bulk(data[uid][f"BODY[{LIST_FIELDS}]".encode()]):
                    item["bulk"] = True
                if not self.list_extras(item, state) and data[uid].get(b"RFC822.SIZE", 0) <= SNIPPET_FETCH_MAX:
                    unarchived.append(uid)
                items.append(item)
            if unarchived:  # small messages the archive doesn't have yet: one download for all of them
                bodies = client.fetch(unarchived, ["BODY.PEEK[]"])
                for item, uid in zip(items, uids):
                    if uid in unarchived and b"BODY[]" in bodies.get(uid, {}):
                        message = email.message_from_bytes(bodies[uid][b"BODY[]"], policy=email.policy.default)
                        item["attachments"] = [name for _, name, _, _ in attachment_parts(message)]
                        if not self.from_security_sender(item):
                            with_snippet(item, body_text(message)[0])
        return items

    def bulk_or_not(self, client, uids: list[int], bulk: bool, limit: int) -> list[int]:
        """The newest `limit` of these that are (bulk true) or aren't mass mail, by the same headers as a row's
        `bulk` (is_bulk). Only the headers are fetched, of at most BULK_SCAN messages: a header search on the
        server (HEADER List-Id "") isn't supported alike everywhere (Gmail and Exchange are picky about it)."""
        out: list[int] = []
        field = f"BODY[{LIST_FIELDS}]".encode()
        for start in range(0, min(len(uids), BULK_SCAN), BULK_STEP):
            step = uids[start:min(start + BULK_STEP, BULK_SCAN)]
            heads = client.fetch(step, [f"BODY.PEEK[{LIST_FIELDS}]"])
            out += [uid for uid in step if is_bulk(heads.get(uid, {}).get(field, b"")) == bulk]
            if len(out) >= limit:
                break
        return out[:limit]

    def list_extras(self, item: dict, state: dict) -> bool:
        """A list row's attachment names and the start of its text, from the archive when it has the
        message (no download). False when it doesn't."""
        row = self.archive.message(state["message_id"]) if self.archive.on else None
        if row is None:
            return False
        item["attachments"] = [a["name"] for a in json.loads(row["attachments"] or "[]")]
        if not row["security"]:
            found = self.archive.query("SELECT text FROM texts WHERE mid=? AND part=0", (row["mid"],))
            with_snippet(item, found[0]["text"] if found else "")
        return True

    def read_recent(self, params):
        """The inbox's newest messages from `since` on, newest first: who, when, the subject (doorman recent).
        IMAP's SINCE knows only days, in the server's own zone: ask from the day before, then compare times."""
        since = since_param(params)
        asked = {"limit": params.get("limit", 20)}
        if since:
            asked["since"] = (since.date() - timedelta(days=1)).isoformat()
        out = []
        for m in self.read_search(asked):
            sent = iso_moment(m.get("date"))
            if since and sent and sent < since:
                continue
            out.append({"ref": m["ref"], "id": m["id"], "sent": m.get("date"), "folder": m.get("folder"),
                        "from": m.get("from") or [], "subject": m.get("subject"),
                        "unread": m.get("unread"),
                        **{k: m[k] for k in ("snippet", "attachments", "bulk", "_guard_text") if k in m}})
        return out

    def fetch_message(self, message_id: str):
        """(state, parsed message) for one Message-ID: from the archive's original (archive: full), else from
        the server. GoneFromServer when only the archive's text is left."""
        if self.archive.mode == "full":
            raw = self.archive.original(message_id)
            row = self.archive.message(message_id) if raw is not None else None
            if row is not None:
                return self.archive.state_of(row), email.message_from_bytes(raw, policy=email.policy.default)
        with self.imap() as client:
            found = self.locate(client, message_id)
            if not found:
                if self.archive.on and self.archive.message(message_id) is not None:
                    raise GoneFromServer(message_id)
                raise NoSuchMessage(f"no message {message_id}")
            folder, uid = found
            state = self.state(client, folder, uid)
            raw = client.fetch([uid], ["BODY.PEEK[]"])[uid][b"BODY[]"]
        return state, email.message_from_bytes(raw, policy=email.policy.default)

    def from_security_sender(self, state: dict) -> bool:
        return any(self.ctx.redactor.is_security_sender(a) for a in state["from"])

    def read_message(self, params):
        try:
            state, message = self.fetch_message(params["id"])
        except GoneFromServer:
            return self.archived_message(params["id"], params)
        removed = None
        if self.from_security_sender(state):
            body = "[redacted: message from a security sender]"
        else:
            part = message.get_body(preferencelist=("plain", "html"))
            body = "" if part is None else part.get_content()
            if part is not None and part.get_content_type() == "text/html":
                body, report = html_to_text(body)
                removed = describe(report)
        mid = state["message_id"]
        attachments = [{"part": n, "ref": f"{self.ctx.instance}:{mid}#{n}", "name": name, "type": ctype,
                        "size": len(content)} for n, name, ctype, content in attachment_parts(message)]
        out = {"id": mid, "ref": f"{self.ctx.instance}:{mid}", **state,
               "cc": [a for _, a in getaddresses([str(message.get("Cc", ""))]) if a],
               "body": body, "attachments": attachments}
        in_reply_to = str(message.get("In-Reply-To", "")).strip().strip("<>").strip()
        if in_reply_to:
            out["in_reply_to"] = in_reply_to  # the thread: the message this one answers
        if removed:
            out["sanitized"] = removed
        self._archive_note(out)
        return _cut_body(out, params)

    def _archive_note(self, out: dict) -> None:
        row = self.archive.message(out["id"]) if self.archive.on else None
        if row and row["deleted_on_server"]:
            out["deleted_on_server"] = row["deleted_on_server"]
            out["note"] = "deleted on the server; this is the original Doorman archived"

    def archived_message(self, message_id: str, params: dict | None = None) -> dict:
        """A message gone from the server, from the archive's text (archive: index keeps no originals)."""
        row = self.archive.message(message_id)
        texts = self.archive.texts(message_id)
        state = self.archive.state_of(row)
        mid = row["mid"]
        body = "[redacted: message from a security sender]" if self.from_security_sender(state) \
            else (texts.get(0) or {}).get("text") or ""
        attachments = [{"part": a["part"], "ref": f"{self.ctx.instance}:{mid}#{a['part']}", "name": a["name"],
                        "type": a["type"], "size": a["size"]} for a in json.loads(row["attachments"] or "[]")]
        out = {"id": mid, "ref": f"{self.ctx.instance}:{mid}", **state,
               "cc": json.loads(row["cc"] or "[]"), "body": body, "attachments": attachments,
               "deleted_on_server": row["deleted_on_server"],
               "note": "gone from the server; this is the text Doorman archived (archive: index keeps no "
                       "originals, so attachments can be read as text but not sent on)"}
        if (texts.get(0) or {}).get("sanitized"):
            out["sanitized"] = texts[0]["sanitized"]
        return _cut_body(out, params)

    def archived_attachment(self, message_id: str, n: int, limit: int) -> dict:
        row = self.archive.message(message_id)
        part = self.archive.texts(message_id).get(n)
        if part is None or n == 0:
            raise PluginError(f"message {message_id} has no attachment #{n}")
        state = self.archive.state_of(row)
        # a PDF no hidden-text check has cleared yet gives no text, as a live read never gives it unchecked
        # (the same rule as the search feed's `unchecked`, archive.feed_item)
        unchecked = archive_unchecked(part, self.archive.checking())
        text = "[redacted: attachment from a security sender]" if self.from_security_sender(state) \
            else "" if unchecked else part["text"] or ""
        mid = row["mid"]
        out = {"id": mid, "part": n, "ref": f"{self.ctx.instance}:{mid}#{n}", "name": part["name"],
               "type": part["type"], "size": part["size"], "from": state["from"], "text": text[:limit],
               "truncated": len(text) > limit, "deleted_on_server": row["deleted_on_server"]}
        if part["pages"]:
            out["pages"] = part["pages"]
        if json.loads(part["ocr_pages"] or "[]"):
            out["ocr_pages"] = json.loads(part["ocr_pages"])
        if part["hidden"]:
            out["hidden_text"] = json.loads(part["hidden"])  # the guard holds this back (engine._scan_item)
        if part["sanitized"]:
            out["sanitized"] = part["sanitized"]
        notes = ["gone from the server; this is the text Doorman archived"]
        if part["note"]:
            notes.append(part["note"])
        if unchecked:
            notes.append("Doorman hasn't checked this PDF for hidden text yet, so its text isn't given; ask again later")
        elif part["state"] in ("ocr", "retry"):
            notes.append("its scanned pages hadn't been read yet")
        out["note"] = "; ".join(notes)
        return out

    def read_attachment(self, params):
        """The text of one attachment: PDF (text layer, OCR for scanned pages), images (OCR), Word,
        OpenDocument, text, HTML. Doorman's extractor reads it, in a process of its own."""
        n = int(params["part"])
        try:
            state, message = self.fetch_message(params["id"])
        except GoneFromServer:
            return self.archived_attachment(params["id"], n, int(params.get("max_chars", 20000)))
        found = next((p for p in attachment_parts(message) if p[0] == n), None)
        if found is None:
            raise PluginError(f"message {params['id']} has no attachment #{n}")
        _, name, ctype, content = found
        limit = int(params.get("max_chars", 20000))
        if self.from_security_sender(state):
            found = {"text": "[redacted: attachment from a security sender]"}
        else:
            found = self.ctx.extract_text(name, content, ctype, limit=limit + 1,
                                          check_pdf=bool(self.config.get("check_hidden_text", True)))
        text = found.get("text") or ""
        report = dict(found.get("report") or {})
        mid = state["message_id"]
        out = {"id": mid, "part": n, "ref": f"{self.ctx.instance}:{mid}#{n}", "name": name, "type": ctype,
               "size": len(content), "from": state["from"], "text": text[:limit], "truncated": len(text) > limit}
        for key in ("pages", "ocr_pages"):
            if found.get(key):
                out[key] = found[key]
        hidden = report.pop("hidden_text", None)
        if hidden:
            out["hidden_text"] = hidden  # the guard holds this back for the owner (engine._scan_item)
        if describe(report):
            out["sanitized"] = describe(report)
        if found.get("note"):
            out["note"] = found["note"]
        elif not text.strip():
            out["note"] = "no text found in this attachment (an archive, or a format Doorman can't read)"
        return out

    def open_ref(self, path):
        """mail:<message-id>#<n> returns attachment n (numbered from 1, as read lists them)."""
        message_id, sep, number = path.rpartition("#")
        if not sep or not message_id or not number.isdigit():
            raise PluginError("attachment references look like mail:<message-id>#<n>, as read lists them")
        try:
            _, message = self.fetch_message(message_id)
        except GoneFromServer:
            raise PluginError(f"message {message_id} is gone from the server, and this mailbox's archive keeps "
                              "only its text (archive: index), so its attachments can't be sent on") from None
        for n, name, _, content in attachment_parts(message):
            if n == int(number):
                return name, content
        raise PluginError(f"message {message_id} has no attachment #{number}")

    # triggers

    def poll_events(self, cursor):
        state = json.loads(cursor) if cursor else None
        with self.imap() as client:
            info = client.select_folder("INBOX", readonly=True)
            validity = int(info[b"UIDVALIDITY"])
            if state is None or state.get("uidvalidity") != validity:
                # first poll, or the folder was rebuilt: start from what's there now
                if info.get(b"UIDNEXT"):
                    top = int(info[b"UIDNEXT"]) - 1
                else:
                    uids = client.search(["ALL"])
                    top = max(uids) if uids else 0
                return [], json.dumps({"uidvalidity": validity, "last_uid": top})
            # only mail after the cursor ("n:*" also matches the highest UID, hence the filter)
            uids = sorted(u for u in client.search(["UID", f"{state['last_uid'] + 1}:*"]) if u > state["last_uid"])
            top = max([state["last_uid"], *uids])
            events = []
            for uid in uids:
                item = self.state(client, "INBOX", uid)
                events.append({"type": "new_mail", "ref": f"{self.ctx.instance}:{item['message_id']}",
                               "id": item["message_id"], "from": (item["from"] or [""])[0],
                               "subject": item["subject"]})
        return events, json.dumps({"uidvalidity": validity, "last_uid": top})


def _cut_body(out: dict, params: dict | None) -> dict:
    """The first max_chars (20000) characters of the body. A longer one says so (truncated, chars: its
    whole length), so the agent can ask for more; one mail can't keep the guard busy for minutes."""
    limit = int((params or {}).get("max_chars", READ_CHARS))
    body = out.get("body") or ""
    if len(body) <= limit:
        return out
    return {**out, "body": body[:limit], "truncated": True, "chars": len(body)}
