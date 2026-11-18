"""Checks an irreversible action before it goes to the owner for approval: what looks off, or deny."""

import fnmatch
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from . import clock
from .plugin_api import Denied
from .util import extract_destinations, get_path, loads, normalize

log = logging.getLogger("doorman.policy")

COUNTED_STATES = ("waiting_approval", "approved", "running", "sending", "unknown", "done")  # what counts toward the budget
# Who the owner already knows counts as theirs in the recipient check, unless doorman.yaml's `trust:` or the
# switches on More → Trust list say otherwise: people in their own address books, and destinations they
# wrote to before (sends they approved, mail in their Sent folder). Both on: the warning is for strangers.
KNOWN_DEFAULTS = {"contacts": True, "written_before": True}


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    data: dict = field(default_factory=dict)


class Policy:
    def __init__(self, config, db, provenance, reviewer, registry=None):
        self.config = config
        self.db = db
        self.provenance = provenance
        self.reviewer = reviewer
        self.registry = registry  # for the plugins that know the owner's contacts and sent mail

    # trust

    def trusted_entry(self, kind: str, value: str) -> dict | None:
        for row in self.db.all("SELECT kind, value, label FROM trust WHERE kind=?", (kind,)):
            if value == row["value"] or fnmatch.fnmatch(value, row["value"]):
                return row
        return None

    def owner_answers(self, key_id: int | None, task: dict | None) -> dict[str, str]:
        """Destinations the owner typed into answers to this key's questions (doorman ask-owner,
        owner_questions.py), each with where it came from. An answer is the owner's own text, like the task's,
        so it counts the same way and for the same scope: the task the question was asked for, or, asked
        outside a task, the key's actions outside one. A tapped option doesn't count: its text is the
        agent's, and a tap on "Yes, send it to x@y" is not the owner writing x@y."""
        if key_id is None:
            return {}
        found: dict[str, str] = {}
        rows = self.db.all("SELECT id, options, answer FROM owner_questions WHERE key_id=? AND status='answered' "
                           "AND task_id IS ? ORDER BY id", (key_id, task["id"] if task else None))
        for row in rows:
            if not row["answer"] or row["answer"] in loads(row["options"], []):
                continue
            for _, value in extract_destinations(row["answer"]):
                found.setdefault(value, f"your answer to question #{row['id']}")
        return found

    def destination_source(self, kind: str, value: str, task: dict | None, context_trusted: set[str],
                           answers: dict[str, str] | None = None) -> str | None:
        """Why this destination counts as the owner's, in a few words the approval shows, or None. What
        only the address book or earlier sends know comes after it (known_destinations, in evaluate)."""
        if value in context_trusted:
            return "already in this conversation"  # the thread answered, the chat written in, the organizer
        if task and task.get("trusted"):
            task_values = {v for _, v in extract_destinations(task["text"])}
            if value in task_values:
                return f"task #{task['id']}"
        if answers and value in answers:
            return answers[value]
        entry = self.trusted_entry(kind, value)
        if entry:
            return f"trust list ({entry['label'] or entry['kind']})"
        return None

    # known: in the owner's contacts, or written to before

    def known_settings(self) -> dict:
        """Whether contacts and earlier sends count as the owner's. A key doorman.yaml's `trust:` sets is
        fixed there (and read-only in the app); otherwise the app's switch decides, else it is on."""
        block = dict(self.config.get("trust") or {})
        out = {}
        for name, default in KNOWN_DEFAULTS.items():
            if name in block:
                out[name] = bool(block[name])
            else:
                stored = self.db.get_setting(f"trust_{name}")
                out[name] = default if stored is None else stored == "1"
        return {**out, "locked": [k for k in KNOWN_DEFAULTS if k in block]}

    def save_known_settings(self, changes: dict) -> tuple[dict, dict]:
        """(before, after) for the app's switches. A key doorman.yaml sets can't be changed here."""
        before = self.known_settings()
        for name, value in changes.items():
            if name not in KNOWN_DEFAULTS:
                raise Denied(f"unknown setting {name}; there are {', '.join(KNOWN_DEFAULTS)}", "invalid")
            if not isinstance(value, bool):
                raise Denied(f"{name} is true or false", "invalid")
            if name in before["locked"]:
                raise Denied(f"trust.{name} is set in doorman.yaml; change it there", "invalid")
        for name, value in changes.items():
            self.db.set_setting(f"trust_{name}", "1" if value else "0")
        return before, self.known_settings()

    def known_loosens(self, changes: dict) -> bool:
        """Switching one on lets more sends through without the warning: that takes a fresh passkey check."""
        now = self.known_settings()
        return any(changes.get(name) is True and not now[name] for name in KNOWN_DEFAULTS)

    def known_destinations(self, destinations: list[tuple[str, str]]) -> dict[tuple[str, str], str]:
        """The destinations of a send the owner already knows, each with why: in one of their own address
        books ("in your contacts (Anna de Vries)") or written to before ("you wrote to them before (3 Nov)").
        A bank account never counts this way: a payment's IBAN is the owner's to trust."""
        wanted = list(dict.fromkeys((k, v) for k, v in destinations if k != "iban"))
        settings = self.known_settings()
        found: dict[tuple[str, str], str] = {}
        if not wanted or not (settings["contacts"] or settings["written_before"]):
            return found
        if settings["written_before"]:
            found.update(self.approved_before(wanted))
        rest = [d for d in wanted if d not in found]
        answers = self._ask_plugins(rest, settings) if rest else {}
        for pair, name in answers.get("contacts", {}).items():
            found.setdefault(pair, f"in your contacts ({name})" if name else "in your contacts")
        for pair, when in answers.get("sent_mail", {}).items():
            found.setdefault(pair, f"you wrote to them before ({self._day(when)})")
        return found

    def approved_before(self, wanted: list[tuple[str, str]]) -> dict[tuple[str, str], str]:
        """Destinations of earlier sends the owner approved and that went out. Only the owner's decision
        counts: a send that ran without asking (a tool set to Auto, an MCP tool on Always allow) was the
        agent's choice, and counting it would let an agent make an address known by sending to it once."""
        found: dict[tuple[str, str], str] = {}
        for kind, value in wanted:
            like = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            rows = self.db.all(
                "SELECT j.checks, a.decided FROM journal j JOIN approvals a ON a.status='approved' "
                "AND EXISTS (SELECT 1 FROM json_each(a.journal_ids) WHERE json_each.value=j.id) "
                "WHERE j.kind='action' AND j.decision='approval' AND j.status='done' AND j.tier='irreversible' "
                "AND j.checks LIKE ? ESCAPE '\\' ORDER BY a.decided DESC LIMIT 20", (f"%{like}%",))
            for row in rows:
                checks = loads(row["checks"], {}) or {}
                # `targets` ([kind, value]) since 7 Nov; older entries have only the values
                targets = [tuple(t) for t in checks.get("targets") or []]
                if (kind, value) in targets or (not targets and value in (checks.get("destinations") or [])):
                    found[(kind, value)] = f"you wrote to them before ({self._day(row['decided'])})"
                    break
        return found

    def _ask_plugins(self, wanted: list[tuple[str, str]], settings: dict) -> dict[str, dict]:
        """{"contacts": {(kind, value): name}, "sent_mail": {(kind, value): date}} from the switched-on
        plugins whose manifest says `known_recipients:` (plugin_api.BasePlugin.known_recipients). A plugin
        that fails or is slow knows nobody: the send keeps its warning."""
        out: dict[str, dict] = {"contacts": {}, "sent_mail": {}}
        if self.registry is None:
            return out
        setting = {"contacts": "contacts", "sent_mail": "written_before"}
        for instance in self.registry.configured():
            if self.registry.is_mcp(instance):
                continue
            try:
                role = self.registry.manifest(instance).get("known_recipients")
                if role not in setting or not settings[setting[role]] or not self.registry.state(instance)["enabled"]:
                    continue
                answer = self.registry.instance(instance).known_recipients([list(d) for d in wanted]) or {}
            except Exception as exc:  # noqa: BLE001 - nobody is known from this plugin, the others stand
                log.warning("known_recipients of %s failed: %s", instance, exc)
                continue
            for kind, value in wanted:
                hit = answer.get(value) if isinstance(answer, dict) else None
                if not isinstance(hit, dict) or (kind, value) in out[role]:
                    continue
                if role == "contacts":
                    out[role][(kind, value)] = " ".join(str(hit.get("name") or "").split())[:80]
                else:
                    when = self._untouched_sent(instance, [m for m in hit.get("messages") or [] if isinstance(m, dict)])
                    if when:
                        out[role][(kind, value)] = when
        return out

    def _untouched_sent(self, instance: str, messages: list[dict]) -> str | None:
        """The date of the newest of these mails in the owner's Sent folder that Doorman had no hand in. A
        message an agent drafted, moved or labelled isn't the owner's own writing (an agent could move a
        forged mail into Sent), and one Doorman sent counts through approved_before or not at all."""
        for message in sorted(messages, key=lambda m: str(m.get("date") or ""), reverse=True):
            mid = str(message.get("id") or "")
            if mid and not self.db.one("SELECT 1 AS x FROM journal WHERE plugin=? AND object_ref=? LIMIT 1",
                                       (instance, mid)):
                return str(message.get("date") or "")
        return None

    def _day(self, when: str | None) -> str:
        """3 Nov, in the owner's time zone; with the year when it isn't this one."""
        try:
            moment = datetime.fromisoformat(str(when).replace("Z", "+00:00"))
            zone = ZoneInfo(self.config.get("timezone") or "UTC")
        except (TypeError, ValueError, KeyError):
            return "earlier"
        local = moment.astimezone(zone) if moment.tzinfo else moment
        day = f"{local.day} {local:%b}"
        return day if local.year == clock.now().astimezone(zone).year else f"{day} {local.year}"

    # checks

    def _month_payments(self, amount_field: str) -> float:
        month = clock.now().strftime("%Y-%m")
        rows = self.db.all(
            f"SELECT args FROM journal WHERE kind='action' AND tier='payment' AND ts LIKE ? "
            f"AND status IN ({','.join('?' * len(COUNTED_STATES))})",
            (month + "%", *COUNTED_STATES),
        )
        return sum(float(get_path(loads(row["args"], {}), amount_field) or 0) for row in rows)

    def evaluate(self, session: dict, task: dict | None, full_name: str, tool, args: dict, tier: str) -> dict:
        """Every irreversible action needs the owner's approval; the checks that fail are shown on it as
        warnings. Raises Denied if the action may not even be asked for."""
        checks: list[Check] = []
        destinations = tool.destinations(args)
        context_trusted = {normalize("email", v) for v in tool.trusted_destinations(args)}
        # a reply-all's other recipients come from the mail it answers, which the agent may never have read
        origins = {normalize("email", k): v for k, v in (tool.destination_origins(args) or {}).items()}

        answers = self.owner_answers(session.get("key_id"), task) if destinations else {}
        sources = {(kind, value): self.destination_source(kind, value, task, context_trusted, answers)
                   for kind, value in destinations}
        # only for what nothing above vouches for: the address book and the archive cost a plugin call
        unknown = [d for d, source in sources.items() if source is None]
        if unknown:
            known = self.known_destinations(unknown)
            sources.update({d: known[d] for d in unknown if d in known})
        untrusted, vouched = [], []
        for kind, value in destinations:
            source = sources[(kind, value)]
            if source is None:
                untrusted.append({"kind": kind, "value": value,
                                  "first_seen": origins.get(value) or self.provenance.origin_of(value)})
            else:
                vouched.append({"kind": kind, "value": value, "source": source})

        def named(d: dict) -> str:
            return d["value"] + (" (from the mail being answered)" if (d["first_seen"] or {}).get("answered") else "")

        if destinations:
            checks.append(Check(
                "trusted_destinations", not untrusted,
                "all destinations come from the owner" if not untrusted
                else "new recipient, not from the owner: " + ", ".join(named(d) for d in untrusted),
                {"untrusted": untrusted, "known": vouched},  # known: why each other one counts as the owner's
            ))

        key = self.db.one("SELECT third_party_at, private_at FROM agent_keys WHERE id=?", (session["key_id"],)) or {}
        window = clock.iso(clock.now() - timedelta(hours=float(self.config.get("taint_window_hours", 12))))
        third_party = bool(session.get("read_third_party")) or (key.get("third_party_at") or "") >= window
        private = bool(session.get("read_private")) or (key.get("private_at") or "") >= window
        tainted = third_party and private
        checks.append(Check(
            "clean_session", not tainted,
            "session is clean" if not tainted
            else "this agent read outside content and private data before writing this",
        ))

        if tier == "payment":
            amount_field = tool.spec.get("amount_field", "amount")
            amount = float(get_path(args, amount_field) or 0)
            budget = float(self.config.get("payments", {}).get("monthly_budget", 0))
            spent = self._month_payments(amount_field)
            if spent + amount > budget:
                raise Denied(f"payment of {amount:.2f} would exceed the monthly budget "
                             f"({spent:.2f} of {budget:.2f} used)", "budget")
            checks.append(Check("payment", True, f"{spent + amount:.2f} of {budget:.2f} budget this month "
                                                 f"with this payment"))

        if self.reviewer.enabled:
            if task and task.get("trusted"):
                ok, reason = self.reviewer.review(task["text"], tool.describe(args), args)
            else:
                ok, reason = False, "no task from the owner to check this action against"
            checks.append(Check("reviewer", ok, reason))

        return {
            "checks": [asdict(c) for c in checks],
            "destinations": [value for _, value in destinations],
            "targets": [[kind, value] for kind, value in destinations],  # what approved_before matches
        }
