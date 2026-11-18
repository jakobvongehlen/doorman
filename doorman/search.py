"""One search over everything the plugins feed into the search index, as an agent may see it.

The index itself is library.py: what each plugin feeds, words, stems and vectors. This is what stands
between it and an agent: which sources a key may search (those whose gating read is on), feeding a source
again when its settings changed, and every hit screened as the answer of its own source's read would be
(the guard, the redactor, pseudonyms, taint, the read log).
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from . import textsearch
from .guard import REASON as GUARD_REASON
from .guard import GuardBusy, held_row
from .library import FEED_EVERY, KINDS
from .plugin_api import Denied
from .util import canonical, sha256_hex

log = logging.getLogger("doorman.search")


class Search:
    def __init__(self, engine):
        self.engine = engine
        self.db = engine.db
        self._refeeds: set[str] = set()  # sources being fed again after a settings change (refeed)
        self._refeeds_lock = threading.Lock()

    def sources(self, session: dict, role: str | None = None) -> list[dict]:
        """Plugins that feed the search index (`index:` in their manifest), switched on, with the read that
        gates their text on: {name, type, read, trust, raw, kinds, skip_kinds, parts, part_read,
        attachment_refs}. With role actor and the reader/actor split on, those whose text is raw are left out,
        as the actor couldn't read it.

        `index: {needs: {<kind>: <read>, attachment: <read>}}` names the reads that return a kind's items or an
        attachment's text (caldav.tasks, mail.attachment): while one is off (or raw for the actor), the kind
        is left out (`skip_kinds`), or the source's parts besides part 0 are (`parts` False), as if the agent
        had asked that read."""
        split = role == "actor" and self.engine.config["reader_actor_split"]
        out = []
        for plugin in self.engine.registry.list():
            if not plugin["enabled"]:
                continue
            manifest = self.engine.registry.manifest(plugin["name"])
            spec = manifest.get("index")
            if not isinstance(spec, dict) or not spec.get("read") or spec["read"] in plugin["disabled_tools"]:
                continue
            reads = {r["name"].split(".", 1)[1]: r for r in plugin["reads"]}
            read = reads.get(spec["read"])
            if read is None or (split and read["raw"]):
                continue

            def on(short: Any) -> bool:
                names = short if isinstance(short, list) else [short]
                return all(n in reads and n not in plugin["disabled_tools"] and not (split and reads[n]["raw"])
                           for n in names)

            needs = spec.get("needs") if isinstance(spec.get("needs"), dict) else {}
            attachment = needs.get("attachment")
            out.append({"name": plugin["name"], "type": plugin["type"], "read": read["name"], "trust": read["trust"],
                        "raw": read["raw"], "private": read["private"], "kinds": list(spec.get("kinds") or []),
                        "skip_kinds": sorted(k for k, short in needs.items() if k != "attachment" and not on(short)),
                        "parts": attachment is None or on(attachment),
                        "part_read": f"{plugin['name']}.{attachment}" if isinstance(attachment, str) else read["name"],
                        "attachment_refs": bool((manifest.get("item") or {}).get("attachments"))})
        return out

    def feed_settings(self, instance: str) -> str:
        """What a source's items depend on besides the plugin's data, as a hash: its settings (which calendars,
        which task lists, the hidden-text check) and the security senders. When it changes, the search index
        holds the source's items back until it has fed them again (library.settle). `index: {settings}` names
        the settings that change what the plugin feeds (the mail archive's: archive, check_hidden_text);
        without it, every setting does."""
        block = self.engine.registry.configured().get(instance) or {}
        config = block.get("config") or {}
        spec = self.engine.registry.manifest(instance).get("index") if block else None
        if isinstance(spec, dict) and isinstance(spec.get("settings"), list):
            config = {k: config.get(k) for k in spec["settings"]}
        # `index: {security_senders: false}`: what it feeds doesn't depend on them (only mail's does), so
        # editing that list doesn't send all its items again
        senders = [] if isinstance(spec, dict) and spec.get("security_senders") is False \
            else sorted(getattr(self.engine.redactor, "security_senders", []))
        return sha256_hex(canonical([config, senders]))[:32]

    def settle(self, instance: str) -> bool:
        """A source whose settings changed since its items were fed: they leave search at once, and it is fed
        again from the start right away, to the end (refeed). Search and every pull look, so a change
        made anywhere (the owner app, an agent's doorman.configure, doorman.yaml, a revert) counts."""
        changed = self.engine.library.settle(instance, self.feed_settings(instance))
        if changed:
            self.refeed(instance)
        return changed

    def refeed(self, instance: str) -> None:
        """In the background, feed a source whose settings changed until that pass is through, instead of
        one slice now and the rest at its next pull (every 30 minutes for a calendar): until then search
        shows none of its items. One at a time per source; off with search_index.pull_after_writes."""
        if not (self.engine.config.get("search_index") or {}).get("pull_after_writes", True):
            return
        with self._refeeds_lock:
            if instance in self._refeeds:
                return
            self._refeeds.add(instance)
        threading.Thread(target=self._refeed, args=(instance,), daemon=True, name=f"refeed-{instance}").start()

    def _refeed(self, instance: str) -> None:
        try:
            while self.engine.library.refeeding(instance):
                out = self.pull(instance, 30)
                if out.get("busy"):  # behind the pull that runs now (search's, the worker's)
                    with self.engine.library.pulling[instance]:
                        pass
                elif out.get("error") or out.get("skipped"):
                    return  # the scheduled pulls try again; its items stay out of search until it works
        except Exception:  # noqa: BLE001 - the scheduled pulls try again
            log.exception("feeding %s again after its settings changed", instance)
        finally:
            with self._refeeds_lock:
                self._refeeds.discard(instance)

    def _refeed_now(self, names: list[str], seconds: float) -> None:
        """Search right after a settings change: feed those sources again here, behind any pull already
        running, until their pass is through or `seconds` are spent, so the search finds what it found before
        (minus what the new settings take out). A feed that fails, or one not through in time, leaves its
        items out, with the note under `sources`."""
        deadline = time.monotonic() + seconds
        for name in names:
            lock = self.engine.library.pulling.setdefault(name, threading.Lock())
            while self.engine.library.refeeding(name):
                left = deadline - time.monotonic()
                if left <= 0:
                    return
                if lock.locked():  # another pull feeds it now: wait for that one's slice
                    if lock.acquire(timeout=left):
                        lock.release()
                    continue
                out = self.pull(name, left)
                if out.get("error") or out.get("skipped"):
                    break

    def query(self, session: dict, key: dict, params: dict, meaning: bool = True) -> dict:
        """One query over everything the plugins feed into the search index (library.py): mail archives,
        files, notes, calendars, chats. Best first, or the newest first without words or with sort=date. One
        document found in several places (a PDF attached to a mail and saved in the files) comes once, with
        the other places under `also`.

        Each hit is the agent's as if it had read the item from its plugin: only sources that are switched on,
        whose gating read (`index: {read}`) is on and that the actor rule lets through, and of those only the
        kinds and attachments whose own reads are on (`index: {needs}`); each source's hits go through the
        guard, the redactor, pseudonyms, taint and the read log as that read's answer would. A hit whose
        passage comes from an attachment is that attachment's (its ref is <item>#<n> where the plugin has
        attachment refs): the guard holds it under that ref, a hold on that ref holds it, and the attachment's
        name is its header for pseudonyms, as reading the attachment would be. Words and filters the
        pseudonyms hide aren't searched, and a hit found only by text hidden from the agent is left out:
        what's hidden can't be found. meaning=False: by words only (any_word's single words)."""
        self.engine._guard(session, None, write=False)
        self.engine._validate(SEARCH_SCHEMA, params, "parameters")
        if not any(params.get(k) not in (None, "", False, []) for k in SEARCH_SCHEMA["properties"] if k not in NOT_FILTERS):
            raise Denied("give a query or at least one filter (kind, from, to, in, since, until, has_attachment)",
                         "invalid")
        limit = int(params.get("limit", SEARCH_LIMIT))
        allowed = {s["name"]: s for s in self.sources(session, key["role"])}
        wanted = params.get("sources")
        if wanted:
            unknown = sorted(set(wanted) - set(allowed))
            if unknown:
                raise Denied(f"not searchable here: {', '.join(unknown)} (searchable: {', '.join(sorted(allowed)) or 'none'})",
                             "invalid")
            allowed = {n: s for n, s in allowed.items() if n in set(wanted)}
        for name in allowed:  # settings changed since its items were fed (narrower calendars): fed again first
            self.settle(name)
        self._refeed_now([name for name in allowed if self.engine.library.refeeding(name)], SETTLE_WAIT)
        types = sorted({s["type"] for s in allowed.values()})
        report: dict[str, dict] = {name: {"count": 0} for name in allowed}
        asked, notes = self._visible_query(params, types)
        if asked is None:  # all its words, or a filter, would look for what's hidden from the agent
            return {"results": [], "sources": report, "more": False, "note": "; ".join(notes)}
        scope = {n: {"skip_kinds": s["skip_kinds"], "parts": s["parts"]} for n, s in allowed.items()}
        found = self.engine.library.search(
            asked, scope, limit, allow=lambda word: not self.engine.pseudonyms.hidden_word(word, types),
            hide_part=lambda source, name: self.engine.pseudonyms.hides_item({"name": name}, allowed[source]["type"]),
            meaning=meaning)
        hits = [_hit_for_agent(h, allowed[h["source"]]) for h in found["hits"]]
        # a hit found by words or by a sender is left out when what found it is hidden from the agent: the
        # pseudonyms hide it whole or hide the attachment its passage is from (before copies are folded, so
        # a copy the agent may see takes its place)
        if asked.get("query") or asked.get("from") or asked.get("to"):
            hits = [h for h in hits if not self._hidden_hit(h, allowed[h["source"]]["type"])]
        hits = once(hits)
        more = len(hits) > limit
        hits = hits[:limit]
        self._hold_held_messages(hits)
        words = [textsearch.fold(t) for t, _ in textsearch.terms_of(asked.get("query") or "")]
        # every hit, and every other place of one (`also`: a title from another source), is screened as
        # an answer of its own source's read; (hit index, place index or None) -> what the agent gets
        shown: dict[tuple[int, int | None], Any] = {}
        for name, source in allowed.items():
            mine = [((i, None), h) for i, h in enumerate(hits) if h["source"] == name]
            mine += [((i, j), place) for i, h in enumerate(hits) for j, place in enumerate(h.get("also") or [])
                     if place.get("source") == name]
            if not mine:
                continue
            read = self.engine.registry.find_read(source["read"])[2]
            plain = [{k: v for k, v in h.items() if k != "also"} for _, h in mine]
            try:
                data, trust, unscanned = self.engine._screen(session, source["read"], read, params, plain)
            except GuardBusy as busy:  # its hits stay out until scanned; the other sources' come back now
                self.engine.reads.add(key, session, f"search:{name}", params, status="denied", error=busy.reason)
                report[name] = {"count": 0, "busy": busy.reason, "retry_after": busy.retry_after}
                notes.append(f"{name}: still being scanned for prompt injection; search again in about "
                             f"{busy.retry_after} s for its hits")
                continue
            before = [_for_hiding(item) for item in data]
            data, hidden = self.engine.pseudonyms.hide(before, source["type"])
            data = [_from_hiding(item) for item in data]
            kept, hidden_kept = [], []
            for n, ((where, raw), item) in enumerate(zip(mine, data)):
                if where[1] is None and _lost_its_words(raw, item, words):
                    continue
                if n in hidden:
                    hidden_kept.append(len(kept))
                kept.append((where, item))
            self.engine.reads.add(key, session, f"search:{name}", params, [item for _, item in kept], trust=trust,
                           hidden=hidden_kept, status="unscanned" if unscanned else "ok", error=unscanned)
            for where, item in kept:
                shown[where] = item
            count = sum(1 for (_, j), _ in kept if j is None)
            report[name] = {"count": count, **({"unscanned": unscanned} if unscanned else {})}
        results, near = [], 0
        for i, hit in enumerate(hits):
            item = shown.get((i, None))
            if item is None:
                continue
            near += bool(hit.get("_near"))  # the closest by meaning when little stands out: always the last
            places = [shown[(i, j)] for j in range(len(hit.get("also") or [])) if (i, j) in shown]
            if places and isinstance(item, dict) and not item.get("held"):
                item = {**item, "also": places}
            results.append(_without_internal(item))
        for name in allowed:
            state = self.engine.library.feed_state(name)
            if state.get("error"):
                report[name]["feed_error"] = state["error"]
            if not state.get("pulled"):
                report[name]["note"] = "not in the index yet: its first feed hasn't run"
            elif self.engine.library.refeeding(name):
                report[name]["note"] = "its settings changed: its items come back as it feeds them again"
        close = _visible_close(found["close"], results)
        notes += found["notes"] + ([textsearch.close_note(close)] if close else [])
        out = {"results": results, "sources": report, "more": more, "_near": near}
        if notes:
            out["note"] = "; ".join(dict.fromkeys(notes))
        return out

    def _visible_query(self, params: dict, types: list[str]) -> tuple[dict | None, list[str]]:
        """The search's words and filters as they may run: a word the pseudonyms would hide isn't searched (so
        a hidden word finds nothing, as in records), and a sender, recipient or place filter on a hidden word
        finds nothing at all. (params to search with, or None for nothing; notes)."""
        notes: list[str] = []
        for name in ("from", "to", "in"):
            if self.engine.pseudonyms.hidden_word(params.get(name), types):
                return None, [f"{name}: '{params[name]}' is hidden from you (privacy placeholders), so nothing is "
                              "searched by it"]
        terms = textsearch.terms_of(params.get("query") or "")
        if not terms:
            return params, notes
        visible = [(t, p) for t, p in terms if not self.engine.pseudonyms.hidden_word(t, types)]
        left = [t for t, p in terms if (t, p) not in visible]
        if not left:
            return params, notes
        notes.append(f"not searched, as hidden from you (privacy placeholders): {', '.join(left)}")
        if not visible:
            return None, notes
        query = " ".join((f'"{t}"' if " " in t else t) + ("*" if p else "") for t, p in visible)
        return {**params, "query": query}, notes

    def _hidden_hit(self, hit: dict, plugin_type: str) -> bool:
        """Whether the pseudonyms hide this hit whole (a word in its title, subject or sender) or the
        attachment its passage comes from (a word in the file's name)."""
        shape = _for_hiding(hit)
        return self.engine.pseudonyms.hides_item(shape, plugin_type) or self.engine.pseudonyms.hides_item(shape.get("_attachment"),
                                                                                           plugin_type)

    def _hold_held_messages(self, hits: list[dict]) -> None:
        """A hit made of several messages (a chat's day) is held back whole when the guard holds one of them,
        as a list of those messages shows it held (the hit's own ref is checked by the guard itself)."""
        if not self.engine.guard.enabled:
            return
        refs = [r for h in hits for r in h.get("_refs") or []]
        held = self.engine.guard.held_refs(refs) if refs else set()
        for i, hit in enumerate(hits):
            if held & set(hit.get("_refs") or []):
                hits[i] = {**held_row(hit, {"reason": GUARD_REASON}), "source": hit["source"]}

    def pull(self, instance: str, budget: float = 60.0, wait: bool = False) -> dict:
        """Ask one indexed plugin for what changed (library.pull). `wait`: behind a pull already running,
        instead of leaving it to that one. Settings changed since its items were fed: they wait, and this pull
        feeds them again from the start (library.settle)."""
        spec = self.engine.registry.manifest(instance).get("index") if instance in self.engine.registry.configured() else None
        if not isinstance(spec, dict) or not self.engine.registry.state(instance)["enabled"]:
            return {"skipped": "not indexed or switched off"}
        if wait:
            lock = self.engine.library.pulling.setdefault(instance, threading.Lock())
            with lock:
                pass
        self.settle(instance)
        return self.engine.library.pull(instance, self.engine.registry.instance(instance), budget)

    def poke(self, instance: str) -> None:
        """Doorman just changed something in an indexed plugin (a kept file, a moved event): its feed is
        asked now, in the background, so search has the change in seconds instead of at the next pull."""
        if not (self.engine.config.get("search_index") or {}).get("pull_after_writes", True):
            return
        if instance not in self.engine.registry.configured() or not isinstance(self.engine.registry.manifest(instance).get("index"), dict):
            return
        threading.Thread(target=self._quiet_pull, args=(instance,), daemon=True, name=f"pull-{instance}").start()

    def _quiet_pull(self, instance: str) -> None:
        try:
            self.pull(instance, 30)
        except Exception:  # noqa: BLE001 - the next scheduled pull tries again
            log.exception("pulling %s after a write", instance)

    def indexed_plugins(self) -> set[str]:
        """Configured plugins whose manifest has `index:`, switched on or off (off keeps its items)."""
        out = set()
        for name in self.engine.registry.configured():
            try:
                if isinstance(self.engine.registry.manifest(name).get("index"), dict):
                    out.add(name)
            except Exception:  # noqa: BLE001 - a plugin that can't load feeds nothing
                log.warning("plugin %s: no manifest, so nothing of it stays in search", name, exc_info=True)
        return out

    def tidy(self) -> list[str]:
        """Sources in the search index that aren't any more: a plugin removed (also while Doorman was down, or
        while a pull of it was running) or one whose manifest no longer has `index:`. At start and every
        upkeep round. Their items go, and with them the background work of reading them for meaning."""
        gone = sorted(self.engine.library.sources() - self.indexed_plugins())
        for name in gone:
            log.info("search index: %s isn't a source any more, its items go", name)
            self.engine.library.purge(name)
        return gone

    def due(self, now: float, last: dict[str, float]) -> list[str]:
        """Indexed plugins, switched on, whose feed is due (`index: {every_minutes}`, default 5)."""
        due = []
        for plugin in self.engine.registry.list():
            spec = self.engine.registry.manifest(plugin["name"]).get("index")
            if not plugin["enabled"] or not isinstance(spec, dict):
                continue
            every = 60 * float(spec.get("every_minutes", FEED_EVERY))
            if now - last.get(plugin["name"], -1e9) >= every:
                due.append(plugin["name"])
        return due

    def status(self) -> dict:
        """The index for the owner app: totals and, per source, how many items and when its feed last ran."""
        out = self.engine.library.status()
        out["sources"] = []
        for plugin in self.engine.registry.list():
            if not isinstance(self.engine.registry.manifest(plugin["name"]).get("index"), dict):
                continue
            state = self.engine.library.feed_state(plugin["name"])
            out["sources"].append({"name": plugin["name"], "enabled": plugin["enabled"], "pulled": state["pulled"],
                                   "error": state["error"], "skipped": state["skipped"],
                                   "skip_note": state["skip_note"], **self.engine.library.status(plugin["name"])})
        return out

    def any_word(self, session: dict, key: dict, params: dict) -> dict:
        """query(), and when a query of several words finds nothing at all, each word on its own: hits for
        any of them, merged and marked `matched: "any_word"`, with how many each word found. An agent then
        sees the near misses ("proposal", not "thesis proposal") instead of an empty list. The single words go
        by words only: the whole query was already searched by meaning, and one word alone, by meaning, is
        close to every short text (a calendar entry called "Free time" for "Frist")."""
        out = self.query(session, key, params)
        near = out["results"][len(out["results"]) - out.pop("_near", 0):]
        words = [w for w in str(params.get("query") or "").split() if w.strip('"')]
        if len(out["results"]) > len(near) or len(words) < 2 or '"' in str(params.get("query")):
            return out
        limit, counts, lists = int(params.get("limit", SEARCH_LIMIT)), {}, []
        for word in words[:5]:
            found = self.query(session, key, {**params, "query": word}, meaning=False)
            counts[word] = len(found["results"])
            lists.append(found["results"])
        if params.get("sort") == "date":
            results = by_newest(lists)
        else:  # a hit found by several of the words first, then by how high each word put it
            seen: dict[str, dict] = {}
            for hits in lists:
                for hit in hits:
                    seen.setdefault(_hit_id(hit), hit)
            order = textsearch.fuse([([_hit_id(h) for h in hits], 1.0) for hits in lists])
            results = [seen[i] for i in order]
        results = list({_hit_id(h): h for h in results}.values())
        first = out.get("note")  # what the search of all the words said (words it left out, say)
        if not results:
            if near:  # only the closest by meaning, each with its meaning_score
                return out
            return {**out, "note": "; ".join(filter(None, [
                first, f"nothing for all of {' '.join(words)}, nor for any one of them: try other words (a synonym, "
                       "the other language, the sender's name)"]))}
        closest = [h for h in near if _hit_id(h) not in {_hit_id(r) for r in results}]  # after the words' hits
        found_by = "; ".join(f"{n} for '{w}'" for w, n in counts.items())
        return {**out, "results": (results + closest)[:limit], "more": len(results + closest) > limit,
                "matched": "any_word", "note": "; ".join(filter(None, [
                    first, f"nothing has all of '{' '.join(words)}'; these have some of them ({found_by})"
                           + ("; then the closest by meaning" if closest else "")]))}


SEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {"type": "string", "maxLength": 500},
        "from": {"type": "string", "maxLength": 200},
        "to": {"type": "string", "maxLength": 200},
        "since": {"type": "string", "format": "date"},
        "until": {"type": "string", "format": "date"},
        "has_attachment": {"type": "boolean"},
        "kind": {"anyOf": [{"type": "string", "enum": list(KINDS)},
                           {"type": "array", "items": {"type": "string", "enum": list(KINDS)}, "maxItems": 6}]},
        "in": {"type": "string", "maxLength": 200},
        "sources": {"type": "array", "items": {"type": "string"}, "maxItems": 50},
        "sort": {"type": "string", "enum": ["relevance", "date"]},
        "limit": {"type": "integer", "minimum": 1, "maximum": 100},
    },
    "additionalProperties": False,
}

SEARCH_LIMIT = 10        # hits per search; each comes with a passage of up to ~800 characters

SETTLE_WAIT = 15.0       # seconds a search spends feeding again sources whose settings just changed

NOT_FILTERS = ("sources", "limit", "sort")

# what a source's search hit carries for Doorman alone (Search.query): taken off before any agent sees it
INTERNAL_KEYS = ("_same", "_near", "_refs")


def _hit_id(hit: Any) -> str:
    if not isinstance(hit, dict):
        return str(id(hit))
    return f"{hit.get('source')}|{hit.get('ref') or hit.get('path') or hit.get('id') or id(hit)}"


def _hit_date(hit: Any) -> str:
    return str(hit.get("date") or hit.get("modified") or "") if isinstance(hit, dict) else ""


def by_newest(lists: list[list]) -> list:
    """Hits of several lists in one, the newest first."""
    return sorted((hit for hits in lists for hit in hits), key=_hit_date, reverse=True)


HIT_KEYS = ("passage", "where", "by_meaning", "hidden_text", "withheld")  # Doorman's, not a plugin field's


def _hit_for_agent(hit: dict, source: dict | None = None) -> dict:
    """A library hit in the shape agents get: source, kind, ref, title, date, the passage and where in the
    item it is, then the plugin's own fields (subject, from, folder, path, start, location, chat...). The
    keys Doorman merges copies by stay underscored until Search.query takes them off.

    A passage from an attachment (part n of an item whose plugin has attachment refs, `item: {attachments}`)
    makes the hit that attachment's: ref <item ref>#<n>, as mail.attachment's answer has it, so the guard
    files and finds holds under the same ref. `hidden_text` (the check found text nobody sees in that PDF)
    goes with it, for the guard to hold it whatever its model says; a PDF the check hasn't read yet gives no
    passage, and `withheld` says why."""
    source = source or {}
    ref = hit["ref"]
    if hit.get("part") and source.get("attachment_refs"):
        ref = f"{ref}#{hit['part']}"
    out = {"source": hit["source"], "kind": hit["kind"], "ref": ref, "title": hit["title"], "date": hit["date"]}
    for name, value in (hit.get("fields") or {}).items():
        if name not in out and name not in INTERNAL_KEYS and name not in HIT_KEYS:
            out[name] = value
    if hit.get("passage"):
        out["passage"] = hit["passage"]
    if hit.get("where"):
        out["where"] = hit["where"]
    if hit.get("unchecked"):
        read = source.get("part_read") if hit.get("part") else source.get("read")
        out["withheld"] = ("no passage until this PDF is checked for hidden text"
                           + (f"; {read} checks it as it reads it" if read else ""))
    if hit.get("hidden_text"):
        out["hidden_text"] = hit["hidden_text"]
    if hit.get("by_meaning"):
        out["by_meaning"] = True
    if hit.get("meaning") is not None:
        out["meaning_score"] = round(float(hit["meaning"]), 1)
    if hit.get("near"):
        out["_near"] = True
    out["_same"] = hit.get("same") or []
    if hit.get("refs"):
        out["_refs"] = list(hit["refs"])
    return out


def _for_hiding(item: Any) -> Any:
    """A screened hit as the pseudonyms see it: a passage from an attachment together with that attachment's
    name (`_attachment: {name, passage}`), as mail.attachment returns them, so a sensitive file name hides
    that passage; attachment names as mail.read lists them ({name})."""
    if not isinstance(item, dict) or item.get("held"):
        return item
    out = dict(item)
    if out.get("where"):
        out["_attachment"] = {"name": out.pop("where"), **({"passage": out.pop("passage")} if "passage" in out else {})}
    if isinstance(out.get("attachments"), list):
        out["attachments"] = [{"name": a} if isinstance(a, str) else a for a in out["attachments"]]
    return out


def _from_hiding(item: Any) -> Any:
    """The hit again in the shape agents get (_for_hiding undone, placeholders kept)."""
    if not isinstance(item, dict) or "_attachment" not in item and not isinstance(item.get("attachments"), list):
        return item
    out = dict(item)
    part = out.pop("_attachment", None)
    if isinstance(part, dict):
        if "passage" in part:
            out["passage"] = part["passage"]
        out["where"] = part.get("name")
    if isinstance(out.get("attachments"), list):
        out["attachments"] = [a["name"] if isinstance(a, dict) and set(a) == {"name"} else a
                              for a in out["attachments"]]
    return out


def _lost_its_words(raw: Any, shown: Any, words: list[str]) -> bool:
    """A hit whose passage held a searched word that what the agent gets of it doesn't any more (the
    pseudonyms or the redactor took it out): it was found by text the agent can't see. One the guard holds
    back says nothing either way."""
    if not words or not isinstance(raw, dict) or not isinstance(shown, dict) or shown.get("held"):
        return False
    before, after = textsearch.fold(str(raw.get("passage") or "")), textsearch.fold(str(shown.get("passage") or ""))
    return any(w in before and w not in after for w in words if w)


def _visible_close(close: dict[str, list[str]], results: list) -> dict[str, list[str]]:
    """The close spellings a search may mention: those found in what the agent got (a title, a passage), not
    words that only exist in what it can't see (another source, a held or hidden item)."""
    seen = textsearch.fold(" ".join(str(r.get(k) or "") for r in results if isinstance(r, dict)
                                    for k in ("title", "passage", "where", "subject", "summary", "name")))
    out = {}
    for term, spellings in (close or {}).items():
        shown = [s for s in spellings if textsearch.fold(s) in seen]
        if shown:
            out[term] = shown
    return out


def _place(hit: dict) -> dict:
    """Where else a document is, for `also`: the source, its ref and what names it there."""
    out = {"source": hit.get("source"), "ref": hit.get("ref")}
    for field in ("subject", "title", "summary", "path", "name", "chat"):
        if hit.get(field):
            out[field] = hit[field]
            break
    if _hit_date(hit):
        out["date"] = _hit_date(hit)
    if hit.get("made_by"):
        out["made_by"] = hit["made_by"]
    return out


def once(results: list) -> list:
    """Each document once: hits that share a `_same` key (one text in two places; the same mail in two
    mailboxes, one event in two calendars, when they read the same: library.put) become the first, best
    placed one, with the others under `also`."""
    out, owner = [], {}
    for hit in results:
        same = hit.get("_same") if isinstance(hit, dict) else None
        keys = [k for k in ([same] if isinstance(same, str) else same or []) if isinstance(k, str) and k]
        first = next((owner[k] for k in keys if k in owner), None)
        if first is None:
            out.append(hit)
            for k in keys:
                owner[k] = hit
            continue
        first.setdefault("also", []).append(_place(hit))
        for k in keys:
            owner.setdefault(k, first)
    return out


def _without_internal(data: Any) -> Any:
    """A read's answer without what only Doorman uses (INTERNAL_KEYS), at any depth."""
    if isinstance(data, list):
        return [_without_internal(v) for v in data]
    if isinstance(data, dict):
        return {k: _without_internal(v) for k, v in data.items() if k not in INTERNAL_KEYS}
    return data
