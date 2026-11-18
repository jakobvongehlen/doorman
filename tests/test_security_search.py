"""doorman search gives what the equivalent plugin read would give, no more (the security review of the central
search index, doorman/library.py and engine.search.query): hidden text in PDFs, a read per kind and attachment,
pseudonyms on attachments, settings that narrow a source, guard holds on parts, hidden words, borrowed or stale
provenance, and the work one search may cause. The mail archive's side is in test_mail_archive.py."""

import hashlib
import time

import pytest

from doorman import clock
from doorman import search as search_mod
from doorman import library as library_mod
from doorman import textsearch
from doorman.library import Library
from doorman.plugin_api import Denied, PluginError
from conftest import FAKE_PLUGINS, Agent, make_engine
from test_attachments import tiny_pdf

HIDDEN = {"reason": "a PDF with text that isn't visible on the page", "page": 1}


def mail(key, subject, body, *attachments, date="2026-11-01"):
    """A mail as the archive feeds it: the body as part 0, then (name, text, flags) per attachment."""
    parts = [{"part": 0, "text": body}] + [{"part": n, "name": name, "text": text, **flags}
                                           for n, (name, text, flags) in enumerate(attachments, 1)]
    return {"key": key, "kind": "mail", "title": subject, "date": date, "parts": parts,
            "has_attachment": bool(attachments), "fields": {"subject": subject, "attachments": [a[0] for a in attachments]}}


def entry(key, kind, title, text, date="2026-11-02", **more):
    return {"key": key, "kind": kind, "title": title, "text": text, "date": date, **more}


ITEMS = [
    mail("m1", "Angebot", "Anbei das Angebot.",
         ("angebot.pdf", "Preis 120 EUR netto", {"hidden_text": HIDDEN}),
         ("liste.pdf", "Lieferliste Schrauben", {"unchecked": True})),
    mail("m2", "Unterlagen", "Siehe Anhang zur Kaution",
         ("Arztbrief_Mueller.pdf", "Der Patient stellte sich mit Brustschmerzen vor. Termin zur Kaution.", {})),
    mail("m3", "Abrechnung", "Bitte bis Freitag bezahlen", ("abrechnung.txt", "Stromkosten 84 EUR", {})),
    mail("m4", "Werte", "Wir sehen uns Montag. Die Kardiologin hat die Laborwerte geschickt."),
    entry("t1", "task", "Steuererklärung abgeben", "Belege sammeln"),
    entry("e1", "event", "Teamtreffen", "Raum 2.05"),
    entry("e2", "event", "Psychiater Dr. Weber", "Raum 3, zweiter Stock"),
    entry("c1", "chat", "Familie", "09:00 Mum: Kuchen am Sonntag\n09:05 me: gerne", ref="box:fam/1",
          refs=["box:fam/1", "box:fam/2"]),
]


def plugin(plugin_type, *items):
    return {"type": plugin_type, "enabled": True, "config": {"items": list(items)}}


@pytest.fixture
def world(tmp_path):
    engine = make_engine(tmp_path, plugin_paths=[FAKE_PLUGINS], plugins={
        "notes": {"enabled": False}, "box": plugin("fake_parts", *ITEMS),
        "lib": plugin("fake_library", {"key": "p1", "title": "Pizza", "text": "Ein Rezept für Pizza"})})
    for name in ("box", "lib"):
        engine.search.pull(name)
    return engine, Agent(engine)


def find(agent, **params):
    return agent.engine.search.any_word(agent.session, agent.key, params)


def refs(out):
    return [h["ref"] for h in out["results"]]


def switch_off(engine, name, *reads):
    engine.registry.set_state(name, {**engine.registry.state(name), "disabled_tools": list(reads)})


def hold(engine, ref):
    """What the guard keeps when it holds something back: a quarantine row for that ref."""
    engine.db.exec("INSERT INTO quarantine(sha256, source, ref, label, score, excerpt, status, created) "
                   "VALUES(?,?,?,?,?,?,?,?)", (hashlib.sha256(ref.encode()).hexdigest(), "box.get", ref, "x", 0.97,
                                               "x", "held", clock.iso()))


# ------------------------------------------------------------------ 1. hidden text in PDFs

def test_hidden_text_holds_the_hits_of_its_pdf_and_an_unchecked_pdf_gives_no_passage(world):
    engine, agent = world
    [held] = find(agent, query="Preis")["results"]
    assert held["held"] and held["ref"] == "box:m1#1" and "Preis" not in str(held)
    # held under the attachment's ref, as reading the attachment would be; the mail itself isn't
    assert engine.guard.held_refs(["box:m1#1", "box:m1"]) == {"box:m1#1"}
    [body] = find(agent, query="Anbei")["results"]
    assert body["ref"] == "box:m1" and body["passage"] == "Anbei das Angebot." and not body.get("held")
    [waiting] = find(agent, query="Lieferliste")["results"]
    assert waiting["ref"] == "box:m1#2" and waiting["where"] == "liste.pdf" and "passage" not in waiting
    assert waiting["withheld"] == ("no passage until this PDF is checked for hidden text; box.attachment checks "
                                   "it as it reads it")


def test_the_cli_says_why_a_hit_has_no_passage_and_which_attachment_it_is(world):
    from test_recent import load_cli

    _, agent = world
    out = find(agent, query="Lieferliste")
    out["results"][0]["subject"] = "Angebot"  # a mail hit: the line shows the attachment's number
    lines = load_cli().search_rows(out).splitlines()
    assert lines[0].endswith("in: liste.pdf  part 2")
    assert lines[1] == ("    (no passage until this PDF is checked for hidden text; box.attachment checks it as it "
                        "reads it)")


def test_the_files_archive_checks_its_pdfs_in_the_background(tmp_path, monkeypatch):
    """The walk's structural check finds both PDFs clean, so search shows them at once; the OCR check runs for
    each as the backstop, and what it finds holds a PDF search showed already."""
    root = tmp_path / "archive"
    root.mkdir()
    (root / "angebot.pdf").write_bytes(tiny_pdf("Angebot Preis 120 EUR"))
    (root / "brief.pdf").write_bytes(tiny_pdf("Brief Preis 99 EUR"))
    engine = make_engine(tmp_path, plugins={"files": {"enabled": True, "config": {"root": str(root)}},
                                            "notes": {"enabled": False}})
    files = engine.registry.instance("files")
    files.index()
    engine.search.pull("files")
    agent = Agent(engine)
    shown = find(agent, query="Preis")["results"]
    assert len(shown) == 2 and all("Preis" in h["passage"] and "withheld" not in h for h in shown)
    assert sorted(files.unchecked()) == ["angebot.pdf", "brief.pdf"]  # the OCR check still runs for each

    real = files.text_of

    def text_of(path, ocr, limit=files_module(files)["TEXT_CHARS"], check_pdf=False, background=False):
        found = real(path, ocr, limit, check_pdf)
        if check_pdf and path.name == "angebot.pdf":
            found = {**found, "report": {"hidden_text": HIDDEN}}
        return found

    monkeypatch.setattr(files, "text_of", text_of)
    status = files.run_job("pdf_check", 60)
    assert status == {"summary": "every PDF is checked for hidden text", "checked": 2, "more": False}
    engine.search.pull("files")
    hits = {h["ref"]: h for h in find(agent, query="Preis")["results"]}
    assert hits["files:angebot.pdf"]["held"] and "Brief Preis 99 EUR" in hits["files:brief.pdf"]["passage"]
    # a file that changes is checked again
    (root / "brief.pdf").write_bytes(tiny_pdf("Brief Preis 101 EUR"))
    files.index()
    assert files.unchecked() == ["brief.pdf"]
    # with the check off (the owner's setting), reads don't check and search doesn't wait for it
    files.config["check_hidden_text"] = False
    assert files.feed_item("brief.pdf").get("unchecked") is None and files.run_job("pdf_check", 60)["summary"] \
        == "check_hidden_text is off"


def files_module(files) -> dict:
    return type(files).index_feed.__globals__


# ------------------------------------------------------------------ 2. a read per kind and per attachment

def test_each_hit_needs_the_read_that_returns_what_it_shows(world):
    engine, agent = world
    assert refs(find(agent, query="Stromkosten")) == ["box:m3#1"]
    assert refs(find(agent, query="Belege")) == ["box:t1"] and refs(find(agent, query="Kuchen")) == ["box:fam/1"]
    switch_off(engine, "box", "attachment", "tasks", "messages")
    assert find(agent, query="Stromkosten")["results"] == []            # an attachment's text: box.attachment's
    [hit] = find(agent, query="bezahlen")["results"]                    # the mail itself: box.get's
    assert hit["ref"] == "box:m3" and "where" not in hit
    assert find(agent, query="Belege")["results"] == [] and find(agent, kind="task")["results"] == []
    assert find(agent, query="Kuchen")["results"] == [] and find(agent, kind="chat")["results"] == []
    assert refs(find(agent, query="Teamtreffen")) == ["box:e1"]
    switch_off(engine, "box")
    assert refs(find(agent, query="Stromkosten")) == ["box:m3#1"]
    # the actor, with the reader/actor split, can't read raw attachments: it searches mail without them
    engine.config["reader_actor_split"] = True
    actor = Agent(engine, "actor")
    assert find(actor, query="Stromkosten")["results"] == [] and refs(find(actor, query="bezahlen")) == ["box:m3"]


def test_files_list_off_keeps_the_archive_from_being_listed(tmp_path):
    root = tmp_path / "archive"
    root.mkdir()
    (root / "kochen.txt").write_text("Ein Rezept für Pizza")
    engine = make_engine(tmp_path, plugins={"files": {"enabled": True, "config": {"root": str(root)}},
                                            "notes": {"enabled": False}})
    engine.registry.instance("files").index()
    engine.search.pull("files")
    agent = Agent(engine)
    assert refs(find(agent, kind="file")) == ["files:kochen.txt"]
    switch_off(engine, "files", "list")
    assert find(agent, kind="file")["results"] == [] and find(agent, query="Pizza")["results"] == []


# ------------------------------------------------------------------ 3. pseudonyms on attachments

def test_a_sensitive_attachment_name_hides_its_passage(world):
    engine, agent = world
    out = find(agent, query="Brustschmerzen")
    assert out["results"] == [] and "Patient" not in str(out)
    # the mail found by its body: its subject and passage in clear, the attachment's name a placeholder,
    # as mail.read shows it (Kaution is in the attachment too; the body is what finds it)
    [hit] = find(agent, query="Kaution")["results"]
    assert (hit["ref"], hit["title"], hit["passage"]) == ("box:m2", "Unterlagen", "Siehe Anhang zur Kaution")
    assert hit["attachments"][0].startswith("[Gesundheit PSN-") and "Mueller" not in str(hit)


def test_the_pseudonyms_see_an_attachments_passage_with_its_name(world):
    """The hit's shape for the real Pseudonymizer: the attachment's name is the header of its passage, as it
    is of mail.attachment's answer, so a word in the name hides the passage and nothing else."""
    engine, _ = world
    hit = {"source": "box", "ref": "box:m2#1", "title": "Unterlagen", "subject": "Unterlagen",
           "passage": "Der Patient stellte sich mit Brustschmerzen vor.", "where": "Arztbrief_Mueller.pdf",
           "attachments": ["Arztbrief_Mueller.pdf", "anfahrt.pdf"]}
    shape = search_mod._for_hiding(hit)
    assert shape["_attachment"] == {"name": "Arztbrief_Mueller.pdf", "passage": hit["passage"]}
    shown = search_mod._from_hiding(engine.pseudonyms.hide(shape, "mail_imap")[0])
    assert shown["title"] == shown["subject"] == "Unterlagen" and shown["ref"] == "box:m2#1"
    assert shown["passage"].startswith("[Gesundheit PSN-") and shown["where"].startswith("[Gesundheit PSN-")
    assert shown["attachments"][0].startswith("[Gesundheit PSN-") and shown["attachments"][1] == "anfahrt.pdf"


# ------------------------------------------------------------------ 4. settings that narrow a source

def test_narrowed_settings_take_what_a_source_no_longer_feeds_out_at_once(tmp_path, monkeypatch):
    engine = make_engine(tmp_path, plugin_paths=[FAKE_PLUGINS], plugins={"notes": {"enabled": False}})
    work, family = entry("e1", "event", "Teamtreffen", "Raum 2.05"), entry("e2", "event", "Geburtstag Oma", "Kuchen")
    engine.plugin_setup.add("cal", "fake_parts", config={"items": [work, family]})
    engine.search.pull("cal")
    agent = Agent(engine)
    assert refs(find(agent, query="Geburtstag")) == ["cal:e2"]
    # the feed fails from now on (an expired login): narrowing still takes the other calendar out at once
    plugin_class = type(engine.registry.instance("cal"))
    monkeypatch.setattr(plugin_class, "index_feed", lambda self, cursor, budget: (_ for _ in ()).throw(
        PluginError("the login expired")))
    engine.plugin_setup.configure("cal", config={"items": [work]})
    out = find(agent, query="Geburtstag")
    assert out["results"] == [] and "settings changed" in out["sources"]["cal"]["note"]
    assert find(agent, query="Teamtreffen")["results"] == []  # until it has fed again under the new settings
    monkeypatch.undo()
    engine.search.pull("cal", wait=True)
    assert refs(find(agent, query="Teamtreffen")) == ["cal:e1"] and find(agent, query="Geburtstag")["results"] == []
    assert "note" not in find(agent, query="Teamtreffen")["sources"]["cal"]


def test_a_mailbox_counts_only_the_settings_that_change_what_it_feeds(tmp_path):
    engine = make_engine(tmp_path, plugins={"notes": {"enabled": False}, "mail": {
        "type": "mail_imap", "enabled": True, "config": {"imap_host": "127.0.0.1", "archive": "index"}}})
    config = dict(engine.registry.configured()["mail"]["config"])
    before = engine.search.feed_settings("mail")

    def change(**settings):
        config.update(settings)
        engine.registry.save_instance("mail", "mail_imap", config, False)

    change(archive_ocr=False, imap_host="imap.example.org")  # scans: the archive follows that itself
    assert engine.search.feed_settings("mail") == before
    change(check_hidden_text=False)                          # what search may show of its PDFs
    after = engine.search.feed_settings("mail")
    assert after != before
    engine.redactor.security_senders = ["*@bank.example"]    # its archive feeds their mail without the text
    assert engine.search.feed_settings("mail") != after


def test_a_search_right_after_a_settings_change_feeds_the_source_first(tmp_path):
    """The source isn't missing from a search right after the change: the search feeds it again under the
    new settings before it looks (behind any pull already running, for at most SETTLE_WAIT seconds)."""
    engine = make_engine(tmp_path, plugin_paths=[FAKE_PLUGINS], plugins={"notes": {"enabled": False}})
    work, family = entry("e1", "event", "Teamtreffen", "Raum 2.05"), entry("e2", "event", "Geburtstag Oma", "Kuchen")
    engine.plugin_setup.add("cal", "fake_parts", config={"items": [work, family]})
    engine.search.pull("cal")
    agent = Agent(engine)
    engine.plugin_setup.configure("cal", config={"items": [work]})
    out = find(agent, query="Teamtreffen")
    assert refs(out) == ["cal:e1"] and "note" not in out["sources"]["cal"]
    assert find(agent, query="Geburtstag")["results"] == []


def test_after_a_settings_change_the_source_is_fed_to_the_end_at_once(tmp_path, monkeypatch):
    """Not a slice now and the rest at its next pull (every 30 minutes for a calendar): Doorman goes on
    feeding it in the background until the pass is through."""
    engine = make_engine(tmp_path, plugin_paths=[FAKE_PLUGINS], plugins={"notes": {"enabled": False}},
                         search_index={"pull_after_writes": True, "upkeep_minutes": 2})
    events = [entry(f"e{n}", "event", f"Termin {n}", "Raum 2.05") for n in range(6)]
    engine.plugin_setup.add("cal", "fake_parts", config={"items": events})
    engine.search.pull("cal", wait=True)

    def in_slices(self, cursor, budget):  # two events per answer
        start = int(cursor or 0)
        return {"items": [dict(i) for i in self.items()[start:start + 2]], "cursor": str(start + 2),
                "more": start + 2 < len(self.items())}

    monkeypatch.setattr(type(engine.registry.instance("cal")), "index_feed", in_slices)
    pull = engine.search.pull
    monkeypatch.setattr(engine.search, "pull", lambda name, budget=60.0, wait=False: pull(name, 0, wait))  # one answer per pull
    engine.plugin_setup.configure("cal", config={"items": events[:5]})
    engine.search.pull("cal")  # the scheduled pull: it sees the change, takes one slice
    deadline = time.monotonic() + 10
    while engine.library.refeeding("cal") and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not engine.library.refeeding("cal")
    assert sorted(engine.library.keys("cal")) == ["e0", "e1", "e2", "e3", "e4"]  # e5 left with the pass

def test_a_change_of_the_security_senders_feeds_again_only_what_depends_on_them(world):
    """Only mail's feed leaves out what security senders wrote. A source whose manifest says
    `index: {security_senders: false}` (calendars, files, notes, WhatsApp) isn't fed again when the list
    changes; one that doesn't say so is, and a search right after the change feeds it first."""
    engine, agent = world
    assert refs(find(agent, query="Pizza")) == ["lib:p1"]
    notes, lib = engine.search.feed_settings("notes"), engine.search.feed_settings("lib")
    engine.redactor.security_senders = ["*@bank.example"]  # doorman.yaml changed, Doorman restarted
    assert engine.search.feed_settings("notes") == notes and engine.search.feed_settings("lib") != lib
    out = find(agent, query="Pizza")
    assert refs(out) == ["lib:p1"] and "note" not in out["sources"]["lib"]
    assert engine.library.feed_state("lib")["fence"] and not engine.library.refeeding("lib")  # fed again


def test_a_pull_under_the_old_settings_stops_and_brings_nothing_back(tmp_path):
    library = Library(tmp_path / "index.db")
    library.settle("cal", "v1")

    class Feed:
        def index_feed(self, cursor, budget):
            library.settle("cal", "v2")  # the settings change while this feed runs
            return {"items": [entry("old", "event", "Alt", "von vorher")], "complete": True}

    assert "stopped" in library.pull("cal", Feed())
    assert library.feed_state("cal")["cursor"] is None
    assert library.search({"query": "Alt"}, ["cal"], 10)["hits"] == []


# ------------------------------------------------------------------ 5. guard holds on parts and messages

def test_a_hold_on_an_attachment_or_on_one_message_holds_the_hits_made_of_it(world):
    engine, agent = world
    hold(engine, "box:m3#1")
    hold(engine, "box:fam/2")
    [attachment] = find(agent, query="Stromkosten")["results"]
    assert attachment["held"] and "Stromkosten" not in str(attachment)
    [body] = find(agent, query="bezahlen")["results"]  # the mail's body isn't the held attachment
    assert not body.get("held") and body["passage"] == "Bitte bis Freitag bezahlen"
    [day] = find(agent, query="Kuchen")["results"]     # the second message of the day is held: the day is
    assert day["held"] and "Kuchen" not in str(day)


# ------------------------------------------------------------------ 6. hidden words

def test_a_hidden_word_finds_nothing(world):
    engine, agent = world
    out = find(agent, query="Psychiater", kind="event")
    assert out["results"] == [] and out["note"] == ("not searched, as hidden from you (privacy placeholders): "
                                                    "Psychiater")
    assert find(agent, query="Weber")["results"] == []      # a visible word of a hidden item doesn't find it
    out = find(agent, **{"from": "zahnarzt"})
    assert out["results"] == [] and "hidden from you" in out["note"]
    # Psychiater left out, Teamtreffen searched
    out = find(agent, query="Psychiater Teamtreffen")
    assert refs(out) == ["box:e1"] and "Psychiater" in out["note"]
    # listed without words, it is there as a placeholder, as the events read would show it
    [listed] = [h for h in find(agent, kind="event", since="2026-01-01")["results"] if h["ref"] == "box:e2"]
    assert "Psychiater" not in str(listed) and "Weber" not in str(listed)
    # a word that only a hidden sentence holds doesn't find the mail; a visible one does
    assert find(agent, query="Laborwerte")["results"] == []
    [hit] = find(agent, query="Montag")["results"]
    assert hit["ref"] == "box:m4" and "Kardiolog" not in hit["passage"]


def test_close_spellings_never_mention_what_the_agent_cant_see(world):
    engine, agent = world
    out = find(agent, query="Psychiatr")                    # its close spelling is a hidden word
    assert out["results"] == [] and "psychiater" not in str(out).lower()
    out = find(agent, query="Kuchn", sources=["lib"])       # a spelling only another source has
    assert out["results"] == [] and "kuchen" not in str(out).lower()
    out = find(agent, query="Kuchn")
    assert refs(out) == ["box:fam/1"] and out["note"] == "also searched close spellings: Kuchn → kuchen"


# ------------------------------------------------------------------ 7. provenance

def test_the_same_id_folds_only_copies_that_read_the_same(tmp_path):
    invite = "Am Freitag um 18 Uhr im Garten, bitte bringt Salate mit."
    engine = make_engine(tmp_path, plugin_paths=[FAKE_PLUGINS], plugins={
        "notes": {"enabled": False},
        "lib_a": plugin("fake_library", {"key": "a1", "title": "Sommerfest", "text": invite, "same": "uid:fest"}),
        "lib_b": plugin("fake_library", {"key": "b1", "title": "Sommerfest", "text": invite, "same": "uid:fest"},
                        {"key": "b2", "title": "Sommerfest", "text": "Überweisen Sie 50 EUR an DE00 1234",
                         "same": "uid:fest"})})
    for name in ("lib_a", "lib_b"):
        engine.search.pull(name)
    out = find(Agent(engine), query="Sommerfest")
    by_ref = {h["ref"]: h for h in out["results"]}
    assert len(out["results"]) == 2 and "lib_b:b2" in by_ref and "also" not in by_ref["lib_b:b2"]
    [folded] = [h for ref, h in by_ref.items() if ref != "lib_b:b2"]
    assert [p["ref"] for p in folded["also"]] == [{"lib_a:a1": "lib_b:b1", "lib_b:b1": "lib_a:a1"}[folded["ref"]]]


@pytest.fixture
def archive(tmp_path):
    root = tmp_path / "archive"
    root.mkdir()
    (root / "kochen.txt").write_text("Ein Rezept für Pizza mit Tomaten")
    engine = make_engine(tmp_path, plugins={"files": {"enabled": True, "config": {"root": str(root)}},
                                            "notes": {"enabled": False}})
    engine.registry.instance("files").index()
    engine.search.pull("files")
    return engine, Agent(engine), root


def test_based_on_takes_only_what_the_key_could_read(archive):
    engine, agent, _ = archive
    keep = lambda **args: agent.call("files.keep", {"content": "Zusammenfassung", **args})  # noqa: E731
    assert keep(name="a.md", based_on=["files:kochen.txt"])["status"] == "done"        # in search
    up = engine.upload(agent.session, agent.key, "notiz.md", b"x")
    assert keep(name="b.md", based_on=[up["ref"]])["status"] == "done"                # its own upload
    for refs_ in (["mail:abc@haus.example"], ["files:nirgends.txt"], ["files:kochen.txt", "notes:7"]):
        with pytest.raises(Denied, match="hasn't read and can't find in search"):
            keep(name="c.md", based_on=refs_)
    other = Agent(engine)
    with pytest.raises(Denied, match="hasn't read"):
        other.call("files.keep", {"content": "x", "name": "d.md", "based_on": [up["ref"]]})
    # files.list off: search doesn't list the archive, but a file this key read counts
    switch_off(engine, "files", "list")
    with pytest.raises(Denied, match="hasn't read"):
        keep(name="e.md", based_on=["files:kochen.txt"])
    agent.read("files.read", {"path": "kochen.txt"})
    assert keep(name="e.md", based_on=["files:kochen.txt"])["status"] == "done"


def test_replace_never_writes_over_a_kept_file_someone_changed_since(archive):
    engine, agent, root = archive
    agent.call("files.keep", {"content": "Erste Fassung", "name": "bericht.md"})
    (root / "Agent" / "bericht.md").write_text("Erste Fassung, vom Owner ergänzt")
    with pytest.raises(Denied, match="changed since an agent kept it"):
        agent.call("files.keep", {"content": "Zweite Fassung", "name": "bericht.md", "replace": True})
    assert (root / "Agent" / "bericht.md").read_text() == "Erste Fassung, vom Owner ergänzt"
    assert not (root / ".trash").exists()


# ------------------------------------------------------------------ 8. the work one search causes

def test_the_fast_fold_is_the_same_fold():
    """fold() runs Latin text through str.translate; every character still folds as it did one at a time."""
    import unicodedata

    def slow(ch):
        base = unicodedata.normalize("NFKD", ch)
        base = "".join(c for c in base if not unicodedata.combining(c)) or ch
        return base[0].lower() if len(base[0].lower()) == 1 else ch

    text = "".join(chr(i) for i in range(1, 0x3100) if not 0xD800 <= i < 0xE000) + "İ ß Straße ÆØÅ ǅ ﬁ Ⅻ ①"
    assert textsearch.fold(text) == "".join(slow(c) for c in text)
    assert len(textsearch.fold(text)) == len(text)


def test_one_search_reads_a_bounded_amount_of_text(tmp_path, monkeypatch):
    library = Library(tmp_path / "index.db")
    long = "Kaution am Anfang. " + "Wort " * 59_000      # ~300,000 characters per part
    library.put("notes", {"key": "big", "kind": "note", "title": "Groß", "parts": [{"part": 0, "text": long}] + [
        {"part": n, "name": f"anhang{n}.txt", "text": long} for n in range(1, 10)]})
    passages, folded = [], []
    real_passage, real_fold = textsearch.passage, textsearch.fold
    monkeypatch.setattr(textsearch, "passage", lambda text, terms, chunk=None: passages.append(len(text))
                        or real_passage(text, terms, chunk))
    monkeypatch.setattr(textsearch, "fold", lambda text: folded.append(len(text)) or real_fold(text))
    [hit] = library.search({"query": "Kaution Wort"}, ["notes"], 100)["hits"]
    assert "Kaution am Anfang" in hit["passage"]
    assert max(passages) <= library_mod.PASSAGE_CHARS and sum(folded) < 100_000
    words = " ".join(f"zeile{i}x" for i in range(30))
    looked_up = []
    monkeypatch.setattr(library, "_vocabulary", lambda first: looked_up.append(first) or [])
    found = library.search({"query": words}, ["notes"], 10)
    assert found["notes"][0].startswith(f"only the first {textsearch.MAX_TERMS} words were searched")
    assert looked_up == ["z"]                                # the index's words read once, not once a word
