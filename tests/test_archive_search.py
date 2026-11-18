"""How doorman search finds mail the archives feed it: stems, close spellings, and meaning (semantic
search); switching semantic search on and the owner app's view of it."""

import hashlib
import http.server
import os
import shutil
import threading
import time
from pathlib import Path

import pytest

from doorman import embedder as embedder_mod
from doorman import textsearch
from conftest import Agent, concept_vectors
from test_attachments import deliver_with, tiny_pdf
from test_mail_archive import find, setup, synced
from test_mail_imap import deliver, imap_server, smtp_server  # noqa: F401 - fixtures
from test_mail_imap import pytestmark as needs_dovecot

# ------------------------------------------------------------------ text analysis, no server


def test_stems_in_three_languages():
    assert textsearch.language("sehr geehrte damen und herren anbei die rechnung".split()) == "german"
    assert textsearch.language("de betaling is ontvangen met dank".split()) == "dutch"
    assert textsearch.language("please find the invoice attached".split()) == "english"
    assert textsearch.stemmed_text("Anbei die Rechnungen") == "anbei die rechnung"
    assert "betaal" in textsearch.query_stems("betalingen")
    assert "rechnung" in textsearch.query_stems("Rechnungen")


def test_close_spellings_prefer_common_words():
    vocabulary = [("rechnung", 40), ("rechnurg", 1), ("reichung", 2), ("rechner", 5)]
    assert textsearch.close_spellings("rechnug", vocabulary) == ["rechnung", "rechnurg"]  # rechner: 2 off
    assert textsearch.close_spellings("rechnung", vocabulary)[:1] == ["rechnurg"]
    assert textsearch.close_spellings("rec", vocabulary) == []  # too short to guess


def test_rank_fusion_rewards_agreement():
    assert textsearch.fuse([([1, 2, 3], 1.0), ([2], 1.0)])[0] == 2
    assert textsearch.fuse([([1], 1.0), ([2], 0.5)]) == [1, 2]


# ------------------------------------------------------------------ against Dovecot

@pytest.fixture
def mailbox(tmp_path, imap_server, smtp_server):  # noqa: F811
    engine, agent = setup(tmp_path, imap_server, smtp_server)
    deliver(imap_server, "verwaltung@haus.example", "Ihre Kaution", "Die Kaution wird im März überwiesen.")
    deliver(imap_server, "shop@example.com", "Ihre Rechnung", "Anbei Ihre Rechnung für Oktober.")
    deliver(imap_server, "scan@example.com", "Scan", "Rechnurg Nr. 5 vom Scanner")
    deliver(imap_server, "bank@example.nl", "Betaling", "De betaling is ontvangen, met dank.")
    deliver(imap_server, "anna@example.com", "Abendessen", "Ein Rezept für Pizza mit Tomaten.")
    return engine, agent, imap_server


def subjects(agent, query, **more):
    return [h["subject"] for h in find(agent, query=query, **more)["results"]]


@needs_dovecot[1]
def test_stems_find_other_forms(mailbox):
    engine, agent, _ = mailbox
    synced(engine)
    assert "Ihre Rechnung" in subjects(agent, "Rechnungen")
    assert subjects(agent, "betalingen") == ["Betaling"]
    [hit] = [h for h in find(agent, query="Rechnungen")["results"] if h["subject"] == "Ihre Rechnung"]
    assert "Rechnung für Oktober" in hit["passage"]


@needs_dovecot[1]
def test_close_spellings_catch_typos_and_ocr_misreads(mailbox):
    engine, agent, _ = mailbox
    synced(engine)
    typo = find(agent, query="Rechnug")
    assert "Ihre Rechnung" in [h["subject"] for h in typo["results"]]
    assert "close spellings" in typo["note"] and "rechnung" in typo["note"]
    assert {"Ihre Rechnung", "Scan"} <= set(subjects(agent, "Rechnung"))


@needs_dovecot[1]
def test_several_words_that_find_nothing_together_find_each_alone(mailbox):
    engine, agent, _ = mailbox
    synced(engine)
    together = engine.search.any_word(agent.session, agent.key, {"query": "Kaution Pizza"})
    assert together["matched"] == "any_word" and "1 for 'Kaution'; 1 for 'Pizza'" in together["note"]
    assert {h["subject"] for h in together["results"]} == {"Ihre Kaution", "Abendessen"}
    both = engine.search.any_word(agent.session, agent.key, {"query": "Ihre Kaution"})
    assert "matched" not in both and [h["subject"] for h in both["results"]] == ["Ihre Kaution"]
    nothing = engine.search.any_word(agent.session, agent.key, {"query": "Steuer Urlaub"})
    assert nothing["results"] == [] and "nor for any one of them" in nothing["note"]


@needs_dovecot[1]
def test_meaning_finds_other_words_and_languages(mailbox, monkeypatch):
    engine, agent, _ = mailbox
    monkeypatch.setattr(embedder_mod.Embedder, "backend", staticmethod(concept_vectors))
    synced(engine)
    assert "semantic" not in engine.library.run(time.monotonic() + 60)  # off: no vectors
    assert not any(h.get("by_meaning") for h in find(agent, query="deposit")["results"])

    engine.embedder.save(True)
    status = engine.library.run(time.monotonic() + 60)
    assert status["semantic"] == {"embedded": 5, "of": 5}, status
    found = find(agent, query="deposit")["results"]
    assert found[0]["subject"] == "Ihre Kaution"
    assert found[0]["by_meaning"] and "März" in found[0]["passage"]
    # words and meaning together: exact hits stay on top
    assert subjects(agent, "Pizza")[0] == "Abendessen"
    # filters apply to meaning too
    assert "Ihre Kaution" not in subjects(agent, "deposit", **{"from": "anna"})


@needs_dovecot[1]
def test_new_text_gets_vectors_and_attachments_count(mailbox, monkeypatch):
    engine, agent, port = mailbox
    monkeypatch.setattr(embedder_mod.Embedder, "backend", staticmethod(concept_vectors))
    engine.embedder.save(True)
    deliver_with(port, "bahn@example.com", "Ihre Buchung", "Siehe Anhang.", [
        ("ticket.pdf", "application/pdf", tiny_pdf("Fahrkarte Utrecht Amsterdam"))], "ticket@bahn.example")
    synced(engine)
    engine.library.run(time.monotonic() + 60)
    hit = find(agent, query="train")["results"][0]
    assert hit["id"] == "ticket@bahn.example" and hit["by_meaning"]
    assert hit["where"] == "ticket.pdf" and "Fahrkarte" in hit["passage"]  # the attachment that matched


# ------------------------------------------------------------------ the setting and the download


class _Files(http.server.BaseHTTPRequestHandler):
    files: dict = {}

    def do_GET(self):
        body = self.files.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_switching_on_downloads_the_model(tmp_path, monkeypatch):
    from conftest import make_engine

    files = {"model.onnx": b"m" * 500, "tokenizer.json": b"{}", "config.json": b"{}"}
    pinned = {name: (f"x/{name}", hashlib.sha256(body).hexdigest(), len(body)) for name, body in files.items()}
    monkeypatch.setitem(embedder_mod.MODEL, "files", pinned)
    _Files.files = {f"/{embedder_mod.MODEL['repo']}/resolve/{embedder_mod.MODEL['revision']}/x/{n}": b
                    for n, b in files.items()}
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Files)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        engine = make_engine(tmp_path)
        url = f"http://127.0.0.1:{server.server_address[1]}"
        started = []
        monkeypatch.setattr(engine.embedder.files, "fetch",
                            lambda wait=False, base_url=url: started.append(1) or
                            type(engine.embedder.files).fetch(engine.embedder.files, wait=True, base_url=url))
        assert engine.embedder.status()["state"] == "off"
        assert engine.embedder.embed(["x"]) == {"off": True, "state": "off"}
        status = engine.embedder.save(True)
        assert started and status["state"] == "ready" and status["model"]["ready"]
        assert (engine.embedder.files.model_dir / "model.onnx").read_bytes() == files["model.onnx"]
        # a probe says which model, without starting it
        assert engine.embedder.embed([])["model"] == embedder_mod.MODEL_ID and engine.embedder.worker is None
        engine.embedder.save(False)
        assert engine.embedder.status()["state"] == "off"
    finally:
        server.shutdown()


def test_doorman_yaml_wins(tmp_path):
    from conftest import make_engine
    from doorman.plugin_api import Denied

    engine = make_engine(tmp_path, semantic={"enabled": False})
    with pytest.raises(Denied, match="doorman.yaml"):
        engine.embedder.save(True)


def test_owner_api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from soft_authenticator import SoftAuthenticator

    from conftest import make_engine
    from doorman.api.owner import create_owner_app
    from test_api import register

    monkeypatch.setattr(embedder_mod.Embedder, "backend", staticmethod(concept_vectors))
    url = "http://localhost:8711"
    engine = make_engine(tmp_path, public_url=url)  # with the notes plugin, which feeds the search index
    owner = TestClient(create_owner_app(engine), base_url=url)
    register(engine, owner, SoftAuthenticator("localhost", url))
    csrf = {"X-Requested-With": "doorman"}
    off = owner.get("/owner/semantic", headers=csrf).json()
    assert off["state"] == "off" and off["sources"] == [
        {"name": "notes", "items": 0, "pulled": None, "error": None, "skipped": 0, "skip_note": None,
         "embedded": 0, "of": 0}]
    agent = Agent(engine)
    for title in ("Kaution", "Pizza"):
        agent.call("notes.create", {"title": title, "body": f"Alles zu {title}"})
    engine.search.pull("notes")
    on = owner.post("/owner/semantic", headers=csrf, json={"enabled": True}).json()
    assert on["enabled"] and on["state"] == "ready"
    engine.library.run(time.monotonic() + 60)
    status = owner.get("/owner/semantic", headers=csrf).json()
    [notes] = status["sources"]
    assert notes == {**notes, "name": "notes", "items": 2, "error": None, "embedded": 2, "of": 2} and notes["pulled"]
    assert status["index"]["items"] == 2 and status["index"]["summary"] == "2 items indexed"
    assert owner.post("/owner/semantic", headers=csrf, json={"enabled": "yes"}).status_code in (400, 403)


# ------------------------------------------------------------------ the real model, when it's here

REAL = os.environ.get("DOORMAN_EMBED_MODEL_DIR")  # a folder with model.onnx, tokenizer.json, config.json


def real_model(engine):
    """The downloaded model in the engine's model folder, as if Doorman had fetched it."""
    target = engine.embedder.files.model_dir
    target.mkdir(parents=True)
    for name in ("model.onnx", "tokenizer.json", "config.json"):
        source = Path(REAL) / name
        try:
            os.link(source, target / name)
        except OSError:
            shutil.copy(source, target / name)
    sizes = {n: (p, s, (target / n).stat().st_size) for n, (p, s, _) in embedder_mod.MODEL["files"].items()}
    engine.embedder.files.spec = {**embedder_mod.MODEL, "files": sizes}
    engine.embedder.save(True)


@pytest.mark.skipif(not REAL, reason="set DOORMAN_EMBED_MODEL_DIR to a downloaded Granite embedding model")
def test_the_real_model_matches_across_languages(tmp_path):
    from conftest import make_engine

    engine = make_engine(tmp_path, plugin_sandbox=True)
    real_model(engine)
    import numpy as np

    texts = ["Die Mietkaution wird nach dem Auszug zurücküberwiesen.", "Pizza mit Tomaten und Basilikum",
             "rent deposit refund after moving out"]
    out = engine.embedder.embed(texts)
    vectors = np.frombuffer(out["vectors"], dtype="<f2").astype(np.float32).reshape(3, 384)
    sims = vectors @ vectors.T
    assert sims[2, 0] > sims[2, 1] + 0.05, sims
    engine.embedder.stop()


REAL_DOCS = {
    "parcel": "Uw bestelling is verzonden. Track & trace: 3SABC123. Bezorging morgen tussen 9 en 12 uur.",
    "kaution": "Wohnung. Die Mietkaution beträgt drei Monatsmieten und wird nach dem Auszug zurücküberwiesen.",
    "power": "Stromrechnung Oktober. Betrag: 84,20 EUR wird am 15. abgebucht. Stadtwerke Hamburg.",
    "train": "Zugticket Hamburg - Utrecht, ICE 104, Abfahrt 07:12, Wagen 12 Platz 54.",
    "pizza": "Ein Rezept für Pizza mit Tomaten und Basilikum. Den Teig 24 Stunden gehen lassen.",
    "thesis": "Re: Termin Besprechung Masterarbeit. Hallo Robin, können wir uns Donnerstag um 14 Uhr treffen?",
    "tax": "Einkommensteuerbescheid 2025: Erstattung 412 EUR. Das Finanzamt hat Ihre Erklärung geprüft.",
    "spam": "Newsletter: 20% Rabatt auf alle Sneaker nur dieses Wochenende!",
}


@pytest.mark.skipif(not REAL, reason="set DOORMAN_EMBED_MODEL_DIR to a downloaded Granite embedding model")
def test_the_real_model_finds_by_meaning_what_the_old_one_missed(tmp_path):
    """Queries the int8 Granite r2 got wrong on this CPU, through the search index: no shared words, other
    languages."""
    from conftest import FAKE_PLUGINS, make_engine

    items = [{"key": k, "title": "", "text": t} for k, t in REAL_DOCS.items()]
    engine = make_engine(tmp_path, plugin_sandbox=True, plugin_paths=[FAKE_PLUGINS], plugins={
        "notes": {"enabled": False}, "lib": {"type": "fake_library", "enabled": True, "config": {"items": items}}})
    real_model(engine)
    engine.search.pull("lib")
    assert engine.library.run(time.monotonic() + 120)["semantic"] == {"embedded": 8, "of": 8}
    for query, key in (("package delivery", "parcel"), ("rent deposit", "kaution"), ("electricity bill", "power"),
                       ("train ticket to Utrecht", "train"), ("meeting with my supervisor", "thesis")):
        hits = engine.library.search({"query": query}, ["lib"], 3)["hits"]
        assert hits and hits[0]["key"] == key, (query, [(h["key"], h["meaning"]) for h in hits])
    engine.embedder.stop()
