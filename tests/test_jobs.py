"""What the mail archive needs from Doorman: plugin jobs, background extraction that steps aside, backups that
hard-link originals and leave out rebuildable indexes, and the common search over the agent API."""

import asyncio
import os
import time

from fastapi.testclient import TestClient

from doorman import backup, clock, extractor, spotlight
from doorman.api.agent import create_agent_app
from doorman.plugin_api import Denied
from doorman.server import _job, start_jobs
from conftest import Agent, make_engine


# ------------------------------------------------------------------ backups


def test_backups_hard_link_immutable_files_and_skip_rebuildable_ones(tmp_path):
    engine = make_engine(tmp_path)
    plugin = tmp_path / "data" / "plugins" / "mail" / "archive"
    (plugin / "eml" / "ab").mkdir(parents=True)
    (plugin / "eml" / ".immutable").touch()
    (plugin / "eml" / "ab" / "abc.eml.gz").write_bytes(b"original one")
    (plugin / "cache").mkdir()
    (plugin / "cache" / ".no-backup").touch()
    (plugin / "cache" / "index.db").write_bytes(b"rebuildable")
    (plugin / "archive.db").write_bytes(b"metadata v1")
    dest = tmp_path / "backups"
    first = backup.make_backup(engine.config.data_dir, None, dest)
    clock.advance(2)
    (plugin / "eml" / "ab" / "abd.eml.gz").write_bytes(b"original two")
    (plugin / "archive.db").write_bytes(b"metadata v2")
    second = backup.make_backup(engine.config.data_dir, None, dest)

    rel = "data/plugins/mail/archive"
    assert not (first / rel / "cache").exists() and not (second / rel / "cache").exists()
    one_before, one_after = first / rel / "eml/ab/abc.eml.gz", second / rel / "eml/ab/abc.eml.gz"
    assert os.stat(one_before).st_ino == os.stat(one_after).st_ino   # linked, not copied
    assert (second / rel / "eml/ab/abd.eml.gz").read_bytes() == b"original two"
    assert os.stat(first / rel / "archive.db").st_ino != os.stat(second / rel / "archive.db").st_ino
    assert (second / rel / "archive.db").read_bytes() == b"metadata v2"
    backup.verify(second)
    # pruning the first leaves the second whole
    backup.prune(dest, 1)
    assert not first.exists() and one_after.read_bytes() == b"original one"
    backup.verify(second)


# ------------------------------------------------------------------ the extractor steps aside


class FakeWorker:
    def __init__(self):
        self.calls = []

    def alive(self):
        return True

    def call(self, message, timeout):
        self.calls.append(message)
        return {"text": "ok", "report": {}}


def test_background_extraction_waits_for_the_agent(tmp_path, monkeypatch):
    engine = make_engine(tmp_path)
    ex = engine.extractor
    worker = FakeWorker()
    monkeypatch.setattr(ex, "_worker", lambda background=False: worker)
    monkeypatch.setattr(extractor, "BACKGROUND_WAIT", 0.6)
    pdf = b"%PDF-1.4"
    assert ex.extract("a.pdf", pdf)["text"] == "ok"          # an agent read: runs at once
    busy = ex.extract("b.pdf", pdf, background=True)          # right after it: steps aside
    assert busy["busy"] and len(worker.calls) == 1
    ex.last_interactive = time.monotonic() - 10                # quiet for 10 s: text layers may go
    assert ex.extract("c.pdf", pdf, ocr=False, background=True)["text"] == "ok"
    assert ex.extract("d.pdf", pdf, ocr=True, background=True)["busy"]   # OCR waits for a quiet minute
    ex.last_interactive = time.monotonic() - 61
    assert ex.extract("e.pdf", pdf, ocr=True, background=True)["text"] == "ok"


# ------------------------------------------------------------------ jobs


class JobPlugin:
    def __init__(self, results):
        self.results = results
        self.runs = []

    def run_job(self, name, budget):
        self.runs.append((name, budget))
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def test_jobs_run_in_the_background_and_report(tmp_path, monkeypatch):
    engine = make_engine(tmp_path)
    plugin = JobPlugin([{"summary": "first", "more": True}, {"summary": "second"}])
    listed = [{"name": "box", "enabled": True, "config": {}, "jobs": [{"name": "archive", "every_minutes": 5,
                                                                         "budget_seconds": 7}]},
              {"name": "quiet", "enabled": True, "config": {"archive": "off"},
               "jobs": [{"name": "archive", "off_when": {"archive": "off"}}]},
              {"name": "asleep", "enabled": False, "config": {}, "jobs": [{"name": "archive"}]}]
    monkeypatch.setattr(engine.registry, "list", lambda: listed)
    monkeypatch.setattr(engine.registry, "instance", lambda name: plugin)

    async def run():
        last, running = {}, {}
        assert start_jobs(engine, last, running) == ["box.archive"]
        assert start_jobs(engine, last, running) == []        # running, then not due for 5 minutes
        await asyncio.sleep(0.2)
        assert running == {} and plugin.runs == [("archive", 7.0)]
        assert engine.job_status("box")["archive"]["status"]["summary"] == "first"
        # more to do: comes back in half a minute instead of five
        assert last[("box", "archive")] < time.monotonic() - 60 * 5 + 31
        last[("box", "archive")] -= 30
        assert start_jobs(engine, last, running) == ["box.archive"]
        await asyncio.sleep(0.2)
        assert engine.job_status("box")["archive"]["status"]["summary"] == "second"

    asyncio.run(run())


def test_a_job_can_return_events(tmp_path, monkeypatch):
    """What is too heavy to poll for every few minutes comes with a job's run: the events go into the feed
    and to the triggers, and the status the owner sees keeps only how many there were."""
    engine = make_engine(tmp_path)
    plugin = JobPlugin([{"summary": "2 new", "events": [
        {"type": "posted", "ref": "box:1", "title": "Exam moved"},
        {"type": "undeclared", "ref": "box:2"}]}])
    monkeypatch.setattr(engine.registry, "instance", lambda name: plugin)
    monkeypatch.setattr(engine.registry, "manifest", lambda name: {"events": [
        {"name": "posted", "fields": ["title"], "job": "check"}], "jobs": [{"name": "check"}]})
    engine.db.exec("INSERT INTO triggers(name, plugin, event, match, task_text, enabled) VALUES"
                   "('moved','box','posted','{}','Look at {title}',1)")
    asyncio.run(_job(engine, "box", {"name": "check"}, {}))
    assert engine.job_status("box")["check"]["status"] == {"summary": "2 new", "events": 1}
    [row] = engine.db.all("SELECT * FROM events")
    assert (row["plugin"], row["type"], row["ref"]) == ("box", "posted", "box:1")
    [task] = engine.db.all("SELECT * FROM tasks")
    assert task["text"] == "Look at Exam moved" and task["origin"] == "trigger:moved"


def test_a_job_failing_for_an_hour_needs_attention(tmp_path):
    engine = make_engine(tmp_path)
    engine.job_done("box", "archive", None, "login refused")
    assert not engine.attention_list()
    clock.advance(2 * 3600)
    engine.job_done("box", "archive", None, "login refused")
    [item] = engine.attention_list()
    assert item["kind"] == "job" and "box.archive" in item["title"]
    engine.job_done("box", "archive", {"summary": "ok"})
    assert not engine.attention_list()
    assert engine.job_status("box")["archive"]["status"] == {"summary": "ok"}


def test_a_dismissed_job_error_stays_quiet_until_the_job_works_again(tmp_path):
    engine = make_engine(tmp_path)
    try:
        engine.dismiss_job_error("box", "archive")
        raise AssertionError("dismissed a job that isn't failing")
    except Denied:
        pass
    engine.job_done("box", "archive", None, "login refused")
    clock.advance(2 * 3600)
    engine.job_done("box", "archive", None, "login refused")
    assert engine.attention_list()
    engine.dismiss_job_error("box", "archive")
    assert engine.job_status("box")["archive"]["dismissed"] is True
    assert not engine.attention_list()
    clock.advance(3600)
    engine.job_done("box", "archive", None, "login refused again")  # still failing: no new item
    assert not engine.attention_list() and engine.job_status("box")["archive"]["dismissed"] is True
    engine.job_done("box", "archive", {"summary": "ok"})
    engine.job_done("box", "archive", None, "broken once more")
    clock.advance(2 * 3600)
    engine.job_done("box", "archive", None, "broken once more")
    assert engine.job_status("box")["archive"]["dismissed"] is False
    [item] = engine.attention_list()
    # dismissing it in the inbox keeps it quiet too
    engine.resolve_attention(item_id=item["id"])
    clock.advance(3600)
    engine.job_done("box", "archive", None, "broken once more")
    assert not engine.attention_list() and engine.job_status("box")["archive"]["dismissed"] is True


# ------------------------------------------------------------------ the common search, over the agent API


def test_search_over_the_agent_api(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    (files / "lease.txt").write_text("Mietvertrag Wohnung 3B")
    engine = make_engine(tmp_path, plugins={"files": {"enabled": True, "config": {"root": str(files)}},
                                            "notes": {"enabled": True}})
    engine.registry.instance("files").maintenance()
    engine.search.pull("files")
    agent = Agent(engine)
    made = agent.call("notes.create", {"title": "Wohnung 3B", "body": "Mietvertrag unterschrieben", "tags": ["home"]})
    engine.search.pull("notes")
    client = TestClient(create_agent_app(engine))
    headers = {"Authorization": f"Bearer {agent.token}"}
    caps = client.get("/v1/capabilities", headers=headers).json()
    assert sorted(caps["search"]["sources"], key=lambda x: x["name"]) == [
        {"name": "files", "kinds": ["file"]}, {"name": "notes", "kinds": ["note"]}]
    found = client.post("/v1/read/search", headers=headers, json={"query": "Mietvertrag"})
    assert found.status_code == 200, found.text
    body = found.json()
    hits = spotlight.unmark((body.get("data") or body)["results"])  # spaces come datamarked (spotlight.py)
    assert {h["ref"] for h in hits} == {"files:lease.txt", f"notes:{made['result']['id']}"}
    hit = next(h for h in hits if h["source"] == "notes")
    assert hit["title"] == "Wohnung 3B" and hit["tags"] == ["home"]
    assert hit["passage"] == "Mietvertrag unterschrieben"
    refused = client.post("/v1/read/search", headers=headers, json={"limit": 5})
    assert refused.status_code in (400, 403, 422) and "query" in refused.text
