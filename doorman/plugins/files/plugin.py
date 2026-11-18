"""File archive on disk. Paths are always relative to the archive root.

Doorman's search index (doorman/library.py) finds the files: this plugin feeds it (index_feed) from its own
tables in index.db, which the maintenance walk (index) and every write Doorman makes here keep up to date:

    files  what the archive holds: size and mtime (while they stay the same, the file isn't read again), when
           its text was last read (`indexed`, for new_file events) and when anything the search index shows of
           it changed (`changed`: text, place, tags, maker; the feed's cursor)
    texts  each file's extracted text, so a scan is OCRed once, not on every feed or after a move, and for a
           PDF what the structural check for hidden text said as the text was read (`hidden_check`: clean,
           hidden or undecided; extract.py), so a clean PDF is searchable at once
    gone   tombstones: paths moved away, deleted or put in the trash, so the feed can say they're gone
    tags   the owner's and agents' tags (kept here, not in the files)
    made   files an agent kept (files.keep): who, the title, the refs it was made from
    kept   the sha256 of what an agent kept, so `replace` never writes over a version someone changed since
    checks PDFs the OCR check for hidden text has read (the `pdf_check` job, the backstop for every PDF),
           with what it found, and PDFs the structural check found hiding text; search shows no passage of a
           PDF neither check has cleared yet, as files.read never gives its text unchecked

Files in the trash folder aren't searchable: moving one there is a removal for the search index."""

import hashlib
import json
import os
import secrets
import threading
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import httpx

from doorman import clock
from doorman.sanitize import describe
from doorman.plugin_api import BasePlugin, Denied, ExecResult, PluginError, Tool, generic_diff, open_store
from doorman.util import safe_filename

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, size INTEGER, mtime_ns INTEGER, indexed TEXT, changed TEXT);
CREATE INDEX IF NOT EXISTS files_changed ON files(changed);
CREATE INDEX IF NOT EXISTS files_indexed ON files(indexed);
CREATE TABLE IF NOT EXISTS texts (path TEXT PRIMARY KEY, text TEXT NOT NULL, hidden_check TEXT);
CREATE TABLE IF NOT EXISTS gone (path TEXT PRIMARY KEY, at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS gone_at ON gone(at);
CREATE TABLE IF NOT EXISTS tags (path TEXT, tag TEXT, PRIMARY KEY (path, tag));
CREATE TABLE IF NOT EXISTS made (path TEXT PRIMARY KEY, made_by TEXT, title TEXT, based_on TEXT, created TEXT);
CREATE TABLE IF NOT EXISTS kept (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS checks (path TEXT PRIMARY KEY, hidden TEXT);
"""
# Changes to index.db's layout after SCHEMA (version 1), in order (plugin_api.open_store): MIGRATIONS[n] brings
# it from version n + 1 to n + 2. SCHEMA always shows the newest layout. Append; never change one that shipped.
MIGRATIONS: list = [
    # 2: what the structural check for hidden text said of a PDF (NULL: not looked at yet; pdf_check catches up)
    lambda conn: conn.execute("ALTER TABLE texts ADD COLUMN hidden_check TEXT"),
]
PER_PATH = ("files", "texts", "tags", "made", "kept", "checks")  # the tables a move or removal takes along
CHECK_BATCH = 20         # PDFs the pdf_check job looks up at a time
TEXT_CHARS = 300_000     # text kept per file: what the search index keeps of one (library.TEXT_LIMIT)
FEED_ITEMS = 200         # changes per answer of the feed
FEED_CHARS = 4_000_000   # text per answer: a batch of long documents stops early and says `more`
AGENT_FOLDER = "Agent/"  # where files.keep puts an agent's work unless it names a folder (config agent_folder)


class FileTool(Tool):
    def current(self, object_ref):
        state = self.plugin.state(object_ref)
        return state if state["exists"] else None  # gone (to the trash, moved): no object, for drift and undo


class Tag(FileTool):
    FIELD_SCOPED_UNDO = True  # undo sets the tags back and touches nothing else

    def ref_for(self, args):
        return args["path"]

    def snapshot(self, args):
        state = self.plugin.state(args["path"])
        if not state["exists"]:
            raise PluginError(f"no file {args['path']}")
        return state

    def preview(self, args, before):
        tags = (set(before["tags"]) | set(args.get("add", []))) - set(args.get("remove", []))
        return {**before, "tags": sorted(tags)}

    def execute(self, args, before):
        self.plugin.set_tags(args["path"], self.preview(args, before)["tags"])
        after = self.plugin.state(args["path"])
        return ExecResult(result={"path": args["path"], "tags": after["tags"]}, after=after, object_ref=args["path"],
                          summary=f"Tagged {args['path']}: {', '.join(after['tags']) or 'no tags'}")

    def undo(self, object_ref, before, after):
        self.plugin.set_tags(object_ref, before["tags"])

    def describe(self, args):
        return f"Tag {args.get('path')}"


class Move(FileTool):
    FIELD_SCOPED_UNDO = True  # undo moves the file back and touches nothing else

    def destination(self, args, before) -> str:
        target = args["to"].strip("/")
        if args["to"].endswith("/") or self.plugin.resolve(target).is_dir():
            target = f"{target}/{Path(before['path']).name}".strip("/")
        return target

    def snapshot(self, args):
        return Tag.snapshot(self, args)

    def preview(self, args, before):
        return {**before, "path": self.destination(args, before)}

    def execute(self, args, before):
        dest = self.destination(args, before)
        self.plugin.move(before["path"], dest)
        after = self.plugin.state(dest)
        return ExecResult(result={"path": dest}, after=after, object_ref=dest,
                          summary=f"Moved {before['path']} to {dest}")

    def undo(self, object_ref, before, after):
        self.plugin.move(after["path"], before["path"])
        return before["path"]

    def render_diff(self, before, after, args):
        pick = (lambda s: {"path": s["path"]} if s else None)
        return super().render_diff(pick(before), pick(after), args)

    def describe(self, args):
        return f"Move {args.get('path')} to {args.get('to')}"


class Delete(Move):
    def destination(self, args, before) -> str:
        return self.plugin.trash_path(before["path"])

    def describe(self, args):
        return f"Move {args.get('path')} to the trash"


class Save(FileTool):
    """Copies what a reference points at (a mail attachment, an upload, another plugin's file) into the
    archive. Doorman hands over the bytes; the agent only picks where. It never overwrites: a taken name
    gets " (2)". Undo moves the copy to the trash."""

    def destination(self, args, filename: str) -> str:
        target = (args.get("path") or "").strip().strip("/")
        if not target or args["path"].endswith("/") or self.plugin.resolve(target).is_dir():
            target = f"{target}/{filename}".strip("/")
        return self.plugin.free(target)

    def execute(self, args, before):
        filename, content = self.ctx.resolve_ref(args["source"])
        dest = self.destination(args, safe_filename(filename))
        if self.plugin.in_trash(dest):
            raise PluginError("can't save into the trash folder")
        self.plugin.write_new(dest, content)
        self.plugin.index_one(dest)
        after = self.plugin.state(dest)
        return ExecResult(result={"path": dest, "ref": f"{self.ctx.instance}:{dest}", "size": len(content)},
                          after=after, object_ref=dest, summary=f"Saved {filename} as {dest}")

    def undo(self, object_ref, before, after):
        self.plugin.move(object_ref, self.plugin.trash_path(object_ref))

    def render_diff(self, before, after, args):
        pick = (lambda s: {"path": s["path"], "size": s.get("size")} if s else None)
        return super().render_diff(None, pick(after), args)

    def describe(self, args):
        return f"Save {args.get('source')} to the archive{' at ' + args['path'] if args.get('path') else ''}"


class Keep(FileTool):
    """An agent's finished work into the archive: a report, a research summary, a filled-in form, meeting
    notes. Its text (`content`, with a `name`) or what a reference points at (`source`: an upload, a mail
    attachment, another file) becomes a file in the agent folder or where `path` says; who made it (stamped
    by Doorman from the calling key, manifest `caller_arg`), its title and what it was made from (`based_on`)
    go in the `made` table and show with it in search.

    A taken name gets " (2)". `replace` writes over a file at that exact path instead, but only over one an
    agent kept: the owner's own files are never written over. The earlier version goes to the trash, and
    undo brings it back (and moves the new one to the trash)."""

    def prepare(self, args):
        if ("content" in args) == bool(args.get("source")):
            raise Denied("files.keep takes the text as content (with name) or a reference as source, one of them",
                         "invalid")
        dest = self.target(args)  # outside the archive: refused here, before anything is journaled
        if "content" in args and dest is None:
            raise Denied("content needs a file name: name=rent-research.md (or a path that ends in one)", "invalid")
        if args.get("replace") and dest is None:
            raise Denied("replace writes over one file: give its name (name=...) or a path that ends in it", "invalid")
        if self.plugin.in_trash(dest or (args.get("path") or "").strip().strip("/")):
            raise Denied("files.keep doesn't put files into the trash folder", "invalid")
        return args

    def target(self, args, filename: str | None = None) -> str | None:
        """Where it goes: `path` when that names a file; else that folder (the agent folder without a path)
        and `name`, or the source's own name. None while that name isn't known yet (the source unopened)."""
        raw = (args.get("path") or "").strip()
        folder = (raw or self.plugin.agent_folder).strip("/")
        if raw and not raw.endswith("/") and not self.plugin.resolve(folder).is_dir():
            return self.plugin.rel(self.plugin.resolve(folder))
        name = args.get("name") or filename
        if not name:
            return None
        return self.plugin.rel(self.plugin.resolve(f"{folder}/{safe_filename(name)}"))

    def replaceable(self, dest: str) -> dict | None:
        """The file `replace` would write over (its state), None if there's none; refused unless an agent
        kept it and it is still what the agent kept (the owner may have edited it since)."""
        state = self.plugin.state(dest)
        if not state["exists"]:
            if self.plugin.resolve(dest).exists():
                raise Denied(f"{dest} is a folder", "invalid")
            return None
        if not state.get("made_by"):
            raise Denied(f"{dest} wasn't kept by an agent, so it isn't written over; keep without replace and "
                         "the new file gets a name of its own", "not_allowed")
        if not self.plugin.unchanged_since_kept(dest):
            raise Denied(f"{dest} changed since an agent kept it, so it isn't written over; keep without replace "
                         "and the new file gets a name of its own", "not_allowed")
        return state

    def snapshot(self, args):
        if not args.get("replace"):
            return None
        return self.replaceable(self.target(args))

    def preview(self, args, before):
        dest = self.target(args) or f"{(args.get('path') or self.plugin.agent_folder).rstrip('/')}/"
        out = {"path": dest, "title": args.get("title"), "based_on": args.get("based_on"), "made_by": args.get("made_by")}
        if "content" in args:
            out["size"] = len(args["content"].encode())
        return {k: v for k, v in out.items() if v not in (None, [], "")}

    def execute(self, args, before):
        plugin = self.plugin
        if args.get("source"):
            filename, content = self.ctx.resolve_ref(args["source"])
        else:
            filename, content = args["name"], args["content"].encode()
        dest = self.target(args, safe_filename(filename))
        if plugin.in_trash(dest):
            raise PluginError("can't keep a file in the trash folder")
        made_by = args.get("made_by") or "an agent"
        replaced, tags = None, []
        if args.get("replace") and self.replaceable(dest) is not None:
            tags = plugin.tags(dest)  # the owner's tags stay with the file, not with the old version
            replaced = plugin.trash_path(dest)
            plugin.move(dest, replaced)
        else:
            dest = plugin.free(dest)
        try:
            plugin.write_new(dest, content)
        except Exception:
            if replaced:  # nothing new was written: the earlier version goes back
                plugin.move(replaced, dest)
            raise
        plugin.set_made(dest, made_by, args.get("title"), args.get("based_on") or [], hashlib.sha256(content).hexdigest())
        if tags:
            plugin.set_tags(dest, tags)
        plugin.index_one(dest)
        after = plugin.state(dest)
        result = {"path": dest, "ref": f"{self.ctx.instance}:{dest}", "size": len(content), "made_by": made_by}
        if replaced:
            after["_replaced"] = replaced  # where the earlier version is: undo brings it back
            result["replaced"] = f"the earlier version is in the trash ({replaced})"
        return ExecResult(result=result, after=after, object_ref=dest,
                          summary=f"Kept {dest}" + (", replacing the earlier version" if replaced else ""))

    def undo(self, object_ref, before, after):
        self.plugin.move(object_ref, self.plugin.trash_path(object_ref))
        if (after or {}).get("_replaced"):
            self.plugin.move(after["_replaced"], object_ref)

    def render_diff(self, before, after, args):
        fields = ("path", "size", "title", "made_by", "based_on")
        pick = (lambda s: {k: s[k] for k in fields if s.get(k) not in (None, [], "")} if s else None)
        # not run yet (it waits for the owner): what it would make
        lines = generic_diff(None, pick(after) if after else self.preview(args or {}, before))
        if before:
            lines.append({"sign": "-", "field": "replaces",
                          "value": f"{before['path']} ({before.get('size')} bytes, kept by {before.get('made_by')}), "
                                   "now in the trash"})
        return lines

    def describe(self, args):
        what = args.get("name") or args.get("source") or "a file"
        where = f" at {args['path']}" if args.get("path") else ""
        return f"Keep {what} in the archive{where}" + (", replacing the earlier version" if args.get("replace") else "")


class ShareLink(Tool):
    def execute(self, args, before):
        nextcloud = self.plugin.config.get("nextcloud") or {}
        password = self.plugin.credentials.get("nextcloud_password")
        if not nextcloud.get("url") or not password:
            raise PluginError("share links need config.nextcloud.url/user and nextcloud_password in the vault")
        self.plugin.resolve(args["path"], must_exist=True)
        data = {"path": f"{nextcloud.get('path_prefix', '').rstrip('/')}/{args['path']}", "shareType": 3}
        if args.get("expire_days"):
            data["expireDate"] = (date.today() + timedelta(days=args["expire_days"])).isoformat()
        if args.get("password"):
            data["password"] = args["password"]
        response = httpx.post(f"{nextcloud['url'].rstrip('/')}/ocs/v2.php/apps/files_sharing/api/v1/shares",
                              data=data, auth=(nextcloud["user"], password),
                              headers={"OCS-APIRequest": "true", "Accept": "application/json"}, timeout=30)
        if response.status_code >= 400:
            raise PluginError(f"Nextcloud refused the share ({response.status_code})")
        share = response.json()["ocs"]["data"]
        return ExecResult(result={"url": share["url"], "share_id": share["id"]},
                          summary=f"Shared {args['path']} by public link")

    def describe(self, args):
        return f"Create a public link to {args.get('path')}"

    def follow_up(self, args, result):
        return "Delete the share in Nextcloud to stop new downloads; copies already downloaded stay out there."


class Plugin(BasePlugin):
    TOOLS = {"tag": Tag, "move": Move, "delete": Delete, "save": Save, "keep": Keep, "share_link": ShareLink}
    READS = {"list": "read_list", "read": "read_file"}

    def __init__(self, ctx, manifest):
        super().__init__(ctx, manifest)
        if not self.config.get("root"):
            raise PluginError("files: set config.root")
        self.root = Path(self.config["root"]).expanduser().resolve()
        self.trash = self.config.get("trash", ".trash").strip("/")
        self.agent_folder = str(self.config.get("agent_folder") or AGENT_FOLDER)
        self.lock = threading.Lock()
        self.db = open_store(ctx.data_dir / "index.db", SCHEMA, MIGRATIONS, check_same_thread=False)
        # which index.db a feed's cursor belongs to: one made anew (deleted, put back) starts the feed over
        self.db.execute("INSERT OR IGNORE INTO store_info(key, value) VALUES('feed_id', ?)", (secrets.token_hex(8),))
        self.db.commit()
        self.feed_id = self.db.execute("SELECT value FROM store_info WHERE key='feed_id'").fetchone()[0]
        last = self.db.execute("SELECT max(m) FROM (SELECT max(changed) AS m FROM files UNION ALL "
                               "SELECT max(indexed) FROM files UNION ALL SELECT max(at) FROM gone)").fetchone()[0]
        self.last_stamp = datetime.fromisoformat(last) if last else None

    def close(self):
        self.db.close()

    # paths and state

    def resolve(self, rel: str, must_exist: bool = False) -> Path:
        rel = (rel or "").strip().lstrip("/")
        path = (self.root / rel).resolve()
        if path != self.root and not path.is_relative_to(self.root):
            raise PluginError("path is outside the archive")
        if must_exist and not path.exists():
            raise PluginError(f"no file {rel}")
        return path

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def in_trash(self, rel: str) -> bool:
        return rel == self.trash or rel.startswith(self.trash + "/")

    def free(self, rel: str) -> str:
        """rel, or when that's taken the first free of "name (2).pdf", "name (3).pdf"..."""
        path = self.resolve(rel)
        stem, suffix, n = path.stem, path.suffix, 2
        while path.exists():
            path = path.with_name(f"{stem} ({n}){suffix}")
            n += 1
        return self.rel(path)

    def trash_path(self, rel: str) -> str:
        """Where a file goes in the trash: under the moment it went, at its path, free (two in one second)."""
        return self.free(f"{self.trash}/{clock.now().strftime('%Y%m%d-%H%M%S')}/{rel}")

    def write_new(self, rel: str, content: bytes) -> None:
        path = self.resolve(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "xb") as out:  # x: never replace a file that appeared in the meantime
            out.write(content)

    def _stamp(self) -> str:
        """A moment for the feed's cursor, later than every one before (the caller holds the lock): changes
        order by it even when two land in the same microsecond or the clock steps back."""
        moment = clock.now().astimezone(timezone.utc)
        if self.last_stamp is not None and moment <= self.last_stamp:
            moment = self.last_stamp + timedelta(microseconds=1)
        self.last_stamp = moment
        return moment.isoformat(timespec="microseconds")

    def tags(self, rel: str) -> list[str]:
        with self.lock:
            return [r[0] for r in self.db.execute("SELECT tag FROM tags WHERE path=? ORDER BY tag", (rel,))]

    def set_tags(self, rel: str, tags: list[str]) -> None:
        with self.lock, self.db:
            self.db.execute("DELETE FROM tags WHERE path=?", (rel,))
            self.db.executemany("INSERT INTO tags(path, tag) VALUES(?,?)", [(rel, t) for t in sorted(set(tags))])
            self.db.execute("UPDATE files SET changed=? WHERE path=?", (self._stamp(), rel))

    def made(self, rel: str) -> dict | None:
        """Who kept this file (files.keep), its title and what it was made from; None for anyone else's."""
        with self.lock:
            row = self.db.execute("SELECT made_by, title, based_on, created FROM made WHERE path=?", (rel,)).fetchone()
        if row is None:
            return None
        return {"made_by": row[0], "title": row[1], "based_on": json.loads(row[2] or "[]"), "created": row[3]}

    def set_made(self, rel: str, made_by: str, title: str | None, based_on: list[str], sha256: str | None = None) -> None:
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO made(path, made_by, title, based_on, created) VALUES(?,?,?,?,?)",
                            (rel, made_by, title or None, json.dumps(list(based_on), ensure_ascii=False), clock.iso()))
            if sha256:
                self.db.execute("INSERT OR REPLACE INTO kept(path, sha256) VALUES(?,?)", (rel, sha256))
            self.db.execute("UPDATE files SET changed=? WHERE path=?", (self._stamp(), rel))

    def unchanged_since_kept(self, rel: str) -> bool:
        """Whether the file is still what an agent kept there (by its sha256): not after the owner edited it."""
        with self.lock:
            row = self.db.execute("SELECT sha256 FROM kept WHERE path=?", (rel,)).fetchone()
        if row is None:
            return False
        try:
            return hashlib.sha256(self.resolve(rel).read_bytes()).hexdigest() == row[0]
        except OSError:
            return False

    def state(self, rel: str) -> dict:
        path = self.resolve(rel)
        if not path.is_file():
            return {"path": rel, "exists": False}
        stat = path.stat()
        out = {"path": rel, "exists": True, "size": stat.st_size, "mtime_ns": stat.st_mtime_ns, "tags": self.tags(rel)}
        made = self.made(rel)
        if made:
            out.update({k: made[k] for k in ("made_by", "title", "based_on")})
        return out

    def move(self, source: str, dest: str) -> None:
        """Move a file, and with it its text, tags and maker. For the search index the old path is gone and
        the new one is new; into the trash, it's only gone."""
        src, dst = self.resolve(source, must_exist=True), self.resolve(dest)
        if dst.exists():
            raise PluginError(f"{dest} already exists")
        dst.parent.mkdir(parents=True, exist_ok=True)
        os.rename(src, dst)
        with self.lock, self.db:
            for table in PER_PATH:
                self.db.execute(f"DELETE FROM {table} WHERE path=?", (dest,))
                self.db.execute(f"UPDATE {table} SET path=? WHERE path=?", (dest, source))
            self.db.execute("DELETE FROM gone WHERE path=?", (dest,))
            if not self.in_trash(source):
                self.db.execute("INSERT OR REPLACE INTO gone(path, at) VALUES(?,?)", (source, self._stamp()))
            known = self.db.execute("UPDATE files SET changed=? WHERE path=?", (self._stamp(), dest)).rowcount
        if not known and not self.in_trash(dest):
            self.index_one(dest)  # a file that came in after the last walk

    def check(self):
        return None if self.root.is_dir() else f"the archive folder {self.root} isn't there"

    # the plugin's own index: files and their texts

    def maintenance(self):
        self.index()

    def index_one(self, rel: str) -> None:
        """Read a file Doorman just wrote, so the next feed hands it to search before the next walk."""
        path = self.resolve(rel)
        self._write(rel, self.first_read(path, ocr=bool(self.config.get("ocr"))), path.stat())

    def first_read(self, path: Path, ocr: bool) -> dict:
        """A file's text as the walk reads it: with the structural check of a PDF for hidden text, which takes
        milliseconds a page (the OCR check is the pdf_check job's)."""
        return self.text_of(path, ocr=ocr, check_pdf=self.checking() and "fast")

    def _write(self, rel: str, found: dict, stat) -> None:
        text = found.get("text") or ""
        glance = self.glance(rel, found)
        hidden = (found.get("report") or {}).get("hidden_text") if glance == "hidden" else None
        with self.lock, self.db:
            stamp = self._stamp()
            self.db.execute("INSERT OR REPLACE INTO files(path, size, mtime_ns, indexed, changed) VALUES(?,?,?,?,?)",
                            (rel, stat.st_size, stat.st_mtime_ns, stamp, stamp))
            self.db.execute("INSERT OR REPLACE INTO texts(path, text, hidden_check) VALUES(?,?,?)",
                            (rel, text[:TEXT_CHARS], glance))
            self.db.execute("DELETE FROM checks WHERE path=?", (rel,))  # a new text: checked again
            if hidden:  # held at once; OCR has nothing to add
                self.db.execute("INSERT INTO checks(path, hidden) VALUES(?,?)", (rel, json.dumps(hidden)))
            self.db.execute("DELETE FROM gone WHERE path=?", (rel,))

    def glance(self, rel: str, found: dict) -> str | None:
        """What the structural check said of a PDF that has text: clean, hidden or undecided (also when it
        couldn't look); None for anything else, or with check_hidden_text off."""
        if not (self.checking() and rel.lower().endswith(".pdf") and (found.get("text") or "").strip()):
            return None
        return found.get("hidden_check") or "undecided"

    # the hidden-text check (the pdf_check job)

    def checking(self) -> bool:
        """Whether PDFs are checked for hidden text (check_hidden_text, the owner's; default on)."""
        return bool(self.config.get("check_hidden_text", True))

    def run_job(self, name, budget):
        if name != "pdf_check":
            raise PluginError(f"no job {name}")
        return self.check_pdfs(float(budget))

    def unchecked(self, limit: int | None = None, glance: bool = False) -> list[str]:
        """PDFs with text the OCR check for hidden text hasn't read, the newest first; `glance`: those the
        structural check hasn't looked at either (read before it, or while check_hidden_text was off)."""
        with self.lock:
            rows = self.db.execute(
                "SELECT f.path FROM files f JOIN texts t ON t.path = f.path LEFT JOIN checks c ON c.path = f.path "
                "WHERE c.path IS NULL AND lower(f.path) LIKE '%.pdf' AND t.text != ''"
                + (" AND t.hidden_check IS NULL" if glance else "") + " ORDER BY f.mtime_ns DESC"
                + (" LIMIT ?" if limit else ""), (limit,) if limit else ()).fetchall()
        return [r[0] for r in rows if not self.in_trash(r[0])]

    def check_pdfs(self, budget: float) -> dict:
        """The OCR check for hidden text, the backstop for every PDF the walk found with text: newest first, as
        background work that steps aside for the agent's reads. It renders a page or two and reads them with
        OCR (about 4 s a page), which is why it isn't part of the walk; the walk's structural check (milliseconds
        a page) already decided most PDFs, so search waits for this only for those it couldn't. What it finds is
        kept (checks) and goes to search with the file's next feed: the guard holds back a hit of a PDF with
        hidden text, as it does files.read. First, quickly, the structural check of PDFs read before it."""
        if not self.checking():
            return {"summary": "check_hidden_text is off"}
        deadline = time.monotonic() + max(1.0, budget - 10)
        checked = 0
        for glance in (True, False):
            while time.monotonic() < deadline:
                batch = self.unchecked(CHECK_BATCH, glance=glance)
                if not batch:
                    break
                for rel in batch:
                    if time.monotonic() >= deadline:
                        break
                    try:
                        found = self.text_of(self.resolve(rel), ocr=False, check_pdf="fast" if glance else True,
                                             background=True)
                    except Exception as exc:  # noqa: BLE001 - a check that can't run says nothing, as in files.read
                        self.ctx.log.warning("the hidden-text check of %s failed: %s", rel, exc)
                        found = {}
                    if found.get("busy"):  # an agent is reading: the rest next time
                        return self._check_status(checked)
                    self._checked(rel, found, glance)
                    checked += 1
        return self._check_status(checked)

    def _checked(self, rel: str, found: dict, glance: bool) -> None:
        """Keep what a check found. The structural one only says clean, hidden or undecided (`hidden_check`;
        hidden is held at once); the OCR one is done with the PDF either way (checks). Search is fed the file
        again when what it may show changed."""
        hidden = (found.get("report") or {}).get("hidden_text")
        outcome = found.get("hidden_check") or "undecided"
        with self.lock, self.db:
            before = self.db.execute("SELECT hidden_check FROM texts WHERE path=?", (rel,)).fetchone()
            shown = bool(before) and before[0] == "clean"
            if glance:
                self.db.execute("UPDATE texts SET hidden_check=? WHERE path=?", (outcome, rel))
                if hidden:
                    self.db.execute("INSERT OR REPLACE INTO checks(path, hidden) VALUES(?,?)", (rel, json.dumps(hidden)))
                changed = outcome in ("clean", "hidden")
            else:
                self.db.execute("INSERT OR REPLACE INTO checks(path, hidden) VALUES(?,?)",
                                (rel, json.dumps(hidden) if hidden else None))
                changed = bool(hidden) or not shown
            if changed:
                self.db.execute("UPDATE files SET changed=? WHERE path=?", (self._stamp(), rel))

    def _check_status(self, checked: int) -> dict:
        left = len(self.unchecked())
        summary = f"{left} PDFs wait for the hidden-text check" if left else "every PDF is checked for hidden text"
        return {"summary": summary, "checked": checked, "more": bool(left and checked)}

    def index(self) -> dict:
        """The walk: every file in the archive (not hidden ones, not the trash) against the files table. A new
        or changed file has its text read and kept; an unchanged one costs a lookup. A file that's no longer
        there leaves a tombstone for the search feed and takes its tags and maker along: a new file at its
        path is someone else's."""
        ocr = bool(self.config.get("ocr"))
        seen, added = set(), 0
        for dirpath, dirnames, filenames in os.walk(self.root):
            current = Path(dirpath)
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and not self.in_trash(self.rel(current / d))]
            for filename in filenames:
                if filename.startswith("."):
                    continue
                path = current / filename
                rel = self.rel(path)
                try:
                    stat = path.stat()
                except OSError:  # gone since the folder was listed
                    continue
                seen.add(rel)
                with self.lock:
                    row = self.db.execute("SELECT f.size, f.mtime_ns, t.path IS NOT NULL FROM files f LEFT JOIN texts t "
                                          "ON t.path = f.path WHERE f.path=?", (rel,)).fetchone()
                if row is not None and tuple(row) == (stat.st_size, stat.st_mtime_ns, 1):
                    continue
                self._write(rel, self.first_read(path, ocr=ocr), stat)
                added += 1
        with self.lock:
            known = [r[0] for r in self.db.execute("SELECT path FROM files")]
        # the trash isn't walked, and a file Doorman moved while the walk ran wasn't seen where it is now
        gone = [p for p in known if p not in seen and not self.resolve(p).is_file()]
        with self.lock, self.db:
            for rel in gone:
                for table in PER_PATH:
                    self.db.execute(f"DELETE FROM {table} WHERE path=?", (rel,))
                if not self.in_trash(rel):
                    self.db.execute("INSERT OR REPLACE INTO gone(path, at) VALUES(?,?)", (rel, self._stamp()))
        return {"indexed": added, "removed": len(gone), "total": len(seen)}

    # Doorman's search index (library.py)

    def index_feed(self, cursor, budget):
        """What changed for Doorman's search index since `cursor` ("<feed_id>|<_stamp>"; None: from the
        start): files whose text, place, tags or maker changed, and the paths in `gone`. A file in the trash
        isn't handed over; moving it there left a tombstone. The text comes from the texts table: nothing is
        read again. A cursor of another index.db (this one made anew) starts over with `reset`: everything
        again, and the search index drops what doesn't come."""
        deadline = time.monotonic() + max(1.0, float(budget))
        mine, mark, after = (cursor or "").partition("|")
        reset = bool(cursor) and not (mark and mine == self.feed_id)
        since = "" if reset else after
        with self.lock:
            changed = self.db.execute("SELECT changed, path FROM files WHERE changed > ? ORDER BY changed LIMIT ?",
                                      (since, FEED_ITEMS + 1)).fetchall()
            gone = self.db.execute("SELECT at, path FROM gone WHERE at > ? ORDER BY at LIMIT ?",
                                   (since, FEED_ITEMS + 1)).fetchall()
        changes = sorted([(stamp, False, path) for stamp, path in changed] + [(at, True, path) for at, path in gone])
        more = len(changes) > FEED_ITEMS
        items, removed, chars, last = [], [], 0, since
        for stamp, is_gone, path in changes[:FEED_ITEMS]:
            if (items or removed) and (chars > FEED_CHARS or time.monotonic() > deadline):
                more = True
                break
            if is_gone:
                removed.append(path)
            elif not self.in_trash(path):
                item = self.feed_item(path)
                if item is not None:
                    items.append(item)
                    chars += len(item["text"])
            last = stamp
        out = {"items": items, "removed": removed, "cursor": f"{self.feed_id}|{last}" if last else None, "more": more}
        if reset:
            out["reset"] = True
        return out

    def feed_item(self, rel: str) -> dict | None:
        """One file as the search index keeps it; its `fields` show with each hit as they are, `name` among
        them as files.read has it (a word in it hides the hit, as it hides the read). A PDF carries what the
        hidden-text checks found, or that neither has cleared it yet (no passage until then)."""
        with self.lock:
            row = self.db.execute("SELECT f.size, f.mtime_ns, t.text, c.path IS NOT NULL, c.hidden, t.hidden_check "
                                  "FROM files f LEFT JOIN texts t ON t.path = f.path LEFT JOIN checks c ON "
                                  "c.path = f.path WHERE f.path=?", (rel,)).fetchone()
        if row is None:
            return None
        size, mtime_ns, text, checked, hidden, glance = row
        fields = {"path": rel, "name": Path(rel).name, "size": size}
        tags = self.tags(rel)
        if tags:
            fields["tags"] = tags
        made = self.made(rel)
        if made:
            fields["made_by"] = made["made_by"]
            if made["based_on"]:
                fields["based_on"] = made["based_on"]
        folder = Path(rel).parent.as_posix()
        item = {"key": rel, "ref": f"{self.ctx.instance}:{rel}", "kind": "file",
                # an agent's title says more than its file name; the path is in the fields either way
                "title": (made or {}).get("title") or Path(rel).name,
                "date": datetime.fromtimestamp((mtime_ns or 0) / 1e9, timezone.utc).isoformat(timespec="seconds"),
                "in": None if folder == "." else folder, "text": text or "", "fields": fields}
        if self.checking() and rel.lower().endswith(".pdf") and (text or "").strip():
            if hidden:
                item["hidden_text"] = json.loads(hidden)
            elif not checked and glance != "clean":
                item["unchecked"] = True
        return item

    def poll_events(self, cursor):
        """new_file for each file whose text was read since the last poll: new in the archive, or changed. The
        cursor is the latest such moment (`indexed`); the first poll starts from now. At most 200 per poll;
        the rest come with the next one. A file an agent kept says who (made_by)."""
        with self.lock:
            if cursor is None:
                return [], self.db.execute("SELECT MAX(indexed) FROM files").fetchone()[0] or ""
            rows = self.db.execute("SELECT f.path, f.size, f.indexed, m.made_by FROM files f LEFT JOIN made m "
                                   "ON m.path = f.path WHERE f.indexed > ? ORDER BY f.indexed LIMIT 200",
                                   (cursor,)).fetchall()
        events = [{"type": "new_file", "ref": f"{self.ctx.instance}:{path}", "path": path, "size": size,
                   **({"made_by": made_by} if made_by else {})}
                  for path, size, _, made_by in rows if not self.in_trash(path)]
        return events, rows[-1][2] if rows else cursor

    # reads

    def _item(self, rel: str) -> dict:
        state = self.state(rel)
        modified = datetime.fromtimestamp(state["mtime_ns"] / 1e9, timezone.utc).isoformat(timespec="seconds") \
            if state["exists"] else None
        out = {"path": rel, "ref": f"{self.ctx.instance}:{rel}", "name": Path(rel).name,
               "size": state.get("size"), "modified": modified, "tags": state.get("tags", [])}
        out.update({k: state[k] for k in ("made_by", "title", "based_on") if state.get(k)})
        return out

    def read_list(self, params):
        directory = self.resolve(params.get("path", ""), must_exist=True)
        if not directory.is_dir():
            raise PluginError("not a folder")
        entries = []
        for child in sorted(directory.iterdir()):
            if child.name.startswith("."):
                continue
            if child.is_dir():
                entries.append({"path": self.rel(child), "type": "folder"})
            else:
                entries.append({**self._item(self.rel(child)), "type": "file"})
        return entries

    def text_of(self, path: Path, ocr: bool, limit: int = TEXT_CHARS, check_pdf: bool | str = False,
                background: bool = False) -> dict:
        try:
            content = path.read_bytes()
        except OSError as exc:
            return {"text": "", "report": {}, "note": f"can't read it: {type(exc).__name__}"}
        if background:
            return self.ctx.extract_text(path.name, content, None, ocr, limit, check_pdf, background=True)
        return self.ctx.extract_text(path.name, content, None, ocr, limit, check_pdf)

    def read_file(self, params):
        path = self.resolve(params["path"], must_exist=True)
        limit = params.get("max_chars", 20000)
        found = self.text_of(path, ocr=True, limit=limit + 1,
                             check_pdf=bool(self.config.get("check_hidden_text", True)))
        text = found.get("text") or ""
        out = {**self._item(params["path"]), "text": text[:limit], "truncated": len(text) > limit}
        out.update({k: found[k] for k in ("pages", "ocr_pages", "note") if found.get(k)})
        report = dict(found.get("report") or {})
        hidden = report.pop("hidden_text", None)
        if hidden:
            out["hidden_text"] = hidden  # the guard holds this back for the owner (engine._scan_item)
        if describe(report):
            out["sanitized"] = describe(report)
        return out

    def open_ref(self, path):
        resolved = self.resolve(path, must_exist=True)
        if not resolved.is_file():
            raise PluginError(f"{path} is not a file")
        return resolved.name, resolved.read_bytes()
