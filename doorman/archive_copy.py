"""Copying into the archive: files a plugin downloads into its own folder (course material, say) that
Doorman copies into the files archive, where search, OCR and files.read work on them. The plugin can't write there itself: it runs as
its own user, and the archive belongs to Doorman. Doorman can read the plugin's folder (group doorman, see
privsep.prepare_folder), so it copies, the way files.save copies a mail attachment.

A manifest declares them:

    copy_to_archive:
      - from: downloads                     # a folder in the plugin's own folder
        to: Invoices                        # where in the files archive, by default
        setting: archive_into               # the owner's override: <files plugin>:<folder>, or off
        after: [fetch, sync]                # the jobs and tools whose runs refresh it

The default archive is the first switched-on files plugin.

The plugin's folder is untrusted: a plugin gone bad could plant a link to Doorman's database or vault
there and wait for Doorman to copy it into the archive, where the agent reads it. So only regular files
are copied, opened relative to their folder without following any link (os.fwalk, O_NOFOLLOW), and a
file with more than one hard link is skipped (a hard link to a file Doorman owns looks regular). Names
starting with a dot stay behind. Files only arrive and change: one deleted at the source stays in the
archive.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .plugin_api import PluginError

CHUNK = 1 << 20


def _target_dir(root: Path, parts: tuple[str, ...]) -> Path | None:
    """root/parts, made where missing; None when a part is a link or a file."""
    path = root
    for part in parts:
        path = path / part
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            path.mkdir()
            continue
        if not stat.S_ISDIR(st.st_mode):
            return None
    return path


def mirror(source: Path, target: Path) -> dict:
    """Copy new and changed files below source to target (made if missing). A copy keeps the source's
    modification time, so the next run sees it unchanged by size and time. Returns counts."""
    counts = {"copied": 0, "unchanged": 0, "skipped": 0}
    try:
        if not stat.S_ISDIR(os.lstat(source).st_mode):
            return counts
    except FileNotFoundError:
        return counts
    target.mkdir(parents=True, exist_ok=True)
    for dirpath, dirnames, filenames, dirfd in os.fwalk(source, follow_symlinks=False):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        rel = Path(dirpath).relative_to(source).parts
        if any(part.startswith(".") for part in rel):
            continue
        out_dir = None
        for name in filenames:
            if name.startswith("."):
                continue
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
            except OSError:  # a link (ELOOP), or gone
                counts["skipped"] += 1
                continue
            with os.fdopen(fd, "rb") as src:
                st = os.fstat(src.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    counts["skipped"] += 1
                    continue
                if out_dir is None:
                    out_dir = _target_dir(target, rel)
                if out_dir is None:
                    counts["skipped"] += 1
                    continue
                dest = out_dir / name
                try:
                    have = os.lstat(dest)
                except FileNotFoundError:
                    have = None
                if have is not None and not stat.S_ISREG(have.st_mode):
                    counts["skipped"] += 1
                    continue
                if have is not None and have.st_size == st.st_size and have.st_mtime_ns == st.st_mtime_ns:
                    counts["unchanged"] += 1
                    continue
                part = out_dir / f".{name}.part"
                try:
                    with open(part, "wb") as out:
                        while chunk := src.read(CHUNK):
                            out.write(chunk)
                    os.utime(part, ns=(st.st_atime_ns, st.st_mtime_ns))
                    os.replace(part, dest)
                except BaseException:
                    part.unlink(missing_ok=True)
                    raise
                counts["copied"] += 1
    return counts


def target(registry, instance: str, spec: dict) -> tuple[str, Path] | None:
    """(name, folder) in the files archive a copy goes to; None when it's off or there's no archive."""
    block = registry.configured().get(instance) or {}
    value = str((block.get("config") or {}).get(spec.get("setting") or "", "") or "").strip()
    if value.lower() == "off":
        return None
    plugin, _, folder = value.partition(":")
    folder = (folder or spec.get("to") or instance).strip("/")
    parts = Path(folder).parts
    if not parts or any(p in (".", "..") or p.startswith(".") for p in parts):
        raise PluginError(f"{spec.get('setting')}: {folder!r} isn't a folder name inside the archive")
    archives = sorted(name for name, b in registry.configured().items() if b.get("type") == "files")
    if not plugin:
        plugin = next((name for name in archives if registry.state(name)["enabled"]), "")
        if not plugin:
            return None
    if plugin not in archives:
        raise PluginError(f"{spec.get('setting')}: there is no files plugin named {plugin}")
    root = (registry.configured()[plugin].get("config") or {}).get("root")
    if not registry.state(plugin)["enabled"] or not root:
        return None
    return f"{plugin}:{folder}", Path(root).expanduser() / folder


def copy_after(registry, data_dir: Path, instance: str, after: str) -> dict | None:
    """The copies a run of job or tool `after` refreshes: copy what's new. Counts summed over them, with
    where they went; None when none applies."""
    total = None
    for spec in registry.manifest(instance).get("copy_to_archive") or []:
        if after not in (spec.get("after") or []):
            continue
        where = target(registry, instance, spec)
        if where is None:
            continue
        counts = mirror(data_dir / "plugins" / instance / spec["from"], where[1])
        total = total or {"into": [], "copied": 0, "unchanged": 0, "skipped": 0}
        total["into"].append(where[0])
        for key, value in counts.items():
            total[key] += value
    return total
