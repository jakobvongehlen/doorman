"""The file archive is on from the first start: a new Doorman (a database made just now) starts with the
files plugin switched on, and an archive without a `root` lives in `archive/` inside the data directory."""

from pathlib import Path

import pytest
import yaml

from doorman import clock, config
from doorman.admin import EXAMPLE
from doorman.engine import Engine
from doorman.registry import STARTER_PLUGINS, Registry

REPO = Path(__file__).resolve().parent.parent


def _engine(tmp_path: Path, **settings) -> Engine:
    clock.reset()
    path = tmp_path / "doorman.yaml"
    path.write_text(yaml.safe_dump({"data_dir": "./data", "vault_key_file_warn": False, **settings}))
    return Engine(config.load(path))


def _root(engine: Engine, name: str) -> Path:
    return Path(engine.registry.configured()[name]["config"]["root"])


def test_a_new_doorman_starts_with_the_archive_and_notes(tmp_path, monkeypatch):
    monkeypatch.setattr(Registry, "starter", STARTER_PLUGINS)
    engine = _engine(tmp_path)
    assert list(engine.registry.configured()) == ["notes", "files"]
    assert engine.registry.state("files")["enabled"] and engine.registry.state("notes")["enabled"]
    root = _root(engine, "files")
    assert root == (tmp_path / "data" / "archive").resolve() and root.is_dir()
    # the owner removes one: it stays removed, the next start isn't a new Doorman
    engine.plugin_setup.remove("notes")
    assert list(_engine(tmp_path).registry.configured()) == ["files"]


@pytest.mark.parametrize("example", [EXAMPLE, REPO / "deploy" / "doorman.example.yaml"])
def test_the_example_config_starts(tmp_path, example):
    """The example (what a new install copies) defines no plugins, so Doorman starts with it."""
    target = tmp_path / "doorman.yaml"
    target.write_text(example.read_text())
    assert "plugins" not in yaml.safe_load(target.read_text())
    assert config.load(target).data_dir == (tmp_path / "data").resolve()


def test_archive_without_root_goes_into_the_data_dir(tmp_path):
    engine = _engine(tmp_path)
    engine.registry.put_plugin("files", {"enabled": True})
    assert _root(engine, "files") == (tmp_path / "data" / "archive").resolve()
    assert _root(engine, "files").is_dir()


def test_relative_root_is_relative_to_the_config_file(tmp_path, monkeypatch):
    monkeypatch.chdir("/")
    engine = _engine(tmp_path)
    engine.registry.put_plugin("files", {"enabled": True, "config": {"root": "my-archive"}})
    assert _root(engine, "files") == (tmp_path / "my-archive").resolve()
    assert (tmp_path / "my-archive").is_dir()


def test_absolute_root_is_kept(tmp_path):
    elsewhere = tmp_path / "srv" / "archive"
    engine = _engine(tmp_path)
    engine.registry.put_plugin("files", {"enabled": True, "config": {"root": str(elsewhere)}})
    assert _root(engine, "files") == elsewhere and elsewhere.is_dir()


def test_another_instance_of_the_files_type_gets_its_own_folder(tmp_path):
    engine = _engine(tmp_path)
    engine.registry.put_plugin("files", {"enabled": True})
    engine.registry.put_plugin("scans", {"type": "files", "enabled": True})
    assert _root(engine, "scans") == (tmp_path / "data" / "archive-scans").resolve()


def test_other_plugins_are_untouched(tmp_path):
    engine = _engine(tmp_path)
    engine.registry.put_plugin("notes", {"enabled": True, "config": {"root": "x"}})
    assert engine.registry.configured()["notes"]["config"]["root"] == "x"


def test_example_config_has_no_duplicate_keys():
    """YAML keeps the last of two equal keys without a word; a block pasted twice would hide the first."""

    class Strict(yaml.SafeLoader):
        pass

    def mapping(loader, node, deep=False):
        keys = [loader.construct_object(k, deep=deep) for k, _ in node.value]
        duplicates = {k for k in keys if keys.count(k) > 1}
        assert not duplicates, f"duplicate keys {duplicates} at line {node.start_mark.line + 1}"
        return loader.construct_mapping(node, deep)

    Strict.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    yaml.load(EXAMPLE.read_text(), Loader=Strict)


def test_archive_added_in_the_app_without_root_works(tmp_path):
    """The owner adds the files plugin in the app and leaves its settings empty: it starts, with its archive
    in the data directory, instead of failing with "set config.root"."""
    clock.reset()
    engine = Engine(config.load(overrides={"data_dir": str(tmp_path / "data"), "vault_key_file_warn": False}))
    engine.registry.save_instance("files", "files", {}, False)
    engine.registry.save_instance("scans", "files", {"root": "elsewhere"}, False)
    blocks = engine.registry.configured()
    root = Path(blocks["files"]["config"]["root"])
    assert root == tmp_path / "data" / "archive" and root.is_dir()
    assert Path(blocks["scans"]["config"]["root"]).is_absolute()
    (root / "hello.txt").write_text("Hallo Welt, ein Test im Archiv")
    plugin = engine.registry.instance("files")
    plugin.index()
    assert [r["path"] for r in plugin.read_list({})] == ["hello.txt"]
    # switched on, it feeds Doorman's search index, and doorman search finds the file
    engine.registry.set_state("files", {**engine.registry.state("files"), "enabled": True})
    engine.search.pull("files")
    key = engine.auth.key_from_token(engine.auth.create_key("agent", "solo"))
    session = engine.auth.session_for(key, None)
    assert [h["ref"] for h in engine.search.query(session, key, {"query": "Archiv"})["results"]] == ["files:hello.txt"]
