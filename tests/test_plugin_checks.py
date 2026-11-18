"""Manifest checks when plugins load (manifest_check.py), a broken plugin not stopping Doorman, and
`doorman-admin plugin check`."""

from pathlib import Path

import pytest
import yaml

from doorman import admin
from doorman.manifest_check import check
from doorman.plugin_api import PluginError
from doorman.registry import BUILTIN_DIR
from conftest import Agent, make_engine

FAKES = Path(__file__).parent / "fakes" / "plugins"
FOLDERS = sorted(p for base in (BUILTIN_DIR, FAKES) for p in base.iterdir() if (p / "manifest.yaml").is_file())

GOOD = {
    "name": "pinboard", "version": "0.1.0", "description": "Pins", "credentials": [],
    "config": {"url": "where it is"},
    "events": [{"name": "new_pin", "description": "A pin", "fields": ["title"]}],
    "index": {"read": "pin", "kinds": ["note"]},
    "item": {"read": "pin", "param": "id", "events": ["new_pin"]},
    "reads": [
        {"name": "find", "description": "Search", "trust": "third_party",
         "params": {"type": "object", "properties": {"query": {"type": "string"}}}},
        {"name": "pin", "description": "One pin", "trust": "third_party",
         "params": {"type": "object", "properties": {"id": {"type": "string"}}}},
    ],
    "tools": [
        {"name": "share", "description": "Share a pin", "tier": "irreversible", "editable": ["text"],
         "destinations": [{"field": "to", "kind": "email"}],
         "params": {"type": "object", "properties": {"to": {"type": "string"}, "text": {"type": "string"}}}},
    ],
}
PLUGIN_PY = """from doorman.plugin_api import BasePlugin, ExecResult, Tool


class Share(Tool):
    def execute(self, args, before):
        return ExecResult(summary="shared")


class Plugin(BasePlugin):
    TOOLS = {"share": Share}
    READS = {"find": "read_find", "pin": "read_pin"}

    def read_find(self, params):
        return {"results": []}

    def read_pin(self, params):
        return {"id": params["id"]}
"""


def write_plugin(base: Path, manifest: dict, code: str = PLUGIN_PY, folder: str | None = None) -> Path:
    path = base / (folder or str(manifest.get("name") or "nameless"))
    path.mkdir(parents=True)
    (path / "manifest.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False))
    (path / "plugin.py").write_text(code)
    return path


def changed(**keys) -> dict:
    out = yaml.safe_load(yaml.safe_dump(GOOD))
    for key, value in keys.items():
        if value is None:
            out.pop(key, None)
        else:
            out[key] = value
    return out


@pytest.mark.parametrize("folder", FOLDERS, ids=lambda p: p.name)
def test_every_shipped_and_fake_plugin_passes_the_strict_check(folder):
    assert admin.check_plugin_folder(folder) == ([], [])


def test_the_example_passes():
    assert check(GOOD) == ([], [])
    # an event a job returns, gated by a read of its own
    assert check(changed(jobs=[{"name": "sync", "every_minutes": 30}], events=[
        {"name": "new_pin", "description": "A pin", "fields": ["title"], "job": "sync", "read": "pin"}])) == ([], [])


@pytest.mark.parametrize("manifest, kind, words", [
    (changed(name=None), "error", "name is missing"),
    (changed(name="Pin Board"), "error", "lower case"),
    (changed(indx={"read": "pin"}), "warning", "unknown key 'indx'; did you mean 'index'?"),
    (changed(index={"read": "fnd"}), "error", "index: read fnd isn't one of the plugin's reads"),
    (changed(index={"read": "pin", "kinds": ["poem"]}), "error", "index: kinds must be among"),
    (changed(index="pin"), "error", "index must be a mapping"),
    (changed(recent="fnd"), "error", "recent: fnd isn't one of the plugin's reads; did you mean find?"),
    (changed(agenda="events"), "error", "agenda: events isn't one of the plugin's reads"),
    (changed(recent="latest"), "error", "recent: latest isn't one of the plugin's reads"),
    (changed(contacts="people"), "error", "contacts: people isn't one of the plugin's reads"),
    (changed(ref_read="file"), "error", "ref_read: file isn't one of the plugin's reads"),
    (changed(item={"read": "pins", "param": "id"}), "error", "item.read: pins isn't one of the plugin's reads"),
    (changed(item={"read": "pin", "param": "ref"}), "error", "item.param: pin has no parameter ref"),
    (changed(item={"read": "pin", "param": "id", "events": ["new_pins"]}), "error",
     "item.events: new_pins isn't among the plugin's events"),
    (changed(events=[{"name": "new_pin", "job": "sync"}]), "error",
     "event new_pin: job sync isn't one of the plugin's jobs (none)"),
    (changed(events=[{"name": "new_pin", "read": "pins"}]), "error",
     "event new_pin: read pins isn't one of the plugin's reads"),
    (changed(events=[{"name": "new_pin", "feilds": ["title"]}]), "warning",
     "event new_pin: unknown key 'feilds'; did you mean 'fields'?"),
    (changed(agent_settings=["timeout"]), "error", "agent_settings: timeout isn't one of the settings"),
    (changed(reads=[{**GOOD["reads"][0], "params": {"type": "obj"}}, GOOD["reads"][1]]), "error",
     "read find: params isn't a valid JSON Schema"),
    (changed(reads=[{**GOOD["reads"][0], "trusted": "owner"}, GOOD["reads"][1]]), "warning",
     "read find: unknown key 'trusted'; did you mean 'trust'?"),
    (changed(reads=[{**GOOD["reads"][0], "not_scanned": "id"}, GOOD["reads"][1]]), "error",
     "read find: not_scanned is a list of field names"),
    (changed(tools=[{**GOOD["tools"][0], "tier": "send"}]), "error", "tool share: unknown tier 'send'"),
    (changed(tools=[{**GOOD["tools"][0], "editable": ["body"]}]), "error",
     "tool share: editable names body, which isn't one of its params"),
    (changed(tools=[{**GOOD["tools"][0], "params": {"type": "object", "required": "to"}}]), "error",
     "tool share: params isn't a valid JSON Schema"),
    (changed(reads=[GOOD["reads"][0], GOOD["reads"][0], GOOD["reads"][1]]), "error", "find is listed twice"),
    (["just", "a", "list"], "error", "must be a mapping"),
])
def test_a_broken_manifest_says_what_is_wrong(manifest, kind, words):
    errors, warnings = check(manifest)
    found = errors if kind == "error" else warnings
    assert any(words in problem for problem in found), (errors, warnings)
    if kind == "warning":
        assert errors == []  # an unknown key alone doesn't stop the plugin


def test_a_broken_plugin_is_left_out_and_listed_while_doorman_starts(tmp_path):
    extra = tmp_path / "plugins"
    write_plugin(extra, changed(name=None), folder="nameless")           # stopped Doorman before
    write_plugin(extra, changed(name="typo", recent="fnd"))
    (extra / "badyaml").mkdir()
    (extra / "badyaml" / "manifest.yaml").write_text("name: [unclosed\n")
    (extra / "badyaml" / "plugin.py").write_text("")
    write_plugin(extra, GOOD)
    engine = make_engine(tmp_path, plugin_paths=[str(extra)], plugins={"pinboard": {"enabled": True},
                                                                       "typo": {"enabled": True}})
    assert set(engine.registry.broken) == {str(extra / n) for n in ("nameless", "typo", "badyaml")}
    assert "name is missing" in engine.registry.broken[str(extra / "nameless")]
    assert "pinboard" in engine.registry.configured() and "typo" not in engine.registry.configured()
    assert Agent(engine).read("pinboard.pin", {"id": "7"}) == {"id": "7"}

    engine.check_plugins(force=True)
    listed = {a["ref"]: a for a in engine.attention_list() if a["kind"] == "plugin_broken"}
    assert set(listed) == set(engine.registry.broken)
    assert "recent: fnd isn't one of the plugin's reads" in listed[str(extra / "typo")]["detail"]
    assert "doorman-admin plugin check" in listed[str(extra / "typo")]["detail"]

    # fixed and restarted: the item goes away by itself
    (extra / "typo" / "manifest.yaml").write_text(yaml.safe_dump(changed(name="typo")))
    restarted = make_engine(tmp_path, plugin_paths=[str(extra)], plugins={"typo": {"enabled": True}})
    restarted.check_plugins(force=True)
    assert str(extra / "typo") not in {a["ref"] for a in restarted.attention_list() if a["kind"] == "plugin_broken"}


def test_a_read_naming_a_missing_method_fails_when_the_plugin_is_made(tmp_path):
    extra = tmp_path / "plugins"
    write_plugin(extra, GOOD, PLUGIN_PY.replace("def read_pin", "def read_pins"))
    engine = make_engine(tmp_path, plugin_paths=[str(extra)], plugins={"pinboard": {"enabled": True}})
    with pytest.raises(PluginError, match="read pin names read_pin, which the plugin doesn't have"):
        engine.registry.instance("pinboard")


def test_plugin_check_prints_every_problem_with_its_path(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("DOORMAN_CONFIG", str(tmp_path / "none.yaml"))
    folder = write_plugin(tmp_path, changed(indx={"read": "pin"}, recent="latest"))
    with pytest.raises(SystemExit) as exit_:
        admin.main(["plugin", "check", str(folder)])
    assert exit_.value.code == 1
    out = capsys.readouterr().out.splitlines()
    assert f"{folder / 'manifest.yaml'}: error: recent: latest isn't one of the plugin's reads (find, pin)" in out
    assert f"{folder / 'manifest.yaml'}: warning: manifest: unknown key 'indx'; did you mean 'index'?" in out

    code_only = write_plugin(tmp_path / "more", GOOD, PLUGIN_PY.replace('"share": Share', '"shares": Share'))
    with pytest.raises(SystemExit):
        admin.main(["plugin", "check", str(code_only)])
    assert "error: tool share has no class in Plugin.TOOLS" in capsys.readouterr().out

    admin.main(["plugin", "check", str(FAKES / "fake_chat")])
    assert capsys.readouterr().out.strip().endswith("fake_chat/manifest.yaml: ok")
    admin.main(["plugins", "check", "notes"])  # a built-in by name
    assert capsys.readouterr().out.strip().endswith("notes/manifest.yaml: ok")
