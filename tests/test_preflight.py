import json
from pathlib import Path

import pytest

from core.preflight import ToolPreflight
from core.tool_registry import ToolRegistry


def tool(**overrides):
    item = {
        "name": "scanner",
        "category": "recon",
        "executable": "scanner-bin",
        "args": ["--target", "{target}"],
        "enabled": True,
    }
    item.update(overrides)
    return item


def test_preflight_reports_ready_executable_and_required_file(tmp_path, monkeypatch):
    required = tmp_path / "common.txt"
    required.write_text("index.html\n", encoding="utf-8")
    monkeypatch.setattr("core.preflight.shutil.which", lambda executable: "/usr/bin/scanner-bin")

    result = ToolPreflight().inspect([tool(required_files=[str(required)])])[0]

    assert result["status"] == "ready"
    assert result["resolved_executable"] == "/usr/bin/scanner-bin"
    assert "required files are available" in result["message"]


def test_preflight_reports_missing_executable_as_unavailable(monkeypatch):
    monkeypatch.setattr("core.preflight.shutil.which", lambda executable: None)

    result = ToolPreflight().inspect([tool()])[0]

    assert result["status"] == "unavailable"
    assert "scanner-bin" in result["message"]
    assert "config/tools.json" in result["message"]


def test_preflight_reports_missing_required_file_as_misconfigured(tmp_path, monkeypatch):
    monkeypatch.setattr("core.preflight.shutil.which", lambda executable: "/usr/bin/scanner-bin")
    missing = tmp_path / "missing-wordlist.txt"

    result = ToolPreflight().inspect([tool(required_files=[str(missing)])])[0]

    assert result["status"] == "misconfigured"
    assert str(missing) in result["message"]
    assert "required_files" in result["message"]


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (None, "JSON object"),
        (tool(args="--unsafe"), "args must be a list of strings"),
        (tool(required_files="wordlist.txt"), "required_files must be a list"),
        (tool(executable=""), "executable must be a non-empty"),
    ],
)
def test_preflight_marks_malformed_tool_entries(entry, message):
    result = ToolPreflight().inspect([entry])[0]
    assert result["status"] == "misconfigured"
    assert message in result["message"]


def test_preflight_skips_disabled_tools_and_does_not_block_ready_peers(monkeypatch):
    monkeypatch.setattr(
        "core.preflight.shutil.which",
        lambda executable: "/usr/bin/ready" if executable == "ready" else None,
    )
    entries = [
        tool(name="ready", executable="ready"),
        tool(name="optional", executable="optional"),
        tool(name="disabled", executable="disabled", enabled=False),
    ]

    results = ToolPreflight().inspect(entries)

    assert [(item["name"], item["status"]) for item in results] == [
        ("ready", "ready"),
        ("optional", "unavailable"),
    ]
    assert len(entries) == 3


def test_preflight_reports_malformed_registry_without_replacing_it(tmp_path):
    path = tmp_path / "tools.json"
    original = "{ definitely not json"
    path.write_text(original, encoding="utf-8")

    registry = ToolRegistry(path)
    results = ToolPreflight().inspect(registry.list(), registry_error=registry.load_error)

    assert registry.load_error
    assert results[0]["status"] == "misconfigured"
    assert "Repair the JSON tool registry" in results[0]["message"]
    assert path.read_text(encoding="utf-8") == original
    with pytest.raises(ValueError, match="Could not parse"):
        registry.add("new", "recon", "new", [])
    assert path.read_text(encoding="utf-8") == original


def test_preflight_cli_command_displays_actionable_status(capsys, monkeypatch):
    from types import SimpleNamespace

    from main import App

    monkeypatch.setattr("core.preflight.shutil.which", lambda executable: None)
    app = App.__new__(App)
    app.tool_preflight = ToolPreflight()
    app.registry = SimpleNamespace(list=lambda: [tool()], load_error=None)

    assert app.dispatch("preflight") is True
    output = capsys.readouterr().out
    assert "[UNAVAILABLE] scanner" in output
    assert "config/tools.json" in output


def test_gobuster_wordlist_is_declared_as_a_required_file():
    config = json.loads((Path("config") / "tools.json").read_text(encoding="utf-8"))
    gobuster = next(item for item in config["tools"] if item["name"] == "gobuster")
    assert gobuster["required_files"] == ["/usr/share/wordlists/dirb/common.txt"]
