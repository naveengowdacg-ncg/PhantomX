import pytest

from core.scope import TargetScopeError
from core.settings import DEFAULT_SETTINGS, SettingsError
from gui import SelectedToolRegistry, build_scope


def test_gui_scope_uses_the_backend_settings_and_scope_validators():
    settings, scope, target = build_scope(
        DEFAULT_SETTINGS,
        "127.0.0.1",
        True,
        ["127.0.0.0/8", "LOCALHOST"],
    )

    assert target == "127.0.0.1"
    assert settings["authorized_targets"] == ["127.0.0.0/8", "localhost"]
    assert scope.validate("localhost") == "localhost"


def test_gui_scope_rejects_targets_outside_the_allowlist():
    with pytest.raises(TargetScopeError, match="outside configured scope"):
        build_scope(
            DEFAULT_SETTINGS,
            "192.0.2.10",
            True,
            ["127.0.0.1"],
        )


def test_gui_scope_rejects_malformed_allowlist_entries():
    with pytest.raises(SettingsError):
        build_scope(
            DEFAULT_SETTINGS,
            "127.0.0.1",
            True,
            ["bad host"],
        )


def test_selected_registry_only_changes_its_private_tool_copies():
    original = [
        {"name": "nmap", "enabled": True, "args": ["{target}"]},
        {"name": "whatweb", "enabled": False, "args": ["{target}"]},
    ]

    selected = SelectedToolRegistry(original, {"whatweb"})

    assert [tool["enabled"] for tool in original] == [True, False]
    assert [tool["enabled"] for tool in selected.list()] == [False, True]
    assert selected.list()[1] is not original[1]

def test_dnsx_config_resolves_the_supplied_host_without_bruteforce_mode():
    import json
    from pathlib import Path

    config_path = Path(__file__).resolve().parents[1] / "config" / "tools.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    tool = next(item for item in config["tools"] if item["name"] == "dnsx")

    assert tool["args"][:2] == ["-l", "{target}"]
