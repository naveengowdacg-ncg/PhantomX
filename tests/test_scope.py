import json

import pytest

from core.scope import TargetScope, TargetScopeError, normalize_http_url, normalize_target
from core.settings import SettingsError, load_settings


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("127.0.0.1", "127.0.0.1"),
        ("LOCALHOST", "localhost"),
        ("Example.COM.", "example.com"),
        ("::1", "::1"),
    ],
)
def test_normalize_valid_targets(raw, expected):
    assert normalize_target(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "https://example.com",
        "example.com/path",
        "example.com:443",
        "example.com;whoami",
        "bad host",
        "-bad.example",
        "example..com",
    ],
)
def test_rejects_invalid_or_non_host_targets(raw):
    with pytest.raises(TargetScopeError):
        normalize_target(raw)


def test_exact_allowlist_match_and_rejection():
    scope = TargetScope(True, ["127.0.0.1", "localhost"])
    assert scope.validate("127.0.0.1") == "127.0.0.1"
    with pytest.raises(TargetScopeError, match="outside configured scope"):
        scope.validate("example.com")


def test_cidr_and_wildcard_scope_matches():
    scope = TargetScope(True, ["192.168.10.0/24", "*.lab.example"])
    assert scope.validate("192.168.10.25") == "192.168.10.25"
    assert scope.validate("web.lab.example") == "web.lab.example"
    with pytest.raises(TargetScopeError):
        scope.validate("lab.example")
    with pytest.raises(TargetScopeError):
        scope.validate("192.168.11.25")


def test_required_scope_fails_closed_without_allowlist():
    with pytest.raises(TargetScopeError, match="No authorized targets"):
        TargetScope(True, []).validate("127.0.0.1")


def test_scope_can_be_disabled_but_target_syntax_is_still_checked():
    scope = TargetScope(False, [])
    assert scope.validate("example.com") == "example.com"
    with pytest.raises(TargetScopeError):
        scope.validate("https://example.com")


def test_settings_defaults_and_configured_scope(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps({"authorized_targets": ["10.0.0.0/8"], "max_workers": 2}),
        encoding="utf-8",
    )
    settings = load_settings(path)
    assert settings["max_workers"] == 2
    assert settings["authorized_targets"] == ["10.0.0.0/8"]
    assert settings["reports_dir"] == "reports"


def test_settings_reject_invalid_worker_count(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"max_workers": 0}), encoding="utf-8")
    with pytest.raises(SettingsError, match="max_workers"):
        load_settings(path)


def test_cli_target_command_enforces_scope(capsys):
    from main import App

    app = App.__new__(App)
    app.scope = TargetScope(True, ["127.0.0.1"])
    app.target = None

    app.dispatch("target example.com")
    assert app.target is None
    assert "outside configured scope" in capsys.readouterr().out

    app.dispatch("target 127.0.0.1")
    assert app.target == "127.0.0.1"
    assert "Target set: 127.0.0.1" in capsys.readouterr().out


def test_scan_revalidates_target_before_execution(capsys):
    from main import App

    app = App.__new__(App)
    app.scope = TargetScope(True, ["127.0.0.1"])
    app.target = "example.com"  # Simulates a target set outside the CLI path.

    assert app._validated_target() is None
    assert "outside configured scope" in capsys.readouterr().out


def test_settings_reject_unknown_profile(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps({"allowed_profiles": ["experimental"]}),
        encoding="utf-8",
    )
    with pytest.raises(SettingsError, match="Unknown profile"):
        load_settings(path)


@pytest.mark.parametrize(
    ("raw", "expected_url", "expected_host", "expected_port"),
    [
        ("http://EXAMPLE.test:80/login", "http://example.test", "example.test", 80),
        ("https://localhost:8443/a", "https://localhost:8443", "localhost", 8443),
        ("http://[::1]:8080/health", "http://[::1]:8080", "::1", 8080),
    ],
)
def test_http_endpoint_normalization_handles_hosts_ports_and_urls(
    raw, expected_url, expected_host, expected_port
):
    endpoint = normalize_http_url(raw)
    assert endpoint["url"] == expected_url
    assert endpoint["host"] == expected_host
    assert endpoint["port"] == expected_port


def test_scope_validate_url_checks_host_and_accepts_localhost_and_ports():
    scope = TargetScope(True, ["localhost", "::1"])
    assert scope.validate_url("http://localhost:8080/admin") == "http://localhost:8080"
    assert scope.validate_url("http://[::1]:80/") == "http://[::1]"
    with pytest.raises(TargetScopeError, match="outside configured scope"):
        scope.validate_url("https://outside.test:443/path")


@pytest.mark.parametrize(
    "raw",
    [
        "ftp://example.test",
        "http://user:pass@example.test",
        "http://example.test:99999",
        "http://example.test:",
    ],
)
def test_http_endpoint_normalization_rejects_unsafe_or_malformed_urls(raw):
    with pytest.raises(TargetScopeError):
        normalize_http_url(raw)
