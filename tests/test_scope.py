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


@pytest.mark.parametrize("worker_count", [True, 1.5, "1.5", "invalid", "0", "-1"])
def test_settings_reject_non_integer_worker_count_types(tmp_path, worker_count):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"max_workers": worker_count}), encoding="utf-8")
    with pytest.raises(SettingsError, match="max_workers"):
        load_settings(path)


@pytest.mark.parametrize(("worker_count", "expected"), [(1, 1), (64, 64), ("4", 4), (" 2 ", 2), ("+3", 3)])
def test_settings_accept_integer_and_legacy_numeric_string_worker_counts(
    tmp_path, worker_count, expected
):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"max_workers": worker_count}), encoding="utf-8")

    assert load_settings(path)["max_workers"] == expected


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


# --- New tests for flexible authorized target configuration ---


@pytest.mark.parametrize(
    "target",
    [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.255.255",
    ],
)
def test_authorized_ipv4_addresses(target):
    scope = TargetScope(True, [target])
    assert scope.validate(target) == target


@pytest.mark.parametrize(
    "target",
    [
        "::1",
        "2001:db8::1",
        "fe80::1",
        "2001:db8:85a3::8a2e:370:7334",
    ],
)
def test_authorized_ipv6_addresses(target):
    scope = TargetScope(True, [target])
    assert scope.validate(target) == target


@pytest.mark.parametrize(
    "cidr,allowed,denied",
    [
        ("192.168.1.0/24", ["192.168.1.1", "192.168.1.254"], ["192.168.0.1", "192.168.2.1", "10.0.0.1"]),
        ("10.0.0.0/8", ["10.1.2.3", "10.255.255.255"], ["192.168.1.1", "11.0.0.1"]),
        ("172.16.0.0/12", ["172.16.0.1", "172.31.255.255"], ["172.15.0.1", "172.32.0.1"]),
        ("2001:db8::/32", ["2001:db8::1", "2001:db8:ffff::1"], ["2001:db9::1", "::1"]),
        ("::1/128", ["::1"], ["::2", "2001:db8::1"]),
        ("fe80::/10", ["fe80::1", "febf:ffff::1"], ["ff00::1", "2001:db8::1"]),
    ],
)
def test_cidr_scope_membership_ipv4_ipv6(cidr, allowed, denied):
    scope = TargetScope(True, [cidr])
    for target in allowed:
        assert scope.validate(target) == target, f"Expected {target} to be allowed in {cidr}"
    for target in denied:
        with pytest.raises(TargetScopeError, match="outside configured scope"):
            scope.validate(target)


@pytest.mark.parametrize(
    "wildcard,allowed,denied",
    [
        ("*.example.com", ["test.example.com", "api.test.example.com"], ["example.com", "other.com", "test.example.org"]),
        ("*.internal.corp", ["server.internal.corp", "db.internal.corp"], ["internal.corp", "external.corp"]),
        ("*.sub.domain.example", ["a.sub.domain.example"], ["domain.example", "sub.domain.example"]),
    ],
)
def test_wildcard_hostname_scope(wildcard, allowed, denied):
    scope = TargetScope(True, [wildcard])
    for target in allowed:
        assert scope.validate(target) == target
    for target in denied:
        with pytest.raises(TargetScopeError, match="outside configured scope"):
            scope.validate(target)


def test_mixed_authorized_targets():
    """Test scope with mixed IPv4, IPv6, CIDR, hostname, and wildcard entries."""
    authorized = [
        "192.168.1.10",           # exact IPv4
        "2001:db8::1",            # exact IPv6
        "10.0.0.0/8",             # IPv4 CIDR
        "2001:db8::/32",          # IPv6 CIDR
        "example.com",            # exact hostname
        "*.internal.net",         # wildcard
    ]
    scope = TargetScope(True, authorized)

    # All authorized targets should work
    assert scope.validate("192.168.1.10") == "192.168.1.10"
    assert scope.validate("2001:db8::1") == "2001:db8::1"
    assert scope.validate("10.5.5.5") == "10.5.5.5"
    assert scope.validate("2001:db8:1234::1") == "2001:db8:1234::1"
    assert scope.validate("example.com") == "example.com"
    assert scope.validate("server.internal.net") == "server.internal.net"
    assert scope.validate("api.server.internal.net") == "api.server.internal.net"

    # Unauthorized targets should be rejected
    with pytest.raises(TargetScopeError):
        scope.validate("192.168.1.11")
    with pytest.raises(TargetScopeError):
        scope.validate("2001:db9::1")
    with pytest.raises(TargetScopeError):
        scope.validate("11.0.0.1")
    with pytest.raises(TargetScopeError):
        scope.validate("2001:db9::1")
    with pytest.raises(TargetScopeError):
        scope.validate("other.com")
    with pytest.raises(TargetScopeError):
        scope.validate("internal.net")  # wildcard doesn't match bare domain
    with pytest.raises(TargetScopeError):
        scope.validate("external.net")


def test_unauthorized_ipv4_rejected():
    scope = TargetScope(True, ["192.168.1.0/24"])
    with pytest.raises(TargetScopeError, match="outside configured scope"):
        scope.validate("192.168.2.1")
    with pytest.raises(TargetScopeError):
        scope.validate("10.0.0.1")
    with pytest.raises(TargetScopeError):
        scope.validate("8.8.8.8")


def test_unauthorized_ipv6_rejected():
    scope = TargetScope(True, ["2001:db8::/32"])
    with pytest.raises(TargetScopeError, match="outside configured scope"):
        scope.validate("2001:db9::1")
    with pytest.raises(TargetScopeError):
        scope.validate("::1")
    with pytest.raises(TargetScopeError):
        scope.validate("fe80::1")


def test_unauthorized_hostname_rejected():
    scope = TargetScope(True, ["example.com", "*.internal.net"])
    with pytest.raises(TargetScopeError, match="outside configured scope"):
        scope.validate("other.com")
    with pytest.raises(TargetScopeError):
        scope.validate("test.example.org")
    with pytest.raises(TargetScopeError):
        scope.validate("internal.net")  # bare domain not matched by wildcard
    with pytest.raises(TargetScopeError):
        scope.validate("external.net")


@pytest.mark.parametrize(
    "invalid_entry",
    [
        "192.168.1.0/33",      # invalid CIDR prefix
        "192.168.1.256",       # invalid IPv4 octet
        "192.168.1",           # partial IPv4
        "192.168",             # partial IPv4
        "*.",                  # invalid wildcard
        "example..com",        # invalid hostname
        "not a valid target",  # spaces
        "http://example.com",  # URL
        "example.com/path",    # path
        "example.com:443",     # port
    ],
)
def test_settings_reject_invalid_authorized_target_entries(tmp_path, invalid_entry):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"authorized_targets": [invalid_entry]}), encoding="utf-8")
    with pytest.raises(SettingsError):
        load_settings(path)


def test_settings_reject_mixed_valid_invalid_authorized_targets(tmp_path):
    path = tmp_path / "settings.json"
    # "invalid-host!" contains invalid character for hostname
    path.write_text(json.dumps({"authorized_targets": ["192.168.1.0/24", "invalid-host!"]}), encoding="utf-8")
    with pytest.raises(SettingsError, match="Invalid"):
        load_settings(path)


def test_settings_accept_valid_authorized_target_formats(tmp_path):
    """Test that all valid target formats are accepted in settings."""
    authorized = [
        "192.168.1.1",           # IPv4
        "::1",                   # IPv6
        "2001:db8::1",           # IPv6 full
        "192.168.1.0/24",        # IPv4 CIDR
        "2001:db8::/32",         # IPv6 CIDR
        "example.com",           # hostname
        "sub.example.com",       # subdomain
        "*.example.com",         # wildcard
        "localhost",             # single-label hostname
        "myserver",              # single-label hostname
    ]
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"authorized_targets": authorized}), encoding="utf-8")
    settings = load_settings(path)
    # Settings normalizes targets, so compare normalized forms
    assert settings["authorized_targets"] == [
        "192.168.1.1",
        "::1",
        "2001:db8::1",
        "192.168.1.0/24",
        "2001:db8::/32",
        "example.com",
        "sub.example.com",
        "*.example.com",
        "localhost",
        "myserver",
    ]


def test_empty_scope_fails_closed():
    """Empty authorized_targets list should fail closed when scope_required=True."""
    with pytest.raises(TargetScopeError, match="No authorized targets"):
        TargetScope(True, []).validate("127.0.0.1")


def test_scope_disabled_allows_any_valid_target():
    """When scope_required=False, any syntactically valid target should be allowed."""
    scope = TargetScope(False, [])
    assert scope.validate("192.168.1.1") == "192.168.1.1"
    assert scope.validate("2001:db8::1") == "2001:db8::1"
    assert scope.validate("example.com") == "example.com"
    # Wildcards are for authorization only, not valid as scan targets
    with pytest.raises(TargetScopeError):
        scope.validate("*.example.com")
    # But invalid syntax still rejected
    with pytest.raises(TargetScopeError):
        scope.validate("https://example.com")
    with pytest.raises(TargetScopeError):
        scope.validate("example.com/path")


def test_ipv6_zone_id_handling():
    """IPv6 addresses with zone IDs should be normalized and match correctly."""
    scope = TargetScope(True, ["fe80::1%eth0"])
    # Zone IDs are preserved in normalization
    assert scope.validate("fe80::1%eth0") == "fe80::1%eth0"
    # Different zone ID should not match
    with pytest.raises(TargetScopeError):
        scope.validate("fe80::1%eth1")
    # Without zone ID should not match (different address)
    with pytest.raises(TargetScopeError):
        scope.validate("fe80::1")


def test_cidr_with_host_address_boundary():
    """Test CIDR boundary conditions (network/broadcast addresses)."""
    scope = TargetScope(True, ["192.168.1.0/24"])
    # Network and broadcast addresses are valid hosts in ipaddress module
    assert scope.validate("192.168.1.0") == "192.168.1.0"
    assert scope.validate("192.168.1.255") == "192.168.1.255"


def test_ipv4_mapped_ipv6_address():
    """IPv4-mapped IPv6 addresses should be handled correctly."""
    scope = TargetScope(True, ["::ffff:192.168.1.1"])
    assert scope.validate("::ffff:192.168.1.1") == "::ffff:192.168.1.1"
    # The IPv4 equivalent should NOT match (different address format)
    with pytest.raises(TargetScopeError):
        scope.validate("192.168.1.1")


def test_case_insensitive_hostname_matching():
    """Hostname matching should be case-insensitive."""
    scope = TargetScope(True, ["Example.COM", "*.INTERNAL.NET"])
    assert scope.validate("example.com") == "example.com"
    assert scope.validate("EXAMPLE.COM") == "example.com"
    assert scope.validate("Test.Internal.Net") == "test.internal.net"
    assert scope.validate("API.TEST.INTERNAL.NET") == "api.test.internal.net"


@pytest.mark.parametrize(
    "settings",
    [
        {"allowed_profiles": ["standard", None]},
        {"authorized_targets": ["https://example.test/path"]},
        {"authorized_targets": ["*.bad..example.test"]},
        {"authorized_targets": ["10.0.0.0/99"]},
    ],
)
def test_settings_reject_malformed_profile_and_scope_entries(tmp_path, settings):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(settings), encoding="utf-8")

    with pytest.raises(SettingsError):
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


# --- Regression tests for adapter scope propagation ---


def test_adapter_manager_receives_and_propagates_scope():
    """AdapterManager should accept scope and pass it to all built-in adapters."""
    from core.adapter_manager import AdapterManager
    from core.scope import TargetScope

    configured_scope = TargetScope(True, ["192.168.31.0/24", "lab.test"])
    mgr = AdapterManager(scope=configured_scope)

    for name, adapter in mgr.adapters.items():
        assert adapter.scope is configured_scope, f"Adapter {name} did not receive configured scope"


def test_adapter_manager_defaults_to_local_scope_when_none_provided():
    """AdapterManager should fall back to local_only_scope when no scope is given."""
    from core.adapter_manager import AdapterManager
    from core.scope import local_only_scope

    mgr = AdapterManager()

    for adapter in mgr.adapters.values():
        # All adapters should have a scope (the local-only default)
        assert adapter.scope is not None
        assert adapter.scope.authorized_targets == ["127.0.0.1", "localhost", "::1"]


def test_cidr_authorized_target_accepted_by_all_adapters(tmp_path, monkeypatch):
    """When 192.168.31.0/24 is configured, 192.168.31.188 should be accepted by all adapters."""
    import main as main_module
    from core.scope import TargetScope

    # Mock external tool executables as missing (we only test scope validation)
    monkeypatch.setattr("shutil.which", lambda _: None)

    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({
        "default_profile": "standard",
        "allowed_profiles": ["standard"],
        "authorized_targets": ["127.0.0.1", "localhost", "::1", "192.168.31.0/24"],
        "scope_required": True,
    }), encoding="utf-8")

    app = main_module.App(str(settings))

    # Test that the configured scope accepts the target
    validated = app.scope.validate("192.168.31.188")
    assert validated == "192.168.31.188"

    # Test that all adapters share the same scope
    for name, adapter in app.adapter_manager.adapters.items():
        assert adapter.scope is app.scope, f"Adapter {name} does not share app scope"

    # Test adapter-level scope validation (simulating what happens during scan)
    for name, adapter in app.adapter_manager.adapters.items():
        if hasattr(adapter, 'scan'):
            # Each adapter validates via its own scope, which should now be the configured one
            try:
                adapter.scope.validate_scan_target("192.168.31.188", require_resolution=False)
            except TargetScopeError:
                pytest.fail(f"Adapter {name} rejected in-scope target 192.168.31.188")


def test_out_of_scope_target_rejected_by_all_adapters(tmp_path, monkeypatch):
    """An out-of-scope target should be rejected by all adapters when scope_required=True."""
    import main as main_module
    from core.scope import TargetScope, TargetScopeError

    monkeypatch.setattr("shutil.which", lambda _: None)

    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({
        "default_profile": "standard",
        "allowed_profiles": ["standard"],
        "authorized_targets": ["127.0.0.1", "localhost", "::1", "192.168.31.0/24"],
        "scope_required": True,
    }), encoding="utf-8")

    app = main_module.App(str(settings))

    # 192.168.32.1 is outside the configured 192.168.31.0/24 range
    out_of_scope_target = "192.168.32.1"

    # App-level scope should reject it
    with pytest.raises(TargetScopeError, match="outside configured scope"):
        app.scope.validate(out_of_scope_target)

    # All adapters should also reject it via their shared scope
    for name, adapter in app.adapter_manager.adapters.items():
        with pytest.raises(TargetScopeError, match="outside configured scope"):
            adapter.scope.validate_scan_target(out_of_scope_target, require_resolution=False)


def test_executor_validates_target_with_configured_scope(tmp_path, monkeypatch):
    """ToolExecutor should validate targets using the configured scope."""
    from core.executor import ToolExecutor
    from core.scope import TargetScope, TargetScopeError

    configured_scope = TargetScope(True, ["192.168.31.0/24"])
    executor = ToolExecutor(logger=None, scope=configured_scope)

    # In-scope target should pass validation (we can't run the tool, but validation happens early)
    tool = {"name": "nmap", "category": "recon", "executable": "nmap", "args": ["{target}"], "timeout": 120}

    # We can't easily test _run_once without mocking, but we can test the scope directly
    assert executor.scope is configured_scope
    assert executor.scope.validate("192.168.31.188") == "192.168.31.188"

    # Out of scope should be rejected
    with pytest.raises(TargetScopeError, match="outside configured scope"):
        executor.scope.validate("192.168.32.1")
