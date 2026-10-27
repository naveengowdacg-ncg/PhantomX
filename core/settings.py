"""Load and validate PhantomX application settings."""

import ipaddress
import json
import re
from pathlib import Path


KNOWN_PROFILES = ("passive", "standard", "full")
DEFAULT_SETTINGS = {
    "default_profile": "standard",
    "reports_dir": "reports",
    "max_workers": 4,
    "scope_required": True,
    "allowed_profiles": list(KNOWN_PROFILES),
    # Only local lab targets are trusted by default. Add hosts, IPs, or
    # CIDR ranges here only when you are authorized to assess them.
    "authorized_targets": ["127.0.0.1", "localhost", "::1"],
}


class SettingsError(ValueError):
    """Raised when settings cannot be safely interpreted."""


_HOST_LABEL = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
_IPV4_LIKE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV4_PARTIAL = re.compile(r"^\d{1,3}(?:\.\d{1,3}){1,2}$")  # 2-3 octets
_IPV6_LIKE = re.compile(r"^[0-9a-fA-F:]+$")


def _is_valid_hostname(hostname: str) -> bool:
    """Validate a hostname (ASCII or IDN)."""
    if not hostname or len(hostname) > 253:
        return False
    # Reject strings that look like IPv4 addresses but aren't valid
    if _IPV4_LIKE.match(hostname):
        return False
    # Reject partial IPv4-like strings (2-3 octets)
    if _IPV4_PARTIAL.match(hostname):
        return False
    # Reject strings that look like IPv6 addresses but aren't valid
    if _IPV6_LIKE.match(hostname) and ":" in hostname:
        try:
            ipaddress.ip_address(hostname)
            return False  # It's a valid IP, not a hostname
        except ValueError:
            pass  # Not a valid IP, continue to hostname validation
    try:
        ascii_host = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    ascii_host = ascii_host.rstrip(".")
    if not ascii_host:
        return False
    labels = ascii_host.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        return False
    if len(labels) > 1 and (len(labels[-1]) < 2 and not labels[-1].isdigit()):
        return False
    return True


def _is_valid_wildcard_hostname(pattern: str) -> bool:
    """Validate a wildcard hostname pattern (e.g., *.example.com)."""
    if not pattern.startswith("*."):
        return False
    suffix = pattern[2:]
    return _is_valid_hostname(suffix)


def _is_valid_ip_address(address: str) -> bool:
    """Validate an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def _is_valid_cidr(cidr: str) -> bool:
    """Validate a CIDR network range (IPv4 or IPv6)."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def _is_valid_authorized_target(entry: str) -> bool:
    """Check if an authorized_targets entry is a valid IP, hostname, CIDR, or wildcard."""
    entry = entry.strip()
    if not entry:
        return False
    # Order matters: check CIDR before IP (since IP is subset of CIDR syntax)
    if _is_valid_cidr(entry):
        return True
    if _is_valid_ip_address(entry):
        return True
    if _is_valid_wildcard_hostname(entry):
        return True
    if _is_valid_hostname(entry):
        return True
    return False


def load_settings(path="config/settings.json"):
    """Load settings, filling supported defaults and validating key fields."""
    settings_path = Path(path)
    if settings_path.exists():
        try:
            loaded = json.loads(settings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SettingsError(f"Could not load settings from {settings_path}: {exc}") from exc
        if not isinstance(loaded, dict):
            raise SettingsError("Settings file must contain a JSON object.")
    else:
        loaded = {}

    settings = {**DEFAULT_SETTINGS, **loaded}

    if not isinstance(settings.get("scope_required"), bool):
        raise SettingsError("scope_required must be true or false.")

    try:
        max_workers = int(settings.get("max_workers", 4))
    except (TypeError, ValueError) as exc:
        raise SettingsError("max_workers must be a positive integer.") from exc
    if max_workers < 1 or max_workers > 64:
        raise SettingsError("max_workers must be between 1 and 64.")
    settings["max_workers"] = max_workers

    reports_dir = settings.get("reports_dir")
    if not isinstance(reports_dir, str) or not reports_dir.strip():
        raise SettingsError("reports_dir must be a non-empty path string.")
    settings["reports_dir"] = reports_dir.strip()

    allowed_profiles = settings.get("allowed_profiles")
    if not isinstance(allowed_profiles, list) or not allowed_profiles:
        raise SettingsError("allowed_profiles must be a non-empty list.")
    invalid_profiles = [p for p in allowed_profiles if p not in KNOWN_PROFILES]
    if invalid_profiles:
        raise SettingsError(
            "Unknown profile(s) in allowed_profiles: "
            + ", ".join(map(str, invalid_profiles))
        )
    if settings.get("default_profile") not in allowed_profiles:
        raise SettingsError("default_profile must be included in allowed_profiles.")

    authorized_targets = settings.get("authorized_targets")
    if not isinstance(authorized_targets, list) or any(
        not isinstance(target, str) or not target.strip()
        for target in authorized_targets
    ):
        raise SettingsError("authorized_targets must be a list of non-empty strings.")
    settings["authorized_targets"] = [target.strip() for target in authorized_targets]

    # Validate each authorized target entry
    invalid_targets = [
        t for t in settings["authorized_targets"] if not _is_valid_authorized_target(t)
    ]
    if invalid_targets:
        raise SettingsError(
            "Invalid authorized_targets entry/entries: "
            + ", ".join(map(str, invalid_targets))
            + ". Each entry must be a valid IPv4/IPv6 address, hostname, CIDR range, or wildcard hostname (*.example.com)."
        )

    return settings
