"""Load and validate PhantomX application settings."""

import json
import ipaddress
import re
from pathlib import Path

from core.scope import TargetScopeError, normalize_target


KNOWN_PROFILES = ("passive", "stealth", "standard", "full", "aggressive")
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

    max_workers = settings.get("max_workers", 4)
    if isinstance(max_workers, bool):
        raise SettingsError("max_workers must be an integer from 1 to 64.")
    if isinstance(max_workers, str):
        value = max_workers.strip()
        if not re.fullmatch(r"[+-]?\d+", value):
            raise SettingsError("max_workers must be an integer from 1 to 64.")
        try:
            max_workers = int(value)
        except ValueError as exc:
            raise SettingsError("max_workers must be an integer from 1 to 64.") from exc
    elif not isinstance(max_workers, int):
        raise SettingsError("max_workers must be an integer from 1 to 64.")
    if max_workers < 1 or max_workers > 64:
        raise SettingsError("max_workers must be between 1 and 64.")
    settings["max_workers"] = max_workers

    reports_dir = settings.get("reports_dir")
    if not isinstance(reports_dir, str) or not reports_dir.strip():
        raise SettingsError("reports_dir must be a non-empty path string.")
    settings["reports_dir"] = reports_dir.strip()

    allowed_profiles = settings.get("allowed_profiles")
    if (
        not isinstance(allowed_profiles, list)
        or not allowed_profiles
        or any(not isinstance(profile, str) for profile in allowed_profiles)
    ):
        raise SettingsError("allowed_profiles must be a non-empty list of profile names.")
    invalid_profiles = [p for p in allowed_profiles if p not in KNOWN_PROFILES]
    if invalid_profiles:
        raise SettingsError(
            "Unknown profile(s) in allowed_profiles: "
            + ", ".join(map(str, invalid_profiles))
        )
    default_profile = settings.get("default_profile")
    if not isinstance(default_profile, str) or default_profile not in allowed_profiles:
        raise SettingsError("default_profile must be included in allowed_profiles.")

    authorized_targets = settings.get("authorized_targets")
    if not isinstance(authorized_targets, list) or any(
        not isinstance(target, str) or not target.strip()
        for target in authorized_targets
    ):
        raise SettingsError("authorized_targets must be a list of non-empty strings.")
    normalized_targets = []
    for raw_target in authorized_targets:
        target = raw_target.strip()
        if target.startswith("*."):
            suffix = target[2:].rstrip(".")
            try:
                target = "*." + normalize_target(suffix)
            except TargetScopeError as exc:
                raise SettingsError(
                    f"Invalid wildcard in authorized_targets: {raw_target!r}."
                ) from exc
        else:
            if "/" in target:
                try:
                    target = str(ipaddress.ip_network(target, strict=False))
                except ValueError as exc:
                    raise SettingsError(
                        f"Invalid network in authorized_targets: {raw_target!r}."
                    ) from exc
            else:
                try:
                    target = normalize_target(target)
                except TargetScopeError as exc:
                    raise SettingsError(
                        f"Invalid entry in authorized_targets: {raw_target!r}."
                    ) from exc
        normalized_targets.append(target)
    settings["authorized_targets"] = normalized_targets

    return settings
