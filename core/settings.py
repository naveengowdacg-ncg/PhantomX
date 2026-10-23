"""Load and validate PhantomX application settings."""

import json
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

    return settings
