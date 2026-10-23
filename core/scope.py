"""Target syntax validation and explicit authorization-scope checks."""

import ipaddress
import re


_HOST_LABEL = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


class TargetScopeError(ValueError):
    """Raised when a target is invalid or outside configured scope."""


def normalize_target(value):
    """Return a normalized host/IP, rejecting URLs, paths, and shell syntax."""
    if not isinstance(value, str):
        raise TargetScopeError("Target must be a hostname or IP address.")

    target = value.strip()
    if not target:
        raise TargetScopeError("Target cannot be empty.")
    if any(char.isspace() for char in target):
        raise TargetScopeError("Target cannot contain whitespace.")
    if any(char in target for char in "/\\@?#$;|&`<>\"'(){}[]"):
        raise TargetScopeError(
            "Use a hostname or IP address only; URLs, paths, and shell syntax are not accepted."
        )
    if "://" in target:
        raise TargetScopeError("Enter a hostname or IP address, not a URL.")

    # IP addresses are normalized before hostname validation.
    try:
        return ipaddress.ip_address(target).compressed
    except ValueError:
        pass

    # A trailing DNS root dot is valid but unnecessary for tool invocation.
    target = target.rstrip(".")
    if not target or len(target) > 253:
        raise TargetScopeError("Target is not a valid hostname or IP address.")

    try:
        ascii_target = target.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetScopeError("Target contains an invalid hostname.") from exc

    labels = ascii_target.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise TargetScopeError("Target is not a valid hostname or IP address.")
    if len(labels) > 1 and (len(labels[-1]) < 2 and not labels[-1].isdigit()):
        raise TargetScopeError("Target is not a valid hostname or IP address.")

    return ascii_target.lower()


def _matches_scope(target, entry):
    """Match a normalized target against an exact host, wildcard, IP, or CIDR."""
    entry = entry.strip()
    if not entry:
        return False

    if entry.startswith("*."):
        suffix = entry[2:].rstrip(".").lower()
        return target.lower().endswith("." + suffix) and target.lower() != suffix

    try:
        network = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        network = None

    if network is not None:
        try:
            return ipaddress.ip_address(target) in network
        except ValueError:
            return False

    try:
        normalized_entry = normalize_target(entry)
    except TargetScopeError:
        return False
    return target.casefold() == normalized_entry.casefold()


class TargetScope:
    """Validate target syntax and, when enabled, require explicit allowlisting."""

    def __init__(self, scope_required=True, authorized_targets=None):
        self.scope_required = bool(scope_required)
        self.authorized_targets = list(authorized_targets or [])

    def validate(self, value):
        target = normalize_target(value)
        if not self.scope_required:
            return target

        if not self.authorized_targets:
            raise TargetScopeError(
                "No authorized targets are configured. Add an authorized host/IP/CIDR "
                "to authorized_targets in config/settings.json."
            )

        if not any(_matches_scope(target, item) for item in self.authorized_targets):
            raise TargetScopeError(
                f"Target '{target}' is outside configured scope. Add it to "
                "authorized_targets only if you have permission to assess it."
            )
        return target
