"""Target syntax validation and explicit authorization-scope checks."""

import ipaddress
import re
import socket
from urllib.parse import urlsplit


_HOST_LABEL = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
LOCAL_ONLY_TARGETS = ("127.0.0.1", "localhost", "::1")


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
    forbidden = "/\\@?#$;|&" + chr(96) + "<>\"'(){}[]"
    if any(char in target for char in forbidden):
        raise TargetScopeError(
            "Use a hostname or IP address only; URLs, paths, and shell syntax are not accepted."
        )
    if "://" in target:
        raise TargetScopeError("Enter a hostname or IP address, not a URL.")
    try:
        return ipaddress.ip_address(target).compressed
    except ValueError:
        pass
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


def normalize_http_url(value):
    """Return a canonical HTTP(S) origin and its validated host/port parts."""
    if not isinstance(value, str) or not value.strip():
        raise TargetScopeError("Discovered endpoint must be an HTTP or HTTPS URL.")
    raw = value.strip()
    if any(char.isspace() for char in raw):
        raise TargetScopeError("Discovered endpoint URL cannot contain whitespace.")
    try:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise TargetScopeError("Only HTTP and HTTPS endpoints can be assessed.")
        if not parsed.netloc or not parsed.hostname:
            raise TargetScopeError("Discovered endpoint URL has no valid hostname.")
        if parsed.username is not None or parsed.password is not None:
            raise TargetScopeError("Endpoint URLs containing credentials are not accepted.")
        if parsed.netloc.endswith(":"):
            raise TargetScopeError("Discovered endpoint URL has an empty port.")
        host = normalize_target(parsed.hostname)
        port = parsed.port
    except ValueError as exc:
        if isinstance(exc, TargetScopeError):
            raise
        raise TargetScopeError(f"Discovered endpoint URL is invalid: {exc}") from exc
    default_port = 443 if scheme == "https" else 80
    port = default_port if port is None else port
    if port < 1 or port > 65535:
        raise TargetScopeError("Endpoint port must be between 1 and 65535.")
    authority_host = f"[{host}]" if ":" in host else host
    authority = authority_host if port == default_port else f"{authority_host}:{port}"
    return {
        "scheme": scheme,
        "host": host,
        "port": port,
        "url": f"{scheme}://{authority}",
        "path": parsed.path or "/",
    }


class TargetScope:
    """Validate target syntax, authorization, and active DNS resolutions."""

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

    def resolve_and_validate(self, value):
        """Resolve a host and require every returned IP to be explicitly authorized."""
        target = self.validate(value)
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            try:
                answers = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
            except OSError as exc:
                raise TargetScopeError(
                    f"Could not resolve active target '{target}': {exc}"
                ) from exc
            addresses = sorted({
                ipaddress.ip_address(answer[4][0].split("%", 1)[0]).compressed
                for answer in answers
                if answer and len(answer) > 4 and answer[4]
            })
        else:
            addresses = [address.compressed]
        if not addresses:
            raise TargetScopeError(f"Active target '{target}' resolved to no IP addresses.")
        if self.scope_required:
            denied = [
                address for address in addresses
                if not any(_matches_scope(address, item) for item in self.authorized_targets)
            ]
            if denied:
                raise TargetScopeError(
                    f"Active target '{target}' resolved outside configured IP scope: "
                    + ", ".join(denied)
                    + ". Add the authorized IP address or CIDR before scanning."
                )
        return tuple(addresses)

    def validate_scan_target(self, value, require_resolution=True):
        """Validate a host, host:port, or HTTP(S) target at the execution boundary."""
        if not isinstance(value, str) or not value.strip():
            raise TargetScopeError("Scan target must be a non-empty string.")
        raw = value.strip()
        if "://" in raw:
            host = normalize_http_url(raw)["host"]
        elif raw.startswith("["):
            try:
                parsed = urlsplit("//" + raw)
                if (
                    not parsed.hostname
                    or parsed.path
                    or parsed.query
                    or parsed.fragment
                    or parsed.netloc.endswith(":")
                ):
                    raise TargetScopeError("Bracketed host and port target is malformed.")
                port = parsed.port
                if port is not None and not 1 <= port <= 65535:
                    raise TargetScopeError("Target port must be between 1 and 65535.")
                host = normalize_target(parsed.hostname)
            except ValueError as exc:
                if isinstance(exc, TargetScopeError):
                    raise
                raise TargetScopeError(f"Bracketed host and port target is malformed: {exc}") from exc
        elif raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
            try:
                parsed = urlsplit("//" + raw)
                if not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
                    raise TargetScopeError("Host and port target is malformed.")
                port = parsed.port
                if port is None or not 1 <= port <= 65535:
                    raise TargetScopeError("Target port must be between 1 and 65535.")
                host = normalize_target(parsed.hostname)
            except ValueError as exc:
                if isinstance(exc, TargetScopeError):
                    raise
                raise TargetScopeError(f"Host and port target is malformed: {exc}") from exc
        else:
            host = normalize_target(raw)
        if require_resolution:
            self.resolve_and_validate(host)
        else:
            self.validate(host)
        return raw

    def validate_url(self, value):
        """Authorize an HTTP(S) endpoint by its hostname and return its origin."""
        endpoint = normalize_http_url(value)
        self.validate(endpoint["host"])
        return endpoint["url"]


def local_only_scope():
    """Return the safe default scope used by direct adapter/executor APIs."""
    return TargetScope(True, LOCAL_ONLY_TARGETS)
