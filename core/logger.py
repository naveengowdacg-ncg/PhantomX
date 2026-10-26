import logging
import re
from pathlib import Path

# Pattern to match URLs with potential credentials
_URL_PATTERN = re.compile(
    r"(?i)(?:https?:/{0,2}|[a-z][a-z0-9+.-]*://|//)[^\s<>\"']+"
)


def _redact_urls_in_message(message: str) -> str:
    """Remove URL userinfo, query strings, and fragments from log messages."""
    if not isinstance(message, str):
        return str(message)
    return _URL_PATTERN.sub(
        lambda match: _safe_endpoint(match.group(0)) or "[invalid URL]",
        message,
    )


def _safe_endpoint(value: str) -> str:
    """Expose endpoint identity without credentials, query strings, or fragments."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        from urllib.parse import urlsplit, urlunsplit
        parsed = urlsplit(text)
        if parsed.netloc:
            host = parsed.hostname or ""
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            try:
                port = parsed.port
            except ValueError:
                port = None
            authority = f"{host}:{port}" if port is not None else host
            text = urlunsplit((parsed.scheme, authority, parsed.path, "", ""))
        else:
            # Malformed URL fallback
            text = text.split("#", 1)[0].split("?", 1)[0]
            if "://" in text:
                prefix, remainder = text.split("://", 1)
                prefix += "://"
            elif text.startswith("//"):
                prefix, remainder = "//", text[2:]
            elif re.match(r"(?i)^https?:", text):
                prefix, remainder = text.split(":", 1)
                prefix += ":"
            else:
                return text
            remainder = remainder.lstrip("/")
            authority, separator, path = remainder.partition("/")
            if "@" in authority:
                authority = authority.rsplit("@", 1)[-1]
            text = prefix + authority + (separator + path if separator else "")
        return text[:500]
    except ValueError:
        return text[:500]


class _RedactingFilter(logging.Filter):
    def filter(self, record):
        if isinstance(record.msg, str):
            record.msg = _redact_urls_in_message(record.msg)
        if record.args:
            record.args = tuple(
                _redact_urls_in_message(str(arg)) if isinstance(arg, str) else arg
                for arg in record.args
            )
        return True


def get_logger(reports_dir="reports"):
    reports_path = Path(reports_dir)
    reports_path.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("cybersec")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler(reports_path / "execution.log", encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(handler)
        logger.addFilter(_RedactingFilter())
    return logger
