import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlsplit

from core.models import ToolResult


class AuxiliaryAdapter:
    """Small target-aware helpers for tools with special input constraints."""

    def is_available(self):
        # Availability is checked by ToolExecutor for the actual executable.
        return True

    def scan(self, tool, target, fallback_executor):
        name = tool.get("name", "").lower()
        if name in {"subfinder", "dnsx"}:
            raw_target = target.strip()
            parsed = urlsplit(raw_target if "://" in raw_target else "//" + raw_target)
            candidate = (parsed.hostname or raw_target).strip().strip("[]")
            try:
                ipaddress.ip_address(candidate)
                is_ip = True
            except ValueError:
                is_ip = candidate.lower() == "localhost"
            if is_ip:
                now = datetime.now(timezone.utc).isoformat()
                return ToolResult(
                    tool=name,
                    category=tool.get("category", "recon"),
                    target=target,
                    started_at=now,
                    finished_at=now,
                    return_code=0,
                    status="skipped",
                    stderr=f"{name} domain-based enumeration requires a domain name; target is an IP address or localhost.",
                    command=[tool.get("executable", name)],
                )
            # Domain enumeration tools accept a hostname, not a URL or host:port.
            return fallback_executor.run(tool, candidate)
        return fallback_executor.run(tool, target)
