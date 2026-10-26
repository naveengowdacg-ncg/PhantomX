import ipaddress
import shutil
from datetime import datetime, timezone
from urllib.parse import urlsplit

from core.models import ToolResult
from core.process_utils import append_diagnostic, run_process
from core.scope import TargetScopeError, local_only_scope


class SubfinderAdapter:
    """Adapter responsible for executing and parsing Subfinder."""

    def __init__(self, scope=None):
        self.executable = shutil.which("subfinder")
        self.scope = scope or local_only_scope()

    def is_available(self):
        return self.executable is not None

    def scan(self, tool, target, executor):
        """Run Subfinder and return a standardized ToolResult."""
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            self.scope.validate_scan_target(target, require_resolution=False)
        except TargetScopeError as exc:
            return ToolResult(
                tool="subfinder", category="recon", target=target,
                started_at=started_at, finished_at=datetime.now(timezone.utc).isoformat(),
                return_code=None, status="scope_denied", stderr=f"Scope denied: {exc}",
            )
        if not self.is_available():
            return ToolResult(
                tool="subfinder", category="recon", target=target,
                started_at=started_at, finished_at=datetime.now(timezone.utc).isoformat(),
                return_code=None, status="missing", stderr="Executable not found: subfinder",
            )
        # Subfinder only works with domain names, not IPs
        parsed = urlsplit(target if "://" in target else "//" + target)
        candidate = (parsed.hostname or target).strip().strip("[]")
        try:
            ipaddress.ip_address(candidate)
            is_ip = True
        except ValueError:
            is_ip = candidate.lower() == "localhost"
        if is_ip:
            now = datetime.now(timezone.utc).isoformat()
            return ToolResult(
                tool="subfinder",
                category="recon",
                target=target,
                started_at=now,
                finished_at=now,
                return_code=0,
                status="skipped",
                stderr=f"subfinder domain-based enumeration requires a domain name; target is an IP address or localhost.",
                command=[tool.get("executable", "subfinder")],
            )
        command = [self.executable, "-d", candidate, "-silent", "-duc"]
        outcome = run_process(command, timeout=90)
        result = ToolResult(
            tool="subfinder", category="recon", target=target,
            started_at=started_at, finished_at=datetime.now(timezone.utc).isoformat(),
            return_code=outcome.return_code, stdout=outcome.stdout, stderr=outcome.stderr,
            duration_seconds=round(outcome.duration_seconds, 3), status=outcome.status,
            command=command,
        )
        return self._parse_result(result)

    def _parse_result(self, result):
        if result.status in {"missing", "scope_denied", "misconfigured"}:
            return result
        if not result.stdout and result.status != "success":
            return result
        original_status = result.status
        try:
            # Subfinder output is one subdomain per line
            hostnames = []
            for line in (result.stdout or "").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    hostnames.append(line)
            # Normalization will handle creating findings from hostnames
            result.findings = []
        except Exception as exc:
            if original_status == "success":
                result.status = "parse_error"
            result.stderr = append_diagnostic(
                result.stderr,
                f"Subfinder output parsing failed ({type(exc).__name__}): {exc}",
            )
        return result