import shutil
from datetime import datetime, timezone

from core.models import ToolResult
from core.process_utils import append_diagnostic, run_process
from core.scope import TargetScopeError, local_only_scope


class DnsxAdapter:
    """Adapter responsible for executing and parsing DNSX."""

    def __init__(self, scope=None):
        self.executable = shutil.which("dnsx")
        self.scope = scope or local_only_scope()

    def is_available(self):
        return self.executable is not None

    def scan(self, tool, target, executor):
        """Run DNSX and return a standardized ToolResult."""
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            self.scope.validate_scan_target(target, require_resolution=False)
        except TargetScopeError as exc:
            return ToolResult(
                tool="dnsx", category="recon", target=target,
                started_at=started_at, finished_at=datetime.now(timezone.utc).isoformat(),
                return_code=None, status="scope_denied", stderr=f"Scope denied: {exc}",
            )
        if not self.is_available():
            return ToolResult(
                tool="dnsx", category="recon", target=target,
                started_at=started_at, finished_at=datetime.now(timezone.utc).isoformat(),
                return_code=None, status="missing", stderr="Executable not found: dnsx",
            )
        command = [self.executable, "-l", target, "-a", "-aaaa", "-cname", "-resp", "-silent", "-duc"]
        outcome = run_process(command, timeout=60)
        result = ToolResult(
            tool="dnsx", category="recon", target=target,
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
            # DNSX output is JSONL or plain text
            # Normalization will handle creating findings from output
            result.findings = []
        except Exception as exc:
            if original_status == "success":
                result.status = "parse_error"
            result.stderr = append_diagnostic(
                result.stderr,
                f"DNSX output parsing failed ({type(exc).__name__}): {exc}",
            )
        return result