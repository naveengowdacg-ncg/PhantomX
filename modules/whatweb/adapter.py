import shutil
from datetime import datetime, timezone

from core.models import ToolResult
from core.process_utils import append_diagnostic, run_process
from core.scope import TargetScopeError, local_only_scope
from modules.whatweb.parser import WhatWebParser


class WhatWebAdapter:
    """Adapter responsible for executing and parsing WhatWeb."""

    def __init__(self, scope=None):
        self.executable = shutil.which("whatweb")
        self.parser = WhatWebParser()
        self.scope = scope or local_only_scope()

    def is_available(self):
        return self.executable is not None

    def scan(self, target, tool=None, executor=None, scope=None):
        """Run WhatWeb with redirects disabled and return a standardized result."""
        if tool is not None and executor is not None:
            return self._parse_result(executor.run(tool, target), target)
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            (scope or self.scope).validate_scan_target(target, require_resolution=True)
        except TargetScopeError as exc:
            return ToolResult(
                tool="whatweb", category="web", target=target,
                started_at=started_at, finished_at=datetime.now(timezone.utc).isoformat(),
                status="scope_denied", stderr=f"Scope denied: {exc}",
            )
        if not self.is_available():
            return ToolResult(
                tool="whatweb", category="web", target=target,
                started_at=started_at, finished_at=datetime.now(timezone.utc).isoformat(),
                status="missing", stderr="Executable not found: whatweb",
            )
        command = [self.executable, "--follow-redirect=never", target]
        outcome = run_process(command, timeout=180)
        result = ToolResult(
            tool="whatweb", category="web", target=target,
            started_at=started_at, finished_at=datetime.now(timezone.utc).isoformat(),
            return_code=outcome.return_code, stdout=outcome.stdout, stderr=outcome.stderr,
            duration_seconds=round(outcome.duration_seconds, 3), status=outcome.status,
            command=command,
        )
        return self._parse_result(result, target)

    def _parse_result(self, result, target):
        if result.status in {"missing", "scope_denied", "misconfigured"}:
            return result
        if not result.stdout and result.status != "success":
            return result
        original_status = result.status
        try:
            result.observations = self.parser.parse(result.stdout or "", target)
        except Exception as exc:
            if original_status == "success":
                result.status = "parse_error"
            result.stderr = append_diagnostic(
                result.stderr,
                f"WhatWeb output parsing failed ({type(exc).__name__}): {exc}",
            )
        return result
