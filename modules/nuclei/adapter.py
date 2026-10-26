import shutil
from datetime import datetime, timezone

from core.models import ToolResult
from core.process_utils import append_diagnostic, run_process
from core.scope import TargetScopeError, local_only_scope
from modules.nuclei.parser import NucleiParser


class NucleiAdapter:
    """Adapter responsible for executing and parsing Nuclei."""

    def __init__(self, scope=None):
        self.executable = shutil.which("nuclei")
        self.parser = NucleiParser()
        self.scope = scope or local_only_scope()

    def is_available(self):
        return self.executable is not None

    def scan(self, target, extra_args=None, tool=None, executor=None, scope=None):
        if tool is not None and executor is not None:
            result = (
                executor.run(tool, target)
                if extra_args is None
                else executor.run(tool, target, extra_args=extra_args)
            )
            return self._parse_result(result, target)
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            (scope or self.scope).validate_scan_target(target, require_resolution=True)
        except TargetScopeError as exc:
            return ToolResult(
                tool="nuclei", category="vuln", target=target,
                started_at=started_at, finished_at=datetime.now(timezone.utc).isoformat(),
                status="scope_denied", stderr=f"Scope denied: {exc}",
            )
        if not self.is_available():
            return ToolResult(
                tool="nuclei", category="vuln", target=target,
                started_at=started_at, finished_at=datetime.now(timezone.utc).isoformat(),
                status="missing", stderr="Executable not found: nuclei",
            )
        if extra_args is not None and (
            not isinstance(extra_args, list)
            or any(not isinstance(arg, str) for arg in extra_args)
        ):
            return ToolResult(
                tool="nuclei", category="vuln", target=target,
                started_at=started_at, finished_at=datetime.now(timezone.utc).isoformat(),
                status="misconfigured", stderr="Nuclei extra_args must be a list of strings.",
            )
        command = [self.executable, "-u", target, "-disable-redirects", "-jsonl"]
        if extra_args:
            command.extend(extra_args)
        outcome = run_process(command, timeout=300)
        result = ToolResult(
            tool="nuclei", category="vuln", target=target,
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
            result.findings = self.parser.parse(result.stdout or "", target)
        except Exception as exc:
            if original_status == "success":
                result.status = "parse_error"
            result.stderr = append_diagnostic(
                result.stderr,
                f"Nuclei output parsing failed ({type(exc).__name__}): {exc}",
            )
        return result
