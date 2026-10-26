import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from core.models import ToolResult
from core.preflight import redirect_policy_error
from core.process_utils import append_diagnostic, run_process
from core.scope import TargetScopeError, local_only_scope


class ToolExecutor:
    """Execute configured scanner commands with scope and resource safeguards."""

    def __init__(self, logger, scope=None):
        self.logger = logger
        self.scope = scope or local_only_scope()
        self._cancel_event = None

    def set_cancel_event(self, event):
        """Attach a workflow cancellation event for the duration of a run."""
        self._cancel_event = event

    @staticmethod
    def _nikto_scan_completed(return_code, stdout, stderr):
        if return_code != 1 or stderr.strip():
            return False
        output = stdout or ""
        return (
            "host(s) tested" in output
            and "item(s) reported on remote host" in output
            and "End Time:" in output
        )

    @staticmethod
    def _result(tool, target, status, stderr, command=None, stdout="", return_code=None, duration=0.0):
        tool = tool if isinstance(tool, dict) else {}
        now = datetime.now(timezone.utc).isoformat()
        return ToolResult(
            tool=tool.get("name", "unknown"),
            category=tool.get("category", "unknown"),
            target=target,
            started_at=now,
            finished_at=now,
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration,
            status=status,
            command=command or [],
        )

    def run(self, tool, target, extra_args=None, cancel_event=None):
        retries = tool.get("retries", 0) if isinstance(tool, dict) else 0
        retry_on_timeout = tool.get("retry_on_timeout", False) if isinstance(tool, dict) else False
        if (
            isinstance(retries, bool)
            or not isinstance(retries, int)
            or retries < 0
            or retries > 3
            or not isinstance(retry_on_timeout, bool)
        ):
            return self._result(
                tool, target, "misconfigured",
                "retries must be an integer from 0 to 3 and retry_on_timeout must be true or false.",
            )

        active_cancel_event = cancel_event or self._cancel_event
        attempts = []
        for attempt_index in range(retries + 1):
            result = self._run_once(
                tool, target, extra_args=extra_args, cancel_event=active_cancel_event
            )
            retryable = (
                result.status == "error" and result.return_code is None
            ) or (result.status == "timeout" and retry_on_timeout)
            if (
                not retryable
                or attempt_index >= retries
                or (active_cancel_event is not None and active_cancel_event.is_set())
            ):
                if attempts:
                    previous_stdout = [item.stdout for item in attempts if item.stdout]
                    previous_stderr = [
                        f"Attempt {index + 1}: {item.stderr}"
                        for index, item in enumerate(attempts)
                        if item.stderr
                    ]
                    result.stdout = "\n".join(
                        previous_stdout + ([result.stdout] if result.stdout else [])
                    )
                    result.stderr = append_diagnostic(
                        "\n".join(previous_stderr + ([result.stderr] if result.stderr else [])),
                        f"Execution retried {len(attempts)} time(s); final status: {result.status}.",
                    )
                    result.duration_seconds += sum(item.duration_seconds for item in attempts)
                    result.started_at = attempts[0].started_at
                return result

            attempts.append(result)
            log_warning = getattr(self.logger, "warning", None)
            if callable(log_warning):
                log_warning(
                    "Retrying %s after %s (attempt %s of %s)",
                    tool.get("name", "unknown"),
                    result.status,
                    attempt_index + 1,
                    retries,
                )
        return attempts[-1]

    def _run_once(self, tool, target, extra_args=None, cancel_event=None):
        started = datetime.now(timezone.utc)
        start_time = time.monotonic()
        if not isinstance(tool, dict):
            return self._result(tool, target, "misconfigured", "Tool configuration must be an object.")

        executable = tool.get("executable")
        args = tool.get("args", [])
        if (
            not isinstance(executable, str)
            or not executable.strip()
            or not isinstance(args, list)
            or any(not isinstance(arg, str) for arg in args)
            or (extra_args is not None and (
                not isinstance(extra_args, list)
                or any(not isinstance(arg, str) for arg in extra_args)
            ))
        ):
            return self._result(
                tool, target, "misconfigured",
                "Tool executable, args, or extra_args configuration is malformed.",
            )
        if not any("{target}" in arg for arg in args):
            return self._result(
                tool, target, "misconfigured",
                "Tool args must include the {target} placeholder so scope validation applies to the command target.",
            )
        if cancel_event is not None and cancel_event.is_set():
            return self._result(
                tool, target, "cancelled", "Tool execution cancelled before process launch."
            )

        timeout = tool.get("timeout", 120)
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, int)
            or not 1 <= timeout <= 3600
        ):
            return self._result(
                tool, target, "misconfigured",
                "Tool timeout must be an integer from 1 to 3600 seconds.",
            )
        policy_error = redirect_policy_error(tool)
        if policy_error:
            return self._result(tool, target, "misconfigured", policy_error)

        tool_name = str(tool.get("name", "")).casefold()
        try:
            self.scope.validate_scan_target(
                target, require_resolution=tool_name not in {"subfinder", "dnsx"}
            )
        except TargetScopeError as exc:
            return self._result(tool, target, "scope_denied", f"Scope denied: {exc}")

        required_files = tool.get("required_files", [])
        if not isinstance(required_files, list) or any(
            not isinstance(path, str) or not path.strip()
            for path in required_files
        ):
            return self._result(
                tool, target, "misconfigured",
                "required_files must be a list of non-empty paths.",
            )
        missing_files = []
        for raw_path in required_files:
            expanded = os.path.expandvars(os.path.expanduser(raw_path.strip()))
            try:
                if not Path(expanded).is_file():
                    missing_files.append(raw_path)
            except (OSError, ValueError):
                missing_files.append(raw_path)
        if missing_files:
            return self._result(
                tool, target, "misconfigured",
                "Required tool input file(s) are missing: " + ", ".join(missing_files),
            )

        command = [executable] + [arg.replace("{target}", target) for arg in args]
        if extra_args:
            command.extend(extra_args)
        if shutil.which(executable) is None:
            return self._result(
                tool, target, "missing", f"Executable not found: {executable}", command
            )

        outcome = run_process(command, timeout=timeout, cancel_event=cancel_event)
        status = outcome.status
        if status == "failed" and tool_name == "nikto" and self._nikto_scan_completed(
            outcome.return_code, outcome.stdout, outcome.stderr
        ):
            status = "success"
        return ToolResult(
            tool=tool.get("name", "unknown"),
            category=tool.get("category", "unknown"),
            target=target,
            started_at=started.isoformat(),
            finished_at=datetime.now(timezone.utc).isoformat(),
            return_code=outcome.return_code,
            stdout=outcome.stdout,
            stderr=outcome.stderr,
            duration_seconds=max(outcome.duration_seconds, time.monotonic() - start_time),
            status=status,
            command=command,
        )
