
import shutil
import subprocess
import time
from datetime import datetime, timezone
from typing import List

from core.models import ToolResult


class ToolExecutor:
    def __init__(self, logger):
        self.logger = logger

    @staticmethod
    def _nikto_scan_completed(return_code: int, stdout: str, stderr: str) -> bool:
        """Recognize Nikto's completed scan when findings cause exit code 1."""
        if return_code != 1 or stderr.strip():
            return False

        output = stdout or ""

        # Require a completion summary, not just help text or partial output.
        return (
            "host(s) tested" in output
            and "item(s) reported on remote host" in output
            and "End Time:" in output
        )

    def run(self, tool: dict, target: str) -> ToolResult:
        started = datetime.now(timezone.utc)
        command = [tool["executable"]] + [
            a.replace("{target}", target)
            for a in tool.get("args", [])
        ]
        t0 = time.monotonic()

        if shutil.which(tool["executable"]) is None:
            return ToolResult(
                tool["name"],
                tool["category"],
                target,
                started.isoformat(),
                datetime.now(timezone.utc).isoformat(),
                None,
                status="missing",
                command=command,
                stderr=f"Executable not found: {tool['executable']}",
            )

        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=int(tool.get("timeout", 120)),
                shell=False,
            )

            completed_nikto = (
                tool["name"].lower() == "nikto"
                and self._nikto_scan_completed(
                    proc.returncode,
                    proc.stdout,
                    proc.stderr,
                )
            )

            status = (
                "success"
                if proc.returncode == 0 or completed_nikto
                else "failed"
            )

            return ToolResult(
                tool["name"],
                tool["category"],
                target,
                started.isoformat(),
                datetime.now(timezone.utc).isoformat(),
                proc.returncode,
                proc.stdout,
                proc.stderr,
                time.monotonic() - t0,
                status,
                command,
            )

        except subprocess.TimeoutExpired as exc:
            return ToolResult(
                tool["name"],
                tool["category"],
                target,
                started.isoformat(),
                datetime.now(timezone.utc).isoformat(),
                None,
                str(exc.stdout or ""),
                "Tool timed out",
                time.monotonic() - t0,
                "timeout",
                command,
            )

        except Exception as exc:
            return ToolResult(
                tool["name"],
                tool["category"],
                target,
                started.isoformat(),
                datetime.now(timezone.utc).isoformat(),
                None,
                "",
                str(exc),
                time.monotonic() - t0,
                "error",
                command,
            )
