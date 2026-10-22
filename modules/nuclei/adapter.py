import shutil
import subprocess
import time
from datetime import datetime, timezone

from core.models import ToolResult
from modules.nuclei.parser import NucleiParser


class NucleiAdapter:
    """Adapter responsible for executing and parsing Nuclei."""

    def __init__(self):
        self.executable = shutil.which("nuclei")
        self.parser = NucleiParser()

    def is_available(self):
        return self.executable is not None

    def scan(self, target, extra_args=None):
        if not self.is_available():
            raise RuntimeError(
                "Nuclei is not installed or not available in PATH."
            )

        command = [
            self.executable,
            "-u",
            target,
            "-jsonl",
        ]

        if extra_args:
            command.extend(extra_args)

        started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.perf_counter()

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300,
                shell=False,
            )

            duration = time.perf_counter() - start_time
            finished_at = datetime.now(timezone.utc).isoformat()

            status = (
                "success"
                if process.returncode == 0
                else "failed"
            )

            result = ToolResult(
                tool="nuclei",
                category="vuln",
                target=target,
                started_at=started_at,
                finished_at=datetime.now(timezone.utc).isoformat(),
                return_code=process.returncode,
                stdout=process.stdout,
                stderr=process.stderr,
                duration_seconds=round(duration, 3),
                status=status,
                command=command,
            )

            if process.returncode == 0:
                result.findings = self.parser.parse(
                    process.stdout,
                    target,
                )

            return result

        except subprocess.TimeoutExpired as exc:
            duration = time.perf_counter() - start_time

            return ToolResult(
                tool="nuclei",
                category="vuln",
                target=target,
                started_at=started_at,
                finished_at=datetime.now(timezone.utc).isoformat(),
                return_code=None,
                stdout=str(exc.stdout or ""),
                stderr="Nuclei timed out.",
                duration_seconds=round(duration, 3),
                status="timeout",
                command=command,
            )
