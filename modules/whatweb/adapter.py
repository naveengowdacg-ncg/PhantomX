import shutil
import subprocess
import time
from datetime import datetime, timezone

from core.models import ToolResult
from modules.whatweb.parser import WhatWebParser


class WhatWebAdapter:
    """Adapter responsible for executing and parsing WhatWeb."""

    def __init__(self):
        self.executable = shutil.which("whatweb")
        self.parser = WhatWebParser()

    def is_available(self):
        """Check whether WhatWeb is installed and accessible."""
        return self.executable is not None

    def scan(self, target):
        """Run WhatWeb against a target and return a ToolResult."""

        if not self.is_available():
            raise RuntimeError(
                "WhatWeb is not installed or not available in PATH."
            )

        command = [
            self.executable,
            target
        ]

        started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.perf_counter()

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=180,
                shell=False
            )

            duration = time.perf_counter() - start_time
            finished_at = datetime.now(timezone.utc).isoformat()

            status = (
                "success"
                if process.returncode == 0
                else "failed"
            )

            result = ToolResult(
                tool="whatweb",
                category="web",
                target=target,
                started_at=started_at,
                finished_at=finished_at,
                return_code=process.returncode,
                stdout=process.stdout,
                stderr=process.stderr,
                duration_seconds=round(duration, 3),
                status=status,
                command=command
            )

            if process.returncode == 0:
                result.observations = self.parser.parse(
                    process.stdout,
                    target
                )

            return result

        except subprocess.TimeoutExpired as exc:

            duration = time.perf_counter() - start_time

            return ToolResult(
                tool="whatweb",
                category="web",
                target=target,
                started_at=started_at,
                finished_at=datetime.now(timezone.utc).isoformat(),
                return_code=None,
                stdout=str(exc.stdout or ""),
                stderr="WhatWeb timed out.",
                duration_seconds=round(duration, 3),
                status="timeout",
                command=command
            )