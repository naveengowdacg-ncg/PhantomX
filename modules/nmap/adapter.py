import shutil
import subprocess
import time
from datetime import datetime, timezone

from core.models import ToolResult
from modules.nmap.parser import NmapParser


class NmapAdapter:
    """Adapter responsible for executing and parsing Nmap."""

    def __init__(self):
        self.executable = shutil.which("nmap")
        self.parser = NmapParser()

    def is_available(self):
        """Check whether Nmap is installed and accessible."""
        return self.executable is not None

    def scan(self, target):
        """Run Nmap and return a standardized ToolResult."""

        if not self.is_available():
            raise RuntimeError(
                "Nmap is not installed or not available in PATH."
            )

        command = [
            self.executable,
            "-sV",
            target
        ]

        started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.perf_counter()

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180
        )

        duration = time.perf_counter() - start_time
        finished_at = datetime.now(timezone.utc).isoformat()

        services = []

        if process.returncode == 0:
            services = self.parser.parse(process.stdout)

        status = "success" if process.returncode == 0 else "failed"

        return ToolResult(
            tool="nmap",
            category="recon",
            target=target,
            started_at=started_at,
            finished_at=finished_at,
            return_code=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
            duration_seconds=round(duration, 3),
            status=status,
            command=command,
            services=services
        )