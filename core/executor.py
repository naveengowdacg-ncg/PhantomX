import shutil
import subprocess
import time
from datetime import datetime, timezone
from typing import List
from core.models import ToolResult

class ToolExecutor:
    def __init__(self, logger):
        self.logger = logger

    def run(self, tool: dict, target: str) -> ToolResult:
        started = datetime.now(timezone.utc)
        command = [tool["executable"]] + [a.replace("{target}", target) for a in tool.get("args", [])]
        t0 = time.monotonic()
        if shutil.which(tool["executable"]) is None:
            return ToolResult(tool["name"], tool["category"], target, started.isoformat(), datetime.now(timezone.utc).isoformat(), None, status="missing", command=command, stderr=f"Executable not found: {tool['executable']}")
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=int(tool.get("timeout", 120)), shell=False)
            status = "success" if proc.returncode == 0 else "failed"
            return ToolResult(tool["name"], tool["category"], target, started.isoformat(), datetime.now(timezone.utc).isoformat(), proc.returncode, proc.stdout, proc.stderr, time.monotonic()-t0, status, command)
        except subprocess.TimeoutExpired as exc:
            return ToolResult(tool["name"], tool["category"], target, started.isoformat(), datetime.now(timezone.utc).isoformat(), None, str(exc.stdout or ""), "Tool timed out", time.monotonic()-t0, "timeout", command)
        except Exception as exc:
            return ToolResult(tool["name"], tool["category"], target, started.isoformat(), datetime.now(timezone.utc).isoformat(), None, "", str(exc), time.monotonic()-t0, "error", command)
