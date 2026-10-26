"""Structural interface for explicitly registered PhantomX tool adapters."""

from typing import Any, Dict, List, Optional, Protocol

from core.models import ToolResult


class PluginAdapter(Protocol):
    """Contract for adapters registered with AdapterManager.register."""

    def scan(
        self,
        tool: Dict[str, Any],
        target: str,
        executor: Any,
        extra_args: Optional[List[str]] = None,
    ) -> ToolResult:
        ...
