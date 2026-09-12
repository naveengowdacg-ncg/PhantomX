from modules.nmap.adapter import NmapAdapter
from modules.whatweb.adapter import WhatWebAdapter


class AdapterManager:
    """Manage specialized tool adapters."""

    def __init__(self):
        self.adapters = {
            "nmap": NmapAdapter(),
            "whatweb": WhatWebAdapter(),
        }

    def get(self, tool_name):
        """Return the specialized adapter for a tool, if available."""

        return self.adapters.get(tool_name.lower())

    def run(self, tool, target, fallback_executor):
        """
        Run a tool through its specialized adapter when available.

        If the specialized adapter is unavailable, use the generic
        executor so the tool failure is represented as a ToolResult
        instead of raising an exception.
        """

        name = tool["name"].lower()

        adapter = self.get(name)

        if adapter:

            if not adapter.is_available():
                return fallback_executor.run(
                    tool,
                    target
                )

            return adapter.scan(target)

        return fallback_executor.run(
            tool,
            target
        )