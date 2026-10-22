from modules.nmap.adapter import NmapAdapter
from modules.whatweb.adapter import WhatWebAdapter
from modules.nuclei.adapter import NucleiAdapter

class AdapterManager:
    """Manage specialized tool adapters."""

    def __init__(self):
        self.adapters = {
            "nmap": NmapAdapter(),
            "whatweb": WhatWebAdapter(),
            "nuclei": NucleiAdapter(),
        }

    def get(self, tool_name):
        """Return the specialized adapter, if available."""
        return self.adapters.get(tool_name.lower())

    def run(
        self,
        tool,
        target,
        fallback_executor,
        extra_args=None,
    ):
        """Run a specialized adapter or use the fallback executor."""
        name = tool["name"].lower()
        adapter = self.get(name)

        if adapter:
            if not adapter.is_available():
                return fallback_executor.run(tool, target)

            if name == "nuclei":
                return adapter.scan(
                    target,
                    extra_args=extra_args,
                )

            return adapter.scan(target)

        return fallback_executor.run(tool, target)