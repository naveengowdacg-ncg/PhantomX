from modules.nmap.adapter import NmapAdapter
from modules.whatweb.adapter import WhatWebAdapter
from modules.nuclei.adapter import NucleiAdapter
from modules.nikto.adapter import NiktoAdapter
from modules.subfinder.adapter import SubfinderAdapter
from modules.dnsx.adapter import DnsxAdapter
from modules.httpx.adapter import HttpxAdapter
from modules.katana.adapter import KatanaAdapter
from modules.testssl.adapter import TestsslAdapter
from modules.gobuster.adapter import GobusterAdapter


class AdapterManager:
    """Manage specialized tool adapters."""

    def __init__(self, scope=None):
        self.scope = scope
        self.adapters = {
            "nmap": NmapAdapter(scope=scope),
            "whatweb": WhatWebAdapter(scope=scope),
            "nuclei": NucleiAdapter(scope=scope),
            "nikto": NiktoAdapter(scope=scope),
            "subfinder": SubfinderAdapter(scope=scope),
            "dnsx": DnsxAdapter(scope=scope),
            "httpx": HttpxAdapter(scope=scope),
            "katana": KatanaAdapter(scope=scope),
            "testssl": TestsslAdapter(scope=scope),
            "gobuster": GobusterAdapter(scope=scope),
        }

    def get(self, tool_name):
        """Return the specialized adapter, if available."""
        return self.adapters.get(tool_name.lower())

    def register(self, tool_name, adapter, replace=False):
        """Register an adapter implementing the documented plugin scan contract."""
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("Adapter name must be a non-empty string.")
        if not callable(getattr(adapter, "scan", None)):
            raise ValueError("Adapter must provide a callable scan method.")
        key = tool_name.strip().casefold()
        if key in self.adapters and not replace:
            raise ValueError(f"An adapter is already registered for {tool_name}.")
        self.adapters[key] = adapter
        return adapter

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
            if name in {"subfinder", "dnsx", "httpx", "katana", "testssl", "gobuster"}:
                return adapter.scan(tool, target, fallback_executor)
            if name == "nuclei":
                return adapter.scan(
                    target,
                    extra_args=extra_args,
                    tool=tool,
                    executor=fallback_executor,
                )
            if name in {"nmap", "whatweb", "nikto"}:
                return adapter.scan(
                    target,
                    tool=tool,
                    executor=fallback_executor,
                )

            # Custom adapters receive the full tool record and shared executor.
            # The executor remains responsible for command execution safeguards.
            if extra_args is None:
                return adapter.scan(tool, target, fallback_executor)
            return adapter.scan(
                tool, target, fallback_executor, extra_args=extra_args,
            )

        return fallback_executor.run(tool, target)