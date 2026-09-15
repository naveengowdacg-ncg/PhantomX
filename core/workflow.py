from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import threading
import time

from core.models import Endpoint
from analysis.decision_engine import DecisionEngine

class WorkflowEngine:
    """Adaptive, profile-driven assessment workflow."""

    PROFILES = {
        "passive": ["recon"],
        "standard": ["recon", "web"],
        "full": ["recon", "web", "vuln"],
    }

    WEB_PORTS = {
        80: "http",
        443: "https",
        8080: "http",
        8443: "https",
    }

    def __init__(
    self,
    registry,
    executor,
    adapter_manager,
    normalizer,
    risk_engine,
    logger,
    max_workers=4,
):
        self.registry = registry
        self.executor = executor
        self.adapter_manager = adapter_manager
        self.normalizer = normalizer
        self.risk_engine = risk_engine
        self.decision_engine = DecisionEngine()
        self.logger = logger
        self.max_workers = max_workers

    def _show_loading(self, message, stop_event):
        """Display a simple loading spinner while a tool is running."""
        spinner = ["|", "/", "-", "\\"]
        index = 0

        while not stop_event.is_set():
            sys.stdout.write(
                f"\r{message} {spinner[index % len(spinner)]}"
            )
            sys.stdout.flush()

            index += 1
            time.sleep(0.15)

        sys.stdout.write("\r" + " " * (len(message) + 2) + "\r")
        sys.stdout.flush()

    def _run_tool_with_loading(self, tool, target):
        """Run a tool while displaying a live loading indicator."""
        stop_event = threading.Event()

        loading_thread = threading.Thread(
            target=self._show_loading,
            args=(
                f"Running {tool['name']} against {target}...",
                stop_event,
            ),
            daemon=True,
        )

        loading_thread.start()

        try:
            return self._run_tool(tool, target)
        finally:
            stop_event.set()
            loading_thread.join()
    
    def tools_for_profile(self, profile):
        categories = self.PROFILES[profile]

        return [
            tool
            for tool in self.registry.list()
            if tool.get("enabled", True)
            and tool.get("category") in categories
        ]

    def _run_tool(self, tool, target):
        """Execute, normalize, and score one tool result."""

        result = self.adapter_manager.run(
        tool,
        target,
        self.executor
        )
        result = self.normalizer.parse(result)
        result.findings = self.risk_engine.score_all(result.findings)

        return result

    def _find_tool(self, tools, name):
        """Return an enabled tool by name."""

        for tool in tools:
            if tool.get("name") == name and tool.get("enabled", True):
                return tool

        return None

    def _derive_web_endpoints(self, nmap_result):
        """
        Convert discovered HTTP/HTTPS services into endpoint objects.

        Nmap discovers the service. PhantomX interprets that discovery
        and creates the endpoint that a web tool should assess.
        """

        endpoints = []

        for service in nmap_result.services:

            if service.state != "open":
                continue

            scheme = self.WEB_PORTS.get(service.port)

            if scheme is None:
                continue

            url = f"{scheme}://{nmap_result.target}"

            if service.port not in {80, 443}:
                url = f"{scheme}://{nmap_result.target}:{service.port}"

            endpoint = Endpoint(
                url=url,
                scheme=scheme,
                host=nmap_result.target,
                port=service.port,
                source_tool="nmap",
                metadata={
                    "service": service.service,
                    "version": service.version,
                },
            )

            endpoints.append(endpoint)

        return endpoints

    def run(self, session):
        """
        Execute an adaptive workflow.

        Discovery tools run first. Their results are interpreted by
        PhantomX before relevant downstream tools are selected.
        """

        selected = self.tools_for_profile(session.profile)

        self.logger.info(
            "Workflow start: profile=%s target=%s tools=%s",
            session.profile,
            session.target,
            [tool["name"] for tool in selected],
        )

        # ---------------------------------------------------------
        # Stage 1: Discovery
        # ---------------------------------------------------------

        discovery_tools = [
            tool
            for tool in selected
            if tool.get("category") == "recon"
        ]

        discovery_results = []

        if discovery_tools:

            with ThreadPoolExecutor(
                max_workers=self.max_workers
            ) as pool:

                futures = {
                    pool.submit(
                        self._run_tool_with_loading,
                        tool,
                        session.target,
                    ): tool
                    for tool in discovery_tools
                }

                for future in as_completed(futures):

                    result = future.result()

                    session.results.append(result)
                    discovery_results.append(result)

                    self.logger.info(
                        "Discovery tool %s finished with %s findings",
                        result.tool,
                        len(result.findings),
                    )

        # ---------------------------------------------------------
        # Stage 2: Interpret discovery results
        # ---------------------------------------------------------

        decisions = self.decision_engine.decide(
            discovery_results
        )

        web_endpoints = []

        for decision in decisions:

            self.logger.info(
                "Assessment decision: %s -> %s",
                decision["type"],
                decision["target"],
            )

            if decision["type"] == "web_assessment":

                endpoint = Endpoint(
                    url=decision["target"],
                    scheme=(
                        "https"
                        if decision["target"].startswith("https://")
                        else "http"
                    ),
                    host=decision["host"],
                    port=decision["port"],
                    source_tool="nmap",
                    metadata={
                        "service": decision["service"],
                        "version": decision["version"],
                        "decision": decision["type"],
                    },
                )

                if endpoint.url not in {
                    existing.url
                    for existing in web_endpoints
                }:
                    web_endpoints.append(endpoint)

            elif decision["type"] == "database_assessment":

                session.notes.append(
                    f"Database assessment relevant for "
                    f"{decision['port']}/{decision['protocol']} "
                    f"({decision['service']})."
                )

        # ---------------------------------------------------------
        # Stage 3: Adaptive web assessment
        # ---------------------------------------------------------

        web_tools = [
            tool
            for tool in selected
            if tool.get("category") == "web"
        ]

        whatweb = self._find_tool(web_tools, "whatweb")

        if whatweb and web_endpoints:

            for endpoint in web_endpoints:

                self.logger.info(
                    "Adaptive handoff: nmap -> whatweb -> %s",
                    endpoint.url,
                )

                result = self._run_tool_with_loading(
                    whatweb,
                    endpoint.url,
                )

                result.endpoints.append(endpoint)

                for observation in result.observations:
                    observation.endpoint = endpoint

                session.results.append(result)

                self.logger.info(
                    "Web tool %s finished with %s observations",
                    result.tool,
                    len(result.observations),
                )

        elif web_endpoints:

            session.notes.append(
                "Web endpoints discovered, but WhatWeb is not enabled."
            )

        # ---------------------------------------------------------
        # Stage 4: Remaining web tools
        # ---------------------------------------------------------

        remaining_web_tools = [
            tool
            for tool in web_tools
            if tool.get("name") != "whatweb"
        ]

        if remaining_web_tools and web_endpoints:

            with ThreadPoolExecutor(
                max_workers=self.max_workers
            ) as pool:

                futures = {}

                for tool in remaining_web_tools:

                    for endpoint in web_endpoints:

                        futures[
                            pool.submit(
                                self._run_tool_with_loading,
                                tool,
                                endpoint.url,
                            )
                        ] = (
                            tool,
                            endpoint,
                        )

                for future in as_completed(futures):

                    tool, endpoint = futures[future]

                    result = future.result()
                    result.endpoints.append(endpoint)

                    session.results.append(result)

                    self.logger.info(
                        "Web tool %s finished with %s findings",
                        result.tool,
                        len(result.findings),
                    )

        return session