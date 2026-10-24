from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import threading
import time
from urllib.parse import urlsplit

from core.models import Endpoint
from analysis.decision_engine import DecisionEngine
from analysis.correlation import CorrelationEngine

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
    scope=None,
):
        self.registry = registry
        self.executor = executor
        self.adapter_manager = adapter_manager
        self.normalizer = normalizer
        self.risk_engine = risk_engine
        self.decision_engine = DecisionEngine()
        self.correlation_engine = CorrelationEngine()
        self.logger = logger
        self.max_workers = max_workers
        self.scope = scope
        self.max_discovered_hosts = 25

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

    def _run_tool_with_loading(self, tool, target, extra_args=None):
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
            return self._run_tool(
                tool,
                target,
                extra_args=extra_args,
            )
        finally:
            stop_event.set()
            loading_thread.join()

    def tools_for_profile(self, profile):
        if profile not in self.PROFILES:
            raise ValueError(f"Unknown scan profile: {profile}")
        categories = self.PROFILES[profile]

        return [
            tool
            for tool in self.registry.list()
            if tool.get("enabled", True)
            and tool.get("category") in categories
        ]

    def _run_tool(self, tool, target, extra_args=None):
        """Execute, normalize, and score one tool result."""

        result = self.adapter_manager.run(
            tool,
            target,
            self.executor,
            extra_args=extra_args,
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

        # Safely enrich passive subdomain discoveries with HTTP metadata.
        # Newly discovered hosts are actively probed only when the configured
        # scope explicitly authorizes them (including wildcard/CIDR rules).
        subfinder_hosts = []
        for result in discovery_results:
            if result.tool != "subfinder":
                continue
            for finding in result.findings:
                hostname = (finding.metadata or {}).get("hostname")
                if hostname:
                    subfinder_hosts.append(hostname)

        httpx_tool = self._find_tool(selected, "httpx")
        approved_hosts = []
        if self.scope is not None and httpx_tool is not None:
            for host in dict.fromkeys(subfinder_hosts):
                if len(approved_hosts) >= self.max_discovered_hosts:
                    session.notes.append(
                        f"Subdomain enrichment capped at {self.max_discovered_hosts} hosts."
                    )
                    break
                try:
                    approved = self.scope.validate(host)
                except Exception:
                    continue
                if approved != session.target and approved not in approved_hosts:
                    approved_hosts.append(approved)

        if approved_hosts:
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futures = {
                    pool.submit(
                        self._run_tool_with_loading,
                        httpx_tool,
                        host,
                    ): host
                    for host in approved_hosts
                }
                for future in as_completed(futures):
                    result = future.result()
                    session.results.append(result)
                    discovery_results.append(result)
                    self.logger.info(
                        "Scoped httpx enrichment for %s finished with status %s",
                        result.target,
                        result.status,
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

        # Promote reachable httpx URLs to endpoints only after checking that
        # their host is inside the configured authorization scope.
        existing_endpoint_urls = {endpoint.url for endpoint in web_endpoints}
        for result in discovery_results:
            if result.tool != "httpx" or result.status != "success":
                continue
            for finding in result.findings:
                url = (finding.metadata or {}).get("url")
                if not url:
                    continue
                try:
                    parsed = urlsplit(url)
                    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                        continue
                    if self.scope is not None:
                        self.scope.validate(parsed.hostname)
                    elif parsed.hostname != session.target:
                        # Fail closed for discovered hosts if no scope validator
                        # was provided to the workflow engine.
                        continue
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    normalized_url = f"{parsed.scheme}://{parsed.netloc or parsed.hostname}"
                    if normalized_url in existing_endpoint_urls:
                        continue
                    endpoint = Endpoint(
                        url=normalized_url,
                        scheme=parsed.scheme,
                        host=parsed.hostname,
                        port=port,
                        source_tool="httpx",
                        metadata={"discovered_path": parsed.path or "/", "status_code": (finding.metadata or {}).get("status_code")},
                    )
                    web_endpoints.append(endpoint)
                    existing_endpoint_urls.add(normalized_url)
                except Exception:
                    continue

        # ---------------------------------------------------------
        # Stage 3: Prepare adaptive web assessment
        # ---------------------------------------------------------

        assessment_tools = [
            tool
            for tool in selected
            if tool.get("category") in {"web", "vuln"}
        ]

        # Track tools already executed for a target
        executed_tools = {
            (result.tool, result.target)
            for result in session.results
        }

        # ---------------------------------------------------------
        # Stage 4: Execute tools selected by the decision engine
        # ---------------------------------------------------------

        recommended_tool_names = set()

        for decision in decisions:
            if decision["type"] in {
                "web_assessment",
                "database_assessment",
            }:
                recommended_tool_names.update(
                    decision.get("recommended_tools", [])
                )

        selected_web_tools = [
            tool
            for tool in assessment_tools
            if tool.get("name") in recommended_tool_names
            and tool.get("enabled", True)
        ]

        if selected_web_tools and web_endpoints:

            for tool in selected_web_tools:

                for endpoint in web_endpoints:
                    # TLS testing is meaningful only for HTTPS endpoints.
                    if tool.get("name") == "testssl" and endpoint.scheme != "https":
                        continue
                    if (tool["name"], endpoint.url) in executed_tools:
                        continue

                    self.logger.info(
                        "Decision-driven assessment: %s -> %s",
                        tool["name"],
                        endpoint.url,
                    )

                    result = self._run_tool_with_loading(
                        tool,
                        endpoint.url,
                    )
                    result.endpoints.append(endpoint)

                    for observation in result.observations:
                        observation.endpoint = endpoint

                    session.results.append(result)
                    executed_tools.add((tool["name"], endpoint.url))

                    self.logger.info(
                        "Assessment tool %s finished with status %s and %s findings",
                        result.tool,
                        result.status,
                        len(result.findings),
                    )

        elif web_endpoints:

            session.notes.append(
                "Web endpoints discovered, but no recommended "
                "web assessment tools are enabled."
            )


        # ---------------------------------------------------------
        # Stage 4B: Execute database assessments
        # ---------------------------------------------------------

        database_decisions = [
            decision
            for decision in decisions
            if decision["type"] == "database_assessment"
        ]

        database_tool_names = set()

        for decision in database_decisions:
            database_tool_names.update(
                decision.get("recommended_tools", [])
            )

        selected_database_tools = [
            tool
            for tool in selected
            if tool.get("name") in database_tool_names
            and tool.get("category") == "vuln"
            and tool.get("enabled", True)
        ]

        for decision in database_decisions:

            for tool in selected_database_tools:

                target = decision["target"]

                if (tool["name"], target) in executed_tools:
                    continue

                self.logger.info(
                    "Database assessment: %s -> %s",
                    tool["name"],
                    target,
                )

                result = self._run_tool_with_loading(
                    tool,
                    target,
                    extra_args=["--tags", "mysql"],
                )

                session.results.append(result)

                executed_tools.add(
                    (tool["name"], target)
                )

                self.logger.info(
                    "Database assessment tool %s "
                    "finished with status %s",
                    tool["name"],
                    result.status,
                )

        # Stage 5: Follow-up decisions from observations
        follow_up_decisions = self.decision_engine.decide_from_observations(
            session.results
        )

        # Build lookup of tools allowed by the current profile
        selected_tools_by_name = {
            tool["name"]: tool
            for tool in selected
            if tool.get("enabled", True)
        }

        for decision in follow_up_decisions:

            self.logger.info(
                f"Follow-up decision: {decision['type']} "
                f"for {decision['target']}"
            )

            session.notes.append(
                f"Follow-up assessment recommended: "
                f"{decision['type']} for {decision['target']}. "
                f"Reason: {decision['reason']}"
            )

            # Execute tools recommended by the decision engine
            for tool_name in decision.get("recommended_tools", []):

                tool = selected_tools_by_name.get(tool_name)

                # Tool is not part of the current profile
                if not tool:
                    self.logger.info(
                        f"Skipping follow-up tool {tool_name}: "
                        f"not enabled or not selected by profile."
                    )
                    continue

                target = decision["target"]

                # Prevent duplicate execution
                if (tool_name, target) in executed_tools:
                    continue

                self.logger.info(
                    f"Running follow-up tool {tool_name} "
                    f"against {target}"
                )

                result = self._run_tool_with_loading(
                    tool,
                    target
                )

                # Attach the endpoint that triggered this decision
                endpoint = next(
                    (
                        endpoint
                        for endpoint in web_endpoints
                        if endpoint.url == target
                    ),
                    None
                )

                if endpoint:
                    result.endpoints.append(endpoint)

                    for observation in result.observations:
                        observation.endpoint = endpoint

                session.results.append(result)

                executed_tools.add(
                    (tool_name, target)
                )

                self.logger.info(
                    f"Follow-up tool {tool_name} "
                    f"completed with status {result.status}"
                )

        self._correlate_session_findings(session)
        return session

    def _correlate_session_findings(self, session):
        """Annotate findings with conservative cross-tool correlation metadata."""
        findings = [
            finding
            for result in session.results
            for finding in result.findings
        ]

        # Clear annotations before recalculating, so reprocessing a session
        # cannot leave stale group data.
        for finding in findings:
            if isinstance(finding.metadata, dict):
                finding.metadata.pop("correlation", None)

        groups = self.correlation_engine.correlate(findings)
        multi_finding_groups = [
            group for group in groups if len(group.findings) > 1
        ]

        for group in multi_finding_groups:
            details = {
                "key": group.key,
                "sources": group.sources,
                "confidence": group.confidence,
                "group_size": len(group.findings),
            }
            for finding in group.findings:
                if not isinstance(finding.metadata, dict):
                    finding.metadata = {}
                finding.metadata["correlation"] = details.copy()

        # Keep tool-level findings intact for auditability. Reports can use
        # the same keys to present one representative per correlated group.
        session.notes = [
            note for note in session.notes
            if not note.startswith("Finding correlation:")
        ]
        session.notes.append(
            "Finding correlation: "
            f"{len(findings)} raw findings, {len(groups)} distinct groups, "
            f"{len(multi_finding_groups)} groups with multiple related findings."
        )
        self.logger.info(
            "Finding correlation complete: %s raw findings, %s groups, %s multi-finding groups",
            len(findings), len(groups), len(multi_finding_groups),
        )
