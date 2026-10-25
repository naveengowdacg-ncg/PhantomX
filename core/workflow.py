from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import sys
import threading
import time
from urllib.parse import urlsplit

from core.models import Endpoint, ToolResult
from core.scope import TargetScopeError, normalize_http_url, normalize_target
from analysis.decision_engine import DecisionEngine
from analysis.correlation import CorrelationEngine

class WorkflowEngine:
    """Adaptive, profile-driven assessment workflow."""

    PROFILES = {
        "passive": ["recon"],
        "stealth": ["recon"],
        "standard": ["recon", "web"],
        "full": ["recon", "web", "vuln"],
        "aggressive": ["recon", "web", "vuln"],
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
            if isinstance(tool, dict)
            and isinstance(tool.get("name"), str)
            and isinstance(tool.get("category"), str)
            and isinstance(tool.get("enabled", True), bool)
            and tool.get("enabled", True)
            and tool.get("category") in categories
        ]

    def _run_tool(self, tool, target, extra_args=None):
        """Execute, normalize, and score one tool result without aborting peers."""
        try:
            result = self.adapter_manager.run(
                tool,
                target,
                self.executor,
                extra_args=extra_args,
            )
            result = self.normalizer.parse(result)
            result.findings = self.risk_engine.score_all(result.findings)
            return result
        except Exception as exc:
            log_exception = getattr(self.logger, "exception", None)
            if callable(log_exception):
                log_exception("Tool %s failed in workflow: %s", tool.get("name", "unknown"), exc)
            now = datetime.now(timezone.utc).isoformat()
            return ToolResult(
                tool=tool.get("name", "unknown"),
                category=tool.get("category", "unknown"),
                target=target,
                started_at=now,
                finished_at=now,
                return_code=None,
                status="error",
                command=[tool.get("executable", "")],
                stderr=f"Workflow tool error: {exc}",
            )

    def _validated_active_target(self, target, session_target):
        """Authorize a host, host:port, or HTTP(S) endpoint before a probe."""
        if not isinstance(target, str) or not target.strip():
            raise TargetScopeError("Active probe target must be a non-empty string.")
        raw = target.strip()
        endpoint = normalize_http_url(raw) if "://" in raw else None
        port = None

        if endpoint:
            host = endpoint["host"]
        else:
            authority = None
            if raw.startswith("[") or (
                raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit()
            ):
                try:
                    authority = urlsplit("//" + raw)
                    port = authority.port
                except ValueError as exc:
                    raise TargetScopeError(f"Active probe target is invalid: {exc}") from exc
            if authority is not None and authority.hostname and port is not None:
                host = normalize_target(authority.hostname)
                if port < 1 or port > 65535:
                    raise TargetScopeError("Endpoint port must be between 1 and 65535.")
            else:
                host = normalize_target(raw)

        if self.scope is not None:
            approved_host = self.scope.validate(host)
        else:
            # Without an injected validator, permit only the already validated
            # session host. A discovery result cannot authorize a new host.
            approved_host = normalize_target(session_target)
            if host != approved_host:
                raise TargetScopeError(
                    "No scope validator is configured; discovered hosts must match the session target."
                )

        if endpoint:
            default_port = 443 if endpoint["scheme"] == "https" else 80
            authority_host = f"[{approved_host}]" if ":" in approved_host else approved_host
            authority = (
                authority_host
                if endpoint["port"] == default_port
                else f"{authority_host}:{endpoint['port']}"
            )
            return f"{endpoint['scheme']}://{authority}"
        if port is not None:
            authority_host = f"[{approved_host}]" if ":" in approved_host else approved_host
            return f"{authority_host}:{port}"
        return approved_host

    def _record_scope_denial(self, session, tool, target, error):
        note = f"Scope denied: skipped {tool} probe for '{target}': {error}"
        if note not in session.notes:
            session.notes.append(note)
        log = getattr(self.logger, "warning", None) or getattr(self.logger, "info", None)
        if callable(log):
            log("%s", note)

    def _run_scoped_tool_with_loading(self, tool, target, session, extra_args=None):
        """Revalidate a probe target immediately before starting its tool."""
        try:
            approved_target = self._validated_active_target(target, session.target)
        except Exception as exc:
            self._record_scope_denial(session, tool.get("name", "unknown"), target, exc)
            return None
        return self._run_tool_with_loading(tool, approved_target, extra_args=extra_args)

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

        try:
            if self.scope is not None:
                session.target = self.scope.validate(session.target)
            else:
                session.target = normalize_target(session.target)
        except Exception as exc:
            self._record_scope_denial(session, "workflow", session.target, exc)
            self._correlate_session_findings(session)
            return session

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

        # Enrich passive subdomain results only when the scope validator approves them.
        subfinder_hosts = []
        for result in discovery_results:
            if result.tool != "subfinder" or result.status != "success":
                continue
            for finding in result.findings:
                hostname = (finding.metadata or {}).get("hostname")
                if hostname:
                    subfinder_hosts.append(hostname)

        httpx_tool = self._find_tool(selected, "httpx")
        approved_hosts = []
        if httpx_tool is not None:
            for host in dict.fromkeys(subfinder_hosts):
                if len(approved_hosts) >= self.max_discovered_hosts:
                    session.notes.append(
                        f"Subdomain enrichment capped at {self.max_discovered_hosts} hosts."
                    )
                    break
                try:
                    approved = self._validated_active_target(host, session.target)
                except Exception as exc:
                    self._record_scope_denial(session, "httpx", host, exc)
                    continue
                if approved != session.target and approved not in approved_hosts:
                    approved_hosts.append(approved)

        if approved_hosts:
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                futures = {
                    pool.submit(
                        self._run_scoped_tool_with_loading,
                        httpx_tool,
                        host,
                        session,
                    ): host
                    for host in approved_hosts
                }
                for future in as_completed(futures):
                    result = future.result()
                    if result is None:
                        continue
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
                try:
                    normalized_url = self._validated_active_target(
                        decision["target"], session.target
                    )
                    endpoint_parts = normalize_http_url(normalized_url)
                except Exception as exc:
                    self._record_scope_denial(
                        session,
                        decision.get("source_tool", "discovery"),
                        decision["target"],
                        exc,
                    )
                    continue

                endpoint = Endpoint(
                    url=endpoint_parts["url"],
                    scheme=endpoint_parts["scheme"],
                    host=endpoint_parts["host"],
                    port=endpoint_parts["port"],
                    source_tool=decision.get("source_tool", "nmap"),
                    metadata={
                        "service": decision.get("service", ""),
                        "version": decision.get("version", ""),
                        "decision": decision["type"],
                        **decision.get("endpoint_metadata", {}),
                    },
                )

                if endpoint.url not in {existing.url for existing in web_endpoints}:
                    web_endpoints.append(endpoint)

            elif decision["type"] == "database_assessment":

                session.notes.append(
                    f"Database assessment relevant for "
                    f"{decision['port']}/{decision['protocol']} "
                    f"({decision['service']})."
                )

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

                    result = self._run_scoped_tool_with_loading(
                        tool,
                        endpoint.url,
                        session,
                    )
                    if result is None:
                        continue
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
                "Web endpoints discovered, but no recommended web assessment "
                "tools are enabled or included in this profile."
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

                result = self._run_scoped_tool_with_loading(
                    tool,
                    target,
                    session,
                    extra_args=["--tags", "mysql"],
                )
                if result is None:
                    continue

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

                result = self._run_scoped_tool_with_loading(
                    tool,
                    target,
                    session,
                )
                if result is None:
                    continue

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
