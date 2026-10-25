class DecisionEngine:
    """Determine relevant downstream assessments from discovered evidence."""

    WEB_PORTS = {
        80,
        443,
        8080,
        8443,
    }

    DATABASE_PORTS = {
        3306,
        5432,
        1433,
        1521,
        27017,
        6379,
    }

    def decide(self, results):
        """Create downstream decisions only from successful discovery results."""
        from urllib.parse import urlsplit

        from core.scope import TargetScopeError, normalize_http_url

        decisions = []
        web_tools = ["whatweb", "nikto", "nuclei", "katana", "testssl", "gobuster"]

        for result in results:
            if result.status != "success":
                continue

            if result.tool == "httpx":
                for finding in result.findings:
                    metadata = finding.metadata or {}
                    raw_url = metadata.get("url")
                    if not raw_url:
                        continue
                    try:
                        endpoint = normalize_http_url(raw_url)
                    except TargetScopeError:
                        continue
                    decisions.append({
                        "type": "web_assessment",
                        "target": endpoint["url"],
                        "host": endpoint["host"],
                        "port": endpoint["port"],
                        "protocol": "tcp",
                        "service": endpoint["scheme"],
                        "version": metadata.get("webserver", "") or "",
                        "source_tool": "httpx",
                        "endpoint_metadata": {
                            "discovered_path": urlsplit(raw_url).path or "/",
                            "status_code": metadata.get("status_code"),
                        },
                        "recommended_tools": web_tools,
                        "reason": f"HTTP service discovered by httpx at {endpoint['url']}.",
                    })
                continue

            if result.tool != "nmap":
                continue

            for service in result.services:
                if service.state != "open":
                    continue

                if service.port in self.WEB_PORTS:
                    decisions.append({
                        "type": "web_assessment",
                        "target": self._build_web_target(
                            result.target,
                            service.port,
                            service.port in {443, 8443},
                        ),
                        "host": result.target,
                        "port": service.port,
                        "protocol": service.protocol,
                        "service": service.service,
                        "version": service.version,
                        "source_tool": "nmap",
                        "endpoint_metadata": {},
                        "recommended_tools": web_tools,
                        "reason": (
                            f"HTTP service discovered on "
                            f"{service.port}/{service.protocol}."
                        ),
                    })

                elif service.port in self.DATABASE_PORTS:
                    authority_host = (
                        f"[{result.target}]"
                        if ":" in result.target and not result.target.startswith("[")
                        else result.target
                    )
                    decisions.append({
                        "type": "database_assessment",
                        "target": f"{authority_host}:{service.port}",
                        "host": result.target,
                        "port": service.port,
                        "protocol": service.protocol,
                        "service": service.service,
                        "version": service.version,
                        "recommended_tools": ["nuclei"],
                        "reason": (
                            f"Database service discovered on "
                            f"{service.port}/{service.protocol}."
                        ),
                    })

        return self._deduplicate(decisions)

    def _build_web_target(self, host, port, secure):
        scheme = "https" if secure else "http"
        authority_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        default_port = 443 if secure else 80
        if port == default_port:
            return f"{scheme}://{authority_host}"
        return f"{scheme}://{authority_host}:{port}"

    def _deduplicate(self, decisions):
        unique = []
        seen = set()

        for decision in decisions:
            key = (
                decision["type"],
                decision["target"],
                decision["port"],
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(decision)

        return unique

    def decide_from_observations(self, results):
        """
        Generate follow-up assessment decisions from tool observations.
        """

        decisions = []

        for result in results:

            if result.status != "success" or result.tool != "whatweb":
                continue

            for observation in result.observations:

                fingerprint = observation.metadata.get(
                    "fingerprint",
                    ""
                ).lower()

                endpoint = observation.endpoint

                if not endpoint:
                    continue

                if "apache" in fingerprint:
                    decisions.append({
                        "type": "apache_assessment",
                        "target": endpoint.url,
                        "host": endpoint.host,
                        "port": endpoint.port,
                        "recommended_tools": [
                            "nikto",
                            "nuclei",
                        ],
                        "reason": (
                            "WhatWeb identified Apache on the "
                            "discovered web endpoint."
                        ),
                        "source_tool": "whatweb",
                        "evidence": observation.evidence,
                    })

        return self._deduplicate_observation_decisions(
            decisions
        )

    def _deduplicate_observation_decisions(self, decisions):
        unique = []
        seen = set()

        for decision in decisions:

            key = (
                decision["type"],
                decision["target"],
                decision["port"],
            )

            if key in seen:
                continue

            seen.add(key)
            unique.append(decision)

        return unique
