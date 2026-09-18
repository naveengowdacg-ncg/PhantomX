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
        """
        Analyze discovery results and return assessment decisions.

        Decisions are represented as dictionaries for now. This keeps
        the decision layer lightweight while the assessment model evolves.
        """

        decisions = []

        for result in results:

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
                        "recommended_tools": [
                            "whatweb",
                        ],
                        "reason": (
                            f"HTTP service discovered on "
                            f"{service.port}/{service.protocol}."
                        ),
                    })

                elif service.port in self.DATABASE_PORTS:
                    decisions.append({
                        "type": "database_assessment",
                        "target": result.target,
                        "host": result.target,
                        "port": service.port,
                        "protocol": service.protocol,
                        "service": service.service,
                        "version": service.version,
                        "recommended_tools": [],
                        "reason": (
                            f"Database service discovered on "
                            f"{service.port}/{service.protocol}."
                        ),
                    })

        return self._deduplicate(decisions)

    def _build_web_target(self, host, port, secure):
        scheme = "https" if secure else "http"

        if port in {80, 443}:
            return f"{scheme}://{host}"

        return f"{scheme}://{host}:{port}"

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

            if result.tool != "whatweb":
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