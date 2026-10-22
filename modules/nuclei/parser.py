import json

from core.models import Finding


class NucleiParser:
    """Parse Nuclei JSONL output into standardized findings."""

    SEVERITY_MAP = {
        "info": "INFO",
        "low": "LOW",
        "medium": "MEDIUM",
        "high": "HIGH",
        "critical": "CRITICAL",
    }

    def parse(self, output, target):
        findings = []

        if not output:
            return findings

        for line in output.splitlines():

            line = line.strip()

            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = data.get("info", {})
            classification = info.get("classification", {})

            severity = info.get(
                "severity",
                "info"
            ).lower()

            template_id = data.get(
                "template-id",
                ""
            )

            tags = info.get(
                "tags",
                []
            )

            result_type = self._classify_result(
                template_id,
                tags,
                severity
            )

            # HSTS is relevant to HTTPS, not a plain HTTP response.
            matched_url = (
                data.get("matched-at", "")
                or data.get("url", "")
                or target
            )

            if (
                template_id.lower() == "http-missing-security-headers"
                and data.get("matcher-name", "").lower()
                    == "strict-transport-security"
                and matched_url.lower().startswith("http://")
            ):
                result_type = "observation"

            findings.append(
                Finding(
                    title=(
                        "MySQL native password authentication detected "
                        "(verify security policy)"
                        if template_id.lower() == "mysql-native-password"
                        else (
                            "Missing HTTP security header: "
                            + data.get("matcher-name", "unspecified")
                            .replace("-", " ")
                            .title()
                            if template_id.lower() == "http-missing-security-headers"
                            else info.get(
                                "name",
                                data.get("template-id", "Nuclei detection"),
                            )
                        )
                    ),
                    category=result_type,
                    severity=self.SEVERITY_MAP.get(
                    severity,
                    "INFO"
                ).lower(),

                scanner_severity=self.SEVERITY_MAP.get(
                    severity,
                    "INFO"
                ).lower(),
                    impact=(
                        0
                        if result_type == "observation"
                        else self._impact(severity)
                    ),
                    exploitability=(
                        0
                        if result_type == "observation"
                        else self._exploitability(severity)
                    ),
                    confidence=0.90,
                    exposure=(
                        0
                        if result_type == "observation"
                        else (
                            3
                            if result_type == "misconfiguration"
                            else 6
                        )
                    ),
                    evidence=data.get(
                        "matched-at",
                        data.get("url", target)
                    ),
                    source_tool="nuclei",
                    target=target,
                    recommendation=(
                        "Validate the Nuclei result and "
                        "apply the remediation guidance "
                        "associated with the detected "
                        "template."
                    ),
                    metadata={
                        "template_id": data.get(
                            "template-id",
                            ""
                        ),
                        "classification": result_type,
                        "template": data.get(
                            "template",
                            ""
                        ),
                        "severity": severity,
                        "tags": info.get(
                            "tags",
                            []
                        ),
                        "description": info.get(
                            "description",
                            ""
                        ),
                        "matched_at": data.get(
                            "matched-at",
                            ""
                        ),
                        "url": data.get(
                            "url",
                            ""
                        ),
                        "host": data.get(
                            "host",
                            ""
                        ),
                        "port": data.get(
                            "port",
                            ""
                        ),
                        "scheme": data.get(
                            "scheme",
                            ""
                        ),
                        "matcher_name": data.get(
                            "matcher-name",
                            ""
                        ),
                        "type": data.get(
                            "type",
                            ""
                        ),
                        "cwe_id": classification.get(
                            "cwe-id",
                            []
                        ),
                        "cve_id": classification.get(
                            "cve-id",
                            []
                        ),
                        "references": info.get(
                            "reference",
                            []
                        ),
                    },
                )
            )

        return findings

    def _classify_result(self, template_id, tags, severity):
        """
        Classify Nuclei results by security meaning rather than
        scanner severity alone.
        """

        template_id = template_id.lower()
        tags = [tag.lower() for tag in tags]

        # Pure technology / service discovery
        observation_patterns = [
            "waf-detect",
            "apache-detect",
            "mysql-detect",
            "mysql-info",
            "mysql-native-password",
            "default-apache-test-all",
            "default-apache2-page",
        ]

        for pattern in observation_patterns:
            if pattern in template_id:
                return "observation"

        # Known configuration / exposure checks
        misconfiguration_patterns = [
            "http-missing-security-headers",
            "apache-server-status",
        ]

        for pattern in misconfiguration_patterns:
            if pattern in template_id:
                return "misconfiguration"
        if "misconfig" in tags:
            return "misconfiguration"

        # Explicit vulnerability/CVE/security classifications
        if (
            "cve" in tags
            or "vulnerability" in tags
            or "rce" in tags
            or "sqli" in tags
            or "xss" in tags
            or "ssrf" in tags
            or "lfi" in tags
            or "rfi" in tags
            or "auth-bypass" in tags
        ):
            return "vulnerability"

        # If Nuclei reports a medium+ severity result and it
        # wasn't identified as pure discovery, treat it as a finding.
        if severity in {"medium", "high", "critical"}:
            return "vulnerability"

        return "observation"

    def _impact(self, severity):
        return {
            "info": 1,
            "low": 2,
            "medium": 5,
            "high": 8,
            "critical": 10,
        }.get(severity, 1)

    def _exploitability(self, severity):
        return {
            "info": 1,
            "low": 2,
            "medium": 5,
            "high": 8,
            "critical": 10,
        }.get(severity, 1)