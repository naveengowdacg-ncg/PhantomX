
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

    @staticmethod
    def _reject_nonfinite(value):
        raise ValueError(f"Non-finite JSON value: {value}")

    @staticmethod
    def _text(value, default=""):
        return value if isinstance(value, str) else default

    def parse(self, output, target):
        findings = []

        if not output:
            return findings

        for line in output.splitlines():
            line = line.strip()

            if not line:
                continue

            try:
                data = json.loads(line, parse_constant=self._reject_nonfinite)
            except (json.JSONDecodeError, ValueError):
                continue

            # Scanner output is untrusted. Ignore well-formed JSON values whose
            # shape is not a Nuclei event instead of aborting the entire scan.
            if not isinstance(data, dict):
                continue

            info = data.get("info", {})
            if not isinstance(info, dict):
                continue
            classification = info.get("classification", {})
            if not isinstance(classification, dict):
                classification = {}

            severity = self._text(info.get("severity"), "info").lower()
            template_id = self._text(data.get("template-id"))
            normalized_template_id = template_id.lower()

            tags = info.get("tags", [])
            if not isinstance(tags, list):
                tags = []
            tags = [tag for tag in tags if isinstance(tag, str)]
            result_type = self._classify_result(
                template_id,
                tags,
                severity,
            )

            matched_url = next(
                (
                    value for value in (
                        data.get("matched-at"), data.get("url"), target,
                    )
                    if isinstance(value, str) and value
                ),
                target,
            )

            matcher_name = self._text(data.get("matcher-name"))
            description = self._text(info.get("description"))
            title = self._text(info.get("name")) or template_id or "Nuclei detection"

            # HSTS is relevant to HTTPS, not a plain HTTP response.
            if (
                normalized_template_id
                == "http-missing-security-headers"
                and matcher_name.lower() == "strict-transport-security"
                and matched_url.lower().startswith("http://")
            ):
                result_type = "observation"

            is_apache_status = (
                normalized_template_id == "apache-server-status"
            )

            if is_apache_status:
                recommendation = (
                    "Restrict /server-status to trusted administrators "
                    "or disable it if unnecessary. Verify access controls "
                    "from a non-local client before concluding that the "
                    "endpoint is remotely exposed."
                )
            else:
                recommendation = (
                    "Validate the Nuclei result and apply the remediation "
                    "guidance associated with the detected template."
                )

            metadata = {
                "template_id": template_id,
                "classification": result_type,
                "template": self._text(data.get("template")),
                "severity": severity,
                "tags": tags,
                "description": description,
                "matched_at": self._text(data.get("matched-at")),
                "url": self._text(data.get("url")),
                "host": self._text(data.get("host")),
                "port": data.get("port") if isinstance(data.get("port"), (str, int, float)) and not isinstance(data.get("port"), bool) else "",
                "scheme": self._text(data.get("scheme")),
                "matcher_name": matcher_name,
                "type": data.get("type", ""),
                "cwe_id": classification.get("cwe-id", []),
                "cve_id": classification.get("cve-id", []),
                "references": info.get("reference", []),
                # A template match is a lead for verification, not confirmation.
                "verification_status": "scanner_match_unverified",
            }

            if is_apache_status:
                metadata.update({
                    "verification_status": "scanner_match_unverified",
                    "remote_exposure": "not_verified",
                    "access_control": "not_assessed",
                    "exposure_scope": "unknown",
                })

            findings.append(
                Finding(
                    title=(
                        "MySQL native password authentication detected "
                        "(verify security policy)"
                        if normalized_template_id
                        == "mysql-native-password"
                        else (
                            "Missing HTTP security header: "
                            + matcher_name.replace("-", " ").title()
                            if normalized_template_id
                            == "http-missing-security-headers"
                            else title
                        )
                    ),
                    category=result_type,
                    severity=self.SEVERITY_MAP.get(
                        severity, "INFO"
                    ).lower(),
                    scanner_severity=self.SEVERITY_MAP.get(
                        severity, "INFO"
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
                    evidence=(
                        data.get("matched-at")
                        or data.get("url")
                        or target
                    ),
                    source_tool="nuclei",
                    target=target,
                    recommendation=recommendation,
                    metadata=metadata,
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

        misconfiguration_patterns = [
            "http-missing-security-headers",
            "apache-server-status",
        ]

        for pattern in misconfiguration_patterns:
            if pattern in template_id:
                return "misconfiguration"

        if "misconfig" in tags:
            return "misconfiguration"

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
