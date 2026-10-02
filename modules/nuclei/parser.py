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

            findings.append(
                Finding(
                    title=info.get(
                        "name",
                        data.get(
                            "template-id",
                            "Nuclei detection"
                        )
                    ),
                    category="vulnerability",
                    severity=self.SEVERITY_MAP.get(
                    severity,
                    "INFO"
                ).lower(),

                scanner_severity=self.SEVERITY_MAP.get(
                    severity,
                    "INFO"
                ).lower(),
                    impact=self._impact(severity),
                    exploitability=self._exploitability(
                        severity
                    ),
                    confidence=0.90,
                    exposure=6,
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