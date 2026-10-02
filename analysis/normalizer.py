from core.models import Finding


class Normalizer:
    """Convert tool results into the common finding model."""

    def parse(self, result):
        findings = list(result.findings)

        if result.tool == "nmap":
            for service in result.services:
                if service.state != "open":
                    continue

                findings.append(
                    Finding(
                        title=f"Open service: {service.service} on port {service.port}",
                        category="network",
                        impact=2,
                        exploitability=2,
                        confidence=0.95,
                        exposure=7,
                        evidence=(
                            f"Nmap reported "
                            f"{service.port}/{service.protocol} as open "
                            f"({service.service})."
                        ),
                        source_tool=result.tool,
                        target=result.target,
                        recommendation=(
                            "Verify whether the service is required "
                            "and restrict exposure where appropriate."
                        ),
                        metadata={
                            "port": service.port,
                            "protocol": service.protocol,
                            "service": service.service,
                            "version": service.version,
                        },
                    )
                )

        elif result.tool == "nikto":
            text = (result.stdout or "") + "\n" + (result.stderr or "")

            for line in text.splitlines():
                if (
                    line.strip().startswith("+")
                    and any(
                        keyword in line.lower()
                        for keyword in [
                            "missing",
                            "outdated",
                            "disclosure",
                            "vulnerability",
                            "dangerous",
                        ]
                    )
                ):
                    findings.append(
                        Finding(
                            title="Web server finding",
                            category="web",
                            impact=4,
                            exploitability=4,
                            confidence=0.7,
                            exposure=6,
                            evidence=line.strip(),
                            source_tool=result.tool,
                            target=result.target,
                            recommendation=(
                                "Validate the finding and apply the "
                                "vendor/web-server remediation guidance."
                            ),
                        )
                    )

        elif result.tool == "whatweb":
            text = (result.stdout or "") + "\n" + (result.stderr or "")

            if text.strip():
                findings.append(
                    Finding(
                        title="Web technology fingerprint available",
                        category="recon",
                        impact=1,
                        exploitability=1,
                        confidence=0.9,
                        exposure=5,
                        evidence=text[:1000].strip(),
                        source_tool=result.tool,
                        target=result.target,
                        recommendation=(
                            "Review exposed technology versions and "
                            "minimize unnecessary disclosure."
                        ),
                    )
                )

        

        result.findings = findings
        return result