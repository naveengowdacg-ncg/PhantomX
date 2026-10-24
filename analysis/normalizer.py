from core.models import Finding
from modules.nikto.parser import NiktoParser


class Normalizer:
    """Convert tool results into the common finding model."""

    def __init__(self):
        self.nikto_parser = NiktoParser()

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
            findings.extend(
                self.nikto_parser.parse(
                    (result.stdout or "") + "\\n" + (result.stderr or ""),
                    result.target,
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