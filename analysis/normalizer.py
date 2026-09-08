import re
from core.models import Finding

class Normalizer:
    """Turns raw tool output into a small common finding model. Parsers grow over time."""
    def parse(self, result):
        text = (result.stdout or "") + "\n" + (result.stderr or "")
        findings = []
        if result.tool == "nmap":
            for port, state, service in re.findall(r"^(\d+)\/\w+\s+(open|filtered|closed)\s+([^\s]+)", text, re.M):
                if state == "open":
                    findings.append(Finding(
                        title=f"Open service: {service} on port {port}", category="network",
                        impact=2, exploitability=2, confidence=0.95, exposure=7,
                        evidence=f"Nmap reported {port} as open ({service}).", source_tool=result.tool,
                        target=result.target, recommendation="Verify whether the service is required and restrict exposure where appropriate.",
                        metadata={"port": int(port), "service": service}
                    ))
        elif result.tool == "nikto":
            for line in text.splitlines():
                if line.strip().startswith("+") and any(k in line.lower() for k in ["missing", "outdated", "disclosure", "vulnerability", "dangerous"]):
                    findings.append(Finding(
                        title="Web server finding", category="web", impact=4, exploitability=4,
                        confidence=0.7, exposure=6, evidence=line.strip(), source_tool=result.tool,
                        target=result.target, recommendation="Validate the finding and apply the vendor/web-server remediation guidance."
                    ))
        elif result.tool == "whatweb":
            if text.strip():
                findings.append(Finding(
                    title="Web technology fingerprint available", category="recon", impact=1, exploitability=1,
                    confidence=0.9, exposure=5, evidence=text[:1000].strip(), source_tool=result.tool,
                    target=result.target, recommendation="Review exposed technology versions and minimize unnecessary disclosure."
                ))
        elif result.tool == "nuclei":
            for line in text.splitlines():
                if line.strip():
                    findings.append(Finding(
                        title="Template-based vulnerability result", category="vulnerability", impact=6, exploitability=5,
                        confidence=0.8, exposure=6, evidence=line.strip(), source_tool=result.tool,
                        target=result.target, recommendation="Manually validate the result and follow the template/vendor remediation guidance."
                    ))
        result.findings = findings
        return result
