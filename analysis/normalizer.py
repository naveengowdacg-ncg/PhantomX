from core.models import Finding
from modules.nikto.parser import NiktoParser
import json
import re


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
                    result.stdout or "",
                    result.target,
                )
            )

        elif result.tool in {"subfinder", "dnsx", "httpx", "katana", "testssl", "gobuster"}:
            findings.extend(self._parse_auxiliary(result))

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

    def _parse_auxiliary(self, result):
        """Normalize reconnaissance metadata without overstating it as a vulnerability."""
        output = (result.stdout or "").strip()
        if not output or result.status not in {"success", "skipped"}:
            return []
        tool = result.tool.lower()
        findings = []
        seen = set()

        def add(title, evidence, metadata=None):
            key = (title.lower(), evidence.strip().lower())
            if not evidence.strip() or key in seen:
                return
            seen.add(key)
            findings.append(Finding(
                title=title,
                category="observation",
                impact=0,
                exploitability=0,
                confidence=0.75,
                exposure=0,
                evidence=evidence.strip()[:2000],
                source_tool=tool,
                target=result.target,
                recommendation="Treat this as reconnaissance evidence; independently validate before making security conclusions.",
                metadata={"scanner": tool, **(metadata or {})},
            ))

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if tool in {"httpx", "katana"}:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    item = None
                if isinstance(item, dict):
                    url = item.get("url") or item.get("input") or item.get("matched-at")
                    if not url and tool == "katana":
                        url = item.get("request", {}).get("endpoint") if isinstance(item.get("request"), dict) else None
                    if url:
                        title = "HTTP service metadata discovered" if tool == "httpx" else "Web endpoint discovered"
                        add(title, line, {"url": url, "status_code": item.get("status_code"), "webserver": item.get("webserver"), "technologies": item.get("tech", []), "content_type": item.get("content_type")})
                        continue
            if tool == "testssl":
                # Keep actionable TLS rows, skipping banners and progress noise.
                if re.search(r"(TLS|SSL|certificate|cert|cipher|protocol|heartbleed|poodle|sweet32|weak|expired|self.signed|not trusted|vulnerable)", line, re.I) and not re.search(r"(Testing protocols|Start .*|Done .*|Using .*|Hint:|testssl\.sh)", line, re.I):
                    add("TLS configuration observation", line, {"verification_status": "scanner_match_unverified"})
            elif tool == "gobuster":
                if re.search(r"^/[^\s]*\s+\(Status:\s*\d{3}", line) or re.search(r"^/[^\s]*\s+\(Status:\s*\d{3}", line, re.I):
                    add("Web path discovered", line, {"verification_status": "path_discovery_only"})
            elif tool == "subfinder":
                if re.fullmatch(r"[A-Za-z0-9._*-]+", line) and "." in line:
                    add("Subdomain discovered", line, {"hostname": line, "verification_status": "passive_discovery_unverified"})
            elif tool == "dnsx":
                add("DNS record discovered", line, {"verification_status": "dns_observation"})
        return findings
