from core.models import Finding
from modules.nikto.parser import NiktoParser
import json
import re


class Normalizer:
    """Convert tool results into the common finding model."""

    def __init__(self):
        self.nikto_parser = NiktoParser()

    @staticmethod
    def _finding_signature(finding):
        metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
        stable_metadata = {
            key: value for key, value in metadata.items()
            if key != "correlation"
        }
        value = {
            "source_tool": finding.source_tool,
            "category": finding.category,
            "title": finding.title,
            "target": finding.target,
            "evidence": finding.evidence,
            "recommendation": finding.recommendation,
            "metadata": stable_metadata,
        }
        try:
            return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return repr(value)

    def parse(self, result):
        # Older saved results can have the completion flag but no generated-ID
        # bookkeeping. Leave those intact rather than duplicating their findings.
        if result.normalization_complete and result.normalization_generated_ids is None:
            return result
        generated_ids = set(result.normalization_generated_ids or [])
        prior_generated = [
            finding for finding in result.findings
            if finding.finding_id in generated_ids
        ]
        findings = [
            finding for finding in result.findings
            if finding.finding_id not in generated_ids
        ]
        generated = []

        if result.tool == "nmap":
            for service in result.services:
                if service.state != "open":
                    continue

                generated.append(
                    Finding(
                        title=f"Open service: {service.service} on port {service.port}",
                        category="observation",
                        impact=0,
                        exploitability=0,
                        confidence=0.95,
                        exposure=0,
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
                            "finding_type": "service_discovery",
                            "verification_status": "service_discovery_observed",
                            "port": service.port,
                            "protocol": service.protocol,
                            "service": service.service,
                            "version": service.version,
                        },
                    )
                )

        elif result.tool == "nikto":
            generated.extend(
                self.nikto_parser.parse(
                    result.stdout or "",
                    result.target,
                )
            )

        elif result.tool in {"subfinder", "dnsx", "httpx", "katana", "testssl", "gobuster"}:
            generated.extend(self._parse_auxiliary(result))

        elif result.tool == "whatweb":
            text = (result.stdout or "") + "\n" + (result.stderr or "")

            if text.strip():
                generated.append(
                    Finding(
                        title="Web technology fingerprint available",
                        category="observation",
                        impact=0,
                        exploitability=0,
                        confidence=0.9,
                        exposure=0,
                        evidence=text[:1000].strip(),
                        source_tool=result.tool,
                        target=result.target,
                        recommendation=(
                            "Review exposed technology versions and "
                            "minimize unnecessary disclosure."
                        ),
                        metadata={
                            "finding_type": "technology_fingerprint",
                            "verification_status": "technology_observation",
                        },
                    )
                )
        prior_by_signature = {
            self._finding_signature(finding): finding
            for finding in prior_generated
        }
        normalized = []
        seen_signatures = set()
        for finding in generated:
            signature = self._finding_signature(finding)
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            normalized.append(prior_by_signature.get(signature, finding))

        result.findings = findings + normalized
        result.normalization_complete = True
        result.normalization_generated_ids = [
            finding.finding_id for finding in normalized
        ]
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
                match = re.match(
                    r"^(?P<path>/?\S+)\s+\(Status:\s*(?P<status>\d{3})\)",
                    line,
                    re.I,
                )
                if match:
                    add(
                        "Web path discovered",
                        line,
                        {
                            "verification_status": "path_discovery_only",
                            "path": match.group("path"),
                            "status_code": int(match.group("status")),
                        },
                    )
            elif tool == "subfinder":
                if re.fullmatch(r"[A-Za-z0-9._*-]+", line) and "." in line:
                    add("Subdomain discovered", line, {"hostname": line, "verification_status": "passive_discovery_unverified"})
            elif tool == "dnsx":
                # Parse JSONL output from dnsx
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    item = None
                if isinstance(item, dict):
                    # JSONL format: {"host": "...", "a": ["..."], "cname": ["..."]}
                    host = item.get("host") or item.get("name") or item.get("input")
                    for rrtype in ("a", "aaaa", "cname", "ns", "mx", "txt"):
                        values = item.get(rrtype)
                        if isinstance(values, str):
                            values = [values]
                        if isinstance(values, list):
                            for value in values:
                                add(f"DNS {rrtype.upper()} record", line, {
                                    "hostname": host,
                                    "record_type": rrtype.upper(),
                                    "value": value,
                                    "verification_status": "dns_observation"
                                })
                    continue
                # Fallback: parse plain text format
                match = re.match(r"^(?P<host>[A-Za-z0-9._-]+)\s+(?:\[(?P<rr>A|AAAA|CNAME|NS|MX|TXT)\]|(?P<plain>A|AAAA|CNAME|NS|MX|TXT))\s+(?P<value>\S+)", line, re.I)
                if match:
                    host = match.group("host")
                    rrtype = (match.group("rr") or match.group("plain")).upper()
                    value = match.group("value")
                    add(f"DNS {rrtype} record", line, {
                        "hostname": host,
                        "record_type": rrtype,
                        "value": value,
                        "verification_status": "dns_observation"
                    })
                else:
                    add("DNS record discovered", line, {"verification_status": "dns_observation"})
        return findings
