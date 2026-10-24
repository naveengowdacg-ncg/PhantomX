"""Conservative correlation of findings using specific evidence."""
import re
from collections import defaultdict

from core.models import CorrelationGroup


_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_SPACE = re.compile(r"\s+")


def _normalized_title(title):
    return _SPACE.sub(" ", (title or "").strip().lower())


def _finding_key(finding):
    metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
    target = (finding.target or "").strip().lower()
    category = (finding.category or "").strip().lower()
    port = metadata.get("port")
    protocol = (metadata.get("protocol") or "").strip().lower()
    endpoint = (
        metadata.get("url")
        or metadata.get("endpoint")
        or (finding.metadata.get("endpoint_url") if isinstance(finding.metadata, dict) else "")
    )
    endpoint = str(endpoint or "").strip().lower().rstrip("/")

    # A shared vulnerability identifier is stronger evidence than title similarity.
    identifiers = []
    for field in ("cve", "cve_id", "vulnerability_id", "plugin_id", "template_id"):
        value = metadata.get(field)
        if value:
            match = _CVE.search(str(value))
            identifiers.append(match.group(0).upper() if match else str(value).strip().lower())
    evidence_match = _CVE.search((finding.title or "") + " " + (finding.evidence or ""))
    if evidence_match:
        identifiers.append(evidence_match.group(0).upper())
    if identifiers:
        return ("vulnerability-id", target, sorted(set(identifiers))[0])

    title = _normalized_title(finding.title)

    # Broad grouping is reserved for recognizable service-discovery findings.
    service_language = any(token in title for token in (
        "service", "http detected", "open port", "port open",
    ))
    if port is not None and protocol and category == "network" and service_language:
        return ("service", target, str(port), protocol)

    # Otherwise require a specific endpoint/title identity. A shared port alone
    # is insufficient evidence that two findings describe the same issue.
    if endpoint:
        return ("endpoint-finding", target, endpoint, category, title)
    if port is not None:
        return ("port-finding", target, str(port), protocol, category, title)
    if title:
        return ("specific-finding", target, category, title)

    # Missing identifiers and titles should never cause unrelated findings to
    # collapse into one group.
    return ("independent", target, getattr(finding, "finding_id", id(finding)))


class CorrelationEngine:
    """Identify likely relationships without over-grouping unrelated findings."""

    def correlate(self, findings):
        groups = defaultdict(list)
        for finding in findings:
            groups[_finding_key(finding)].append(finding)

        correlation_groups = []
        for key, group_findings in groups.items():
            sources = sorted({
                finding.source_tool
                for finding in group_findings
                if finding.source_tool
            })
            correlation_groups.append(CorrelationGroup(
                target=group_findings[0].target,
                key=str(key),
                findings=group_findings,
                sources=sources,
                confidence=self._calculate_confidence(group_findings),
            ))
        return correlation_groups

    def _calculate_confidence(self, findings):
        if not findings:
            return 0.0
        unique_sources = {
            finding.source_tool for finding in findings if finding.source_tool
        }
        if len(unique_sources) >= 3:
            return 0.95
        if len(unique_sources) == 2:
            return 0.85
        return 0.70
