"""Conservative correlation of findings using specific evidence."""
import re
from collections import defaultdict

from core.models import CorrelationGroup


_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_SPACE = re.compile(r"\s+")


def _normalized_title(title):
    if not isinstance(title, str):
        return ""
    return _SPACE.sub(" ", title.strip().lower())


def _normalized_endpoint(endpoint):
    """Normalize simple host/URL forms without discarding path identity."""
    value = str(endpoint or "").strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    return value.rstrip("/")


def _finding_key(finding):
    metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
    target = finding.target.strip().lower() if isinstance(finding.target, str) else ""
    category = finding.category.strip().lower() if isinstance(finding.category, str) else ""
    raw_port = metadata.get("port")
    port = (
        str(raw_port).strip()
        if isinstance(raw_port, (str, int, float)) and not isinstance(raw_port, bool)
        else None
    )
    raw_protocol = metadata.get("protocol")
    protocol = raw_protocol.strip().lower() if isinstance(raw_protocol, str) else ""
    evidence = finding.evidence if isinstance(finding.evidence, str) else ""
    endpoint = (
        metadata.get("matched_at")
        or metadata.get("url")
        or metadata.get("endpoint")
        or metadata.get("endpoint_url")
        or evidence
    )
    endpoint = _normalized_endpoint(endpoint)

    # Nuclei can run in more than one workflow stage and return the same
    # detection with different target formatting (for example, a bare host
    # in one result and an HTTP URL in another). Correlate only when the
    # template, endpoint, category, and title all agree. Including title is
    # important because one generic template can emit multiple distinct
    # findings, such as individual missing HTTP security headers.
    template_id = str(metadata.get("template_id") or "").strip().lower()
    source_tool = finding.source_tool if isinstance(finding.source_tool, str) else ""
    if (
        source_tool.strip().lower() == "nuclei"
        and template_id
        and endpoint
    ):
        return (
            "nuclei-detection",
            endpoint,
            template_id,
            category,
            _normalized_title(finding.title),
        )

    # CVEs are globally meaningful identifiers. Generic scanner plugin/template
    # IDs are not: one template can emit several distinct findings (for example,
    # a missing-header template can report multiple different headers).
    cve_ids = []
    for field in ("cve", "cve_id", "vulnerability_id"):
        value = metadata.get(field)
        if value:
            match = _CVE.search(str(value))
            if match:
                cve_ids.append(match.group(0).upper())
    title_text = finding.title if isinstance(finding.title, str) else ""
    evidence_match = _CVE.search(title_text + " " + evidence)
    if evidence_match:
        cve_ids.append(evidence_match.group(0).upper())
    if cve_ids:
        return ("cve", target, sorted(set(cve_ids))[0])

    title = _normalized_title(finding.title)

    # Broad grouping is reserved for recognizable service-discovery findings.
    service_language = any(token in title for token in (
        "service", "http detected", "open port", "port open",
    ))
    service_discovery = metadata.get("finding_type") == "service_discovery"
    if (
        port and protocol and (category == "network" or service_discovery)
        and service_language
    ):
        return ("service", target, port, protocol)

    # Otherwise require a specific endpoint/title identity. A shared port alone
    # is insufficient evidence that two findings describe the same issue.
    if endpoint:
        return ("endpoint-finding", target, endpoint, category, title)
    if port:
        return ("port-finding", target, port, protocol, category, title)
    if title:
        return ("specific-finding", target, category, title)

    # Missing identifiers and titles should never cause unrelated findings to
    # collapse into one group.
    finding_id = getattr(finding, "finding_id", id(finding))
    if not isinstance(finding_id, (str, int, float)) or isinstance(finding_id, bool):
        finding_id = id(finding)
    return ("independent", target, str(finding_id))


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
                if isinstance(finding.source_tool, str) and finding.source_tool
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
        """Return a fixed match indicator, not a calibrated probability.

        Existing reports use 0.70 for every multi-record correlation and 0.00
        for a singleton. The value does not rank match classes, indicate
        vulnerability confidence, or change with repeated/independent sources.
        """
        return 0.70 if len(findings) > 1 else 0.0
