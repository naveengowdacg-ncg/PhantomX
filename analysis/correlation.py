from collections import defaultdict

from core.models import CorrelationGroup


class CorrelationEngine:
    """Identify relationships between security findings."""

    def correlate(self, findings):
        """
        Group findings that appear to describe the same
        target and network service.
        """

        groups = defaultdict(list)

        for finding in findings:
            metadata = finding.metadata

            port = metadata.get("port")
            protocol = metadata.get("protocol")

            if port is None:
                key = (
                    "independent",
                    finding.target,
                    finding.category,
                )
            else:
                key = (
                    "service",
                    finding.target,
                    port,
                    protocol,
                )

            groups[key].append(finding)

        correlation_groups = []

        for key, group_findings in groups.items():

            sources = sorted(
                {
                    finding.source_tool
                    for finding in group_findings
                    if finding.source_tool
                }
            )

            target = group_findings[0].target

            correlation_groups.append(
                CorrelationGroup(
                    target=target,
                    key=str(key),
                    findings=group_findings,
                    sources=sources,
                    confidence=self._calculate_confidence(
                        group_findings
                    ),
                )
            )

        return correlation_groups

    def _calculate_confidence(self, findings):
        """
        Calculate confidence for a correlation group.

        Multiple independent sources increase confidence.
        """

        if not findings:
            return 0.0

        unique_sources = {
            finding.source_tool
            for finding in findings
            if finding.source_tool
        }

        if len(unique_sources) >= 3:
            return 0.95

        if len(unique_sources) == 2:
            return 0.85

        return 0.70