
import json
import hashlib
import math
import re
import textwrap
import unicodedata
from pathlib import Path
from html import escape
from urllib.parse import urlsplit, urlunsplit

from analysis.correlation import CorrelationEngine
from analysis.asset_intelligence import AssetIntelligenceBuilder


class Reporter:
    _URL_PATTERN = re.compile(
        r"(?i)(?:https?:/{0,2}|[a-z][a-z0-9+.-]*://|//)[^\s<>\"']+"
    )
    _MAX_FILENAME_ID = 160
    VERIFICATION_FIELDS = {
        "verification_status": "Verification status",
        "remote_exposure": "Remote exposure",
        "access_control": "Access control",
        "exposure_scope": "Exposure scope",
    }

    def __init__(self, reports_dir="reports"):
        self.dir = Path(reports_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _display(value, missing="not provided"):
        return missing if value is None else str(value)

    @staticmethod
    def _numeric(value):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return 0.0
        try:
            return float(value) if math.isfinite(value) else 0.0
        except OverflowError:
            return 0.0

    @classmethod
    def _filename_id(cls, session_id):
        """Keep user supplied session IDs inside the configured report folder."""
        original = str(session_id)
        safe_basis = cls._redact_urls(original)
        safe_id = re.sub(r"[^A-Za-z0-9._-]+", "_", safe_basis).strip("._")
        safe_id = safe_id or "session"
        digest = hashlib.sha256(
            original.encode("utf-8", errors="surrogatepass")
        ).hexdigest()[:32]
        prefix_length = cls._MAX_FILENAME_ID - len(digest) - 1
        prefix = safe_id[:prefix_length].rstrip("._") or "session"
        return f"{prefix}-{digest}"

    @classmethod
    def _redact_urls(cls, value):
        """Remove URL userinfo, query strings, and fragments from display text."""
        text = str(value).encode("utf-8", errors="surrogatepass").decode(
            "utf-8", errors="replace"
        )
        return cls._URL_PATTERN.sub(
            lambda match: cls._safe_endpoint(match.group(0)) or "[invalid URL]",
            text,
        )

    @staticmethod
    def _markdown(value):
        """Escape untrusted plain text for a Markdown report line."""
        text = Reporter._redact_urls(value).replace(chr(13) + chr(10), chr(10))
        text = text.replace(chr(13), chr(10)).replace(chr(10), " ")
        text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        markdown_special = chr(92) + chr(96) + "*_{}[]()#+-!|~"
        return "".join(chr(92) + char if char in markdown_special else char for char in text)

    @staticmethod
    def _code(value):
        """Wrap untrusted text in a code span with a safe delimiter length."""
        marker = chr(96)
        text = Reporter._redact_urls(value).replace(chr(13) + chr(10), chr(10))
        text = text.replace(chr(13), chr(10)).replace(chr(10), " ")
        runs = re.findall(re.escape(marker) + r"+", text)
        delimiter = marker * (max((len(run) for run in runs), default=0) + 1)
        if not text:
            return marker + chr(32) + marker
        padding = " " if (
            text[0].isspace() or text[-1].isspace()
            or text.startswith(marker) or text.endswith(marker)
        ) else ""
        return f"{delimiter}{padding}{text}{padding}{delimiter}"

    @classmethod
    def _html(cls, value):
        return escape(cls._redact_urls(value), quote=True)

    def _flat_findings(self, session):
        return [f for r in session.results for f in r.findings]

    def _correlated_findings(self, session):
        """Return one report entry per conservative correlation group."""
        raw_findings = self._flat_findings(session)
        groups = CorrelationEngine().correlate(raw_findings)
        entries = []

        for group in groups:
            # Keep the highest-risk finding as the representative while
            # retaining the group sources and unique evidence in the report.
            representative = max(
                group.findings,
                key=lambda finding: (
                    self._numeric(finding.score),
                    self._numeric(finding.confidence),
                ),
            )
            evidence = []
            for finding in group.findings:
                text = self._display(finding.evidence, missing="").strip()
                if text and text not in evidence:
                    evidence.append(text)
            detections = [
                self._detection_record(finding, session.target)
                for finding in group.findings
            ]
            verification = [
                {
                    "source": detection["source"],
                    "finding_id": detection["finding_id"],
                    "status": detection["verification_status"],
                    "details": detection["verification_details"],
                }
                for detection in detections
            ]
            explicit_statuses = {
                member["status"] for member in verification
                if member["status"] is not None
            }
            entries.append({
                "finding": representative,
                "sources": group.sources or sorted({
                    finding.source_tool for finding in group.findings
                    if isinstance(finding.source_tool, str) and finding.source_tool
                }),
                "count": len(group.findings),
                "confidence": group.confidence,
                "evidence": evidence,
                "verification": verification,
                "detections": detections,
                "verification_conflict": len(explicit_statuses) > 1,
            })

        return sorted(
            entries,
            key=lambda entry: self._numeric(entry["finding"].score),
            reverse=True,
        )

    def _asset_graph(self, session):
        # Rebuild for exports so edits/restored legacy sessions cannot expose a
        # stale graph. The builder does not mutate the source session.
        return AssetIntelligenceBuilder().build(session)

    def _asset_surface_lines(self, graph):
        summary = graph.get("summary", {}) if isinstance(graph, dict) else {}
        assets = graph.get("assets", []) if isinstance(graph, dict) else []
        relationships = graph.get("relationships", []) if isinstance(graph, dict) else []
        findings = graph.get("findings", []) if isinstance(graph, dict) else []
        coverage = graph.get("coverage", {}) if isinstance(graph, dict) else {}
        names = {
            item.get("asset_id"): item.get("display_name", item.get("asset_id", "unknown"))
            for item in assets if isinstance(item, dict)
        }
        names.update({
            item.get("finding_ref"): item.get("title", item.get("finding_ref", "finding"))
            for item in findings if isinstance(item, dict)
        })
        type_counts = summary.get("assets_by_type", {})
        status_counts = coverage.get("status_counts", {})
        verification_counts = summary.get("findings_by_verification_status", {})
        lines = [
            f"Assets: {summary.get('asset_count', len(assets))}; relationships: {summary.get('relationship_count', len(relationships))}; "
            f"findings linked to assets: {summary.get('findings_with_assets', 0)}/{summary.get('finding_count', len(findings))}",
            "Asset types: " + (", ".join(f"{key}={value}" for key, value in sorted(type_counts.items())) or "none"),
            "Tool coverage: " + (", ".join(f"{key}={value}" for key, value in sorted(status_counts.items())) or "no results"),
            "Finding verification states: " + (", ".join(f"{key}={value}" for key, value in sorted(verification_counts.items())) or "none"),
        ]
        for asset in assets[:50]:
            if not isinstance(asset, dict):
                continue
            sources = sorted({
                proof.get("source_tool", "unknown")
                for proof in asset.get("provenance", [])
                if isinstance(proof, dict)
            })
            details = []
            attributes = asset.get("attributes", {})
            if asset.get("type") == "service" and isinstance(attributes, dict):
                service_names = attributes.get("service_names", [])
                versions = attributes.get("versions", [])
                if service_names:
                    details.append("service=" + ", ".join(str(value) for value in service_names))
                if versions:
                    details.append("version=" + ", ".join(str(value) for value in versions))
                if attributes.get("state"):
                    details.append("state=" + str(attributes["state"]))
            if asset.get("type") in {"domain", "ip"} and isinstance(attributes, dict):
                roles = list(attributes.get("discovery_role", [])) if isinstance(
                    attributes.get("discovery_role"), list
                ) else [attributes.get("discovery_role")]
                variants = asset.get("attribute_variants", {})
                if isinstance(variants, dict):
                    roles.extend(variants.get("discovery_role", []))
                roles = sorted({str(value) for value in roles if value})
                if roles:
                    details.append("roles=" + ", ".join(roles))
            suffix = "; " + "; ".join(details) if details else ""
            lines.append(
                f"Asset {asset.get('type', 'unknown')}: {asset.get('display_name', 'unknown')}"
                f"{suffix} [sources: {', '.join(sources) or 'unknown'}]"
            )
        if len(assets) > 50:
            lines.append(f"Additional assets in JSON: {len(assets) - 50}")
        for relation in relationships[:75]:
            if not isinstance(relation, dict):
                continue
            sources = sorted({
                proof.get("source_tool", "unknown")
                for proof in relation.get("provenance", [])
                if isinstance(proof, dict)
            })
            lines.append(
                f"Relationship {names.get(relation.get('source_id'), relation.get('source_id', 'unknown'))} "
                f"- {relation.get('relationship', 'related_to')} -> "
                f"{names.get(relation.get('target_id'), relation.get('target_id', 'unknown'))} "
                f"[sources: {', '.join(sources) or 'unknown'}]"
            )
        if len(relationships) > 75:
            lines.append(f"Additional relationships in JSON: {len(relationships) - 75}")
        return lines

    def _verification_details(self, finding):
        """Return available verification metadata for a finding."""
        metadata = getattr(finding, "metadata", None) or {}

        if not isinstance(metadata, dict):
            return []

        return [
            (label, str(metadata[key]))
            for key, label in self.VERIFICATION_FIELDS.items()
            if metadata.get(key) is not None
        ]

    @staticmethod
    def _malformed_url_without_secrets(value):
        """Conservatively remove URL authority userinfo and suffixes on parse errors."""
        text = str(value).split("#", 1)[0].split("?", 1)[0]
        if "://" in text:
            prefix, remainder = text.split("://", 1)
            prefix += "://"
        elif text.startswith("//"):
            prefix, remainder = "//", text[2:]
        elif re.match(r"(?i)^https?:", text):
            prefix, remainder = text.split(":", 1)
            prefix += ":"
        else:
            return text
        remainder = remainder.lstrip("/")
        authority, separator, path = remainder.partition("/")
        if "@" in authority:
            authority = authority.rsplit("@", 1)[-1]
        return prefix + authority + (separator + path if separator else "")

    @classmethod
    def _safe_endpoint(cls, value):
        """Expose endpoint identity without credentials, query strings, or fragments."""
        if not isinstance(value, (str, int, float)) or isinstance(value, bool):
            return None
        text = str(value).strip()
        if not text:
            return None
        try:
            parsed = urlsplit(text)
            if parsed.netloc:
                host = parsed.hostname or ""
                if ":" in host and not host.startswith("["):
                    host = f"[{host}]"
                try:
                    port = parsed.port
                except ValueError:
                    port = None
                authority = f"{host}:{port}" if port is not None else host
                text = urlunsplit((parsed.scheme, authority, parsed.path, "", ""))
            else:
                text = cls._malformed_url_without_secrets(text)
        except ValueError:
            text = cls._malformed_url_without_secrets(text)
        return text[:500]

    def _detection_record(self, finding, default_target):
        """Project only report-safe, useful fields from one raw detection."""
        metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
        endpoint_fields = ("matched_at", "url", "endpoint", "endpoint_url", "path")
        identifier_fields = ("template_id", "cve", "cve_id", "vulnerability_id")
        context_fields = (
            "port", "protocol", "service", "version", "hostname",
            "http_status", "status_code",
        )

        def scalar_fields(names):
            values = {}
            for key in names:
                value = metadata.get(key)
                if isinstance(value, (str, int, float, bool)) and str(value).strip():
                    values[key] = self._safe_endpoint(value) if key in endpoint_fields else str(value)
            return values

        status = metadata.get("verification_status")
        return {
            "source": finding.source_tool or "unknown",
            "finding_id": finding.finding_id,
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity,
            "score": finding.score,
            "scanner_severity": finding.scanner_severity,
            "target": self._safe_endpoint(finding.target or default_target) or "not provided",
            "endpoints": scalar_fields(endpoint_fields),
            "identifiers": scalar_fields(identifier_fields),
            "metadata": scalar_fields(context_fields),
            "recommendation": finding.recommendation,
            "evidence": self._display(finding.evidence, missing=""),
            "verification_status": None if status is None else str(status),
            "verification_details": [
                item for item in self._verification_details(finding)
                if item[0] != "Verification status"
            ],
        }

    @staticmethod
    def _score_breakdown_text(finding):
        breakdown = finding.score_breakdown if isinstance(finding.score_breakdown, dict) else {}
        normalized = breakdown.get("normalized_inputs", {})
        contributions = breakdown.get("contributions", {})
        if not isinstance(normalized, dict) or not isinstance(contributions, dict) or not contributions:
            return (
                "Observations are informational and are not risk-scored."
                if breakdown.get("method") == "observation"
                else "Not available"
            )
        parts = [
            f"{name}: input {normalized.get(name, 'not available')}, contribution {value}"
            for name, value in contributions.items()
        ]
        interpretation = breakdown.get("confidence_interpretation")
        if interpretation:
            parts.append(f"confidence handling: {interpretation}")
        return "; ".join(parts)

    def write_json(self, session):
        p = self.dir / f"session_{self._filename_id(session.session_id)}.json"
        entries = self._correlated_findings(session)
        raw_count = len(self._flat_findings(session))
        data = session.as_dict()
        asset_graph = self._asset_graph(session)
        data["asset_intelligence"] = asset_graph
        data["report_summary"] = {
            "attack_surface": asset_graph["summary"],
            "raw_finding_count": raw_count,
            "distinct_report_entry_count": len(entries),
            "grouped_detection_count": raw_count - len(entries),
            "correlation_groups": [
                {
                    "representative_finding_id": entry["finding"].finding_id,
                    "source_tools": entry["sources"],
                    "detection_count": entry["count"],
                    "correlation_confidence": entry["confidence"],
                    "verification_statuses": [
                        {
                            "source_tool": member["source"],
                            "status": member["status"],
                        }
                        for member in entry["verification"]
                        if member["status"] is not None
                    ],
                    "verification_conflict": entry["verification_conflict"],
                }
                for entry in entries
            ],
        }
        p.write_text(
            json.dumps(data, indent=2, ensure_ascii=True, allow_nan=False),
            encoding="utf-8",
        )
        return p

    def write_markdown(self, session):
        entries = self._correlated_findings(session)
        asset_graph = self._asset_graph(session)
        raw_count = len(self._flat_findings(session))
        duplicate_count = raw_count - len(entries)

        lines = [
            "# Security Assessment Report\n",
            f"- Target: {self._code(session.target)}",
            f"- Profile: {self._code(session.profile)}",
            f"- Session: {self._code(session.session_id)}",
            f"- Raw findings: **{raw_count}**",
            f"- Distinct correlated findings: **{len(entries)}**",
            f"- Related duplicate detections grouped: **{duplicate_count}**",
            "",
            "> PhantomX risk score/severity is its normalized prioritization; scanner severity is shown separately when available.",
            "> Correlation confidence is a fixed record-match indicator, not a calibrated probability or independent verification.",
            "",
        ]
        lines.extend(["## Attack Surface", ""])
        lines.extend(f"- {self._markdown(line)}" for line in self._asset_surface_lines(asset_graph))
        lines.extend(["", "## Tool Execution"])

        for result in session.results:
            lines.append(
                f"- **{self._markdown(result.tool)}** — {self._markdown(result.status)}, "
                f"{result.duration_seconds:.2f}s, "
                f"findings: {len(result.findings)}"
            )

        lines += ["", "## Workflow Notes", ""]
        if session.notes:
            lines.extend(f"- {self._markdown(note)}" for note in session.notes)
        else:
            lines.append("- No additional workflow notes.")

        lines += ["", "## Prioritized Findings", ""]

        if not entries:
            lines.append(
                "No normalized findings were produced. "
                "Review raw tool output and validate coverage."
            )

        for entry in entries:
            finding = entry["finding"]
            source_text = ", ".join(entry["sources"]) or "unknown"
            scanner_severity = self._code(finding.scanner_severity or "not provided")
            score_detail = self._markdown(self._score_breakdown_text(finding))
            lines.append("**Group summary (representative detection)**")
            lines += [
                f"### {self._markdown(self._display(finding.severity).upper())} — {self._markdown(finding.title)}",
                f"- PhantomX risk score: **{self._markdown(finding.score)}/100**",
                f"- Scanner severity: {scanner_severity}",
                f"- Source tools: {self._code(source_text)}",
                f"- Correlated detections: **{entry['count']}**",
                f"- Correlation confidence: **{entry['confidence']:.2f}**",
                f"- Category: {self._code(finding.category)}",
                f"- Score breakdown contributions: {score_detail}",
            ]

            if entry["evidence"]:
                lines.append("- Evidence:")
                for text in entry["evidence"][:5]:
                    shown = text[:800]
                    truncation = " [truncated for report; full evidence is in JSON]" if len(text) > 800 else ""
                    lines.append(f"  - {self._markdown(shown)}{truncation}")
            else:
                lines.append("- Evidence: Not provided")

            lines.append(f"- Representative recommendation: {self._markdown(finding.recommendation)}")

            lines += ["", "**Individual detections**"]
            if entry["verification_conflict"]:
                lines.append("- Conflicting verification states were reported by related detections.")
            for index, detection in enumerate(entry["detections"], start=1):
                status = detection["verification_status"]
                status = status if status is not None else "not provided"
                lines += [
                    f"**Detection {index}: {self._markdown(detection['title'])}**",
                    f"- Source: {self._code(detection['source'])}",
                    f"- Finding ID: {self._code(detection['finding_id'])}",
                    f"- Category and PhantomX severity: {self._markdown(detection['category'])} / {self._markdown(detection['severity'])}",
                    f"- PhantomX risk score: {self._code(detection['score'])}/100",
                    f"- Target: {self._code(detection['target'])}",
                    f"- Scanner severity: {self._code(detection['scanner_severity'] or 'not provided')}",
                    f"- Verification status {self._code(status)}",
                    f"- Recommendation: {self._markdown(detection['recommendation'])}",
                ]
                if detection["endpoints"]:
                    endpoint_text = "; ".join(
                        f"{self._markdown(key)}: {self._code(value)}"
                        for key, value in detection["endpoints"].items()
                    )
                    lines.append(f"- Endpoint details: {endpoint_text}")
                if detection["identifiers"]:
                    identifier_text = "; ".join(
                        f"{self._markdown(key)}: {self._code(value)}"
                        for key, value in detection["identifiers"].items()
                    )
                    lines.append(f"- Vulnerability/template identifiers: {identifier_text}")
                if detection["metadata"]:
                    metadata_text = "; ".join(
                        f"{self._markdown(key)}: {self._code(value)}"
                        for key, value in detection["metadata"].items()
                    )
                    lines.append(f"- Selected metadata: {metadata_text}")
                if detection["verification_details"]:
                    for label, value in detection["verification_details"]:
                        lines.append(f"- {self._markdown(label)}: {self._code(value)}")
                if detection["evidence"]:
                    shown = detection["evidence"][:800]
                    truncation = (
                        " [truncated for report; full evidence is in JSON]"
                        if len(detection["evidence"]) > 800
                        else ""
                    )
                    lines.append(f"- Detection evidence: {self._markdown(shown)}{truncation}")
                else:
                    lines.append("- Detection evidence: Not provided")
                lines.append("")

        p = self.dir / f"report_{self._filename_id(session.session_id)}.md"
        p.write_text("\n".join(lines), encoding="utf-8")
        return p

    def _html_detections(self, detections, verification_conflict):
        items = []
        if verification_conflict:
            items.append("<li><strong>Conflicting verification states reported.</strong></li>")

        def field(label, value):
            return (
                f"<li><strong>{self._html(label)}:</strong> "
                f"{self._html(value)}</li>"
            )

        for index, detection in enumerate(detections, start=1):
            details = [
                field("Finding ID", detection["finding_id"]),
                field("Category", detection["category"]),
                field("PhantomX risk score", detection["score"]),
                field("Target", detection["target"]),
                field(
                    "Scanner severity",
                    detection["scanner_severity"] or "not provided",
                ),
                field(
                    "Verification status",
                    detection["verification_status"]
                    if detection["verification_status"] is not None
                    else "not provided",
                ),
                field("Recommendation", detection["recommendation"]),
            ]
            details.extend(
                field(f"Endpoint {key}", value)
                for key, value in detection["endpoints"].items()
            )
            details.extend(
                field(f"Identifier {key}", value)
                for key, value in detection["identifiers"].items()
            )
            details.extend(
                field(f"Metadata {key}", value)
                for key, value in detection["metadata"].items()
            )
            details.extend(
                field(label, value)
                for label, value in detection["verification_details"]
            )
            if detection["evidence"]:
                evidence = detection["evidence"]
                suffix = (
                    " [truncated for report; full evidence is in JSON]"
                    if len(evidence) > 500
                    else ""
                )
                details.append(field("Evidence", evidence[:500] + suffix))
            else:
                details.append(field("Evidence", "Not provided"))

            items.append(
                "<li><strong>"
                f"Detection {index}: {self._html(detection['source'])} — "
                f"{self._html(detection['title'])}"
                "</strong><ul>" + "".join(details) + "</ul></li>"
            )
        return "<ul>" + "".join(items) + "</ul>"

    def write_html(self, session):
        entries = self._correlated_findings(session)
        asset_graph = self._asset_graph(session)
        attack_surface_html = "<ul>" + "".join(
            f"<li>{self._html(line)}</li>"
            for line in self._asset_surface_lines(asset_graph)
        ) + "</ul>"
        raw_count = len(self._flat_findings(session))
        duplicate_count = raw_count - len(entries)
        rows = []

        for entry in entries:
            finding = entry["finding"]
            detections_html = self._html_detections(
                entry["detections"],
                entry["verification_conflict"],
            )

            evidence_html = "<ul>" + "".join(
                f"<li>{self._html(text[:500])}"
                f"{' [truncated for report; full evidence is in JSON]' if len(text) > 500 else ''}</li>"
                for text in entry["evidence"][:5]
            ) + "</ul>" if entry["evidence"] else "&mdash;"
            sources = ", ".join(entry["sources"]) or "unknown"
            score_detail = self._score_breakdown_text(finding)
            correlation_confidence = f"{entry['confidence']:.2f}"

            rows.append(
                "<tr>"
                f"<td>{self._html(self._display(finding.severity).upper())}</td>"
                f"<td>{self._html(finding.title)}</td>"
                f"<td>{self._html(finding.category)}</td>"
                f"<td>{self._html(finding.score)}</td>"
                f"<td>{self._html(score_detail)}</td>"
                f"<td>{self._html(finding.scanner_severity or 'not provided')}</td>"
                f"<td>{self._html(sources)}</td>"
                f"<td>{self._html(entry['count'])}</td>"
                f"<td>{self._html(correlation_confidence)}</td>"
                f"<td>{self._html(finding.recommendation)}</td>"
                f"<td>{evidence_html}</td>"
                f"<td>{detections_html}</td>"
                "</tr>"
            )

        rows_html = "".join(rows) or (
            '<tr><td colspan="12">No normalized findings.</td></tr>'
        )

        html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Security Assessment</title>
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    background: #111827;
    color: #e5e7eb;
}}
table {{
    width: 100%;
    border-collapse: collapse;
}}
th, td {{
    padding: 10px;
    border: 1px solid #374151;
    text-align: left;
    vertical-align: top;
}}
th {{
    background: #1f2937;
}}
.meta {{
    margin-bottom: 25px;
}}
.summary {{
    display: flex;
    flex-wrap: wrap;
    gap: 18px;
    margin: 18px 0 28px;
}}
.summary div {{
    padding: 12px;
    border: 1px solid #374151;
    min-width: 150px;
}}
ul {{
    margin: 0;
    padding-left: 20px;
}}
</style>
</head>
<body>
<h1>Security Assessment Report</h1>
<div class="meta">
<b>Target:</b> {self._html(session.target)}<br>
<b>Profile:</b> {self._html(session.profile)}<br>
<b>Session:</b> {self._html(session.session_id)}
</div>
<div class="summary">
<div><b>Raw findings</b><br>{raw_count}</div>
<div><b>Distinct findings</b><br>{len(entries)}</div>
<div><b>Grouped duplicate detections</b><br>{duplicate_count}</div>
</div>
<h2>Attack Surface</h2>
{attack_surface_html}
<p>PhantomX risk score/severity is its normalized prioritization. Scanner severity is reported separately and may differ. Correlation confidence describes a heuristic record match, not independent verification.</p>
<h2>Workflow Notes</h2>
<ul>
{''.join(f'<li>{self._html(note)}</li>' for note in session.notes) or '<li>No additional workflow notes.</li>'}
</ul>
<h2>Prioritized Findings</h2>
<table>
<thead>
<tr>
<th>Representative Severity</th>
<th>Representative Finding</th>
<th>Category</th>
<th>Risk Score</th>
<th>Score Breakdown</th>
<th>Scanner Severity</th>
<th>Source Tools</th>
<th>Detections</th>
<th>Correlation Confidence</th>
<th>Recommendation</th>
<th>Evidence</th>
<th>Individual detections and verification</th>
</tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>
</body>
</html>
"""

        p = self.dir / f"report_{self._filename_id(session.session_id)}.html"
        p.write_text(html, encoding="utf-8")
        return p

    @classmethod
    def _pdf_plain_text(cls, value):
        """Make a bounded, redacted string safe for a built-in PDF font."""
        text = cls._redact_urls(value)
        text = " ".join(text.split())
        text = unicodedata.normalize("NFKD", text)
        text = "".join(char for char in text if not unicodedata.combining(char))
        text = text.translate(str.maketrans({
            "\u2013": "-", "\u2014": "-",
            "\u2018": "'", "\u2019": "'",
            "\u201c": '"', "\u201d": '"',
            "\u2026": "...", "\u2022": "*",
        }))
        return text.encode(
            "ascii", errors="replace"
        ).decode("ascii")

    def _pdf_report_lines(self, session):
        entries = self._correlated_findings(session)
        asset_graph = self._asset_graph(session)
        raw_count = len(self._flat_findings(session))
        lines = [
            "PhantomX Security Assessment Report",
            f"Target: {session.target}",
            f"Profile: {session.profile}",
            f"Session: {session.session_id}",
            f"Started: {session.started_at}",
            f"Raw findings: {raw_count}",
            f"Distinct correlated findings: {len(entries)}",
            f"Related duplicate detections grouped: {raw_count - len(entries)}",
            "",
            "PhantomX risk scores are prioritization, not proof of exploitability.",
            "Correlation confidence is a fixed record-match indicator, not probability.",
            "",
            "ATTACK SURFACE",
        ]
        lines.extend(self._asset_surface_lines(asset_graph))
        lines += ["", "TOOL EXECUTION"]
        for result in session.results:
            lines.append(
                f"{result.tool}: {result.status}; {result.duration_seconds:.2f}s; "
                f"return code {result.return_code}; findings {len(result.findings)}"
            )
            if result.stderr:
                lines.append(f"  Diagnostic: {result.stderr[:1200]}")

        lines += ["", "WORKFLOW NOTES"]
        lines.extend(session.notes or ["No additional workflow notes."])
        lines += ["", "PRIORITIZED FINDINGS"]
        if not entries:
            lines.append("No normalized findings were produced.")

        for entry in entries:
            finding = entry["finding"]
            lines += [
                "",
                f"{self._display(finding.severity).upper()} — {finding.title}",
                f"PhantomX score: {self._numeric(finding.score):.1f}/100; "
                f"scanner severity: {finding.scanner_severity or 'not provided'}",
                f"Category: {finding.category}; sources: "
                f"{', '.join(entry['sources']) or 'unknown'}; "
                f"related detections: {entry['count']}; "
                f"correlation indicator: {entry['confidence']:.2f}",
                f"Score breakdown: {self._score_breakdown_text(finding)}",
                f"Recommendation: {finding.recommendation}",
            ]
            for evidence in entry["evidence"][:5]:
                shown = evidence[:800]
                if len(evidence) > 800:
                    shown += " [truncated; full evidence is in JSON]"
                lines.append(f"Evidence: {shown}")
            if not entry["evidence"]:
                lines.append("Evidence: not provided")
            if entry["verification_conflict"]:
                lines.append("Warning: related detections report conflicting verification states.")

            for index, detection in enumerate(entry["detections"], start=1):
                status = detection["verification_status"] or "not provided"
                lines += [
                    f"  Detection {index}: {detection['title']}",
                    f"    Source: {detection['source']}; ID: {detection['finding_id']}",
                    f"    Target: {detection['target']}; verification: {status}",
                    f"    Category/severity: {detection['category']} / {detection['severity']}; "
                    f"score: {self._numeric(detection['score']):.1f}; "
                    f"scanner severity: {detection['scanner_severity'] or 'not provided'}",
                    f"    Recommendation: {detection['recommendation']}",
                ]
                for label, mapping in (
                    ("Endpoint", detection["endpoints"]),
                    ("Identifier", detection["identifiers"]),
                    ("Metadata", detection["metadata"]),
                ):
                    for key, value in mapping.items():
                        lines.append(f"    {label} {key}: {value}")
                for label, value in detection["verification_details"]:
                    lines.append(f"    {label}: {value}")
                if detection["evidence"]:
                    evidence = detection["evidence"]
                    suffix = " [truncated; full evidence is in JSON]" if len(evidence) > 800 else ""
                    lines.append(f"    Detection evidence: {evidence[:800]}{suffix}")
                else:
                    lines.append("    Detection evidence: not provided")
        return [self._pdf_plain_text(line) for line in lines]

    @staticmethod
    def _pdf_literal(value):
        return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def write_pdf(self, session):
        """Write a compact, dependency-free PDF assessment report.

        Built-in PDF fonts are used for portability, so text outside the
        supported ASCII subset is replaced with a readable approximation.
        """
        wrapped = []
        for line in self._pdf_report_lines(session):
            wrapped.extend(textwrap.wrap(
                line,
                width=94,
                break_long_words=True,
                break_on_hyphens=False,
            ) or [""])
        lines_per_page = 54
        pages = [wrapped[i:i + lines_per_page] for i in range(0, len(wrapped), lines_per_page)] or [[]]
        font_object = 3 + len(pages) * 2
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            (
                "<< /Type /Pages /Kids ["
                + " ".join(f"{3 + i * 2} 0 R" for i in range(len(pages)))
                + f"] /Count {len(pages)} >>"
            ).encode("ascii"),
        ]
        for index, page_lines in enumerate(pages):
            page_id = 3 + index * 2
            content_id = page_id + 1
            content = ["BT", "/F1 10 Tf", "48 790 Td", "14 TL"]
            for line in page_lines:
                content.append(f"({self._pdf_literal(line)}) Tj")
                content.append("T*")
            content.append("ET")
            stream = "\n".join(content).encode("ascii", errors="strict")
            objects.append(
                (
                    f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                    f"/Resources << /Font << /F1 {font_object} 0 R >> >> "
                    f"/Contents {content_id} 0 R >>"
                ).encode("ascii")
            )
            objects.append(
                f"<< /Length {len(stream)} >>\nstream\n".encode("ascii")
                + stream + b"\nendstream"
            )
        objects.append(
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
            b"/Encoding /WinAnsiEncoding >>"
        )

        output = bytearray(b"%PDF-1.4\n%PhantomX\n")
        offsets = [0]
        for number, obj in enumerate(objects, start=1):
            offsets.append(len(output))
            output.extend(f"{number} 0 obj\n".encode("ascii"))
            output.extend(obj)
            output.extend(b"\nendobj\n")
        xref_offset = len(output)
        output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
        output.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
        output.extend(
            (
                f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
                f"startxref\n{xref_offset}\n%%EOF\n"
            ).encode("ascii")
        )
        path = self.dir / f"report_{self._filename_id(session.session_id)}.pdf"
        path.write_bytes(output)
        return path
