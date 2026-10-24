
import json
from pathlib import Path
from html import escape

from analysis.correlation import CorrelationEngine


class Reporter:
    VERIFICATION_FIELDS = {
        "verification_status": "Verification status",
        "remote_exposure": "Remote exposure",
        "access_control": "Access control",
        "exposure_scope": "Exposure scope",
    }

    def __init__(self, reports_dir="reports"):
        self.dir = Path(reports_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

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
                key=lambda finding: (finding.score, finding.confidence),
            )
            evidence = []
            for finding in group.findings:
                text = (finding.evidence or "").strip()
                if text and text not in evidence:
                    evidence.append(text)
            entries.append({
                "finding": representative,
                "sources": group.sources or sorted({
                    finding.source_tool for finding in group.findings
                    if finding.source_tool
                }),
                "count": len(group.findings),
                "confidence": group.confidence,
                "evidence": evidence,
            })

        return sorted(
            entries,
            key=lambda entry: entry["finding"].score,
            reverse=True,
        )

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

    def write_json(self, session):
        p = self.dir / f"session_{session.session_id}.json"
        p.write_text(
            json.dumps(session.as_dict(), indent=2),
            encoding="utf-8",
        )
        return p

    def write_markdown(self, session):
        entries = self._correlated_findings(session)
        raw_count = len(self._flat_findings(session))
        duplicate_count = raw_count - len(entries)

        lines = [
            "# Security Assessment Report\\n",
            f"- Target: `{session.target}`",
            f"- Profile: `{session.profile}`",
            f"- Session: `{session.session_id}`",
            f"- Raw findings: **{raw_count}**",
            f"- Distinct correlated findings: **{len(entries)}**",
            f"- Related duplicate detections grouped: **{duplicate_count}**",
            "",
            "> PhantomX risk score/severity is its normalized prioritization; scanner severity is shown separately when available.",
            "",
            "## Tool Execution",
        ]

        for result in session.results:
            lines.append(
                f"- **{result.tool}** — {result.status}, "
                f"{result.duration_seconds:.2f}s, "
                f"findings: {len(result.findings)}"
            )

        lines += ["", "## Workflow Notes", ""]
        if session.notes:
            lines.extend(f"- {note}" for note in session.notes)
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
            scanner_severity = finding.scanner_severity or "not provided"
            lines += [
                f"### {finding.severity.upper()} — {finding.title}",
                f"- PhantomX risk score: **{finding.score}/100**",
                f"- Scanner severity: `{scanner_severity}`",
                f"- Source tools: `{source_text}`",
                f"- Correlated detections: **{entry['count']}**",
                f"- Correlation confidence: **{entry['confidence']:.2f}**",
                f"- Category: `{finding.category}`",
            ]

            if entry["evidence"]:
                lines.append("- Evidence:")
                lines.extend(
                    f"  - {text[:800]}" for text in entry["evidence"][:5]
                )
            else:
                lines.append("- Evidence: Not provided")

            lines.append(f"- Recommendation: {finding.recommendation}")

            verification = self._verification_details(finding)
            if verification:
                lines += ["", "**Verification details**"]
                for label, value in verification:
                    lines.append(f"- {label}: `{value}`")
            lines.append("")

        p = self.dir / f"report_{session.session_id}.md"
        p.write_text("\\n".join(lines), encoding="utf-8")
        return p

    def write_html(self, session):
        entries = self._correlated_findings(session)
        raw_count = len(self._flat_findings(session))
        duplicate_count = raw_count - len(entries)
        rows = []

        for entry in entries:
            finding = entry["finding"]
            verification = self._verification_details(finding)

            if verification:
                verification_html = "<ul>" + "".join(
                    f"<li><strong>{escape(label)}:</strong> "
                    f"{escape(value)}</li>"
                    for label, value in verification
                ) + "</ul>"
            else:
                verification_html = "&mdash;"

            evidence_html = "<ul>" + "".join(
                f"<li>{escape(text[:500])}</li>"
                for text in entry["evidence"][:5]
            ) + "</ul>" if entry["evidence"] else "&mdash;"
            sources = ", ".join(entry["sources"]) or "unknown"

            rows.append(
                "<tr>"
                f"<td>{escape(finding.severity.upper())}</td>"
                f"<td>{escape(finding.title)}</td>"
                f"<td>{finding.score}</td>"
                f"<td>{escape(finding.scanner_severity or 'not provided')}</td>"
                f"<td>{escape(sources)}</td>"
                f"<td>{entry['count']}</td>"
                f"<td>{evidence_html}</td>"
                f"<td>{verification_html}</td>"
                "</tr>"
            )

        rows_html = "".join(rows) or (
            '<tr><td colspan="8">No normalized findings.</td></tr>'
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
<b>Target:</b> {escape(str(session.target))}<br>
<b>Profile:</b> {escape(str(session.profile))}<br>
<b>Session:</b> {escape(str(session.session_id))}
</div>
<div class="summary">
<div><b>Raw findings</b><br>{raw_count}</div>
<div><b>Distinct findings</b><br>{len(entries)}</div>
<div><b>Grouped duplicate detections</b><br>{duplicate_count}</div>
</div>
<p>PhantomX risk score/severity is its normalized prioritization. Scanner severity is reported separately and may differ.</p>
<h2>Workflow Notes</h2>
<ul>
{''.join(f'<li>{escape(note)}</li>' for note in session.notes) or '<li>No additional workflow notes.</li>'}
</ul>
<h2>Prioritized Findings</h2>
<table>
<thead>
<tr>
<th>PhantomX Severity</th>
<th>Finding</th>
<th>Risk Score</th>
<th>Scanner Severity</th>
<th>Source Tools</th>
<th>Detections</th>
<th>Evidence</th>
<th>Verification details</th>
</tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>
</body>
</html>
"""

        p = self.dir / f"report_{session.session_id}.html"
        p.write_text(html, encoding="utf-8")
        return p
