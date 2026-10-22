
import json
from pathlib import Path
from html import escape


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
        findings = sorted(
            self._flat_findings(session),
            key=lambda f: f.score,
            reverse=True,
        )

        lines = [
            "# Security Assessment Report\n",
            f"- Target: `{session.target}`",
            f"- Profile: `{session.profile}`",
            f"- Session: `{session.session_id}`",
            "",
            "## Tool Execution",
        ]

        for result in session.results:
            lines.append(
                f"- **{result.tool}** — {result.status}, "
                f"{result.duration_seconds:.2f}s, "
                f"findings: {len(result.findings)}"
            )

        lines += ["", "## Findings", ""]

        if not findings:
            lines.append(
                "No normalized findings were produced. "
                "Review raw tool output and validate coverage."
            )

        for finding in findings:
            lines += [
                f"### {finding.severity.upper()} — {finding.title}",
                f"- Score: **{finding.score}/100**",
                f"- Source: `{finding.source_tool}`",
                f"- Category: `{finding.category}`",
                f"- Evidence: {finding.evidence[:800]}",
                f"- Recommendation: {finding.recommendation}",
            ]

            verification = self._verification_details(finding)

            if verification:
                lines += ["", "**Verification details**"]
                for label, value in verification:
                    lines.append(f"- {label}: `{value}`")

            lines.append("")

        p = self.dir / f"report_{session.session_id}.md"
        p.write_text("\n".join(lines), encoding="utf-8")
        return p

    def write_html(self, session):
        findings = sorted(
            self._flat_findings(session),
            key=lambda f: f.score,
            reverse=True,
        )

        rows = []

        for finding in findings:
            verification = self._verification_details(finding)

            if verification:
                verification_html = "<ul>" + "".join(
                    f"<li><strong>{escape(label)}:</strong> "
                    f"{escape(value)}</li>"
                    for label, value in verification
                ) + "</ul>"
            else:
                verification_html = "&mdash;"

            rows.append(
                "<tr>"
                f"<td>{escape(finding.severity.upper())}</td>"
                f"<td>{escape(finding.title)}</td>"
                f"<td>{finding.score}</td>"
                f"<td>{escape(finding.source_tool)}</td>"
                f"<td>{escape(finding.evidence[:500])}</td>"
                f"<td>{verification_html}</td>"
                "</tr>"
            )

        rows_html = "".join(rows) or (
            '<tr><td colspan="6">No normalized findings.</td></tr>'
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
<h2>Findings</h2>
<table>
<thead>
<tr>
<th>Severity</th>
<th>Finding</th>
<th>Score</th>
<th>Source</th>
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
