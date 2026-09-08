import json
from pathlib import Path
from html import escape

class Reporter:
    def __init__(self, reports_dir="reports"):
        self.dir = Path(reports_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _flat_findings(self, session):
        return [f for r in session.results for f in r.findings]

    def write_json(self, session):
        p = self.dir / f"session_{session.session_id}.json"
        p.write_text(json.dumps(session.as_dict(), indent=2), encoding="utf-8")
        return p

    def write_markdown(self, session):
        findings = sorted(self._flat_findings(session), key=lambda f: f.score, reverse=True)
        lines = [f"# Security Assessment Report\n", f"- Target: `{session.target}`", f"- Profile: `{session.profile}`", f"- Session: `{session.session_id}`", "", "## Tool Execution"]
        for r in session.results:
            lines.append(f"- **{r.tool}** — {r.status}, {r.duration_seconds:.2f}s, findings: {len(r.findings)}")
        lines += ["", "## Findings", ""]
        if not findings:
            lines.append("No normalized findings were produced. Review raw tool output and validate coverage.")
        for f in findings:
            lines += [f"### {f.severity.upper()} — {f.title}", f"- Score: **{f.score}/100**", f"- Source: `{f.source_tool}`", f"- Category: `{f.category}`", f"- Evidence: {f.evidence[:800]}", f"- Recommendation: {f.recommendation}", ""]
        p = self.dir / f"report_{session.session_id}.md"
        p.write_text("\n".join(lines), encoding="utf-8")
        return p

    def write_html(self, session):
        findings = sorted(self._flat_findings(session), key=lambda f: f.score, reverse=True)
        rows = "".join(
            f"<tr><td>{escape(f.severity.upper())}</td><td>{escape(f.title)}</td><td>{f.score}</td><td>{escape(f.source_tool)}</td><td>{escape(f.evidence[:500])}</td></tr>"
            for f in findings
        ) or '<tr><td colspan="5">No normalized findings.</td></tr>'
        html = f"""<!doctype html><html><head><meta charset='utf-8'><title>Security Assessment</title><style>body{{font-family:Arial;margin:40px;background:#111827;color:#e5e7eb}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;border:1px solid #374151;text-align:left}}th{{background:#1f2937}}.meta{{margin-bottom:25px}}</style></head><body><h1>Security Assessment Report</h1><div class='meta'><b>Target:</b> {escape(session.target)}<br><b>Profile:</b> {escape(session.profile)}<br><b>Session:</b> {escape(session.session_id)}</div><h2>Findings</h2><table><tr><th>Severity</th><th>Finding</th><th>Score</th><th>Source</th><th>Evidence</th></tr>{rows}</table></body></html>"""
        p = self.dir / f"report_{session.session_id}.html"
        p.write_text(html, encoding="utf-8")
        return p
