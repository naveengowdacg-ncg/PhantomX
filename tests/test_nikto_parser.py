from analysis.normalizer import Normalizer
from core.models import ToolResult
from modules.nikto.parser import NiktoParser


SAMPLE = """
- Nikto v2.5.0
+ Target IP:          127.0.0.1
+ Target Hostname:    localhost
+ Server: Apache/2.4
+ /: The X-Content-Type-Options header is not set.
+ /server-status: Apache server-status page may be exposed.
+ /backup.zip: Backup archive may be accessible.
+ /: The X-Content-Type-Options header is not set.
+ 15 item(s) reported on remote host
+ End Time: 2026-10-24 14:38:24
+ 1 host(s) tested
"""


def test_parser_extracts_distinct_path_findings_and_deduplicates():
    findings = NiktoParser().parse(SAMPLE, "http://127.0.0.1")

    assert len(findings) == 3
    assert len({finding.evidence for finding in findings}) == 3
    assert any("X-Content-Type-Options" in finding.title for finding in findings)
    assert any("server-status" in finding.title for finding in findings)
    assert any("backup.zip" in finding.title for finding in findings)


def test_parser_preserves_path_and_verification_metadata():
    findings = NiktoParser().parse(SAMPLE, "http://127.0.0.1")
    header_finding = next(
        finding for finding in findings
        if "X-Content-Type-Options" in finding.title
    )

    assert header_finding.metadata["path"] == "/"
    assert header_finding.metadata["verification_status"] == "scanner_match_unverified"
    assert header_finding.source_tool == "nikto"
    assert header_finding.target == "http://127.0.0.1"


def test_parser_ignores_empty_output_and_scan_summary():
    summary = """
+ Target IP: 127.0.0.1
+ Server: Apache
+ 15 item(s) reported on remote host
+ End Time: 2026-10-24 14:38:24
+ 1 host(s) tested
"""
    assert NiktoParser().parse("", "http://127.0.0.1") == []
    assert NiktoParser().parse(summary, "http://127.0.0.1") == []


def test_normalizer_uses_parser_for_multiple_nikto_items():
    result = ToolResult(
        tool="nikto",
        category="web",
        target="http://127.0.0.1",
        started_at="",
        finished_at="",
        return_code=1,
        stdout=SAMPLE,
        status="success",
    )

    normalized = Normalizer().parse(result)

    assert len(normalized.findings) == 3
    assert all(f.source_tool == "nikto" for f in normalized.findings)
