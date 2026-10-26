import json

import pytest

from core.models import Finding, Session, ToolResult
from reporting.reporter import Reporter


def result(tool, finding):
    return ToolResult(
        tool=tool,
        category="recon",
        target="127.0.0.1",
        started_at="",
        finished_at="",
        return_code=0,
        findings=[finding],
    )


def test_report_formats_preserve_group_evidence_verification_and_scores(tmp_path):
    first = Finding(
        title="HTTP service",
        category="network",
        target="127.0.0.1",
        source_tool="nmap",
        score=43.8,
        severity="medium",
        evidence="Observed service evidence α",
        metadata={
            "port": 80,
            "protocol": "tcp",
            "verification_status": "scanner_match_unverified",
        },
        score_breakdown={
            "normalized_inputs": {"impact": 4.0, "confidence": 8.0},
            "contributions": {"impact": 14.0, "confidence": 20.0},
            "confidence_interpretation": "fraction converted to 0-10",
        },
    )
    second = Finding(
        title="HTTP detected",
        category="network",
        target="127.0.0.1",
        source_tool="whatweb",
        score=34.0,
        severity="low",
        evidence="Second source evidence",
        metadata={
            "port": 80,
            "protocol": "tcp",
            "verification_status": "path_discovery_only",
        },
    )
    session = Session(
        target="127.0.0.1",
        profile="full",
        session_id="phase3-report",
        results=[result("nmap", first), result("whatweb", second)],
    )
    reporter = Reporter(tmp_path)

    json_path = reporter.write_json(session)
    markdown_path = reporter.write_markdown(session)
    html_path = reporter.write_html(session)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = markdown_path.read_text(encoding="utf-8")
    html = html_path.read_text(encoding="utf-8")

    assert len(payload["results"]) == 2
    assert payload["results"][0]["findings"][0]["score_breakdown"]["contributions"]["impact"] == 14.0
    assert payload["report_summary"]["raw_finding_count"] == 2
    assert payload["report_summary"]["distinct_report_entry_count"] == 1
    assert payload["report_summary"]["grouped_detection_count"] == 1
    assert payload["report_summary"]["correlation_groups"][0]["verification_conflict"] is True
    assert "Distinct correlated findings: **1**" in markdown
    assert "nmap, whatweb" in markdown and "nmap, whatweb" in html
    assert "Observed service evidence α" in markdown and "Second source evidence" in html
    assert "Conflicting verification states" in markdown
    assert "scanner_match_unverified" in markdown and "path_discovery_only" in html
    assert "Score breakdown contributions: impact: input 4.0, contribution 14.0" in markdown
    assert "impact: input 4.0, contribution 14.0" in html
    assert "Correlation Confidence" in html
    assert "heuristic record match, not independent verification" in html
    assert "fixed record-match indicator, not a calibrated probability" in markdown


def test_html_escapes_untrusted_values_and_report_filename_stays_in_directory(tmp_path):
    payload = "<script>alert(1)</script>"
    finding = Finding(
        title=payload,
        category=payload,
        severity=payload,
        scanner_severity=payload,
        score=payload,
        recommendation=payload,
        evidence=payload,
        source_tool=payload,
        target=payload,
        finding_id=payload,
        metadata={"verification_status": payload},
    )
    session = Session(
        target=payload,
        profile=payload,
        session_id="../../outside",
        results=[result(payload, finding)],
        notes=[payload],
    )

    html_path = Reporter(tmp_path).write_html(session)
    html = html_path.read_text(encoding="utf-8")

    assert html_path.parent == tmp_path.resolve()
    assert "<script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert payload not in html


def test_report_marks_evidence_truncation_while_json_keeps_complete_evidence(tmp_path):
    finding = Finding(
        title="Long evidence",
        category="web",
        evidence="x" * 900,
    )
    session = Session(target="127.0.0.1", profile="full", results=[result("scanner", finding)])
    reporter = Reporter(tmp_path)

    markdown = reporter.write_markdown(session).read_text(encoding="utf-8")
    html = reporter.write_html(session).read_text(encoding="utf-8")

    assert "truncated for report; full evidence is in JSON" in markdown
    assert "truncated for report; full evidence is in JSON" in html
    payload = json.loads(reporter.write_json(session).read_text(encoding="utf-8"))
    assert payload["results"][0]["findings"][0]["evidence"] == "x" * 900


def test_json_report_rejects_nonfinite_metadata_instead_of_writing_invalid_json(tmp_path):
    finding = Finding("Malformed metadata", "web", metadata={"scanner_value": float("nan")})
    session = Session(target="127.0.0.1", profile="full", results=[result("scanner", finding)])

    with pytest.raises(ValueError):
        Reporter(tmp_path).write_json(session)


def test_missing_or_malformed_verification_metadata_is_not_inferred_or_mutated(tmp_path):
    malformed = ["scanner", "<script>"]
    finding = Finding(
        title="Metadata edge case",
        category="web",
        target="127.0.0.1",
        source_tool="scanner",
        metadata={"verification_status": malformed},
    )
    session = Session(target="127.0.0.1", profile="full", results=[result("scanner", finding)])
    reporter = Reporter(tmp_path)

    markdown = reporter.write_markdown(session).read_text(encoding="utf-8")
    html = reporter.write_html(session).read_text(encoding="utf-8")
    payload = json.loads(reporter.write_json(session).read_text(encoding="utf-8"))

    assert "status `['scanner', '<script>']`" in markdown
    assert "status `not provided`" not in markdown
    assert "&lt;script&gt;" in html and "<script>" not in html
    assert payload["results"][0]["findings"][0]["metadata"]["verification_status"] == malformed
    assert finding.metadata["verification_status"] is malformed


def test_human_reports_redact_urls_everywhere_without_mutating_raw_session(tmp_path):
    valid_url = "https://alice:secret@lab.test/admin?token=one#private"
    malformed_url = "https://bob:password@[broken/path?api_key=two#hidden"
    protocol_relative = "//carol:credential@lab.test/internalpage?key=three#four"
    evidence = (
        "<script>alert(1)</script> "
        f"GET {valid_url}, then GET {malformed_url}, then {protocol_relative}"
    )
    finding = Finding(
        "URLs observed",
        "web",
        target=valid_url,
        source_tool="scanner",
        evidence=evidence,
        metadata={"url": valid_url, "matched_at": malformed_url},
    )
    session = Session(
        target=valid_url,
        profile="full",
        session_id="url-redaction",
        results=[result("scanner", finding)],
    )
    original = json.dumps(session.as_dict(), sort_keys=True, ensure_ascii=False)
    reporter = Reporter(tmp_path)

    markdown = reporter.write_markdown(session).read_text(encoding="utf-8")
    html = reporter.write_html(session).read_text(encoding="utf-8")
    payload = json.loads(reporter.write_json(session).read_text(encoding="utf-8"))

    for content in (markdown, html):
        for secret in (
            "alice", "secret", "token=one", "private", "bob", "password",
            "api_key=two", "hidden", "carol", "credential", "key=three", "four",
        ):
            assert secret not in content
        assert "lab.test/admin" in content
        assert "broken/path" in content
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "Detection evidence:" in markdown
    assert "&lt;script&gt;" in markdown
    status_line = next(line for line in markdown.splitlines() if "Verification status " in line)
    assert status_line.startswith("- Verification status `")
    assert status_line.endswith("`")
    assert payload["target"] == valid_url
    assert payload["results"][0]["findings"][0]["evidence"] == evidence
    assert payload["results"][0]["findings"][0]["metadata"]["matched_at"] == malformed_url
    assert json.dumps(session.as_dict(), sort_keys=True, ensure_ascii=False) == original


def test_report_filenames_are_bounded_and_collisions_from_sanitizing_are_avoided(tmp_path):
    reporter = Reporter(tmp_path)
    sensitive_id = reporter._filename_id(
        "https://alice:secret@lab.test/report?token=one#fragment"
    )
    assert all(secret not in sensitive_id for secret in ("alice", "secret", "token", "one", "fragment"))
    long_session = Session("127.0.0.1", "full", session_id="x" * 1000)
    paths = [
        reporter.write_json(long_session),
        reporter.write_markdown(long_session),
        reporter.write_html(long_session),
    ]
    assert all(path.exists() and path.parent == tmp_path.resolve() for path in paths)
    assert all(len(path.name) <= 255 for path in paths)

    first = Session("127.0.0.1", "full", session_id="lab/a")
    second = Session("127.0.0.1", "full", session_id="lab?a")
    first_path = reporter.write_json(first)
    second_path = reporter.write_json(second)
    assert first_path != second_path
    assert first_path.parent == second_path.parent == tmp_path.resolve()

    case_variant = reporter.write_json(
        Session("127.0.0.1", "full", session_id="LAB/A")
    )
    assert case_variant != first_path


def test_reports_handle_unpaired_surrogates_without_mutating_raw_values(tmp_path):
    malformed_unicode = "\ud800"
    finding = Finding(
        title=f"Scanner title {malformed_unicode}",
        category="web",
        target="lab.test",
        evidence=f"Evidence {malformed_unicode}",
        metadata={"verification_status": malformed_unicode},
    )
    session = Session(
        "lab.test",
        "full",
        results=[result("scanner", finding)],
    )
    reporter = Reporter(tmp_path)

    markdown = reporter.write_markdown(session).read_text(encoding="utf-8")
    html = reporter.write_html(session).read_text(encoding="utf-8")
    payload = json.loads(reporter.write_json(session).read_text(encoding="utf-8"))

    assert "\ufffd" in markdown
    assert "\ufffd" in html
    assert payload["results"][0]["findings"][0]["title"] == finding.title
    assert finding.title.endswith(malformed_unicode)


def test_reports_survive_malformed_scanner_fields_and_redact_nested_url_text(tmp_path):
    raw_evidence = {
        "response": "https://user:password@lab.test/path?token=hidden#fragment",
        "details": ["<script>alert(1)</script>"],
    }
    finding = Finding(
        title={"unexpected": "shape"},
        category="web",
        severity={"unexpected": "shape"},
        score="not-a-number",
        confidence={"unexpected": "shape"},
        evidence=raw_evidence,
        source_tool={"unexpected": "shape"},
        metadata={"verification_status": ["malformed", "<script>"]},
    )
    session = Session("lab.test", "full", results=[result("scanner", finding)])
    reporter = Reporter(tmp_path)

    markdown = reporter.write_markdown(session).read_text(encoding="utf-8")
    html = reporter.write_html(session).read_text(encoding="utf-8")
    payload = json.loads(reporter.write_json(session).read_text(encoding="utf-8"))

    for content in (markdown, html):
        for secret in ("user", "password", "token=hidden", "fragment"):
            assert secret not in content
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "Detection evidence:" in markdown
    assert "&lt;script&gt;" in markdown
    assert payload["results"][0]["findings"][0]["evidence"] == raw_evidence


def test_pdf_report_is_valid_paginated_and_redacts_human_readable_urls(tmp_path):
    from core.models import Finding, Session, ToolResult

    findings = [
        Finding(
            title=f"Finding {index} <script>",
            category="misconfiguration",
            source_tool="scanner",
            target="https://alice:secret@lab.test/path?token=hidden#fragment",
            evidence=(
                "https://alice:secret@lab.test/path?token=hidden#fragment "
                + ("evidence " * 120)
            ),
            metadata={"verification_status": "scanner_match_unverified"},
        )
        for index in range(65)
    ]
    result = ToolResult(
        tool="scanner", category="web", target="127.0.0.1",
        started_at="start", finished_at="finish", return_code=0,
        findings=findings,
    )
    session = Session(
        target="https://alice:secret@lab.test/?token=hidden#fragment",
        profile="full", results=[result], session_id="pdf-test",
    )
    path = Reporter(tmp_path).write_pdf(session)
    data = path.read_bytes()

    assert Reporter._pdf_plain_text("INFO — Open service") == "INFO - Open service"
    assert Reporter._pdf_plain_text("Unicode café ☃") == "Unicode cafe ?"

    assert path.parent == tmp_path.resolve()
    assert data.startswith(b"%PDF-1.4")
    assert data.rstrip().endswith(b"%%EOF")
    assert data.count(b"/Type /Page ") > 1
    assert b"Finding 64" in data
    assert b"lab.test/path" in data
    for secret in (b"alice", b"secret", b"token=hidden", b"fragment"):
        assert secret not in data


def test_report_all_includes_pdf_and_continues_after_writer_failure(capsys):
    from types import SimpleNamespace
    from main import App

    class ReporterStub:
        def write_json(self, session):
            raise OSError("simulated JSON write error")

        def write_markdown(self, session):
            return "report.md"

        def write_html(self, session):
            return "report.html"

        def write_pdf(self, session):
            return "report.pdf"

    app = App.__new__(App)
    app.last_session = object()
    app.reporter = ReporterStub()
    app.logger = SimpleNamespace(exception=lambda *args, **kwargs: None)
    app.reports("all")
    output = capsys.readouterr().out

    assert "Could not write json report" in output
    assert "report.md" in output
    assert "report.html" in output
    assert "report.pdf" in output
