from analysis.scoring import RiskEngine
from core.models import Finding, Session, ToolResult
from core.workflow import WorkflowEngine
from reporting.reporter import Reporter


class QuietLogger:
    def info(self, *args, **kwargs):
        pass


class EmptyRegistry:
    def list(self):
        return []


class UnusedExecutor:
    def run(self, *args, **kwargs):
        raise AssertionError("No tools should execute in this test")


class UnusedAdapter:
    def run(self, *args, **kwargs):
        raise AssertionError("No tools should execute in this test")


class PassthroughNormalizer:
    def parse(self, result):
        return result


def make_engine():
    return WorkflowEngine(
        registry=EmptyRegistry(),
        executor=UnusedExecutor(),
        adapter_manager=UnusedAdapter(),
        normalizer=PassthroughNormalizer(),
        risk_engine=RiskEngine(),
        logger=QuietLogger(),
    )


def make_result(tool, finding):
    return ToolResult(
        tool=tool,
        category="recon",
        target="127.0.0.1",
        started_at="",
        finished_at="",
        return_code=0,
        findings=[finding],
    )


def test_workflow_annotates_cross_tool_correlated_findings():
    first = Finding(
        title="HTTP service", category="network", target="127.0.0.1",
        source_tool="nmap", score=43.8,
        metadata={"port": 80, "protocol": "tcp"},
    )
    second = Finding(
        title="HTTP detected", category="network", target="127.0.0.1",
        source_tool="whatweb", score=34.0,
        metadata={"port": 80, "protocol": "tcp"},
    )
    session = Session(
        target="127.0.0.1",
        profile="standard",
        results=[make_result("nmap", first), make_result("whatweb", second)],
    )

    make_engine()._correlate_session_findings(session)

    assert first.metadata["correlation"]["group_size"] == 2
    assert first.metadata["correlation"]["sources"] == ["nmap", "whatweb"]
    assert second.metadata["correlation"]["confidence"] == 0.85
    assert any(note.startswith("Finding correlation: 2 raw findings, 1 distinct groups")
               for note in session.notes)


def test_correlation_annotation_is_recomputed_not_duplicated():
    finding = Finding(
        title="HTTP service", category="network", target="127.0.0.1",
        source_tool="nmap", metadata={"port": 80, "protocol": "tcp"},
    )
    session = Session(
        target="127.0.0.1", profile="standard",
        results=[make_result("nmap", finding)],
    )
    engine = make_engine()

    engine._correlate_session_findings(session)
    engine._correlate_session_findings(session)

    assert sum(note.startswith("Finding correlation:") for note in session.notes) == 1
    assert "correlation" not in finding.metadata


def test_markdown_report_groups_duplicates_and_explains_scores(tmp_path):
    first = Finding(
        title="HTTP service", category="network", target="127.0.0.1",
        source_tool="nmap", score=43.8, severity="medium",
        scanner_severity="",
        evidence="Port 80 is open.",
        metadata={"port": 80, "protocol": "tcp"},
    )
    second = Finding(
        title="HTTP detected", category="network", target="127.0.0.1",
        source_tool="whatweb", score=34.0, severity="low",
        evidence="HTTP server answered.",
        metadata={"port": 80, "protocol": "tcp"},
    )
    distinct = Finding(
        title="Exposed backup file", category="web", target="127.0.0.1",
        source_tool="nuclei", score=50.0, severity="medium",
        scanner_severity="low", evidence="/backup.zip",
    )
    session = Session(
        target="127.0.0.1", profile="full",
        results=[
            make_result("nmap", first),
            make_result("whatweb", second),
            make_result("nuclei", distinct),
        ],
    )

    report = Reporter(tmp_path).write_markdown(session).read_text(encoding="utf-8")

    assert "- Raw findings: **3**" in report
    assert "- Distinct correlated findings: **2**" in report
    assert "- Related duplicate detections grouped: **1**" in report
    assert "nmap, whatweb" in report
    assert "Scanner severity: `low`" in report
    assert "Port 80 is open." in report
    assert "HTTP server answered." in report
    assert "Exposed backup file" in report



def test_workflow_run_finalizes_with_correlation_summary():
    session = Session(target="127.0.0.1", profile="passive")
    result = make_engine().run(session)

    assert result is session
    assert any(
        note.startswith("Finding correlation: 0 raw findings, 0 distinct groups")
        for note in session.notes
    )


def test_distinct_missing_headers_are_not_merged_by_shared_template_id(tmp_path):
    first = Finding(
        title="Missing HTTP security header: Content Security Policy",
        category="misconfiguration", target="127.0.0.1",
        source_tool="nuclei", severity="low", score=32,
        metadata={"template_id": "http-missing-security-headers"},
    )
    second = Finding(
        title="Missing HTTP security header: X Frame Options",
        category="misconfiguration", target="127.0.0.1",
        source_tool="nuclei", severity="low", score=32,
        metadata={"template_id": "http-missing-security-headers"},
    )
    session = Session(
        target="127.0.0.1", profile="full",
        results=[make_result("nuclei", first), make_result("nuclei", second)],
    )

    report = Reporter(tmp_path).write_markdown(session).read_text(encoding="utf-8")

    assert "- Raw findings: **2**" in report
    assert "- Distinct correlated findings: **2**" in report
    assert "Correlated detections: **2**" not in report


def test_markdown_report_uses_real_newlines(tmp_path):
    session = Session(target="127.0.0.1", profile="passive")
    report = Reporter(tmp_path).write_markdown(session).read_text(encoding="utf-8")

    assert "\\n" not in report
    assert report.startswith("# Security Assessment Report\n")
    assert "\n- Target: `127.0.0.1`\n" in report
