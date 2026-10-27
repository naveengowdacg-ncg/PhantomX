from __future__ import annotations

import importlib
import json
import re
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from analysis.correlation import CorrelationEngine
from analysis.normalizer import Normalizer
from analysis.scoring import RiskEngine
from core.models import Finding, Session, ToolResult
from core.process_utils import ProcessOutcome
from core.scope import TargetScope
from core.workflow import WorkflowEngine
from modules.nmap.adapter import NmapAdapter
from modules.nuclei.adapter import NucleiAdapter
from modules.whatweb.adapter import WhatWebAdapter
from reporting.reporter import Reporter


ADAPTERS = {
    "nmap": ("modules.nmap.adapter", NmapAdapter, "recon", "Nmap"),
    "whatweb": ("modules.whatweb.adapter", WhatWebAdapter, "web", "WhatWeb"),
    "nuclei": ("modules.nuclei.adapter", NucleiAdapter, "vuln", "Nuclei"),
}


def _adapter(name):
    _, adapter_type, _, _ = ADAPTERS[name]
    adapter = adapter_type()
    adapter.executable = f"/test/{name}"
    adapter.parser.parse = Mock(return_value=[])
    return adapter


def _outcome(stdout="", stderr="", return_code=0, status="success"):
    return ProcessOutcome(
        stdout=stdout,
        stderr=stderr,
        return_code=return_code,
        status=status,
        duration_seconds=0.01,
    )


@pytest.mark.parametrize("name", list(ADAPTERS))
def test_specialized_adapters_decode_invalid_utf8_and_keep_nonzero_results(name, monkeypatch):
    module_name, _, _, _ = ADAPTERS[name]
    module = importlib.import_module(module_name)
    adapter = _adapter(name)
    calls = {}

    def fake_run(command, **kwargs):
        calls.update(kwargs)
        return _outcome(
            "partial output �", "scanner diagnostic �", 7, "failed"
        )

    monkeypatch.setattr(module, "run_process", fake_run)
    result = adapter.scan("127.0.0.1")

    assert result.status == "failed"
    assert result.return_code == 7
    assert result.stdout == "partial output �"
    assert result.stderr == "scanner diagnostic �"
    assert calls["timeout"] > 0


@pytest.mark.parametrize("name", list(ADAPTERS))
def test_specialized_adapters_preserve_timeout_partial_bytes(name, monkeypatch):
    module_name, _, _, _ = ADAPTERS[name]
    module = importlib.import_module(module_name)
    adapter = _adapter(name)
    monkeypatch.setattr(
        module, "run_process",
        Mock(return_value=_outcome(
            "partial stdout �",
            "partial stderr �\nTool timed out after 1 seconds.",
            None,
            "timeout",
        )),
    )

    result = adapter.scan("127.0.0.1")

    assert result.status == "timeout"
    assert result.return_code is None
    assert result.stdout == "partial stdout �"
    assert result.stderr == "partial stderr �\nTool timed out after 1 seconds."
    assert "b'" not in result.stdout
    assert "b'" not in result.stderr


@pytest.mark.parametrize("name", list(ADAPTERS))
def test_specialized_adapters_do_not_invent_empty_timeout_output(name, monkeypatch):
    module_name, _, _, _ = ADAPTERS[name]
    module = importlib.import_module(module_name)
    adapter = _adapter(name)
    monkeypatch.setattr(
        module, "run_process",
        Mock(return_value=_outcome(
            "", "Tool timed out after 1 seconds.", None, "timeout"
        )),
    )

    result = adapter.scan("127.0.0.1")

    assert result.status == "timeout"
    assert result.stdout == ""
    assert result.stderr == "Tool timed out after 1 seconds."


@pytest.mark.parametrize("name", list(ADAPTERS))
def test_specialized_adapters_preserve_output_when_parser_raises(name, monkeypatch):
    module_name, _, _, _ = ADAPTERS[name]
    module = importlib.import_module(module_name)
    adapter = _adapter(name)
    monkeypatch.setattr(
        module,
        "run_process",
        Mock(return_value=_outcome(
            "captured scanner output", "scanner note", 0, "success"
        )),
    )
    adapter.parser.parse = Mock(side_effect=ValueError("parser rejected output"))

    result = adapter.scan("127.0.0.1")

    assert result.status == "parse_error"
    assert result.return_code == 0
    assert result.stdout == "captured scanner output"
    assert result.stderr.startswith("scanner note\n")
    assert "parser rejected output" in result.stderr


@pytest.mark.parametrize("name", list(ADAPTERS))
def test_specialized_adapters_preserve_exception_partial_output(name, monkeypatch):
    module_name, _, _, _ = ADAPTERS[name]
    module = importlib.import_module(module_name)
    adapter = _adapter(name)
    monkeypatch.setattr(
        module,
        "run_process",
        Mock(return_value=_outcome(
            "partial stdout �",
            "partial stderr �\nTool process launch failed (OSError): process launch failed",
            7,
            "error",
        )),
    )

    result = adapter.scan("127.0.0.1")

    assert result.status == "error"
    assert result.return_code == 7
    assert result.stdout == "partial stdout �"
    assert result.stderr.startswith("partial stderr �\n")
    assert "process launch failed" in result.stderr


def test_nuclei_parser_ignores_unexpected_json_shapes_and_nonfinite_values():
    from modules.nuclei.parser import NucleiParser

    parser = NucleiParser()
    output = "\n".join((
        "[]",
        "null",
        '{"info": []}',
        '{"info":{"severity":[],"tags":"not-a-list","name":[]},"port":{}}',
        '{"info":{"severity":"high"},"unexpected":NaN}',
    ))

    findings = parser.parse(output, "127.0.0.1")

    assert len(findings) == 1
    assert findings[0].title == "Nuclei detection"
    assert findings[0].category == "observation"


class _Registry:
    def __init__(self, tools):
        self.tools = tools

    def list(self):
        return self.tools


class _Logger:
    def __init__(self):
        self.messages = []

    def info(self, message, *args):
        self.messages.append(message % args if args else message)

    def warning(self, message, *args):
        self.messages.append(message % args if args else message)

    def exception(self, message, *args):
        self.messages.append(message % args if args else message)


class _AdapterManager:
    def __init__(self, handler):
        self.handler = handler

    def run(self, tool, target, executor, extra_args=None):
        return self.handler(tool, target)


def _tool(name, category):
    return {
        "name": name,
        "category": category,
        "executable": name,
        "args": [],
        "enabled": True,
    }


def _tool_result(name, category, target, **kwargs):
    return ToolResult(
        tool=name,
        category=category,
        target=target,
        started_at="",
        finished_at="",
        return_code=kwargs.pop("return_code", 0),
        status=kwargs.pop("status", "success"),
        **kwargs,
    )


def _workflow(tools, handler):
    logger = _Logger()
    engine = WorkflowEngine(
        registry=_Registry(tools),
        executor=object(),
        adapter_manager=_AdapterManager(handler),
        normalizer=Normalizer(),
        risk_engine=RiskEngine(),
        logger=logger,
        max_workers=2,
        scope=TargetScope(True, ["127.0.0.1", "lab.test", "*.lab.test"]),
    )
    engine._show_loading = lambda *args: None
    return engine, logger


def test_discovery_future_exception_is_a_failed_result_and_keeps_peer_results():
    def handle(tool, target):
        return _tool_result(tool["name"], tool["category"], target)

    engine, logger = _workflow(
        [_tool("nmap", "recon"), _tool("httpx", "recon")],
        handle,
    )

    def worker(tool, target, extra_args=None):
        if tool["name"] == "nmap":
            raise RuntimeError("simulated future failure")
        return handle(tool, target)

    engine._run_tool_with_loading = worker
    session = engine.run(Session(target="127.0.0.1", profile="standard"))

    failed = next(result for result in session.results if result.tool == "nmap")
    peer = next(result for result in session.results if result.tool == "httpx")
    assert failed.status == "error"
    assert failed.target == "127.0.0.1"
    assert "simulated future failure" in failed.stderr
    assert peer.status == "success"
    assert any("Discovery worker failed" in note for note in session.notes)
    assert any("Discovery worker for nmap failed" in message for message in logger.messages)


def test_scoped_enrichment_future_exception_is_recorded_and_keeps_discovery():
    def handle(tool, target):
        if tool["name"] == "subfinder":
            finding = Finding(
                "Subdomain discovered",
                "observation",
                target=target,
                source_tool="subfinder",
                metadata={"hostname": "api.lab.test"},
            )
            return _tool_result(tool["name"], tool["category"], target, findings=[finding])
        return _tool_result(tool["name"], tool["category"], target)

    engine, logger = _workflow(
        [_tool("subfinder", "recon"), _tool("httpx", "recon")],
        handle,
    )

    def scoped_worker(tool, target, session, extra_args=None):
        raise RuntimeError("scoped future failure")

    engine._run_scoped_tool_with_loading = scoped_worker
    session = engine.run(Session(target="lab.test", profile="standard"))

    failed = next(
        result for result in session.results
        if result.tool == "httpx" and result.target == "api.lab.test"
    )
    assert failed.status == "error"
    assert "scoped future failure" in failed.stderr
    assert any(
        result.tool == "subfinder" and result.status == "success"
        for result in session.results
    )
    assert any(
        result.tool == "httpx" and result.target == "lab.test"
        and result.status == "success"
        for result in session.results
    )
    assert any("Scoped enrichment worker failed" in note for note in session.notes)
    assert any("Scoped enrichment worker for httpx" in message for message in logger.messages)


def test_score_all_accepts_generators_and_validates_before_scoring():
    engine = RiskEngine()
    first = Finding("one", "vuln", impact=4, exploitability=4, confidence=0.5, exposure=2)
    second = Finding("two", "vuln", impact=6, exploitability=3, confidence=0.8, exposure=1)

    scored = engine.score_all(item for item in (first, second))

    assert scored == [first, second]
    assert [finding.score for finding in scored] == [40.5, 51.0]
    assert engine.score_all((first, second)) == [first, second]
    assert engine.score_all(item for item in ()) == []

    valid = Finding("valid", "vuln", impact=10, exploitability=10, confidence=1, exposure=10)
    invalid = Finding("invalid", "vuln", impact=float("nan"))
    with pytest.raises(ValueError):
        engine.score_all(item for item in (valid, invalid))
    assert valid.score == 0.0
    assert valid.score_breakdown == {}


def test_normalization_is_idempotent_and_keeps_findings_added_afterward():
    normalizer = Normalizer()
    result = _tool_result(
        "nmap",
        "recon",
        "127.0.0.1",
        services=[SimpleNamespace(
            port=80,
            protocol="tcp",
            state="open",
            service="http",
            version="Apache",
        )],
    )

    normalizer.parse(result)
    first_ids = [finding.finding_id for finding in result.findings]
    original_generated = result.findings[0]
    original_generated.metadata["correlation"] = {"marker": "keep until recalculated"}
    result.services.append(SimpleNamespace(
        port=443,
        protocol="tcp",
        state="open",
        service="https",
        version="nginx",
    ))
    normalizer.parse(result)

    assert result.findings[0] is original_generated
    assert result.findings[0].finding_id == first_ids[0]
    assert len(result.findings) == 2
    assert result.findings[0].metadata["correlation"] == {"marker": "keep until recalculated"}
    later = Finding("Later adapter finding", "observation", source_tool="nmap")
    result.findings.append(later)
    normalizer.parse(result)
    assert later in result.findings
    assert len(result.findings) == 3
    second_generated = next(
        finding for finding in result.findings
        if finding.title == "Open service: https on port 443"
    )

    result.services[-1].state = "closed"
    normalizer.parse(result)
    assert len(result.findings) == 2
    assert original_generated in result.findings
    assert later in result.findings
    assert second_generated not in result.findings


def test_correlation_indicator_does_not_depend_on_source_count_or_match_class():
    engine = CorrelationEngine()

    repeated_source = [
        Finding("HTTP service", "network", source_tool="nmap", target="127.0.0.1",
                metadata={"port": 80, "protocol": "tcp"})
        for _ in range(3)
    ]
    distinct_sources = [
        Finding(title, "network", source_tool=source, target="127.0.0.1",
                metadata={"port": 80, "protocol": "tcp"})
        for title, source in (("HTTP service", "nmap"), ("HTTP detected", "whatweb"))
    ]
    cve_findings = [
        Finding("Finding A", "vuln", source_tool="scanner-a", target="127.0.0.1",
                metadata={"cve": "CVE-2024-12345"}),
        Finding("Finding B", "vuln", source_tool="scanner-b", target="127.0.0.1",
                metadata={"cve_id": "CVE-2024-12345"}),
    ]
    nuclei_findings = [
        Finding("Database service", "recon", source_tool="nuclei", target="127.0.0.1",
                metadata={"template_id": "mysql-detect", "matched_at": "127.0.0.1:3306"}),
        Finding("Database service", "recon", source_tool="nuclei", target="127.0.0.1",
                metadata={"template_id": "mysql-detect", "matched_at": "127.0.0.1:3306"}),
    ]

    for findings in (repeated_source, distinct_sources, cve_findings, nuclei_findings):
        group, = engine.correlate(findings)
        assert group.confidence == 0.70

    singleton, = engine.correlate([Finding("single", "web", target="127.0.0.1")])
    assert singleton.confidence == 0.0
    assert len(engine.correlate(repeated_source)[0].sources) == 1


def test_correlation_reprocessing_clears_stale_data_and_tolerates_malformed_fields():
    engine, _ = _workflow([], lambda tool, target: None)
    first = Finding(
        "First result",
        "vuln",
        target="127.0.0.1",
        source_tool="scanner-a",
        metadata={"cve": "CVE-2024-12345"},
    )
    second = Finding(
        {"malformed": "title"},
        "vuln",
        target="127.0.0.1",
        source_tool={"malformed": "source"},
        metadata={
            "cve": "CVE-2024-12345",
            "port": [],
            "protocol": [],
        },
    )
    session = Session(
        "127.0.0.1",
        "full",
        results=[
            _tool_result("scanner-a", "vuln", "127.0.0.1", findings=[first]),
            _tool_result("scanner-b", "vuln", "127.0.0.1", findings=[second]),
        ],
    )

    engine._correlate_session_findings(session)
    first_correlation = dict(first.metadata["correlation"])
    engine._correlate_session_findings(session)
    assert first.metadata["correlation"] == first_correlation
    assert len([note for note in session.notes if note.startswith("Finding correlation:")]) == 1

    second.metadata["cve"] = "CVE-2025-54321"
    engine._correlate_session_findings(session)
    assert "correlation" not in first.metadata
    assert "correlation" not in second.metadata
    assert len([note for note in session.notes if note.startswith("Finding correlation:")]) == 1


def test_synthetic_workflow_assessment_exports_json_markdown_and_html(tmp_path):
    finding = Finding(
        "Synthetic local observation",
        "observation",
        target="127.0.0.1",
        source_tool="nmap",
        evidence="Synthetic scanner evidence",
        metadata={"port": 80, "protocol": "tcp"},
    )
    engine, _ = _workflow(
        [_tool("nmap", "recon")],
        lambda tool, target: _tool_result(
            tool["name"], tool["category"], target, findings=[finding]
        ),
    )
    session = engine.run(Session("127.0.0.1", "standard", session_id="synthetic-e2e"))
    reporter = Reporter(tmp_path)

    json_path = reporter.write_json(session)
    markdown_path = reporter.write_markdown(session)
    html_path = reporter.write_html(session)
    pdf_path = reporter.write_pdf(session)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = markdown_path.read_text(encoding="utf-8")
    html = html_path.read_text(encoding="utf-8")

    assert all(path.exists() and path.parent == tmp_path.resolve() for path in (json_path, markdown_path, html_path, pdf_path))
    assert pdf_path.read_bytes().startswith(b"%PDF-1.4")
    assert payload["results"][0]["status"] == "success"
    assert payload["results"][0]["findings"][0]["score"] == 0.0
    assert payload["report_summary"]["raw_finding_count"] == 1
    assert "Synthetic local observation" in markdown
    assert "Synthetic local observation" in html
    assert "Synthetic scanner evidence" in markdown
    assert "Synthetic scanner evidence" in html
    assert b"Synthetic local observation" in pdf_path.read_bytes()


def test_markdown_escaping_handles_code_runs_links_html_newlines_and_unicode(tmp_path):
    tick = chr(96)
    code_value = tick + "one" + tick * 2 + "<script>alert(1)</script>" + tick
    plain_value = "bold *value* [link](https://lab.test)\n# heading α <script>alert(2)</script>"
    wrapped = Reporter._code(code_value)
    runs = re.findall(re.escape(tick) + r"+", wrapped)

    assert len(runs) == 5
    assert runs[0] == runs[-1]
    assert len(runs[0]) > max(len(run) for run in runs[1:-1])
    escaped = Reporter._markdown(plain_value)
    assert "<script>" not in escaped
    assert "&lt;script&gt;" in escaped
    assert chr(92) + "*value" + chr(92) + "*" in escaped
    assert chr(92) + "[link" + chr(92) + "]" in escaped
    assert chr(10) not in escaped
    assert "α" in escaped

    finding = Finding(
        plain_value,
        "web",
        scanner_severity="MEDIUM",
        target="127.0.0.1",
        metadata={"verification_status": code_value},
    )
    original_title = finding.title
    session = Session(
        target="127.0.0.1",
        profile="full",
        results=[_tool_result("scanner", "web", "127.0.0.1", findings=[finding])],
        notes=[plain_value],
    )
    markdown = Reporter(tmp_path).write_markdown(session).read_text(encoding="utf-8")
    status_line = next(line for line in markdown.splitlines() if "Verification status " in line)

    assert "&lt;script&gt;" in markdown
    assert "α" in markdown
    assert f"{tick * 3} {code_value} {tick * 3}" in status_line
    assert finding.title == original_title
    assert finding.metadata["verification_status"] == code_value


def test_grouped_reports_show_each_detection_and_allowlisted_metadata(tmp_path):
    first_metadata = {
        "cve": "CVE-2024-12345",
        "template_id": "template-a",
        "url": "https://user:secret@127.0.0.1/a?token=secret",
        "port": 443,
        "protocol": "tcp",
        "verification_status": "not_verified",
        "internal_secret": "do-not-render",
    }
    second_metadata = {
        "cve_id": "CVE-2024-12345",
        "template_id": "template-b",
        "matched_at": "https://127.0.0.1/b?token=other",
        "status_code": 403,
        "verification_status": "confirmed_by_manual_review",
        "internal_secret": "also-do-not-render",
    }
    first = Finding(
        "CVE-2024-12345 on endpoint A",
        "vuln",
        scanner_severity="HIGH",
        source_tool="scanner-a",
        target="127.0.0.1",
        recommendation="Patch component A",
        evidence="Evidence from A",
        metadata=first_metadata,
    )
    second = Finding(
        "CVE-2024-12345 on endpoint B",
        "vuln",
        scanner_severity="MEDIUM",
        source_tool="scanner-b",
        target="127.0.0.1",
        recommendation="Upgrade component B",
        evidence="Evidence from B",
        metadata=second_metadata,
    )
    first_before = dict(first.metadata)
    second_before = dict(second.metadata)
    session = Session(
        target="127.0.0.1",
        profile="full",
        results=[
            _tool_result("scanner-a", "vuln", "127.0.0.1", findings=[first]),
            _tool_result("scanner-b", "vuln", "127.0.0.1", findings=[second]),
        ],
    )
    reporter = Reporter(tmp_path)
    json_path = reporter.write_json(session)
    markdown = reporter.write_markdown(session).read_text(encoding="utf-8")
    html = reporter.write_html(session).read_text(encoding="utf-8")
    payload = json.loads(json_path.read_text(encoding="utf-8"))

    for content in (markdown, html):
        for value in (
            "template-a", "template-b", "HIGH", "MEDIUM",
            "Patch component A", "Upgrade component B",
            "not_verified", "confirmed_by_manual_review",
            "Evidence from A", "Evidence from B",
        ):
            assert value in content
        assert "do-not-render" not in content
        assert "also-do-not-render" not in content
        assert "secret" not in content
    assert "127.0.0.1/a" in markdown and "127.0.0.1/b" in markdown
    assert payload["report_summary"]["raw_finding_count"] == 2
    assert payload["report_summary"]["distinct_report_entry_count"] == 1
    assert payload["results"][0]["findings"][0]["metadata"]["url"] == first_metadata["url"]
    assert first.metadata == first_before
    assert second.metadata == second_before


def _direct_scan_app(tmp_path, result, normalizer, risk):
    from main import App

    app = App.__new__(App)
    app.scope = TargetScope(True, ["127.0.0.1"])
    app.target = "127.0.0.1"
    app.registry = SimpleNamespace(get=lambda name: {
        "name": name,
        "category": "recon",
        "executable": "scanner",
        "enabled": True,
    })
    app.adapter_manager = SimpleNamespace(run=lambda *args, **kwargs: result)
    app.executor = object()
    app.normalizer = normalizer
    app.risk = risk
    app.logger = _Logger()
    app.workflow = SimpleNamespace(_correlate_session_findings=lambda session: None)
    app.reporter = Reporter(tmp_path)
    app.last_session = None
    persisted = []
    app.persist_session = persisted.append
    return app, persisted


def test_direct_cli_scan_retains_result_after_normalization_failure(tmp_path, capsys):
    result = _tool_result(
        "scanner", "recon", "127.0.0.1",
        stdout="captured raw output", stderr="scanner diagnostic",
    )

    class BrokenNormalizer:
        def parse(self, result):
            raise ValueError("parser failed")

    app, persisted = _direct_scan_app(tmp_path, result, BrokenNormalizer(), RiskEngine())
    app.run_tool("scanner")

    assert app.last_session.results == [result]
    assert persisted == [app.last_session]
    assert result.status == "parse_error"
    assert result.stdout == "captured raw output"
    assert "scanner diagnostic" in result.stderr
    assert "parser failed" in result.stderr
    app.reports("json")
    report = json.loads(next(tmp_path.glob("session_*.json")).read_text(encoding="utf-8"))
    assert report["results"][0]["stdout"] == "captured raw output"
    assert report["results"][0]["status"] == "parse_error"
    assert "Status: parse_error" in capsys.readouterr().out


def test_direct_cli_scan_retains_result_after_scoring_failure(tmp_path, capsys):
    finding = Finding("captured finding", "vuln", source_tool="scanner")
    result = _tool_result(
        "scanner", "recon", "127.0.0.1",
        stdout="captured raw output", findings=[finding],
    )

    class PassNormalizer:
        def parse(self, result):
            return result

    class BrokenScorer:
        def score_all(self, findings):
            raise ValueError("scorer failed")

    app, persisted = _direct_scan_app(tmp_path, result, PassNormalizer(), BrokenScorer())
    app.run_tool("scanner")

    assert persisted == [app.last_session]
    assert result.status == "scoring_error"
    assert result.stdout == "captured raw output"
    assert result.findings == [finding]
    assert "scorer failed" in result.stderr
    app.reports("json")
    report = json.loads(next(tmp_path.glob("session_*.json")).read_text(encoding="utf-8"))
    assert report["results"][0]["status"] == "scoring_error"
    assert report["results"][0]["findings"][0]["title"] == "captured finding"
    assert "Status: scoring_error" in capsys.readouterr().out


def test_direct_cli_exports_specialized_adapter_parser_failure(tmp_path, capsys, monkeypatch):
    from main import App

    module = importlib.import_module("modules.nuclei.adapter")
    adapter = NucleiAdapter()
    adapter.executable = "/test/nuclei"
    adapter.parser.parse = Mock(side_effect=ValueError("unexpected Nuclei schema"))
    monkeypatch.setattr(
        module,
        "run_process",
        Mock(return_value=_outcome(
            '{"scanner":"raw"}\n', "scanner warning", 0, "success"
        )),
    )
    app, persisted = _direct_scan_app(
        tmp_path,
        _tool_result("nuclei", "vuln", "127.0.0.1"),
        Normalizer(),
        RiskEngine(),
    )
    app.adapter_manager = SimpleNamespace(
        run=lambda tool, target, executor, extra_args=None: adapter.scan(target, extra_args)
    )

    app.run_tool("scanner")
    app.reports("json")
    report = json.loads(next(tmp_path.glob("session_*.json")).read_text(encoding="utf-8"))

    assert len(persisted) == 1
    assert report["results"][0]["status"] == "parse_error"
    assert report["results"][0]["stdout"] == '{"scanner":"raw"}\n'
    assert "scanner warning" in report["results"][0]["stderr"]
    assert "unexpected Nuclei schema" in report["results"][0]["stderr"]
    assert "Status: parse_error" in capsys.readouterr().out
