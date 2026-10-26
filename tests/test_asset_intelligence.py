import copy
import json

from analysis.asset_intelligence import AssetIntelligenceBuilder
from analysis.correlation import CorrelationEngine
from analysis.normalizer import Normalizer
from analysis.scoring import RiskEngine
from core.models import Finding, Service, Session, ToolResult
from core.scope import TargetScope
from core.storage import SQLiteSessionStore, session_from_dict
from core.workflow import WorkflowEngine
from reporting.reporter import Reporter


def tool_result(tool, target, stdout="", services=None, findings=None):
    return ToolResult(
        tool=tool,
        category="recon",
        target=target,
        started_at="2026-10-25T10:00:00+00:00",
        finished_at="2026-10-25T10:00:02+00:00",
        return_code=0,
        status="success",
        stdout=stdout,
        services=list(services or []),
        findings=list(findings or []),
    )


def make_session():
    normalizer = Normalizer()
    subfinder = normalizer.parse(tool_result(
        "subfinder", "example.test", "api.example.test\n",
    ))
    dnsx = normalizer.parse(tool_result(
        "dnsx", "example.test", "api.example.test [A] 127.0.0.1\n",
    ))
    httpx = normalizer.parse(tool_result(
        "httpx", "example.test",
        json.dumps({
            "url": "https://api.example.test/login?token=secret#frag",
            "status_code": 200,
            "webserver": "nginx",
            "tech": ["nginx", "<script>alert(1)</script>"],
        }),
    ))
    nmap = normalizer.parse(tool_result(
        "nmap", "127.0.0.1",
        services=[Service(443, "tcp", "open", "https", "Apache 2.4")],
    ))
    gobuster = normalizer.parse(tool_result(
        "gobuster", "https://api.example.test",
        "admin (Status: 403) [Size: 20]\n",
    ))
    nuclei = tool_result(
        "nuclei", "https://api.example.test/login",
        findings=[
            Finding(
                title="Example vulnerability",
                category="vulnerability",
                target="https://api.example.test/login",
                source_tool="nuclei",
                evidence="matched response at https://api.example.test/login?secret=x",
                confidence=0.7,
                metadata={
                    "template_id": "example-template",
                    "matched_at": "https://api.example.test/login?token=raw#fragment",
                    "verification_status": "scanner_match_unverified",
                },
            )
        ],
    )
    session = Session(
        target="example.test",
        profile="standard",
        started_at="2026-10-25T10:00:00+00:00",
        session_id="asset-graph",
        results=[subfinder, dnsx, httpx, nmap, gobuster, nuclei],
    )
    nuclei.findings[0].score = 42.0
    nuclei.findings[0].severity = "medium"
    return session


def asset_by_key(graph, kind, key):
    return next(
        asset for asset in graph["assets"]
        if asset["type"] == kind and asset["canonical_key"] == key
    )


def relation_types(graph):
    return {
        (edge["relationship"], edge["source_id"], edge["target_id"])
        for edge in graph["relationships"]
    }


def test_asset_graph_models_discovery_dns_services_endpoints_and_findings():
    session = make_session()
    original = json.dumps(session.as_dict(), sort_keys=True, default=str)
    graph = AssetIntelligenceBuilder().build(session)

    root = asset_by_key(graph, "domain", "example.test")
    subdomain = asset_by_key(graph, "domain", "api.example.test")
    address = asset_by_key(graph, "ip", "127.0.0.1")
    service = asset_by_key(graph, "service", "127.0.0.1|tcp|443")
    endpoint = asset_by_key(graph, "endpoint", "https://api.example.test/login")
    technology = asset_by_key(graph, "technology", "nginx")

    assert graph["root_asset_id"] == root["asset_id"]
    assert graph["summary"]["asset_count"] == len(graph["assets"])
    assert graph["summary"]["findings_with_assets"] == graph["summary"]["finding_count"]
    relations = relation_types(graph)
    assert ("discovers", root["asset_id"], subdomain["asset_id"]) in relations
    assert ("resolves_to", subdomain["asset_id"], address["asset_id"]) in relations
    assert ("exposes", address["asset_id"], service["asset_id"]) in relations
    assert ("serves", subdomain["asset_id"], endpoint["asset_id"]) in relations
    assert ("uses_technology", endpoint["asset_id"], technology["asset_id"]) in relations
    assert any(item[0] == "has_finding" for item in relations)
    assert endpoint["canonical_key"] == "https://api.example.test/login"
    assert "secret" not in endpoint["canonical_key"]
    assert endpoint["provenance"][0]["source_tool"] == "httpx"
    assert endpoint["provenance"][0]["observed_at"] == "2026-10-25T10:00:02+00:00"
    finding = next(item for item in graph["findings"] if item["source_tool"] == "nuclei")
    assert finding["verification_status"] == "scanner_match_unverified"
    assert finding["source_tool"] == "nuclei"
    assert finding["stable_fingerprint"].startswith("fp:")
    assert finding["risk_score"] == 42.0
    assert finding["confidence"] == 0.7
    subfinder_finding = next(item for item in graph["findings"] if item["source_tool"] == "subfinder")
    assert subfinder_finding["affected_asset_ids"] == [subdomain["asset_id"]]
    assert "subdomain" in subdomain["attribute_variants"]["discovery_role"]
    gobuster_finding = next(item for item in graph["findings"] if item["source_tool"] == "gobuster")
    assert gobuster_finding["asset_link_basis"] == "path_metadata"
    assert asset_by_key(graph, "endpoint", "https://api.example.test/admin")["asset_id"] in gobuster_finding["affected_asset_ids"]
    assert json.dumps(session.as_dict(), sort_keys=True, default=str) == original


def test_asset_identity_is_stable_and_distinct_resources_are_not_merged():
    session = make_session()
    first = AssetIntelligenceBuilder().build(session)
    second = AssetIntelligenceBuilder().build(copy.deepcopy(session))
    ids = {(x["type"], x["canonical_key"]): x["asset_id"] for x in first["assets"]}
    assert ids == {
        (x["type"], x["canonical_key"]): x["asset_id"]
        for x in second["assets"]
    }
    login = asset_by_key(first, "endpoint", "https://api.example.test/login")
    admin = asset_by_key(first, "endpoint", "https://api.example.test/admin")
    assert login["asset_id"] != admin["asset_id"]
    assert not any("token=" in item["canonical_key"] or "#frag" in item["canonical_key"]
                   for item in first["assets"])


def test_dns_parser_ignores_malformed_records_and_keeps_valid_resolution():
    session = Session(
        target="example.test",
        profile="passive",
        results=[tool_result(
            "dnsx", "example.test",
            '{"host":"api.example.test","a":["192.0.2.4"],"aaaa":["not-an-ip"]}\n'
            'api.example.test [A] 999.999.999.999\n'
            'api.example.test [CNAME] edge.example.test\n',
        )],
    )
    graph = AssetIntelligenceBuilder().build(session)
    assert ("resolves_to",
            asset_by_key(graph, "domain", "api.example.test")["asset_id"],
            asset_by_key(graph, "ip", "192.0.2.4")["asset_id"]) in relation_types(graph)
    assert asset_by_key(graph, "domain", "edge.example.test")
    assert not any("999.999" in asset["canonical_key"] for asset in graph["assets"])


def test_workflow_persists_asset_graph_on_session_completion():
    session = make_session()

    class Logger:
        def info(self, *args):
            pass

    engine = object.__new__(WorkflowEngine)
    engine.correlation_engine = CorrelationEngine()
    engine.logger = Logger()
    engine._correlate_session_findings(session)

    assert session.asset_intelligence["summary"]["asset_count"] > 0
    assert session.asset_intelligence["summary"]["finding_count"] == 6


def test_asset_graph_round_trips_and_old_payloads_restore(tmp_path):
    session = make_session()
    session.asset_intelligence = AssetIntelligenceBuilder().build(session)
    store = SQLiteSessionStore(tmp_path / "sessions.sqlite3")
    store.save(session)

    restored = store.load(session.session_id)
    assert restored.asset_intelligence == session.asset_intelligence

    legacy = session.as_dict()
    legacy.pop("asset_intelligence")
    restored_legacy = session_from_dict(legacy)
    assert restored_legacy.asset_intelligence == {}


def test_all_human_reports_share_asset_summary_and_escape_untrusted_asset_names(tmp_path):
    session = make_session()
    snapshot = json.dumps(session.as_dict(), sort_keys=True, default=str)
    reporter = Reporter(tmp_path)

    json_path = reporter.write_json(session)
    md_path = reporter.write_markdown(session)
    html_path = reporter.write_html(session)
    pdf_path = reporter.write_pdf(session)

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    graph = payload["asset_intelligence"]
    summary = graph["summary"]
    markdown = md_path.read_text(encoding="utf-8")
    html = html_path.read_text(encoding="utf-8")
    pdf_lines = reporter._pdf_report_lines(session)

    assert payload["report_summary"]["attack_surface"] == summary
    assert f"Assets: {summary['asset_count']}; relationships: {summary['relationship_count']}" in markdown
    assert f"Assets: {summary['asset_count']}; relationships: {summary['relationship_count']}" in html
    assert any(f"Assets: {summary['asset_count']}; relationships: {summary['relationship_count']}" in line
               for line in pdf_lines)
    assert "api.example.test" in markdown and "api.example.test" in html
    assert "Apache 2.4" in markdown and "Apache 2.4" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert "token=secret" not in markdown and "token=secret" not in html
    assert "token=raw" not in markdown and "token=raw" not in html
    assert pdf_path.exists() and pdf_path.stat().st_size > 0
    assert json.dumps(session.as_dict(), sort_keys=True, default=str) == snapshot


def test_graph_builder_does_not_merge_different_assets_or_invent_verified_state():
    first = Finding(
        title="Different issue A", category="vulnerability",
        target="api.example.test", source_tool="scanner-a",
        metadata={"verification_status": "scanner_match_unverified"},
    )
    second = Finding(
        title="Different issue B", category="vulnerability",
        target="api.example.test", source_tool="scanner-b",
        metadata={"verification_status": "inconclusive"},
    )
    session = Session(
        target="example.test", profile="standard",
        results=[
            tool_result("scanner-a", "api.example.test", findings=[first]),
            tool_result("scanner-b", "api.example.test", findings=[second]),
        ],
    )
    graph = AssetIntelligenceBuilder().build(session)

    assert graph["summary"]["finding_count"] == 2
    assert {x["verification_status"] for x in graph["findings"]} == {
        "scanner_match_unverified", "inconclusive",
    }
    assert len({x["finding_id"] for x in graph["findings"]}) == 2


def test_asset_link_fallback_is_context_not_an_asserted_affected_asset():
    finding = Finding(
        title="Target-wide observation", category="observation",
        source_tool="scanner", target="",
    )
    session = Session(
        target="example.test", profile="standard",
        results=[tool_result("scanner", "", findings=[finding])],
    )
    graph = AssetIntelligenceBuilder().build(session)
    record = next(item for item in graph["findings"] if item["finding_id"] == finding.finding_id)
    assert record["affected_asset_ids"] == []
    assert record["context_asset_id"] == graph["root_asset_id"]
    assert record["asset_link_basis"] == "assessment_context"
    assert graph["summary"]["findings_with_assets"] == 0
    assert graph["summary"]["findings_without_assets"] == 1
    assert any(edge["relationship"] == "assessment_context_for" for edge in graph["relationships"])


def test_identifier_fingerprint_is_stable_across_new_session_finding_ids():
    findings = []
    for _ in range(2):
        finding = Finding(
            title="Example vulnerability", category="vulnerability",
            target="https://api.example.test/login",
            source_tool="nuclei",
            metadata={
                "template_id": "example-template",
                "matched_at": "https://api.example.test/login?session=private",
            },
        )
        session = Session(
            target="example.test", profile="standard",
            results=[tool_result("nuclei", "https://api.example.test/login", findings=[finding])],
        )
        findings.append(AssetIntelligenceBuilder().build(session)["findings"][0])
    assert findings[0]["finding_id"] != findings[1]["finding_id"]
    assert findings[0]["stable_fingerprint"] == findings[1]["stable_fingerprint"]



def test_complete_synthetic_workflow_builds_graph_without_launching_processes():
    class Registry:
        def list(self):
            return [{
                "name": "httpx", "category": "recon", "executable": "unused",
                "args": [], "enabled": True,
            }]

    class Executor:
        def run(self, tool, target, extra_args=None):
            return tool_result(
                "httpx", target,
                json.dumps({"url": "http://127.0.0.1:8080/login", "status_code": 200}),
            )

    class Adapters:
        def run(self, tool, target, fallback_executor, extra_args=None):
            return fallback_executor.run(tool, target, extra_args=extra_args)

    class Logger:
        def info(self, *args):
            pass
        def warning(self, *args):
            pass
        def exception(self, *args):
            pass

    engine = WorkflowEngine(
        registry=Registry(), executor=Executor(), adapter_manager=Adapters(),
        normalizer=Normalizer(), risk_engine=RiskEngine(), logger=Logger(),
        max_workers=1, scope=TargetScope(True, ["127.0.0.1"]),
    )
    session = engine.run(Session(target="127.0.0.1", profile="standard"))

    endpoint = asset_by_key(
        session.asset_intelligence, "endpoint", "http://127.0.0.1:8080/login",
    )
    assert session.results[0].tool == "httpx"
    assert endpoint["provenance"][0]["source_tool"] == "httpx"
    assert session.asset_intelligence["coverage"]["status_counts"] == {"success": 1}


def test_malformed_numeric_values_and_overlong_urls_do_not_corrupt_asset_identity():
    finding = Finding(
        title="Malformed score", category="vulnerability",
        source_tool="scanner", target="example.test",
        confidence=10 ** 1000, score=float("nan"),
        score_breakdown={"contribution": float("nan")},
        metadata={"url": "https://example.test/" + "x" * 3000},
    )
    graph = AssetIntelligenceBuilder().build(Session(
        target="example.test", profile="standard",
        results=[tool_result("scanner", "example.test", findings=[finding])],
    ))
    record = next(item for item in graph["findings"] if item["finding_id"] == finding.finding_id)
    assert record["risk_score"] is None
    assert record["confidence"] is None
    assert record["score_breakdown"]["contribution"] is None
    assert not any(
        asset["type"] == "endpoint" and asset["canonical_key"].startswith("https://example.test/")
        for asset in graph["assets"]
    )


def test_cve_in_scanner_title_produces_stable_cross_session_fingerprint():
    fingerprints = []
    for _ in range(2):
        finding = Finding(
            title="Detected CVE-2025-12345 remotely",
            category="vulnerability",
            target="192.0.2.10",
            source_tool="scanner",
            evidence="The response matched the signature",
        )
        graph = AssetIntelligenceBuilder().build(Session(
            target="192.0.2.10", profile="standard",
            results=[tool_result("scanner", "192.0.2.10", findings=[finding])],
        ))
        fingerprints.append(graph["findings"][0]["stable_fingerprint"])
    assert fingerprints[0].startswith("fp:")
    assert fingerprints[0] == fingerprints[1]
