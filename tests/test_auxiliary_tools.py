import json
from types import SimpleNamespace

from analysis.normalizer import Normalizer
from core.adapter_manager import AdapterManager
from core.models import ToolResult
from modules.auxiliary.adapter import AuxiliaryAdapter


def result(tool, output, target="example.test", status="success"):
    return ToolResult(tool=tool, category="recon", target=target,
                      started_at="", finished_at="", return_code=0,
                      stdout=output, status=status)


def test_subfinder_outputs_become_non_vulnerability_observations():
    parsed = Normalizer().parse(result("subfinder", "www.example.test\napi.example.test\nwww.example.test\n"))
    assert len(parsed.findings) == 2
    assert all(f.category == "observation" and f.impact == 0 for f in parsed.findings)
    assert parsed.findings[0].metadata["hostname"] == "www.example.test"


def test_httpx_jsonl_preserves_metadata():
    line = json.dumps({"url":"https://example.test", "status_code":200, "title":"Home", "webserver":"nginx", "tech":["Nginx"]})
    parsed = Normalizer().parse(result("httpx", line))
    assert len(parsed.findings) == 1
    assert parsed.findings[0].metadata["url"] == "https://example.test"
    assert parsed.findings[0].metadata["status_code"] == 200


def test_katana_jsonl_records_endpoints():
    line = json.dumps({"request":{"endpoint":"https://example.test/login"}, "url":"https://example.test/login"})
    parsed = Normalizer().parse(result("katana", line))
    assert len(parsed.findings) == 1
    assert parsed.findings[0].title == "Web endpoint discovered"


def test_gobuster_paths_are_discovery_only():
    parsed = Normalizer().parse(result("gobuster", "/admin (Status: 301) [Size: 0]"))
    assert len(parsed.findings) == 1
    assert parsed.findings[0].metadata["verification_status"] == "path_discovery_only"
    assert parsed.findings[0].impact == 0


def test_testssl_actionable_lines_are_observations():
    parsed = Normalizer().parse(result("testssl", "TLS 1.0 offered\nCertificate expires soon\nStart 2026-01-01\n"))
    assert len(parsed.findings) == 2
    assert all(f.metadata["verification_status"] == "scanner_match_unverified" for f in parsed.findings)


def test_subfinder_skips_ip_targets_without_invoking_executor():
    class Executor:
        def run(self, *args):
            raise AssertionError("should not execute subfinder for an IP")
    tool = {"name":"subfinder", "category":"recon", "executable":"subfinder", "args":["-d", "{target}"]}
    skipped = AuxiliaryAdapter().scan(tool, "127.0.0.1", Executor())
    assert skipped.status == "skipped"
    assert "requires a domain" in skipped.stderr


def test_config_contains_auxiliary_integrations():
    from core.tool_registry import ToolRegistry
    registry = ToolRegistry("config/tools.json")
    names = {tool["name"] for tool in registry.list()}
    assert {"subfinder", "dnsx", "httpx", "katana", "testssl", "gobuster"} <= names


def test_subfinder_receives_hostname_not_url():
    class Executor:
        def __init__(self):
            self.target = None
            self.tool = None
        def run(self, tool, target):
            self.tool = tool
            self.target = target
            return ToolResult(tool="subfinder", category="recon", target=target, started_at="", finished_at="", return_code=0, stdout="api.example.test\n", status="success")
    executor = Executor()
    tool = {"name":"subfinder", "category":"recon", "executable":"subfinder", "args":["-d", "{target}", "-silent"]}
    AuxiliaryAdapter().scan(tool, "https://example.test:443/path", executor)
    assert executor.target == "example.test"
    assert executor.tool["args"] == ["-d", "example.test", "-silent"]


# Adaptive integration regressions: configuration alone is not sufficient;
# selected tools must be handed the discovered endpoint in the workflow.
def test_http_decision_recommends_existing_web_and_vulnerability_scanners():
    from analysis.decision_engine import DecisionEngine
    from core.models import Service, ToolResult

    discovery = ToolResult(
        tool="nmap", category="recon", target="127.0.0.1",
        started_at="", finished_at="", return_code=0,
        services=[Service(port=443, protocol="tcp", state="open", service="https", version="")],
    )
    decisions = DecisionEngine().decide([discovery])
    assert len(decisions) == 1
    assert {"whatweb", "nikto", "nuclei", "katana", "testssl", "gobuster"} <= set(decisions[0]["recommended_tools"])


def test_adapter_manager_routes_all_auxiliary_tools_through_shared_adapter():
    manager = AdapterManager()
    for name in ("subfinder", "dnsx", "httpx", "katana", "testssl", "gobuster"):
        assert isinstance(manager.get(name), AuxiliaryAdapter)


def test_dnsx_skips_ip_targets():
    class Executor:
        def run(self, *args):
            raise AssertionError("dnsx domain enumeration must not run against an IP")
    tool = {"name":"dnsx", "category":"recon", "executable":"dnsx", "args":["-d", "{target}"]}
    skipped = AuxiliaryAdapter().scan(tool, "127.0.0.1", Executor())
    assert skipped.status == "skipped"
    assert "requires a domain" in skipped.stderr


def test_full_profile_hands_web_endpoint_to_vulnerability_tools_and_limits_tls_to_https():
    from core.models import Service, Session, ToolResult
    from core.scope import TargetScope
    from core.workflow import WorkflowEngine

    tools = [
        {"name":"nmap", "category":"recon", "enabled":True},
        {"name":"whatweb", "category":"web", "enabled":True},
        {"name":"nikto", "category":"web", "enabled":True},
        {"name":"nuclei", "category":"vuln", "enabled":True},
        {"name":"katana", "category":"web", "enabled":True},
        {"name":"testssl", "category":"web", "enabled":True},
        {"name":"gobuster", "category":"web", "enabled":True},
    ]

    class Registry:
        def list(self):
            return tools

    class Executor:
        def __init__(self): self.calls = []
        def run(self, tool, target):
            self.calls.append((tool["name"], target))
            services = [
                Service(port=80, protocol="tcp", state="open", service="http", version=""),
                Service(port=443, protocol="tcp", state="open", service="https", version=""),
            ] if tool["name"] == "nmap" else []
            return ToolResult(tool=tool["name"], category=tool["category"], target=target,
                started_at="", finished_at="", return_code=0, status="success", services=services)

    class Adapters:
        def run(self, tool, target, fallback_executor, extra_args=None):
            return fallback_executor.run(tool, target)

    class Logger:
        def info(self, *args, **kwargs): pass

    class Normalizer:
        def parse(self, result): return result

    class Risk:
        def score_all(self, findings): return findings

    executor = Executor()
    engine = WorkflowEngine(Registry(), executor, Adapters(), Normalizer(), Risk(), Logger(),
                            scope=TargetScope(scope_required=True, authorized_targets=["127.0.0.1"]))
    session = engine.run(Session(target="127.0.0.1", profile="full"))
    calls = executor.calls
    assert ("nikto", "http://127.0.0.1") in calls
    assert ("nuclei", "http://127.0.0.1") in calls
    assert ("testssl", "https://127.0.0.1") in calls
    assert ("testssl", "http://127.0.0.1") not in calls
    assert any(r.tool == "nuclei" and r.target == "https://127.0.0.1" for r in session.results)


def test_discovered_subdomain_is_http_probed_only_if_scope_authorizes_it():
    from core.models import Finding, Session, ToolResult
    from core.scope import TargetScope
    from core.workflow import WorkflowEngine

    tools = [
        {"name":"nmap", "category":"recon", "enabled":True},
        {"name":"subfinder", "category":"recon", "enabled":True},
        {"name":"httpx", "category":"recon", "enabled":True},
    ]
    class Registry:
        def list(self): return tools
    class Executor:
        def __init__(self): self.calls=[]
        def run(self, tool, target):
            self.calls.append((tool["name"], target))
            findings = [Finding(title="Subdomain discovered", category="observation", source_tool="subfinder",
                target=target, metadata={"hostname":"api.example.test"})] if tool["name"] == "subfinder" else []
            return ToolResult(tool=tool["name"], category=tool["category"], target=target,
                started_at="", finished_at="", return_code=0, status="success", findings=findings)
    class Adapters:
        def run(self, tool, target, fallback_executor, extra_args=None): return fallback_executor.run(tool, target)
    class Logger:
        def info(self, *args, **kwargs): pass
    class Normalizer:
        def parse(self, result): return result
    class Risk:
        def score_all(self, findings): return findings

    executor = Executor()
    scope = TargetScope(scope_required=True, authorized_targets=["example.test", "*.example.test"])
    engine = WorkflowEngine(Registry(), executor, Adapters(), Normalizer(), Risk(), Logger(), scope=scope)
    engine.run(Session(target="example.test", profile="standard"))
    assert ("httpx", "api.example.test") in executor.calls

    executor2 = Executor()
    restricted_scope = TargetScope(scope_required=True, authorized_targets=["example.test"])
    engine2 = WorkflowEngine(Registry(), executor2, Adapters(), Normalizer(), Risk(), Logger(), scope=restricted_scope)
    engine2.run(Session(target="example.test", profile="standard"))
    assert ("httpx", "api.example.test") not in executor2.calls
