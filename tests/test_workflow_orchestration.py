import json

import pytest

from analysis.normalizer import Normalizer
from analysis.scoring import RiskEngine
from core.models import Finding, Service, Session, ToolResult
from core.scope import TargetScope, TargetScopeError
from core.workflow import WorkflowEngine


class Registry:
    def __init__(self, tools):
        self.tools = tools

    def list(self):
        return self.tools


class Logger:
    def __init__(self):
        self.messages = []

    def info(self, message, *args):
        self.messages.append(message % args if args else message)

    def warning(self, message, *args):
        self.messages.append(message % args if args else message)

    def exception(self, message, *args):
        self.messages.append(message % args if args else message)


class DirectAdapters:
    def run(self, tool, target, fallback_executor, extra_args=None):
        return fallback_executor.run(tool, target)


class RecordingExecutor:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def run(self, tool, target):
        self.calls.append((tool["name"], target))
        return self.handler(tool, target)


def make_tool(name, category, enabled=True):
    return {
        "name": name,
        "category": category,
        "executable": name,
        "args": [],
        "enabled": enabled,
    }


def make_result(tool, category, target, **kwargs):
    status = kwargs.pop("status", "success")
    return ToolResult(
        tool=tool,
        category=category,
        target=target,
        started_at="",
        finished_at="",
        return_code=0 if status == "success" else 1,
        status=status,
        **kwargs,
    )


def httpx_output(url):
    return json.dumps({
        "url": url,
        "status_code": 200,
        "title": "Local endpoint",
        "webserver": "Apache",
        "tech": ["Apache"],
    })


def make_engine(tools, handler, scope):
    logger = Logger()
    executor = RecordingExecutor(handler)
    engine = WorkflowEngine(
        registry=Registry(tools),
        executor=executor,
        adapter_manager=DirectAdapters(),
        normalizer=Normalizer(),
        risk_engine=RiskEngine(),
        logger=logger,
        max_workers=2,
        scope=scope,
    )
    return engine, executor, logger


def test_httpx_endpoint_drives_standard_web_assessment_without_nmap():
    def handle(tool, target):
        if tool["name"] == "httpx":
            return make_result("httpx", "recon", target, stdout=httpx_output("http://127.0.0.1:8080/login"))
        return make_result(tool["name"], tool["category"], target)

    engine, executor, _ = make_engine(
        [make_tool("httpx", "recon"), make_tool("whatweb", "web")],
        handle,
        TargetScope(True, ["127.0.0.1"]),
    )
    session = engine.run(Session(target="127.0.0.1", profile="standard"))

    assert ("whatweb", "http://127.0.0.1:8080") in executor.calls
    web_result = next(result for result in session.results if result.tool == "whatweb")
    assert web_result.endpoints[0].source_tool == "httpx"
    assert web_result.endpoints[0].metadata["discovered_path"] == "/login"
    httpx_finding = next(result for result in session.results if result.tool == "httpx").findings[0]
    assert httpx_finding.score == 0
    assert httpx_finding.severity == "info"


def test_nmap_and_httpx_equivalent_urls_run_each_web_tool_once():
    def handle(tool, target):
        if tool["name"] == "httpx":
            return make_result("httpx", "recon", target, stdout=httpx_output("HTTP://127.0.0.1:80/login"))
        if tool["name"] == "nmap":
            return make_result(
                "nmap", "recon", target,
                services=[Service(80, "tcp", "open", "http", "")],
            )
        return make_result(tool["name"], tool["category"], target)

    engine, executor, _ = make_engine(
        [make_tool("nmap", "recon"), make_tool("httpx", "recon"), make_tool("whatweb", "web")],
        handle,
        TargetScope(True, ["127.0.0.1"]),
    )
    engine.run(Session(target="127.0.0.1", profile="standard"))

    assert executor.calls.count(("whatweb", "http://127.0.0.1")) == 1


@pytest.mark.parametrize(
    ("profile", "expected_web", "expected_vuln"),
    [
        ("stealth", False, False),
        ("standard", True, False),
        ("aggressive", True, True),
    ],
)
def test_profile_aliases_and_tool_enable_settings_control_downstream(
    profile, expected_web, expected_vuln
):
    def handle(tool, target):
        if tool["name"] == "httpx":
            return make_result("httpx", "recon", target, stdout=httpx_output("http://127.0.0.1"))
        return make_result(tool["name"], tool["category"], target)

    tools = [
        make_tool("httpx", "recon"),
        make_tool("whatweb", "web"),
        make_tool("nikto", "web", enabled=False),
        make_tool("nuclei", "vuln"),
    ]
    engine, executor, _ = make_engine(tools, handle, TargetScope(True, ["127.0.0.1"]))
    engine.run(Session(target="127.0.0.1", profile=profile))
    called = {name for name, _ in executor.calls}

    assert ("whatweb" in called) is expected_web
    assert ("nuclei" in called) is expected_vuln
    assert "nikto" not in called


def test_authorized_subfinder_host_can_be_http_probed_and_assessed():
    def handle(tool, target):
        if tool["name"] == "subfinder":
            finding = Finding(
                title="Subdomain discovered", category="observation", source_tool="subfinder",
                target=target, metadata={"hostname": "api.lab.test"},
            )
            return make_result("subfinder", "recon", target, findings=[finding])
        if tool["name"] == "httpx" and target == "api.lab.test":
            return make_result("httpx", "recon", target, stdout=httpx_output("https://api.lab.test:8443/login"))
        if tool["name"] == "httpx":
            return make_result("httpx", "recon", target)
        return make_result(tool["name"], tool["category"], target)

    tools = [
        make_tool("subfinder", "recon"),
        make_tool("httpx", "recon"),
        make_tool("whatweb", "web"),
    ]
    engine, executor, _ = make_engine(
        tools,
        handle,
        TargetScope(True, ["lab.test", "*.lab.test"]),
    )
    session = engine.run(Session(target="lab.test", profile="standard"))

    assert ("httpx", "api.lab.test") in executor.calls
    assert ("whatweb", "https://api.lab.test:8443") in executor.calls
    assert not any("Scope denied" in note for note in session.notes)


def test_out_of_scope_subfinder_host_is_skipped_with_visible_reason():
    def handle(tool, target):
        if tool["name"] == "subfinder":
            finding = Finding(
                title="Subdomain discovered", category="observation", source_tool="subfinder",
                target=target, metadata={"hostname": "outside.test"},
            )
            return make_result("subfinder", "recon", target, findings=[finding])
        return make_result(tool["name"], tool["category"], target)

    engine, executor, logger = make_engine(
        [make_tool("subfinder", "recon"), make_tool("httpx", "recon")],
        handle,
        TargetScope(True, ["lab.test"]),
    )
    session = engine.run(Session(target="lab.test", profile="standard"))

    assert ("httpx", "outside.test") not in executor.calls
    assert any("Scope denied" in note and "outside.test" in note for note in session.notes)
    assert any("outside.test" in message for message in logger.messages)


def test_out_of_scope_httpx_url_cannot_trigger_web_assessment():
    def handle(tool, target):
        if tool["name"] == "httpx":
            return make_result("httpx", "recon", target, stdout=httpx_output("http://outside.test/login"))
        return make_result(tool["name"], tool["category"], target)

    engine, executor, _ = make_engine(
        [make_tool("httpx", "recon"), make_tool("whatweb", "web")],
        handle,
        TargetScope(True, ["127.0.0.1"]),
    )
    session = engine.run(Session(target="127.0.0.1", profile="standard"))

    assert not any(name == "whatweb" for name, _ in executor.calls)
    assert any("outside.test" in note and "Scope denied" in note for note in session.notes)


def test_workflow_without_scope_does_not_authorize_a_discovered_host():
    def handle(tool, target):
        if tool["name"] == "httpx":
            return make_result("httpx", "recon", target, stdout=httpx_output("http://outside.test"))
        return make_result(tool["name"], tool["category"], target)

    engine, executor, _ = make_engine(
        [make_tool("httpx", "recon"), make_tool("whatweb", "web")],
        handle,
        None,
    )
    session = engine.run(Session(target="127.0.0.1", profile="standard"))

    assert not any(name == "whatweb" for name, _ in executor.calls)
    assert any("No scope validator is configured" in note for note in session.notes)


def test_endpoint_scope_is_rechecked_immediately_before_execution():
    class RevocableScope:
        def __init__(self):
            self.calls = 0

        def validate(self, target):
            self.calls += 1
            if self.calls >= 3:
                raise TargetScopeError("scope changed before tool execution")
            return TargetScope(True, ["127.0.0.1"]).validate(target)

    def handle(tool, target):
        if tool["name"] == "httpx":
            return make_result("httpx", "recon", target, stdout=httpx_output("http://127.0.0.1"))
        return make_result(tool["name"], tool["category"], target)

    engine, executor, _ = make_engine(
        [make_tool("httpx", "recon"), make_tool("whatweb", "web")],
        handle,
        RevocableScope(),
    )
    session = engine.run(Session(target="127.0.0.1", profile="standard"))

    assert not any(name == "whatweb" for name, _ in executor.calls)
    assert any("scope changed before tool execution" in note for note in session.notes)


@pytest.mark.parametrize("mode", ["no_endpoint", "invalid_scheme", "failed_with_stale_finding", "tool_exception"])
def test_missing_failed_or_unusable_discovery_does_not_run_downstream(mode):
    def handle(tool, target):
        if tool["name"] == "httpx":
            if mode == "tool_exception":
                return make_result("httpx", "recon", target, status="missing")
            if mode == "no_endpoint":
                return make_result("httpx", "recon", target)
            if mode == "invalid_scheme":
                return make_result("httpx", "recon", target, stdout=httpx_output("file:///etc/passwd"))
            stale = Finding(
                title="stale", category="observation", source_tool="httpx", target=target,
                metadata={"url": "http://127.0.0.1"},
            )
            return make_result("httpx", "recon", target, status="failed", findings=[stale])
        if tool["name"] == "nmap" and mode == "tool_exception":
            raise RuntimeError("simulated optional adapter failure")
        if tool["name"] == "nmap":
            return make_result(
                "nmap", "recon", target, status="failed",
                services=[Service(80, "tcp", "open", "http", "")],
            )
        return make_result(tool["name"], tool["category"], target)

    tools = [make_tool("httpx", "recon"), make_tool("nmap", "recon"), make_tool("whatweb", "web")]
    engine, executor, _ = make_engine(tools, handle, TargetScope(True, ["127.0.0.1"]))
    session = engine.run(Session(target="127.0.0.1", profile="standard"))

    assert not any(name == "whatweb" for name, _ in executor.calls)
    if mode == "tool_exception":
        assert {result.status for result in session.results} == {"missing", "error"}


def test_parser_failure_preserves_raw_output_and_peer_results():
    def handle(tool, target):
        if tool["name"] == "nmap":
            return make_result(
                "nmap", "recon", target, stdout="raw nmap output survives",
            )
        return make_result("httpx", "recon", target, stdout=httpx_output("http://127.0.0.1"))

    engine, _, _ = make_engine(
        [make_tool("nmap", "recon"), make_tool("httpx", "recon")],
        handle,
        TargetScope(True, ["127.0.0.1"]),
    )

    class SelectiveParserFailure:
        def parse(self, result):
            if result.tool == "nmap":
                raise ValueError("simulated parser failure")
            return Normalizer().parse(result)

    engine.normalizer = SelectiveParserFailure()
    session = engine.run(Session(target="127.0.0.1", profile="standard"))

    nmap_result = next(result for result in session.results if result.tool == "nmap")
    httpx_result = next(result for result in session.results if result.tool == "httpx")
    assert nmap_result.status == "parse_error"
    assert nmap_result.stdout == "raw nmap output survives"
    assert "simulated parser failure" in nmap_result.stderr
    assert len(httpx_result.findings) == 1
    assert httpx_result.findings[0].category == "observation"
