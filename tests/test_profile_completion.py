from types import SimpleNamespace

from core.adapter_manager import AdapterManager
from core.executor import ToolExecutor
from core.models import Service, ToolResult
from core.preflight import ToolPreflight
from core.workflow import WorkflowEngine
from core.scope import TargetScope
from analysis.normalizer import Normalizer
from analysis.scoring import RiskEngine


def _tool(name, category, **extra):
    return {
        "name": name,
        "category": category,
        "executable": name,
        "args": ["{target}"],
        "enabled": True,
        **extra,
    }


def _engine(tools, max_workers=8):
    return WorkflowEngine(
        registry=SimpleNamespace(list=lambda: tools),
        executor=object(),
        adapter_manager=object(),
        normalizer=object(),
        risk_engine=object(),
        logger=object(),
        max_workers=max_workers,
    )


def test_passive_and_stealth_have_distinct_selection_and_execution_limits():
    tools = [
        _tool("nmap", "recon"),
        _tool("subfinder", "recon"),
        _tool("httpx", "recon"),
        _tool("dnsx", "recon"),
        _tool("whatweb", "web"),
        _tool("nuclei", "vuln"),
    ]
    engine = _engine(tools)

    assert [x["name"] for x in engine.tools_for_profile("passive")] == ["subfinder"]
    assert {x["name"] for x in engine.tools_for_profile("stealth")} == {
        "subfinder", "httpx",
    }
    assert [x["name"] for x in engine.tools_for_profile("standard")] == [
        "nmap", "subfinder", "httpx", "dnsx", "whatweb",
    ]
    assert {x["name"] for x in engine.tools_for_profile("full")} == {
        "nmap", "subfinder", "httpx", "dnsx", "whatweb", "nuclei",
    }
    assert engine._worker_limit("stealth") == 1
    assert engine._worker_limit("aggressive") == 4


def test_profile_modes_can_narrow_custom_tool_selection():
    tools = [
        _tool("custom-recon", "recon", profile_modes=["standard"]),
        _tool("subfinder", "recon", profile_modes=["passive", "standard"]),
    ]
    engine = _engine(tools)

    assert [x["name"] for x in engine.tools_for_profile("passive")] == ["subfinder"]
    assert {x["name"] for x in engine.tools_for_profile("standard")} == {
        "custom-recon", "subfinder",
    }


def test_malformed_profile_modes_fail_closed():
    engine = _engine([
        _tool("subfinder", "recon", profile_modes="passive"),
        _tool("nmap", "recon", profile_modes=["unknown"]),
    ])
    assert engine.tools_for_profile("passive") == []
    assert engine.tools_for_profile("standard") == []


def test_aggressive_profile_uses_copy_of_configured_profile_arguments():
    original = _tool(
        "nmap", "recon", args=["-sV", "{target}"],
        profile_args={"aggressive": ["-sV", "-p1-1024", "-T4", "{target}"]},
    )
    engine = _engine([original])

    aggressive = engine.tools_for_profile("aggressive")[0]
    standard = engine.tools_for_profile("standard")[0]
    assert aggressive["args"] == ["-sV", "-p1-1024", "-T4", "{target}"]
    assert standard["args"] == ["-sV", "{target}"]
    assert original["args"] == ["-sV", "{target}"]


def test_preflight_rejects_malformed_profile_configuration():
    results = ToolPreflight().inspect([
        _tool("scanner", "recon", profile_modes=["passive", "unknown"]),
        _tool("scanner2", "recon", profile_args={"full": "--fast"}),
    ])
    assert len(results) == 2
    assert all(item["status"] == "misconfigured" for item in results)
    assert "profile_modes" in results[0]["message"]
    assert "profile_args" in results[1]["message"]


def test_adapter_manager_uses_configured_tool_and_shared_executor():
    class Executor:
        def __init__(self):
            self.calls = []

        def run(self, tool, target, **kwargs):
            self.calls.append((tool, target, kwargs))
            return ToolResult(
                tool=tool["name"], category=tool["category"], target=target,
                started_at="start", finished_at="finish", return_code=0,
                status="success", stdout="80/tcp open http Apache",
            )

    executor = Executor()
    configured = _tool(
        "nmap", "recon", executable="nmap-custom",
        args=["-p", "80", "{target}"], timeout=9,
    )
    result = AdapterManager().run(configured, "127.0.0.1", executor)

    assert executor.calls == [(configured, "127.0.0.1", {})]
    assert result.services == [Service(80, "tcp", "open", "http", "Apache")]


def test_adapter_manager_passes_nuclei_extra_args_to_shared_executor():
    class Executor:
        def __init__(self):
            self.call = None

        def run(self, tool, target, **kwargs):
            self.call = (tool, target, kwargs)
            return ToolResult(
                tool=tool["name"], category=tool["category"], target=target,
                started_at="start", finished_at="finish", return_code=0,
                status="success", stdout='{"info":{"name":"test"}}',
            )

    executor = Executor()
    tool = _tool("nuclei", "vuln", args=["-u", "{target}"])
    extra_args = ["--tags", "misconfig"]
    result = AdapterManager().run(
        tool, "127.0.0.1", executor, extra_args=extra_args,
    )

    assert executor.call == (tool, "127.0.0.1", {"extra_args": extra_args})
    assert result.status == "success"


def test_adapter_manager_supports_explicit_plugin_registration():
    from core.adapter_manager import AdapterManager

    class Plugin:
        def __init__(self):
            self.call = None

        def scan(self, tool, target, executor, extra_args=None):
            self.call = (tool, target, executor, extra_args)
            return ToolResult(
                tool=tool["name"], category=tool["category"], target=target,
                started_at="start", finished_at="finish", return_code=0,
                status="success",
            )

    manager = AdapterManager()
    plugin = Plugin()
    executor = object()
    assert manager.register("custom-scanner", plugin) is plugin
    result = manager.run(
        _tool("custom-scanner", "recon"), "127.0.0.1", executor,
        extra_args=["--safe"],
    )
    assert result.status == "success"
    assert plugin.call == (_tool("custom-scanner", "recon"), "127.0.0.1", executor, ["--safe"])


def test_stealth_workflow_does_not_run_downstream_tools():
    tools = [
        _tool("nmap", "recon"),
        _tool("subfinder", "recon"),
        _tool("httpx", "recon"),
        _tool("whatweb", "web"),
        _tool("nuclei", "vuln"),
    ]

    class Logger:
        def info(self, *args, **kwargs):
            pass

        def warning(self, *args, **kwargs):
            pass

    engine = WorkflowEngine(
        registry=SimpleNamespace(list=lambda: tools),
        executor=object(), adapter_manager=object(),
        normalizer=Normalizer(), risk_engine=RiskEngine(), logger=Logger(),
        max_workers=8, scope=TargetScope(True, ["127.0.0.1"]),
    )
    called = []

    def worker(tool, target, extra_args=None):
        called.append(tool["name"])
        return Normalizer().parse(ToolResult(
            tool=tool["name"], category=tool["category"], target=target,
            started_at="start", finished_at="finish", return_code=0,
            status="success",
            stdout=(
                '{"url":"http://127.0.0.1","status_code":200}'
                if tool["name"] == "httpx" else ""
            ),
        ))

    engine._run_tool_with_loading = worker
    from core.models import Session

    session = engine.run(Session("127.0.0.1", "stealth"))
    assert set(called) == {"subfinder", "httpx"}
    assert {result.tool for result in session.results} == {"subfinder", "httpx"}
    assert any("not invisible scanning" in note for note in session.notes)


def test_workflow_notes_profile_excluded_and_disabled_tools():
    from core.models import Session

    tools = [
        _tool("subfinder", "recon"),
        _tool("nmap", "recon"),
        _tool("nuclei", "vuln", enabled=False),
    ]
    logger = SimpleNamespace(info=lambda *args, **kwargs: None)
    engine = WorkflowEngine(
        registry=SimpleNamespace(list=lambda: tools),
        executor=object(), adapter_manager=object(), normalizer=Normalizer(),
        risk_engine=RiskEngine(), logger=logger, scope=TargetScope(True, ["127.0.0.1"]),
    )
    engine._run_tool_with_loading = lambda tool, target, extra_args=None: ToolResult(
        tool=tool["name"], category=tool["category"], target=target,
        started_at="start", finished_at="finish", return_code=0, status="success",
    )

    session = engine.run(Session("127.0.0.1", "passive"))

    assert any("nuclei" in note and "Disabled" in note for note in session.notes)
    assert any("nmap" in note and "not selected by profile" in note for note in session.notes)


def test_executor_appends_explicit_args_to_configured_argument_list(monkeypatch):
    from core.process_utils import ProcessOutcome

    calls = {}
    monkeypatch.setattr("core.executor.shutil.which", lambda _: "/usr/bin/nuclei")

    def fake_run(command, **kwargs):
        calls["command"] = command
        calls.update(kwargs)
        return ProcessOutcome(stdout="ok", status="success", return_code=0)

    monkeypatch.setattr("core.executor.run_process", fake_run)
    tool = _tool(
        "nuclei", "vuln", executable="nuclei",
        args=["-u", "{target}", "-disable-redirects"], timeout=9,
    )
    result = ToolExecutor(object()).run(
        tool, "127.0.0.1", extra_args=["--tags", "misconfig"],
    )

    assert result.status == "success"
    assert calls["command"] == [
        "nuclei", "-u", "127.0.0.1", "-disable-redirects",
        "--tags", "misconfig",
    ]
    assert calls["timeout"] == 9


def test_executor_retries_process_launch_error_and_preserves_partial_diagnostics(monkeypatch):
    from core.process_utils import ProcessOutcome

    calls = []
    monkeypatch.setattr("core.executor.shutil.which", lambda _: "/usr/bin/scanner")

    def fake_run(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            return ProcessOutcome(
                stdout="first partial", stderr="first diagnostic",
                status="error", return_code=None,
            )
        return ProcessOutcome(stdout="final output", status="success", return_code=0)

    monkeypatch.setattr("core.executor.run_process", fake_run)
    result = ToolExecutor(object()).run(
        _tool("scanner", "recon", retries=1), "127.0.0.1",
    )

    assert len(calls) == 2
    assert result.status == "success"
    assert "first partial" in result.stdout
    assert "final output" in result.stdout
    assert "first diagnostic" in result.stderr
    assert "retried 1 time(s)" in result.stderr


def test_timeout_retry_requires_explicit_configuration(monkeypatch):
    from core.process_utils import ProcessOutcome

    calls = []
    monkeypatch.setattr("core.executor.shutil.which", lambda _: "/usr/bin/scanner")

    def fake_run(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            return ProcessOutcome(
                stdout="partial",
                stderr="slow\nTool timed out after 1 seconds.",
                return_code=None,
                status="timeout",
            )
        return ProcessOutcome(stdout="complete", status="success", return_code=0)

    monkeypatch.setattr("core.executor.run_process", fake_run)
    result = ToolExecutor(object()).run(
        _tool("scanner", "recon", retries=1, retry_on_timeout=True),
        "127.0.0.1",
    )

    assert len(calls) == 2
    assert result.status == "success"
    assert "partial" in result.stdout
    assert "Tool timed out" in result.stderr



def test_cli_default_alias_resolves_configured_profile_without_scanning():
    from main import App
    from core.models import Session

    app = App.__new__(App)
    app.settings = {"default_profile": "aggressive", "allowed_profiles": ["aggressive"]}
    app.target = "127.0.0.1"
    app.last_session = None
    app._validated_target = lambda: "127.0.0.1"
    captured = []
    app.workflow = SimpleNamespace(
        PROFILES={"aggressive": []},
        run=lambda session: captured.append(session),
    )
    app.persist_session = lambda session: None
    app.run_profile("default")

    assert len(captured) == 1
    assert isinstance(captured[0], Session)
    assert captured[0].profile == "aggressive"


def test_cli_execution_summary_counts_unavailable_and_failure_statuses(capsys):
    from core.models import Session, ToolResult
    from main import App

    session = Session("127.0.0.1", "standard")
    for tool, status in (("nmap", "success"), ("whatweb", "missing"), ("nuclei", "parse_error")):
        session.results.append(ToolResult(
            tool=tool, category="recon", target=session.target,
            started_at="", finished_at="", return_code=None, status=status,
        ))

    App.print_execution_summary(session)
    output = capsys.readouterr().out
    assert "success=1" in output
    assert "unavailable=1" in output
    assert "parse_error=1" in output


def test_cli_dispatch_accepts_pdf_report_mode():
    from main import App

    app = App.__new__(App)
    selected = []
    app.reports = selected.append
    assert app.dispatch("report pdf") is True
    assert selected == ["pdf"]


def test_profile_specific_args_override_configured_args():
    """Test that profile_args override the base args for each profile."""
    from core.workflow import WorkflowEngine
    from types import SimpleNamespace

    tools = [{
        "name": "nmap", "category": "recon", "executable": "nmap",
        "args": ["-sV", "{target}"],
        "enabled": True, "profile_args": {
            "aggressive": ["-sV", "-p1-1024", "-T4", "{target}"],
        },
    }]
    engine = WorkflowEngine(
        registry=SimpleNamespace(list=lambda: tools),
        executor=object(), adapter_manager=object(),
        normalizer=object(), risk_engine=object(), logger=object(),
    )
    aggressive_tools = engine.tools_for_profile("aggressive")
    standard_tools = engine.tools_for_profile("standard")
    assert aggressive_tools[0]["args"] == ["-sV", "-p1-1024", "-T4", "{target}"]
    assert standard_tools[0]["args"] == ["-sV", "{target}"]


def test_profile_specific_timeout_applied():
    """Test that profile_timeout overrides base timeout per profile."""
    from core.workflow import WorkflowEngine
    from types import SimpleNamespace

    tools = [{
        "name": "subfinder", "category": "recon", "executable": "subfinder",
        "args": ["-d", "{target}"], "timeout": 90,
        "profile_timeout": {"passive": 60, "aggressive": 240},
        "enabled": True, "profile_modes": ["passive", "stealth", "standard", "full", "aggressive"],
    }]
    engine = WorkflowEngine(
        registry=SimpleNamespace(list=lambda: tools),
        executor=object(), adapter_manager=object(),
        normalizer=object(), risk_engine=object(), logger=object(),
    )
    passive_tool = engine.tools_for_profile("passive")[0]
    aggressive_tool = engine.tools_for_profile("aggressive")[0]
    assert passive_tool["timeout"] == 60
    assert aggressive_tool["timeout"] == 240


def test_profile_specific_retries_applied():
    """Test that profile_retries overrides base retries per profile."""
    from core.workflow import WorkflowEngine
    from types import SimpleNamespace

    tools = [{
        "name": "nmap", "category": "recon", "executable": "nmap",
        "args": ["-sV", "{target}"], "retries": 0,
        "profile_retries": {"standard": 1, "aggressive": 0},
        "enabled": True,
    }]
    engine = WorkflowEngine(
        registry=SimpleNamespace(list=lambda: tools),
        executor=object(), adapter_manager=object(),
        normalizer=object(), risk_engine=object(), logger=object(),
    )
    standard_tool = engine.tools_for_profile("standard")[0]
    aggressive_tool = engine.tools_for_profile("aggressive")[0]
    assert standard_tool["retries"] == 1
    assert aggressive_tool["retries"] == 0


def test_profile_retry_on_timeout_applied():
    """Test that profile_retry_on_timeout overrides base setting per profile."""
    from core.workflow import WorkflowEngine
    from types import SimpleNamespace

    tools = [{
        "name": "nmap", "category": "recon", "executable": "nmap",
        "args": ["-sV", "{target}"], "retry_on_timeout": False,
        "profile_retry_on_timeout": {"aggressive": True},
        "enabled": True,
    }]
    engine = WorkflowEngine(
        registry=SimpleNamespace(list=lambda: tools),
        executor=object(), adapter_manager=object(),
        normalizer=object(), risk_engine=object(), logger=object(),
    )
    standard_tool = engine.tools_for_profile("standard")[0]
    aggressive_tool = engine.tools_for_profile("aggressive")[0]
    assert standard_tool["retry_on_timeout"] is False
    assert aggressive_tool["retry_on_timeout"] is True


def test_passive_profile_excludes_active_tools():
    """Passive profile must only include passive recon tools."""
    from core.workflow import WorkflowEngine
    from types import SimpleNamespace

    tools = [
        {"name": "subfinder", "category": "recon", "executable": "subfinder", "args": ["-d", "{target}"], "enabled": True, "profile_modes": ["passive", "stealth"]},
        {"name": "httpx", "category": "recon", "executable": "httpx-toolkit", "args": ["-u", "{target}"], "enabled": True, "profile_modes": ["stealth", "standard"]},
        {"name": "nmap", "category": "recon", "executable": "nmap", "args": ["-sV", "{target}"], "enabled": True},
        {"name": "nuclei", "category": "vuln", "executable": "nuclei", "args": ["-u", "{target}"], "enabled": True},
    ]
    engine = WorkflowEngine(
        registry=SimpleNamespace(list=lambda: tools),
        executor=object(), adapter_manager=object(),
        normalizer=object(), risk_engine=object(), logger=object(),
    )
    passive_tools = engine.tools_for_profile("passive")
    assert [t["name"] for t in passive_tools] == ["subfinder"]


def test_stealth_profile_is_not_passive():
    """Stealth profile uses active but limited probing."""
    from core.workflow import WorkflowEngine
    from types import SimpleNamespace

    tools = [
        {"name": "subfinder", "category": "recon", "executable": "subfinder", "args": ["-d", "{target}"], "enabled": True, "profile_modes": ["passive", "stealth"]},
        {"name": "httpx", "category": "recon", "executable": "httpx-toolkit", "args": ["-u", "{target}"], "enabled": True, "profile_modes": ["stealth", "standard"]},
        {"name": "nmap", "category": "recon", "executable": "nmap", "args": ["-sV", "{target}"], "enabled": True},
    ]
    engine = WorkflowEngine(
        registry=SimpleNamespace(list=lambda: tools),
        executor=object(), adapter_manager=object(),
        normalizer=object(), risk_engine=object(), logger=object(),
    )
    stealth_tools = engine.tools_for_profile("stealth")
    tool_names = {t["name"] for t in stealth_tools}
    assert tool_names == {"subfinder", "httpx"}


def test_profile_args_with_non_list_raises_error():
    """Malformed profile_args should raise ValueError."""
    from core.workflow import WorkflowEngine
    from types import SimpleNamespace
    import pytest

    tools = [{
        "name": "nmap", "category": "recon", "executable": "nmap",
        "args": ["-sV", "{target}"],
        "profile_args": {"aggressive": "-sV -p1-1024 {target}"},  # string instead of list
        "enabled": True,
    }]
    engine = WorkflowEngine(
        registry=SimpleNamespace(list=lambda: tools),
        executor=object(), adapter_manager=object(),
        normalizer=object(), risk_engine=object(), logger=object(),
    )
    with pytest.raises(ValueError, match="Invalid aggressive profile_args"):
        engine.tools_for_profile("aggressive")


def test_executor_uses_profile_timeout_and_retries(monkeypatch):
    """Test that executor receives profile-specific timeout and retries."""
    from core.executor import ToolExecutor
    from core.process_utils import ProcessOutcome

    calls = {}
    monkeypatch.setattr("core.executor.shutil.which", lambda _: "/usr/bin/nmap")

    def fake_run(command, **kwargs):
        calls["command"] = command
        calls.update(kwargs)
        return ProcessOutcome(stdout="80/tcp open http Apache", status="success", return_code=0)

    monkeypatch.setattr("core.executor.run_process", fake_run)

    tool = {
        "name": "nmap", "category": "recon", "executable": "nmap",
        "args": ["-sV", "{target}"],
        "timeout": 180, "retries": 0, "retry_on_timeout": False,
    }
    result = ToolExecutor(object()).run(tool, "127.0.0.1")

    assert result.status == "success"
    assert calls["timeout"] == 180


def test_executor_uses_profile_retries_and_retry_on_timeout(monkeypatch):
    """Test that executor uses profile-specific retries and retry_on_timeout."""
    from core.executor import ToolExecutor
    from core.process_utils import ProcessOutcome

    calls = []
    monkeypatch.setattr("core.executor.shutil.which", lambda _: "/usr/bin/nmap")

    def fake_run(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            return ProcessOutcome(
                stdout="partial", stderr="first diagnostic",
                status="error", return_code=None,
            )
        return ProcessOutcome(stdout="final output", status="success", return_code=0)

    monkeypatch.setattr("core.executor.run_process", fake_run)
    tool = {
        "name": "nmap", "category": "recon", "executable": "nmap",
        "args": ["-sV", "{target}"],
        "retries": 1, "retry_on_timeout": False,
    }
    result = ToolExecutor(object()).run(tool, "127.0.0.1")

    assert len(calls) == 2
    assert result.status == "success"
    assert "-sV" in calls[0]  # -sV in first call


def test_passive_profile_no_active_scanning(monkeypatch):
    """Verify passive profile never runs Nmap or other active tools."""
    from core.workflow import WorkflowEngine
    from types import SimpleNamespace
    from analysis.normalizer import Normalizer
    from analysis.scoring import RiskEngine
    from core.logger import get_logger
    from core.models import Session

    tools = [
        {"name": "subfinder", "category": "recon", "executable": "subfinder", "args": ["-d", "{target}"], "enabled": True, "profile_modes": ["passive", "stealth"]},
        {"name": "nmap", "category": "recon", "executable": "nmap", "args": ["-sV", "{target}"], "enabled": True},
    ]
    logger = get_logger("reports")
    engine = WorkflowEngine(
        registry=SimpleNamespace(list=lambda: tools),
        executor=object(), adapter_manager=object(),
        normalizer=Normalizer(), risk_engine=RiskEngine(), logger=logger,
        scope=TargetScope(True, ["127.0.0.1"]),
    )
    engine._show_loading = lambda *args: None

    class MockAdapterManager:
        def run(self, tool, target, fallback_executor):
            from core.models import ToolResult
            from datetime import datetime, timezone
            return ToolResult(
                tool=tool["name"], category=tool["category"], target=target,
                started_at=datetime.now(timezone.utc).isoformat(),
                finished_at=datetime.now(timezone.utc).isoformat(),
                return_code=0, status="success", stdout="", stderr="", command=[],
            )

    engine.adapter_manager = MockAdapterManager()
    session = engine.run(Session("127.0.0.1", "passive"))
    tool_names = {r.tool for r in session.results}
    assert tool_names == {"subfinder"}
    assert "nmap" not in tool_names


def test_stealth_profile_does_not_run_downstream_web_tools(monkeypatch):
    """Stealth profile only runs passive discovery + single HTTPX, no downstream web tools."""
    from core.workflow import WorkflowEngine
    from types import SimpleNamespace
    from analysis.normalizer import Normalizer
    from analysis.scoring import RiskEngine
    from core.logger import get_logger
    from core.scope import TargetScope
    from core.models import Session

    tools = [
        {"name": "subfinder", "category": "recon", "executable": "subfinder", "args": ["-d", "{target}"], "enabled": True, "profile_modes": ["passive", "stealth"]},
        {"name": "httpx", "category": "recon", "executable": "httpx-toolkit", "args": ["-u", "{target}"], "enabled": True, "profile_modes": ["stealth", "standard"]},
        {"name": "whatweb", "category": "web", "executable": "whatweb", "args": ["{target}"], "enabled": True},
        {"name": "nikto", "category": "web", "executable": "nikto", "args": ["{target}"], "enabled": True},
    ]
    logger = get_logger("reports")
    engine = WorkflowEngine(
        registry=SimpleNamespace(list=lambda: tools),
        executor=object(), adapter_manager=object(),
        normalizer=Normalizer(), risk_engine=RiskEngine(), logger=logger,
        scope=TargetScope(True, ["127.0.0.1"]),
    )
    engine._show_loading = lambda *args: None

    class MockAdapterManager:
        def run(self, tool, target, fallback_executor):
            from core.models import ToolResult
            from datetime import datetime, timezone
            return ToolResult(
                tool=tool["name"], category=tool["category"], target=target,
                started_at=datetime.now(timezone.utc).isoformat(),
                finished_at=datetime.now(timezone.utc).isoformat(),
                return_code=0, status="success", stdout="", stderr="", command=[],
            )

    engine.adapter_manager = MockAdapterManager()
    session = engine.run(Session("127.0.0.1", "stealth"))
    tool_names = {r.tool for r in session.results}
    assert tool_names == {"subfinder", "httpx"}
    assert "whatweb" not in tool_names
    assert "nikto" not in tool_names
