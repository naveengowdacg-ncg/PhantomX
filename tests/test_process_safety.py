import json
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

import pytest

from core.executor import ToolExecutor
from core.preflight import ToolPreflight, redirect_policy_error
from core.process_utils import run_process
from core.scope import TargetScope, TargetScopeError
from core.models import Session
from core.workflow import WorkflowEngine
from analysis.normalizer import Normalizer
from analysis.scoring import RiskEngine


def _tool(name="scanner", args=None, **extra):
    return {
        "name": name,
        "category": "recon",
        "executable": "scanner-bin",
        "args": ["--target", "{target}"] if args is None else args,
        "timeout": 5,
        "enabled": True,
        **extra,
    }


def test_runner_bounds_both_output_streams_and_reports_incomplete_capture():
    code = (
        "import sys; "
        "sys.stdout.write('o' * 500000); sys.stdout.flush(); "
        "sys.stderr.write('e' * 500000); sys.stderr.flush()"
    )
    outcome = run_process(
        [sys.executable, "-c", code],
        timeout=5,
        max_output_bytes=128,
    )

    assert outcome.status == "output_limited"
    assert len(outcome.stdout.encode("utf-8")) == 128
    captured_stderr = outcome.stderr.split("Output limit reached", 1)[0].rstrip()
    assert len(captured_stderr.encode("utf-8")) == 128
    assert "128 bytes per stream" in outcome.stderr
    assert outcome.truncated is True


def test_runner_decodes_invalid_utf8_without_losing_process_status():
    code = "import sys; sys.stdout.buffer.write(bytes([103, 111, 111, 100, 255])); sys.stdout.flush()"
    outcome = run_process([sys.executable, "-c", code], timeout=5)

    assert outcome.status == "success"
    assert outcome.return_code == 0
    assert outcome.stdout == "good�"


def test_runner_timeout_preserves_partial_streams_and_kills_child_tree(tmp_path):
    marker = tmp_path / "child-survived.txt"
    child_code = (
        "import pathlib,time; time.sleep(1.0); "
        f"pathlib.Path({str(marker)!r}).write_text('survived', encoding='utf-8')"
    )
    parent_code = (
        "import subprocess,sys,time; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[1]]); "
        "print('parent partial', flush=True); "
        "print('child started', file=sys.stderr, flush=True); time.sleep(30)"
    )

    outcome = run_process(
        [sys.executable, "-c", parent_code, child_code],
        timeout=0.4,
        max_output_bytes=1024,
    )
    time.sleep(1.2)

    assert outcome.status == "timeout"
    assert outcome.return_code is None
    assert "parent partial" in outcome.stdout
    assert "child started" in outcome.stderr
    assert "timed out" in outcome.stderr
    assert not marker.exists()


def test_runner_cancellation_stops_process_and_preserves_partial_output():
    event = threading.Event()
    timer = threading.Timer(0.2, event.set)
    timer.start()
    try:
        outcome = run_process(
            [
                sys.executable,
                "-c",
                "import time; print('before cancel', flush=True); time.sleep(30)",
            ],
            timeout=10,
            cancel_event=event,
            max_output_bytes=1024,
        )
    finally:
        timer.cancel()

    assert outcome.status == "cancelled"
    assert outcome.return_code is None
    assert "before cancel" in outcome.stdout
    assert "cancelled" in outcome.stderr


def test_runner_rejects_unbounded_timeout_and_invalid_command():
    too_long = run_process([sys.executable, "-c", "pass"], timeout=3601)
    invalid_command = run_process("python -c pass", timeout=1)

    assert too_long.status == "misconfigured"
    assert invalid_command.status == "misconfigured"


def test_dns_resolution_requires_every_address_to_be_in_authorized_scope(monkeypatch):
    responses = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.18", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::4", 0, 0, 0)),
    ]
    monkeypatch.setattr("core.scope.socket.getaddrinfo", lambda *args, **kwargs: responses)
    scope = TargetScope(True, ["scan.lab.test", "192.0.2.0/24", "2001:db8::/32"])

    assert scope.resolve_and_validate("scan.lab.test") == ("192.0.2.18", "2001:db8::4")


def test_dns_resolution_fails_closed_for_mixed_or_unresolved_answers(monkeypatch):
    mixed = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.18", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
    ]
    monkeypatch.setattr("core.scope.socket.getaddrinfo", lambda *args, **kwargs: mixed)
    scope = TargetScope(True, ["scan.lab.test", "192.0.2.0/24"])
    with pytest.raises(TargetScopeError, match="resolved outside configured IP scope"):
        scope.resolve_and_validate("scan.lab.test")

    monkeypatch.setattr(
        "core.scope.socket.getaddrinfo",
        lambda *args, **kwargs: (_ for _ in ()).throw(socket.gaierror("offline")),
    )
    with pytest.raises(TargetScopeError, match="Could not resolve active target"):
        scope.resolve_and_validate("scan.lab.test")


def test_executor_rejects_out_of_scope_target_before_launch(monkeypatch):
    called = []
    monkeypatch.setattr("core.executor.shutil.which", lambda _: "scanner-bin")
    monkeypatch.setattr(
        "core.executor.run_process",
        lambda *args, **kwargs: called.append(args) or pytest.fail("must not launch"),
    )
    executor = ToolExecutor(
        object(),
        scope=TargetScope(True, ["127.0.0.1"]),
    )

    result = executor.run(_tool(), "192.0.2.25")

    assert result.status == "scope_denied"
    assert "outside configured scope" in result.stderr
    assert called == []


def test_executor_rejects_tool_configuration_without_target_placeholder(monkeypatch):
    monkeypatch.setattr("core.executor.shutil.which", lambda _: "scanner-bin")
    monkeypatch.setattr(
        "core.executor.run_process",
        lambda *args, **kwargs: pytest.fail("must not launch"),
    )
    result = ToolExecutor(object()).run(_tool(args=["--help"]), "127.0.0.1")

    assert result.status == "misconfigured"
    assert "target" in result.stderr


def test_redirect_policy_blocks_unsafe_overrides_and_accepts_shipped_config():
    config = json.loads(Path("config/tools.json").read_text(encoding="utf-8"))
    configured = {tool["name"]: tool for tool in config["tools"]}

    for name in ("whatweb", "nuclei", "katana"):
        assert redirect_policy_error(configured[name]) is None

    assert redirect_policy_error(_tool(
        "whatweb", executable="whatweb",
        args=["--follow-redirect=never", "--follow-redirect=always", "{target}"],
    ))
    assert redirect_policy_error(_tool(
        "nuclei", executable="nuclei",
        args=["-u", "{target}", "-disable-redirects", "-fr"],
    ))
    assert redirect_policy_error(_tool(
        "katana", executable="katana",
        args=["-u", "{target}", "-disable-redirects", "-fs", "rdn"],
    ))
    assert redirect_policy_error(_tool(
        "httpx", executable="httpx-toolkit", args=["-u", "{target}", "-fr"],
    ))


def test_preflight_and_executor_reject_redirect_following_config(monkeypatch):
    unsafe = _tool(
        "whatweb", executable="whatweb",
        args=["--follow-redirect=always", "{target}"],
    )
    status = ToolPreflight().inspect([unsafe])[0]
    monkeypatch.setattr("core.executor.shutil.which", lambda _: "whatweb")

    result = ToolExecutor(object()).run(unsafe, "127.0.0.1")

    assert status["status"] == "misconfigured"
    assert "follow-redirect" in status["message"]
    assert "to never" in status["message"]
    assert result.status == "misconfigured"
    assert "follow-redirect" in result.stderr
    assert "to never" in result.stderr


def test_workflow_cancellation_records_result_diagnostic_and_session_note(tmp_path):
    ready = tmp_path / "scanner-ready.txt"
    scanner_code = (
        "import pathlib,sys,time; "
        f"pathlib.Path({str(ready)!r}).write_text('ready', encoding='utf-8'); "
        "print('partial scanner output', flush=True); time.sleep(30)"
    )
    tool = _tool(
        "lab-scanner",
        executable=sys.executable,
        args=["-c", scanner_code, "{target}"],
        timeout=10,
    )

    class Registry:
        def list(self):
            return [tool]

    class Logger:
        def info(self, *args, **kwargs):
            pass

        def warning(self, *args, **kwargs):
            pass

    from core.adapter_manager import AdapterManager

    executor = ToolExecutor(
        Logger(), scope=TargetScope(True, ["127.0.0.1"])
    )
    engine = WorkflowEngine(
        Registry(), executor, AdapterManager(), Normalizer(), RiskEngine(), Logger(),
        scope=TargetScope(True, ["127.0.0.1"]),
    )
    session = Session(target="127.0.0.1", profile="standard")
    worker = threading.Thread(target=engine.run, args=(session,), daemon=True)
    worker.start()

    deadline = time.monotonic() + 5
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert ready.exists(), "workflow did not launch the local scanner process"

    engine.cancel()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert len(session.results) == 1
    assert session.results[0].status == "cancelled"
    assert "partial scanner output" in session.results[0].stdout
    assert "cancelled" in session.results[0].stderr
    assert any(
        "Tool lab-scanner finished with status cancelled" in note
        for note in session.notes
    )
