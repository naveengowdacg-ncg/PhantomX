
import subprocess
from unittest.mock import patch, Mock

from core.executor import ToolExecutor
from core.process_utils import ProcessOutcome


def test_nikto_exit_zero_is_success():
    assert ToolExecutor._nikto_scan_completed(
        0,
        "1 host(s) tested",
        "",
    ) is False


def test_nikto_exit_one_completed_scan_is_recognized():
    output = """
    + 8074 requests: 0 error(s) and 15 item(s) reported on remote host
    + End Time: 2026-10-24 14:38:24
    + 1 host(s) tested
    """
    assert ToolExecutor._nikto_scan_completed(1, output, "") is True


def test_nikto_invalid_option_is_not_success():
    output = "Unknown option: nocheck"
    assert ToolExecutor._nikto_scan_completed(1, output, "") is False


def test_nikto_incomplete_output_is_not_success():
    output = "+ Server: Apache"
    assert ToolExecutor._nikto_scan_completed(1, output, "") is False


def test_nikto_stderr_error_is_not_success():
    output = """
    + 15 item(s) reported on remote host
    + End Time: 2026-10-24 14:38:24
    + 1 host(s) tested
    """
    assert ToolExecutor._nikto_scan_completed(
        1, output, "fatal error"
    ) is False


def test_timeout_preserves_partial_utf8_safe_output_and_shell_is_disabled():
    logger = Mock()
    tool = {
        "name": "scanner",
        "category": "recon",
        "executable": "scanner-bin",
        "args": ["--target", "{target}"],
        "timeout": 5,
    }
    outcome = ProcessOutcome(
        stdout="partial output \ufffd",
        stderr="partial diagnostic\nTool timed out after 5 seconds.",
        return_code=None,
        status="timeout",
        duration_seconds=0.01,
    )

    with patch("core.executor.shutil.which", return_value="/usr/bin/scanner-bin"), \
         patch("core.executor.run_process", return_value=outcome) as run:
        result = ToolExecutor(logger).run(tool, "127.0.0.1")

    assert result.status == "timeout"
    assert result.stdout == "partial output \ufffd"
    assert result.stderr == "partial diagnostic\nTool timed out after 5 seconds."
    assert run.call_args.args[0] == ["scanner-bin", "--target", "127.0.0.1"]
    assert run.call_args.kwargs["timeout"] == 5


def test_subprocess_exception_preserves_partial_output_and_diagnostic():
    logger = Mock()
    tool = {
        "name": "scanner",
        "category": "recon",
        "executable": "scanner-bin",
        "args": ["{target}"],
        "timeout": 5,
    }
    outcome = ProcessOutcome(
        stdout="partial output \ufffd",
        stderr="partial diagnostic \ufffd\nTool process launch failed (OSError): process launch failed",
        return_code=9,
        status="error",
        duration_seconds=0.01,
    )

    with patch("core.executor.shutil.which", return_value="/usr/bin/scanner-bin"), \
         patch("core.executor.run_process", return_value=outcome):
        result = ToolExecutor(logger).run(tool, "127.0.0.1")

    assert result.status == "error"
    assert result.return_code == 9
    assert result.stdout == "partial output \ufffd"
    assert result.stderr.startswith("partial diagnostic \ufffd\n")
    assert "process launch failed" in result.stderr
