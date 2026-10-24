
from unittest.mock import patch, Mock

from core.executor import ToolExecutor


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
