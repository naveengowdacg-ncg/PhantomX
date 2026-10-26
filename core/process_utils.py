"""Bounded, cancellable subprocess execution helpers shared by every adapter."""

from dataclasses import dataclass
import math
import os
import signal
import subprocess
import threading
import time


DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_PROCESS_TIMEOUT_SECONDS = 3600
_POLL_INTERVAL_SECONDS = 0.1


@dataclass(frozen=True)
class ProcessOutcome:
    """Captured process result with an explicit completion state."""

    stdout: str = ""
    stderr: str = ""
    return_code: int | None = None
    status: str = "error"
    duration_seconds: float = 0.0
    truncated: bool = False


def decode_process_output(value):
    """Return subprocess output as text, replacing malformed UTF-8 safely."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def append_diagnostic(partial_stderr, message):
    """Preserve captured stderr before adding a processing diagnostic."""
    partial = decode_process_output(partial_stderr)
    if partial and not partial.endswith(("\n", "\r")):
        partial += "\n"
    return f"{partial}{message}"


def timeout_stderr(partial_stderr, message):
    """Keep any partial stderr and append a concise timeout diagnostic."""
    return append_diagnostic(partial_stderr, message)


def process_exception_output(error, stream):
    """Read partial output from subprocess exceptions without leaking bytes reprs."""
    value = getattr(error, stream, None)
    if stream == "stdout" and value is None:
        value = getattr(error, "output", None)
    return decode_process_output(value)


def process_exception_return_code(error):
    """Keep a useful process return code when an exception provides one."""
    value = getattr(error, "returncode", None)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _read_bounded_stream(stream, limit, state, errors):
    captured = bytearray()
    truncated = False
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            if isinstance(chunk, str):
                chunk = chunk.encode("utf-8", errors="replace")
            remaining = max(0, limit - len(captured))
            if remaining:
                captured.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True
    except (OSError, ValueError) as exc:
        errors.append(f"Could not finish reading process output ({type(exc).__name__}): {exc}")
    state["data"] = bytes(captured)
    state["truncated"] = truncated


def _terminate_process_tree(process, grace_seconds=0.4):
    """Stop the process and descendants created in its isolated process group."""
    pid = getattr(process, "pid", None)
    if not isinstance(pid, int):
        return

    if os.name == "nt":
        killer = None
        try:
            killer = subprocess.Popen(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            killer.wait(timeout=5)
        except Exception:
            if killer is not None and killer.poll() is None:
                try:
                    killer.kill()
                    killer.wait(timeout=1)
                except Exception:
                    pass
        if process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=grace_seconds)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        return

    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        process.wait(timeout=grace_seconds)
    except Exception:
        pass
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    if process.poll() is None:
        try:
            process.kill()
            process.wait(timeout=grace_seconds)
        except Exception:
            pass


def run_process(command, timeout=120, cancel_event=None, max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES):
    """Run an argument vector with bounded output, a hard timeout, and tree cleanup.

    Each output stream is drained concurrently but only its first
    max_output_bytes are retained. Timeout and cancellation keep captured
    partial output and never report a successful completion.
    """
    started = time.monotonic()
    if (
        not isinstance(command, (list, tuple))
        or not command
        or any(not isinstance(item, str) for item in command)
        or not command[0].strip()
    ):
        return ProcessOutcome(
            stderr="Process command must be a non-empty list of strings.",
            status="misconfigured",
        )
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > MAX_PROCESS_TIMEOUT_SECONDS
    ):
        return ProcessOutcome(
            stderr=f"Process timeout must be greater than 0 and at most {MAX_PROCESS_TIMEOUT_SECONDS} seconds.",
            status="misconfigured",
        )
    if (
        isinstance(max_output_bytes, bool)
        or not isinstance(max_output_bytes, int)
        or not 1 <= max_output_bytes <= MAX_OUTPUT_BYTES
    ):
        return ProcessOutcome(
            stderr=f"Per-stream output limit must be from 1 to {MAX_OUTPUT_BYTES} bytes.",
            status="misconfigured",
        )
    if cancel_event is not None and cancel_event.is_set():
        return ProcessOutcome(
            stderr="Tool execution cancelled before process launch.",
            status="cancelled",
        )

    kwargs = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "shell": False,
        "close_fds": True,
        "bufsize": 0,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True

    try:
        process = subprocess.Popen(list(command), **kwargs)
    except KeyboardInterrupt:
        if cancel_event is not None:
            cancel_event.set()
        return ProcessOutcome(
            stderr="Tool execution cancelled during process launch.",
            status="cancelled",
            duration_seconds=time.monotonic() - started,
        )
    except Exception as exc:
        stderr = append_diagnostic(
            process_exception_output(exc, "stderr"),
            f"Tool process launch failed ({type(exc).__name__}): {exc}",
        )
        return ProcessOutcome(
            stdout=process_exception_output(exc, "stdout"),
            stderr=stderr,
            return_code=process_exception_return_code(exc),
            status="error",
            duration_seconds=time.monotonic() - started,
        )

    captures = {
        "stdout": {"data": b"", "truncated": False},
        "stderr": {"data": b"", "truncated": False},
    }
    reader_errors = []
    readers = []
    for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
        thread = threading.Thread(
            target=_read_bounded_stream,
            args=(stream, max_output_bytes, captures[name], reader_errors),
            name=f"phantomx-{name}-{process.pid}",
            daemon=True,
        )
        thread.start()
        readers.append(thread)

    outcome_status = None
    diagnostic = None
    try:
        deadline = started + float(timeout)
        while True:
            if cancel_event is not None and cancel_event.is_set():
                outcome_status = "cancelled"
                diagnostic = "Tool execution cancelled."
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                outcome_status = "timeout"
                diagnostic = f"Tool timed out after {float(timeout):g} seconds."
                break
            try:
                process.wait(timeout=min(remaining, _POLL_INTERVAL_SECONDS))
                break
            except subprocess.TimeoutExpired:
                continue
    except KeyboardInterrupt:
        if cancel_event is not None:
            cancel_event.set()
        outcome_status = "cancelled"
        diagnostic = "Tool execution cancelled by keyboard interrupt."
    except Exception as exc:
        outcome_status = "error"
        diagnostic = f"Tool process monitoring failed ({type(exc).__name__}): {exc}"

    if outcome_status in {"timeout", "cancelled", "error"}:
        _terminate_process_tree(process)

    for thread in readers:
        thread.join(timeout=2)
    if any(thread.is_alive() for thread in readers):
        _terminate_process_tree(process)
        for thread in readers:
            thread.join(timeout=1)
        reader_errors.append("A process output stream did not close after child cleanup.")

    stdout = decode_process_output(captures["stdout"]["data"])
    stderr = decode_process_output(captures["stderr"]["data"])
    truncated = any(state["truncated"] for state in captures.values())
    if diagnostic:
        stderr = append_diagnostic(stderr, diagnostic)
    if truncated:
        stderr = append_diagnostic(
            stderr,
            f"Output limit reached ({max_output_bytes} bytes per stream); captured output is incomplete.",
        )
    for error in reader_errors:
        stderr = append_diagnostic(stderr, error)

    duration = time.monotonic() - started
    if outcome_status is None:
        if reader_errors:
            outcome_status = "error"
        elif truncated:
            outcome_status = "output_limited"
        else:
            outcome_status = "success" if process.returncode == 0 else "failed"

    return_code = None if outcome_status in {"timeout", "cancelled"} else process.returncode
    return ProcessOutcome(
        stdout=stdout,
        stderr=stderr,
        return_code=return_code,
        status=outcome_status,
        duration_seconds=duration,
        truncated=truncated,
    )
