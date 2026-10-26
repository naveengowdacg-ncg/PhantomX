# PhantomX troubleshooting

## Startup and Python

Run commands from the repository root so `config/settings.json` and
`config/tools.json` resolve correctly. Create and activate a virtual environment
before installing requirements:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python main.py
```

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

Python 3.10 or newer is required. No third-party Python runtime packages are
currently required. Install `pytest` separately to run the test suite. Scanner
programs are independent executables.

Windows validation is performed with the Python version reported by the current
project run; verify the same minimum version on Kali before submission. There is no
configured Ruff or mypy job in the repository.

## Target rejected

Use a hostname or IP without a URL path, shell characters, credentials, or
whitespace. By default only `127.0.0.1`, `localhost`, and `::1` are authorized.
Add other hosts, CIDRs, or wildcard DNS suffixes to `authorized_targets` only
when authorized to assess them. Keep `scope_required` enabled.

For an active scan, each resolved IP address must also match an authorized IP or
CIDR. If a configured hostname resolves outside that address scope, add only the
authorized address/network or use the correct lab DNS configuration. PhantomX does
not pin the checked resolution into third-party scanner processes.

## Tool unavailable or misconfigured

Run `preflight`. It only checks registry structure, executable lookup, and
required files; it does not invoke scanners. Install the missing system tool or
correct its `executable`, `args`, `timeout`, and `required_files` fields in
`config/tools.json`. Gobuster's default wordlist path is Kali-specific. `profile_modes`
and `profile_args` are optional and validated by preflight.

## Unexpected process status

Use `results <tool>` to inspect return code, captured stdout/stderr, timeout or
parser diagnostics. A nonzero code is not automatically a scan failure or success.
Nikto code 1 is accepted only when its output contains the completion summary
and stderr is empty; its reported item count may differ from normalized findings
because summary/progress lines are not findings. Timed-out results preserve
partial output. Retries default to zero; process-launch retries and explicitly
configured timeout retries are limited to three.

Captured stdout and stderr are each capped at 1 MiB by default. `output_limited`
means retained output is incomplete. Press Ctrl+C during a workflow to request
cancellation; PhantomX preserves captured output and attempts to stop scanner child
processes. A tool timeout must be between 1 and 3,600 seconds.

## No downstream web scan

Downstream work requires successful discovery and a valid HTTP(S) endpoint. The
endpoint host is checked against the allowlist again. `passive` intentionally
does not probe discovered endpoints; `stealth` performs only a single-target
HTTPX metadata check and never launches web follow-up. `standard`, `full`, and
`aggressive` have broader selection as documented in the README.

## Reports and session history

Use `report all` for JSON, Markdown, HTML, and PDF. If one format fails, the CLI
reports that error and continues attempting the other formats. Human-readable
reports redact URL credentials, query strings, and fragments; JSON preserves raw
evidence and should be handled as sensitive. Sessions are stored in
`data/phantomx.sqlite3`, which is local runtime state and intentionally ignored by
Git. `history [limit]` lists saved sessions; `load <session_id>` restores one.

## Logs

Execution diagnostics are written to `reports/execution.log`. Review the
per-tool raw output and status before treating any scanner match as a confirmed
vulnerability. Reports and logs can contain sensitive assessment details; protect
the reports directory accordingly.
