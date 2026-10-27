# PhantomX — Automated Cybersecurity Reconnaissance and Vulnerability Assessment Framework

PhantomX is a Python command-line framework for orchestrating authorized reconnaissance, normalizing scanner output, prioritizing findings, and producing assessment reports. Scanner matches are leads for review; they are not proof that a vulnerability is exploitable.

> Use only against systems you own or have explicit authorization to assess. Start with local VMs/lab targets.

## Design goals

- Modular tool orchestration: add/remove tools without changing the core.
- Adaptive assessment workflows: later stages can depend on earlier findings.
- Configurable risk scoring and correlation.
- Multiple assessment options/profiles.
- Consolidated JSON, Markdown, HTML and PDF reporting with correlated findings and evidence.
- Graceful failures, timeouts and execution logs.

## Quick start

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# Kali/Linux:         source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

Python 3.10 or newer is required. The runtime and built-in PDF writer use only the
Python standard library. Scanner programs are separate operating-system packages.
For development, install `pytest` with `python -m pip install pytest` before running
the test suite.

From the repository root, run the regression suite and compile check with:

```bash
python -m pytest -q
python -m compileall -q .
```

Inside the CLI:

```text
tools list
tools add nmap recon nmap -sV {target}
tools add whatweb web whatweb {target}
tools add nikto web nikto -h {target}
tools add nuclei vuln nuclei -u {target}
tools remove nikto
target 127.0.0.1
scan nmap
scan profile standard
workflow full
report html
report pdf
report all
```

The framework does not require all tools to be installed. Run `preflight` to check
executable and wordlist availability without launching scanners. Missing tools are
reported as unavailable and the workflow continues without claiming they succeeded.

## Local demonstration

Start with a service you own that is bound to loopback, then use the CLI:

```text
preflight
target 127.0.0.1
scan profile standard
results
report all
```

The exact findings depend on which scanners are installed and which local services
are running. Review each tool status and its captured output; do not describe an
unverified scanner match as a confirmed vulnerability.


## Target authorization and configuration

PhantomX validates target syntax and enforces an explicit allowlist by default.
The default `config/settings.json` permits only local lab targets (`127.0.0.1`,
`localhost`, and `::1`). Before assessing another system, add its authorized hostname,
IP address, or network CIDR to `authorized_targets` only when you have permission
to test it. CIDR entries such as `192.168.56.0/24` are supported; wildcard DNS
entries such as `*.lab.example` are also supported. Before an active scan, PhantomX
resolves the hostname and requires every returned IPv4 and IPv6 address to match an
authorized IP or CIDR entry. A hostname or wildcard entry alone authorizes the name,
but does not authorize the addresses to which it resolves. Resolution failures and
mixed in-scope/out-of-scope answers fail closed. PhantomX does not pin the checked
addresses into third-party scanners, so DNS can change between validation and use.

Example configuration for an explicitly authorized lab network:

```json
{
  "default_profile": "standard",
  "reports_dir": "reports",
  "max_workers": 4,
  "scope_required": true,
  "allowed_profiles": ["passive", "stealth", "standard", "full", "aggressive"],
  "authorized_targets": ["127.0.0.1", "192.168.56.0/24"]
}
```

The `max_workers` setting controls concurrent discovery tasks, `reports_dir` controls
report and execution-log output, and `allowed_profiles` restricts which scan profiles
can be launched. `scan profile default` uses `default_profile`. Setting
`scope_required` to `false` disables allowlist enforcement but does not disable target
syntax validation; use that setting only when your assessment workflow explicitly
requires it and you are authorized to assess the supplied targets.

Application settings accept max_workers as an integer or a decimal integer string from 1 through 64; booleans, fractional values, and malformed strings are rejected.

Each tool may set `retries` from 0 to 3 (default 0). Only process-launch errors are
retried by default; timed-out scans are never repeated unless `retry_on_timeout` is
explicitly set to `true`. Non-zero scanner exit codes are retained as assessment
outcomes and are not automatically retried.

Scanner processes receive an argument list with `shell=False`. Output capture is
limited to 1 MiB per stream by default, and configured timeouts must be between 1
and 3,600 seconds. Timeout, output-limit, and cancellation states retain captured
partial output and a diagnostic; cancellation terminates the process tree where the
operating system permits it. Shipped HTTP tool configurations disable redirects or
constrain crawling to the authorized hostname, and preflight rejects known unsafe
redirect flags. This does not pin DNS or mediate custom tools that implement their
own network requests.

## Current implementation milestone

Implemented foundation:
- tool registry persisted in `config/tools.json`
- safe argument-list execution (`shell=False`)
- tool add/remove/list commands
- scan profiles
- adaptive workflow engine
- result normalization
- configurable risk scoring
- JSON/Markdown/HTML/PDF reports
- execution logging
- conservative cross-tool finding correlation integrated into workflow completion
- correlation metadata persisted with findings and sessions
- reports that group related detections, retain source/evidence, and distinguish PhantomX risk scores from scanner severity

## Correlation and prioritization

PhantomX correlates findings conservatively using vulnerability identifiers, recognized
service-discovery evidence, and specific endpoint/title identity. A shared port or broad
category alone is not enough to merge unrelated findings. Tool-level results remain
available for auditability; Markdown and HTML reports show a representative group
summary plus inspectable per-detection details, contributing source tools, distinct
evidence, and how many detections were grouped.
Correlation confidence is a fixed record-match indicator, not a calibrated probability. For compatibility, every group with multiple records is assigned 0.70 and an unmatched record is assigned 0.00. The value does not rank correlation-key classes, estimate vulnerability confidence, or contribute to the PhantomX risk score. Repeated records from one scanner do not increase it, and source count does not imply independent verification. Reports list the verification metadata available for each grouped detection and call out differing reported states; missing metadata is not inferred.

The **PhantomX risk score** is calculated using the configured weighted risk model and
severity thresholds. **Scanner severity** is retained separately when the source scanner
provides it, so differences between the two are visible rather than silently overwritten.
The current model weights and thresholds remain unchanged.

Open services and technology fingerprints are represented as zero-risk
observations; a listening port or product banner is not a confirmed vulnerability.
Nuclei and Nikto detections carry an explicit `scanner_match_unverified` state.
For Nikto, exit code 1 is accepted only when stdout contains a complete scan summary
(`host(s) tested`, `item(s) reported on remote host`, and `End Time`) and stderr
is empty. In the observed local run, Nikto reported 15 raw items and PhantomX
normalized 14 actionable lines because progress and summary rows are excluded.
Missing headers and ETag inode disclosures remain scanner observations; reported
`/server-status`, arbitrary-file-read patterns, PHP backdoor signatures, and
router command-execution signatures require independent validation before being
described as vulnerabilities.

The score formula is `10 × (0.35 × impact + 0.30 × exploitability + 0.25 × confidence + 0.10 × exposure)`.
Impact, exploitability, exposure, and normalized confidence use a 0–10 scale. For
compatibility, confidence from 0 through 1 is interpreted as a fraction and multiplied
by 10; values above 1 through 10 are already on the 0–10 scale. Inputs outside their
valid finite numeric ranges are rejected instead of clamped. Each scored finding stores
its normalized inputs, weights, contribution breakdown, final score, and severity.
Observations always remain score `0` / `info`. A score describes PhantomX
prioritization; it does not establish independent verification or exploitability.

JSON reports preserve the full session data and evidence. Markdown and HTML summaries
show up to five evidence records, with truncation called out and the complete evidence
available in JSON. Human-readable reports remove URL credentials, query strings, and
fragments from targets, endpoint metadata, and URLs embedded in scanner text. HTML and
Markdown output escape untrusted report values. Report filenames are sanitized,
bounded, and receive a stable hash suffix so distinct IDs remain distinct on
case-insensitive filesystems as well as after sanitization.
Malformed non-finite JSON values cause JSON export to fail rather than emit non-standard
JSON.
PDF reports contain the same grouped risk, tool outcome, verification, and evidence
context; portable built-in fonts replace characters outside their supported subset.

Scanner process output remains available when parsing fails. Such results use the
`parse_error` status and include a parser diagnostic alongside captured stdout and
stderr. Nuclei JSONL rows with unexpected JSON shapes are skipped safely while the raw
process output remains in the result. Saved tool results retain enough normalization
state to refresh derived findings without duplicating them after reload.

## Asset intelligence graph

Each completed workflow now derives a versioned asset graph from captured tool
results. Stable identities represent domains, IP addresses, services, HTTP
endpoints, technologies, DNS A/AAAA/CNAME records, discovered resources, and
finding references. Relationships include discovery, DNS resolution, exposed
services, served endpoints, technology fingerprints, resources, and finding
associations. Asset and relationship records retain source tool, observation
time, and an evidence reference; identified CVE/template findings also receive
a stable fingerprint while retaining their original finding ID and scanner
provenance.

The graph is part of the session payload and survives SQLite save/load. Older
sessions without the graph continue to load; reports derive a fresh projection
from their saved results. JSON contains the complete graph, while Markdown,
HTML, and PDF use the same graph summary and bounded human-readable asset and
relationship lists. Endpoint identity keeps its path and excludes URL userinfo,
query strings, and fragments; raw scanner evidence remains in the machine-readable
session. Findings without a defensible asset link remain in the graph as
assessment-context records rather than being asserted to affect the root asset.

The projection makes no network requests. DNS relationships are built only from
recognized structured or host [A|AAAA|CNAME] value dnsx records. The active-scan
scope check resolves target names and checks every returned address, but the
resolution is not pinned into third-party tools. Shipped configurations constrain
redirect behavior for known HTTP tools; custom tools can require separate review.
The graph does not verify vulnerabilities or compare graph changes across sessions.

## Assessment history

Completed assessments are saved in `data/phantomx.sqlite3`. Use `history [limit]` to
list saved sessions and `load <session_id>` to restore one. The local database is
intentionally excluded from Git; do not commit live assessment history.

The project includes a CLI and an optional Tk desktop GUI. Advanced adaptive-intelligence
features remain outside the college submission scope.

## Optional reconnaissance tools (batch integration)

PhantomX can integrate the following optional command-line tools when installed and present in `PATH`: `subfinder`, `dnsx`, ProjectDiscovery `httpx`, `katana`, `testssl.sh` (Kali package command: `testssl`), and `gobuster`. They are enabled in `config/tools.json`; unavailable tools return a missing-tool status rather than being treated as findings. Subfinder is skipped for IP/localhost targets because passive subdomain discovery requires a domain. On Kali/Linux, Gobuster defaults to `/usr/share/wordlists/dirb/common.txt`; change the configured path if your system stores the wordlist elsewhere.

New reconnaissance results are recorded as observations (zero impact/exploitability) until independently validated. Keep target authorization and scope enforcement enabled, especially when reviewing discovered hosts or endpoints.

## Phase 2: workflow scope and tool preflight

Run `preflight` in the CLI to check enabled tools without launching them. Results identify tools as `ready`, `unavailable` (executable not found on PATH), or `misconfigured` (invalid configuration or a missing required file when the executable is available). Tool file dependencies are declared in `config/tools.json` with `required_files`; update that field and the matching tool argument when a wordlist or other input lives elsewhere. Checks use the current operating system's paths and PATH and do not run shell commands.

Profiles have distinct selection and execution rules:

- `passive` runs only tools explicitly assigned to passive discovery (the default registry selects Subfinder). It does not probe the target or trigger downstream assessments.
- `stealth` runs passive discovery and a single-target HTTPX metadata check, serially. It does not assess discovered subdomains or run downstream web tools. This limits scope and concurrency; it does not make traffic invisible.
- `standard` runs enabled recon and web-category tools, using adaptive decisions to select web checks. It excludes vulnerability-category tools.
- `full` runs enabled recon, web, and vulnerability-category tools.
- `aggressive` uses the full tool selection and the configured Nmap `-p1-1024 -T4 --max-retries 1 --host-timeout 120s` override. Aggressive workflow concurrency is capped at four workers and remains bounded by each tool's process timeout. It does not enable an exploitation framework.

`scan profile default` resolves `default_profile` before execution. Optional `profile_modes` lists restrict a tool to named profiles; `profile_args` maps a profile to an alternate string argument list. Restricted profiles default to Subfinder for `passive` and Subfinder/HTTPX for `stealth`; other tools must be explicitly configured for these modes. Preflight validates both fields.

Discovered HTTP(S) endpoints can drive the existing downstream web decisions. Each derived active probe rechecks the endpoint hostname against `authorized_targets`; a discovery result alone does not authorize a new host. Missing or failed optional tools are recorded and do not stop other workflow stages. HTTPX and Gobuster path results remain observations until independently verified.

Architecture details, troubleshooting, and the tracked completion checklist are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
[`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md), and
[`docs/COMPLETION_CHECKLIST.md`](docs/COMPLETION_CHECKLIST.md).
