# Automated Cybersecurity Reconnaissance & Vulnerability Assessment Framework

Academic implementation starter inspired by the architecture and feature ideas documented in the GhostScan paper/repository. This project is an original implementation and does not copy GhostScan source code.

> Use only against systems you own or have explicit authorization to assess. Start with local VMs/lab targets.

## Design goals

- Modular tool orchestration: add/remove tools without changing the core.
- Adaptive assessment workflows: later stages can depend on earlier findings.
- Configurable risk scoring and correlation.
- Multiple assessment options/profiles.
- Consolidated JSON, Markdown and HTML reporting with correlated findings and evidence.
- Graceful failures, timeouts and execution logs.

## Quick start

```bash
python main.py
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
```

The framework does not require all tools to be installed. Missing executables are reported and the workflow continues.


## Target authorization and configuration

PhantomX validates target syntax and enforces an explicit allowlist by default.
The default `config/settings.json` permits only local lab targets (`127.0.0.1`,
`localhost`, and `::1`). Before assessing another system, add its authorized hostname,
IP address, or network CIDR to `authorized_targets` only when you have permission
to test it. CIDR entries such as `192.168.56.0/24` are supported; wildcard DNS
entries such as `*.lab.example` are also supported. Hostnames are matched by name
without automatically resolving them to IP addresses.

Example configuration for an explicitly authorized lab network:

```json
{
  "default_profile": "standard",
  "reports_dir": "reports",
  "max_workers": 4,
  "scope_required": true,
  "allowed_profiles": ["passive", "standard", "full"],
  "authorized_targets": ["127.0.0.1", "192.168.56.0/24"]
}
```

The `max_workers` setting controls concurrent discovery tasks, `reports_dir` controls
report and execution-log output, and `allowed_profiles` restricts which scan profiles
can be launched. `scan profile default` uses `default_profile`. Setting
`scope_required` to `false` disables allowlist enforcement but does not disable target
syntax validation; use that setting only when your assessment workflow explicitly
requires it and you are authorized to assess the supplied targets.

## Current implementation milestone

Implemented foundation:
- tool registry persisted in `config/tools.json`
- safe argument-list execution (`shell=False`)
- tool add/remove/list commands
- scan profiles
- adaptive workflow engine
- result normalization
- configurable risk scoring
- JSON/Markdown/HTML reports
- execution logging
- conservative cross-tool finding correlation integrated into workflow completion
- correlation metadata persisted with findings and sessions
- reports that group related detections, retain source/evidence, and distinguish PhantomX risk scores from scanner severity

## Correlation and prioritization

PhantomX correlates findings conservatively using vulnerability identifiers, recognized
service-discovery evidence, and specific endpoint/title identity. A shared port or broad
category alone is not enough to merge unrelated findings. Tool-level results remain
available for auditability; Markdown and HTML reports show one representative per
correlation group, the contributing source tools, distinct evidence, and how many
detections were grouped.

The **PhantomX risk score** is calculated using the configured weighted risk model and
severity thresholds. **Scanner severity** is retained separately when the source scanner
provides it, so differences between the two are visible rather than silently overwritten.
The current model weights and thresholds remain unchanged.

## Assessment history

Completed assessments are saved in `data/phantomx.sqlite3`. Use `history [limit]` to
list saved sessions and `load <session_id>` to restore one. The local database is
intentionally excluded from Git; do not commit live assessment history.

Next milestones: richer parsers, additional wrappers, PDF export, expanded controlled-lab test fixtures, and optional GUI.

## Optional reconnaissance tools (batch integration)

PhantomX can integrate the following optional command-line tools when installed and present in `PATH`: `subfinder`, `dnsx`, ProjectDiscovery `httpx`, `katana`, `testssl.sh`, and `gobuster`. They are enabled in `config/tools.json`; unavailable tools return a missing-tool status rather than being treated as findings. Subfinder is skipped for IP/localhost targets because passive subdomain discovery requires a domain. On Kali/Linux, Gobuster defaults to `/usr/share/wordlists/dirb/common.txt`; change the configured path if your system stores the wordlist elsewhere.

New reconnaissance results are recorded as observations (zero impact/exploitability) until independently validated. Keep target authorization and scope enforcement enabled, especially when reviewing discovered hosts or endpoints.

## Phase 2: workflow scope and tool preflight

Run `preflight` in the CLI to check enabled tools without launching them. Results identify tools as `ready`, `unavailable` (executable not found on PATH), or `misconfigured` (invalid configuration or a missing required file when the executable is available). Tool file dependencies are declared in `config/tools.json` with `required_files`; update that field and the matching tool argument when a wordlist or other input lives elsewhere. Checks use the current operating system's paths and PATH and do not run shell commands.

Profiles select configured tool categories: `passive` and `stealth` select recon tools, `standard` adds web tools, and `full` and `aggressive` include vulnerability tools. `stealth` is a recon-only selection; it does not guarantee low network visibility. Existing `passive` and `full` profile names remain supported.

Discovered HTTP(S) endpoints can drive the existing downstream web decisions. Each derived active probe rechecks the endpoint hostname against `authorized_targets`; a discovery result alone does not authorize a new host. Missing or failed optional tools are recorded and do not stop other workflow stages. HTTPX and Gobuster path results remain observations until independently verified.
