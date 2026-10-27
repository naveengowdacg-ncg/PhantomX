# PhantomX architecture

## Design boundary

PhantomX is a local CLI orchestration framework. It invokes separately installed
reconnaissance tools, converts their output into common session models, applies a
fixed explainable prioritization model, stores sessions in SQLite, and renders
JSON, Markdown, HTML, and PDF reports. It does not provide an exploitation
framework and scanner detections remain unverified until corroborated manually.

## Data flow

```text
CLI / settings / scope
        |
        v
WorkflowEngine -- selects profile and checks scope before active work
        |
        +--> AdapterManager --> specialized parser adapters
        |                         |
        +-------------------------+--> ToolExecutor (argument list, shell=False)
                                      |
                                      v
                              captured ToolResult
                                      |
                    Normalizer --> RiskEngine --> CorrelationEngine
                         |              |               |
                         +--------------+---------------+
                                        |
                         AssetIntelligenceBuilder
                                        |
                       SQLiteSessionStore + Reporter
                             JSON / Markdown / HTML / PDF
```

The production `AdapterManager` routes Nmap, WhatWeb, Nuclei, and auxiliary tools
through the configured `ToolExecutor`; those adapters then parse the captured
result. Direct calls to legacy specialized adapter `scan(target)` methods retain
their standalone default commands for compatibility. New integrations should use
`AdapterManager` so registry arguments, timeouts, retries, and diagnostics are
respected.

## Main packages

- `core.scope`: target syntax, allowlist, CIDR and wildcard checks, and normalized
  HTTP(S) endpoint validation.
- `core.workflow`: profile selection, discovery concurrency, scope-checked
  enrichment, adaptive follow-up, result capture, and correlation annotations.
- `core.tool_registry` / `core.preflight`: persistent tool configuration and
  read-only executable/file/schema checks.
- `core.executor` / `core.process_utils`: safe subprocess execution, timeouts,
  partial output, bounded retries, decoding, and process outcome status.
- `modules/*`: specialized parsers; auxiliary tools use one target-aware adapter.
- `analysis.normalizer`: stable conversion into common `Finding`/`Observation`
  records with persisted provenance for idempotent normalization.
- `analysis.scoring`: unchanged weighted risk model: impact 0.35, exploitability
  0.30, confidence 0.25, exposure 0.10. Thresholds remain critical >=85, high
  >=65, medium >=40, low >=20, otherwise info. Observations score 0/info.
- `analysis.correlation`: conservative grouping; a fixed 0.70 record-match
  indicator for groups with multiple records and 0.00 for singletons. It is not a
  probability or proof of independent verification.
- `core.storage`: complete session payloads in a local SQLite database.
- `reporting.reporter`: raw JSON export and sanitized human-readable Markdown,
  HTML, and dependency-free PDF output.

## Asset intelligence projection

After finding correlation, AssetIntelligenceBuilder derives a versioned graph
from captured session data without making network requests. It assigns
deterministic IDs to normalized domain/IP, DNS record, service, endpoint,
technology, and resource assets. Relationships connect discovery, DNS
resolution, exposed services, served endpoints, technology fingerprints, and
finding references. Each asset and edge retains source, timestamp, and an
evidence reference.

Finding references preserve scanner source, raw verification status, severity,
risk score, confidence, exposure, score breakdown, recommendation, and evidence
reference. A stable cross-session fingerprint is produced only when a
CVE/template identifier is present; the original finding ID and record remain
unchanged. Findings with only an assessment-target fallback are marked as
assessment context rather than asserted affected assets.

The graph is stored inside the existing session JSON payload, so the SQLite
schema does not change. Older payloads load with an empty graph; exports rebuild
the projection from their saved results. All report formats use the same graph
summary. JSON has the complete graph; human-readable formats list up to 50 assets
and 75 relationships. Endpoint identity excludes credentials, query strings, and
fragments while preserving the path. DNS parsing currently recognizes structured
A, AAAA, and CNAME records and the equivalent bracketed text rows. The graph does
not establish verification, pin DNS, validate redirects, or compare sessions.

## Profile contract

| Profile | Selection and behavior |
| --- | --- |
| `passive` | Subfinder or tools explicitly assigned a passive mode; no direct target probe or downstream assessment. |
| `stealth` | Passive discovery plus a single-target HTTPX metadata check, one worker, no subdomain enrichment or web follow-up. It is limited, not invisible. |
| `standard` | Enabled recon and web categories; vulnerability-category tools excluded. |
| `full` | Enabled recon, web, and vulnerability-category tools. |
| `aggressive` | Full selection; Nmap uses the explicit ports 1–1024, T4, max-retries 1, and 120-second host timeout override; concurrency is capped at four. |

The `default` CLI alias resolves `default_profile` from settings before creating a
session. `profile_modes` can narrow tool selection; `profile_args` can override an
argument list. Preflight validates both fields.

## Execution outcomes

`success` means the process exited successfully, except Nikto exit code 1 is
accepted only with a complete scan summary and no stderr diagnostic. `failed`
preserves a nonzero process result that does not meet that exception. `missing`,
`misconfigured`, `skipped`, `scope_denied`, `timeout`, `cancelled`, `output_limited`,
and `error` distinguish availability, policy, and execution outcomes. `parse_error`
and `scoring_error` mean the process result remains
inspectable but a later stage failed. `retries` is opt-in (0–3); timeout retries
require explicit `retry_on_timeout: true`.

## Security boundaries and limitations

The configured allowlist is checked before scans and again before active
downstream probes. Active target names are resolved and every returned IP address
must also match an authorized IP or CIDR. Resolution errors and mixed-scope answers
fail closed. PhantomX does not pin the checked DNS answers into third-party
scanners, so DNS can change between validation and use. Shipped HTTP tool settings
disable redirects or limit Katana to the exact hostname; preflight rejects known
unsafe redirect-following options. These checks do not mediate redirects inside
custom tools or plugins. Subprocesses use argument lists and `shell=False`.

Process output is capped at 1 MiB per stream by default. Tool timeouts are bounded
to 1–3,600 seconds. Timeout and cancellation keep partial output and diagnostics;
cancellation attempts to terminate the process tree. `output_limited` means captured
output is incomplete and must not be interpreted as complete scanner coverage.

JSON deliberately retains raw session evidence and may therefore contain
credential-bearing URLs or query data. Human-readable formats remove URL
credentials, queries, and fragments. PDF uses built-in fonts and replaces text
outside their portable ASCII subset with readable placeholders. Adapters are
built in statically; trusted application setup can register an in-process adapter
through `AdapterManager.register`. Plugins are not auto-imported from disk or
discovered from the environment.

## Verification approach

Unit and synthetic integration tests mock scanner processes. They validate target
scope, failures, normalization, scoring, persistence, correlation, and exports
without launching scanners. Real tool availability depends on the host and is
reported by `preflight`; local controlled-lab integration is a separate step.
