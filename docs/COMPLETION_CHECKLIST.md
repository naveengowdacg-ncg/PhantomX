# PhantomX completion checklist

Status definitions: `DONE` means implemented and covered by an executed test or
inspection; `PARTIAL` means implemented but not fully validated or missing a
material boundary; `BLOCKED` means an external dependency or environment prevents
completion; `NOT DONE` means work remains. This checklist records the current
Windows implementation state after local validation; Kali integration remains
pending.

## 1. Architecture and code quality

001. Keep CLI, workflow, analysis, adapters, persistence, and reporting separated — **DONE**
002. Pass common session and tool-result models across package boundaries — **DONE**
003. Add automatic installed-plugin discovery (explicit registration API exists) — **NOT DONE**
004. Route production adapter-manager executions through configured shared process execution — **DONE**
005. Remove duplicate legacy subprocess implementations from direct specialized adapter APIs — **DONE**

## 2. CLI and user experience

006. Validate and set an authorized target before every assessment — **DONE**
007. List, add, remove, enable, and disable registered tools — **DONE**
008. Expose read-only tool preflight from the CLI — **DONE**
009. Run a single tool, a named profile, and the full-workflow alias — **DONE**
010. Restore sessions, inspect history/results, and export reports without losing live results — **DONE**

## 3. Configuration and tool registry

011. Load defaults and produce actionable errors for malformed settings — **DONE**
012. Validate profile modes and profile-specific argument overrides — **DONE**
013. Support bounded retries with timeout retries opt-in — **DONE**
014. Validate executable, argument list, timeout, retry count, and required files in preflight — **DONE**
015. Expose profile and retry controls through interactive `tools add` syntax — **DONE**

## 4. Scan profiles

016. Ensure passive mode selects only passive discovery tools and never launches target probes — **DONE**
017. Limit stealth to serial passive discovery and single-target HTTP metadata collection — **DONE**
018. Keep standard mode to recon and web categories, excluding vulnerability-category tools — **DONE**
019. Include all enabled categories in full mode — **DONE**
020. Give aggressive mode a bounded Nmap override and a four-worker cap distinct from full — **DONE**

## 5. Reconnaissance modules

021. Apply configured Nmap executable, arguments, timeout, and parser in the workflow path — **DONE**
022. Apply configured WhatWeb execution and parser while preserving nonzero/partial status — **DONE**
023. Handle Subfinder domain-only inputs and label results as unverified observations — **DONE**
024. Parse dnsx, HTTPX, Katana, testssl, and Gobuster output without calling it a confirmed vulnerability — **DONE**
025. Verify all optional integrations against installed tool versions in Kali — **BLOCKED**

## 6. Adaptive assessment workflow

026. Validate session target before discovery and active work — **DONE**
027. Derive web assessments only from successful discovery results — **DONE**
028. Revalidate discovered endpoints and hosts immediately before active probes — **DONE**
029. Keep successful peer results when a concurrent worker fails — **DONE**
030. Record skipped, missing, failed, and follow-up outcomes consistently — **DONE**

## 7. Scope enforcement and safety

031. Reject malformed targets, URLs, shell syntax, and unauthorized hosts — **DONE**
032. Fail closed when a workflow lacks scope validation for a newly discovered host — **DONE**
033. Use argument lists and `shell=False` in shared subprocess execution — **DONE**
034. Resolve active targets and constrain known redirect options; pin resolutions and validate every redirect destination — **PARTIAL**
035. Bound profile concurrency and cap subdomain enrichment — **DONE**

## 8. Process execution and error handling

036. Preserve timeout stdout/stderr and decode invalid bytes safely — **DONE**
037. Preserve partial output, return code, and diagnostics for process exceptions — **DONE**
038. Distinguish Nikto completed-exit-code-1 from incomplete/error output — **DONE**
039. Retry transient launch errors and explicitly opted-in timeout retries, at most three — **DONE**
040. Bound captured process output and add cancellation support — **DONE**

## 9. Output parsing and normalization

041. Parse Nmap TCP/UDP service rows and WhatWeb fingerprint rows — **DONE**
042. Parse Nuclei JSONL while skipping malformed and unexpected row shapes — **DONE**
043. Filter Nikto summary lines and retain evidence-backed observations — **DONE**
044. Deduplicate generated findings and refresh them idempotently after reload — **DONE**
045. Maintain versioned fixtures for every supported scanner output format — **PARTIAL**

## 10. Finding verification and confidence

046. Keep service discovery and technology fingerprints as zero-risk observations — **DONE**
047. Mark Nikto and Nuclei scanner matches as requiring verification — **DONE**
048. Add independent safe verification procedures or a reviewer workflow — **NOT DONE**
049. Preserve source, evidence, endpoint, verification state, and relevant metadata — **DONE**
050. Calibrate parser-assigned confidence values against validated lab findings — **NOT DONE**

## 11. Risk scoring and prioritization

051. Preserve approved score weights and severity thresholds — **DONE**
052. Validate score batches before mutation and support generator inputs — **DONE**
053. Store normalized inputs, contributions, final score, and severity breakdown — **DONE**
054. Keep observations at score zero/info when rescored — **DONE**
055. Validate model calibration with a labeled assessment corpus — **NOT DONE**

## 12. Correlation and deduplication

056. Correlate using specific CVE/template/endpoint identity instead of shared ports alone — **DONE**
057. Use the documented fixed 0.70/0.00 match indicator consistently — **DONE**
058. Preserve source tools, individual evidence, and conflicting verification states — **DONE**
059. Recompute correlation annotations without stale metadata — **DONE**
060. Persist a versioned graph linking domains, IPs, DNS records, services, endpoints, technologies, and findings — **DONE**

## 13. Sessions, persistence, and history

061. Save complete nested sessions transactionally in SQLite — **DONE**
062. Restore nested sessions and normalization provenance — **DONE**
063. List history with a bounded result limit — **DONE**
064. Add schema-versioned database migrations and recovery tooling — **NOT DONE**
065. Define retention, encryption, and backup policy for local assessment data — **NOT DONE**

## 14. Reporting and exports

066. Export full raw sessions and correlation summaries to valid JSON — **DONE**
067. Escape Markdown/HTML and redact URL credentials, queries, and fragments — **DONE**
068. Generate dependency-free, multipage PDF summaries — **DONE**
069. Constrain report filenames to the report directory with stable collision resistance — **DONE**
070. Validate report summary parity across all four formats using an external PDF validator — **DONE**

## 15. Logging and diagnostics

071. Log workflow starts, decisions, correlation summaries, and process outcomes — **DONE**
072. Preserve actionable parser, scoring, timeout, and persistence errors — **DONE**
073. Review every log path for URL-secret redaction and sensitive evidence leakage — **DONE**
074. Add log rotation and maximum log size — **NOT DONE**
075. Show a final per-tool executed/skipped/missing/failed summary in the CLI — **DONE**

## 16. Automated tests

076. Run the complete pytest suite after the current mission changes — **DONE**
077. Test profile selection, configured adapters, retries, and PDF writing — **DONE**
079. Exercise SQLite round-trip, update, and malformed session payload handling — **PARTIAL**
080. Add property-based or fuzz tests for target, parser, and report boundaries — **NOT DONE**

## 17. Integration testing

081. Test synthetic workflow-to-session-to-JSON/Markdown/HTML/PDF export — **DONE**
082. Run a bounded localhost assessment with a controlled local service — **DONE**
083. Run installed tool integrations on the current Windows host (Nmap loopback only; other configured scanners unavailable) — **PARTIAL**
084. Pull and run the transfer on Kali with its optional toolchain — **BLOCKED**
085. Measure concurrency, output growth, and timeout behavior under load — **NOT DONE**

## 18. Documentation

086. Document profile selection, score semantics, correlation, and data sensitivity — **DONE**
087. Document package boundaries, data flow, execution statuses, and limitations — **DONE**
088. Document installation, configuration, and optional tool preflight — **DONE**
089. Document common target, tool, process, and report troubleshooting — **DONE**
090. Publish a complete controlled-lab demonstration walkthrough with screenshots — **NOT DONE**

## 19. Installation and dependency management

091. Keep the core and PDF implementation standard-library-only — **DONE**
092. Explain that scanner executables are optional and separately installed — **DONE**
093. Declare and test the minimum supported Python version on Windows and Kali — **PARTIAL**
094. Add repeatable platform-specific installation/bootstrap scripts — **NOT DONE**
095. Add a package manifest and installable CLI entry point — **NOT DONE**

## 20. Packaging, release readiness, and final validation

096. Preserve all existing staged, unstaged, and untracked user changes — **DONE**
097. Run compilation, configuration, CLI, and full-suite validation — **DONE**
098. Run a configured linter/type checker or document its absence — **DONE**
099. Produce a reviewed release bundle and verify its checksum after final edits — **PARTIAL**
100. Treat GUI as a planned follow-up stage without implying it is implemented — **DONE**

## Remaining follow-up work

1. **P1 — Kali integration (blocked):** Apply the final Windows changes to a clean checkout at the expected base, then validate the installed versions of Subfinder, dnsx, HTTPX, Katana, testssl, Gobuster, WhatWeb, Nikto, and Nuclei. The Windows preflight cannot validate these Linux executables.
2. **P1 — Network boundary hardening:** Active target resolution now fails closed unless every answer is authorized, and preflight rejects known unsafe redirect flags. Still needed: pin those DNS answers into scanner connections and validate destinations for every redirect/custom tool (task 034).
3. **P2 — Finding confidence and verification:** Add safe independent verification/reviewer workflow and calibration against labeled lab findings (tasks 048, 050, 055).
4. **P2 — Regression depth:** Add versioned fixtures for every supported scanner format, broader malformed-input/property tests, load/concurrency coverage, and report-summary parity validation (tasks 045, 070, 079, 080, 085).
5. **P2 — Data lifecycle:** Add database migrations/recovery, retention/encryption/backup policy, and bounded log rotation (tasks 064, 065, 074).
5. **P2 — Installation:** Test Python 3.10+ on Windows and Kali and consider platform bootstrap steps and an installable package/CLI entry point (tasks 093–095).
7. **P3 — CLI/plugin polish:** Expose profile and retry settings in `tools add`; consider automatic plugin discovery only with an explicit trust model. The explicit in-process plugin registration API is implemented.
8. **P3 — Demonstration:** Prepare a controlled-lab walkthrough with screenshots and document the GUI as a planned stage (task 090; GUI scope is documented in task 100).

Windows validation has run the full pytest suite (247 tests), compile check, read-only preflight, CLI help, and a one-port Nmap workflow against a temporary HTTP service bound only to 127.0.0.1. JSON, Markdown, HTML, and PDF were generated; report escaping and raw-data preservation were checked synthetically. PDF structure and rendering were checked with Poppler. HTML escaping and structure were checked with Python's HTML parser; browser rendering was not visually inspected. Only Nmap was installed for the real scan; other optional scanners and Kali remain unverified.