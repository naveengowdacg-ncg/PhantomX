# Automated Cybersecurity Reconnaissance & Vulnerability Assessment Framework

Academic implementation starter inspired by the architecture and feature ideas documented in the GhostScan paper/repository. This project is an original implementation and does not copy GhostScan source code.

> Use only against systems you own or have explicit authorization to assess. Start with local VMs/lab targets.

## Design goals

- Modular tool orchestration: add/remove tools without changing the core.
- Adaptive assessment workflows: later stages can depend on earlier findings.
- Configurable risk scoring and correlation.
- Multiple assessment options/profiles.
- Consolidated JSON, Markdown and HTML reporting.
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

Next milestones: richer parsers, more wrappers, plugin discovery, correlation rules, PDF export, test fixtures, and optional GUI.
