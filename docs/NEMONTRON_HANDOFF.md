# Nemontron handoff: PhantomX

## Objective

Continue work in the Windows development checkout D:/phantomX. Complete scanner compatibility and validation, verify the GUI against the actual backend, and return exact evidence. The Kali machine is a test runtime only; do not copy the whole Windows repository to Kali.

## Preserve the existing checkout

The inspected HEAD was 0dc42fecc58d256039be9b545cd19dd5bccbd4ad on main. The checkout already contained a large mixture of staged, unstaged, and untracked user work before this task. Do not reset, clean, switch branches, stage, commit, push, or overwrite unrelated files. Start by recording git status and reviewing only the files you intend to touch.

Changes made in this task:

- Added gui.py and tests/test_gui.py.
- Added docs/GUI.md and this handoff.
- Added tools/kali_loopback_integration.py for real, scope-checked scanner execution over SSH.
- Changed DNSX input from -d to -l because this configured command consumes a host list; a regression test covers it. Added -duc to Nuclei, Subfinder, DNSX, HTTPX, and Katana so routine scans do not trigger background update checks; a config regression test covers these flags.
- All earlier user changes, including staged changes, remain in place.

## GUI behavior

Run python gui.py from D:/phantomX. It is connected to the existing application workflow and reporter. It supports target and allowlist validation, saved scope, scan profiles, selecting tools, local availability checks, start/cancel, live progress, findings and tool-run inspection, and JSON/Markdown/HTML/PDF export.

The GUI checks tools on the machine where it runs. The Windows preflight found Nmap available and the other nine scanners unavailable. Kali-installed tools are not automatically callable by the Windows GUI. If remote execution is intended, implement it as a deliberate backend runtime with scope enforcement and tests; do not present Kali tools as locally available.

## Kali runtime

The user installed the missing packages in the running Kali VM. The SSH host used for validation was the private VM address 192.168.31.188 and account kali. The VM has Nmap, WhatWeb, Nuclei, Nikto, Subfinder, dnsx, HTTPX, Katana, testssl, and Gobuster commands available. The Kali package exposes testssl as /usr/bin/testssl, while config/tools.json currently expects testssl.sh; the integration harness maps that name for the Kali test. Resolve the alias cleanly if the production Kali runtime must use this package.

No PhantomX checkout was copied to Kali. The harness used a temporary fixture under /tmp/phantomx-loopback-codex-mvp0me1l with HTTP on 127.0.0.1:18080, HTTPS on 127.0.0.1:18443, and a DNS responder on 127.0.0.1:15353. Every scanner target was localhost or 127.0.0.1; DNSX was pointed at the loopback resolver. Nuclei used a custom informational template against the local page, disabled update checks and Interactsh. Subfinder had all 52 available public providers excluded so it would not query outside services.

If the loopback services have stopped, restart them from a Kali terminal in the fixture folder. Do not start duplicates if the ports are already listening.

~~~bash
cd /tmp/phantomx-loopback-codex-mvp0me1l
nohup python3 server.py "$PWD" http >http.log 2>&1 &
echo $! >http.pid
nohup python3 server.py "$PWD" https cert.pem key.pem >https.log 2>&1 &
echo $! >https.pid
nohup python3 dns.py >dns.log 2>&1 &
echo $! >dns.pid
~~~

The server and DNS scripts bind only to 127.0.0.1. The fixture folder contains the local HTML, wordlist, self-signed certificate, and Nuclei template; no PhantomX source files are on Kali.
The temporary SSH key was created only on the Windows host and its private half was not placed in the repository. If another agent needs SSH access, create a fresh key and add only its public half to Kali authorized_keys. Never put the private key in the repository or in this handoff.

## Real integration evidence

The harness uses the real PhantomX ToolExecutor and AdapterManager, then the normalizer and risk scorer. DNSX and Subfinder are invoked through ToolExecutor directly because the production AuxiliaryAdapter intentionally skips localhost/IP targets for these domain-based tools; scope validation remains active. The harness uses a controlled temporary wordlist for Gobuster and removes local required-file checks only in its copied test configuration.

Successful backend runs against the loopback fixture:

- Nmap: identified 127.0.0.1 ports 18080/http and 18443/ssl with light service probes.
- WhatWeb: returned HTTP 200 and detected the local Python HTTP server and PhantomX Loopback Lab title.
- Nikto: completed in about 14 seconds and produced parsed findings from the deliberately simple local server.
- DNSX: resolved localhost to 127.0.0.1 and ::1 through the loopback DNS fixture.
- testssl: completed against 127.0.0.1:18443 and produced parsed TLS observations. Kali's actual executable is testssl.
- Gobuster: found the fixture's robots.txt, index.html, and admin path.

Unresolved real-tool results:

- Nuclei was invoked against the local page but timed out at the harness's 90-second limit with no parsed output.
- HTTPX repeatedly timed out against the local page. A direct diagnostic warned that its page-classifier model file (model.json) was missing.
- Katana repeatedly timed out against the local page.
- Subfinder exited with “No sources selected for this search” because all public providers were disabled. Do not re-enable public providers merely to obtain a green test; only run a domain-source test if a fully controlled local provider/fixture can be used.

The earlier first pass had Nmap's heavier default service probes time out and a harness-only invalid Nikto option. The successful retest used Nmap TCP connect/light service probes and removed the invalid Nikto option. Do not treat the earlier Nikto status as evidence.

## Validation on this checkpoint

- python -m pytest -q: 236 passed.
- python -m compileall -q .: passed.
- python -m tools.kali_loopback_integration --help: passed.
- git diff --check: passed; Git displayed only existing LF-to-CRLF configuration warnings.
- The GUI was compile-checked and unit-tested but not manually opened for visual verification.
## Continue and acceptance checklist

1. Record current HEAD and the complete staged/unstaged/untracked status before editing.
2. Run python -m pytest -q and python -m compileall -q . after changes.
3. Inspect and fix the Kali HTTPX packaging/model issue, Katana runtime timeout, and Nuclei timeout using only the fixture. Keep remote process limits and update checks disabled.
4. Keep Subfinder safe: the localhost-only test must not contact public providers. Document an expected skip if no controlled provider fixture exists.
5. Resolve the testssl.sh/testssl executable difference without breaking supported platforms.
6. Manually open and verify the Tk GUI on Windows. Verify real execution, cancellation, scope denial, tool availability, results, and report export. Do not claim visual verification unless performed.
7. Review the exact final diff and confirm all pre-existing staged and unstaged changes remain untouched. Do not stage, commit, or push.

To rerun the loopback harness from D:/phantomX, obtain a fresh SSH key and trusted known-hosts file, make the loopback fixture available on Kali, then use:

~~~powershell
python -m tools.kali_loopback_integration --ssh-host <KALI_PRIVATE_IP> --ssh-user kali --ssh-key <PRIVATE_KEY_FILE> --known-hosts <KNOWN_HOSTS_FILE> --lab-root /tmp/phantomx-loopback-codex-mvp0me1l
~~~

For a focused rerun, append --only followed by selected scanner names, for example: nuclei httpx katana.