import shlex
import sys
import threading
import time

from core.adapter_manager import AdapterManager
from core.executor import ToolExecutor
from core.logger import get_logger
from core.models import Session, ToolResult
from datetime import datetime, timezone
from core.tool_registry import ToolRegistry
from core.preflight import ToolPreflight
from core.workflow import WorkflowEngine

from analysis.normalizer import Normalizer
from analysis.scoring import RiskEngine

from reporting.reporter import Reporter
from core.settings import load_settings
from core.scope import TargetScope, TargetScopeError
from core.storage import SQLiteSessionStore


BANNER = r"""
==============================================================
 Automated Cybersecurity Reconnaissance & Vulnerability
 Assessment Framework
==============================================================
 Type 'help' for commands. Use only on authorized targets.
"""


class App:
    def show_loading(self, message, stop_event):
        """Display a simple live spinner while an operation is running."""
        spinner = ["|", "/", "-", "\\"]
        index = 0

        while not stop_event.is_set():
            sys.stdout.write(
                f"\r{message} {spinner[index % len(spinner)]}"
            )
            sys.stdout.flush()

            index += 1
            time.sleep(0.15)

        sys.stdout.write("\r" + " " * (len(message) + 2) + "\r")
        sys.stdout.flush()

    def run_with_loading(self, message, function):
        """Run a function while displaying a live loading indicator."""
        stop_event = threading.Event()

        loading_thread = threading.Thread(
            target=self.show_loading,
            args=(message, stop_event),
            daemon=True
        )

        loading_thread.start()

        try:
            return function()
        finally:
            stop_event.set()
            loading_thread.join()

    def __init__(self, settings_path="config/settings.json"):
        self.settings = load_settings(settings_path)
        self.scope = TargetScope(
            scope_required=self.settings["scope_required"],
            authorized_targets=self.settings["authorized_targets"],
        )
        self.registry = ToolRegistry()
        self.tool_preflight = ToolPreflight()
        self.logger = get_logger(self.settings["reports_dir"])
        self.executor = ToolExecutor(self.logger, scope=self.scope)
        self.adapter_manager = AdapterManager()
        self.normalizer = Normalizer()
        self.risk = RiskEngine()

        self.workflow = WorkflowEngine(
            self.registry,
            self.executor,
            self.adapter_manager,
            self.normalizer,
            self.risk,
            self.logger,
            max_workers=self.settings["max_workers"],
            scope=self.scope,
        )

        self.reporter = Reporter(
            reports_dir=self.settings["reports_dir"]
        )

        self.storage = SQLiteSessionStore("data/phantomx.sqlite3")
        self.target = None
        self.last_session = None

    def print_tools(self):
        for t in self.registry.list():
            if not isinstance(t, dict):
                continue
            state = "ON" if t.get("enabled", True) else "OFF"

            print(
                f"{t.get('name', '<unnamed>'):<12} "
                f"{t.get('category', '<unknown>'):<10} "
                f"[{state}]  "
                f"{t.get('description', '')}"
            )

    def preflight_tools(self):
        """Display read-only readiness checks for enabled external tools."""
        results = self.tool_preflight.inspect(
            self.registry.list(),
            registry_error=getattr(self.registry, "load_error", None),
        )
        if not results:
            print("No enabled tools are configured.")
            return
        print("\nTOOL PREFLIGHT")
        for result in results:
            print(
                f"[{result['status'].upper()}] {result['name']}: "
                f"{result['message']}"
            )
    def status(self):
        print("\n" + "=" * 60)
        print("PHANTOMX STATUS")
        print("=" * 60)

        if not self.last_session:
            print("Target       : Not scanned")
            print("Last tool    : None")
            print("Last status  : None")
            print("Services     : 0")
            print("Findings     : 0")
            print("Correlation  : 0 groups")
            print("=" * 60)
            return

        session = self.last_session

        total_services = sum(
            len(result.services)
            for result in session.results
        )

        total_findings = sum(
            len(result.findings)
            for result in session.results
        )

        print(f"Session      : {session.session_id}")
        print(f"Target       : {session.target}")
        print(f"Profile      : {session.profile}")

        if session.results:
            last_result = session.results[-1]

            print(f"Last tool    : {last_result.tool}")
            print(f"Last status  : {last_result.status}")

        print(f"Tools run    : {len(session.results)}")
        print(f"Services     : {total_services}")
        print(f"Findings     : {total_findings}")

        print("=" * 60)

    def results(self, tool_name=None):
        if not self.last_session:
            print("\nNo results available. Run a scan first.")
            return

        if tool_name:
            self.detailed_results(tool_name)
            return

        print("\n" + "=" * 60)
        print("PHANTOMX RESULTS")
        print("=" * 60)

        for result in self.last_session.results:

            print(
                f"\nTool: {result.tool}"
                f"\nStatus: {result.status}"
                f"\nTarget: {result.target}"
            )

            if result.services:
                print("\nServices:")

                for service in result.services:
                    print(
                        f"  {service.port}/{service.protocol} "
                        f"{service.state:<8} "
                        f"{service.service:<15} "
                        f"{service.version}"
                    )

            if result.endpoints:
                print("\nEndpoints:")

                for endpoint in result.endpoints:
                    print(
                        f"  {endpoint.url}"
                        f" | Source: {endpoint.source_tool}"
                        f" | Port: {endpoint.port}"
                    )

            if result.observations:
                print("\nObservations:")

                for observation in result.observations:
                    endpoint_url = (
                        observation.endpoint.url
                        if observation.endpoint
                        else "N/A"
                    )

                    print(
                        f"  {observation.title}"
                        f" | Source: {observation.source_tool}"
                        f" | Endpoint: {endpoint_url}"
                    )

                    if observation.evidence:
                        print(
                            f"    Evidence: {observation.evidence}"
                        )

            if result.findings:
                print("\nFindings:")

                for finding in result.findings:
                    scanner_severity = (
                        f" | Scanner: "
                        f"{finding.scanner_severity.upper()}"
                        if finding.scanner_severity
                        else ""
                    )

                    print(
                        f"  [{finding.severity.upper():<8}] "
                        f"{finding.title}"
                        f"{scanner_severity}"
                        f" | Score: {finding.score:.1f}"
                    )

        print("\n" + "=" * 60)

    def detailed_results(self, tool_name):
        tool_name = tool_name.lower()

        matching_results = [
            result
            for result in self.last_session.results
            if result.tool.lower() == tool_name
        ]

        if not matching_results:
            print(
                f"\nNo results found for tool: {tool_name}"
            )
            return

        print("\n" + "=" * 70)
        print(
            f"PHANTOMX DETAILED RESULTS — "
            f"{tool_name.upper()}"
        )
        print("=" * 70)

        for result in matching_results:

            print(f"\nTool          : {result.tool}")
            print(f"Status        : {result.status}")
            print(f"Target        : {result.target}")
            print(f"Return code   : {result.return_code}")
            print(
                f"Duration      : "
                f"{result.duration_seconds:.3f}s"
            )

            if result.command:
                print(
                    "\nCommand       : "
                    + " ".join(result.command)
                )

            if result.services:
                print("\n--- SERVICES ---")

                for service in result.services:
                    print(
                        f"  {service.port}/{service.protocol} "
                        f"{service.state:<8} "
                        f"{service.service:<15} "
                        f"{service.version}"
                    )

            if result.endpoints:
                print("\n--- ENDPOINTS ---")

                for endpoint in result.endpoints:
                    print(f"  URL       : {endpoint.url}")
                    print(
                        f"  Source    : "
                        f"{endpoint.source_tool}"
                    )
                    print(f"  Host      : {endpoint.host}")
                    print(f"  Port      : {endpoint.port}")

            if result.observations:
                print("\n--- OBSERVATIONS ---")

                for observation in result.observations:
                    print(
                        f"\n  Title      : "
                        f"{observation.title}"
                    )
                    print(
                        f"  Category   : "
                        f"{observation.category}"
                    )
                    print(
                        f"  Source     : "
                        f"{observation.source_tool}"
                    )
                    print(
                        f"  Confidence : "
                        f"{observation.confidence}"
                    )

                    if observation.evidence:
                        print(
                            f"  Evidence   : "
                            f"{observation.evidence}"
                        )

            if result.findings:
                print("\n--- FINDINGS ---")

                for finding in result.findings:

                    print(
                        f"\n  Title              : "
                        f"{finding.title}"
                    )
                    print(
                        f"  Category           : "
                        f"{finding.category}"
                    )
                    print(
                        f"  PhantomX Severity  : "
                        f"{finding.severity.upper()}"
                    )

                    if finding.scanner_severity:
                        print(
                            f"  Scanner Severity   : "
                            f"{finding.scanner_severity.upper()}"
                        )

                    print(
                        f"  Risk Score         : "
                        f"{finding.score:.1f}"
                    )
                    print(
                        f"  Confidence         : "
                        f"{finding.confidence}"
                    )
                    print(
                        f"  Source             : "
                        f"{finding.source_tool}"
                    )

                    if finding.evidence:
                        print(
                            f"  Evidence           : "
                            f"{finding.evidence}"
                        )

                    if finding.recommendation:
                        print(
                            f"  Recommendation     : "
                            f"{finding.recommendation}"
                        )

                    if finding.metadata:
                        print(
                            "  Metadata           :"
                        )

                        for key, value in finding.metadata.items():
                            print(
                                f"    {key}: {value}"
                            )

            if result.stderr:
                print("\n--- STDERR ---")
                print(result.stderr)

            print("\n--- RAW STDOUT ---")
            print(result.stdout)

        print("\n" + "=" * 70)

    def help(self):
        print("""
Target / tools
  target <host>                              Set authorized target
  preflight                                   Check enabled tool executables and files
  tools list                                 List registered tools
  tools add <name> <category> <exe> [args...]
      [--timeout <seconds>] [--retries <0-3>]
      [--retry-on-timeout <true|false>] [--description <text>]
      [--profile-modes <mode1,mode2,...>]
      [--profile-args <mode:arg1,arg2,...> ...]
      Add a tool; use {target} placeholder in args
  tools remove <name>                        Remove a tool from the registry
  tools enable <name>                        Enable a registered tool
  tools disable <name>                       Disable a registered tool

Assessment
  scan <tool>                                Run one registered tool
  scan profile <passive|stealth|standard|full|aggressive|default>  Run a profile
  workflow full                              Run the full adaptive workflow
  passive: Subfinder only; stealth: serial Subfinder + single-target HTTPX
  standard: recon/web; full: all categories; aggressive: bounded wider Nmap scan

Reports
  report json|markdown|html|pdf|all           Generate report from last session
  history [limit]                            List saved assessments
  load <session_id>                          Restore a saved assessment
  status                                     Show current PhantomX status
  results                                    Show consolidated findings
  results <tool>                             Show detailed results for a tool
  help
  exit

Examples
  target 127.0.0.1
  scan nmap
  scan profile standard
  workflow full
  tools add custom recon myscanner --target {target} --safe-mode
  tools add mytool web myscanner -u {target} --timeout 180 --retries 1 --retry-on-timeout true --description "My custom web scanner"
  tools add mytool vuln myscanner -t {target} --profile-modes standard,full --profile-args full:-deep-scan,{target}
  tools remove custom
""")

    def _validated_target(self):
        """Revalidate the current target immediately before any scan."""
        if not self.target:
            print("Set a target first.")
            return None
        try:
            return self.scope.validate(self.target)
        except TargetScopeError as exc:
            print(f"Target rejected: {exc}")
            return None

    def persist_session(self, session):
        """Save a completed session without losing live results on DB errors."""
        try:
            self.storage.save(session)
            print(f"[+] Assessment saved: {session.session_id}")
        except Exception as exc:
            self.logger.exception("Failed to persist assessment session")
            print(f"[!] Could not save assessment history: {exc}")

    def show_history(self, limit=20):
        try:
            sessions = self.storage.list_sessions(limit)
        except Exception as exc:
            print(f"Could not read assessment history: {exc}")
            return
        if not sessions:
            print("No saved assessments yet.")
            return
        print("\nSAVED ASSESSMENTS")
        print("-" * 92)
        print(f"{'SESSION ID':<25} {'TARGET':<20} {'PROFILE':<16} {'STARTED AT'}")
        for item in sessions:
            print(
                f"{item['session_id']:<25} {item['target']:<20} "
                f"{item['profile']:<16} {item['started_at']}"
            )

    def load_saved_session(self, session_id):
        try:
            session = self.storage.load(session_id)
        except Exception as exc:
            print(f"Could not load saved assessment: {exc}")
            return
        if session is None:
            print(f"Assessment not found: {session_id}")
            return
        self.last_session = session
        self.target = session.target
        print(
            f"Loaded assessment {session.session_id} "
            f"({session.target}, profile={session.profile}, "
            f"results={len(session.results)})."
        )
    def run_tool(self, name):
        target = self._validated_target()
        if target is None:
            return

        tool = self.registry.get(name)

        if not tool:
            print(f"Unknown tool: {name}")
            return

        if not tool.get("enabled", True):
            print(f"Tool is disabled: {name}")
            return

        session = Session(
            target,
            f"single:{name}"
        )

        print(f"\n[+] Running {name} against {target}...")
        started_at = datetime.now(timezone.utc).isoformat()
        start_time = time.perf_counter()

        try:
            result = self.adapter_manager.run(
                tool,
                target,
                self.executor,
            )
        except Exception as exc:
            result = ToolResult(
                tool=name,
                category=tool.get("category", "unknown"),
                target=target,
                started_at=started_at,
                finished_at=datetime.now(timezone.utc).isoformat(),
                return_code=None,
                duration_seconds=round(time.perf_counter() - start_time, 3),
                status="error",
                command=(
                    [tool["executable"]]
                    if isinstance(tool.get("executable"), str)
                    and tool["executable"]
                    else []
                ),
                stderr=f"Tool execution failed ({type(exc).__name__}): {exc}",
            )
            self.logger.exception("Direct scan of %s failed: %s", name, exc)

        try:
            result = self.normalizer.parse(result)
        except Exception as exc:
            result.status = "parse_error"
            result.stderr = "\n".join(
                item for item in (result.stderr, f"Normalization failed: {exc}") if item
            )
            self.logger.exception("Direct scan normalization for %s failed: %s", name, exc)
        else:
            try:
                result.findings = self.risk.score_all(result.findings)
            except Exception as exc:
                result.status = "scoring_error"
                result.stderr = "\n".join(
                    item for item in (result.stderr, f"Finding scoring failed: {exc}") if item
                )
                self.logger.exception("Direct scan scoring for %s failed: %s", name, exc)

        # Preserve captured output and findings even when later processing fails.
        session.results.append(result)
        self.workflow._correlate_session_findings(session)

        self.last_session = session
        self.persist_session(session)

        print("\n[+] Scan completed.")
        print(f"Tool: {result.tool}")
        print(f"Status: {result.status}")
        print(
            f"Duration: "
            f"{result.duration_seconds:.3f}s"
        )

        if result.services:

            print(
                f"Services discovered: "
                f"{len(result.services)}"
            )

            print("\n--- SERVICES ---")

            for service in result.services:
                print(
                    f"{service.port}/{service.protocol}  "
                    f"{service.state:<8} "
                    f"{service.service:<15} "
                    f"{service.version}"
                )

        print(
            f"\nNormalized findings: "
            f"{len(result.findings)}"
        )

    def run_profile(self, profile):
        target = self._validated_target()
        if target is None:
            return

        if profile == "default":
            profile = self.settings["default_profile"]

        if (
            profile not in self.workflow.PROFILES
            or profile not in self.settings["allowed_profiles"]
        ):
            allowed = ", ".join(self.settings["allowed_profiles"])
            print(f"Profile must be one of: {allowed}.")
            return

        session = Session(
            target,
            profile
        )

        self.workflow.run(session)

        self.last_session = session
        self.persist_session(session)

        total_findings = sum(
            len(r.findings)
            for r in session.results
        )

        print(
            f"Completed {profile}: "
            f"{total_findings} findings"
        )
        self.print_execution_summary(session)

        print(
            "Use 'report all' to export the session."
        )

    @staticmethod
    def print_execution_summary(session):
        """Show the final per-status outcome counts, including unavailable tools."""
        counts = {}
        for result in session.results:
            status = "unavailable" if result.status == "missing" else result.status
            counts[status] = counts.get(status, 0) + 1
        if not counts:
            print("Tool outcomes: no tools executed.")
            return
        order = (
            "success", "skipped", "unavailable", "failed", "timeout",
            "error", "parse_error", "scoring_error",
        )
        summary = ", ".join(
            f"{name}={counts[name]}" for name in order if counts.get(name)
        )
        other = sorted(set(counts) - set(order))
        if other:
            summary += ", " + ", ".join(f"{name}={counts[name]}" for name in other)
        print(f"Tool outcomes: {summary}")

    def reports(self, mode):

        if not self.last_session:
            print(
                "No session available. "
                "Run a scan first."
            )
            return

        writers = {
            "json": self.reporter.write_json,
            "markdown": self.reporter.write_markdown,
            "html": self.reporter.write_html,
            "pdf": self.reporter.write_pdf,
        }
        selected = writers.items() if mode == "all" else [(mode, writers.get(mode))]
        for name, writer in selected:
            if writer is None:
                print("Usage: report json|markdown|html|pdf|all")
                return
            try:
                print(f"Created: {writer(self.last_session)}")
            except Exception as exc:
                self.logger.exception("Could not write %s report: %s", name, exc)
                print(f"[!] Could not write {name} report: {exc}")

    def dispatch(self, line):

        try:
            parts = shlex.split(line)

        except ValueError as e:
            print(f"Parse error: {e}")
            return True

        if not parts:
            return True

        cmd = parts[0].lower()

        if cmd in {"exit", "quit"}:
            return False

        if cmd == "help":
            self.help()
            return True

        if cmd == "preflight":
            self.preflight_tools()
            return True

        if cmd == "status":
            self.status()
            return True

        if cmd == "history":
            if len(parts) > 2:
                print("Usage: history [limit]")
            else:
                try:
                    limit = int(parts[1]) if len(parts) == 2 else 20
                    self.show_history(limit)
                except ValueError:
                    print("History limit must be an integer.")
            return True

        if cmd == "load" and len(parts) == 2:
            self.load_saved_session(parts[1])
            return True

        if cmd == "results":
            if len(parts) == 1:
                self.results()
            elif len(parts) == 2:
                self.results(parts[1])
            else:
                print("Usage: results [tool]")
            return True

        if cmd == "target" and len(parts) == 2:
            try:
                validated = self.scope.validate(parts[1])
            except TargetScopeError as exc:
                print(f"Target rejected: {exc}")
                return True

            self.target = validated
            print(f"Target set: {self.target}")
            return True

        if cmd == "tools" and len(parts) >= 2:

            action = parts[1]

            try:

                if action == "list":
                    self.print_tools()

                elif action == "remove" and len(parts) == 3:
                    self.registry.remove(parts[2])
                    print("Tool removed.")

                elif (
                    action in {"enable", "disable"}
                    and len(parts) == 3
                ):
                    self.registry.set_enabled(
                        parts[2],
                        action == "enable"
                    )

                    print(
                        f"Tool {action}d."
                    )

                elif action == "add" and len(parts) >= 5:

                    name, category, exe = parts[2:5]
                    remaining = parts[5:]

                    # Parse optional flags
                    args = []
                    timeout = 120
                    retries = 0
                    retry_on_timeout = False
                    description = ""
                    profile_modes = None
                    profile_args = None

                    i = 0
                    while i < len(remaining):
                        token = remaining[i]
                        if token == "--timeout" and i + 1 < len(remaining):
                            try:
                                timeout = int(remaining[i + 1])
                                i += 2
                            except ValueError:
                                print("Invalid timeout value")
                                return True
                        elif token == "--retries" and i + 1 < len(remaining):
                            try:
                                retries = int(remaining[i + 1])
                                if not 0 <= retries <= 3:
                                    print("Retries must be 0-3")
                                    return True
                                i += 2
                            except ValueError:
                                print("Invalid retries value")
                                return True
                        elif token == "--retry-on-timeout" and i + 1 < len(remaining):
                            val = remaining[i + 1].lower()
                            if val not in ("true", "false"):
                                print("retry-on-timeout must be true or false")
                                return True
                            retry_on_timeout = val == "true"
                            i += 2
                        elif token == "--description" and i + 1 < len(remaining):
                            description = remaining[i + 1]
                            i += 2
                        elif token == "--profile-modes" and i + 1 < len(remaining):
                            modes = remaining[i + 1].split(",")
                            for m in modes:
                                if m not in self.settings["allowed_profiles"]:
                                    print(f"Unknown profile mode: {m}")
                                    return True
                            profile_modes = modes
                            i += 2
                        elif token == "--profile-args" and i + 1 < len(remaining):
                            # Format: mode:arg1,arg2,...
                            pa = remaining[i + 1]
                            if ":" not in pa:
                                print("Profile args format: mode:arg1,arg2,...")
                                return True
                            mode, argstr = pa.split(":", 1)
                            if mode not in self.settings["allowed_profiles"]:
                                print(f"Unknown profile mode: {mode}")
                                return True
                            if profile_args is None:
                                profile_args = {}
                            profile_args[mode] = argstr.split(",")
                            i += 2
                        else:
                            args.append(token)
                            i += 1

                    self.registry.add(
                        name,
                        category,
                        exe,
                        args,
                        timeout=timeout,
                        description=description,
                        retries=retries,
                        retry_on_timeout=retry_on_timeout,
                    )

                    # Update profile_modes and profile_args if provided
                    if profile_modes is not None or profile_args is not None:
                        tool = self.registry.get(name)
                        if tool:
                            if profile_modes is not None:
                                tool["profile_modes"] = profile_modes
                            if profile_args is not None:
                                tool["profile_args"] = profile_args
                            self.registry._save(self.registry.data)

                    print(
                        f"Tool added: {name}"
                    )

                else:
                    print(
                        "Invalid tools command. "
                        "Use 'help'."
                    )

            except ValueError as e:
                print(e)

            return True

        if cmd == "scan" and len(parts) == 2:

            if parts[1] == "profile":
                print(
                    "Use: scan profile <name>"
                )

            else:
                self.run_tool(parts[1])

            return True

        if (
            cmd == "scan"
            and len(parts) == 3
            and parts[1] == "profile"
        ):
            self.run_profile(parts[2])
            return True

        if (
            cmd == "workflow"
            and len(parts) == 2
            and parts[1] == "full"
        ):
            self.run_profile("full")
            return True

        if cmd == "history":
            if len(parts) == 1:
                self.show_history()
            elif len(parts) == 2 and parts[1].isdigit():
                self.show_history(int(parts[1]))
            else:
                print("Usage: history [limit]")
            return True

        if cmd == "load" and len(parts) == 2:
            self.load_saved_session(parts[1])
            return True
        if cmd == "report" and len(parts) == 2:
            if parts[1] not in {"json", "markdown", "html", "pdf", "all"}:
                print("Usage: report json|markdown|html|pdf|all")
            else:
                self.reports(parts[1])
            return True

        print(
            "Unknown command. Type 'help'."
        )

        return True

    def run(self):

        print(BANNER)

        while True:

            try:
                line = input("phantomx> ")

            except (EOFError, KeyboardInterrupt):
                print()
                break

            try:
                should_continue = self.dispatch(line)
            except Exception as exc:
                logger = getattr(self, "logger", None)
                log_exception = getattr(logger, "exception", None)
                if callable(log_exception):
                    log_exception("CLI command failed: %s", exc)
                print(f"Command failed safely ({type(exc).__name__}): {exc}")
                continue
            if not should_continue:
                break


if __name__ == "__main__":
    App().run()
