import shlex
from pathlib import Path

from core.executor import ToolExecutor
from core.logger import get_logger
from core.models import Session
from core.tool_registry import ToolRegistry
from core.workflow import WorkflowEngine
from analysis.normalizer import Normalizer
from analysis.scoring import RiskEngine
from reporting.reporter import Reporter

BANNER = r"""
==============================================================
 Automated Cybersecurity Reconnaissance & Vulnerability
 Assessment Framework
==============================================================
 Type 'help' for commands. Use only on authorized targets.
"""

class App:
    def __init__(self):
        self.registry = ToolRegistry()
        self.logger = get_logger()
        self.executor = ToolExecutor(self.logger)
        self.normalizer = Normalizer()
        self.risk = RiskEngine()
        self.workflow = WorkflowEngine(self.registry, self.executor, self.normalizer, self.risk, self.logger)
        self.reporter = Reporter()
        self.target = None
        self.last_session = None

    def print_tools(self):
        for t in self.registry.list():
            state = "ON" if t.get("enabled", True) else "OFF"
            print(f"{t['name']:<12} {t['category']:<10} [{state}]  {t.get('description','')}")

    def help(self):
        print("""
Target / tools
  target <host>                              Set authorized target
  tools list                                 List registered tools
  tools add <name> <category> <exe> [args]   Add a tool; use {target} placeholder
  tools remove <name>                        Remove a tool from the registry
  tools enable <name>                        Enable a registered tool
  tools disable <name>                       Disable a registered tool

Assessment
  scan <tool>                                Run one registered tool
  scan profile <passive|standard|full>       Run a profile
  workflow full                              Run the full adaptive workflow

Reports
  report json|markdown|html|all              Generate report from last session
  help
  exit

Examples
  target 127.0.0.1
  scan nmap
  scan profile standard
  workflow full
  tools add custom recon myscanner --target {target} --safe-mode
  tools remove custom
""")

    def run_tool(self, name):
        if not self.target:
            print("Set a target first.")
            return
        tool = self.registry.get(name)
        if not tool:
            print(f"Unknown tool: {name}")
            return
        session = Session(self.target, f"single:{name}")
        result = self.normalizer.parse(self.executor.run(tool, self.target))
        result.findings = self.risk.score_all(result.findings)
        session.results.append(result)
        self.last_session = session
        print(f"{name}: {result.status}; normalized findings={len(result.findings)}")

    def run_profile(self, profile):
        if not self.target:
            print("Set a target first.")
            return
        if profile not in self.workflow.PROFILES:
            print("Profile must be passive, standard, or full.")
            return
        session = Session(self.target, profile)
        self.workflow.run(session)
        self.last_session = session
        print(f"Completed {profile}: {sum(len(r.findings) for r in session.results)} findings")
        print("Use 'report all' to export the session.")

    def reports(self, mode):
        if not self.last_session:
            print("No session available. Run a scan first.")
            return
        outputs = []
        if mode in {"json", "all"}: outputs.append(self.reporter.write_json(self.last_session))
        if mode in {"markdown", "all"}: outputs.append(self.reporter.write_markdown(self.last_session))
        if mode in {"html", "all"}: outputs.append(self.reporter.write_html(self.last_session))
        for p in outputs: print(f"Created: {p}")

    def dispatch(self, line):
        try:
            parts = shlex.split(line)
        except ValueError as e:
            print(f"Parse error: {e}"); return True
        if not parts: return True
        cmd = parts[0].lower()
        if cmd in {"exit", "quit"}: return False
        if cmd == "help": self.help(); return True
        if cmd == "target" and len(parts) == 2:
            self.target = parts[1]; print(f"Target set: {self.target}"); return True
        if cmd == "tools" and len(parts) >= 2:
            action = parts[1]
            try:
                if action == "list": self.print_tools()
                elif action == "remove" and len(parts) == 3: self.registry.remove(parts[2]); print("Tool removed.")
                elif action in {"enable", "disable"} and len(parts) == 3: self.registry.set_enabled(parts[2], action == "enable"); print(f"Tool {action}d.")
                elif action == "add" and len(parts) >= 5:
                    name, category, exe = parts[2:5]
                    args = parts[5:]
                    self.registry.add(name, category, exe, args)
                    print(f"Tool added: {name}")
                else: print("Invalid tools command. Use 'help'.")
            except ValueError as e: print(e)
            return True
        if cmd == "scan" and len(parts) == 2:
            if parts[1] == "profile": print("Use: scan profile <name>")
            else: self.run_tool(parts[1])
            return True
        if cmd == "scan" and len(parts) == 3 and parts[1] == "profile":
            self.run_profile(parts[2]); return True
        if cmd == "workflow" and len(parts) == 2 and parts[1] == "full":
            self.run_profile("full"); return True
        if cmd == "report" and len(parts) == 2:
            self.reports(parts[1]); return True
        print("Unknown command. Type 'help'.")
        return True

    def run(self):
        print(BANNER)
        while True:
            try: line = input("cybersec> ")
            except (EOFError, KeyboardInterrupt): print(); break
            if not self.dispatch(line): break

if __name__ == "__main__":
    App().run()
