"""Tkinter desktop interface for the existing PhantomX assessment backend."""

import copy
import json
import os
import queue
import tempfile
import threading
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk

from core.models import Session
from core.scope import TargetScope
from core.settings import load_settings
from main import App


BASE_DIR = Path(__file__).resolve().parent
SETTINGS_FILE = BASE_DIR / "config" / "settings.json"


def validate_scope_configuration(settings, scope_required, authorized_targets):
    """Normalize scope settings through the backend's existing validator."""
    candidate = dict(settings)
    candidate["scope_required"] = bool(scope_required)
    candidate["authorized_targets"] = list(authorized_targets)
    with tempfile.TemporaryDirectory(prefix="phantomx-scope-") as directory:
        path = Path(directory) / "settings.json"
        path.write_text(json.dumps(candidate, indent=2), encoding="utf-8")
        return load_settings(path)


def build_scope(settings, target, scope_required, authorized_targets):
    """Build a real TargetScope and validate a target against it."""
    validated = validate_scope_configuration(settings, scope_required, authorized_targets)
    scope = TargetScope(validated["scope_required"], validated["authorized_targets"])
    return validated, scope, scope.validate(target)


class SelectedToolRegistry:
    """Apply the GUI's per-run tool selection without changing the saved registry."""

    def __init__(self, tools, selected_names):
        selected_names = set(selected_names)
        self._tools = copy.deepcopy(list(tools))
        for tool in self._tools:
            if isinstance(tool, dict):
                name = tool.get("name")
                tool["enabled"] = isinstance(name, str) and name in selected_names

    def list(self):
        return self._tools


class ObservedAdapterManager:
    """Delegate to real adapters and publish their actual start/finish events."""

    def __init__(self, delegate, event_queue):
        self.delegate = delegate
        self.events = event_queue
        self.counter = 0
        self.lock = threading.Lock()

    def run(self, tool, target, *args, **kwargs):
        with self.lock:
            self.counter += 1
            run_id = str(self.counter)
        name = tool.get("name", "unknown") if isinstance(tool, dict) else "unknown"
        self.events.put(("started", run_id, name, target))
        try:
            result = self.delegate.run(tool, target, *args, **kwargs)
        except Exception as exc:
            self.events.put(("failed", run_id, name, target, str(exc)))
            raise
        self.events.put(("finished", run_id, result))
        return result


class PhantomXGUI:
    """Desktop controls and live views for actual PhantomX assessment sessions."""

    COLORS = {
        "background": "#0b1220",
        "panel": "#111b2e",
        "field": "#17243a",
        "text": "#e7eef8",
        "muted": "#9cafc7",
        "accent": "#59d7bd",
        "accent_dark": "#153d3a",
        "warning": "#edc16b",
        "danger": "#f17878",
    }

    def __init__(self, root, backend=None):
        self.root = root
        self.backend = backend or App(str(SETTINGS_FILE))
        self.events = queue.Queue()
        self.run_thread = None
        self.current_session = None
        self.finding_rows = {}
        self.completed_runs = 0
        self.close_when_idle = False
        self.tool_vars = {}
        self.tool_checks = []
        self.tool_status_labels = {}

        self.root.title("PhantomX — Assessment Console")
        self.root.geometry("1280x830")
        self.root.minsize(1060, 700)
        self.root.configure(background=self.COLORS["background"])
        self._style()
        self._build()
        self._refresh_availability()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._drain_events)

    def _style(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=self.COLORS["panel"], foreground=self.COLORS["text"], fieldbackground=self.COLORS["field"], font=("Segoe UI", 10))
        style.configure("TFrame", background=self.COLORS["background"])
        style.configure("Panel.TFrame", background=self.COLORS["panel"])
        style.configure("TLabel", background=self.COLORS["panel"], foreground=self.COLORS["text"])
        style.configure("Muted.TLabel", background=self.COLORS["panel"], foreground=self.COLORS["muted"])
        style.configure("Title.TLabel", background=self.COLORS["background"], foreground=self.COLORS["text"], font=("Segoe UI Semibold", 20))
        style.configure("Section.TLabel", background=self.COLORS["panel"], foreground=self.COLORS["accent"], font=("Segoe UI Semibold", 11))
        style.configure("TButton", background=self.COLORS["field"], foreground=self.COLORS["text"], padding=(10, 7))
        style.map("TButton", background=[("active", "#223653"), ("disabled", "#182338")])
        style.configure("Accent.TButton", background=self.COLORS["accent_dark"], foreground=self.COLORS["accent"])
        style.configure("Danger.TButton", background="#48272d", foreground="#ffdada")
        style.configure("TCheckbutton", background=self.COLORS["panel"], foreground=self.COLORS["text"])
        style.configure("TCombobox", fieldbackground=self.COLORS["field"], background=self.COLORS["field"])
        style.configure("Treeview", background=self.COLORS["field"], fieldbackground=self.COLORS["field"], foreground=self.COLORS["text"], rowheight=27)
        style.configure("Treeview.Heading", background="#1c2b43", foreground=self.COLORS["muted"], relief="flat")
        style.map("Treeview", background=[("selected", "#24544f")])
        style.configure("TNotebook", background=self.COLORS["background"], borderwidth=0)
        style.configure("TNotebook.Tab", background=self.COLORS["panel"], foreground=self.COLORS["muted"], padding=(14, 8))
        style.map("TNotebook.Tab", background=[("selected", self.COLORS["field"])], foreground=[("selected", self.COLORS["accent"])])
        style.configure("Horizontal.TProgressbar", background=self.COLORS["accent"], troughcolor=self.COLORS["field"])

    def _panel(self, parent, **grid_options):
        panel = ttk.Frame(parent, style="Panel.TFrame", padding=14)
        panel.grid(**grid_options)
        return panel

    def _build(self):
        outer = ttk.Frame(self.root, padding=18)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 14))
        ttk.Label(header, text="PhantomX", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="AUTHORIZED ASSESSMENT WORKSPACE", style="Muted.TLabel").pack(side="left", padx=(14, 0), pady=(8, 0))
        self.header_status = ttk.Label(header, text="Ready", style="Muted.TLabel")
        self.header_status.pack(side="right", pady=(8, 0))

        content = ttk.Frame(outer)
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=0, minsize=350)
        content.columnconfigure(1, weight=1)
        content.rowconfigure(0, weight=1)

        left = ttk.Frame(content)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(2, weight=1)

        scope = self._panel(left, row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(scope, text="Scope", style="Section.TLabel").pack(anchor="w", pady=(0, 8))
        ttk.Label(scope, text="Target host or IP").pack(anchor="w")
        self.target_var = tk.StringVar(value="127.0.0.1")
        self.target_entry = ttk.Entry(scope, textvariable=self.target_var)
        self.target_entry.pack(fill="x", pady=(4, 8))
        self.scope_required_var = tk.BooleanVar(value=self.backend.settings["scope_required"])
        self.scope_check = ttk.Checkbutton(scope, text="Require target to match authorized list", variable=self.scope_required_var)
        self.scope_check.pack(anchor="w", pady=(0, 8))
        ttk.Label(scope, text="Hosts, IPs, CIDRs, or *.domain (one per line)", style="Muted.TLabel").pack(anchor="w")
        self.authorized_text = tk.Text(scope, height=4, wrap="none", background=self.COLORS["field"], foreground=self.COLORS["text"], insertbackground=self.COLORS["accent"], relief="flat", padx=8, pady=7, font=("Consolas", 9))
        self.authorized_text.pack(fill="x", pady=(4, 8))
        self.authorized_text.insert("1.0", "\n".join(self.backend.settings.get("authorized_targets", [])))
        scope_actions = ttk.Frame(scope, style="Panel.TFrame")
        scope_actions.pack(fill="x")
        self.validate_button = ttk.Button(scope_actions, text="Validate", command=self._validate_scope)
        self.validate_button.pack(side="left")
        self.save_scope_button = ttk.Button(scope_actions, text="Save scope", command=self._save_scope)
        self.save_scope_button.pack(side="left", padx=(7, 0))

        profile = self._panel(left, row=1, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(profile, text="Assessment profile", style="Section.TLabel").pack(anchor="w", pady=(0, 8))
        self.profile_var = tk.StringVar(value=self.backend.settings["default_profile"])
        self.profile_combo = ttk.Combobox(profile, textvariable=self.profile_var, state="readonly", values=self.backend.settings["allowed_profiles"])
        self.profile_combo.pack(fill="x")
        self.profile_combo.bind("<<ComboboxSelected>>", self._profile_changed)
        self.profile_description = ttk.Label(profile, text="", style="Muted.TLabel", wraplength=310, justify="left")
        self.profile_description.pack(anchor="w", pady=(7, 0))
        self._profile_changed()

        tools_panel = self._panel(left, row=2, column=0, sticky="nsew", pady=(0, 10))
        tools_panel.columnconfigure(0, weight=1)
        tools_panel.rowconfigure(1, weight=1)
        tool_header = ttk.Frame(tools_panel, style="Panel.TFrame")
        tool_header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(tool_header, text="Tools", style="Section.TLabel").pack(side="left")
        self.refresh_button = ttk.Button(tool_header, text="Refresh", command=self._refresh_availability)
        self.refresh_button.pack(side="right")
        self.tools_frame = ttk.Frame(tools_panel, style="Panel.TFrame")
        self.tools_frame.grid(row=1, column=0, sticky="nsew")
        self._build_tool_rows()
        run_panel = self._panel(left, row=3, column=0, sticky="ew")
        self.progress = ttk.Progressbar(run_panel, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 8))
        self.start_button = ttk.Button(run_panel, text="Start assessment", style="Accent.TButton", command=self._start_assessment)
        self.start_button.pack(fill="x")
        self.cancel_button = ttk.Button(run_panel, text="Cancel running tools", style="Danger.TButton", command=self._cancel_assessment, state="disabled")
        self.cancel_button.pack(fill="x", pady=(7, 0))
        self.status_label = ttk.Label(run_panel, text="Set an authorized target, then start.", style="Muted.TLabel", wraplength=310, justify="left")
        self.status_label.pack(anchor="w", pady=(9, 0))

        right = ttk.Frame(content)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)
        right.rowconfigure(0, weight=1)
        self.notebook = ttk.Notebook(right)
        self.notebook.grid(row=0, column=0, sticky="nsew")

        findings_page = ttk.Frame(self.notebook, padding=12)
        findings_page.columnconfigure(0, weight=1)
        findings_page.rowconfigure(0, weight=3)
        findings_page.rowconfigure(1, weight=2)
        self.notebook.add(findings_page, text="Findings")
        self.findings_tree = self._tree(
            findings_page,
            ("severity", "title", "source", "target", "score"),
            ("Severity", "Finding", "Source", "Target", "Score"),
            (90, 330, 115, 180, 70),
            0,
        )
        self.findings_tree.bind("<<TreeviewSelect>>", self._show_finding)
        detail = ttk.Frame(findings_page, style="Panel.TFrame", padding=10)
        detail.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        detail.rowconfigure(0, weight=1)
        detail.columnconfigure(0, weight=1)
        self.details_text = tk.Text(detail, wrap="word", state="disabled", background=self.COLORS["field"], foreground=self.COLORS["text"], relief="flat", padx=10, pady=9)
        self.details_text.grid(row=0, column=0, sticky="nsew")
        detail_scroll = ttk.Scrollbar(detail, orient="vertical", command=self.details_text.yview)
        detail_scroll.grid(row=0, column=1, sticky="ns")
        self.details_text.configure(yscrollcommand=detail_scroll.set)

        runs_page = ttk.Frame(self.notebook, padding=12)
        runs_page.columnconfigure(0, weight=1)
        runs_page.rowconfigure(0, weight=1)
        self.notebook.add(runs_page, text="Tool runs")
        self.runs_tree = self._tree(
            runs_page,
            ("tool", "target", "status", "seconds", "findings"),
            ("Tool", "Target", "Status", "Seconds", "Findings"),
            (140, 280, 120, 90, 90),
            0,
        )
        self.runs_tree.bind("<<TreeviewSelect>>", self._show_run)

        activity_page = ttk.Frame(self.notebook, padding=12)
        activity_page.columnconfigure(0, weight=1)
        activity_page.rowconfigure(0, weight=1)
        self.notebook.add(activity_page, text="Activity")
        self.activity_tree = self._tree(
            activity_page,
            ("tool", "target", "state", "seconds"),
            ("Tool", "Target", "State", "Seconds"),
            (150, 300, 150, 90),
            0,
        )

        footer = ttk.Frame(outer)
        footer.pack(fill="x", pady=(12, 0))
        self.report_var = tk.StringVar(value="html")
        self.report_combo = ttk.Combobox(footer, textvariable=self.report_var, state="readonly", values=("json", "markdown", "html", "pdf", "all"), width=12)
        self.report_combo.pack(side="left")
        self.export_button = ttk.Button(footer, text="Export report", command=self._export_report, state="disabled")
        self.export_button.pack(side="left", padx=(8, 0))
        self.summary_label = ttk.Label(footer, text="No assessment results loaded.", style="Muted.TLabel")
        self.summary_label.pack(side="right")
        self.controls = [
            self.target_entry, self.scope_check, self.authorized_text,
            self.validate_button, self.save_scope_button, self.profile_combo,
            self.refresh_button, *self.tool_checks,
        ]

    def _tree(self, parent, columns, headings, widths, row):
        frame = ttk.Frame(parent, style="Panel.TFrame")
        frame.grid(row=row, column=0, sticky="nsew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for col, heading, width in zip(columns, headings, widths):
            tree.heading(col, text=heading)
            tree.column(col, width=width, minwidth=60, anchor="w", stretch=col in {"title", "target"})
        tree.grid(row=0, column=0, sticky="nsew")
        vertical = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        horizontal.grid(row=1, column=0, sticky="ew")
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        return tree

    def _availability(self):
        tools = []
        for configured in self.backend.registry.list():
            if isinstance(configured, dict):
                item = copy.deepcopy(configured)
                item["enabled"] = True
                tools.append(item)
        result = self.backend.tool_preflight.inspect(
            tools,
            registry_error=getattr(self.backend.registry, "load_error", None),
        )
        return {item["name"]: item for item in result}

    def _build_tool_rows(self):
        availability = self._availability()
        for row, tool in enumerate(self.backend.registry.list()):
            if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                continue
            name = tool["name"]
            variable = tk.BooleanVar(value=bool(tool.get("enabled", True)))
            self.tool_vars[name] = variable
            check = ttk.Checkbutton(self.tools_frame, text=name, variable=variable, command=self._selection_summary)
            check.grid(row=row, column=0, sticky="w", pady=2)
            self.tool_checks.append(check)
            status = availability.get(name, {}).get("status", "unknown")
            label, color = {
                "ready": ("ready", self.COLORS["accent"]),
                "unavailable": ("missing", self.COLORS["warning"]),
            }.get(status, (status, self.COLORS["danger"]))
            shown = ttk.Label(self.tools_frame, text=label, style="Muted.TLabel", foreground=color)
            shown.grid(row=row, column=1, sticky="e", padx=(8, 0))
            self.tool_status_labels[name] = shown
        self.tools_frame.columnconfigure(0, weight=1)

    def _refresh_availability(self):
        for name, label in self.tool_status_labels.items():
            item = self._availability().get(name)
            if item is None:
                label.configure(text="unknown", foreground=self.COLORS["muted"])
            elif item["status"] == "ready":
                label.configure(text="ready", foreground=self.COLORS["accent"])
            elif item["status"] == "unavailable":
                label.configure(text="missing", foreground=self.COLORS["warning"])
            else:
                label.configure(text=item["status"], foreground=self.COLORS["danger"])
        self._set_status("Tool availability refreshed from configured executables.", "muted")

    def _profile_changed(self, _event=None):
        self.profile_description.configure(
            text=self.backend.workflow.PROFILE_SEMANTICS.get(
                self.profile_var.get(),
                "Run the selected tools.",
            )
        )

    def _selection_summary(self):
        count = len(self._selected_names())
        self.summary_label.configure(text="{} tool{} selected".format(count, "" if count == 1 else "s"))

    def _selected_names(self):
        return {name for name, variable in self.tool_vars.items() if variable.get()}
    def _scope_values(self, require_target):
        lines = self.authorized_text.get("1.0", "end-1c").splitlines()
        entries = [line.strip() for line in lines if line.strip()]
        settings = validate_scope_configuration(
            self.backend.settings,
            self.scope_required_var.get(),
            entries,
        )
        scope = TargetScope(settings["scope_required"], settings["authorized_targets"])
        text = self.target_var.get().strip()
        target = None
        addresses = ()
        if require_target or text:
            if not text:
                raise ValueError("Enter a target host or IP address.")
            target = scope.validate(text)
            addresses = scope.resolve_and_validate(target)
        return settings, scope, target, addresses

    def _apply_scope(self, require_target):
        settings, scope, target, addresses = self._scope_values(require_target)
        self.backend.settings.update(settings)
        self.backend.scope = scope
        self.backend.executor.scope = scope
        self.backend.workflow.scope = scope
        if target:
            self.target_var.set(target)
            self.backend.target = target
        return settings, scope, target, addresses

    def _validate_scope(self):
        try:
            _settings, _scope, target, addresses = self._apply_scope(True)
        except Exception as exc:
            self._set_status("Scope rejected: {}".format(exc), "danger")
            return
        self._set_status(
            "Scope valid for {}. Resolved addresses: {}".format(target, ", ".join(addresses)),
            "success",
        )

    def _save_scope(self):
        temporary = None
        try:
            settings, scope, target, addresses = self._scope_values(False)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                prefix="settings-",
                suffix=".tmp",
                dir=str(SETTINGS_FILE.parent),
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
                json.dump(settings, handle, indent=2)
                handle.write("\n")
            os.replace(temporary, SETTINGS_FILE)
            self.backend.settings.update(settings)
            self.backend.scope = scope
            self.backend.executor.scope = scope
            self.backend.workflow.scope = scope
            if target:
                self.backend.target = target
            self._set_status("Saved scope settings to {}.".format(SETTINGS_FILE), "success")
        except Exception as exc:
            self._set_status("Could not save scope: {}".format(exc), "danger")
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()

    def _set_controls_enabled(self, enabled):
        state = "normal" if enabled else "disabled"
        for widget in self.controls:
            widget.configure(state=state)
        self.profile_combo.configure(state="readonly" if enabled else "disabled")
        self.refresh_button.configure(state=state)
        self.start_button.configure(state=state)
        self.export_button.configure(
            state="normal" if enabled and self.current_session else "disabled"
        )

    def _start_assessment(self):
        if self.run_thread and self.run_thread.is_alive():
            return
        profile = self.profile_var.get().strip()
        if profile not in self.backend.settings["allowed_profiles"]:
            self._set_status("That profile is not enabled in settings.", "danger")
            return
        try:
            _settings, _scope, target, addresses = self._apply_scope(True)
        except Exception as exc:
            self._set_status("Assessment not started: {}".format(exc), "danger")
            return
        selected = self._selected_names()
        if not selected:
            self._set_status("Select at least one tool to run.", "warning")
            return

        session = Session(target, profile)
        workflow = self.backend.workflow
        original_registry = workflow.registry
        original_manager = workflow.adapter_manager
        original_spinner = workflow._show_loading
        workflow.registry = SelectedToolRegistry(original_registry.list(), selected)
        workflow.adapter_manager = ObservedAdapterManager(original_manager, self.events)
        workflow._show_loading = lambda _message, stop_event: stop_event.wait()
        self.completed_runs = 0
        for item in self.activity_tree.get_children():
            self.activity_tree.delete(item)
        self._set_controls_enabled(False)
        self.cancel_button.configure(state="disabled")
        self.progress.start(12)
        self.header_status.configure(text="Assessment running")
        self._set_status(
            "Starting {} profile for {} ({}).".format(profile, target, ", ".join(addresses)),
            "muted",
        )

        def run_workflow():
            error = None
            save_error = None
            try:
                workflow.run(session)
                try:
                    self.backend.storage.save(session)
                except Exception as exc:
                    save_error = exc
                self.backend.last_session = session
                self.backend.target = session.target
            except Exception as exc:
                error = exc
            finally:
                workflow.registry = original_registry
                workflow.adapter_manager = original_manager
                workflow._show_loading = original_spinner
            self.events.put(("complete", session, error, save_error))

        self.run_thread = threading.Thread(
            target=run_workflow,
            name="phantomx-workflow",
            daemon=True,
        )
        self.run_thread.start()

    def _cancel_assessment(self):
        if self.run_thread and self.run_thread.is_alive():
            self.backend.workflow.cancel()
            self.cancel_button.configure(state="disabled")
            self._set_status(
                "Cancellation requested; waiting for active scanner processes to stop.",
                "warning",
            )

    def _drain_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "started":
                    _kind, run_id, name, target = event
                    self.activity_tree.insert(
                        "",
                        "end",
                        iid=run_id,
                        values=(name, target, "running", "—"),
                    )
                    self.cancel_button.configure(state="normal")
                    self._set_status("Running {} against {}.".format(name, target), "muted")
                elif event[0] == "finished":
                    _kind, run_id, result = event
                    self.completed_runs += 1
                    if self.activity_tree.exists(run_id):
                        self.activity_tree.item(
                            run_id,
                            values=(
                                result.tool,
                                result.target,
                                result.status,
                                "{:.2f}".format(result.duration_seconds),
                            ),
                        )
                    self._set_status(
                        "{} finished with {}. {} tool run(s) complete.".format(
                            result.tool,
                            result.status,
                            self.completed_runs,
                        ),
                        "muted",
                    )
                elif event[0] == "failed":
                    _kind, run_id, name, target, error = event
                    if self.activity_tree.exists(run_id):
                        self.activity_tree.item(
                            run_id,
                            values=(name, target, "error: {}".format(error), "—"),
                        )
                elif event[0] == "complete":
                    _kind, session, error, save_error = event
                    self._assessment_finished(session, error, save_error)
        except queue.Empty:
            pass
        try:
            if self.root.winfo_exists():
                self.root.after(100, self._drain_events)
        except tk.TclError:
            pass
    def _assessment_finished(self, session, error, save_error):
        self.run_thread = None
        self.progress.stop()
        self._set_controls_enabled(True)
        self.cancel_button.configure(state="disabled")
        if self.close_when_idle:
            self.root.destroy()
            return
        if error is not None:
            self.header_status.configure(text="Assessment error")
            self._set_status("{}: {}".format(type(error).__name__, error), "danger")
            return

        self.current_session = session
        self.header_status.configure(text="Assessment complete")
        self._populate_session(session)
        finding_count = sum(len(result.findings) for result in session.results)
        statuses = {}
        for result in session.results:
            statuses[result.status] = statuses.get(result.status, 0) + 1
        status_text = ", ".join(
            "{} {}".format(count, name)
            for name, count in sorted(statuses.items())
        ) or "no tool runs"
        self.summary_label.configure(
            text="{} findings · {} tools · {}".format(
                finding_count,
                len(session.results),
                status_text,
            )
        )
        self.export_button.configure(state="normal")
        if save_error:
            self._set_status(
                "Assessment finished; history save failed: {}".format(save_error),
                "warning",
            )
        else:
            self._set_status(
                "Assessment complete for {}. {} findings recorded.".format(
                    session.target,
                    finding_count,
                ),
                "success",
            )

    def _populate_session(self, session):
        for tree in (self.findings_tree, self.runs_tree):
            for item in tree.get_children():
                tree.delete(item)
        self.finding_rows.clear()
        row_index = 0
        for result in session.results:
            for finding in result.findings:
                row_index += 1
                row_id = str(row_index)
                self.finding_rows[row_id] = finding
                self.findings_tree.insert(
                    "",
                    "end",
                    iid=row_id,
                    values=(
                        finding.severity,
                        finding.title,
                        finding.source_tool or result.tool,
                        finding.target or result.target,
                        "{:.1f}".format(finding.score),
                    ),
                )
            self.runs_tree.insert(
                "",
                "end",
                values=(
                    result.tool,
                    result.target,
                    result.status,
                    "{:.2f}".format(result.duration_seconds),
                    len(result.findings),
                ),
            )
        self._set_details("Select a finding to inspect its evidence and recommendation.")
        self.notebook.select(0)

    def _show_finding(self, _event=None):
        selection = self.findings_tree.selection()
        if not selection:
            return
        finding = self.finding_rows.get(selection[0])
        if finding is None:
            return
        details = [
            finding.title,
            "Severity: {} (scanner: {})".format(
                finding.severity,
                finding.scanner_severity or "not provided",
            ),
            "Category: {}".format(finding.category),
            "Target: {}".format(finding.target or "not provided"),
            "Source: {}".format(finding.source_tool or "not provided"),
            "Score: {:.1f} · confidence: {:.2f}".format(
                finding.score,
                finding.confidence,
            ),
            "",
            "Evidence",
            finding.evidence or "No evidence captured.",
            "",
            "Recommendation",
            finding.recommendation or "No recommendation provided.",
            "",
            "Score breakdown",
            json.dumps(finding.score_breakdown, indent=2, ensure_ascii=False),
            "",
            "Metadata",
            json.dumps(finding.metadata, indent=2, ensure_ascii=False),
        ]
        self._set_details("\n".join(details))

    def _show_run(self, _event=None):
        selection = self.runs_tree.selection()
        if not selection or self.current_session is None:
            return
        index = self.runs_tree.index(selection[0])
        if index >= len(self.current_session.results):
            return
        result = self.current_session.results[index]
        details = (
            "Tool: {}\nTarget: {}\nStatus: {}\nDuration: {:.2f}s\n\n"
            "Diagnostic:\n{}\n\nServices: {}\nEndpoints: {}\nObservations: {}\nFindings: {}\n\n"
            "Captured stdout:\n{}\n\nCaptured stderr:\n{}"
        ).format(
            result.tool,
            result.target,
            result.status,
            result.duration_seconds,
            result.stderr or "None",
            len(result.services),
            len(result.endpoints),
            len(result.observations),
            len(result.findings),
            result.stdout or "None",
            result.stderr or "None",
        )
        self.notebook.select(0)
        self._set_details(details)

    def _set_details(self, text):
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", text)
        self.details_text.configure(state="disabled")

    def _export_report(self):
        if self.current_session is None:
            self._set_status("Run an assessment before exporting a report.", "warning")
            return
        writers = {
            "json": self.backend.reporter.write_json,
            "markdown": self.backend.reporter.write_markdown,
            "html": self.backend.reporter.write_html,
            "pdf": self.backend.reporter.write_pdf,
        }
        selected = self.report_var.get()
        chosen = list(writers.items()) if selected == "all" else [(selected, writers.get(selected))]
        created = []
        errors = []
        for name, writer in chosen:
            if writer is None:
                errors.append("Unknown format: {}".format(name))
                continue
            try:
                created.append(str(writer(self.current_session)))
            except Exception as exc:
                errors.append("{}: {}".format(name, exc))
        if errors:
            self._set_status(
                "Exported {} report(s); {}".format(len(created), "; ".join(errors)),
                "warning" if created else "danger",
            )
        else:
            self._set_status(
                "Created report{}: {}".format(
                    "" if len(created) == 1 else "s",
                    ", ".join(created),
                ),
                "success",
            )

    def _set_status(self, message, level="muted"):
        color = {
            "success": self.COLORS["accent"],
            "warning": self.COLORS["warning"],
            "danger": self.COLORS["danger"],
            "muted": self.COLORS["muted"],
        }.get(level, self.COLORS["muted"])
        self.status_label.configure(text=message, foreground=color)

    def _on_close(self):
        if self.run_thread and self.run_thread.is_alive():
            close = messagebox.askyesno(
                "Assessment in progress",
                "Cancel active scanner processes and close after they stop?",
                parent=self.root,
            )
            if not close:
                return
            self.close_when_idle = True
            self.backend.workflow.cancel()
            self.cancel_button.configure(state="disabled")
            self._set_status("Waiting for scanner processes to stop.", "warning")
            return
        self.root.destroy()


def main():
    os.chdir(BASE_DIR)
    root = tk.Tk()
    PhantomXGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
