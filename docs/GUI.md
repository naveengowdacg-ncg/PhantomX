# PhantomX desktop GUI

## Start

From the PhantomX project folder, run:

~~~powershell
python gui.py
~~~

The GUI uses the existing PhantomX application, workflow, tool registry, scope validation, result models, and reporter. Findings come from actual scanner runs; the interface does not insert sample scan results.

## Workflow

1. Enter a hostname or IP address as the target.
2. Add the host/IP/CIDR entries that authorize the scan. Scope-required is enabled by default. Validate the target before starting.
3. Save the authorized scope to config/settings.json when it should persist for later runs.
4. Choose a scan profile and the tools for this run. The tool panel shows local availability from PATH and required input files.
5. Start the run. Progress and per-tool status update while the backend runs. Cancel stops the active workflow.
6. Review findings and individual tool output in the Findings and Tool Runs tabs.
7. Export JSON, Markdown, HTML, or PDF reports from the results view.

Tool availability is checked on the computer running the GUI. Installing Linux scanners inside Kali does not make them available to a Windows GUI process. To run the GUI on Windows, install the selected Windows-compatible tools there or add a supported remote runtime before treating Kali tools as available.