"""Read-only preflight checks for configured external tools and files."""

import os
from pathlib import Path
import shutil


class ToolPreflight:
    """Inspect tool configuration, PATH availability, and required files."""

    def inspect(self, tools, registry_error=None):
        results = []
        if registry_error:
            results.append({
                "name": "<tool registry>",
                "status": "misconfigured",
                "executable": "",
                "resolved_executable": None,
                "message": registry_error,
            })
        if not isinstance(tools, list):
            results.append({
                "name": "<tool registry>",
                "status": "misconfigured",
                "executable": "",
                "resolved_executable": None,
                "message": "Expected a JSON object containing a list of tools.",
            })
            return results

        for index, tool in enumerate(tools, start=1):
            check = self._inspect_tool(tool, index)
            if check is not None:
                results.append(check)
        return results

    def _inspect_tool(self, tool, index):
        if not isinstance(tool, dict):
            return self._misconfigured(
                f"<tool #{index}>", "", "Tool entry must be a JSON object."
            )

        name = tool.get("name")
        label = name.strip() if isinstance(name, str) and name.strip() else f"<tool #{index}>"
        enabled = tool.get("enabled", True)
        if isinstance(enabled, bool) and not enabled:
            return None

        errors = []
        if not isinstance(name, str) or not name.strip():
            errors.append("name must be a non-empty string")
        if not isinstance(enabled, bool):
            errors.append("enabled must be true or false")
        category = tool.get("category")
        if not isinstance(category, str) or not category.strip():
            errors.append("category must be a non-empty string")
        executable = tool.get("executable")
        if not isinstance(executable, str) or not executable.strip():
            errors.append("executable must be a non-empty command or path")
        args = tool.get("args", [])
        if not isinstance(args, list) or any(not isinstance(arg, str) for arg in args):
            errors.append("args must be a list of strings")
        required_files = tool.get("required_files", [])
        if not isinstance(required_files, list) or any(
            not isinstance(path, str) or not path.strip()
            for path in required_files
        ):
            errors.append("required_files must be a list of non-empty path strings")
        if errors:
            return self._misconfigured(label, executable if isinstance(executable, str) else "", "; ".join(errors) + ".")

        executable = executable.strip()
        resolved = shutil.which(executable)
        missing_files = []
        for raw_path in required_files:
            expanded = os.path.expandvars(os.path.expanduser(raw_path.strip()))
            try:
                if not Path(expanded).is_file():
                    missing_files.append(raw_path)
            except (OSError, ValueError):
                missing_files.append(raw_path)

        if missing_files:
            details = []
            if resolved is None:
                details.append(f"executable '{executable}' was not found on PATH")
            else:
                details.append(f"executable '{executable}' is available at '{resolved}'")
            details.extend(
                f"required file '{path}' is missing" for path in missing_files
            )
            details.append(
                "install the missing tool or update executable/required_files and its matching arguments in config/tools.json"
            )
            return {
                "name": label,
                "status": "unavailable" if resolved is None else "misconfigured",
                "executable": executable,
                "resolved_executable": resolved,
                "message": ". ".join(details) + ".",
            }
        if resolved is None:
            return {
                "name": label,
                "status": "unavailable",
                "executable": executable,
                "resolved_executable": None,
                "message": (
                    f"Executable '{executable}' was not found on PATH. Install it "
                    "or update the executable field in config/tools.json."
                ),
            }
        return {
            "name": label,
            "status": "ready",
            "executable": executable,
            "resolved_executable": resolved,
            "message": f"Executable is available at '{resolved}'; required files are available.",
        }

    @staticmethod
    def _misconfigured(name, executable, message):
        return {
            "name": name,
            "status": "misconfigured",
            "executable": executable,
            "resolved_executable": None,
            "message": message,
        }
