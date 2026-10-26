"""Read-only preflight checks for configured external tools and files."""

import os
from pathlib import Path
import shutil


KNOWN_PROFILES = {"passive", "stealth", "standard", "full", "aggressive"}


def redirect_policy_error(tool):
    """Reject built-in HTTP options that can escape the authorized hostname."""
    if not isinstance(tool, dict):
        return None
    name = str(tool.get("name", "")).strip().casefold()
    executable = str(tool.get("executable", "")).replace("\\", "/").rsplit("/", 1)[-1]
    if executable.casefold().endswith(".exe"):
        executable = executable[:-4]
    executable = executable.casefold()
    identity = {name, executable}
    if "httpx-toolkit" in identity:
        identity.add("httpx")
    args = tool.get("args", [])
    if not isinstance(args, list) or any(not isinstance(arg, str) for arg in args):
        return None
    tokens = [arg.strip().casefold() for arg in args]

    def values_for(flag):
        values = []
        for index, token in enumerate(tokens):
            if token.startswith(flag + "="):
                values.append(token.split("=", 1)[1])
            elif token == flag and index + 1 < len(tokens):
                values.append(tokens[index + 1])
        return values

    def has_enabled_flag(*flags):
        for token in tokens:
            flag, separator, value = token.partition("=")
            if flag in flags and (
                not separator or value.strip().casefold() not in {"false", "0", "no", "off"}
            ):
                return True
        return False

    if "whatweb" in identity:
        values = values_for("--follow-redirect")
        if not values or any(value != "never" for value in values):
            return "WhatWeb must set every --follow-redirect option to never."
    if "nuclei" in identity:
        if not has_enabled_flag("-disable-redirects", "--disable-redirects", "-dr"):
            return "Nuclei must disable HTTP redirects with -disable-redirects."
        if has_enabled_flag(
            "-follow-redirects", "--follow-redirects", "-fr",
            "-follow-host-redirects", "--follow-host-redirects", "-fhr",
        ):
            return "Nuclei redirect-following options are not allowed for scoped scans."
    if "katana" in identity:
        if not has_enabled_flag("-disable-redirects", "--disable-redirects", "-dr"):
            return "Katana must disable redirects with -disable-redirects."
        field_scopes = values_for("-fs") + values_for("-field-scope")
        if not field_scopes or any(value != "fqdn" for value in field_scopes):
            return "Katana must use only -fs fqdn so crawling stays on the authorized hostname."
    if "httpx" in identity and has_enabled_flag(
        "-follow-redirects", "--follow-redirects", "-fr",
        "-follow-host-redirects", "--follow-host-redirects", "-fhr",
    ):
        return "HTTPX redirect-following options are not allowed for scoped scans."
    if "gobuster" in identity and has_enabled_flag(
        "-follow-redirect", "--follow-redirect", "-r",
    ):
        return "Gobuster redirect-following is not allowed for scoped scans."
    if "nikto" in identity and has_enabled_flag(
        "-followredirects", "--followredirects", "-follow-redirects",
    ):
        return "Nikto redirect-following is not allowed for scoped scans."
    return None

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

        name_counts = {}
        for tool in tools:
            if isinstance(tool, dict) and isinstance(tool.get("name"), str):
                key = tool["name"].strip().casefold()
                if key:
                    name_counts[key] = name_counts.get(key, 0) + 1
        for index, tool in enumerate(tools, start=1):
            duplicate = (
                isinstance(tool, dict)
                and isinstance(tool.get("name"), str)
                and name_counts.get(tool["name"].strip().casefold(), 0) > 1
            )
            check = self._inspect_tool(tool, index, duplicate=duplicate)
            if check is not None:
                results.append(check)
        return results

    def _inspect_tool(self, tool, index, duplicate=False):
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
        if duplicate:
            errors.append("tool name must be unique, ignoring case")
        category = tool.get("category")
        if not isinstance(category, str) or not category.strip():
            errors.append("category must be a non-empty string")
        executable = tool.get("executable")
        if not isinstance(executable, str) or not executable.strip():
            errors.append("executable must be a non-empty command or path")
        args = tool.get("args", [])
        if not isinstance(args, list) or any(not isinstance(arg, str) for arg in args):
            errors.append("args must be a list of strings")
        timeout = tool.get("timeout", 120)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 3600:
            errors.append("timeout must be a positive integer")
        retries = tool.get("retries", 0)
        if isinstance(retries, bool) or not isinstance(retries, int) or not 0 <= retries <= 3:
            errors.append("retries must be an integer from 0 to 3")
        if not isinstance(tool.get("retry_on_timeout", False), bool):
            errors.append("retry_on_timeout must be true or false")
        required_files = tool.get("required_files", [])
        if not isinstance(required_files, list) or any(
            not isinstance(path, str) or not path.strip()
            for path in required_files
        ):
            errors.append("required_files must be a list of non-empty path strings")
        profile_modes = tool.get("profile_modes")
        if profile_modes is not None and (
            not isinstance(profile_modes, list)
            or any(
                not isinstance(profile, str) or profile not in KNOWN_PROFILES
                for profile in profile_modes
            )
            or len(set(profile_modes)) != len(profile_modes)
        ):
            errors.append("profile_modes must contain unique known profile names")
        profile_args = tool.get("profile_args")
        if profile_args is not None and (
            not isinstance(profile_args, dict)
            or any(profile not in KNOWN_PROFILES for profile in profile_args)
            or any(
                not isinstance(args, list)
                or any(not isinstance(arg, str) for arg in args)
                for args in profile_args.values()
            )
        ):
            errors.append(
                "profile_args must map known profile names to lists of strings"
            )
        if not errors and not any("{target}" in arg for arg in args):
            errors.append("args must include the {target} placeholder")
        if not errors:
            policy_error = redirect_policy_error(tool)
            if policy_error:
                errors.append(policy_error)
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
