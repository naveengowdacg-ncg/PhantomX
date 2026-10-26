"""Run real PhantomX tool adapters against a loopback-only Kali lab over SSH.

The scanner targets are fixed to 127.0.0.1 or localhost. SSH is used only to
reach the user's Kali VM; the script never accepts a remote scan target.
"""

import argparse
import copy
import ipaddress
import json
import shutil
import sys
import tempfile
from pathlib import Path

from analysis.normalizer import Normalizer
from analysis.scoring import RiskEngine
from core.adapter_manager import AdapterManager
from core.executor import ToolExecutor
from core.logger import get_logger
from core.scope import TargetScope
from core.tool_registry import ToolRegistry


SUBFINDER_SOURCES = ",".join(
    [
        "alienvault", "anubis", "bevigil", "bufferover", "builtwith", "c99",
        "censys", "certspotter", "chaos", "chinaz", "commoncrawl", "crtsh",
        "digitalyama", "digitorus", "dnsdb", "dnsdumpster", "dnsrepo",
        "domainsproject", "driftnet", "fofa", "fullhunt", "github",
        "hackertarget", "hudsonrock", "intelx", "leakix", "merklemap",
        "netlas", "onyphe", "profundis", "pugrecon", "quake", "rapiddns",
        "reconeer", "redhuntlabs", "robtex", "rsecloud", "scanmalware",
        "securitytrails", "shodan", "shodanct", "sitedossier", "thc",
        "threatbook", "threatcrowd", "urlscan", "virustotal",
        "waybackarchive", "whoisxmlapi", "windvane", "zoomeyeapi", "submd",
    ]
)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh-host", required=True, help="Private IP of the Kali VM")
    parser.add_argument("--ssh-user", default="kali")
    parser.add_argument("--ssh-key", required=True, type=Path)
    parser.add_argument("--known-hosts", required=True, type=Path)
    parser.add_argument("--lab-root", required=True)
    parser.add_argument("--only", choices=("nmap", "whatweb", "nuclei", "nikto", "subfinder", "dnsx", "httpx", "katana", "testssl", "gobuster"), nargs="+", help="Run only the selected loopback scanners.")
    return parser.parse_args()


def _validate_options(options):
    address = ipaddress.ip_address(options.ssh_host)
    if not address.is_private:
        raise ValueError("SSH host must be a private IP address.")
    if not options.ssh_key.is_file():
        raise ValueError("SSH private key file does not exist.")
    if not options.known_hosts.is_file():
        raise ValueError("SSH known-hosts file does not exist.")
    if not options.lab_root.startswith("/tmp/phantomx-loopback-"):
        raise ValueError("Lab directory must be under the expected temporary directory.")
    executable = shutil.which("ssh")
    if executable is None:
        raise ValueError("OpenSSH client was not found on PATH.")
    return executable


def _remote_tool(configured, scanner, ssh_executable, options, lab_root):
    tool = copy.deepcopy(configured)
    limits = {
        "nmap": 30, "whatweb": 45, "nuclei": 90, "nikto": 50,
        "subfinder": 40, "dnsx": 30, "httpx": 40, "katana": 40,
        "testssl": 60, "gobuster": 45,
    }
    remote_timeout = limits.get(tool.get("name"), 45)
    tool["timeout"] = remote_timeout + 10
    prefix = [
        "-i",
        str(options.ssh_key),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UserKnownHostsFile={}".format(options.known_hosts),
        "{}@{}".format(options.ssh_user, options.ssh_host),
        "timeout",
        "--kill-after=5",
        "{}s".format(remote_timeout),
        scanner,
    ]
    tool["executable"] = ssh_executable
    tool["args"] = prefix + list(tool.get("args", []))
    tool.pop("required_files", None)

    name = tool.get("name")
    if name == "nmap":
        tool["args"] = prefix + [
            "-sT", "-sV", "--version-light", "-Pn", "-n",
            "-p", "18080,18443", "{target}",
        ]
    elif name == "subfinder":
        tool["args"].extend(["-exclude-sources", SUBFINDER_SOURCES])
    elif name == "dnsx":
        tool["args"].extend(["-r", "udp:127.0.0.1:15353"])
    elif name == "nuclei":
        tool["args"].extend(
            [
                "-t", "{}/loopback-template.yaml".format(lab_root),
                "-no-interactsh",
                "-timeout", "3", "-retries", "0", "-c", "1", "-rl", "2",
            ]
        )
    elif name == "nikto":
        max_time = tool["args"].index("-maxtime")
        tool["args"][max_time + 1] = "30s"
    elif name == "httpx":
        tool["args"].extend(["-timeout", "5", "-retries", "0"])
    elif name == "katana":
        tool["args"].extend(
            ["-timeout", "5", "-crawl-duration", "10s"]
        )
    elif name == "gobuster":
        try:
            wordlist_flag = tool["args"].index("-w")
        except ValueError as exc:
            raise ValueError("Gobuster configuration is missing its wordlist flag.") from exc
        tool["args"][wordlist_flag + 1] = "{}/words.txt".format(lab_root)
    return tool

def _result_summary(result):
    return {
        "tool": result.tool,
        "target": result.target,
        "status": result.status,
        "return_code": result.return_code,
        "duration_seconds": result.duration_seconds,
        "services": [service.as_dict() for service in result.services],
        "endpoints": [endpoint.as_dict() for endpoint in result.endpoints],
        "observations": len(result.observations),
        "findings": [
            {
                "title": finding.title,
                "severity": finding.severity,
                "score": finding.score,
            }
            for finding in result.findings
        ],
        "diagnostic": (result.stderr or "")[:400],
        "stdout_excerpt": (result.stdout or "")[:500],
    }


def main():
    options = parse_args()
    try:
        ssh_executable = _validate_options(options)
    except ValueError as exc:
        print("Configuration error: {}".format(exc), file=sys.stderr)
        return 2

    targets = {
        "nmap": "127.0.0.1",
        "whatweb": "http://127.0.0.1:18080/",
        "nuclei": "http://127.0.0.1:18080/",
        "nikto": "http://127.0.0.1:18080/",
        "subfinder": "localhost",
        "dnsx": "localhost",
        "httpx": "http://127.0.0.1:18080/",
        "katana": "http://127.0.0.1:18080/",
        "testssl": "127.0.0.1:18443",
        "gobuster": "http://127.0.0.1:18080/",
    }
    scanners = {
        "nmap": "nmap",
        "whatweb": "whatweb",
        "nuclei": "nuclei",
        "nikto": "nikto",
        "subfinder": "subfinder",
        "dnsx": "dnsx",
        "httpx": "httpx-toolkit",
        "katana": "katana",
        "testssl": "testssl",
        "gobuster": "gobuster",
    }
    scope = TargetScope(True, ["127.0.0.1", "localhost", "::1"])
    manager = AdapterManager()
    normalizer = Normalizer()
    risk = RiskEngine()
    results = []

    with tempfile.TemporaryDirectory(prefix="phantomx-real-integration-") as log_dir:
        logger = get_logger(log_dir)
        executor = ToolExecutor(logger, scope=scope)
        configured_tools = {
            tool["name"]: tool
            for tool in ToolRegistry().list()
            if isinstance(tool, dict) and isinstance(tool.get("name"), str)
        }
        for name in (options.only or list(scanners)):
            scanner = scanners[name]
            configured = configured_tools.get(name)
            if configured is None:
                item = {"tool": name, "status": "not_configured", "target": targets[name]}
                results.append(item)
                print("[{}] {}".format(name, item["status"]), file=sys.stderr, flush=True)
                continue
            tool = _remote_tool(
                configured,
                scanner,
                ssh_executable,
                options,
                options.lab_root,
            )
            try:
                if name in {"subfinder", "dnsx"}:
                    # The workflow adapter intentionally skips localhost. Run the
                    # same real executor directly with scope still enforced.
                    result = executor.run(tool, targets[name])
                else:
                    result = manager.run(tool, targets[name], executor)
                result = normalizer.parse(result)
                result.findings = risk.score_all(result.findings)
                item = _result_summary(result)
            except Exception as exc:
                item = {
                    "tool": name,
                    "target": targets[name],
                    "status": "harness_error",
                    "diagnostic": "{}: {}".format(type(exc).__name__, exc),
                }
            results.append(item)
            print("[{}] {}".format(name, item.get("status")), file=sys.stderr, flush=True)
        for handler in tuple(logger.handlers):
            handler.flush()
            handler.close()
            logger.removeHandler(handler)
    print(json.dumps({"loopback_only": True, "results": results}, indent=2))
    failed = [
        item for item in results
        if item.get("status") != "success"
    ]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
