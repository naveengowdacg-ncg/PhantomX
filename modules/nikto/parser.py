import re

from core.models import Finding


class NiktoParser:
    """Convert Nikto's human-readable findings into individual findings."""

    SUMMARY_PREFIXES = (
        "target ip:",
        "target hostname:",
        "target port:",
        "start time:",
        "end time:",
        "server:",
        "retrieved",
        "no cgi directories found",
        "0 error(s)",
        "1 host(s) tested",
        "host(s) tested",
        "item(s) reported on remote host",
        "requests:",
    )

    FINDING_MARKERS = (
        "missing", "outdated", "disclosure", "vulnerability", "vulnerable",
        "dangerous", "osvdb-", "cve-", "backdoor", "backup", "exposed",
        "injection", "deprecated", "directory listing", "phpinfo",
        "credentials", "cross-site", "xss", "sql", "upload", "traversal",
        "misconfiguration", "allows", "may be", "might be interesting",
        "not set", "not secure", "weak", "default file", "default page",
        "configuration file", "source code", "server-status",
    )

    PATH_PREFIX = re.compile(r"^(?P<path>/[^\s:]*)(?::\s*|\s+)?(?P<detail>.*)$")
    HEADER_PREFIX = re.compile(r"^\+\s*")

    def parse(self, output, target):
        """Return distinct, evidence-backed Nikto findings from stdout."""
        findings = []
        seen = set()

        for raw_line in (output or "").splitlines():
            line = raw_line.strip()
            if not line.startswith("+"):
                continue

            message = self.HEADER_PREFIX.sub("", line).strip()
            if not message:
                continue

            lowered = message.lower()
            if any(lowered.startswith(prefix) for prefix in self.SUMMARY_PREFIXES):
                continue

            path_match = self.PATH_PREFIX.match(message)
            has_marker = any(marker in lowered for marker in self.FINDING_MARKERS)

            # Nikto's useful item lines normally identify a path. Keep
            # explicit vulnerability identifiers/markers even without a path,
            # but avoid turning routine server banners and scan summaries
            # into vulnerabilities.
            if not path_match and not has_marker:
                continue

            normalized = re.sub(r"\s+", " ", message).casefold()
            if normalized in seen:
                continue
            seen.add(normalized)

            path = path_match.group("path") if path_match else ""
            detail = path_match.group("detail").strip() if path_match else message
            title_detail = detail or message
            title_detail = re.sub(r"^[:\s-]+", "", title_detail).strip()
            if not title_detail:
                title_detail = message

            # Titles remain readable and distinct while full evidence is kept.
            title = (
                f"Nikto: {path} — {title_detail}"
                if path
                else "Nikto: " + title_detail
            )
            if len(title) > 140:
                title = title[:137].rstrip() + "..."

            findings.append(
                Finding(
                    title=title,
                    category="web",
                    impact=4,
                    exploitability=4,
                    confidence=0.7,
                    exposure=6,
                    evidence=message,
                    source_tool="nikto",
                    target=target,
                    recommendation=(
                        "Validate this Nikto observation manually, confirm "
                        "whether the affected path or configuration is exposed, "
                        "and apply the relevant vendor/web-server guidance."
                    ),
                    metadata={
                        "scanner": "nikto",
                        "path": path,
                        "raw_finding": message,
                        "verification_status": "scanner_match_unverified",
                    },
                )
            )

        return findings
