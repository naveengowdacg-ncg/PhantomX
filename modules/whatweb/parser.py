import re

from core.models import Observation


class WhatWebParser:
    """Parse WhatWeb output into standardized observations."""

    ANSI_ESCAPE = re.compile(
        r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
    )

    def parse(self, output, target):
        observations = []

        if not output:
            return observations

        # Remove terminal formatting/color codes produced by WhatWeb.
        output = self.ANSI_ESCAPE.sub("", output)

        for line in output.splitlines():

            line = line.strip()

            if not line:
                continue

            match = re.match(
                r"^(https?://[^\s]+)\s+\[(\d{3})\s+[^\]]+\]\s*(.*)$",
                line
            )

            if not match:
                continue

            url, status_code, fingerprint_data = match.groups()

            observations.append(
                Observation(
                    title="Web technology fingerprint",
                    category="web-technology",
                    target=target,
                    source_tool="whatweb",
                    evidence=line,
                    confidence=0.90,
                    metadata={
                        "url": url,
                        "http_status": int(status_code),
                        "fingerprint": fingerprint_data,
                    }
                )
            )

        return observations