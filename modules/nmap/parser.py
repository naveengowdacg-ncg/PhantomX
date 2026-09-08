import re

from core.models import Service


class NmapParser:
    """Parse Nmap service/version scan output."""

    PORT_LINE = re.compile(
        r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$"
    )

    def parse(self, output):
        """Parse Nmap stdout into Service objects."""

        services = []

        for line in output.splitlines():
            line = line.strip()

            match = self.PORT_LINE.match(line)

            if not match:
                continue

            port, protocol, state, service, version = match.groups()

            services.append(
                Service(
                    port=int(port),
                    protocol=protocol,
                    state=state,
                    service=service,
                    version=(version or "").strip()
                )
            )

        return services