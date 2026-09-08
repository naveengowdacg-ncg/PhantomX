from core.models import Finding
from analysis.correlation import CorrelationEngine


def main():

    engine = CorrelationEngine()

    findings = [

        Finding(
            title="Open service: microsoft-ds on port 445",
            category="network",
            target="127.0.0.1",
            source_tool="nmap",
            metadata={
                "port": 445,
                "protocol": "tcp",
                "service": "microsoft-ds",
            },
        ),

        Finding(
            title="SMB service detected",
            category="network",
            target="127.0.0.1",
            source_tool="another-tool",
            metadata={
                "port": 445,
                "protocol": "tcp",
                "service": "smb",
            },
        ),

        Finding(
            title="Open service: msrpc on port 135",
            category="network",
            target="127.0.0.1",
            source_tool="nmap",
            metadata={
                "port": 135,
                "protocol": "tcp",
                "service": "msrpc",
            },
        ),
    ]

    groups = engine.correlate(findings)

    print("=" * 60)
    print("PHANTOMX - CORRELATION TEST")
    print("=" * 60)

    print(f"\nTotal findings: {len(findings)}")
    print(f"Correlation groups: {len(groups)}")

    for index, group in enumerate(groups, start=1):

        print(f"\n--- GROUP {index} ---")

        print(f"Target: {group.target}")
        print(f"Key: {group.key}")
        print(f"Sources: {', '.join(group.sources)}")
        print(f"Confidence: {group.confidence:.2f}")
        print(f"Findings: {len(group.findings)}")

        for finding in group.findings:
            print(
                f"  - {finding.source_tool}: "
                f"{finding.title}"
            )


if __name__ == "__main__":
    main()