from modules.nmap.adapter import NmapAdapter
from analysis.normalizer import Normalizer
from analysis.correlation import CorrelationEngine


def main():

    target = "127.0.0.1"

    print("=" * 60)
    print("PHANTOMX - NMAP CORRELATION TEST")
    print("=" * 60)

    nmap = NmapAdapter()
    normalizer = Normalizer()
    correlation = CorrelationEngine()

    print(f"\nTarget: {target}")
    print(f"Nmap available: {nmap.is_available()}")

    if not nmap.is_available():
        print("Nmap is not available.")
        return

    print("\n[+] Running Nmap...")

    result = nmap.scan(target)

    if result.status != "success":
        print("[!] Nmap failed.")
        print(result.stderr)
        return

    print("[+] Nmap completed.")

    result = normalizer.parse(result)

    print(
        f"[+] Normalized findings: "
        f"{len(result.findings)}"
    )

    groups = correlation.correlate(
        result.findings
    )

    print(
        f"[+] Correlation groups: "
        f"{len(groups)}"
    )

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