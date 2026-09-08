from modules.nmap.adapter import NmapAdapter


def main():
    target = "127.0.0.1"

    nmap = NmapAdapter()

    print("=" * 60)
    print("PHANTOMX - NMAP PIPELINE TEST")
    print("=" * 60)

    print(f"\nTarget: {target}")
    print(f"Nmap available: {nmap.is_available()}")
    print(f"Nmap path: {nmap.executable}")

    if not nmap.is_available():
        print("Nmap is not available.")
        return

    print("\n[+] Running Nmap...")

    result = nmap.scan(target)

    if result.status != "success":
        print("[!] Nmap failed.")
        print(result.stderr)
        return

    print("[+] Nmap scan completed.")

    print("\n--- TOOL RESULT ---")
    print(f"Tool: {result.tool}")
    print(f"Category: {result.category}")
    print(f"Target: {result.target}")
    print(f"Return code: {result.return_code}")
    print(f"Duration: {result.duration_seconds}s")
    print(f"Services discovered: {len(result.services)}")

    print("\n--- DISCOVERED SERVICES ---")

    for service in result.services:
        print(
            f"{service.port}/{service.protocol}  "
            f"{service.state:<6} "
            f"{service.service:<15} "
            f"{service.version}"
        )


if __name__ == "__main__":
    main()