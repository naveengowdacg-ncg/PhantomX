from modules.whatweb.adapter import WhatWebAdapter


def main():

    target = "http://127.0.0.1"

    print("=" * 60)
    print("PHANTOMX - WHATWEB PIPELINE TEST")
    print("=" * 60)

    whatweb = WhatWebAdapter()

    print(f"\nTarget: {target}")
    print(f"WhatWeb available: {whatweb.is_available()}")
    print(f"WhatWeb path: {whatweb.executable}")

    if not whatweb.is_available():
        print("WhatWeb is not available.")
        return

    print("\n[+] Running WhatWeb...")

    result = whatweb.scan(target)

    print("[+] WhatWeb completed.")

    print("\n--- TOOL RESULT ---")
    print(f"Tool: {result.tool}")
    print(f"Category: {result.category}")
    print(f"Target: {result.target}")
    print(f"Status: {result.status}")
    print(f"Return code: {result.return_code}")
    print(f"Duration: {result.duration_seconds:.3f}s")

    print(
        f"Observations discovered: "
        f"{len(result.observations)}"
    )

    for observation in result.observations:
        

        print("\n--- OBSERVATION ---")
        print(f"Title: {observation.title}")
        print(f"Category: {observation.category}")
        print(f"Confidence: {observation.confidence}")
        print(f"Evidence: {observation.evidence}")
        print(f"Metadata: {observation.metadata}")


if __name__ == "__main__":
    main()