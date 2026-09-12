from modules.whatweb.parser import WhatWebParser


def main():

    print("=" * 60)
    print("PHANTOMX - WHATWEB PARSER TEST")
    print("=" * 60)

    sample_output = (
        "http://127.0.0.1 [200 OK] "
        "Apache[2.4.68], Country[RESERVED][ZZ], "
        "HTTPServer[Debian Linux][Apache/2.4.68 (Debian)], "
        "IP[127.0.0.1], "
        "Title[Apache2 Debian Default Page: It works]"
    )

    parser = WhatWebParser()

    observations = parser.parse(
        sample_output,
        "127.0.0.1"
    )

    print(f"\nObservations discovered: {len(observations)}")

    for observation in observations:

        print("\n--- OBSERVATION ---")
        print(f"Title: {observation.title}")
        print(f"Category: {observation.category}")
        print(f"Target: {observation.target}")
        print(f"Source: {observation.source_tool}")
        print(f"Confidence: {observation.confidence}")
        print(f"Evidence: {observation.evidence}")
        print(f"Metadata: {observation.metadata}")


if __name__ == "__main__":
    main()