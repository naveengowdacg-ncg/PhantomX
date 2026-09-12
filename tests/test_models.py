from core.models import Endpoint, Observation, ToolResult


def main():

    print("=" * 60)
    print("PHANTOMX - MODEL TEST")
    print("=" * 60)

    endpoint = Endpoint(
        url="https://127.0.0.1",
        scheme="https",
        host="127.0.0.1",
        port=443,
        source_tool="nmap"
    )

    observation = Observation(
        title="HTTPS service discovered",
        category="service-discovery",
        target="127.0.0.1",
        source_tool="nmap",
        evidence="Nmap identified 443/tcp as an HTTPS service.",
        confidence=0.95,
        endpoint=endpoint
    )

    result = ToolResult(
        tool="nmap",
        category="recon",
        target="127.0.0.1",
        started_at="",
        finished_at="",
        return_code=0,
        observations=[observation],
        endpoints=[endpoint]
    )

    data = result.as_dict()

    print("\n[+] Endpoint:")
    print(data["endpoints"][0])

    print("\n[+] Observation:")
    print(data["observations"][0])

    print("\n[+] Model serialization successful.")


if __name__ == "__main__":
    main()