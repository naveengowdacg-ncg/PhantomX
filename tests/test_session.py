from core.models import Session
from modules.nmap.adapter import NmapAdapter


def main():
    target = "127.0.0.1"

    print("=" * 60)
    print("PHANTOMX - SESSION TEST")
    print("=" * 60)

    # Create assessment session
    session = Session(
        target=target,
        profile="standard"
    )

    print(f"\nSession ID: {session.session_id}")
    print(f"Target: {session.target}")
    print(f"Profile: {session.profile}")

    # Run Nmap
    nmap = NmapAdapter()

    print("\n[+] Running Nmap...")

    result = nmap.scan(target)

    # Store result in session
    session.results.append(result)

    print("[+] Nmap result stored in session.")

    print("\n--- SESSION SUMMARY ---")
    print(f"Session ID: {session.session_id}")
    print(f"Target: {session.target}")
    print(f"Tools executed: {len(session.results)}")

    for tool_result in session.results:
        print(
            f"- {tool_result.tool}: "
            f"{len(tool_result.services)} services discovered"
        )


if __name__ == "__main__":
    main()