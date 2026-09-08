from modules.nmap.adapter import NmapAdapter


def main():
    nmap = NmapAdapter()

    print("Nmap available:", nmap.is_available())
    print("Nmap path:", nmap.executable)

    result = nmap.scan("127.0.0.1")

    print("\nReturn code:", result["return_code"])
    print("\n--- NMAP OUTPUT ---")
    print(result["stdout"])

    if result["stderr"]:
        print("\n--- NMAP ERRORS ---")
        print(result["stderr"])


if __name__ == "__main__":
    main()