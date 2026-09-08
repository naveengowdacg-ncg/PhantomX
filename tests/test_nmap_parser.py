from modules.nmap.parser import NmapParser


def main():
    sample_output = """
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
445/tcp open  microsoft-ds?
"""

    parser = NmapParser()
    services = parser.parse(sample_output)

    print("Services discovered:", len(services))

    for service in services:
        print(service.as_dict())


if __name__ == "__main__":
    main()