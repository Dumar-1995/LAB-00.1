import socket


def resolve_domain(domain):
    try:
        results = socket.getaddrinfo(domain, None)

        ipv4_addresses = set()
        ipv6_addresses = set()

        for result in results:
            family = result[0]
            address = result[4][0]

            if family == socket.AF_INET:
                ipv4_addresses.add(address)

            elif family == socket.AF_INET6:
                ipv6_addresses.add(address)

        print("\n" + "=" * 50)
        print("         ADVANCED DOMAIN INFORMATION")
        print("=" * 50)

        print(f"\n[+] Domain: {domain}")

        print("\n[+] IPv4 Addresses:")

        if ipv4_addresses:
            for ip in ipv4_addresses:
                print(f"    - {ip}")
        else:
            print("    No IPv4 addresses found.")

        print("\n[+] IPv6 Addresses:")

        if ipv6_addresses:
            for ip in ipv6_addresses:
                print(f"    - {ip}")
        else:
            print("    No IPv6 addresses found.")

        print("\n" + "=" * 50)

    except socket.gaierror:
        print("\n[-] Error: The domain could not be resolved.")


while True:

    domain = input("\nEnter a domain (or 'exit' to quit): ").strip()

    if domain.lower() == "exit":
        print("\n[+] Program finished.")
        break

    if not domain:
        print("[-] Please enter a valid domain.")
        continue

    resolve_domain(domain)
