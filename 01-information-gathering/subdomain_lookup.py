import socket


def get_subdomains(mode):

    basic_subdomains = [
        "www",
        "mail",
        "ftp",
        "blog",
        "api",
        "dev",
        "test"
    ]

    extended_subdomains = [
        "www",
        "mail",
        "ftp",
        "blog",
        "api",
        "dev",
        "test",
        "admin",
        "portal",
        "webmail",
        "vpn",
        "shop",
        "store",
        "support",
        "docs"
    ]

    if mode == "2":
        return extended_subdomains

    return basic_subdomains


def resolve_subdomain(target):

    try:
        results = socket.getaddrinfo(target, None)

        ipv4_addresses = set()
        ipv6_addresses = set()

        for result in results:

            ip_address = result[4][0]

            if ":" in ip_address:
                ipv6_addresses.add(ip_address)
            else:
                ipv4_addresses.add(ip_address)

        return ipv4_addresses, ipv6_addresses

    except socket.gaierror:
        return None, None


def main():

    print("=" * 60)
    print("SUBDOMAIN INFORMATION TOOL")
    print("=" * 60)

    domain = input("\nEnter a domain (example.com): ").strip()

    print("\nSelect scan mode:")
    print("1. Basic list (7 common subdomains)")
    print("2. Extended list (15 common subdomains)")

    mode = input("\nSelect an option (1 or 2): ").strip()

    if mode not in ["1", "2"]:
        print("\n[-] Invalid option. Using Basic mode.")
        mode = "1"

    subdomains = get_subdomains(mode)

    print(f"\n[+] Target domain: {domain}")
    print(f"[+] Subdomains to check: {len(subdomains)}")

    print("\n" + "=" * 60)
    print("CHECKING SUBDOMAINS")
    print("=" * 60)

    resolved_subdomains = []
    not_resolved_subdomains = []

    for subdomain in subdomains:

        target = f"{subdomain}.{domain}"

        ipv4_addresses, ipv6_addresses = resolve_subdomain(target)

        if ipv4_addresses is None and ipv6_addresses is None:

            print(f"\n[-] {target}")
            print("    Status: Not resolved")

            not_resolved_subdomains.append(target)

        else:

            print(f"\n[+] {target}")
            print("    Status: Resolved")

            if ipv4_addresses:

                print("    IPv4 Addresses:")

                for address in sorted(ipv4_addresses):
                    print(f"      - {address}")

            if ipv6_addresses:

                print("    IPv6 Addresses:")

                for address in sorted(ipv6_addresses):
                    print(f"      - {address}")

            total_addresses = (
                len(ipv4_addresses) +
                len(ipv6_addresses)
            )

            print(f"    Total addresses: {total_addresses}")

            resolved_subdomains.append(target)

    print("\n" + "=" * 60)
    print("SUBDOMAIN SUMMARY")
    print("=" * 60)

    print(f"\nScan mode: {'Extended' if mode == '2' else 'Basic'}")
    print(f"Total checked: {len(subdomains)}")
    print(f"Resolved: {len(resolved_subdomains)}")
    print(f"Not resolved: {len(not_resolved_subdomains)}")

    print("\nResolved subdomains:")

    if resolved_subdomains:

        for subdomain in resolved_subdomains:
            print(f"  - {subdomain}")

    else:
        print("  No subdomains resolved.")

    print("\n" + "=" * 60)
    print("SUBDOMAIN LOOKUP COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()
