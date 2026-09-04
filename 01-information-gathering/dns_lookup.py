import socket


def resolve_domain(domain):
    try:
        ip_address = socket.gethostbyname(domain)

        print("\n" + "=" * 45)
        print("       DOMAIN INFORMATION")
        print("=" * 45)

        print(f"[+] Domain:     {domain}")
        print(f"[+] IPv4:       {ip_address}")

        print("=" * 45)

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
