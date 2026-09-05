#!/usr/bin/env python3

"""
WHOIS Lookup Tool
Cybersecurity Python Lab

This script performs WHOIS queries and displays
domain registration information in a structured format.
"""

import whois


def format_value(value):
    """
    Formats WHOIS values that may not be publicly available.
    """

    if value is None:
        return "Not publicly available"

    return value


def main():

    print("=" * 60)
    print("WHOIS DOMAIN INFORMATION TOOL")
    print("=" * 60)

    domain = input("\nEnter a domain (example.com): ").strip()

    if not domain:
        print("\n[!] No domain provided.")
        return

    try:

        print(f"\n[+] Performing WHOIS lookup for: {domain}")

        domain_info = whois.whois(domain)

        print("\n" + "=" * 60)
        print("DOMAIN REGISTRATION INFORMATION")
        print("=" * 60)

        print(f"\nDomain Name: {format_value(domain_info.domain_name)}")
        print(f"Registrar: {format_value(domain_info.registrar)}")
        print(f"Organization: {format_value(domain_info.org)}")
        print(f"Creation Date: {format_value(domain_info.creation_date)}")
        print(f"Expiration Date: {format_value(domain_info.expiration_date)}")
        print(f"Updated Date: {format_value(domain_info.updated_date)}")
        print(f"Country: {format_value(domain_info.country)}")
        print(f"DNSSEC: {format_value(domain_info.dnssec)}")

        print("\nName Servers:")

        if domain_info.name_servers:

            for server in domain_info.name_servers:
                print(f"  - {server}")

        else:
            print("  No name servers found.")

        print("\nDomain Status:")

        if domain_info.status:

            if isinstance(domain_info.status, list):

                for status in domain_info.status:
                    print(f"  - {status}")

            else:
                print(f"  - {domain_info.status}")

        else:
            print("  No status information found.")

        print("\nContact Emails:")

        if domain_info.emails:

            if isinstance(domain_info.emails, list):

                for email in domain_info.emails:
                    print(f"  - {email}")

            else:
                print(f"  - {domain_info.emails}")

        else:
            print("  No public contact emails found.")

        print("\n" + "=" * 60)
        print("WHOIS LOOKUP COMPLETED")
        print("=" * 60)

    except Exception as error:

        print(f"\n[!] Error performing WHOIS lookup: {error}")


if __name__ == "__main__":
    main()
