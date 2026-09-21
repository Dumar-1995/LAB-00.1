#!/usr/bin/env python3

"""
Hostname Geolocation Tool
-------------------------

Resolves a hostname into IPv4 and IPv6 addresses and retrieves
approximate geolocation and network information for each
publicly routable address.

This tool is intended for authorized cybersecurity assessment,
reconnaissance, and educational purposes.

Version: 1.0
"""

import argparse
import ipaddress
import json
import socket
import sys
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


VERSION = "1.0"

API_BASE_URL = "https://ipwho.is"

USER_AGENT = (
    "Cybersecurity-Python-Lab/"
    f"{VERSION}"
)


def print_banner():
    """Display the application banner."""

    print("=" * 72)
    print("HOSTNAME GEOLOCATION & NETWORK INFORMATION")
    print(f"Version {VERSION}")
    print("=" * 72)


def resolve_hostname(hostname):
    """
    Resolve a hostname into IPv4 and IPv6 addresses.

    Returns a dictionary containing unique addresses
    grouped by address family.
    """

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

    except socket.gaierror as error:
        raise ValueError(
            f"Unable to resolve hostname "
            f"'{hostname}': {error}"
        ) from error

    ipv4_addresses = set()
    ipv6_addresses = set()

    for result in results:
        address_family = result[0]
        address = result[4][0]

        if address_family == socket.AF_INET:
            ipv4_addresses.add(address)

        elif address_family == socket.AF_INET6:
            ipv6_addresses.add(address)

    return {
        "ipv4": sorted(ipv4_addresses),
        "ipv6": sorted(ipv6_addresses),
    }


def classify_ip(ip_address):
    """
    Classify an IP address according to its network context.
    """

    ip = ipaddress.ip_address(ip_address)

    if ip.is_private:
        return "PRIVATE"

    if ip.is_loopback:
        return "LOOPBACK"

    if ip.is_link_local:
        return "LINK-LOCAL"

    if ip.is_multicast:
        return "MULTICAST"

    if ip.is_reserved:
        return "RESERVED"

    if ip.is_unspecified:
        return "UNSPECIFIED"

    return "PUBLIC"


def query_geolocation(ip_address):
    """
    Query the external geolocation service.
    """

    encoded_ip = quote(ip_address)

    url = f"{API_BASE_URL}/{encoded_ip}"

    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        },
    )

    try:
        with urlopen(
            request,
            timeout=10,
        ) as response:

            raw_data = response.read()

    except HTTPError as error:
        raise RuntimeError(
            f"HTTP error {error.code} while querying "
            "the geolocation service."
        ) from error

    except URLError as error:
        raise RuntimeError(
            f"Unable to connect to the geolocation "
            f"service: {error.reason}"
        ) from error

    except TimeoutError as error:
        raise RuntimeError(
            "The geolocation service request timed out."
        ) from error

    try:
        data = json.loads(
            raw_data.decode("utf-8")
        )

    except json.JSONDecodeError as error:
        raise RuntimeError(
            "The geolocation service returned "
            "invalid JSON."
        ) from error

    if not data.get("success", False):
        message = data.get(
            "message",
            "Unknown API error.",
        )

        raise RuntimeError(
            f"Geolocation service error: {message}"
        )

    return data


def build_result(hostname, addresses):
    """
    Build the normalized assessment result.
    """

    result = {
        "assessment": {
            "tool": (
                "Hostname Geolocation & "
                "Network Information"
            ),
            "version": VERSION,
            "target": hostname,
            "timestamp": datetime.now().isoformat(
                timespec="seconds"
            ),
        },
        "resolution": {
            "ipv4": [],
            "ipv6": [],
        },
        "geolocation": [],
    }

    for address_family in ("ipv4", "ipv6"):

        for ip_address in addresses[address_family]:

            classification = classify_ip(
                ip_address
            )

            result["resolution"][
                address_family
            ].append(
                {
                    "address": ip_address,
                    "classification": classification,
                }
            )

            if classification != "PUBLIC":
                continue

            data = query_geolocation(
                ip_address
            )

            connection = data.get(
                "connection",
                {},
            )

            timezone = data.get(
                "timezone",
                {},
            )

            result["geolocation"].append(
                {
                    "ip_address": ip_address,
                    "address_family": (
                        address_family.upper()
                    ),
                    "continent": data.get(
                        "continent"
                    ),
                    "country": data.get(
                        "country"
                    ),
                    "region": data.get(
                        "region"
                    ),
                    "city": data.get(
                        "city"
                    ),
                    "postal_code": data.get(
                        "postal"
                    ),
                    "latitude": data.get(
                        "latitude"
                    ),
                    "longitude": data.get(
                        "longitude"
                    ),
                    "isp": connection.get(
                        "isp"
                    ),
                    "organization": connection.get(
                        "org"
                    ),
                    "asn": connection.get(
                        "asn"
                    ),
                    "network_domain": connection.get(
                        "domain"
                    ),
                    "timezone": timezone.get(
                        "id"
                    ),
                    "utc_offset": timezone.get(
                        "utc"
                    ),
                }
            )

    return result


def print_section(title):
    """Print a formatted section title."""

    print()
    print(f"[{title}]")
    print("-" * 72)


def print_result(result):
    """Display the normalized assessment result."""

    assessment = result["assessment"]
    resolution = result["resolution"]
    geolocation = result["geolocation"]

    print_section("ASSESSMENT")

    print(
        f"Target              : "
        f"{assessment['target']}"
    )

    print(
        f"Assessment Time     : "
        f"{assessment['timestamp']}"
    )

    print_section("DNS RESOLUTION")

    print("IPv4 addresses:")

    if resolution["ipv4"]:
        for item in resolution["ipv4"]:
            print(
                f"  - {item['address']} "
                f"({item['classification']})"
            )
    else:
        print("  - None")

    print()
    print("IPv6 addresses:")

    if resolution["ipv6"]:
        for item in resolution["ipv6"]:
            print(
                f"  - {item['address']} "
                f"({item['classification']})"
            )
    else:
        print("  - None")

    print_section("GEOLOCATION")

    if not geolocation:
        print(
            "No public IP addresses were available "
            "for geolocation."
        )

    for item in geolocation:

        print(
            f"IP Address         : "
            f"{item['ip_address']}"
        )

        print(
            f"Address Family     : "
            f"{item['address_family']}"
        )

        print(
            f"Country            : "
            f"{item['country'] or 'Not available'}"
        )

        print(
            f"Region             : "
            f"{item['region'] or 'Not available'}"
        )

        print(
            f"City               : "
            f"{item['city'] or 'Not available'}"
        )

        print(
            f"Latitude           : "
            f"{item['latitude']}"
        )

        print(
            f"Longitude          : "
            f"{item['longitude']}"
        )

        print(
            f"ISP                : "
            f"{item['isp'] or 'Not available'}"
        )

        print(
            f"Organization       : "
            f"{item['organization'] or 'Not available'}"
        )

        print(
            f"ASN                : "
            f"{item['asn'] or 'Not available'}"
        )

        print(
            f"Network Domain     : "
            f"{item['network_domain'] or 'Not available'}"
        )

        print(
            f"Timezone           : "
            f"{item['timezone'] or 'Not available'}"
        )

        print(
            f"UTC Offset         : "
            f"{item['utc_offset'] or 'Not available'}"
        )

        print("-" * 72)

    print()
    print("=" * 72)
    print("METHODOLOGICAL NOTE")
    print("=" * 72)

    print(
        "DNS resolution can return multiple IP addresses "
        "for a single hostname."
    )

    print(
        "IP geolocation is approximate and should not be "
        "interpreted as the exact physical location of a "
        "person or device."
    )

    print(
        "Geolocation results depend on the accuracy and "
        "coverage of the external service."
    )

    print(
        "Use this information only within an authorized "
        "security assessment scope."
    )

    print("=" * 72)


def main():
    """Main application entry point."""

    parser = argparse.ArgumentParser(
        description=(
            "Resolve a hostname and retrieve approximate "
            "geolocation and network information."
        )
    )

    parser.add_argument(
        "hostname",
        help=(
            "Hostname or domain to analyze."
        ),
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON.",
    )

    args = parser.parse_args()

    print_banner()

    hostname = args.hostname.strip()

    if not hostname:
        print(
            "ERROR: Hostname cannot be empty.",
            file=sys.stderr,
        )

        sys.exit(1)

    try:
        addresses = resolve_hostname(
            hostname
        )

    except ValueError as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )

        sys.exit(1)

    if (
        not addresses["ipv4"]
        and not addresses["ipv6"]
    ):
        print(
            "ERROR: No IP addresses were resolved "
            f"for '{hostname}'.",
            file=sys.stderr,
        )

        sys.exit(1)

    try:
        result = build_result(
            hostname,
            addresses,
        )

    except RuntimeError as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )

        sys.exit(1)

    if args.json:
        print(
            json.dumps(
                result,
                indent=4,
                ensure_ascii=False,
            )
        )

    else:
        print_result(result)


if __name__ == "__main__":
    main()
