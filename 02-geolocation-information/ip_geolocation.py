#!/usr/bin/env python3

"""
IP Geolocation Tool
-------------------

Retrieves approximate geolocation and network information
for a public IPv4 or IPv6 address.

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
    print("IP GEOLOCATION & NETWORK INFORMATION")
    print(f"Version {VERSION}")
    print("=" * 72)


def resolve_target(target):
    """
    Resolve a hostname to an IP address.

    If the target is already an IP address, return it directly.
    """

    try:
        ipaddress.ip_address(target)
        return target

    except ValueError:
        pass

    try:
        resolved_ip = socket.gethostbyname(target)

        return resolved_ip

    except socket.gaierror as error:
        raise ValueError(
            f"Unable to resolve target '{target}': {error}"
        ) from error


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
            f"Unable to connect to the geolocation service: "
            f"{error.reason}"
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
            "The geolocation service returned invalid JSON."
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


def build_result(target, ip_address, data):
    """
    Build a normalized result structure.
    """

    connection = data.get(
        "connection",
        {},
    )

    timezone = data.get(
        "timezone",
        {},
    )

    return {
        "assessment": {
            "tool": "IP Geolocation & Network Information",
            "version": VERSION,
            "target": target,
            "resolved_ip": ip_address,
            "ip_classification": classify_ip(
                ip_address
            ),
            "timestamp": datetime.now().isoformat(
                timespec="seconds"
            ),
        },
        "geolocation": {
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
        },
        "network": {
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
            "reverse_dns": connection.get(
                "reverse"
            ),
        },
        "timezone": {
            "id": timezone.get(
                "id"
            ),
            "abbreviation": timezone.get(
                "abbr"
            ),
            "utc_offset": timezone.get(
                "utc"
            ),
            "current_time": timezone.get(
                "current_time"
            ),
        },
    }


def print_section(title):
    """Print a formatted section title."""

    print()
    print(f"[{title}]")
    print("-" * 72)


def print_result(result):
    """Display the normalized assessment result."""

    assessment = result["assessment"]
    geolocation = result["geolocation"]
    network = result["network"]
    timezone = result["timezone"]

    print_section("ASSESSMENT")

    print(
        f"Target              : "
        f"{assessment['target']}"
    )

    print(
        f"Resolved IP         : "
        f"{assessment['resolved_ip']}"
    )

    print(
        f"IP Classification   : "
        f"{assessment['ip_classification']}"
    )

    print(
        f"Assessment Time     : "
        f"{assessment['timestamp']}"
    )

    print_section("GEOLOCATION")

    print(
        f"Continent           : "
        f"{geolocation['continent'] or 'Not available'}"
    )

    print(
        f"Country             : "
        f"{geolocation['country'] or 'Not available'}"
    )

    print(
        f"Region              : "
        f"{geolocation['region'] or 'Not available'}"
    )

    print(
        f"City                : "
        f"{geolocation['city'] or 'Not available'}"
    )

    print(
        f"Postal Code         : "
        f"{geolocation['postal_code'] or 'Not available'}"
    )

    print(
        f"Latitude            : "
        f"{geolocation['latitude']}"
    )

    print(
        f"Longitude           : "
        f"{geolocation['longitude']}"
    )

    print_section("NETWORK INFORMATION")

    print(
        f"ISP                 : "
        f"{network['isp'] or 'Not available'}"
    )

    print(
        f"Organization        : "
        f"{network['organization'] or 'Not available'}"
    )

    print(
        f"ASN                 : "
        f"{network['asn'] or 'Not available'}"
    )

    print(
        f"Network Domain      : "
        f"{network['network_domain'] or 'Not available'}"
    )

    print(
        f"Reverse DNS         : "
        f"{network['reverse_dns'] or 'Not available'}"
    )

    print_section("TIMEZONE")

    print(
        f"Timezone            : "
        f"{timezone['id'] or 'Not available'}"
    )

    print(
        f"Abbreviation        : "
        f"{timezone['abbreviation'] or 'Not available'}"
    )

    print(
        f"UTC Offset          : "
        f"{timezone['utc_offset'] or 'Not available'}"
    )

    print(
        f"Current Time        : "
        f"{timezone['current_time'] or 'Not available'}"
    )

    print()
    print("=" * 72)
    print("METHODOLOGICAL NOTE")
    print("=" * 72)
    print(
        "IP geolocation is approximate and should not be "
        "interpreted as the exact physical location of a "
        "person or device."
    )

    print(
        "Results depend on the accuracy and coverage of "
        "the external geolocation service."
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
            "Retrieve approximate geolocation and "
            "network information for an IP address."
        )
    )

    parser.add_argument(
        "target",
        help=(
            "IPv4, IPv6 address, or hostname "
            "to analyze."
        ),
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON.",
    )

    args = parser.parse_args()

    print_banner()

    target = args.target.strip()

    if not target:
        print(
            "ERROR: Target cannot be empty.",
            file=sys.stderr,
        )

        sys.exit(1)

    try:
        ip_address = resolve_target(target)

    except ValueError as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )

        sys.exit(1)

    classification = classify_ip(
        ip_address
    )

    if classification != "PUBLIC":
        print()
        print(
            f"Target classification: "
            f"{classification}"
        )

        print(
            "Geolocation lookup is intended "
            "for publicly routable IP addresses."
        )

        sys.exit(0)

    try:
        data = query_geolocation(
            ip_address
        )

    except RuntimeError as error:
        print(
            f"ERROR: {error}",
            file=sys.stderr,
        )

        sys.exit(1)

    result = build_result(
        target,
        ip_address,
        data,
    )

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
