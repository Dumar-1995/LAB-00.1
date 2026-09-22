#!/usr/bin/env python3

"""
Cybersecurity Python Lab
Tool: Local Network Information
Version: 1.0

Purpose:
    Collect basic network information from the local system.

This tool is intended for:
    - Educational laboratories.
    - Authorized security assessments.
    - Defensive network analysis.

The tool does not perform:
    - Port scanning.
    - Network discovery.
    - Traffic interception.
    - Credential collection.
    - Exploitation.
"""

import argparse
import json
import re
import socket
import subprocess
from typing import Any


TOOL_NAME = "Cybersecurity Python Lab - Local Network Information"
VERSION = "1.0"


def run_command(command: list[str]) -> str:
    """Execute a local system command and return its output."""

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

        if result.returncode != 0:
            return ""

        return result.stdout.strip()

    except (subprocess.SubprocessError, OSError):
        return ""


def get_hostname() -> str:
    """Return the local hostname."""

    try:
        return socket.gethostname()
    except OSError:
        return "Unknown"


def get_local_ip() -> str:
    """Determine the primary local IPv4 address."""

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.connect(("10.255.255.255", 1))
        return sock.getsockname()[0]

    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            return "Unknown"

    finally:
        sock.close()


def get_interfaces() -> list[dict[str, str]]:
    """Return basic interface and IPv4 information."""

    output = run_command(["ip", "-o", "-4", "addr", "show"])

    interfaces: list[dict[str, str]] = []

    if not output:
        return interfaces

    for line in output.splitlines():
        parts = line.split()

        if len(parts) < 4:
            continue

        interface = parts[1]
        address = parts[3].split("/")[0]

        interfaces.append(
            {
                "interface": interface,
                "ipv4": address,
            }
        )

    return interfaces


def get_default_gateway() -> str:
    """Return the default IPv4 gateway."""

    output = run_command(["ip", "route", "show", "default"])

    if not output:
        return "Unknown"

    match = re.search(r"default via ([0-9.]+)", output)

    if match:
        return match.group(1)

    return "Unknown"


def get_ipv6_addresses() -> list[dict[str, str]]:
    """Return basic IPv6 information for local interfaces."""

    output = run_command(["ip", "-o", "-6", "addr", "show"])

    addresses: list[dict[str, str]] = []

    if not output:
        return addresses

    for line in output.splitlines():
        parts = line.split()

        if len(parts) < 4:
            continue

        interface = parts[1]
        address = parts[3]

        addresses.append(
            {
                "interface": interface,
                "ipv6": address,
            }
        )

    return addresses


def collect_network_information() -> dict[str, Any]:
    """Collect local network information."""

    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "hostname": get_hostname(),
        "local_ipv4": get_local_ip(),
        "default_gateway": get_default_gateway(),
        "interfaces": get_interfaces(),
        "ipv6_addresses": get_ipv6_addresses(),
    }


def print_human_readable(data: dict[str, Any]) -> None:
    """Print network information in human-readable format."""

    print("=" * 60)
    print(TOOL_NAME)
    print("=" * 60)

    print(f"Hostname        : {data['hostname']}")
    print(f"Local IPv4      : {data['local_ipv4']}")
    print(f"Default Gateway : {data['default_gateway']}")

    print()
    print("IPv4 Interfaces:")

    if data["interfaces"]:
        for item in data["interfaces"]:
            print(
                f"  - {item['interface']}: "
                f"{item['ipv4']}"
            )
    else:
        print("  None detected")

    print()
    print("IPv6 Addresses:")

    if data["ipv6_addresses"]:
        for item in data["ipv6_addresses"]:
            print(
                f"  - {item['interface']}: "
                f"{item['ipv6']}"
            )
    else:
        print("  None detected")


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Collect basic local network information "
            "for authorized security assessments."
        )
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Return results in JSON format.",
    )

    return parser.parse_args()


def main() -> None:
    """Application entry point."""

    args = parse_arguments()
    data = collect_network_information()

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print_human_readable(data)


if __name__ == "__main__":
    main()
