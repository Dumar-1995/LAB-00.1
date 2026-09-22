#!/usr/bin/env python3

"""
Cybersecurity Python Lab
Tool: Network Interface Information
Version: 1.0

Purpose:
    Collect detailed information about local network interfaces.

This tool is intended for:
    - Educational laboratories.
    - Authorized security assessments.
    - Defensive network analysis.

The tool does not perform:
    - Network discovery.
    - Port scanning.
    - Traffic interception.
    - Packet injection.
    - Credential collection.
    - Exploitation.
"""

import argparse
import json
import re
import subprocess
from typing import Any


TOOL_NAME = "Cybersecurity Python Lab - Network Interface Information"
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


def determine_state(flags: list[str], detected_state: str) -> str:
    """Determine interface state using link state and flags."""

    if detected_state in {"UP", "DOWN"}:
        return detected_state

    if "UP" in flags:
        return "UP"

    if "DOWN" in flags:
        return "DOWN"

    return "UNKNOWN"


def get_interfaces() -> list[dict[str, Any]]:
    """Collect local network interface information."""

    output = run_command(["ip", "-details", "link", "show"])

    if not output:
        return []

    interfaces: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    detected_state = "UNKNOWN"

    for line in output.splitlines():
        stripped = line.strip()

        interface_match = re.match(
            r"^\d+:\s+([^:@]+)(?:@[^:]+)?:\s+<([^>]*)>",
            stripped,
        )

        if interface_match:
            if current:
                current["state"] = determine_state(
                    current["flags"],
                    detected_state,
                )
                interfaces.append(current)

            name = interface_match.group(1)

            flags = [
                flag
                for flag in interface_match.group(2).split(",")
                if flag
            ]

            current = {
                "name": name,
                "flags": flags,
                "state": "UNKNOWN",
                "mtu": None,
                "mac_address": None,
            }

            detected_state = "UNKNOWN"

            mtu_match = re.search(
                r"\bmtu\s+(\d+)",
                stripped,
            )

            if mtu_match:
                current["mtu"] = int(mtu_match.group(1))

            state_match = re.search(
                r"\bstate\s+(\S+)",
                stripped,
            )

            if state_match:
                detected_state = state_match.group(1)

            continue

        if current is None:
            continue

        state_match = re.search(
            r"\bstate\s+(\S+)",
            stripped,
        )

        if state_match:
            detected_state = state_match.group(1)

        mac_match = re.search(
            r"\blink/ether\s+([0-9a-fA-F:]{17})",
            stripped,
        )

        if mac_match:
            current["mac_address"] = mac_match.group(1).lower()

    if current:
        current["state"] = determine_state(
            current["flags"],
            detected_state,
        )
        interfaces.append(current)

    return interfaces


def get_ipv4_addresses() -> dict[str, list[str]]:
    """Collect IPv4 addresses grouped by interface."""

    output = run_command(["ip", "-o", "-4", "addr", "show"])

    addresses: dict[str, list[str]] = {}

    if not output:
        return addresses

    for line in output.splitlines():
        parts = line.split()

        if len(parts) < 4:
            continue

        interface = parts[1]
        address = parts[3]

        addresses.setdefault(interface, []).append(address)

    return addresses


def get_ipv6_addresses() -> dict[str, list[str]]:
    """Collect IPv6 addresses grouped by interface."""

    output = run_command(["ip", "-o", "-6", "addr", "show"])

    addresses: dict[str, list[str]] = {}

    if not output:
        return addresses

    for line in output.splitlines():
        parts = line.split()

        if len(parts) < 4:
            continue

        interface = parts[1]
        address = parts[3]

        addresses.setdefault(interface, []).append(address)

    return addresses


def collect_interface_information() -> dict[str, Any]:
    """Collect and combine local interface information."""

    interfaces = get_interfaces()
    ipv4_addresses = get_ipv4_addresses()
    ipv6_addresses = get_ipv6_addresses()

    for interface in interfaces:
        name = interface["name"]

        interface["ipv4_addresses"] = ipv4_addresses.get(
            name,
            [],
        )

        interface["ipv6_addresses"] = ipv6_addresses.get(
            name,
            [],
        )

    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "interfaces": interfaces,
        "summary": {
            "interface_count": len(interfaces),
            "up_count": sum(
                1
                for interface in interfaces
                if interface["state"] == "UP"
            ),
            "down_count": sum(
                1
                for interface in interfaces
                if interface["state"] == "DOWN"
            ),
        },
    }


def print_human_readable(data: dict[str, Any]) -> None:
    """Print interface information in human-readable format."""

    print("=" * 60)
    print(TOOL_NAME)
    print("=" * 60)

    print()
    print("Network Interfaces:")

    if not data["interfaces"]:
        print("  None detected")
    else:
        for interface in data["interfaces"]:
            print()
            print(f"  Interface      : {interface['name']}")
            print(f"  State          : {interface['state']}")
            print(f"  MTU            : {interface['mtu']}")
            print(
                f"  MAC Address    : "
                f"{interface['mac_address'] or 'Unknown'}"
            )

            print("  IPv4 Addresses:")

            if interface["ipv4_addresses"]:
                for address in interface["ipv4_addresses"]:
                    print(f"    - {address}")
            else:
                print("    None")

            print("  IPv6 Addresses:")

            if interface["ipv6_addresses"]:
                for address in interface["ipv6_addresses"]:
                    print(f"    - {address}")
            else:
                print("    None")

    print()
    print("Summary:")
    print(
        f"  Interfaces      : "
        f"{data['summary']['interface_count']}"
    )
    print(
        f"  Interfaces UP   : "
        f"{data['summary']['up_count']}"
    )
    print(
        f"  Interfaces DOWN : "
        f"{data['summary']['down_count']}"
    )


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Collect detailed information about local "
            "network interfaces."
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

    data = collect_interface_information()

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print_human_readable(data)


if __name__ == "__main__":
    main()
