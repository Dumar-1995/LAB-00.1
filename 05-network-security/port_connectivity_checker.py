#!/usr/bin/env python3

"""
Cybersecurity Python Lab
Tool: Port Connectivity Checker
Version: 1.0

Purpose:
    Check TCP connectivity to specific ports on an authorized host.

This tool is intended for:
    - Educational laboratories.
    - Authorized security assessments.
    - Defensive network analysis.

The tool does not perform:
    - Port range scanning.
    - Network discovery.
    - Service exploitation.
    - Credential attacks.
    - Vulnerability exploitation.
"""

import argparse
import json
import socket
from typing import Any


TOOL_NAME = "Cybersecurity Python Lab - Port Connectivity Checker"
VERSION = "1.0"
DEFAULT_TIMEOUT = 3.0


def check_port(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Check TCP connectivity to a specific host and port."""

    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "protocol": "TCP",
        "reachable": False,
        "error": None,
    }

    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ):
            result["reachable"] = True

    except socket.timeout:
        result["error"] = "Connection timed out."

    except ConnectionRefusedError:
        result["error"] = "Connection refused."

    except socket.gaierror:
        result["error"] = "Host resolution failed."

    except OSError as exc:
        result["error"] = str(exc)

    return result


def build_results(
    host: str,
    ports: list[int],
    timeout: float,
) -> dict[str, Any]:
    """Check all requested ports."""

    results = [
        check_port(host, port, timeout)
        for port in ports
    ]

    reachable_count = sum(
        1 for result in results if result["reachable"]
    )

    return {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": host,
        "timeout": timeout,
        "results": results,
        "summary": {
            "port_count": len(results),
            "reachable_count": reachable_count,
            "unreachable_count": len(results) - reachable_count,
        },
    }


def print_human_readable(data: dict[str, Any]) -> None:
    """Print results in human-readable format."""

    print("=" * 60)
    print(TOOL_NAME)
    print("=" * 60)

    print(f"Target          : {data['target']}")
    print(f"Timeout         : {data['timeout']} seconds")

    print()
    print("TCP Connectivity:")

    for result in data["results"]:
        status = "REACHABLE" if result["reachable"] else "UNREACHABLE"

        print(
            f"  - {data['target']}:{result['port']} -> {status}"
        )

        if result["error"]:
            print(f"      Reason: {result['error']}")

    print()
    print("Summary:")
    print(
        f"  Ports checked   : "
        f"{data['summary']['port_count']}"
    )
    print(
        f"  Reachable       : "
        f"{data['summary']['reachable_count']}"
    )
    print(
        f"  Unreachable     : "
        f"{data['summary']['unreachable_count']}"
    )


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Check TCP connectivity to specific ports "
            "on an authorized host."
        )
    )

    parser.add_argument(
        "host",
        help="Target hostname or IP address.",
    )

    parser.add_argument(
        "ports",
        nargs="+",
        type=int,
        help="One or more TCP ports to check.",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=(
            f"Connection timeout in seconds "
            f"(default: {DEFAULT_TIMEOUT})."
        ),
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Return results in JSON format.",
    )

    return parser.parse_args()


def validate_arguments(args: argparse.Namespace) -> None:
    """Validate command-line arguments."""

    if not 0.1 <= args.timeout <= 30:
        raise ValueError(
            "Timeout must be between 0.1 and 30 seconds."
        )

    for port in args.ports:
        if not 1 <= port <= 65535:
            raise ValueError(
                f"Invalid port: {port}. "
                "Ports must be between 1 and 65535."
            )


def main() -> None:
    """Application entry point."""

    args = parse_arguments()

    try:
        validate_arguments(args)

    except ValueError as exc:
        print(f"[ERROR] {exc}")
        raise SystemExit(1)

    data = build_results(
        args.host,
        args.ports,
        args.timeout,
    )

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print_human_readable(data)


if __name__ == "__main__":
    main()
