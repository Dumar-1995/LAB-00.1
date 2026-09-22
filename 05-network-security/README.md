# 05 - Network Security

This module contains network security tools developed as part of the Cybersecurity Python Lab.

The tools are designed for educational purposes and authorized security assessments.

## Objectives

- Collect basic local network information.
- Identify local network interfaces.
- Identify IPv4 addresses.
- Identify IPv6 addresses.
- Identify the default gateway.
- Provide human-readable output.
- Provide structured JSON output.
- Develop defensive and non-invasive network analysis capabilities.

---

## Tool 01 - Local Network Information

### File

`local_network_info.py`

### Version

1.0

### Purpose

The Local Network Information tool collects basic network information from the system where the tool is executed.

The tool is designed to support:

- Educational laboratories.
- Defensive network analysis.
- Authorized security assessments.
- Local system troubleshooting.

### Features

- Hostname detection.
- Primary local IPv4 detection.
- Default gateway detection.
- IPv4 interface detection.
- IPv6 address detection.
- Human-readable output.
- JSON output.
- Local command error handling.
- Command execution timeout.

### Usage

Basic usage:

    python 05-network-security/local_network_info.py

JSON output:

    python 05-network-security/local_network_info.py --json

### Example

Example human-readable output:

    ============================================================
    Cybersecurity Python Lab - Local Network Information
    ============================================================
    Hostname        : kali
    Local IPv4      : 10.0.2.15
    Default Gateway : 10.0.2.2

    IPv4 Interfaces:
      - lo: 127.0.0.1
      - eth0: 10.0.2.15

    IPv6 Addresses:
      - lo: ::1/128
      - eth0: fd17:625c:f037:2:fb5d:e844:683a:430e/64
      - eth0: fe80::570f:6c52:7434:7f24/64

### JSON Output

The `--json` option returns structured information including:

- tool
- version
- hostname
- local_ipv4
- default_gateway
- interfaces
- ipv6_addresses

---

## Security Considerations

This tool is intended for:

- Educational laboratories.
- Systems owned by the user.
- Authorized security assessments.
- Defensive network analysis.

The tool does not perform:

- Port scanning.
- Network discovery.
- Traffic interception.
- Credential collection.
- Authentication bypass.
- Exploitation.
- Packet injection.

The tool only collects basic network information from the local system.

---

## Testing

The following tests were performed:

    python -m py_compile 05-network-security/local_network_info.py
    python 05-network-security/local_network_info.py
    python 05-network-security/local_network_info.py --json

Expected behavior:

- Successful Python compilation.
- Successful human-readable output.
- Successful JSON output.
- Hostname detection.
- IPv4 interface detection.
- IPv6 address detection.
- Default gateway detection.

---

## Future Improvements

Potential future versions may include:

- Network interface state detection.
- MAC address information.
- DNS resolver information.
- Routing table analysis.
- Network configuration summaries.
- Additional defensive network diagnostics.

---

## Version History

### v1.0

Initial local network information tool with:

- Hostname detection.
- IPv4 detection.
- IPv6 detection.
- Default gateway detection.
- Interface detection.
- Human-readable output.
- JSON output.
- Error handling.
