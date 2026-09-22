# 05 - Network Security

This module contains network security tools developed as part of the Cybersecurity Python Lab.

The tools are designed for educational purposes and authorized security assessments.

## Objectives

- Collect basic local network information.
- Identify local network interfaces.
- Identify IPv4 addresses.
- Identify IPv6 addresses.
- Identify the default gateway.
- Check TCP connectivity to specific ports.
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

---

## Tool 02 - Port Connectivity Checker

### File

`port_connectivity_checker.py`

### Version

1.0

### Purpose

The Port Connectivity Checker verifies TCP connectivity to specific ports on a designated host.

The tool is designed to support:

- Educational laboratories.
- Authorized security assessments.
- Defensive network analysis.
- Basic connectivity troubleshooting.

The tool checks only the ports explicitly provided by the user.

### Features

- TCP connectivity testing.
- Hostname or IPv4 address support.
- Multiple specific ports.
- Configurable connection timeout.
- TCP connection status detection.
- Connection timeout handling.
- Connection refusal handling.
- Host resolution error handling.
- Human-readable output.
- JSON output.
- Port range validation.

### Usage

Check one specific port:

    python 05-network-security/port_connectivity_checker.py 127.0.0.1 22

Check multiple specific ports:

    python 05-network-security/port_connectivity_checker.py 127.0.0.1 22 80 443

Custom timeout:

    python 05-network-security/port_connectivity_checker.py 127.0.0.1 22 --timeout 5

JSON output:

    python 05-network-security/port_connectivity_checker.py 127.0.0.1 22 80 443 --json

### Example

Example human-readable output:

    ============================================================
    Cybersecurity Python Lab - Port Connectivity Checker
    ============================================================
    Target          : 127.0.0.1
    Timeout         : 3.0 seconds

    TCP Connectivity:
      - 127.0.0.1:22 -> UNREACHABLE
          Reason: Connection refused.
      - 127.0.0.1:80 -> UNREACHABLE
          Reason: Connection refused.
      - 127.0.0.1:443 -> UNREACHABLE
          Reason: Connection refused.

    Summary:
      Ports checked   : 3
      Reachable       : 0
      Unreachable     : 3

### JSON Output

The `--json` option returns structured information including:

- tool
- version
- target
- timeout
- results
- summary

Each result contains:

- host
- port
- protocol
- reachable
- error

The summary contains:

- port_count
- reachable_count
- unreachable_count

---

## Security Considerations

These tools are intended for:

- Educational laboratories.
- Systems owned by the user.
- Authorized security assessments.
- Defensive network analysis.

The tools do not perform:

- Port range scanning.
- Network discovery.
- Traffic interception.
- Credential collection.
- Authentication bypass.
- Exploitation.
- Packet injection.
- Vulnerability exploitation.

The Port Connectivity Checker only tests the specific TCP ports explicitly provided by the user.

---

## Testing

### Tool 01 - Local Network Information

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

### Tool 02 - Port Connectivity Checker

The following tests were performed:

    python -m py_compile 05-network-security/port_connectivity_checker.py
    python 05-network-security/port_connectivity_checker.py 127.0.0.1 22
    python 05-network-security/port_connectivity_checker.py 127.0.0.1 22 80 443
    python 05-network-security/port_connectivity_checker.py 127.0.0.1 22 80 443 --json

Expected behavior:

- Successful Python compilation.
- TCP connectivity check.
- Multiple specific port checks.
- Connection refusal handling.
- Human-readable output.
- JSON output.
- Port validation.

---

## Future Improvements

Potential future versions may include:

- Network interface state detection.
- MAC address information.
- DNS resolver information.
- Routing table analysis.
- Network configuration summaries.
- Additional defensive network diagnostics.
- Optional service identification for explicitly selected ports.

---

## Version History

### v1.0 - Tool 01

Initial local network information tool with:

- Hostname detection.
- IPv4 detection.
- IPv6 detection.
- Default gateway detection.
- Interface detection.
- Human-readable output.
- JSON output.
- Error handling.

### v1.0 - Tool 02

Initial TCP connectivity checker with:

- Specific TCP port testing.
- Multiple port support.
- Configurable timeout.
- Connection error handling.
- Host resolution error handling.
- Human-readable output.
- JSON output.
- Port validation.
