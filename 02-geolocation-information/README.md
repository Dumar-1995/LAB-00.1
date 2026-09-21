# 02 - Geolocation Information

This module contains tools for collecting approximate geolocation
and network information associated with public IP addresses.

The tools are intended for authorized cybersecurity assessments,
reconnaissance, laboratory environments, and educational purposes.

---

## Tool 01 - IP Geolocation & Network Information

### File

```text
ip_geolocation.py
---

## Tool 02 - Hostname Geolocation & Network Information

### File

```text
hostname_geolocation.py
Purpose

The tool resolves a hostname into IPv4 and IPv6 addresses and
retrieves approximate geolocation and network information for
publicly routable addresses.

Unlike the IP geolocation tool, this tool begins with a hostname
and performs DNS resolution before the geolocation process.

Technical Features

The tool implements:

Hostname resolution.
IPv4 resolution.
IPv6 resolution.
Multiple-address handling.
IP classification.
Public/private address differentiation.
Approximate geolocation.
ISP identification.
Organization identification.
ASN identification.
Network domain identification.
Timezone identification.
Human-readable output.
JSON output.
Error handling.

Usage
Basic execution
python hostname_geolocation.py google.com

python hostname_geolocation.py google.com --json

python hostname_geolocation.py --help

Hostname
   |
   v
DNS Resolution
   |
   +---- IPv4 addresses
   |
   +---- IPv6 addresses
   |
   v
IP Classification
   |
   +---- PRIVATE / RESERVED / etc.
   |
   +---- PUBLIC
             |
             v
       Geolocation API
             |
             v
       Normalized Result

Methodological Considerations

A hostname can resolve to multiple IP addresses.

Different IP addresses associated with the same hostname may
produce different network and geolocation information.

IP geolocation should therefore be treated as approximate
network-context information.

The geographic result should not be interpreted as proof of the
physical location of an organization, person, server, or device.

DNS resolution can also vary according to geographic location,
DNS provider, load balancing, CDN configuration, and other
infrastructure factors.

Security Scope

This tool is intended for:

Authorized reconnaissance.
Cybersecurity laboratories.
Educational exercises.
Infrastructure inventory.
Network-context analysis.

Only domains and infrastructure within an authorized assessment
scope should be analyzed.

