import socket
import ipaddress
from datetime import datetime


# ============================================================
# PORT & SERVICE RECON ANALYZER
# EDUCATIONAL LABORATORY TOOL
# ============================================================


# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP Alternative"
}

TIMEOUT = 1


# ------------------------------------------------------------
# SERVICE EXPOSURE WEIGHTS
# ------------------------------------------------------------

SERVICE_RISK = {
    21: {
        "level": "HIGH",
        "points": 25,
        "reason": "FTP may transmit credentials and data without encryption."
    },

    22: {
        "level": "MEDIUM",
        "points": 8,
        "reason": "SSH provides remote administration and should be strongly protected."
    },

    23: {
        "level": "CRITICAL",
        "points": 30,
        "reason": "Telnet transmits communications without encryption."
    },

    25: {
        "level": "MEDIUM",
        "points": 10,
        "reason": "SMTP can be abused if mail services are improperly configured."
    },

    53: {
        "level": "LOW",
        "points": 5,
        "reason": "DNS is commonly exposed but should be properly secured."
    },

    80: {
        "level": "MEDIUM",
        "points": 10,
        "reason": "HTTP traffic is not encrypted."
    },

    110: {
        "level": "HIGH",
        "points": 20,
        "reason": "POP3 may expose credentials if encryption is not enforced."
    },

    143: {
        "level": "HIGH",
        "points": 20,
        "reason": "IMAP may expose credentials if encryption is not enforced."
    },

    443: {
        "level": "LOW",
        "points": 5,
        "reason": "HTTPS provides encrypted communication when properly configured."
    },

    445: {
        "level": "HIGH",
        "points": 25,
        "reason": "SMB exposure can increase attack surface and should be restricted."
    },

    3306: {
        "level": "HIGH",
        "points": 25,
        "reason": "A publicly exposed database service increases attack surface."
    },

    3389: {
        "level": "HIGH",
        "points": 25,
        "reason": "RDP provides remote access and should be tightly restricted."
    },

    8080: {
        "level": "MEDIUM",
        "points": 10,
        "reason": "Alternative web services may expose administrative interfaces."
    }
}


# ============================================================
# DISPLAY FUNCTIONS
# ============================================================

def print_banner():

    print("=" * 60)
    print("PORT & SERVICE EXPOSURE ANALYZER")
    print("=" * 60)

    print("\nEducational cybersecurity laboratory tool.")
    print("Use only against systems you own or are authorized to test.")


# ============================================================
# TARGET RESOLUTION
# ============================================================

def resolve_target(target):

    try:

        ipaddress.ip_address(target)

        return target, "IP Address"

    except ValueError:

        try:

            ip_address = socket.gethostbyname(target)

            return ip_address, "Domain"

        except socket.gaierror:

            return None, None


# ============================================================
# IP CLASSIFICATION
# ============================================================

def classify_ip(ip_address):

    try:

        ip = ipaddress.ip_address(ip_address)

        if ip.is_private:
            return "PRIVATE"

        elif ip.is_loopback:
            return "LOOPBACK"

        elif ip.is_multicast:
            return "MULTICAST"

        elif ip.is_reserved:
            return "RESERVED"

        else:
            return "PUBLIC"

    except ValueError:

        return "UNKNOWN"


# ============================================================
# TCP PORT CHECK
# ============================================================

def check_port(ip_address, port):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(TIMEOUT)

    result = sock.connect_ex(
        (ip_address, port)
    )

    sock.close()

    return result == 0


# ============================================================
# SERVICE INFORMATION
# ============================================================

def get_service_information(port):

    if port in SERVICE_RISK:

        return SERVICE_RISK[port]

    return {
        "level": "UNKNOWN",
        "points": 5,
        "reason": "Unknown service exposure."
    }


# ============================================================
# EXPOSURE ANALYSIS
# ============================================================

def analyze_service_exposure(port):

    service = COMMON_PORTS.get(
        port,
        "Unknown"
    )

    risk_data = get_service_information(port)

    return {
        "port": port,
        "service": service,
        "risk_level": risk_data["level"],
        "risk_points": risk_data["points"],
        "reason": risk_data["reason"]
    }


# ============================================================
# HTTP / HTTPS OBSERVATION
# ============================================================

def analyze_web_exposure(open_ports):

    observations = []

    http_open = 80 in open_ports
    https_open = 443 in open_ports

    if http_open and not https_open:

        observations.append(
            "HTTP is exposed but HTTPS was not detected in the selected scan. "
            "Review whether encrypted HTTPS access is available."
        )

    elif http_open and https_open:

        observations.append(
            "Both HTTP and HTTPS are available. Review whether HTTP redirects "
            "users automatically to HTTPS."
        )

    elif https_open:

        observations.append(
            "HTTPS is available. TLS and certificate configuration should still "
            "be reviewed separately."
        )

    return observations


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_exposure_risk(open_ports):

    if not open_ports:

        return {
            "score": 0,
            "level": "LOW",
            "assessment": (
                "No open ports were detected from the selected common port list."
            )
        }

    total_points = 0

    for port in open_ports:

        service_info = get_service_information(port)

        total_points += service_info["points"]

    # Limit score to 100
    score = min(total_points, 100)

    # Overall classification
    if score >= 70:

        level = "HIGH"

        assessment = (
            "High exposure detected. Multiple sensitive or higher-risk "
            "services are externally reachable."
        )

    elif score >= 35:

        level = "MEDIUM"

        assessment = (
            "Moderate exposure detected. Some services should be reviewed "
            "and access restrictions should be evaluated."
        )

    else:

        level = "LOW"

        assessment = (
            "Limited exposure detected from the selected port list."
        )

    return {
        "score": score,
        "level": level,
        "assessment": assessment
    }


# ============================================================
# SECURITY RECOMMENDATIONS
# ============================================================

def generate_recommendations(open_ports):

    recommendations = []

    if 21 in open_ports:

        recommendations.append(
            "FTP: Consider replacing traditional FTP with SFTP or FTPS."
        )

    if 22 in open_ports:

        recommendations.append(
            "SSH: Use strong authentication, restrict administrative access, "
            "and review password-based login policies."
        )

    if 23 in open_ports:

        recommendations.append(
            "Telnet: Disable Telnet and migrate to SSH."
        )

    if 25 in open_ports:

        recommendations.append(
            "SMTP: Review relay restrictions, authentication, and mail security."
        )

    if 80 in open_ports:

        recommendations.append(
            "HTTP: Review whether users should be redirected to HTTPS."
        )

    if 110 in open_ports:

        recommendations.append(
            "POP3: Prefer encrypted alternatives such as POP3S."
        )

    if 143 in open_ports:

        recommendations.append(
            "IMAP: Prefer encrypted alternatives such as IMAPS."
        )

    if 445 in open_ports:

        recommendations.append(
            "SMB: Restrict public exposure and review network access controls."
        )

    if 3306 in open_ports:

        recommendations.append(
            "MySQL: Avoid unnecessary public database exposure and restrict "
            "access to trusted hosts."
        )

    if 3389 in open_ports:

        recommendations.append(
            "RDP: Restrict access, use strong authentication, and avoid "
            "unnecessary public exposure."
        )

    if 8080 in open_ports:

        recommendations.append(
            "Port 8080: Review whether administrative or development services "
            "are publicly exposed."
        )

    if not recommendations:

        recommendations.append(
            "Continue monitoring externally exposed services and review "
            "firewall rules regularly."
        )

    return recommendations


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    print_banner()

    target = input(
        "\nEnter an IP address or domain (example: authorized-test-host): "
    ).strip()

    if not target:

        print("\n[-] No target provided.")

        return


    # --------------------------------------------------------
    # TARGET INFORMATION
    # --------------------------------------------------------

    print("\n[+] Target:", target)

    print("=" * 60)
    print("TARGET RESOLUTION")
    print("=" * 60)

    ip_address, target_type = resolve_target(target)

    if not ip_address:

        print("\n[-] Unable to resolve target.")

        return

    print("\nTarget Type:", target_type)
    print("Resolved IP:", ip_address)

    ip_type = classify_ip(ip_address)

    print("IP Classification:", ip_type)


    # --------------------------------------------------------
    # PORT ANALYSIS
    # --------------------------------------------------------

    print("\n" + "=" * 60)
    print("PORT ANALYSIS")
    print("=" * 60)

    print(
        "\n[+] Scan started:",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    print("\nScanning selected common TCP ports...\n")

    open_ports = []

    for port, service in COMMON_PORTS.items():

        is_open = check_port(
            ip_address,
            port
        )

        if is_open:

            service_data = get_service_information(port)

            print(
                f"[+] Port {port}/TCP OPEN"
            )

            print(
                f"    Service: {service}"
            )

            print(
                f"    Exposure Level: {service_data['level']}"
            )

            print(
                f"    Exposure Points: {service_data['points']}"
            )

            open_ports.append(port)

        else:

            print(
                f"[-] Port {port}/TCP CLOSED or FILTERED"
            )


    # --------------------------------------------------------
    # OPEN SERVICE ANALYSIS
    # --------------------------------------------------------

    print("\n" + "=" * 60)
    print("EXPOSED SERVICE ANALYSIS")
    print("=" * 60)

    if open_ports:

        for port in open_ports:

            analysis = analyze_service_exposure(port)

            print(f"\nPort: {analysis['port']}/TCP")
            print(f"Service: {analysis['service']}")
            print(f"Exposure Level: {analysis['risk_level']}")
            print(f"Exposure Points: {analysis['risk_points']}")
            print(f"Observation: {analysis['reason']}")

    else:

        print(
            "\n[-] No open ports detected from the selected list."
        )


    # --------------------------------------------------------
    # WEB EXPOSURE
    # --------------------------------------------------------

    web_observations = analyze_web_exposure(open_ports)

    if web_observations:

        print("\n" + "=" * 60)
        print("WEB SERVICE OBSERVATIONS")
        print("=" * 60)

        for observation in web_observations:

            print("\n- " + observation)


    # --------------------------------------------------------
    # RISK ASSESSMENT
    # --------------------------------------------------------

    risk = calculate_exposure_risk(open_ports)

    print("\n" + "=" * 60)
    print("OVERALL EXPOSURE ASSESSMENT")
    print("=" * 60)

    print(
        "\nExposure Score:",
        f"{risk['score']}/100"
    )

    print(
        "Risk Level:",
        risk["level"]
    )

    print(
        "\nAssessment:",
        risk["assessment"]
    )


    # --------------------------------------------------------
    # SECURITY RECOMMENDATIONS
    # --------------------------------------------------------

    print("\n" + "=" * 60)
    print("SECURITY RECOMMENDATIONS")
    print("=" * 60)

    recommendations = generate_recommendations(open_ports)

    for recommendation in recommendations:

        print("\n- " + recommendation)


    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print("\n" + "=" * 60)
    print("PORT & SERVICE EXPOSURE SUMMARY")
    print("=" * 60)

    print("\nOriginal Target:", target)
    print("Resolved IP:", ip_address)
    print("Target Type:", target_type)

    print(
        "\nTotal Ports Checked:",
        len(COMMON_PORTS)
    )

    print(
        "Open Ports Found:",
        len(open_ports)
    )

    if open_ports:

        print("\nExposed Services:")

        for port in open_ports:

            print(
                f"  - {port}/TCP ({COMMON_PORTS[port]})"
            )

    print(
        "\nFinal Exposure Score:",
        f"{risk['score']}/100"
    )

    print(
        "Final Risk Level:",
        risk["level"]
    )

    print("\n" + "=" * 60)
    print("PORT & SERVICE EXPOSURE ANALYSIS COMPLETED")
    print("=" * 60)


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
