#!/usr/bin/env python3

import socket
import ipaddress
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

TIMEOUT = 3

SERVICES = {
    21: {
        "name": "FTP",
        "exposure_points": 20,
        "description": "File Transfer Protocol"
    },
    22: {
        "name": "SSH",
        "exposure_points": 10,
        "description": "Secure Shell"
    },
    25: {
        "name": "SMTP",
        "exposure_points": 15,
        "description": "Simple Mail Transfer Protocol"
    },
    80: {
        "name": "HTTP",
        "exposure_points": 15,
        "description": "Hypertext Transfer Protocol"
    },
    110: {
        "name": "POP3",
        "exposure_points": 15,
        "description": "Post Office Protocol"
    },
    143: {
        "name": "IMAP",
        "exposure_points": 15,
        "description": "Internet Message Access Protocol"
    },
    443: {
        "name": "HTTPS",
        "exposure_points": 5,
        "description": "HTTP Secure"
    },
    3306: {
        "name": "MySQL",
        "exposure_points": 25,
        "description": "Database Service"
    },
    8080: {
        "name": "HTTP Alternative",
        "exposure_points": 15,
        "description": "Alternative HTTP Service"
    }
}


# ============================================================
# DISPLAY FUNCTIONS
# ============================================================

def print_separator():
    print("=" * 60)


def print_section(title):
    print_separator()
    print(title)
    print_separator()


# ============================================================
# TARGET RESOLUTION
# ============================================================

def resolve_target(target):

    try:
        ipaddress.ip_address(target)

        return {
            "target_type": "IP Address",
            "ip": target
        }

    except ValueError:

        try:
            resolved_ip = socket.gethostbyname(target)

            return {
                "target_type": "Domain",
                "ip": resolved_ip
            }

        except socket.gaierror:

            return None


# ============================================================
# IP CLASSIFICATION
# ============================================================

def classify_ip(ip):

    try:

        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private:
            return "PRIVATE"

        if ip_obj.is_loopback:
            return "LOOPBACK"

        if ip_obj.is_reserved:
            return "RESERVED"

        return "PUBLIC"

    except ValueError:

        return "UNKNOWN"


# ============================================================
# BANNER COLLECTION
# ============================================================

def grab_banner(ip, port, service_name):

    try:

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

            sock.settimeout(TIMEOUT)

            result = sock.connect_ex((ip, port))

            if result != 0:
                return {
                    "open": False,
                    "banner": None
                }

            banner = ""

            # HTTP REQUEST
            if port in [80, 8080]:

                request = (
                    "HEAD / HTTP/1.1\r\n"
                    "Host: target\r\n"
                    "Connection: close\r\n\r\n"
                )

                sock.sendall(request.encode())

            # WAIT FOR RESPONSE
            try:

                response = sock.recv(4096)

                banner = response.decode(
                    errors="ignore"
                ).strip()

            except socket.timeout:

                banner = ""

            return {
                "open": True,
                "banner": banner
            }

    except socket.error:

        return {
            "open": False,
            "banner": None
        }


# ============================================================
# TECHNOLOGY DETECTION
# ============================================================

def detect_technologies(banner):

    technologies = []

    if not banner:
        return technologies

    banner_lower = banner.lower()

    technology_keywords = {
        "nginx": "nginx",
        "apache": "Apache",
        "openssh": "OpenSSH",
        "ubuntu": "Ubuntu",
        "debian": "Debian",
        "microsoft": "Microsoft",
        "iis": "Microsoft IIS",
        "mysql": "MySQL",
        "postgresql": "PostgreSQL",
        "php": "PHP",
        "python": "Python"
    }

    for keyword, name in technology_keywords.items():

        if keyword in banner_lower and name not in technologies:
            technologies.append(name)

    return technologies


# ============================================================
# INFORMATION DISCLOSURE ANALYSIS
# ============================================================

def analyze_information_disclosure(banner, port):

    findings = []
    points = 0

    if not banner:
        return findings, points

    banner_lower = banner.lower()

    # SOFTWARE VERSION DISCLOSURE
    if any(
        keyword in banner_lower
        for keyword in [
            "openssh_",
            "nginx/",
            "apache/",
            "server:"
        ]
    ):

        findings.append(
            "Service banner appears to expose software or version information."
        )

        points += 20

    # PLATFORM INFORMATION
    if any(
        keyword in banner_lower
        for keyword in [
            "ubuntu",
            "debian",
            "centos",
            "windows"
        ]
    ):

        findings.append(
            "Banner appears to expose operating system or platform information."
        )

        points += 15

    # HTTP SERVER HEADER
    if port in [80, 8080] and "server:" in banner_lower:

        findings.append(
            "HTTP response exposes a Server header."
        )

        points += 10

    # LIMIT SCORE
    points = min(points, 100)

    return findings, points


# ============================================================
# SERVICE EXPOSURE ANALYSIS
# ============================================================

def analyze_service_exposure(port, service_name):

    observations = []
    points = SERVICES[port]["exposure_points"]

    if port == 21:

        observations.append(
            "FTP is exposed. Traditional FTP may transmit credentials and data without encryption."
        )

    elif port == 22:

        observations.append(
            "SSH remote administration service is exposed."
        )

    elif port == 23:

        observations.append(
            "Telnet may transmit credentials without encryption."
        )

    elif port == 25:

        observations.append(
            "SMTP service is publicly accessible."
        )

    elif port == 80:

        observations.append(
            "HTTP service is exposed and traffic may not be encrypted."
        )

    elif port == 110:

        observations.append(
            "POP3 service is exposed. Review whether encrypted alternatives are used."
        )

    elif port == 143:

        observations.append(
            "IMAP service is exposed. Review whether TLS encryption is enforced."
        )

    elif port == 3306:

        observations.append(
            "Database service is externally reachable."
        )

    elif port == 8080:

        observations.append(
            "Alternative HTTP service is exposed."
        )

    elif port == 443:

        observations.append(
            "HTTPS service is publicly accessible."
        )

    return observations, points


# ============================================================
# SCORE CALCULATION
# ============================================================

def calculate_exposure_score(open_services):

    total = 0

    for service in open_services:

        total += service["exposure_points"]

    return min(total, 100)


def calculate_disclosure_score(open_services):

    total = 0

    for service in open_services:

        total += service["disclosure_points"]

    return min(total, 100)


def determine_risk_level(exposure_score, disclosure_score):

    combined_score = (
        exposure_score * 0.65
        +
        disclosure_score * 0.35
    )

    combined_score = round(combined_score)

    if combined_score >= 80:
        return combined_score, "HIGH"

    elif combined_score >= 50:
        return combined_score, "MODERATE"

    elif combined_score >= 25:
        return combined_score, "LOW"

    else:
        return combined_score, "MINIMAL"


# ============================================================
# RECOMMENDATIONS
# ============================================================

def generate_recommendations(open_services):

    recommendations = []

    ports = [
        service["port"]
        for service in open_services
    ]

    if 21 in ports:

        recommendations.append(
            "FTP: Consider replacing traditional FTP with SFTP or FTPS."
        )

    if 22 in ports:

        recommendations.append(
            "SSH: Use key-based authentication, restrict administrative access, and keep the service updated."
        )

    if 80 in ports:

        recommendations.append(
            "HTTP: Review whether users should be redirected to HTTPS."
        )

    if 80 in ports and 443 not in ports:

        recommendations.append(
            "Web Security: HTTPS was not detected among the selected ports. Review whether TLS should be enabled."
        )

    if 3306 in ports:

        recommendations.append(
            "Database Security: Avoid exposing database services directly to the public Internet unless strictly required."
        )

    disclosure_detected = any(
        service["disclosure_points"] > 0
        for service in open_services
    )

    if disclosure_detected:

        recommendations.append(
            "Information Disclosure: Review whether unnecessary software versions or platform details are exposed through banners."
        )

    recommendations.append(
        "Important: Banner information alone does not confirm the presence of vulnerabilities."
    )

    return recommendations


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    print_separator()
    print("SERVICE BANNER SECURITY ANALYZER")
    print_separator()

    print()
    print("Educational cybersecurity laboratory tool.")
    print("Use only against systems you own or are authorized to test.")
    print()

    target = input(
        "Enter an IP address or domain "
        "(example: authorized-test-host): "
    ).strip()

    if not target:

        print("\n[-] No target provided.")
        return

    print(f"\n[+] Target: {target}")
    print(
        f"[+] Analysis started: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    # --------------------------------------------------------
    # TARGET RESOLUTION
    # --------------------------------------------------------

    target_info = resolve_target(target)

    if not target_info:

        print("\n[-] Unable to resolve target.")
        return

    resolved_ip = target_info["ip"]

    print_section("TARGET RESOLUTION")

    print()
    print(f"Target Type: {target_info['target_type']}")
    print(f"Resolved IP: {resolved_ip}")

    ip_type = classify_ip(resolved_ip)

    print()
    print(f"IP Classification: {ip_type}")

    # --------------------------------------------------------
    # BANNER ANALYSIS
    # --------------------------------------------------------

    print_section("SERVICE BANNER ANALYSIS")

    print()
    print("Checking selected common TCP services...")

    open_services = []

    for port, service_data in SERVICES.items():

        service_name = service_data["name"]

        print(
            f"\n[*] Checking {port}/TCP ({service_name})..."
        )

        result = grab_banner(
            resolved_ip,
            port,
            service_name
        )

        if not result["open"]:

            print(
                f"[-] Port {port}/TCP CLOSED or FILTERED"
            )

            continue

        print(f"[+] Port {port}/TCP OPEN")

        banner = result["banner"]

        print()
        print(f"Service: {service_name}")

        print()
        print("Banner / Response:")
        print("-" * 60)

        if banner:

            print(banner)

        else:

            print("No banner received.")

        print("-" * 60)

        # ----------------------------------------------------
        # TECHNOLOGY DETECTION
        # ----------------------------------------------------

        technologies = detect_technologies(banner)

        if technologies:

            print()
            print("Detected Technologies:")

            for technology in technologies:

                print(f"  - {technology}")

        # ----------------------------------------------------
        # SERVICE EXPOSURE
        # ----------------------------------------------------

        observations, exposure_points = (
            analyze_service_exposure(
                port,
                service_name
            )
        )

        print()
        print("Service Exposure Observations:")

        for observation in observations:

            print(f"  - {observation}")

        print()
        print(f"Service Exposure Points: {exposure_points}")

        # ----------------------------------------------------
        # INFORMATION DISCLOSURE
        # ----------------------------------------------------

        disclosure_findings, disclosure_points = (
            analyze_information_disclosure(
                banner,
                port
            )
        )

        print()
        print("Information Disclosure Analysis:")

        if disclosure_findings:

            for finding in disclosure_findings:

                print(f"  - {finding}")

        else:

            print(
                "  - No significant banner information disclosure detected."
            )

        print()
        print(
            f"Information Disclosure Points: "
            f"{disclosure_points}"
        )

        # ----------------------------------------------------
        # STORE SERVICE
        # ----------------------------------------------------

        open_services.append({

            "port": port,
            "service": service_name,
            "banner": banner,
            "technologies": technologies,
            "exposure_points": exposure_points,
            "disclosure_points": disclosure_points

        })

    # ========================================================
    # SERVICE EXPOSURE SCORE
    # ========================================================

    exposure_score = calculate_exposure_score(
        open_services
    )

    print_section("SERVICE EXPOSURE ASSESSMENT")

    print()

    print(f"Exposure Score: {exposure_score}/100")

    if exposure_score >= 70:

        exposure_level = "HIGH"

    elif exposure_score >= 40:

        exposure_level = "MODERATE"

    else:

        exposure_level = "LOW"

    print(f"Exposure Level: {exposure_level}")

    print()
    print(
        "This score represents the level of service exposure, "
        "not confirmed vulnerabilities."
    )

    # ========================================================
    # INFORMATION DISCLOSURE SCORE
    # ========================================================

    disclosure_score = calculate_disclosure_score(
        open_services
    )

    print_section("INFORMATION DISCLOSURE ASSESSMENT")

    print()

    print(
        f"Information Disclosure Score: "
        f"{disclosure_score}/100"
    )

    if disclosure_score >= 60:

        disclosure_level = "HIGH"

    elif disclosure_score >= 30:

        disclosure_level = "MODERATE"

    else:

        disclosure_level = "LOW"

    print(
        f"Information Disclosure Level: "
        f"{disclosure_level}"
    )

    print()
    print(
        "This score reflects potentially unnecessary "
        "technology, version, or platform information exposed "
        "through service responses."
    )

    # ========================================================
    # OVERALL RISK
    # ========================================================

    overall_score, risk_level = determine_risk_level(
        exposure_score,
        disclosure_score
    )

    print_section("OVERALL SECURITY ASSESSMENT")

    print()

    print(f"Overall Score: {overall_score}/100")
    print(f"Overall Risk Level: {risk_level}")

    if risk_level == "HIGH":

        assessment = (
            "Significant exposure or information disclosure "
            "was detected and should be reviewed."
        )

    elif risk_level == "MODERATE":

        assessment = (
            "Moderate exposure was detected. Review exposed "
            "services and unnecessary information disclosure."
        )

    elif risk_level == "LOW":

        assessment = (
            "Limited exposure was detected from the selected "
            "services."
        )

    else:

        assessment = (
            "Minimal exposure was detected from the selected "
            "services."
        )

    print()
    print(f"Assessment: {assessment}")

    # ========================================================
    # IMPORTANT LIMITATION
    # ========================================================

    print_section("VULNERABILITY STATUS")

    print()

    print("Confirmed Vulnerabilities: NOT ASSESSED")

    print()
    print(
        "IMPORTANT: Software versions and banners alone do not "
        "confirm that a vulnerability exists."
    )

    print(
        "A proper vulnerability assessment requires additional "
        "validation, patch-level analysis, configuration review, "
        "and authorized testing."
    )

    # ========================================================
    # RECOMMENDATIONS
    # ========================================================

    print_section("SECURITY RECOMMENDATIONS")

    recommendations = generate_recommendations(
        open_services
    )

    print()

    for recommendation in recommendations:

        print(f"- {recommendation}")
        print()

    # ========================================================
    # SUMMARY
    # ========================================================

    print_section("BANNER SECURITY ANALYSIS SUMMARY")

    print()

    print(f"Original Target: {target}")
    print(f"Resolved IP: {resolved_ip}")
    print(
        f"Target Type: "
        f"{target_info['target_type']}"
    )
    print(
        f"IP Classification: {ip_type}"
    )

    print()
    print(
        f"Services Checked: {len(SERVICES)}"
    )

    print(
        f"Open Services Found: {len(open_services)}"
    )

    if open_services:

        print()
        print("Exposed Services:")

        for service in open_services:

            print(
                f"  - {service['port']}/TCP "
                f"({service['service']})"
            )

    print()
    print(
        f"Service Exposure Score: "
        f"{exposure_score}/100"
    )

    print(
        f"Information Disclosure Score: "
        f"{disclosure_score}/100"
    )

    print(
        f"Overall Security Score: "
        f"{overall_score}/100"
    )

    print(
        f"Overall Risk Level: {risk_level}"
    )

    print_separator()
    print("BANNER SECURITY ANALYSIS COMPLETED")
    print_separator()


# ============================================================
# EXECUTION
# ============================================================

if __name__ == "__main__":
    main()
