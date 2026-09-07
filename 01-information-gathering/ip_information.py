import socket
import ipaddress
import requests


LINE = "=" * 60


def print_section(title):
    print(LINE)
    print(title)
    print(LINE)


def get_target_type(target):
    """
    Determines whether the target is an IP address or a domain.
    """

    try:
        ipaddress.ip_address(target)
        return "IP Address"

    except ValueError:
        return "Domain"


def resolve_domain(target):
    """
    Resolves all available IPv4 and IPv6 addresses for a domain.
    """

    addresses = {
        "ipv4": [],
        "ipv6": []
    }

    try:
        results = socket.getaddrinfo(
            target,
            None,
            socket.AF_UNSPEC
        )

        for result in results:

            family = result[0]
            address = result[4][0]

            if family == socket.AF_INET:

                if address not in addresses["ipv4"]:
                    addresses["ipv4"].append(address)

            elif family == socket.AF_INET6:

                if address not in addresses["ipv6"]:
                    addresses["ipv6"].append(address)

        return addresses

    except socket.gaierror:
        return None


def classify_ip(ip):
    """
    Classifies an IP address.
    """

    ip_obj = ipaddress.ip_address(ip)

    if ip_obj.is_private:
        return "PRIVATE"

    if ip_obj.is_loopback:
        return "LOOPBACK"

    if ip_obj.is_multicast:
        return "MULTICAST"

    if ip_obj.is_reserved:
        return "RESERVED"

    if ip_obj.is_unspecified:
        return "UNSPECIFIED"

    if ip_obj.is_link_local:
        return "LINK-LOCAL"

    return "PUBLIC"


def get_reverse_dns(ip):
    """
    Performs a reverse DNS lookup.
    """

    try:

        hostname, aliases, addresses = socket.gethostbyaddr(ip)

        return {
            "hostname": hostname,
            "aliases": aliases,
            "addresses": addresses
        }

    except (socket.herror, socket.gaierror):
        return None


def get_public_ip_information(ip):
    """
    Queries public IP geolocation and ASN information.
    """

    try:

        url = f"https://ipwho.is/{ip}"

        response = requests.get(
            url,
            timeout=10
        )

        data = response.json()

        if not data.get("success", False):
            return None

        return data

    except (
        requests.RequestException,
        ValueError
    ):
        return None


def detect_infrastructure_provider(
    ip_info,
    reverse_dns
):
    """
    Attempts to identify common infrastructure providers.
    """

    text = ""

    if ip_info:

        connection = ip_info.get(
            "connection",
            {}
        )

        text += " "
        text += str(
            connection.get("isp", "")
        ).lower()

        text += " "
        text += str(
            connection.get("org", "")
        ).lower()

        text += " "
        text += str(
            connection.get("domain", "")
        ).lower()

    if reverse_dns:

        text += " "
        text += reverse_dns.get(
            "hostname",
            ""
        ).lower()

    providers = {

        "AWS / Amazon Web Services": [
            "amazon",
            "amazonaws.com",
            "aws"
        ],

        "Google Cloud / Google Infrastructure": [
            "google",
            "1e100.net",
            "googleusercontent"
        ],

        "Microsoft Azure": [
            "microsoft",
            "azure",
            "cloudapp.azure.com"
        ],

        "Cloudflare": [
            "cloudflare"
        ],

        "DigitalOcean": [
            "digitalocean"
        ],

        "Oracle Cloud": [
            "oracle",
            "oraclecloud"
        ],

        "Akamai": [
            "akamai"
        ],

        "Hetzner": [
            "hetzner"
        ],

        "OVH": [
            "ovh"
        ]
    }

    for provider, keywords in providers.items():

        for keyword in keywords:

            if keyword in text:

                return provider

    return "Not Identified"


def assess_reverse_dns(reverse_dns):
    """
    Evaluates reverse DNS availability.
    """

    if not reverse_dns:

        return (
            "NOT AVAILABLE",
            "No reverse DNS record was identified."
        )

    hostname = reverse_dns.get(
        "hostname",
        ""
    )

    return (
        "AVAILABLE",
        f"Reverse DNS identifies: {hostname}"
    )


def analyze_ip(ip):
    """
    Performs analysis for an individual IP address.
    """

    result = {
        "ip": ip,
        "classification": classify_ip(ip),
        "reverse_dns": None,
        "public_info": None,
        "provider": "Not Identified"
    }

    result["reverse_dns"] = get_reverse_dns(ip)

    if result["classification"] == "PUBLIC":

        result["public_info"] = (
            get_public_ip_information(ip)
        )

    result["provider"] = (
        detect_infrastructure_provider(
            result["public_info"],
            result["reverse_dns"]
        )
    )

    return result


def print_ip_analysis(result):
    """
    Prints detailed analysis for an IP address.
    """

    ip = result["ip"]

    print("\n" + "-" * 60)

    print(f"IP ADDRESS: {ip}")

    print("-" * 60)

    print(
        f"Classification: {result['classification']}"
    )

    reverse_dns = result["reverse_dns"]

    print("\nReverse DNS:")

    if reverse_dns:

        print(
            f"  Hostname: {reverse_dns['hostname']}"
        )

    else:

        print(
            "  No reverse DNS record found."
        )

    print("\nInfrastructure Provider:")

    print(
        f"  {result['provider']}"
    )

    public_info = result["public_info"]

    if public_info:

        connection = public_info.get(
            "connection",
            {}
        )

        print("\nNetwork Information:")

        print(
            f"  ISP: {connection.get('isp')}"
        )

        print(
            f"  Organization: {connection.get('org')}"
        )

        print(
            f"  ASN: {connection.get('asn')}"
        )

        print("\nApproximate Location:")

        print(
            f"  Country: {public_info.get('country')}"
        )

        print(
            f"  Region: {public_info.get('region')}"
        )

        print(
            f"  City: {public_info.get('city')}"
        )

    elif result["classification"] == "PUBLIC":

        print(
            "\nPublic information lookup: NOT AVAILABLE"
        )


def calculate_infrastructure_assessment(results):
    """
    Creates a high-level infrastructure assessment.
    """

    public_ips = 0
    private_ips = 0
    cloud_detected = []
    reverse_dns_available = 0

    for result in results:

        if result["classification"] == "PUBLIC":
            public_ips += 1

        elif result["classification"] == "PRIVATE":
            private_ips += 1

        if result["provider"] != "Not Identified":

            if result["provider"] not in cloud_detected:

                cloud_detected.append(
                    result["provider"]
                )

        if result["reverse_dns"]:

            reverse_dns_available += 1

    return {
        "public_ips": public_ips,
        "private_ips": private_ips,
        "providers": cloud_detected,
        "reverse_dns_available": reverse_dns_available
    }


def print_security_recommendations(
    assessment,
    results
):
    """
    Prints general security recommendations.
    """

    recommendations = []

    if assessment["public_ips"] > 0:

        recommendations.append(
            "Review externally exposed services and "
            "maintain continuous security monitoring."
        )

    if assessment["private_ips"] > 0:

        recommendations.append(
            "Private IP addresses were resolved. If this "
            "was unexpected, review internal DNS configuration "
            "and split-horizon DNS behavior."
        )

    if assessment["reverse_dns_available"] > 0:

        recommendations.append(
            "Review public reverse DNS naming conventions "
            "to avoid exposing unnecessary infrastructure details."
        )

    if assessment["providers"]:

        providers = ", ".join(
            assessment["providers"]
        )

        recommendations.append(
            f"Apply security best practices for the identified "
            f"infrastructure providers: {providers}."
        )

    if not recommendations:

        recommendations.append(
            "No specific infrastructure recommendations "
            "were generated."
        )

    for recommendation in recommendations:

        print(f"\n- {recommendation}")


def main():

    print_section(
        "IP & INFRASTRUCTURE RECON ANALYZER"
    )

    target = input(
        "\nEnter an IP address or domain "
        "(example: google.com): "
    ).strip()

    if not target:

        print("\n[-] No target provided.")
        return

    print(f"\n[+] Target: {target}")

    target_type = get_target_type(target)

    print_section("TARGET RESOLUTION")

    print(
        f"Target Type: {target_type}"
    )

    ip_addresses = []

    if target_type == "IP Address":

        ip_addresses.append(target)

    else:

        resolved = resolve_domain(target)

        if not resolved:

            print(
                "[-] Unable to resolve the domain."
            )

            return

        print("\nIPv4 Addresses:")

        if resolved["ipv4"]:

            for ip in resolved["ipv4"]:

                print(f"  - {ip}")

                ip_addresses.append(ip)

        else:

            print("  [-] No IPv4 addresses found.")

        print("\nIPv6 Addresses:")

        if resolved["ipv6"]:

            for ip in resolved["ipv6"]:

                print(f"  - {ip}")

                ip_addresses.append(ip)

        else:

            print("  [-] No IPv6 addresses found.")

    if not ip_addresses:

        print(
            "\n[-] No IP addresses available for analysis."
        )

        return

    print_section(
        "DETAILED IP ANALYSIS"
    )

    results = []

    for ip in ip_addresses:

        result = analyze_ip(ip)

        results.append(result)

        print_ip_analysis(result)

    print_section(
        "INFRASTRUCTURE ASSESSMENT"
    )

    assessment = (
        calculate_infrastructure_assessment(
            results
        )
    )

    print(
        f"Total IP Addresses Analyzed: "
        f"{len(results)}"
    )

    print(
        f"Public IP Addresses: "
        f"{assessment['public_ips']}"
    )

    print(
        f"Private IP Addresses: "
        f"{assessment['private_ips']}"
    )

    print(
        f"Reverse DNS Records Available: "
        f"{assessment['reverse_dns_available']}"
    )

    if assessment["providers"]:

        print(
            "\nInfrastructure Providers Detected:"
        )

        for provider in assessment["providers"]:

            print(f"  - {provider}")

    else:

        print(
            "\nInfrastructure Providers Detected: "
            "Not Identified"
        )

    print_section(
        "SECURITY RECOMMENDATIONS"
    )

    print_security_recommendations(
        assessment,
        results
    )

    print_section(
        "IP & INFRASTRUCTURE RECON SUMMARY"
    )

    print(f"Original Target: {target}")

    print(f"Target Type: {target_type}")

    print(
        f"Total Addresses Found: "
        f"{len(results)}"
    )

    print(
        f"Public Addresses: "
        f"{assessment['public_ips']}"
    )

    print(
        f"Private Addresses: "
        f"{assessment['private_ips']}"
    )

    print_section(
        "IP & INFRASTRUCTURE RECON COMPLETED"
    )


if __name__ == "__main__":
    main()
