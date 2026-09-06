import socket
import ssl
import requests
from urllib.parse import urlparse
from datetime import datetime, timezone


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "points": 5,
        "purpose": "Enforces HTTPS connections",
        "recommendation": "Implement Strict-Transport-Security (HSTS) to enforce HTTPS connections."
    },
    "Content-Security-Policy": {
        "points": 5,
        "purpose": "Helps mitigate XSS and content injection",
        "recommendation": "Implement a Content-Security-Policy (CSP) to reduce XSS and content injection risks."
    },
    "X-Frame-Options": {
        "points": 4,
        "purpose": "Helps protect against clickjacking",
        "recommendation": "Implement X-Frame-Options or an equivalent frame-ancestors CSP directive."
    },
    "X-Content-Type-Options": {
        "points": 4,
        "purpose": "Prevents MIME type sniffing",
        "recommendation": "Set X-Content-Type-Options to nosniff."
    },
    "Referrer-Policy": {
        "points": 4,
        "purpose": "Controls referrer information",
        "recommendation": "Implement a Referrer-Policy appropriate for the application."
    },
    "Permissions-Policy": {
        "points": 3,
        "purpose": "Controls browser features and permissions",
        "recommendation": "Implement a Permissions-Policy to restrict unnecessary browser features."
    }
}


def normalize_url(url):
    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def get_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc.split(":")[0]


def resolve_domain(domain):
    print("\n" + "=" * 60)
    print("DNS INFORMATION")
    print("=" * 60)

    try:
        addresses = socket.getaddrinfo(domain, None)
        ip_addresses = sorted(set(address[4][0] for address in addresses))

        if ip_addresses:
            print("\nIP Addresses:")

            for ip in ip_addresses:
                print(f"  - {ip}")

            return True, ip_addresses

    except socket.gaierror:
        print("\n[-] Unable to resolve domain.")

    return False, []


def analyze_http(url):
    print("\n" + "=" * 60)
    print("HTTP/HTTPS INFORMATION")
    print("=" * 60)

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 "
            "Chrome/120.0 Safari/537.36"
        )
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10,
            allow_redirects=True
        )

        print(f"\nStatus Code: {response.status_code}")
        print(f"Final URL: {response.url}")

        server = response.headers.get("Server", "Not disclosed")
        print(f"Server: {server}")

        print("\nRedirects:")

        if response.history:
            for redirect in response.history:
                print(f"  - {redirect.status_code}: {redirect.url}")

            print(f"  - Final: {response.url}")
        else:
            print("  - No redirects detected.")

        return True, response

    except requests.exceptions.RequestException as error:
        print(f"\n[-] HTTP/HTTPS connection error: {error}")
        return False, None


def analyze_security_headers(response):
    print("\n" + "=" * 60)
    print("SECURITY HEADERS ANALYSIS")
    print("=" * 60)

    score = 0
    recommendations = []

    for header, information in SECURITY_HEADERS.items():
        value = response.headers.get(header)

        if value:
            print(f"\n[+] {header}: PRESENT")
            print(f"    Value: {value}")
            print(f"    Points: +{information['points']}")
            print(f"    Purpose: {information['purpose']}")

            score += information["points"]

        else:
            print(f"\n[-] {header}: NOT DETECTED")
            print(f"    Points: +0/{information['points']}")
            print(f"    Purpose: {information['purpose']}")

            recommendations.append(
                f"{header}: {information['recommendation']}"
            )

    return score, recommendations


def get_certificate_information(domain):
    print("\n" + "=" * 60)
    print("SSL/TLS INFORMATION")
    print("=" * 60)

    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_socket:

                certificate = secure_socket.getpeercert()
                tls_version = secure_socket.version()
                cipher = secure_socket.cipher()

                cipher_name = cipher[0]
                cipher_strength = cipher[2]

                print(f"\nTLS Version: {tls_version}")
                print(f"Cipher: {cipher_name}")
                print(f"Cipher Strength: {cipher_strength} bits")

                expiration_text = certificate.get("notAfter")

                if expiration_text:
                    expiration_date = datetime.strptime(
                        expiration_text,
                        "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)

                    current_date = datetime.now(timezone.utc)
                    days_remaining = (expiration_date - current_date).days

                    print(f"\nCertificate Expiration: {expiration_text}")
                    print(f"Days Remaining: {days_remaining}")

                else:
                    days_remaining = -1

                return True, tls_version, cipher_strength, days_remaining

    except Exception as error:
        print(f"\n[-] SSL/TLS connection error: {error}")
        return False, None, 0, -1


def calculate_ssl_score(success, tls_version, cipher_strength, days_remaining):
    if not success:
        return 0

    score = 0

    if tls_version in ("TLSv1.2", "TLSv1.3"):
        score += 20

    if cipher_strength >= 128:
        score += 15

    if days_remaining > 0:
        score += 15

    return score


def get_risk_level(score):
    if score >= 90:
        return "LOW"
    elif score >= 70:
        return "MEDIUM"
    elif score >= 40:
        return "HIGH"
    else:
        return "CRITICAL"


def main():
    print("=" * 60)
    print("WEB SECURITY ANALYZER")
    print("=" * 60)

    user_input = input(
        "\nEnter a website URL (example: example.com): "
    )

    url = normalize_url(user_input)
    domain = get_domain(url)

    print(f"\n[+] Target URL: {url}")
    print(f"[+] Target Domain: {domain}")

    # DNS ANALYSIS
    dns_success, ip_addresses = resolve_domain(domain)
    dns_score = 10 if dns_success else 0

    # HTTP ANALYSIS
    http_success, response = analyze_http(url)
    http_score = 15 if http_success else 0

    # SECURITY HEADERS ANALYSIS
    headers_score = 0
    recommendations = []

    if response:
        headers_score, recommendations = analyze_security_headers(response)

    # SSL/TLS ANALYSIS
    (
        ssl_success,
        tls_version,
        cipher_strength,
        days_remaining
    ) = get_certificate_information(domain)

    ssl_score = calculate_ssl_score(
        ssl_success,
        tls_version,
        cipher_strength,
        days_remaining
    )

    # FINAL SCORE
    total_score = (
        dns_score
        + http_score
        + headers_score
        + ssl_score
    )

    print("\n" + "=" * 60)
    print("WEB SECURITY SCORE")
    print("=" * 60)

    print(f"\nDNS Resolution: {dns_score}/10")
    print(f"HTTP/HTTPS Connectivity: {http_score}/15")
    print(f"Security Headers: {headers_score}/25")
    print(f"SSL/TLS Security: {ssl_score}/50")

    print("\n" + "-" * 60)

    print(f"\nOVERALL SECURITY SCORE: {total_score}/100")

    risk_level = get_risk_level(total_score)
    print(f"RISK LEVEL: {risk_level}")

    # RECOMMENDATIONS
    if recommendations:
        print("\n" + "=" * 60)
        print("SECURITY RECOMMENDATIONS")
        print("=" * 60)

        for recommendation in recommendations:
            print(f"\n- {recommendation}")

    print("\n" + "=" * 60)
    print("WEB SECURITY ANALYSIS COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()
