import socket
import ssl
from datetime import datetime, timezone


def get_certificate_value(certificate, field_name):
    """
    Extract a value from the SSL certificate subject/issuer.
    """

    for item in certificate:
        for key, value in item:
            if key == field_name:
                return value

    return "Not available"


def analyze_tls_version(tls_version):
    """
    Analyze the TLS version.
    """

    if tls_version == "TLSv1.3":
        return "SECURE", 30

    if tls_version == "TLSv1.2":
        return "ACCEPTABLE", 20

    return "WEAK", 5


def analyze_cipher_strength(cipher_bits):
    """
    Analyze cipher strength.
    """

    if cipher_bits >= 256:
        return "STRONG", 25

    if cipher_bits >= 128:
        return "ACCEPTABLE", 15

    return "WEAK", 5


def analyze_certificate_validity(days_remaining):
    """
    Analyze certificate expiration.
    """

    if days_remaining < 0:
        return "EXPIRED", 0

    if days_remaining <= 30:
        return "EXPIRING SOON", 10

    return "VALID", 25


def calculate_security_score(
    tls_points,
    cipher_points,
    certificate_points,
    certificate_expired
):
    """
    Calculate the overall security score.
    """

    score = tls_points + cipher_points + certificate_points

    if certificate_expired:
        score = min(score, 40)

    return score


def get_risk_level(score):
    """
    Determine risk level based on the security score.
    """

    if score >= 80:
        return "LOW"

    if score >= 60:
        return "MEDIUM"

    if score >= 40:
        return "HIGH"

    return "CRITICAL"


def main():

    print("=" * 60)
    print("SSL/TLS CERTIFICATE INFORMATION TOOL")
    print("=" * 60)

    domain = input(
        "\nEnter a domain (example.com): "
    ).strip()

    if not domain:
        print("\n[-] No domain provided.")
        return

    if domain.startswith("https://"):
        domain = domain.replace("https://", "")

    if domain.startswith("http://"):
        domain = domain.replace("http://", "")

    domain = domain.split("/")[0]

    print(f"\n[+] Target domain: {domain}")
    print("[+] Connecting to the server...")

    context = ssl.create_default_context()

    try:

        with socket.create_connection(
            (domain, 443),
            timeout=10
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as secure_socket:

                print(
                    "\n[+] Secure SSL/TLS connection "
                    "established successfully."
                )

                certificate = secure_socket.getpeercert()

                tls_version = secure_socket.version()

                cipher = secure_socket.cipher()

                cipher_name = cipher[0]
                protocol = cipher[1]
                cipher_bits = cipher[2]

    except socket.gaierror:
        print(
            "\n[-] DNS resolution error. "
            "The domain could not be resolved."
        )
        return

    except socket.timeout:
        print(
            "\n[-] Connection timed out."
        )
        return

    except ssl.SSLError as error:
        print(
            f"\n[-] SSL/TLS error: {error}"
        )
        return

    except ConnectionRefusedError:
        print(
            "\n[-] Connection refused by the server."
        )
        return

    except Exception as error:
        print(
            f"\n[-] Unexpected error: {error}"
        )
        return

    subject = certificate.get("subject", ())
    issuer = certificate.get("issuer", ())

    common_name = get_certificate_value(
        subject,
        "commonName"
    )

    issuer_organization = get_certificate_value(
        issuer,
        "organizationName"
    )

    issuer_name = get_certificate_value(
        issuer,
        "commonName"
    )

    certificate_version = certificate.get(
        "version",
        "Not available"
    )

    serial_number = certificate.get(
        "serialNumber",
        "Not available"
    )

    valid_from = certificate.get(
        "notBefore",
        "Not available"
    )

    valid_until = certificate.get(
        "notAfter",
        "Not available"
    )

    print("\n" + "=" * 60)
    print("SSL/TLS CONNECTION INFORMATION")
    print("=" * 60)

    print(f"\nTLS Version: {tls_version}")
    print(f"Cipher: {cipher_name}")
    print(f"Protocol: {protocol}")
    print(f"Cipher Strength: {cipher_bits} bits")

    print("\n" + "=" * 60)
    print("CERTIFICATE INFORMATION")
    print("=" * 60)

    print(f"\nDomain: {domain}")
    print(f"Certificate Subject: {common_name}")

    print(
        f"\nIssuer Organization: "
        f"{issuer_organization}"
    )

    print(f"Issuer: {issuer_name}")

    print(
        f"\nCertificate Version: "
        f"{certificate_version}"
    )

    print(f"Serial Number: {serial_number}")

    print(f"\nValid From: {valid_from}")
    print(f"Valid Until: {valid_until}")

    certificate_expired = False
    days_remaining = 0

    try:

        expiration_date = datetime.strptime(
            valid_until,
            "%b %d %H:%M:%S %Y %Z"
        )

        expiration_date = expiration_date.replace(
            tzinfo=timezone.utc
        )

        current_date = datetime.now(
            timezone.utc
        )

        days_remaining = (
            expiration_date - current_date
        ).days

        print(f"\nDays Remaining: {days_remaining}")

        if days_remaining < 0:
            certificate_expired = True
            print(
                "[-] Certificate validity status: EXPIRED"
            )

        else:
            print(
                "[+] Certificate validity status: VALID"
            )

    except ValueError:

        print(
            "\n[-] Could not calculate certificate "
            "expiration date."
        )

    san_list = certificate.get(
        "subjectAltName",
        ()
    )

    print("\n" + "=" * 60)
    print("SUBJECT ALTERNATIVE NAMES (SAN)")
    print("=" * 60)

    if san_list:

        print(
            "\nDomains included in the certificate:"
        )

        dns_names = []

        for san_type, san_value in san_list:

            if san_type == "DNS":

                dns_names.append(san_value)

                print(f"  - {san_value}")

        print(
            f"\nTotal DNS names found: "
            f"{len(dns_names)}"
        )

    else:

        print(
            "\n[-] No Subject Alternative Names found."
        )

    tls_assessment, tls_points = analyze_tls_version(
        tls_version
    )

    cipher_assessment, cipher_points = (
        analyze_cipher_strength(
            cipher_bits
        )
    )

    certificate_assessment, certificate_points = (
        analyze_certificate_validity(
            days_remaining
        )
    )

    security_score = calculate_security_score(
        tls_points,
        cipher_points,
        certificate_points,
        certificate_expired
    )

    risk_level = get_risk_level(
        security_score
    )

    print("\n" + "=" * 60)
    print("SECURITY ASSESSMENT")
    print("=" * 60)

    print(
        f"\nTLS Version Assessment: "
        f"[+] {tls_assessment}"
    )

    print(
        f"Cipher Strength Assessment: "
        f"[+] {cipher_assessment}"
    )

    if certificate_expired:

        print(
            "Certificate Status: [-] EXPIRED"
        )

    else:

        print(
            "Certificate Status: [+] VALID"
        )

    print(
        f"Certificate Expiration Assessment: "
        f"[+] {certificate_assessment}"
    )

    print("\n" + "=" * 60)
    print("OVERALL SECURITY SCORE")
    print("=" * 60)

    print(
        f"\nSecurity Score: {security_score}/80"
    )

    percentage_score = (
        security_score / 80
    ) * 100

    print(
        f"Security Percentage: "
        f"{percentage_score:.1f}%"
    )

    print(
        f"Risk Level: {risk_level}"
    )

    print("\nScore Breakdown:")

    print(
        f"  TLS Version: "
        f"{tls_points}/30"
    )

    print(
        f"  Cipher Strength: "
        f"{cipher_points}/25"
    )

    print(
        f"  Certificate Validity: "
        f"{certificate_points}/25"
    )

    print("\n" + "=" * 60)
    print("SSL/TLS CERTIFICATE ANALYSIS COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()
