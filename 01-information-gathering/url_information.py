import socket
import requests
from urllib.parse import urlparse


def normalize_url(url):
    """Adds HTTPS if the URL does not include a scheme."""

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url


def get_domain(url):
    """Extracts the domain from a URL."""

    parsed_url = urlparse(url)

    return parsed_url.netloc


def get_dns_information(domain):
    """Obtains IPv4 addresses associated with a domain."""

    print("\n" + "=" * 60)
    print("DNS INFORMATION")
    print("=" * 60)

    print(f"\n[+] Domain: {domain}")

    try:
        results = socket.getaddrinfo(
            domain,
            None,
            socket.AF_INET
        )

        ip_addresses = sorted(
            set(result[4][0] for result in results)
        )

        print("\nIP Addresses:")

        for ip in ip_addresses:
            print(f"  - {ip}")

    except socket.gaierror as error:
        print(f"\n[-] DNS lookup error: {error}")


def get_http_information(url):
    """Obtains HTTP response information."""

    print("\n" + "=" * 60)
    print("HTTP INFORMATION")
    print("=" * 60)

    headers = {
        "User-Agent": (
            "Mozilla/5.0 "
            "(X11; Linux x86_64) "
            "AppleWebKit/537.36 "
            "Chrome/120 Safari/537.36"
        )
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=10,
            allow_redirects=True
        )

        print(f"\n[+] Status Code: {response.status_code}")
        print(f"[+] Final URL: {response.url}")

        server = response.headers.get("Server")

        if server:
            print(f"[+] Server: {server}")
        else:
            print("[+] Server: Not disclosed")

        print("\nRedirect Information:")

        if response.history:

            for redirect in response.history:
                print(
                    f"  - {redirect.status_code}: "
                    f"{redirect.url}"
                )

            print(f"  - Final: {response.url}")

        else:
            print("  - No redirects detected.")

    except requests.exceptions.SSLError as error:
        print(f"\n[-] SSL connection error: {error}")

    except requests.exceptions.ConnectionError as error:
        print(f"\n[-] HTTP connection error: {error}")

    except requests.exceptions.Timeout:
        print("\n[-] Connection timed out.")

    except requests.exceptions.RequestException as error:
        print(f"\n[-] HTTP request error: {error}")


def main():

    print("=" * 60)
    print("URL INFORMATION ANALYZER")
    print("=" * 60)

    user_url = input(
        "\nEnter a website URL (example: example.com): "
    ).strip()

    if not user_url:
        print("\n[-] No URL provided.")
        return

    target_url = normalize_url(user_url)

    domain = get_domain(target_url)

    print(f"\n[+] Target URL: {target_url}")
    print(f"[+] Extracted Domain: {domain}")

    get_dns_information(domain)

    get_http_information(target_url)

    print("\n" + "=" * 60)
    print("URL ANALYSIS COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()
