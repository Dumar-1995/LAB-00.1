import requests


def check_security_headers(headers):
    """
    Analyze common HTTP security headers.
    """

    security_headers = {
        "Strict-Transport-Security": "Enforces HTTPS connections",
        "Content-Security-Policy": "Helps mitigate XSS and content injection",
        "X-Frame-Options": "Helps protect against clickjacking",
        "X-Content-Type-Options": "Prevents MIME type sniffing",
        "Referrer-Policy": "Controls referrer information",
        "Permissions-Policy": "Controls browser features and permissions"
    }

    print("\n" + "=" * 60)
    print("SECURITY HEADERS ANALYSIS")
    print("=" * 60)

    for header, description in security_headers.items():

        if header.lower() in [h.lower() for h in headers]:

            # Find the original header name and value
            for actual_header, value in headers.items():
                if actual_header.lower() == header.lower():

                    print(f"\n[+] {header}: PRESENT")
                    print(f"    Value: {value}")
                    print(f"    Purpose: {description}")

        else:
            print(f"\n[-] {header}: NOT DETECTED")
            print(f"    Purpose: {description}")


print("=" * 60)
print("HTTP HEADERS ANALYZER")
print("=" * 60)


url = input(
    "\nEnter a website URL (example: https://example.com): "
).strip()


# Add HTTPS automatically if the user does not provide a protocol
if not url.startswith(("http://", "https://")):
    url = "https://" + url


print(f"\n[+] Analyzing: {url}")


try:

    response = requests.get(
        url,
        timeout=10
    )

    print("\n" + "=" * 60)
    print("HTTP RESPONSE INFORMATION")
    print("=" * 60)

    print(f"\nStatus Code: {response.status_code}")
    print(f"Final URL: {response.url}")

    print("\n" + "=" * 60)
    print("HTTP HEADERS")
    print("=" * 60)

    for header, value in response.headers.items():
        print(f"{header}: {value}")

    # Analyze security headers
    check_security_headers(response.headers)


except requests.exceptions.RequestException as error:

    print(f"\n[!] Error connecting to the website: {error}")
