#!/usr/bin/env python3

"""
Web Scraper v1.0

Authorized and non-invasive web scraping tool for cybersecurity labs.

Features:
- URL validation
- HTTP/HTTPS requests
- Identifiable User-Agent
- HTTP status code
- Final URL after redirects
- HTML title extraction
- Basic metadata extraction
- Link extraction
- Human-readable output
- JSON output
- Timeout and response-size limits
"""

import argparse
import json
import re
import sys
from html import unescape
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


TOOL_NAME = "Cybersecurity Python Lab - Web Scraper"
VERSION = "1.0"

USER_AGENT = (
    "Cybersecurity-Python-Lab-WebScraper/1.0 "
    "(authorized-security-assessment)"
)

DEFAULT_TIMEOUT = 10
MAX_RESPONSE_SIZE = 2 * 1024 * 1024


def validate_url(url):
    """Validate that the target uses HTTP or HTTPS."""

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must use HTTP or HTTPS.")

    if not parsed.netloc:
        raise ValueError("URL must contain a valid hostname.")

    return url


def fetch_url(url, timeout=DEFAULT_TIMEOUT):
    """Fetch a web page with a controlled timeout and size limit."""

    request = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
        },
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            content_type = response.headers.get("Content-Type", "")

            data = response.read(MAX_RESPONSE_SIZE + 1)

            truncated = len(data) > MAX_RESPONSE_SIZE

            if truncated:
                data = data[:MAX_RESPONSE_SIZE]

            charset_match = re.search(
                r"charset=([^\s;]+)",
                content_type,
                re.IGNORECASE,
            )

            charset = charset_match.group(1) if charset_match else "utf-8"

            try:
                html = data.decode(charset, errors="replace")
            except LookupError:
                html = data.decode("utf-8", errors="replace")

            return {
                "status_code": response.status,
                "final_url": response.geturl(),
                "content_type": content_type,
                "content_length": len(data),
                "truncated": truncated,
                "html": html,
            }

    except HTTPError as exc:
        return {
            "status_code": exc.code,
            "final_url": exc.geturl(),
            "content_type": exc.headers.get("Content-Type", ""),
            "content_length": 0,
            "truncated": False,
            "html": "",
            "error": f"HTTP error: {exc.code} {exc.reason}",
        }

    except URLError as exc:
        raise RuntimeError(f"Connection error: {exc.reason}") from exc

    except TimeoutError as exc:
        raise RuntimeError("Request timed out.") from exc


def extract_title(html):
    """Extract the HTML title."""

    match = re.search(
        r"<title\b[^>]*>(.*?)</title\s*>",
        html,
        re.IGNORECASE | re.DOTALL,
    )

    if not match:
        return None

    title = re.sub(r"\s+", " ", match.group(1))
    return unescape(title).strip()


def extract_meta_description(html):
    """Extract the HTML meta description."""

    pattern = re.compile(
        r"<meta\b[^>]*"
        r"(?:name\s*=\s*['\"]description['\"][^>]*"
        r"content\s*=\s*['\"](.*?)['\"]|"
        r"content\s*=\s*['\"](.*?)['\"][^>]*"
        r"name\s*=\s*['\"]description['\"])[^>]*>",
        re.IGNORECASE | re.DOTALL,
    )

    match = pattern.search(html)

    if not match:
        return None

    description = match.group(1) or match.group(2)

    description = re.sub(r"\s+", " ", description)

    return unescape(description).strip()


def extract_links(html, base_url):
    """Extract and normalize HTTP/HTTPS links."""

    matches = re.findall(
        r'<a\b[^>]*href\s*=\s*["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    )

    links = []
    seen = set()

    for href in matches:
        href = unescape(href).strip()

        if not href:
            continue

        absolute_url = urljoin(base_url, href)

        parsed = urlparse(absolute_url)

        if parsed.scheme not in ("http", "https"):
            continue

        if absolute_url not in seen:
            seen.add(absolute_url)
            links.append(absolute_url)

    return links


def analyze_page(url, timeout=DEFAULT_TIMEOUT):
    """Fetch and analyze the target page."""

    validate_url(url)

    response = fetch_url(url, timeout)

    html = response.pop("html")

    result = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "target": url,
        "status_code": response["status_code"],
        "final_url": response["final_url"],
        "content_type": response["content_type"],
        "content_length": response["content_length"],
        "truncated": response["truncated"],
        "title": extract_title(html),
        "meta_description": extract_meta_description(html),
        "links": extract_links(html, response["final_url"]),
    }

    if "error" in response:
        result["error"] = response["error"]

    result["link_count"] = len(result["links"])

    return result


def print_report(result):
    """Print a human-readable report."""

    print("=" * 60)
    print(TOOL_NAME)
    print("=" * 60)

    print(f"Target          : {result['target']}")
    print(f"HTTP status     : {result['status_code']}")
    print(f"Final URL       : {result['final_url']}")
    print(f"Content-Type    : {result['content_type']}")
    print(f"Content size    : {result['content_length']} bytes")
    print(f"Response limit  : {'YES' if result['truncated'] else 'NO'}")
    print(f"Title           : {result['title'] or 'Not found'}")
    print(
        "Description     : "
        f"{result['meta_description'] or 'Not found'}"
    )
    print(f"Links found     : {result['link_count']}")

    if result.get("error"):
        print(f"Error           : {result['error']}")

    if result["links"]:
        print("\nLinks:")
        for index, link in enumerate(result["links"], start=1):
            print(f"  {index}. {link}")


def parse_arguments():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="Basic authorized web scraper for cybersecurity labs."
    )

    parser.add_argument(
        "url",
        help="Target HTTP/HTTPS URL",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    return parser.parse_args()


def main():
    """Main program entry point."""

    args = parse_arguments()

    try:
        result = analyze_page(
            args.url,
            timeout=args.timeout,
        )

    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_report(result)

    return 0


if __name__ == "__main__":
    sys.exit(main())
