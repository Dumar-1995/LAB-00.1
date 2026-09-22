#!/usr/bin/env python3

"""
Web Page Structure Analyzer v1.0

Authorized and non-invasive web page structure analyzer
for the Cybersecurity Python Lab.

Features:
- HTTP/HTTPS requests
- HTML title extraction
- Heading extraction
- Form detection
- Input detection
- Script detection
- Image detection
- Stylesheet detection
- Internal/external link classification
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


TOOL_NAME = "Cybersecurity Python Lab - Web Page Structure Analyzer"
VERSION = "1.0"

USER_AGENT = (
    "Cybersecurity-Python-Lab-WebStructureAnalyzer/1.0 "
    "(authorized-security-assessment)"
)

DEFAULT_TIMEOUT = 10
MAX_RESPONSE_SIZE = 2 * 1024 * 1024


def validate_url(url):
    """Validate an HTTP or HTTPS URL."""

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must use HTTP or HTTPS.")

    if not parsed.netloc:
        raise ValueError("URL must contain a valid hostname.")

    return url


def fetch_url(url, timeout=DEFAULT_TIMEOUT):
    """Retrieve the target page with controlled limits."""

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
    """Extract the page title."""

    match = re.search(
        r"<title\b[^>]*>(.*?)</title\s*>",
        html,
        re.IGNORECASE | re.DOTALL,
    )

    if not match:
        return None

    title = re.sub(r"\s+", " ", match.group(1))

    return unescape(title).strip()


def extract_headings(html):
    """Extract H1-H6 headings."""

    headings = []

    pattern = re.compile(
        r"<(h[1-6])\b[^>]*>(.*?)</\1\s*>",
        re.IGNORECASE | re.DOTALL,
    )

    for match in pattern.finditer(html):
        level = match.group(1).lower()
        text = re.sub(r"<[^>]+>", " ", match.group(2))
        text = re.sub(r"\s+", " ", text)
        text = unescape(text).strip()

        if text:
            headings.append(
                {
                    "level": level,
                    "text": text,
                }
            )

    return headings


def extract_forms(html):
    """Extract basic HTML form information."""

    forms = []

    pattern = re.compile(
        r"<form\b([^>]*)>(.*?)</form\s*>",
        re.IGNORECASE | re.DOTALL,
    )

    for match in pattern.finditer(html):
        attributes = match.group(1)
        content = match.group(2)

        action_match = re.search(
            r"\baction\s*=\s*['\"]([^'\"]*)['\"]",
            attributes,
            re.IGNORECASE,
        )

        method_match = re.search(
            r"\bmethod\s*=\s*['\"]([^'\"]*)['\"]",
            attributes,
            re.IGNORECASE,
        )

        inputs = extract_inputs(content)

        forms.append(
            {
                "action": (
                    unescape(action_match.group(1))
                    if action_match
                    else ""
                ),
                "method": (
                    method_match.group(1).upper()
                    if method_match
                    else "GET"
                ),
                "input_count": len(inputs),
            }
        )

    return forms


def extract_inputs(html):
    """Extract basic input information."""

    inputs = []

    pattern = re.compile(
        r"<input\b([^>]*)>",
        re.IGNORECASE,
    )

    for match in pattern.finditer(html):
        attributes = match.group(1)

        type_match = re.search(
            r"\btype\s*=\s*['\"]([^'\"]*)['\"]",
            attributes,
            re.IGNORECASE,
        )

        name_match = re.search(
            r"\bname\s*=\s*['\"]([^'\"]*)['\"]",
            attributes,
            re.IGNORECASE,
        )

        inputs.append(
            {
                "type": (
                    type_match.group(1).lower()
                    if type_match
                    else "text"
                ),
                "name": (
                    unescape(name_match.group(1))
                    if name_match
                    else None
                ),
            }
        )

    return inputs


def extract_scripts(html):
    """Extract script sources."""

    scripts = []

    pattern = re.compile(
        r"<script\b([^>]*)>",
        re.IGNORECASE,
    )

    for match in pattern.finditer(html):
        attributes = match.group(1)

        src_match = re.search(
            r"\bsrc\s*=\s*['\"]([^'\"]+)['\"]",
            attributes,
            re.IGNORECASE,
        )

        scripts.append(
            {
                "src": (
                    unescape(src_match.group(1))
                    if src_match
                    else None
                ),
                "external": bool(src_match),
            }
        )

    return scripts


def extract_images(html):
    """Extract image sources and alternative text."""

    images = []

    pattern = re.compile(
        r"<img\b([^>]*)>",
        re.IGNORECASE,
    )

    for match in pattern.finditer(html):
        attributes = match.group(1)

        src_match = re.search(
            r"\bsrc\s*=\s*['\"]([^'\"]+)['\"]",
            attributes,
            re.IGNORECASE,
        )

        alt_match = re.search(
            r"\balt\s*=\s*['\"]([^'\"]*)['\"]",
            attributes,
            re.IGNORECASE,
        )

        images.append(
            {
                "src": (
                    unescape(src_match.group(1))
                    if src_match
                    else None
                ),
                "alt": (
                    unescape(alt_match.group(1))
                    if alt_match
                    else None
                ),
            }
        )

    return images


def extract_stylesheets(html):
    """Extract linked stylesheets."""

    stylesheets = []

    pattern = re.compile(
        r"<link\b([^>]*)>",
        re.IGNORECASE,
    )

    for match in pattern.finditer(html):
        attributes = match.group(1)

        rel_match = re.search(
            r"\brel\s*=\s*['\"]([^'\"]*)['\"]",
            attributes,
            re.IGNORECASE,
        )

        href_match = re.search(
            r"\bhref\s*=\s*['\"]([^'\"]+)['\"]",
            attributes,
            re.IGNORECASE,
        )

        if not rel_match or not href_match:
            continue

        rel_values = rel_match.group(1).lower().split()

        if "stylesheet" not in rel_values:
            continue

        stylesheets.append(
            unescape(href_match.group(1))
        )

    return stylesheets


def classify_links(html, base_url):
    """Classify links as internal or external."""

    base_domain = urlparse(base_url).netloc.lower()

    internal_links = []
    external_links = []

    pattern = re.compile(
        r'<a\b[^>]*href\s*=\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    )

    seen_internal = set()
    seen_external = set()

    for match in pattern.finditer(html):
        href = unescape(match.group(1)).strip()

        if not href:
            continue

        absolute_url = urljoin(base_url, href)
        parsed = urlparse(absolute_url)

        if parsed.scheme not in ("http", "https"):
            continue

        domain = parsed.netloc.lower()

        if domain == base_domain:
            if absolute_url not in seen_internal:
                seen_internal.add(absolute_url)
                internal_links.append(absolute_url)
        else:
            if absolute_url not in seen_external:
                seen_external.add(absolute_url)
                external_links.append(absolute_url)

    return internal_links, external_links


def analyze_page(url, timeout=DEFAULT_TIMEOUT):
    """Analyze the structure of the target web page."""

    validate_url(url)

    response = fetch_url(url, timeout)

    html = response.pop("html")

    headings = extract_headings(html)
    forms = extract_forms(html)
    inputs = extract_inputs(html)
    scripts = extract_scripts(html)
    images = extract_images(html)
    stylesheets = extract_stylesheets(html)

    internal_links, external_links = classify_links(
        html,
        response["final_url"],
    )

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
        "headings": headings,
        "forms": forms,
        "inputs": inputs,
        "scripts": scripts,
        "images": images,
        "stylesheets": stylesheets,
        "internal_links": internal_links,
        "external_links": external_links,
        "summary": {
            "heading_count": len(headings),
            "form_count": len(forms),
            "input_count": len(inputs),
            "script_count": len(scripts),
            "image_count": len(images),
            "stylesheet_count": len(stylesheets),
            "internal_link_count": len(internal_links),
            "external_link_count": len(external_links),
        },
    }

    if "error" in response:
        result["error"] = response["error"]

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

    print("\nStructure:")
    print(f"  Headings      : {result['summary']['heading_count']}")
    print(f"  Forms         : {result['summary']['form_count']}")
    print(f"  Inputs        : {result['summary']['input_count']}")
    print(f"  Scripts       : {result['summary']['script_count']}")
    print(f"  Images        : {result['summary']['image_count']}")
    print(
        "  Stylesheets   : "
        f"{result['summary']['stylesheet_count']}"
    )
    print(
        "  Internal links: "
        f"{result['summary']['internal_link_count']}"
    )
    print(
        "  External links: "
        f"{result['summary']['external_link_count']}"
    )

    if result["headings"]:
        print("\nHeadings:")

        for heading in result["headings"]:
            print(
                f"  {heading['level'].upper()}: "
                f"{heading['text']}"
            )

    if result["internal_links"]:
        print("\nInternal links:")

        for link in result["internal_links"]:
            print(f"  - {link}")

    if result["external_links"]:
        print("\nExternal links:")

        for link in result["external_links"]:
            print(f"  - {link}")

    if result.get("error"):
        print(f"\nError: {result['error']}")


def parse_arguments():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Analyze the structure of an authorized web page."
        )
    )

    parser.add_argument(
        "url",
        help="Target HTTP/HTTPS URL",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=(
            f"Request timeout in seconds "
            f"(default: {DEFAULT_TIMEOUT})"
        ),
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
        print(
            json.dumps(
                result,
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        print_report(result)

    return 0


if __name__ == "__main__":
    sys.exit(main())
