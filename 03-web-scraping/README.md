cat > README.md <<'EOF'
# 03 - Web Scraping

This module contains web scraping tools developed as part of the Cybersecurity Python Lab.

The tools are designed for educational purposes and authorized security assessments.

## Objectives

- Retrieve HTTP/HTTPS web pages.
- Identify HTTP status codes.
- Detect the final URL.
- Extract HTML titles.
- Extract basic metadata.
- Extract HTTP/HTTPS links.
- Count discovered links.
- Export results in human-readable and JSON formats.
- Implement basic request controls and error handling.

## Tool 01 - Web Scraper

### File

web_scraper.py

### Version

1.0

### Features

- HTTP/HTTPS URL validation.
- HTTP GET requests.
- Identifiable User-Agent.
- Request timeout.
- Response-size limit.
- HTTP status code detection.
- Final URL detection.
- Content-Type detection.
- HTML title extraction.
- Meta description extraction.
- HTTP/HTTPS link extraction.
- Link counting.
- Human-readable output.
- JSON output.
- Connection error handling.

## Usage

Basic usage:

    python web_scraper.py https://example.com

JSON output:

    python web_scraper.py https://example.com --json

Custom timeout:

    python web_scraper.py https://example.com --timeout 15

## Example

Example result:

    ============================================================
    Cybersecurity Python Lab - Web Scraper
    ============================================================
    Target          : http://example.com
    HTTP status     : 200
    Final URL       : http://example.com
    Content-Type    : text/html
    Content size    : 559 bytes
    Response limit  : NO
    Title           : Example Domain
    Description     : Not found
    Links found     : 1

    Links:
      1. https://iana.org/domains/example

## JSON Output

The --json option returns structured information including:

- tool
- version
- target
- status_code
- final_url
- content_type
- content_length
- truncated
- title
- meta_description
- links
- link_count

## Security Considerations

This tool is intended for:

- Educational laboratories.
- Authorized security assessments.
- Systems owned by the user.
- Systems for which explicit permission has been obtained.

The tool does not attempt:

- Authentication bypass.
- Exploitation.
- Brute force.
- Vulnerability exploitation.
- Intrusive scanning.

The scraper uses a controlled timeout and response-size limit.

TLS certificate verification must not be disabled to bypass certificate validation errors.

## Testing

The following tests were performed:

    python -m py_compile web_scraper.py
    python web_scraper.py http://example.com
    python web_scraper.py https://example.com --json
    python web_scraper.py https://example.com --timeout 15
    python web_scraper.py https://this-domain-does-not-exist-123456789.example
    python web_scraper.py ftp://example.com

Expected behavior:

- Successful HTTP page retrieval.
- Successful HTTPS JSON output.
- Successful HTTPS retrieval with custom timeout.
- DNS/connection error handling.
- Protocol validation.
- HTML title extraction.
- Link extraction.

## Future Improvements

Potential future versions may include:

- HTML heading extraction.
- Forms detection.
- Robots.txt awareness.
- Sitemap discovery.
- Structured metadata extraction.
- Internal/external link classification.
- Integration with the cybersecurity assessment framework.

## Version History

### v1.0

Initial web scraping tool with:

- HTTP/HTTPS support.
- HTML title extraction.
- Meta description extraction.
- Link extraction.
- JSON output.
- Error handling.
- Timeout control.
- Response-size limit.
EOF
