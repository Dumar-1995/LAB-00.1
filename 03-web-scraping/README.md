# 03 - Web Scraping

This module contains web scraping and web structure analysis tools developed as part of the Cybersecurity Python Lab.

The tools are designed for educational purposes and authorized security assessments.

## Objectives

- Retrieve HTTP/HTTPS web pages.
- Identify HTTP status codes.
- Detect the final URL.
- Extract HTML titles.
- Extract basic metadata.
- Analyze HTML page structure.
- Detect headings, forms, inputs, scripts, images, stylesheets, and links.
- Classify internal and external links.
- Export results in human-readable and JSON formats.
- Implement request controls and error handling.

---

## Tool 01 - Web Scraper

### File

`web_scraper.py`

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

### Usage

Basic usage:

    python web_scraper.py https://example.com

JSON output:

    python web_scraper.py https://example.com --json

Custom timeout:

    python web_scraper.py https://example.com --timeout 15

### JSON Output

The `--json` option returns structured information including:

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

---

## Tool 02 - Web Structure Analyzer

### File

`web_structure_analyzer.py`

### Version

1.0

### Purpose

The Web Structure Analyzer retrieves an HTTP/HTTPS page and analyzes its basic HTML structure without performing exploitation or intrusive testing.

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
- H1-H6 heading extraction.
- Form detection.
- Input detection.
- Script detection.
- Image detection.
- Stylesheet detection.
- Internal link detection.
- External link detection.
- Structural summary counters.
- Human-readable output.
- JSON output.
- Connection and protocol error handling.

### Usage

Basic analysis:

    python web_structure_analyzer.py http://example.com

JSON output:

    python web_structure_analyzer.py http://example.com --json

Custom timeout:

    python web_structure_analyzer.py https://example.com --timeout 15

### Example

Example HTTP analysis:

    ============================================================
    Cybersecurity Python Lab - Web Page Structure Analyzer
    ============================================================
    Target          : http://example.com
    HTTP status     : 200
    Final URL       : http://example.com
    Content-Type    : text/html
    Content size    : 559 bytes
    Response limit  : NO
    Title           : Example Domain

    Structure:
      Headings      : 1
      Forms         : 0
      Inputs        : 0
      Scripts       : 0
      Images        : 0
      Stylesheets   : 0
      Internal links: 0
      External links: 1

    Headings:
      H1: Example Domain

    External links:
      - https://iana.org/domains/example

### JSON Output

The `--json` option returns structured information including:

- tool
- version
- target
- status_code
- final_url
- content_type
- content_length
- truncated
- title
- headings
- forms
- inputs
- scripts
- images
- stylesheets
- internal_links
- external_links
- summary

The `summary` object contains counters for the detected HTML elements and links.

---

## Security Considerations

These tools are intended for:

- Educational laboratories.
- Authorized security assessments.
- Systems owned by the user.
- Systems for which explicit permission has been obtained.

The tools do not attempt:

- Authentication bypass.
- Exploitation.
- Brute force.
- Vulnerability exploitation.
- Intrusive scanning.

The tools use controlled timeouts and response-size limits.

TLS certificate verification must not be disabled to bypass certificate validation errors.

---

## Testing

### Tool 01

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

### Tool 02

The following tests were performed:

    python -m py_compile web_structure_analyzer.py
    python web_structure_analyzer.py http://example.com
    python web_structure_analyzer.py http://example.com --json
    python web_structure_analyzer.py https://this-domain-does-not-exist-123456789.example
    python web_structure_analyzer.py ftp://example.com

Expected behavior:

- Successful HTTP page retrieval.
- HTML structure analysis.
- JSON output.
- DNS/connection error handling.
- Protocol validation.
- Heading detection.
- Link classification.
- Structural element counting.

---

## Future Improvements

Potential future versions may include:

- Robots.txt awareness.
- Sitemap discovery.
- Structured metadata extraction.
- Additional HTML attribute analysis.
- Improved link normalization.
- Integration with the cybersecurity assessment framework.

---

## Version History

### v1.0 - Tool 01

Initial web scraping tool with:

- HTTP/HTTPS support.
- HTML title extraction.
- Meta description extraction.
- Link extraction.
- JSON output.
- Error handling.
- Timeout control.
- Response-size limit.

### v1.0 - Tool 02

Initial web structure analyzer with:

- HTML structure analysis.
- Heading extraction.
- Form and input detection.
- Script detection.
- Image detection.
- Stylesheet detection.
- Internal/external link classification.
- JSON output.
- Error handling.
- Response-size limit.

