"""
Header Scanner Module
Checks for common security headers in HTTP responses.
"""

import requests
from typing import List

SECURITY_HEADERS = [
    # Core security headers
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",

    # Additional important headers
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
    "X-Permitted-Cross-Domain-Policies",
    "X-Download-Options",
    "X-DNS-Prefetch-Control",
    "Cache-Control",
    "Expect-CT",
]


def scan_headers(url: str) -> List[str]:
    """
    Check the target URL for missing security headers.
    Returns a list of missing header names.
    """
    missing_headers: List[str] = []

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        response_headers = {k.lower(): v for k, v in response.headers.items()}

        for header in SECURITY_HEADERS:
            if header.lower() not in response_headers:
                missing_headers.append(header)

    except requests.exceptions.RequestException:
        # If we can't reach the site, all headers are effectively "missing"
        missing_headers = SECURITY_HEADERS.copy()

    return missing_headers
