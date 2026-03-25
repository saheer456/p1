"""
Open Redirect Checker Module
Tests for open redirect vulnerabilities in common URL parameters.
Educational purposes only.
"""

import requests
from urllib.parse import quote, urlparse
from typing import Dict, Any, List


REDIRECT_PARAMS = [
    "url", "redirect", "next", "return", "returnUrl", "return_url",
    "redir", "redirect_uri", "redirect_url", "continue", "dest",
    "destination", "go", "goto", "target", "to", "out", "view",
    "ref", "from", "data", "path", "forward", "callback",
    "checkout_url", "login_url", "logout_url", "image_url",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%2F%2F",
    "////evil.com",
    "/\\evil.com",
    "https:evil.com",
    "http://evil.com",
    "\\.evil.com",
    "///evil.com/%2f..",
    "//%09/evil.com",
    "https://evil.com/.example.com",
]


def check_open_redirects(url: str) -> Dict[str, Any]:
    """
    Test for open redirect vulnerabilities across common parameters.
    Returns dict with vulnerable params and issues.
    """
    result: Dict[str, Any] = {
        "vulnerable_params": [],
        "issues": [],
    }

    base_url = url.rstrip("/")

    try:
        for param in REDIRECT_PARAMS:
            for payload in REDIRECT_PAYLOADS[:3]:  # Test top 3 payloads per param (speed)
                separator = "&" if "?" in base_url else "?"
                test_url = f"{base_url}{separator}{param}={quote(payload)}"

                try:
                    response = requests.get(
                        test_url,
                        timeout=10,
                        allow_redirects=False,
                    )

                    # Check for redirect status
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get("Location", "")

                        # Check if redirect goes to evil.com
                        if "evil.com" in location:
                            vuln_entry = {
                                "param": param,
                                "payload": payload,
                                "redirects_to": location,
                            }
                            if param not in [v["param"] for v in result["vulnerable_params"]]:
                                result["vulnerable_params"].append(vuln_entry)
                                result["issues"].append(
                                    f"Open redirect via '{param}' parameter — "
                                    f"redirects to attacker-controlled URL: {location}"
                                )
                            break  # Found vuln for this param, move to next

                    # Check meta refresh redirect
                    if response.status_code == 200:
                        body = response.text.lower()
                        if "evil.com" in body and ("meta" in body and "refresh" in body):
                            if param not in [v["param"] for v in result["vulnerable_params"]]:
                                result["vulnerable_params"].append({
                                    "param": param,
                                    "payload": payload,
                                    "redirects_to": "via meta refresh",
                                })
                                result["issues"].append(
                                    f"Open redirect via meta refresh in '{param}' parameter"
                                )
                            break

                except requests.exceptions.RequestException:
                    continue

    except Exception:
        pass

    return result
