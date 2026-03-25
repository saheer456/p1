"""
HTTP Methods Checker Module
Tests for dangerous HTTP methods (PUT, DELETE, TRACE, etc.) that shouldn't be publicly accessible.
Educational purposes only.
"""

import requests
from typing import Dict, Any, List


DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]


def check_http_methods(url: str) -> Dict[str, Any]:
    """
    Test which HTTP methods are accepted by the target server.
    Returns dict with allowed methods and detected issues.
    """
    result: Dict[str, Any] = {
        "allowed_methods": [],
        "dangerous_methods": [],
        "issues": [],
    }

    try:
        # Method 1: OPTIONS request
        try:
            options_response = requests.options(url, timeout=10)
            allow_header = options_response.headers.get("Allow", "")
            if allow_header:
                methods = [m.strip().upper() for m in allow_header.split(",")]
                result["allowed_methods"] = methods

                for method in methods:
                    if method in DANGEROUS_METHODS:
                        result["dangerous_methods"].append(method)
        except requests.exceptions.RequestException:
            pass

        # Method 2: Try each method directly
        for method in ALL_METHODS:
            try:
                response = requests.request(
                    method, url, timeout=5, allow_redirects=False
                )
                # 405 = Method Not Allowed, 501 = Not Implemented
                if response.status_code not in [405, 501]:
                    if method not in result["allowed_methods"]:
                        result["allowed_methods"].append(method)
                    if method in DANGEROUS_METHODS and method not in result["dangerous_methods"]:
                        result["dangerous_methods"].append(method)
            except requests.exceptions.RequestException:
                continue

        # Check TRACE specifically for XST (Cross-Site Tracing)
        if "TRACE" in result["dangerous_methods"]:
            result["issues"].append(
                "TRACE method enabled — vulnerable to Cross-Site Tracing (XST) attacks, "
                "attackers can steal credentials/session tokens via XSS"
            )

        if "PUT" in result["dangerous_methods"]:
            result["issues"].append(
                "PUT method enabled — attackers may be able to upload malicious files "
                "or overwrite existing content on the server"
            )

        if "DELETE" in result["dangerous_methods"]:
            result["issues"].append(
                "DELETE method enabled — attackers may be able to delete "
                "files and resources on the server"
            )

        if "CONNECT" in result["dangerous_methods"]:
            result["issues"].append(
                "CONNECT method enabled — server may be abused as an open proxy "
                "for tunneling traffic"
            )

        if "PATCH" in result["dangerous_methods"]:
            result["issues"].append(
                "PATCH method enabled — attackers may be able to partially "
                "modify server resources"
            )

    except Exception:
        pass

    return result
