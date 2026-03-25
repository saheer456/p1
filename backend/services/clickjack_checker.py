"""
Clickjacking Checker Module
Tests if the target is vulnerable to clickjacking (UI redressing) attacks.
Educational purposes only.
"""

import requests
from typing import Dict, Any


def check_clickjacking(url: str) -> Dict[str, Any]:
    """
    Check if target is vulnerable to clickjacking.
    Tests X-Frame-Options and CSP frame-ancestors directive.
    Returns dict with protection status and issues.
    """
    result: Dict[str, Any] = {
        "x_frame_options": None,
        "csp_frame_ancestors": None,
        "vulnerable": True,  # assume vulnerable until proven otherwise
        "issues": [],
    }

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers

        # Check X-Frame-Options
        xfo = headers.get("X-Frame-Options", "")
        if xfo:
            result["x_frame_options"] = xfo.upper()
            xfo_upper = xfo.upper()

            if xfo_upper in ["DENY", "SAMEORIGIN"]:
                result["vulnerable"] = False
            elif "ALLOW-FROM" in xfo_upper:
                result["issues"].append(
                    "X-Frame-Options uses ALLOW-FROM which is deprecated and not supported by modern browsers"
                )
            else:
                result["issues"].append(f"X-Frame-Options has invalid value: {xfo}")
        else:
            result["issues"].append("Missing X-Frame-Options header — page can be embedded in iframes")

        # Check CSP frame-ancestors
        csp = headers.get("Content-Security-Policy", "")
        if csp:
            if "frame-ancestors" in csp.lower():
                # Extract frame-ancestors value
                for directive in csp.split(";"):
                    if "frame-ancestors" in directive.lower():
                        result["csp_frame_ancestors"] = directive.strip()
                        if "'none'" in directive or "'self'" in directive:
                            result["vulnerable"] = False
                        elif "*" in directive:
                            result["issues"].append(
                                "CSP frame-ancestors is set to wildcard (*) — does not prevent clickjacking"
                            )
                        else:
                            result["vulnerable"] = False
                        break
            else:
                if not xfo:
                    result["issues"].append(
                        "CSP present but missing frame-ancestors directive"
                    )

        if result["vulnerable"]:
            result["issues"].append(
                "Page is vulnerable to clickjacking — can be embedded in a malicious iframe "
                "to trick users into performing unintended actions"
            )

    except requests.exceptions.RequestException:
        result["issues"].append("Could not connect to target for clickjacking check")
    except Exception:
        pass

    return result
