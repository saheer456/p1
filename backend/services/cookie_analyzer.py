"""
Cookie Security Analyzer Module
Checks cookies for missing security flags (HttpOnly, Secure, SameSite).
Educational purposes only.
"""

import requests
from typing import Dict, Any, List


def analyze_cookies(url: str) -> Dict[str, Any]:
    """
    Analyze cookies set by the target for security misconfigurations.
    Returns dict with cookie details and issues.
    """
    result: Dict[str, Any] = {
        "cookies": [],
        "issues": [],
    }

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)

        set_cookie_headers = response.headers.get("Set-Cookie", "")
        # Also check raw headers for multiple Set-Cookie
        raw_cookies = []
        for key, val in response.raw.headers.items():
            if key.lower() == "set-cookie":
                raw_cookies.append(val)

        if not raw_cookies and set_cookie_headers:
            raw_cookies = [set_cookie_headers]

        if not raw_cookies:
            # Also check response.cookies
            for cookie in response.cookies:
                cookie_info = _analyze_cookie_obj(cookie, url)
                result["cookies"].append(cookie_info["info"])
                result["issues"].extend(cookie_info["issues"])
            return result

        for raw in raw_cookies:
            cookie_info = _parse_set_cookie(raw, url)
            result["cookies"].append(cookie_info["info"])
            result["issues"].extend(cookie_info["issues"])

    except requests.exceptions.RequestException:
        result["issues"].append("Could not connect to target for cookie analysis")
    except Exception:
        pass

    return result


def _parse_set_cookie(raw: str, url: str) -> Dict[str, Any]:
    """Parse a raw Set-Cookie header and check for security flags."""
    parts = [p.strip() for p in raw.split(";")]
    name_value = parts[0].split("=", 1)
    name = name_value[0].strip() if name_value else "unknown"

    flags = {p.strip().lower() for p in parts[1:]}
    flag_map = {p.strip().lower(): p.strip() for p in parts[1:]}

    info = {
        "name": name,
        "httponly": any("httponly" in f for f in flags),
        "secure": any("secure" in f for f in flags),
        "samesite": None,
        "path": None,
        "domain": None,
    }

    issues = []

    # Extract SameSite
    for f in flags:
        if f.startswith("samesite"):
            info["samesite"] = flag_map.get(f, "").split("=", 1)[-1].strip() if "=" in f else "Lax"
        if f.startswith("path"):
            info["path"] = f.split("=", 1)[-1].strip() if "=" in f else "/"
        if f.startswith("domain"):
            info["domain"] = f.split("=", 1)[-1].strip() if "=" in f else None

    # Check for session cookie indicators
    session_keywords = ["session", "sess", "sid", "token", "auth", "jwt", "login", "csrf"]
    is_session = any(kw in name.lower() for kw in session_keywords)

    if not info["httponly"]:
        severity = "CRITICAL" if is_session else "Medium"
        issues.append(f"{severity}: Cookie '{name}' missing HttpOnly flag — vulnerable to XSS cookie theft")

    if not info["secure"] and url.startswith("https"):
        severity = "High" if is_session else "Medium"
        issues.append(f"{severity}: Cookie '{name}' missing Secure flag — can be sent over unencrypted HTTP")

    if info["samesite"] is None:
        issues.append(f"Medium: Cookie '{name}' missing SameSite flag — vulnerable to CSRF attacks")
    elif info["samesite"].lower() == "none" and not info["secure"]:
        issues.append(f"High: Cookie '{name}' has SameSite=None without Secure flag")

    if info["path"] == "/" or info["path"] is None:
        if is_session:
            issues.append(f"Low: Session cookie '{name}' has broad path scope (/)")

    return {"info": info, "issues": issues}


def _analyze_cookie_obj(cookie, url: str) -> Dict[str, Any]:
    """Analyze a requests Cookie object."""
    info = {
        "name": cookie.name,
        "httponly": bool(cookie._rest.get("HttpOnly", cookie._rest.get("httponly", False))),
        "secure": cookie.secure,
        "samesite": None,
        "path": cookie.path,
        "domain": cookie.domain,
    }

    issues = []
    session_keywords = ["session", "sess", "sid", "token", "auth", "jwt", "login", "csrf"]
    is_session = any(kw in cookie.name.lower() for kw in session_keywords)

    if not info["httponly"]:
        severity = "CRITICAL" if is_session else "Medium"
        issues.append(f"{severity}: Cookie '{cookie.name}' missing HttpOnly flag")

    if not info["secure"]:
        severity = "High" if is_session else "Medium"
        issues.append(f"{severity}: Cookie '{cookie.name}' missing Secure flag")

    return {"info": info, "issues": issues}
