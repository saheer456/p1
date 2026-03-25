"""
CORS Misconfiguration Checker Module
Tests for insecure Cross-Origin Resource Sharing configurations.
Educational purposes only.
"""

import requests
from typing import Dict, Any, List


def check_cors(url: str) -> Dict[str, Any]:
    """
    Test the target URL for CORS misconfigurations.
    Returns a dict with CORS headers and detected issues.
    """
    result: Dict[str, Any] = {
        "cors_enabled": False,
        "issues": [],
        "details": {},
    }

    try:
        # Test 1: Send request with evil origin
        evil_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
        ]

        for origin in evil_origins:
            try:
                response = requests.get(
                    url,
                    headers={"Origin": origin},
                    timeout=10,
                    allow_redirects=True,
                )

                acao = response.headers.get("Access-Control-Allow-Origin", "")
                acac = response.headers.get("Access-Control-Allow-Credentials", "")
                acam = response.headers.get("Access-Control-Allow-Methods", "")
                acah = response.headers.get("Access-Control-Allow-Headers", "")

                if acao:
                    result["cors_enabled"] = True
                    result["details"] = {
                        "allow_origin": acao,
                        "allow_credentials": acac,
                        "allow_methods": acam,
                        "allow_headers": acah,
                    }

                    # Wildcard origin
                    if acao == "*":
                        result["issues"].append(
                            "Access-Control-Allow-Origin is set to wildcard (*) — any website can read responses"
                        )

                    # Origin reflection — reflects attacker's origin
                    if acao == origin and origin != "null":
                        result["issues"].append(
                            f"Server reflects attacker's Origin ({origin}) in Access-Control-Allow-Origin"
                        )

                    # Null origin accepted
                    if acao == "null" or (origin == "null" and acao == origin):
                        result["issues"].append(
                            "Server accepts 'null' origin — can be exploited via sandboxed iframes"
                        )

                    # Credentials with wildcard
                    if acao == "*" and acac.lower() == "true":
                        result["issues"].append(
                            "CRITICAL: Wildcard origin with Allow-Credentials: true — full cross-origin data theft possible"
                        )

                    # Credentials with reflected origin
                    if acao == origin and acac.lower() == "true":
                        result["issues"].append(
                            "CRITICAL: Reflected origin with Allow-Credentials: true — authenticated cross-origin data theft possible"
                        )

                    if result["issues"]:
                        break  # Found issues, no need to test more origins

            except requests.exceptions.RequestException:
                continue

        # Test 2: Preflight request
        try:
            preflight = requests.options(
                url,
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "PUT",
                    "Access-Control-Request-Headers": "X-Custom-Header",
                },
                timeout=10,
            )

            if preflight.status_code == 200:
                acam = preflight.headers.get("Access-Control-Allow-Methods", "")
                if acam:
                    dangerous = {"PUT", "DELETE", "PATCH"}
                    allowed = {m.strip().upper() for m in acam.split(",")}
                    exposed = dangerous & allowed
                    if exposed:
                        result["issues"].append(
                            f"CORS allows dangerous methods from any origin: {', '.join(exposed)}"
                        )

        except requests.exceptions.RequestException:
            pass

    except Exception:
        pass

    return result
