"""
Information Disclosure Checker Module
Detects leaked server info, stack traces, HTML comments, debug endpoints, source maps.
Educational purposes only.
"""

import re
import requests
from typing import Dict, Any, List


def check_info_disclosure(url: str) -> Dict[str, Any]:
    """
    Check the target for information disclosure vulnerabilities.
    Returns dict with discovered disclosures and issues.
    """
    result: Dict[str, Any] = {
        "disclosures": [],
        "issues": [],
    }

    base_url = url.rstrip("/")

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers
        body = response.text

        # ── Header-based disclosures ──
        disclosure_headers = {
            "Server": "Server software",
            "X-Powered-By": "Backend technology",
            "X-AspNet-Version": "ASP.NET version",
            "X-AspNetMvc-Version": "ASP.NET MVC version",
            "X-Generator": "Site generator",
            "X-Debug-Token": "Debug token (Symfony)",
            "X-Debug-Token-Link": "Debug link (Symfony)",
            "X-Runtime": "Request runtime (Ruby)",
            "X-Request-Id": "Request ID",
        }

        for header, desc in disclosure_headers.items():
            value = headers.get(header)
            if value:
                result["disclosures"].append({
                    "type": "header",
                    "name": header,
                    "value": value,
                    "description": desc,
                })
                # Only flag detailed version info as issues
                if re.search(r"\d+\.\d+", value):
                    result["issues"].append(
                        f"{desc} version disclosed via {header}: {value}"
                    )

        # ── HTML comment analysis ──
        comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
        sensitive_patterns = [
            (r"password", "Password found in HTML comment"),
            (r"api[_-]?key", "API key reference in HTML comment"),
            (r"secret", "Secret reference in HTML comment"),
            (r"token", "Token reference in HTML comment"),
            (r"TODO|FIXME|HACK|BUG", "Developer TODO/FIXME in HTML comment"),
            (r"username|admin|root", "Username/credential reference in HTML comment"),
            (r"/home/|/var/|/usr/|C:\\\\", "File path disclosed in HTML comment"),
            (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP address in HTML comment"),
            (r"database|db_|mysql|postgres", "Database reference in HTML comment"),
        ]

        for comment in comments:
            for pattern, desc in sensitive_patterns:
                if re.search(pattern, comment, re.IGNORECASE):
                    result["disclosures"].append({
                        "type": "html_comment",
                        "description": desc,
                        "snippet": comment.strip()[:100],
                    })
                    result["issues"].append(desc)
                    break

        # ── Stack trace / error detection ──
        error_patterns = [
            (r"Traceback \(most recent call last\)", "Python stack trace exposed"),
            (r"at [\w.]+\([\w]+\.java:\d+\)", "Java stack trace exposed"),
            (r"Fatal error:.*in .* on line \d+", "PHP fatal error exposed"),
            (r"Parse error:.*in .* on line \d+", "PHP parse error exposed"),
            (r"Warning:.*in .* on line \d+", "PHP warning exposed"),
            (r"Microsoft\.AspNetCore|System\.NullReferenceException", ".NET stack trace exposed"),
            (r"node_modules/|at Object\.<anonymous>", "Node.js stack trace exposed"),
            (r"DEBUG\s*=\s*True", "Django DEBUG mode is enabled"),
            (r"DATABASES\s*=", "Database configuration exposed"),
        ]

        for pattern, desc in error_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                result["disclosures"].append({
                    "type": "stack_trace",
                    "description": desc,
                })
                result["issues"].append(desc)

        # ── Source map detection ──
        sourcemap_patterns = [
            r"//# sourceMappingURL=",
            r"/\*# sourceMappingURL=",
        ]
        for pattern in sourcemap_patterns:
            if re.search(pattern, body):
                result["disclosures"].append({
                    "type": "source_map",
                    "description": "JavaScript source map detected — may expose original source code",
                })
                result["issues"].append("JavaScript source maps are accessible — may expose original source code")
                break

        # ── Debug endpoint checks ──
        debug_paths = [
            "/__debug__/",
            "/debug/",
            "/elmah.axd",
            "/trace.axd",
            "/_profiler/",
            "/api/debug",
            "/server-status",
            "/server-info",
            "/.well-known/",
        ]

        for path in debug_paths:
            try:
                debug_url = f"{base_url}{path}"
                r = requests.get(debug_url, timeout=5, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 100:
                    result["disclosures"].append({
                        "type": "debug_endpoint",
                        "path": path,
                        "description": f"Debug/info endpoint accessible: {path}",
                    })
                    result["issues"].append(f"Debug/info endpoint accessible: {path}")
            except requests.exceptions.RequestException:
                continue

        # ── Email address leaks ──
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", body)
        if emails:
            unique_emails = list(set(emails))[:5]
            result["disclosures"].append({
                "type": "email_leak",
                "emails": unique_emails,
                "description": f"Email addresses found in page source: {', '.join(unique_emails)}",
            })
            result["issues"].append(f"{len(unique_emails)} email address(es) exposed in page source")

    except requests.exceptions.RequestException:
        result["issues"].append("Could not connect to target for info disclosure check")
    except Exception:
        pass

    return result
