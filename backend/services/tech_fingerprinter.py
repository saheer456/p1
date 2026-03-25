"""
Technology Fingerprinting Module
Detects server software, CMS platforms, frameworks, and programming languages.
Educational purposes only.
"""

import re
import requests
from typing import Dict, Any, List


# Patterns to detect CMS/frameworks in HTML source
CMS_SIGNATURES = {
    "WordPress": [
        r"/wp-content/",
        r"/wp-includes/",
        r'<meta name="generator" content="WordPress',
        r"/xmlrpc\.php",
        r"wp-json",
    ],
    "Joomla": [
        r"/media/system/",
        r'<meta name="generator" content="Joomla',
        r"/components/com_",
        r"/administrator/",
    ],
    "Drupal": [
        r'<meta name="generator" content="Drupal',
        r"/sites/default/",
        r"/core/misc/drupal",
        r"Drupal\.settings",
    ],
    "Shopify": [
        r"cdn\.shopify\.com",
        r"myshopify\.com",
        r"Shopify\.theme",
    ],
    "Wix": [
        r"static\.wixstatic\.com",
        r"wix-code-",
        r'"wixBiSession"',
    ],
    "Squarespace": [
        r"squarespace\.com",
        r"static1\.squarespace\.com",
    ],
}

JS_FRAMEWORK_SIGNATURES = {
    "React": [r"react", r"__REACT", r"_reactRoot", r"data-reactroot"],
    "Angular": [r"ng-version", r"ng-app", r"angular\.js", r"angular\.min\.js"],
    "Vue.js": [r"vue\.js", r"vue\.min\.js", r"__vue__", r"v-app"],
    "jQuery": [r"jquery", r"jQuery"],
    "Next.js": [r"__NEXT_DATA__", r"_next/static"],
    "Nuxt.js": [r"__NUXT__", r"_nuxt/"],
    "Svelte": [r"__svelte", r"svelte"],
    "Express": [r"X-Powered-By.*Express"],
    "Django": [r"csrfmiddlewaretoken", r"__admin_media_prefix__"],
    "Flask": [r"Werkzeug", r"flask"],
    "Laravel": [r"laravel_session", r"XSRF-TOKEN"],
    "Rails": [r"X-Request-Id", r"csrf-token", r"action_controller"],
    "ASP.NET": [r"__VIEWSTATE", r"__EVENTVALIDATION", r"asp\.net"],
    "Spring": [r"JSESSIONID", r"spring"],
}


def fingerprint_tech(url: str) -> Dict[str, Any]:
    """
    Fingerprint technologies used by the target web application.
    Returns dict with detected server, CMS, frameworks, and issues.
    """
    result: Dict[str, Any] = {
        "server": None,
        "powered_by": None,
        "cms": [],
        "frameworks": [],
        "languages": [],
        "additional_headers": {},
        "issues": [],
    }

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers
        body = response.text
        cookies_str = str(response.cookies.get_dict())

        # Server header
        server = headers.get("Server", "")
        if server:
            result["server"] = server
            # Check for version disclosure
            if re.search(r"\d+\.\d+", server):
                result["issues"].append(f"Server version disclosed: {server}")

        # X-Powered-By
        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            result["powered_by"] = powered_by
            result["issues"].append(f"X-Powered-By header reveals technology: {powered_by}")

        # ASP.NET version
        aspnet = headers.get("X-AspNet-Version", "")
        if aspnet:
            result["additional_headers"]["X-AspNet-Version"] = aspnet
            result["issues"].append(f"ASP.NET version disclosed: {aspnet}")

        # X-Generator
        generator = headers.get("X-Generator", "")
        if generator:
            result["additional_headers"]["X-Generator"] = generator

        # Detect CMS from body
        for cms, patterns in CMS_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    if cms not in result["cms"]:
                        result["cms"].append(cms)
                    break

        # Detect frameworks from body + headers + cookies
        search_text = body + str(headers) + cookies_str
        for framework, patterns in JS_FRAMEWORK_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, search_text, re.IGNORECASE):
                    if framework not in result["frameworks"]:
                        result["frameworks"].append(framework)
                    break

        # Detect programming language hints
        lang_hints = {
            "PHP": [r"\.php", r"PHPSESSID", r"X-Powered-By.*PHP"],
            "Python": [r"X-Powered-By.*Python", r"Werkzeug", r"wsgi"],
            "Java": [r"JSESSIONID", r"X-Powered-By.*Servlet", r"\.jsp"],
            "Ruby": [r"X-Powered-By.*Phusion", r"_session_id", r"\.rb"],
            "Node.js": [r"X-Powered-By.*Express", r"connect\.sid"],
            "ASP.NET": [r"ASP\.NET", r"__VIEWSTATE", r"\.aspx", r"\.ashx"],
        }

        for lang, patterns in lang_hints.items():
            for pattern in patterns:
                if re.search(pattern, search_text, re.IGNORECASE):
                    if lang not in result["languages"]:
                        result["languages"].append(lang)
                    break

        # Version disclosures in meta tags
        generator_meta = re.findall(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
            body, re.IGNORECASE
        )
        for gen in generator_meta:
            result["issues"].append(f"Generator meta tag reveals: {gen}")

    except requests.exceptions.RequestException:
        result["issues"].append("Could not connect to target for fingerprinting")
    except Exception:
        pass

    return result
