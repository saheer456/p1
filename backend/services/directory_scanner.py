"""
Directory Scanner Module
Tests for commonly exposed sensitive directories and files.
Educational purposes only.
"""

import requests
from typing import List

COMMON_DIRECTORIES = [
    # ── Admin panels ──
    "/admin",
    "/administrator",
    "/admin/login",
    "/admin.php",
    "/cpanel",
    "/dashboard",
    "/manager",
    "/panel",
    "/login",
    "/signin",
    "/wp-admin",
    "/wp-login.php",

    # ── Sensitive files ──
    "/.env",
    "/.env.bak",
    "/.env.local",
    "/.env.production",
    "/.git",
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/.htaccess",
    "/.htpasswd",
    "/.svn",
    "/.svn/entries",
    "/web.config",
    "/crossdomain.xml",
    "/elmah.axd",

    # ── Config / Info ──
    "/config",
    "/config.php",
    "/configuration.php",
    "/settings.php",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/phpinfo.php",
    "/info.php",
    "/server-info",
    "/server-status",

    # ── Backup files ──
    "/backup",
    "/backup.zip",
    "/backup.sql",
    "/backup.tar.gz",
    "/db.sql",
    "/database.sql",
    "/dump.sql",
    "/site.sql",
    "/data.sql",

    # ── Common CMS / framework paths ──
    "/wp-content",
    "/wp-includes",
    "/xmlrpc.php",
    "/phpmyadmin",
    "/pma",
    "/adminer.php",

    # ── API / Debug ──
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/debug",
    "/debug/default/view",
    "/console",
    "/trace.axd",
    "/test",
    "/test.php",
    "/temp",
    "/tmp",

    # ── Info disclosure ──
    "/robots.txt",
    "/sitemap.xml",
    "/humans.txt",
    "/security.txt",
    "/.well-known/security.txt",
    "/readme.html",
    "/README.md",
    "/CHANGELOG.md",
    "/LICENSE",
    "/composer.json",
    "/package.json",

    # ── Error / Log pages ──
    "/error",
    "/errors",
    "/logs",
    "/log",
    "/error_log",
    "/access.log",

    # ── Upload / File disclosure ──
    "/uploads",
    "/upload",
    "/files",
    "/images",
    "/documents",
    "/media",
]

# Status codes that indicate an exposed directory/file
EXPOSED_STATUS_CODES = [200, 301, 302, 403]


def scan_directories(url: str) -> List[str]:
    """
    Test the target URL for commonly exposed directories and files.
    Returns a list of paths that returned a meaningful HTTP response.
    """
    exposed: List[str] = []

    # Normalize URL — remove trailing slash
    base_url = url.rstrip("/")

    for directory in COMMON_DIRECTORIES:
        test_url = f"{base_url}{directory}"

        try:
            response = requests.get(
                test_url,
                timeout=5,
                allow_redirects=False,
            )

            if response.status_code in EXPOSED_STATUS_CODES:
                exposed.append(directory)

        except requests.exceptions.RequestException:
            continue

    return exposed
