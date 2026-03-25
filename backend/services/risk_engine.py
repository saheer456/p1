"""
Risk Engine Module
Calculates a weighted risk score based on ALL scan findings (13 modules)
and classifies the overall risk level.
"""

from typing import List, Dict, Any

# Weight configuration
WEIGHT_MISSING_HEADER = 2        # per missing header
WEIGHT_OPEN_PORT = 3             # per open port
WEIGHT_SQLI = 25                 # if SQL injection detected
WEIGHT_XSS = 25                  # if XSS detected
WEIGHT_EXPOSED_DIR = 5           # per exposed directory
WEIGHT_SSL_ISSUE = 5             # per SSL issue
WEIGHT_CORS_ISSUE = 8            # per CORS issue
WEIGHT_COOKIE_ISSUE = 3          # per cookie issue
WEIGHT_METHODS_ISSUE = 4         # per dangerous HTTP method
WEIGHT_REDIRECT_VULN = 6         # per open redirect
WEIGHT_CLICKJACK = 5             # if clickjackable
WEIGHT_INFO_ISSUE = 2            # per info disclosure item

MAX_SCORE = 100


def calculate_risk(
    missing_headers: List[str],
    open_ports: List[int],
    sql_injection: bool,
    xss: bool,
    exposed_directories: List[str],
    ssl_issues: List[str] = None,
    cors_issues: List[str] = None,
    cookie_issues: List[str] = None,
    methods_issues: List[str] = None,
    redirect_vulns: List[dict] = None,
    clickjack_vulnerable: bool = False,
    info_issues: List[str] = None,
) -> Dict[str, Any]:
    """
    Calculate a weighted risk score and classify the risk level.

    Scoring (expanded for 13 modules):
        - Missing headers:       2 pts each
        - Open ports:             3 pts each
        - SQL Injection found:   25 pts
        - XSS found:             25 pts
        - Exposed directories:    5 pts each
        - SSL issues:             5 pts each
        - CORS issues:            8 pts each
        - Cookie issues:          3 pts each
        - HTTP method issues:     4 pts each
        - Open redirects:         6 pts each
        - Clickjacking:           5 pts
        - Info disclosure:        2 pts each

    Risk levels:
        -  0–25  → Low
        - 26–50  → Medium
        - 51–100 → High

    Returns dict with 'risk_score' (int) and 'risk_level' (str).
    """
    score = 0

    # Original
    score += len(missing_headers) * WEIGHT_MISSING_HEADER
    score += len(open_ports) * WEIGHT_OPEN_PORT
    score += WEIGHT_SQLI if sql_injection else 0
    score += WEIGHT_XSS if xss else 0
    score += len(exposed_directories) * WEIGHT_EXPOSED_DIR

    # New scanners
    if ssl_issues:
        score += len(ssl_issues) * WEIGHT_SSL_ISSUE
    if cors_issues:
        score += len(cors_issues) * WEIGHT_CORS_ISSUE
    if cookie_issues:
        score += len(cookie_issues) * WEIGHT_COOKIE_ISSUE
    if methods_issues:
        score += len(methods_issues) * WEIGHT_METHODS_ISSUE
    if redirect_vulns:
        score += len(redirect_vulns) * WEIGHT_REDIRECT_VULN
    if clickjack_vulnerable:
        score += WEIGHT_CLICKJACK
    if info_issues:
        score += len(info_issues) * WEIGHT_INFO_ISSUE

    # Cap at maximum
    score = min(score, MAX_SCORE)

    # Classify (adjusted thresholds for more modules)
    if score <= 25:
        level = "Low"
    elif score <= 50:
        level = "Medium"
    else:
        level = "High"

    return {
        "risk_score": score,
        "risk_level": level,
    }
