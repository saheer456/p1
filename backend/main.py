"""
Web Application Vulnerability Scanner - Backend API
====================================================
Educational Security Assessment Tool

WARNING: This tool is for EDUCATIONAL PURPOSES ONLY.
Unauthorized scanning of websites you do not own or have
explicit permission to test is illegal and unethical.
"""

import re
import socket
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

# ── Original scanners ──
from services.header_scanner import scan_headers
from services.port_scanner import scan_ports
from services.sqli_detector import detect_sqli
from services.xss_detector import detect_xss
from services.directory_scanner import scan_directories
from services.risk_engine import calculate_risk

# ── New scanners ──
from services.ssl_analyzer import analyze_ssl
from services.cors_checker import check_cors
from services.tech_fingerprinter import fingerprint_tech
from services.cookie_analyzer import analyze_cookies
from services.http_methods_checker import check_http_methods
from services.open_redirect_checker import check_open_redirects
from services.info_disclosure_checker import check_info_disclosure
from services.clickjack_checker import check_clickjacking

# ── Attack report engine ──
from services.attack_reporter import generate_attack_report

# ──────────────────────────────────────────────
# App Setup
# ──────────────────────────────────────────────

app = FastAPI(
    title="Vulnerability Scanner API",
    description="Educational security assessment tool — backend API",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────
# Models
# ──────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str
    allow_local: bool = False

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not re.match(r"^https?://", v, re.IGNORECASE):
            raise ValueError("URL must start with http:// or https://")

        parsed = urlparse(v)
        if not parsed.hostname:
            raise ValueError("Invalid URL: no hostname found")

        return v


class ScanResult(BaseModel):
    target: str
    timestamp: str
    # Original results
    open_ports: list[int]
    missing_headers: list[str]
    sql_injection: bool
    xss: bool
    exposed_directories: list[str]
    risk_score: int
    risk_level: str
    # New scanner results
    ssl_analysis: dict
    cors_analysis: dict
    tech_fingerprint: dict
    cookie_analysis: dict
    http_methods: dict
    open_redirects: dict
    info_disclosure: dict
    clickjacking: dict
    # Attack report
    attack_report: dict


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
]


def is_private_ip(hostname: str) -> bool:
    """Check if the resolved hostname points to a private/reserved IP."""
    try:
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in PRIVATE_NETWORKS)
    except (socket.gaierror, ValueError):
        return False


# ──────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "message": "Vulnerability Scanner API v2.0 is running",
        "disclaimer": "This tool is for educational purposes only.",
        "scanners": [
            "Security Headers", "Port Scanner", "SQL Injection", "XSS Detection",
            "Directory Enumeration", "SSL/TLS Analysis", "CORS Checker",
            "Technology Fingerprinting", "Cookie Security", "HTTP Methods",
            "Open Redirect", "Information Disclosure", "Clickjacking",
        ],
    }


@app.post("/scan", response_model=ScanResult)
def run_scan(request: ScanRequest):
    """
    Orchestrates all 13 scanner modules against the target URL and
    returns a consolidated report with detailed attack analysis.
    """
    url = request.url
    parsed = urlparse(url)
    hostname = parsed.hostname

    # Block private / internal IPs (unless allow_local is True)
    if is_private_ip(hostname) and not request.allow_local:
        raise HTTPException(
            status_code=400,
            detail="Scanning private or internal IP addresses is not allowed. "
                   "Enable 'Allow Local Scan' to scan local applications.",
        )

    # ── Run original scanners ──
    missing_headers = scan_headers(url)
    open_ports = scan_ports(url)
    sql_injection = detect_sqli(url)
    xss = detect_xss(url)
    exposed_directories = scan_directories(url)

    # ── Run new scanners ──
    ssl_analysis = analyze_ssl(url)
    cors_analysis = check_cors(url)
    tech_fingerprint = fingerprint_tech(url)
    cookie_analysis = analyze_cookies(url)
    http_methods = check_http_methods(url)
    open_redirects = check_open_redirects(url)
    info_disclosure = check_info_disclosure(url)
    clickjacking = check_clickjacking(url)

    # ── Calculate risk (updated to include new findings) ──
    risk = calculate_risk(
        missing_headers=missing_headers,
        open_ports=open_ports,
        sql_injection=sql_injection,
        xss=xss,
        exposed_directories=exposed_directories,
        ssl_issues=ssl_analysis.get("issues", []),
        cors_issues=cors_analysis.get("issues", []),
        cookie_issues=cookie_analysis.get("issues", []),
        methods_issues=http_methods.get("issues", []),
        redirect_vulns=open_redirects.get("vulnerable_params", []),
        clickjack_vulnerable=clickjacking.get("vulnerable", False),
        info_issues=info_disclosure.get("issues", []),
    )

    # ── Generate attack report ──
    scan_data = {
        "target": url,
        "missing_headers": missing_headers,
        "open_ports": open_ports,
        "sql_injection": sql_injection,
        "xss": xss,
        "exposed_directories": exposed_directories,
        "ssl_analysis": ssl_analysis,
        "cors_analysis": cors_analysis,
        "tech_fingerprint": tech_fingerprint,
        "cookie_analysis": cookie_analysis,
        "http_methods": http_methods,
        "open_redirects": open_redirects,
        "info_disclosure": info_disclosure,
        "clickjacking": clickjacking,
    }
    attack_report = generate_attack_report(scan_data)

    return ScanResult(
        target=url,
        timestamp=datetime.now(timezone.utc).isoformat(),
        open_ports=open_ports,
        missing_headers=missing_headers,
        sql_injection=sql_injection,
        xss=xss,
        exposed_directories=exposed_directories,
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        ssl_analysis=ssl_analysis,
        cors_analysis=cors_analysis,
        tech_fingerprint=tech_fingerprint,
        cookie_analysis=cookie_analysis,
        http_methods=http_methods,
        open_redirects=open_redirects,
        info_disclosure=info_disclosure,
        clickjacking=clickjacking,
        attack_report=attack_report,
    )
