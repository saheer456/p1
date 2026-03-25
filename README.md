<p align="center">
  <h1 align="center">🛡️ VulnScanner v2.0</h1>
  <p align="center">
    <strong>Web Application Vulnerability Scanner — Educational Security Assessment Tool</strong>
  </p>
  <p align="center">
    <a href="#-features">Features</a> · 
    <a href="#-architecture">Architecture</a> · 
    <a href="#-scanner-modules">Scanner Modules</a> · 
    <a href="#-getting-started">Getting Started</a> · 
    <a href="#-api-reference">API Reference</a> · 
    <a href="#-screenshots">Screenshots</a>
  </p>
</p>

---

> **⚠️ DISCLAIMER:** This tool is for **educational purposes only**. Unauthorized scanning of websites you do not own or have explicit written permission to test is **illegal and unethical**. Always obtain proper authorization before scanning any target.

---

## 📖 Overview

VulnScanner is a full-stack web application that performs comprehensive security assessments against web targets. It runs **13 independent scanning modules** that analyze everything from missing HTTP headers to SQL injection vulnerabilities, then generates a detailed **Attack Surface Report** with exploitation paths, severity ratings, and remediation guidance.

**Key Highlights:**
- 🔍 **13 Security Scanning Modules** — covering headers, ports, injection, encryption, access control, and more
- ⚔️ **Automated Attack Report Engine** — generates exploitation steps, attack chains, and severity classifications
- 📊 **Weighted Risk Scoring** — calculates an overall risk score (0–100) across all findings
- 📄 **PDF Export** — download a professional security report with one click
- 🌐 **Local Scanning Support** — opt-in flag to scan localhost / private IP applications
- 🎨 **Modern UI** — dark-themed, responsive interface with real-time scan progress indicators

---

## 🏗️ Architecture

### High-Level System Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        FRONTEND (Browser)                           │
│                                                                     │
│   ┌──────────┐    ┌──────────┐    ┌───────────────────────────┐    │
│   │index.html│    │styles.css│    │       script.js            │    │
│   │  (UI)    │    │ (Design) │    │  • Form handling           │    │
│   │  492 LOC │    │ 26KB CSS │    │  • API calls (fetch)       │    │
│   └──────────┘    └──────────┘    │  • Results rendering       │    │
│                                    │  • Attack report display   │    │
│                                    │  • PDF generation (jsPDF)  │    │
│                                    └────────────┬──────────────┘    │
│                                                 │                   │
└─────────────────────────────────────────────────┼───────────────────┘
                                                  │ POST /scan
                                                  │ (JSON)
                                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      BACKEND (FastAPI + Uvicorn)                    │
│                         http://localhost:8000                        │
│                                                                     │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │                        main.py                               │   │
│   │  • URL validation (Pydantic)                                 │   │
│   │  • Private IP blocking (SSRF protection)                     │   │
│   │  • Scanner orchestration (13 modules)                        │   │
│   │  • Risk calculation                                          │   │
│   │  • Attack report generation                                  │   │
│   └───────────────┬─────────────────────────────────────────────┘   │
│                   │                                                  │
│   ┌───────────────▼─────────────────────────────────────────────┐   │
│   │                    services/ (15 modules)                    │   │
│   │                                                              │   │
│   │  ┌─────────────────────┐  ┌──────────────────────────────┐  │   │
│   │  │  CORE SCANNERS (5)  │  │   ADVANCED SCANNERS (8)      │  │   │
│   │  │                     │  │                               │  │   │
│   │  │  • header_scanner   │  │  • ssl_analyzer               │  │   │
│   │  │  • port_scanner     │  │  • cors_checker               │  │   │
│   │  │  • sqli_detector    │  │  • tech_fingerprinter         │  │   │
│   │  │  • xss_detector     │  │  • cookie_analyzer            │  │   │
│   │  │  • directory_scanner│  │  • http_methods_checker        │  │   │
│   │  │                     │  │  • open_redirect_checker       │  │   │
│   │  └─────────────────────┘  │  • info_disclosure_checker     │  │   │
│   │                           │  • clickjack_checker            │  │   │
│   │  ┌─────────────────────┐  └──────────────────────────────┘  │   │
│   │  │  ENGINES (2)        │                                     │  │
│   │  │  • risk_engine      │                                     │  │
│   │  │  • attack_reporter  │                                     │  │
│   │  └─────────────────────┘                                     │  │
│   └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Request Flow Diagram

```
  User enters URL
       │
       ▼
  ┌──────────┐     POST /scan      ┌─────────────┐
  │ Frontend │ ──────────────────► │   FastAPI    │
  │ (JS)     │     JSON body       │   main.py    │
  └──────────┘                     └──────┬──────┘
                                          │
                                          ▼
                                   ┌──────────────┐
                                   │ URL Validation│
                                   │ + SSRF Check  │
                                   └──────┬───────┘
                                          │
                           ┌──────────────┼──────────────┐
                           ▼              ▼              ▼
                    ┌────────────┐ ┌────────────┐ ┌────────────┐
                    │  Headers   │ │   Ports    │ │   SQLi     │  ... (x13)
                    │  Scanner   │ │  Scanner   │ │  Detector  │
                    └─────┬──────┘ └─────┬──────┘ └─────┬──────┘
                          │              │              │
                          └──────────────┼──────────────┘
                                         ▼
                                  ┌──────────────┐
                                  │ Risk Engine   │
                                  │ (Weighted     │
                                  │  Scoring)     │
                                  └──────┬───────┘
                                         ▼
                                  ┌──────────────┐
                                  │ Attack Report │
                                  │ Generator     │
                                  └──────┬───────┘
                                         ▼
                                  ┌──────────────┐
                                  │  JSON Result  │──────► Frontend renders
                                  └──────────────┘        results + PDF
```

---

## 📁 Project Structure

```
p1/
├── backend/
│   ├── main.py                        # FastAPI app, routes, orchestration
│   ├── requirements.txt               # Python dependencies
│   └── services/
│       ├── __init__.py                # Package marker
│       │
│       │── ── Core Scanners ─────────
│       ├── header_scanner.py          # Security headers check (14 headers)
│       ├── port_scanner.py            # TCP port scan (25 common ports)
│       ├── sqli_detector.py           # SQL injection testing (20+ payloads)
│       ├── xss_detector.py            # XSS detection (25+ payloads)
│       ├── directory_scanner.py       # Exposed directory enumeration (100+ paths)
│       │
│       │── ── Advanced Scanners ─────
│       ├── ssl_analyzer.py            # SSL/TLS certificate & protocol analysis
│       ├── cors_checker.py            # CORS misconfiguration detection
│       ├── tech_fingerprinter.py      # Technology stack fingerprinting
│       ├── cookie_analyzer.py         # Cookie security flag analysis
│       ├── http_methods_checker.py    # Dangerous HTTP method detection
│       ├── open_redirect_checker.py   # Open redirect vulnerability testing
│       ├── info_disclosure_checker.py # Information leakage detection
│       ├── clickjack_checker.py       # Clickjacking/UI redressing check
│       │
│       │── ── Engines ───────────────
│       ├── risk_engine.py             # Weighted risk score calculation
│       └── attack_reporter.py         # Attack surface report generation
│
└── frontend/
    ├── index.html                     # Main UI (hero, form, results grid)
    ├── styles.css                     # Full design system (dark theme)
    └── script.js                      # API integration, rendering, PDF export
```

---

## 🔍 Scanner Modules

### 1. 🛡️ Security Headers Scanner
**File:** `header_scanner.py` · **Function:** `scan_headers(url)`

Checks for **14 critical HTTP security headers** in the target's response:

| Header | Purpose |
|--------|---------|
| `Content-Security-Policy` | Prevents XSS and data injection attacks |
| `Strict-Transport-Security` | Forces HTTPS connections (HSTS) |
| `X-Frame-Options` | Prevents clickjacking via iframe embedding |
| `X-Content-Type-Options` | Prevents MIME type sniffing |
| `X-XSS-Protection` | Enables browser XSS filtering |
| `Referrer-Policy` | Controls referrer information leakage |
| `Permissions-Policy` | Restricts browser feature access (camera, mic, etc.) |
| `Cross-Origin-Opener-Policy` | Isolates browsing context |
| `Cross-Origin-Resource-Policy` | Controls cross-origin resource loading |
| `Cross-Origin-Embedder-Policy` | Enables cross-origin isolation |
| `X-Permitted-Cross-Domain-Policies` | Controls Flash/PDF cross-domain access |
| `X-Download-Options` | Prevents file open on download (IE) |
| `X-DNS-Prefetch-Control` | Controls DNS prefetching |
| `Cache-Control` | Manages caching of sensitive data |

**Returns:** `List[str]` — names of missing headers.

---

### 2. 🔌 Port Scanner
**File:** `port_scanner.py` · **Function:** `scan_ports(url)`

Scans **25 common TCP ports** using socket connections with a 1-second timeout per port:

| Port | Service | Port | Service |
|------|---------|------|---------|
| 20/21 | FTP | 445 | SMB |
| 22 | SSH | 993 | IMAPS |
| 23 | Telnet | 1433 | MSSQL |
| 25 | SMTP | 3306 | MySQL |
| 53 | DNS | 3389 | RDP |
| 80 | HTTP | 5432 | PostgreSQL |
| 110 | POP3 | 5900 | VNC |
| 135 | MSRPC | 6379 | Redis |
| 139 | NetBIOS | 8080 | HTTP Alt |
| 143 | IMAP | 8443 | HTTPS Alt |
| 443 | HTTPS | 27017 | MongoDB |

**Returns:** `List[int]` — list of open port numbers.

---

### 3. 💉 SQL Injection Detector
**File:** `sqli_detector.py` · **Function:** `detect_sqli(url)`

Tests the target with **20+ SQL injection payloads** across multiple techniques:

- **Authentication bypass:** `' OR '1'='1`, `admin' --`
- **Error-based:** Single quote, double quote, syntax errors
- **UNION-based:** `' UNION SELECT NULL --`
- **Time-based blind:** `'; WAITFOR DELAY '0:0:5' --`
- **Stacked queries:** `1; DROP TABLE users --`
- **Encoded payloads:** URL-encoded variants

**Detection methods:**
1. SQL error keyword matching (MySQL, PostgreSQL, Oracle, MSSQL, SQLite)
2. Response size anomaly detection (>50% change from baseline)
3. Status code change detection (200 → 500)

**Returns:** `bool` — `True` if a potential vulnerability is detected.

---

### 4. ⚡ XSS Detector
**File:** `xss_detector.py` · **Function:** `detect_xss(url)`

Injects **25+ XSS payloads** across **5 common parameter names** (`q`, `search`, `query`, `s`, `keyword`):

- **Script injection:** `<script>alert('XSS')</script>`
- **Event handlers:** `<img src=x onerror=alert('XSS')>`
- **SVG-based:** `<svg/onload=alert('XSS')>`
- **Attribute breakout:** `'"><script>alert('XSS')</script>`
- **JavaScript protocol:** `javascript:alert('XSS')`
- **Template injection:** `{{constructor.constructor('alert(1)')()}}`
- **Polyglot payloads:** Multi-context XSS strings

**Returns:** `bool` — `True` if payload is reflected unescaped in the response.

---

### 5. 📂 Directory Scanner
**File:** `directory_scanner.py` · **Function:** `scan_directories(url)`

Tests **100+ common sensitive paths** across categories:

| Category | Examples |
|----------|----------|
| Admin panels | `/admin`, `/wp-admin`, `/cpanel`, `/dashboard` |
| Sensitive files | `/.env`, `/.git`, `/.htpasswd`, `/web.config` |
| Config files | `/config.php`, `/wp-config.php`, `/phpinfo.php` |
| Backup files | `/backup.zip`, `/backup.sql`, `/db.sql` |
| CMS paths | `/wp-content`, `/xmlrpc.php`, `/phpmyadmin` |
| API endpoints | `/api`, `/graphql`, `/debug`, `/console` |
| Info disclosure | `/robots.txt`, `/sitemap.xml`, `/package.json` |
| Log files | `/error_log`, `/access.log`, `/logs` |

**Returns:** `List[str]` — exposed paths returning HTTP 200, 301, 302, or 403.

---

### 6. 🔒 SSL/TLS Analyzer
**File:** `ssl_analyzer.py` · **Function:** `analyze_ssl(url)`

Performs deep SSL/TLS inspection:

- **Certificate analysis:** Subject, issuer, serial number, validity period, SAN (Subject Alternative Names)
- **Expiry check:** Flags expired certs and certs expiring within 30 days
- **Protocol version:** Detects weak protocols (SSLv2, SSLv3, TLSv1, TLSv1.1)
- **Active probing:** Attempts connections with deprecated protocols to verify if they're supported
- **Non-HTTPS detection:** Flags sites not using HTTPS at all

**Returns:** `Dict` with `has_ssl`, `certificate` (details), and `issues` (list).

---

### 7. 🔄 CORS Checker
**File:** `cors_checker.py` · **Function:** `check_cors(url)`

Tests for Cross-Origin Resource Sharing misconfigurations:

| Test | What it catches |
|------|-----------------|
| Wildcard origin `*` | Any website can read responses |
| Origin reflection | Server reflects attacker's `Origin` header |
| Null origin accepted | Exploitable via sandboxed iframes |
| Wildcard + Credentials | **CRITICAL** — full cross-origin data theft |
| Reflected origin + Credentials | **CRITICAL** — authenticated data theft |
| Preflight method analysis | Checks if dangerous methods (PUT, DELETE) are allowed cross-origin |

**Returns:** `Dict` with `cors_enabled`, `details` (CORS headers), and `issues`.

---

### 8. 🔎 Technology Fingerprinter
**File:** `tech_fingerprinter.py` · **Function:** `fingerprint_tech(url)`

Identifies the target's technology stack using:

- **Server headers:** `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`
- **CMS detection (6 platforms):** WordPress, Joomla, Drupal, Shopify, Wix, Squarespace
- **Framework detection (14 frameworks):** React, Angular, Vue.js, jQuery, Next.js, Nuxt.js, Svelte, Express, Django, Flask, Laravel, Rails, ASP.NET, Spring
- **Language hints (6 languages):** PHP, Python, Java, Ruby, Node.js, ASP.NET
- **Meta tag analysis:** Generator meta tags with version disclosure

**Returns:** `Dict` with `server`, `powered_by`, `cms`, `frameworks`, `languages`, and `issues`.

---

### 9. 🍪 Cookie Security Analyzer
**File:** `cookie_analyzer.py` · **Function:** `analyze_cookies(url)`

Analyzes every cookie set by the target for security flags:

| Flag | Checked | Risk if Missing |
|------|---------|-----------------|
| `HttpOnly` | ✅ | XSS can steal cookies via `document.cookie` |
| `Secure` | ✅ | Cookies sent over unencrypted HTTP |
| `SameSite` | ✅ | Vulnerable to CSRF attacks |
| `Path` scope | ✅ | Overly broad cookie access |
| `Domain` scope | ✅ | Overly broad domain sharing |

**Session awareness:** Automatically detects session cookies (names containing `session`, `token`, `auth`, `csrf`, etc.) and applies stricter severity ratings.

**Returns:** `Dict` with `cookies` (list of cookie details) and `issues`.

---

### 10. 📡 HTTP Methods Checker
**File:** `http_methods_checker.py` · **Function:** `check_http_methods(url)`

Tests which HTTP methods are accepted by the server:

- **Phase 1:** Sends an `OPTIONS` request to read the `Allow` header
- **Phase 2:** Probes each method directly (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD, TRACE)

**Dangerous methods flagged:**

| Method | Risk |
|--------|------|
| `TRACE` | Cross-Site Tracing (XST) — credential theft via XSS |
| `PUT` | Upload malicious files or overwrite server content |
| `DELETE` | Delete files and resources on the server |
| `CONNECT` | Abuse as open proxy for traffic tunneling |
| `PATCH` | Partial modification of server resources |

**Returns:** `Dict` with `allowed_methods`, `dangerous_methods`, and `issues`.

---

### 11. ↗️ Open Redirect Checker
**File:** `open_redirect_checker.py` · **Function:** `check_open_redirects(url)`

Tests **25 common redirect parameter names** with **11 bypass payloads**:

**Parameters tested:** `url`, `redirect`, `next`, `return`, `returnUrl`, `redirect_uri`, `continue`, `dest`, `destination`, `goto`, `target`, `to`, `out`, `callback`, `checkout_url`, and more.

**Bypass payloads:** `https://evil.com`, `//evil.com`, `////evil.com`, `/\\evil.com`, URL-encoded variants.

**Detection:**
- Checks `Location` header for redirect to attacker-controlled domain
- Checks response body for meta refresh redirects

**Returns:** `Dict` with `vulnerable_params` (list of param/payload/redirect entries) and `issues`.

---

### 12. 📋 Information Disclosure Checker
**File:** `info_disclosure_checker.py` · **Function:** `check_info_disclosure(url)`

Comprehensive information leakage detection:

| Category | What it detects |
|----------|-----------------|
| **Header disclosures** | Server version, X-Powered-By, ASP.NET version, Debug tokens |
| **HTML comments** | Passwords, API keys, secrets, TODOs, IP addresses, file paths, DB references |
| **Stack traces** | Python, Java, PHP, .NET, Node.js error dumps |
| **Debug mode** | Django `DEBUG=True`, exposed config variables |
| **Source maps** | JavaScript `.map` files that reveal original source code |
| **Debug endpoints** | `/__debug__/`, `/elmah.axd`, `/_profiler/`, `/server-status` |
| **Email leaks** | Email addresses found in page source |

**Returns:** `Dict` with `disclosures` (detailed list) and `issues`.

---

### 13. 🖱️ Clickjacking Checker
**File:** `clickjack_checker.py` · **Function:** `check_clickjacking(url)`

Tests for clickjacking (UI redressing) protection:

1. **X-Frame-Options header:**
   - `DENY` or `SAMEORIGIN` → Protected ✅
   - `ALLOW-FROM` → Deprecated, not supported by modern browsers ⚠️
   - Missing → Vulnerable ❌

2. **CSP `frame-ancestors` directive:**
   - `'none'` or `'self'` → Protected ✅
   - Wildcard `*` → Not protected ❌
   - Missing → No protection ❌

**Returns:** `Dict` with `x_frame_options`, `csp_frame_ancestors`, `vulnerable` (bool), and `issues`.

---

## ⚙️ Risk Engine

**File:** `risk_engine.py` · **Function:** `calculate_risk(...)`

Calculates a weighted risk score (capped at 100) across all 13 scanner modules:

```
┌──────────────────────────────────┬─────────────┬──────────────────┐
│ Finding                          │ Weight      │ Scoring          │
├──────────────────────────────────┼─────────────┼──────────────────┤
│ SQL Injection detected           │ 25 pts      │ Binary (yes/no)  │
│ XSS detected                    │ 25 pts      │ Binary (yes/no)  │
│ CORS misconfiguration           │  8 pts/each │ Per issue        │
│ Open redirect                   │  6 pts/each │ Per vuln param   │
│ SSL/TLS issue                   │  5 pts/each │ Per issue        │
│ Exposed directory               │  5 pts/each │ Per path         │
│ Clickjacking vulnerable         │  5 pts      │ Binary (yes/no)  │
│ Dangerous HTTP method           │  4 pts/each │ Per method       │
│ Cookie security issue           │  3 pts/each │ Per issue        │
│ Open port                       │  3 pts/each │ Per port         │
│ Missing security header         │  2 pts/each │ Per header       │
│ Information disclosure           │  2 pts/each │ Per item         │
└──────────────────────────────────┴─────────────┴──────────────────┘

Risk Levels:
  0 – 25   →  🟢 Low
  26 – 50  →  🟡 Medium
  51 – 100 →  🔴 High
```

---

## ⚔️ Attack Report Engine

**File:** `attack_reporter.py` · **Function:** `generate_attack_report(scan_data)`

For every vulnerability found, the engine generates:

- **📌 Title & Category** — What the vulnerability is and its classification
- **🎯 Severity** — Critical / High / Medium / Low
- **🗡️ Attack Vector** — How an attacker would exploit it
- **💥 Impact** — What damage could be done
- **📝 Step-by-Step Exploitation** — Numbered exploitation instructions
- **🛡️ Remediation** — Specific fix with configuration examples

**Attack Chains:** When multiple vulnerabilities are detected, the engine identifies how they can be **chained together** for deeper exploitation:

```
Examples:
 • XSS + SQLi Combo → Steal admin session → Find SQLi → Dump entire database
 • XSS + No CSP → Inject keylogger → Capture all user passwords  
 • SQLi + DB Port Open → Exploit SQLi → Write web shell → Full server compromise
 • XSS + CORS Misconfig → Steal tokens via XSS → Read API data cross-origin
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.10+**
- **pip** (Python package manager)
- A modern web browser (Chrome, Firefox, Edge)

### Installation

```bash
# 1. Clone the repository
git clone <repository-url>
cd p1

# 2. Install Python dependencies
cd backend
pip install -r requirements.txt
```

### Dependencies

| Package  | Purpose |
|----------|---------|
| `fastapi` | Web framework for the REST API |
| `uvicorn` | ASGI server to run FastAPI |
| `requests` | HTTP client for scanner modules |
| `pydantic` | Data validation and serialization |

### Running the Application

#### Start the Backend Server

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`.

#### Open the Frontend

Simply open `frontend/index.html` in your browser. No build step or web server required — it's pure HTML/CSS/JS.

> **Note:** The frontend connects to `http://localhost:8000` by default. If your backend runs on a different port, update `API_URL` in `script.js`.

---

## 📡 API Reference

### `GET /`

Health check and scanner listing.

**Response:**
```json
{
  "message": "Vulnerability Scanner API v2.0 is running",
  "disclaimer": "This tool is for educational purposes only.",
  "scanners": ["Security Headers", "Port Scanner", "SQL Injection", ...]
}
```

### `POST /scan`

Runs all 13 scanner modules against the target URL.

**Request Body:**
```json
{
  "url": "https://example.com",
  "allow_local": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | `string` | ✅ | Target URL (must start with `http://` or `https://`) |
| `allow_local` | `bool` | ❌ | Set `true` to allow scanning private/localhost IPs |

**Response (ScanResult):**
```json
{
  "target": "https://example.com",
  "timestamp": "2026-03-25T16:35:07.123456+00:00",
  "open_ports": [80, 443],
  "missing_headers": ["Content-Security-Policy", "Permissions-Policy"],
  "sql_injection": false,
  "xss": false,
  "exposed_directories": ["/robots.txt", "/sitemap.xml"],
  "risk_score": 32,
  "risk_level": "Medium",
  "ssl_analysis": { "has_ssl": true, "certificate": {...}, "issues": [] },
  "cors_analysis": { "cors_enabled": false, "issues": [], "details": {} },
  "tech_fingerprint": { "server": "nginx/1.18.0", "cms": [], "frameworks": ["jQuery"], ... },
  "cookie_analysis": { "cookies": [...], "issues": [...] },
  "http_methods": { "allowed_methods": ["GET", "POST"], "dangerous_methods": [], "issues": [] },
  "open_redirects": { "vulnerable_params": [], "issues": [] },
  "info_disclosure": { "disclosures": [...], "issues": [...] },
  "clickjacking": { "vulnerable": true, "x_frame_options": null, "issues": [...] },
  "attack_report": {
    "vulnerabilities": [...],
    "attack_chains": [...],
    "summary": "MODERATE RISK: ...",
    "stats": { "critical": 0, "high": 2, "medium": 5, "low": 3, "total": 10 }
  }
}
```

**Error Responses:**

| Status | Reason |
|--------|--------|
| `400` | Invalid URL format or private IP without `allow_local` |
| `422` | Validation error (missing/malformed fields) |

---

## 🔐 Security Features

### SSRF Protection

The backend includes built-in **Server-Side Request Forgery (SSRF)** protection that blocks scanning of private/internal IP ranges:

```
10.0.0.0/8        (Class A private)
172.16.0.0/12     (Class B private)
192.168.0.0/16    (Class C private)
127.0.0.0/8       (Loopback)
169.254.0.0/16    (Link-local)
0.0.0.0/8         (Current network)
```

This can be bypassed **only** via the explicit `allow_local: true` opt-in flag.

### Input Validation

All inputs are validated using **Pydantic** models:
- URL must start with `http://` or `https://`
- URL must contain a valid hostname
- Leading/trailing whitespace is stripped

---

## 🖥️ Frontend Features

### UI Components
- **Hero section** with URL input form and scan button
- **Loading state** with animated progress pills for each scanner module
- **Risk score card** with animated progress bar and color-coded risk level
- **12-card results grid** showing each scanner's detailed findings
- **Attack Surface Report** with collapsible vulnerability categories
- **PDF download** button for generating professional reports

### Technology Stack
- **HTML5** — Semantic markup
- **Vanilla CSS** — Custom dark theme with glassmorphism, gradients, and animations
- **Vanilla JavaScript** — No framework dependency
- **Google Fonts** — Inter (UI text) + JetBrains Mono (code/technical text)
- **jsPDF** — Client-side PDF generation

---

## 📊 How a Scan Works (Step by Step)

```
1. User enters URL → Frontend validates format
2. Frontend sends POST /scan with URL and allow_local flag
3. Backend validates URL (Pydantic) and checks for private IP (SSRF protection)
4. Backend runs 13 scanner modules sequentially:
   ├── scan_headers(url)           → List of missing headers
   ├── scan_ports(url)             → List of open ports
   ├── detect_sqli(url)            → Boolean
   ├── detect_xss(url)             → Boolean
   ├── scan_directories(url)       → List of exposed paths
   ├── analyze_ssl(url)            → SSL certificate & protocol details
   ├── check_cors(url)             → CORS misconfiguration details
   ├── fingerprint_tech(url)       → Server/CMS/framework identification
   ├── analyze_cookies(url)        → Cookie security flag analysis
   ├── check_http_methods(url)     → Dangerous method detection
   ├── check_open_redirects(url)   → Redirect vulnerability testing
   ├── check_info_disclosure(url)  → Information leakage detection
   └── check_clickjacking(url)     → UI redressing protection check
5. Risk Engine calculates weighted score (0-100) → "Low" / "Medium" / "High"
6. Attack Reporter generates exploitation paths, attack chains, and remediations
7. Backend returns consolidated JSON response
8. Frontend renders results in card grid + attack report
9. User can download PDF report
```

---

## 🧑‍💻 Development

### API Documentation

FastAPI auto-generates interactive API docs:
- **Swagger UI:** `http://localhost:8000/docs`
- **ReDoc:** `http://localhost:8000/redoc`

### Adding a New Scanner Module

1. Create a new file in `backend/services/` (e.g., `my_scanner.py`)
2. Export a function that accepts `url: str` and returns a `dict`
3. Import and call it in `main.py` within the `run_scan()` function
4. Add the result field to the `ScanResult` Pydantic model
5. Pass relevant findings to `calculate_risk()` and `generate_attack_report()`
6. Add frontend rendering in `script.js` → `renderResults()`
7. Add a new card in `index.html`

---

## 📜 License

This project is for **educational purposes only**. Do not use it to scan unauthorized targets.

---

<p align="center">
  <strong>Built for learning. Scan responsibly. 🛡️</strong>
</p>
"# p1" 
