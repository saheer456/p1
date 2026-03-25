/* ═══════════════════════════════════════════
   VulnScanner v2.0 — Client-Side JavaScript
   13 Scanner Modules + Attack Report
   ═══════════════════════════════════════════ */

const API_URL = "http://localhost:8000";

// ── DOM References ──
const scanForm = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const scanBtn = document.getElementById("scanBtn");
const btnText = scanBtn.querySelector(".btn-text");
const iconSearch = scanBtn.querySelector(".btn-icon-search");
const iconSpinner = scanBtn.querySelector(".btn-icon-spinner");
const errorBox = document.getElementById("errorBox");
const loadingSection = document.getElementById("loadingSection");
const resultsSection = document.getElementById("resultsSection");
const featuresSection = document.getElementById("featuresSection");
const downloadBtn = document.getElementById("downloadBtn");
const allowLocalCheckbox = document.getElementById("allowLocal");

let lastResult = null;

// ── Form Submit ──
scanForm.addEventListener("submit", handleScan);

async function handleScan(e) {
    e.preventDefault();
    const url = urlInput.value.trim();

    if (!url) {
        showError("Please enter a URL to scan.");
        return;
    }

    try {
        new URL(url);
    } catch {
        showError("Please enter a valid URL (e.g., https://example.com)");
        return;
    }

    hideError();
    setLoading(true);

    try {
        const response = await fetch(`${API_URL}/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                url,
                allow_local: allowLocalCheckbox.checked,
            }),
        });

        if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            throw new Error(data.detail || `Server error (${response.status})`);
        }

        const result = await response.json();
        lastResult = result;
        renderResults(result);
    } catch (err) {
        showError(err.message || "Failed to complete the scan. Please check the URL and try again.");
    } finally {
        setLoading(false);
    }
}

// ── UI Helpers ──
function setLoading(on) {
    urlInput.disabled = on;
    scanBtn.disabled = on;
    iconSearch.classList.toggle("hidden", on);
    iconSpinner.classList.toggle("hidden", !on);
    btnText.textContent = on ? "Scanning…" : "Start Scan";
    loadingSection.classList.toggle("hidden", !on);

    if (on) {
        resultsSection.classList.add("hidden");
        featuresSection.classList.add("hidden");
    }
}

function showError(msg) {
    errorBox.textContent = msg;
    errorBox.classList.remove("hidden");
}

function hideError() {
    errorBox.classList.add("hidden");
}

// ── Render Results ──
function renderResults(r) {
    featuresSection.classList.add("hidden");
    resultsSection.classList.remove("hidden");
    resultsSection.classList.add("fade-in");

    // Header
    document.getElementById("resultTarget").textContent = r.target;
    document.getElementById("resultTime").textContent = new Date(r.timestamp).toLocaleString();

    // Risk card
    const riskCard = document.getElementById("riskCard");
    riskCard.className = "risk-card risk-" + r.risk_level.toLowerCase();
    document.getElementById("riskScoreValue").textContent = r.risk_score;
    document.getElementById("riskLevelText").textContent = "Risk Level: " + r.risk_level;

    const descriptions = {
        Low: "The target has minimal security issues. Continue monitoring for changes.",
        Medium: "The target has moderate security concerns that should be addressed.",
        High: "The target has critical security issues that require immediate attention.",
    };
    document.getElementById("riskDescription").textContent = descriptions[r.risk_level] || "";

    setTimeout(() => {
        document.getElementById("riskBarFill").style.width = r.risk_score + "%";
    }, 100);

    // ── Original Scanners ──
    // Missing Headers
    document.getElementById("headersCount").textContent = r.missing_headers.length;
    const headersList = document.getElementById("headersList");
    if (r.missing_headers.length > 0) {
        headersList.innerHTML = '<div class="items-list">' +
            r.missing_headers.map(h =>
                `<div class="item-tag miss"><span class="tag-x">✕</span><span style="font-family:'JetBrains Mono',monospace;font-size:0.82rem">${escapeHTML(h)}</span></div>`
            ).join("") + "</div>";
    } else {
        headersList.innerHTML = '<p class="all-good">✓ All security headers are present.</p>';
    }

    // Open Ports
    document.getElementById("portsCount").textContent = r.open_ports.length;
    const portsList = document.getElementById("portsList");
    if (r.open_ports.length > 0) {
        portsList.innerHTML = '<div class="port-tags">' +
            r.open_ports.map(p => `<span class="port-tag">:${p}</span>`).join("") + "</div>";
    } else {
        portsList.innerHTML = '<p class="all-good">✓ No open ports detected on common ports.</p>';
    }

    // SQL Injection
    const sqli = document.getElementById("sqliResult");
    if (r.sql_injection) {
        sqli.innerHTML = '<div class="status-box danger"><span class="status-icon">⚠</span> Potential SQL injection vulnerability detected</div>';
    } else {
        sqli.innerHTML = '<div class="status-box safe"><span class="status-icon">✓</span> No SQL injection vulnerability detected</div>';
    }

    // XSS
    const xss = document.getElementById("xssResult");
    if (r.xss) {
        xss.innerHTML = '<div class="status-box danger"><span class="status-icon">⚠</span> Potential XSS vulnerability detected</div>';
    } else {
        xss.innerHTML = '<div class="status-box safe"><span class="status-icon">✓</span> No XSS vulnerability detected</div>';
    }

    // ── New Scanners ──

    // SSL/TLS
    const sslDiv = document.getElementById("sslResult");
    const ssl = r.ssl_analysis;
    let sslHTML = "";
    if (ssl.has_ssl && ssl.certificate) {
        const cert = ssl.certificate;
        sslHTML += `<div class="info-grid">`;
        if (cert.subject) sslHTML += `<div class="info-row"><span class="info-label">Subject:</span> ${escapeHTML(cert.subject)}</div>`;
        if (cert.issuer) sslHTML += `<div class="info-row"><span class="info-label">Issuer:</span> ${escapeHTML(cert.issuer)}</div>`;
        if (cert.protocol) sslHTML += `<div class="info-row"><span class="info-label">Protocol:</span> ${escapeHTML(cert.protocol)}</div>`;
        if (cert.days_until_expiry !== undefined) sslHTML += `<div class="info-row"><span class="info-label">Expiry:</span> ${cert.days_until_expiry} days</div>`;
        sslHTML += `</div>`;
    }
    if (ssl.issues && ssl.issues.length > 0) {
        sslHTML += renderIssuesList(ssl.issues);
    } else if (ssl.has_ssl) {
        sslHTML += '<p class="all-good">✓ SSL/TLS configuration looks good.</p>';
    } else {
        sslHTML += '<div class="status-box danger"><span class="status-icon">⚠</span> No HTTPS detected</div>';
    }
    sslDiv.innerHTML = sslHTML;

    // CORS
    const corsDiv = document.getElementById("corsResult");
    const cors = r.cors_analysis;
    if (cors.issues && cors.issues.length > 0) {
        corsDiv.innerHTML = renderIssuesList(cors.issues);
    } else if (cors.cors_enabled) {
        corsDiv.innerHTML = '<p class="all-good">✓ CORS is configured properly.</p>';
    } else {
        corsDiv.innerHTML = '<p class="all-good">✓ No CORS headers detected (not cross-origin accessible).</p>';
    }

    // Cookies
    const cookieDiv = document.getElementById("cookieResult");
    const cookies = r.cookie_analysis;
    if (cookies.issues && cookies.issues.length > 0) {
        cookieDiv.innerHTML = renderIssuesList(cookies.issues);
    } else if (cookies.cookies && cookies.cookies.length > 0) {
        cookieDiv.innerHTML = '<p class="all-good">✓ All cookies have proper security flags.</p>';
    } else {
        cookieDiv.innerHTML = '<p class="all-good">✓ No cookies set by the server.</p>';
    }

    // Clickjacking
    const clickDiv = document.getElementById("clickjackResult");
    const click = r.clickjacking;
    if (click.vulnerable) {
        clickDiv.innerHTML = '<div class="status-box danger"><span class="status-icon">⚠</span> Vulnerable to clickjacking</div>' +
            (click.issues ? renderIssuesList(click.issues) : "");
    } else {
        let protectionHTML = '<p class="all-good">✓ Protected against clickjacking.</p>';
        if (click.x_frame_options) protectionHTML += `<div class="info-row"><span class="info-label">X-Frame-Options:</span> ${escapeHTML(click.x_frame_options)}</div>`;
        clickDiv.innerHTML = protectionHTML;
    }

    // HTTP Methods
    const methodsDiv = document.getElementById("methodsResult");
    const methods = r.http_methods;
    if (methods.dangerous_methods && methods.dangerous_methods.length > 0) {
        methodsDiv.innerHTML = '<div class="port-tags">' +
            methods.dangerous_methods.map(m => `<span class="dir-tag">${escapeHTML(m)}</span>`).join("") +
            '</div>' + (methods.issues ? renderIssuesList(methods.issues) : "");
    } else {
        methodsDiv.innerHTML = '<p class="all-good">✓ No dangerous HTTP methods enabled.</p>';
    }

    // Open Redirects
    const redirectDiv = document.getElementById("redirectResult");
    const redirects = r.open_redirects;
    if (redirects.vulnerable_params && redirects.vulnerable_params.length > 0) {
        redirectDiv.innerHTML = '<div class="status-box danger"><span class="status-icon">⚠</span> Open redirect found</div>' +
            '<div class="port-tags">' +
            redirects.vulnerable_params.map(v => `<span class="dir-tag">${escapeHTML(v.param)}</span>`).join("") +
            '</div>';
    } else {
        redirectDiv.innerHTML = '<p class="all-good">✓ No open redirect vulnerabilities found.</p>';
    }

    // Tech Fingerprint
    const techDiv = document.getElementById("techResult");
    const tech = r.tech_fingerprint;
    let techHTML = '<div class="info-grid">';
    if (tech.server) techHTML += `<div class="info-row"><span class="info-label">Server:</span> ${escapeHTML(tech.server)}</div>`;
    if (tech.powered_by) techHTML += `<div class="info-row"><span class="info-label">Powered By:</span> ${escapeHTML(tech.powered_by)}</div>`;
    if (tech.cms && tech.cms.length > 0) techHTML += `<div class="info-row"><span class="info-label">CMS:</span> ${tech.cms.map(escapeHTML).join(", ")}</div>`;
    if (tech.frameworks && tech.frameworks.length > 0) techHTML += `<div class="info-row"><span class="info-label">Frameworks:</span> ${tech.frameworks.map(escapeHTML).join(", ")}</div>`;
    if (tech.languages && tech.languages.length > 0) techHTML += `<div class="info-row"><span class="info-label">Languages:</span> ${tech.languages.map(escapeHTML).join(", ")}</div>`;
    techHTML += '</div>';
    if (tech.issues && tech.issues.length > 0) techHTML += renderIssuesList(tech.issues);
    if (!tech.server && !tech.powered_by && (!tech.cms || tech.cms.length === 0)) {
        techHTML = '<p class="all-good">✓ No technology information leaked.</p>';
    }
    techDiv.innerHTML = techHTML;

    // Info Disclosure
    const infoDiv = document.getElementById("infoResult");
    const info = r.info_disclosure;
    if (info.issues && info.issues.length > 0) {
        infoDiv.innerHTML = renderIssuesList(info.issues);
    } else {
        infoDiv.innerHTML = '<p class="all-good">✓ No information disclosure detected.</p>';
    }

    // Exposed Directories
    document.getElementById("dirsCount").textContent = r.exposed_directories.length;
    const dirsList = document.getElementById("dirsList");
    if (r.exposed_directories.length > 0) {
        dirsList.innerHTML = '<div class="dir-tags">' +
            r.exposed_directories.map(d => `<span class="dir-tag">${escapeHTML(d)}</span>`).join("") + "</div>";
    } else {
        dirsList.innerHTML = '<p class="all-good">✓ No commonly exposed directories found.</p>';
    }

    // ── Attack Report ──
    renderAttackReport(r.attack_report);

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ── Attack Report Renderer ──
function renderAttackReport(report) {
    if (!report) return;

    // Summary
    const summaryDiv = document.getElementById("attackSummary");
    const summaryClass = report.stats.critical > 0 ? "critical" : (report.stats.high > 0 ? "high" : (report.stats.medium > 0 ? "medium" : "low"));
    summaryDiv.innerHTML = `<div class="attack-summary-box ${summaryClass}">${escapeHTML(report.summary)}</div>`;

    // Stats
    const statsDiv = document.getElementById("attackStats");
    statsDiv.innerHTML = `
        <div class="stat-pills">
            <span class="stat-pill critical">${report.stats.critical} Critical</span>
            <span class="stat-pill high">${report.stats.high} High</span>
            <span class="stat-pill medium">${report.stats.medium} Medium</span>
            <span class="stat-pill low">${report.stats.low} Low</span>
            <span class="stat-pill total">${report.stats.total} Total</span>
        </div>
    `;

    // Attack Chains
    const chainsDiv = document.getElementById("attackChains");
    if (report.attack_chains && report.attack_chains.length > 0) {
        chainsDiv.innerHTML = `
            <h3 class="subsection-title">⛓ Attack Chains</h3>
            <div class="chains-list">
                ${report.attack_chains.map(c => `<div class="chain-item">→ ${escapeHTML(c)}</div>`).join("")}
            </div>
        `;
    } else {
        chainsDiv.innerHTML = "";
    }

    // Vulnerabilities — grouped by category
    const vulnsDiv = document.getElementById("attackVulns");
    if (report.vulnerabilities && report.vulnerabilities.length > 0) {
        // Group by category
        const groups = {};
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        const categoryIcons = {
            "Missing Security Header": "🛡",
            "Injection": "💉",
            "Open Port": "🔌",
            "Information Disclosure": "📡",
            "Encryption": "🔒",
            "Access Control": "🚪",
            "Session Management": "🍪",
            "Security Misconfiguration": "⚙",
            "Redirect": "↗",
            "UI Redressing": "🖱",
            "Reconnaissance": "🔎",
        };

        for (const v of report.vulnerabilities) {
            const cat = v.category || "Other";
            if (!groups[cat]) groups[cat] = [];
            groups[cat].push(v);
        }

        // Sort categories by highest severity within
        const sortedCategories = Object.keys(groups).sort((a, b) => {
            const aMax = Math.min(...groups[a].map(v => severityOrder[v.severity.toLowerCase()] ?? 3));
            const bMax = Math.min(...groups[b].map(v => severityOrder[v.severity.toLowerCase()] ?? 3));
            return aMax - bMax;
        });

        let catHTML = '<h3 class="subsection-title">🔍 Vulnerability Details</h3>';
        for (const cat of sortedCategories) {
            const vulns = groups[cat];
            const icon = categoryIcons[cat] || "⚡";
            // Find highest severity in this group
            const highestSev = vulns.reduce((best, v) => {
                const o = severityOrder[v.severity.toLowerCase()] ?? 3;
                return o < severityOrder[best.toLowerCase()] ? v.severity : best;
            }, "Low");
            const sevClass = highestSev.toLowerCase();

            catHTML += `
                <div class="category-group">
                    <button class="category-header" onclick="this.parentElement.classList.toggle('open')">
                        <span class="category-left">
                            <span class="category-icon">${icon}</span>
                            <span class="category-name">${escapeHTML(cat)}</span>
                            <span class="category-count">${vulns.length}</span>
                        </span>
                        <span class="category-right">
                            <span class="severity-badge ${sevClass}">${escapeHTML(highestSev)}</span>
                            <span class="category-chevron">▸</span>
                        </span>
                    </button>
                    <div class="category-body">
                        ${vulns.map(v => renderVulnCard(v)).join("")}
                    </div>
                </div>
            `;
        }

        vulnsDiv.innerHTML = catHTML;
    } else {
        vulnsDiv.innerHTML = '<p class="all-good">✓ No exploitable vulnerabilities found.</p>';
    }
}

function renderVulnCard(v) {
    const severityClass = v.severity.toLowerCase();
    const exploitSteps = v.exploitation ? v.exploitation.map(s => `<li>${escapeHTML(s)}</li>`).join("") : "";

    return `
        <div class="vuln-card ${severityClass}">
            <div class="vuln-header" onclick="this.parentElement.classList.toggle('expanded')">
                <span class="severity-badge ${severityClass}">${escapeHTML(v.severity)}</span>
                <h4>${escapeHTML(v.title)}</h4>
                <span class="vuln-expand">▸</span>
            </div>
            <div class="vuln-body">
                <div class="vuln-section">
                    <strong>Attack Vector:</strong>
                    <p>${escapeHTML(v.attack_vector)}</p>
                </div>
                <div class="vuln-section">
                    <strong>Impact:</strong>
                    <p>${escapeHTML(v.impact)}</p>
                </div>
                ${exploitSteps ? `
                <div class="vuln-section">
                    <strong>Exploitation Steps:</strong>
                    <ol class="exploit-steps">${exploitSteps}</ol>
                </div>` : ""}
                <div class="vuln-section remediation">
                    <strong>🛡 Remediation:</strong>
                    <p>${escapeHTML(v.remediation)}</p>
                </div>
            </div>
        </div>
    `;
}

// ── Helper: render issues list ──
function renderIssuesList(issues) {
    return '<div class="issues-list">' +
        issues.map(i => `<div class="issue-item"><span class="issue-dot">!</span>${escapeHTML(i)}</div>`).join("") +
        '</div>';
}

function escapeHTML(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}

// ── PDF Download ──
downloadBtn.addEventListener("click", () => {
    if (!lastResult) return;
    generatePDF(lastResult);
});

function generatePDF(r) {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    const pw = doc.internal.pageSize.getWidth();
    let y = 20;

    function checkPage(needed = 20) {
        if (y + needed > 275) { doc.addPage(); y = 20; }
    }

    // Title
    doc.setFontSize(20);
    doc.setTextColor(59, 130, 246);
    doc.text("Vulnerability Scan Report", pw / 2, y, { align: "center" });
    y += 12;

    doc.setFontSize(9);
    doc.setTextColor(100, 116, 139);
    doc.text("Educational Security Assessment Tool — 13 Modules — For authorized testing only", pw / 2, y, { align: "center" });
    y += 14;

    doc.setDrawColor(30, 45, 74);
    doc.line(14, y, pw - 14, y);
    y += 10;

    function addSection(title, content) {
        checkPage(30);
        doc.setFontSize(12);
        doc.setTextColor(59, 130, 246);
        doc.text(title, 14, y);
        y += 7;
        doc.setFontSize(10);
        doc.setTextColor(80, 80, 80);
        const lines = doc.splitTextToSize(content, pw - 28);
        doc.text(lines, 14, y);
        y += lines.length * 5 + 8;
    }

    addSection("Target", r.target);
    addSection("Scan Time", new Date(r.timestamp).toLocaleString());
    addSection("Risk Score", r.risk_score + "/100  —  " + r.risk_level);

    // Original results
    addSection("Open Ports", r.open_ports.length > 0 ? r.open_ports.join(", ") : "None detected");
    addSection("Missing Security Headers", r.missing_headers.length > 0 ? r.missing_headers.join(", ") : "All headers present");
    addSection("SQL Injection", r.sql_injection ? "YES — Vulnerability detected" : "No vulnerability detected");
    addSection("XSS", r.xss ? "YES — Vulnerability detected" : "No vulnerability detected");
    addSection("Exposed Directories", r.exposed_directories.length > 0 ? r.exposed_directories.join(", ") : "None found");

    // New scanner results
    if (r.ssl_analysis && r.ssl_analysis.issues && r.ssl_analysis.issues.length > 0) {
        addSection("SSL/TLS Issues", r.ssl_analysis.issues.join("; "));
    } else {
        addSection("SSL/TLS", r.ssl_analysis.has_ssl ? "Properly configured" : "No HTTPS");
    }

    if (r.cors_analysis && r.cors_analysis.issues && r.cors_analysis.issues.length > 0) {
        addSection("CORS Issues", r.cors_analysis.issues.join("; "));
    } else {
        addSection("CORS", "No issues detected");
    }

    if (r.clickjacking) {
        addSection("Clickjacking", r.clickjacking.vulnerable ? "VULNERABLE" : "Protected");
    }

    if (r.http_methods && r.http_methods.dangerous_methods && r.http_methods.dangerous_methods.length > 0) {
        addSection("Dangerous HTTP Methods", r.http_methods.dangerous_methods.join(", "));
    }

    if (r.tech_fingerprint) {
        let techInfo = [];
        if (r.tech_fingerprint.server) techInfo.push("Server: " + r.tech_fingerprint.server);
        if (r.tech_fingerprint.powered_by) techInfo.push("Powered By: " + r.tech_fingerprint.powered_by);
        if (r.tech_fingerprint.cms && r.tech_fingerprint.cms.length > 0) techInfo.push("CMS: " + r.tech_fingerprint.cms.join(", "));
        if (r.tech_fingerprint.frameworks && r.tech_fingerprint.frameworks.length > 0) techInfo.push("Frameworks: " + r.tech_fingerprint.frameworks.join(", "));
        if (techInfo.length > 0) addSection("Technology Fingerprint", techInfo.join("; "));
    }

    // ── Attack Report in PDF ──
    if (r.attack_report) {
        checkPage(30);
        doc.setFontSize(16);
        doc.setTextColor(239, 68, 68);
        doc.text("ATTACK SURFACE REPORT", pw / 2, y, { align: "center" });
        y += 10;

        addSection("Overall Assessment", r.attack_report.summary);

        const stats = r.attack_report.stats;
        addSection("Vulnerability Stats",
            `Critical: ${stats.critical} | High: ${stats.high} | Medium: ${stats.medium} | Low: ${stats.low} | Total: ${stats.total}`
        );

        if (r.attack_report.attack_chains && r.attack_report.attack_chains.length > 0) {
            addSection("Attack Chains", r.attack_report.attack_chains.join("\n"));
        }

        // Vulnerability details
        for (const v of r.attack_report.vulnerabilities) {
            checkPage(40);
            doc.setFontSize(11);
            doc.setTextColor(239, 68, 68);
            doc.text(`[${v.severity}] ${v.title}`, 14, y);
            y += 6;

            doc.setFontSize(9);
            doc.setTextColor(80, 80, 80);

            const attackLines = doc.splitTextToSize(`Attack: ${v.attack_vector}`, pw - 28);
            doc.text(attackLines, 14, y); y += attackLines.length * 4 + 2;

            const impactLines = doc.splitTextToSize(`Impact: ${v.impact}`, pw - 28);
            checkPage(impactLines.length * 4 + 10);
            doc.text(impactLines, 14, y); y += impactLines.length * 4 + 2;

            if (v.exploitation) {
                for (const step of v.exploitation) {
                    checkPage(8);
                    const stepLines = doc.splitTextToSize(step, pw - 32);
                    doc.text(stepLines, 18, y); y += stepLines.length * 4 + 1;
                }
            }

            checkPage(10);
            doc.setTextColor(16, 185, 129);
            const remLines = doc.splitTextToSize(`Fix: ${v.remediation}`, pw - 28);
            doc.text(remLines, 14, y); y += remLines.length * 4 + 6;
            doc.setTextColor(80, 80, 80);
        }
    }

    // Footer
    checkPage(20);
    y += 5;
    doc.setDrawColor(30, 45, 74);
    doc.line(14, y, pw - 14, y);
    y += 8;
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text("Generated by VulnScanner v2.0 — Educational purposes only. Do not use without authorization.", 14, y);

    doc.save("vulnscan-" + r.target.replace(/[^a-zA-Z0-9]/g, "_") + ".pdf");
}
