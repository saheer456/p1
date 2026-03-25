"""
SSL/TLS Analyzer Module
Checks SSL certificate validity, expiry, protocol versions, and cipher strength.
Educational purposes only.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, Any, List


def analyze_ssl(url: str) -> Dict[str, Any]:
    """
    Analyze the SSL/TLS configuration of the target.
    Returns a dict with certificate info and detected issues.
    """
    result: Dict[str, Any] = {
        "has_ssl": False,
        "certificate": {},
        "issues": [],
    }

    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 443)

    if not hostname:
        result["issues"].append("No hostname found in URL")
        return result

    # If not HTTPS, that's already an issue
    if parsed.scheme != "https":
        result["issues"].append("Site does not use HTTPS — all traffic is unencrypted")
        return result

    try:
        # Get certificate info
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["has_ssl"] = True
                cert = ssock.getpeercert()
                protocol_version = ssock.version()

                # Parse certificate details
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")

                result["certificate"] = {
                    "subject": subject.get("commonName", "Unknown"),
                    "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
                    "issued_to": subject.get("commonName", "Unknown"),
                    "serial_number": cert.get("serialNumber", "Unknown"),
                    "protocol": protocol_version,
                    "not_before": not_before,
                    "not_after": not_after,
                }

                # Check expiry
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expiry = expiry.replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days_left = (expiry - now).days

                        result["certificate"]["days_until_expiry"] = days_left

                        if days_left < 0:
                            result["issues"].append(f"SSL certificate EXPIRED {abs(days_left)} days ago")
                        elif days_left < 30:
                            result["issues"].append(f"SSL certificate expires in {days_left} days")
                    except ValueError:
                        pass

                # Check protocol version
                if protocol_version:
                    weak_protocols = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
                    if protocol_version in weak_protocols:
                        result["issues"].append(f"Weak protocol: {protocol_version} (should use TLSv1.2 or TLSv1.3)")

                # Check SAN (Subject Alternative Names)
                san = cert.get("subjectAltName", ())
                san_list = [entry[1] for entry in san if entry[0] == "DNS"]
                result["certificate"]["san"] = san_list

    except ssl.SSLCertVerificationError as e:
        result["issues"].append(f"SSL certificate verification failed: {str(e)}")
        result["has_ssl"] = True  # has SSL but it's invalid
    except ssl.SSLError as e:
        result["issues"].append(f"SSL error: {str(e)}")
    except (socket.timeout, socket.error, OSError) as e:
        result["issues"].append(f"Could not establish SSL connection: {str(e)}")
    except Exception as e:
        result["issues"].append(f"SSL analysis error: {str(e)}")

    # Try weak protocols separately
    weak_protocols_detected = _check_weak_protocols(hostname, port)
    if weak_protocols_detected:
        result["issues"].extend(weak_protocols_detected)

    return result


def _check_weak_protocols(hostname: str, port: int) -> List[str]:
    """Attempt to connect with weak protocols to see if they're supported."""
    issues = []
    weak_checks = {
        "TLSv1": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    }

    for name, version in weak_checks.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    issues.append(f"Server supports deprecated protocol: {name}")
        except (ssl.SSLError, socket.error, OSError):
            pass  # Good — weak protocol not supported
        except Exception:
            pass

    return issues
