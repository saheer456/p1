"""
Port Scanner Module
Scans common ports on the target host using socket connections.
"""

import socket
from typing import List, Dict
from urllib.parse import urlparse

# Port → Service mapping for better reporting
COMMON_PORTS: Dict[int, str] = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alt",
    8443: "HTTPS Alt",
    8888: "HTTP Proxy",
    27017: "MongoDB",
}


def scan_ports(url: str) -> List[int]:
    """
    Scan common ports on the target host.
    Returns a list of open port numbers.
    """
    open_ports: List[int] = []

    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return open_ports

        for port in COMMON_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((hostname, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except (socket.timeout, socket.error, OSError):
                continue

    except Exception:
        pass

    return open_ports
