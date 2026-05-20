import socket
import asyncio
import json
from datetime import datetime

# -------------------------------------------
# Ports to scan + what service runs on them
# -------------------------------------------

PORTS = {
    21:   {"service": "FTP",        "risk": "high",     "reason": "FTP transmits data in plaintext"},
    22:   {"service": "SSH",        "risk": "medium",   "reason": "SSH exposed - check for weak credentials"},
    23:   {"service": "Telnet",     "risk": "critical", "reason": "Telnet is unencrypted - replace with SSH"},
    25:   {"service": "SMTP",       "risk": "medium",   "reason": "Mail server exposed"},
    53:   {"service": "DNS",        "risk": "low",      "reason": "DNS port open - check for zone transfer"},
    80:   {"service": "HTTP",       "risk": "low",      "reason": "Unencrypted HTTP - should redirect to HTTPS"},
    110:  {"service": "POP3",       "risk": "medium",   "reason": "Email retrieval port exposed"},
    143:  {"service": "IMAP",       "risk": "medium",   "reason": "Email port exposed"},
    443:  {"service": "HTTPS",      "risk": "info",     "reason": "Standard HTTPS - verify certificate"},
    445:  {"service": "SMB",        "risk": "critical", "reason": "SMB exposed - high risk of ransomware"},
    1433: {"service": "MSSQL",      "risk": "critical", "reason": "Microsoft SQL Server exposed to internet"},
    1521: {"service": "Oracle DB",  "risk": "critical", "reason": "Oracle database exposed to internet"},
    3306: {"service": "MySQL",      "risk": "critical", "reason": "MySQL database exposed to internet"},
    3389: {"service": "RDP",        "risk": "critical", "reason": "Remote Desktop exposed - brute force risk"},
    4444: {"service": "Metasploit", "risk": "critical", "reason": "Known malware/backdoor port"},
    5432: {"service": "PostgreSQL", "risk": "critical", "reason": "PostgreSQL database exposed to internet"},
    5900: {"service": "VNC",        "risk": "critical", "reason": "VNC remote access exposed"},
    6379: {"service": "Redis",      "risk": "critical", "reason": "Redis exposed - no auth by default"},
    8080: {"service": "HTTP-Alt",   "risk": "medium",   "reason": "Alternative HTTP port - check for admin panels"},
    8443: {"service": "HTTPS-Alt",  "risk": "medium",   "reason": "Alternative HTTPS port"},
    9200: {"service": "Elasticsearch", "risk": "critical", "reason": "Elasticsearch exposed - data leak risk"},
    27017:{"service": "MongoDB",    "risk": "critical", "reason": "MongoDB exposed - no auth by default"},
}

# Risk score mapping
RISK_SCORES = {
    "critical": 9.0,
    "high":     7.0,
    "medium":   5.0,
    "low":      3.0,
    "info":     1.0
}


# -------------------------------------------
# Scan a single port on a host
# -------------------------------------------

async def scan_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        loop = asyncio.get_event_loop()
        # Run blocking socket call in thread pool
        result = await loop.run_in_executor(
            None,
            lambda: _check_port(ip, port, timeout)
        )
        return result
    except Exception:
        return False

def _check_port(ip: str, port: int, timeout: float) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0  # 0 means port is open
    except Exception:
        return False


# -------------------------------------------
# Grab banner from open port
# Identifies exact software version
# -------------------------------------------

def grab_banner(ip: str, port: int) -> str | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, port))
        # Send a basic HTTP request for web ports
        if port in [80, 8080, 8443]:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:200] if banner else None
    except Exception:
        return None


# -------------------------------------------
# Main port scan function
# -------------------------------------------

async def run_port_scan(ip: str, subdomain: str) -> dict:
    print(f"\n[Port Scanner] Scanning {subdomain} ({ip})...")

    open_ports = []
    findings = []

    # Scan all ports concurrently
    tasks = {port: scan_port(ip, port) for port in PORTS.keys()}
    results = await asyncio.gather(*tasks.values())

    for port, is_open in zip(tasks.keys(), results):
        if is_open:
            port_info = PORTS[port]
            service   = port_info["service"]
            risk      = port_info["risk"]
            reason    = port_info["reason"]

            print(f"    [OPEN] Port {port} ({service}) - {risk.upper()}")

            # Try to grab banner for extra info
            banner = grab_banner(ip, port)

            open_ports.append({
                "port":    port,
                "service": service,
                "banner":  banner
            })

            # Auto-generate a finding for risky ports
            if risk != "info":
                findings.append({
                    "title":       f"{service} exposed on port {port}",
                    "description": reason,
                    "risk":        risk,
                    "risk_score":  RISK_SCORES.get(risk, 1.0),
                    "source":      "port_scanner",
                    "evidence":    f"Port {port} open on {ip}. Banner: {banner or 'N/A'}",
                    "remediation": get_remediation(port, service)
                })

    print(f"    [+] {len(open_ports)} open ports found, {len(findings)} findings generated")

    return {
        "ip":         ip,
        "subdomain":  subdomain,
        "open_ports": open_ports,
        "findings":   findings,
        "scanned_at": datetime.now().isoformat()
    }


# -------------------------------------------
# Remediation advice per port
# -------------------------------------------

def get_remediation(port: int, service: str) -> str:
    remediations = {
        21:    "Disable FTP and use SFTP or SCP instead",
        22:    "Restrict SSH to specific IPs using firewall rules. Disable password auth, use keys only",
        23:    "Immediately disable Telnet and replace with SSH",
        25:    "Restrict SMTP relay. Enable authentication",
        53:    "Disable recursive DNS queries. Prevent zone transfers",
        80:    "Force redirect all HTTP traffic to HTTPS",
        443:   "Ensure SSL certificate is valid and not expiring soon",
        445:   "Block SMB from public internet immediately. Apply latest patches",
        1433:  "Move MSSQL behind a firewall. Never expose databases to the internet",
        1521:  "Move Oracle DB behind a firewall. Use VPN for access",
        3306:  "Move MySQL behind a firewall. Bind to localhost only",
        3389:  "Restrict RDP to VPN only. Enable Network Level Authentication",
        5432:  "Move PostgreSQL behind a firewall. Bind to localhost only",
        5900:  "Disable VNC or restrict to VPN only. Enable encryption",
        6379:  "Enable Redis authentication. Bind to localhost only",
        8080:  "Check if this is an admin panel. Restrict access if so",
        9200:  "Enable Elasticsearch security. Never expose to internet",
        27017: "Enable MongoDB authentication. Bind to localhost only",
    }
    return remediations.get(port, f"Review whether {service} needs to be publicly accessible")