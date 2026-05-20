import socket
import ssl
from datetime import datetime
import requests

def check_ssl(domain: str) -> dict:
    print(f"[SSL Scanner] Checking {domain}...")
    findings = []
    result = {
        "domain": domain,
        "has_ssl": False,
        "issuer": None,
        "expiry_date": None,
        "days_until_expiry": None,
        "is_expired": False,
        "is_self_signed": False,
        "protocol": None,
        "findings": []
    }

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain
        )
        conn.settimeout(10)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        result["has_ssl"] = True

        # Get expiry date
        expiry_str = cert.get("notAfter", "")
        if expiry_str:
            expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_date - datetime.utcnow()).days
            result["expiry_date"] = expiry_date.strftime("%d %B %Y")
            result["days_until_expiry"] = days_left
            result["is_expired"] = days_left < 0

            if days_left < 0:
                findings.append({
                    "title": "SSL certificate has expired",
                    "description": f"Certificate for {domain} expired {abs(days_left)} days ago",
                    "risk": "critical",
                    "risk_score": 9.0,
                    "source": "ssl_scanner",
                    "evidence": f"Expiry date: {result['expiry_date']}",
                    "remediation": "Renew the SSL certificate immediately"
                })
            elif days_left < 30:
                findings.append({
                    "title": "SSL certificate expiring soon",
                    "description": f"Certificate for {domain} expires in {days_left} days",
                    "risk": "high",
                    "risk_score": 7.0,
                    "source": "ssl_scanner",
                    "evidence": f"Expiry date: {result['expiry_date']}",
                    "remediation": "Renew the SSL certificate before it expires"
                })

        # Get issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        result["issuer"] = issuer.get("organizationName", "Unknown")

        # Check self-signed
        subject = dict(x[0] for x in cert.get("subject", []))
        if issuer == subject:
            result["is_self_signed"] = True
            findings.append({
                "title": "Self-signed SSL certificate detected",
                "description": f"{domain} uses a self-signed certificate not trusted by browsers",
                "risk": "high",
                "risk_score": 7.0,
                "source": "ssl_scanner",
                "evidence": f"Issuer matches subject: {result['issuer']}",
                "remediation": "Replace with a certificate from a trusted Certificate Authority"
            })

        # Check protocol version
        protocol = conn.version() if hasattr(conn, 'version') else "Unknown"
        result["protocol"] = protocol

        print(f"[SSL Scanner] {domain} - expires in {result['days_until_expiry']} days, issuer: {result['issuer']}")

    except ssl.SSLCertVerificationError:
        result["is_self_signed"] = True
        findings.append({
            "title": "SSL certificate verification failed",
            "description": f"Certificate for {domain} could not be verified",
            "risk": "high",
            "risk_score": 7.5,
            "source": "ssl_scanner",
            "evidence": "SSL verification error",
            "remediation": "Install a valid certificate from a trusted Certificate Authority"
        })
    except ssl.SSLError as e:
        findings.append({
            "title": "SSL error detected",
            "description": f"SSL error on {domain}: {str(e)}",
            "risk": "medium",
            "risk_score": 5.0,
            "source": "ssl_scanner",
            "evidence": str(e),
            "remediation": "Review SSL configuration on the server"
        })
    except ConnectionRefusedError:
        findings.append({
            "title": "No SSL on port 443",
            "description": f"{domain} does not have HTTPS enabled",
            "risk": "high",
            "risk_score": 7.0,
            "source": "ssl_scanner",
            "evidence": "Port 443 refused connection",
            "remediation": "Enable HTTPS and obtain a valid SSL certificate"
        })
    except Exception as e:
        print(f"[SSL Scanner] Error checking {domain}: {e}")

    result["findings"] = findings
    print(f"[SSL Scanner] {len(findings)} findings for {domain}")
    return result