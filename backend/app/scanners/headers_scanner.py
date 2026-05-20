import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "risk": "high",
        "risk_score": 7.0,
        "description": "Missing HSTS header allows downgrade attacks to HTTP",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "risk": "high",
        "risk_score": 7.0,
        "description": "Missing CSP header allows cross-site scripting attacks",
        "remediation": "Add a Content-Security-Policy header to restrict allowed content sources"
    },
    "X-Frame-Options": {
        "risk": "medium",
        "risk_score": 5.0,
        "description": "Missing X-Frame-Options allows clickjacking attacks",
        "remediation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "risk": "medium",
        "risk_score": 4.0,
        "description": "Missing X-Content-Type-Options allows MIME sniffing attacks",
        "remediation": "Add: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "risk": "low",
        "risk_score": 3.0,
        "description": "Missing Referrer-Policy may leak sensitive URL information",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "risk": "low",
        "risk_score": 2.0,
        "description": "Missing Permissions-Policy allows unrestricted browser feature access",
        "remediation": "Add a Permissions-Policy header to restrict camera, microphone, geolocation access"
    }
}

DANGEROUS_HEADERS = {
    "Server": {
        "risk": "low",
        "risk_score": 3.0,
        "description": "Server header reveals software version information to attackers",
        "remediation": "Configure your web server to hide or genericize the Server header"
    },
    "X-Powered-By": {
        "risk": "low",
        "risk_score": 3.0,
        "description": "X-Powered-By header reveals backend technology to attackers",
        "remediation": "Remove the X-Powered-By header from your server configuration"
    },
    "X-AspNet-Version": {
        "risk": "medium",
        "risk_score": 4.0,
        "description": "X-AspNet-Version reveals .NET version to attackers",
        "remediation": "Disable this header in your ASP.NET configuration"
    }
}

def check_headers(url: str) -> dict:
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    print(f"[Headers Scanner] Checking {domain}...")
    findings = []
    result = {
        "domain": domain,
        "headers_present": [],
        "headers_missing": [],
        "dangerous_headers": [],
        "findings": []
    }

    try:
        for scheme in ["https", "http"]:
            try:
                response = requests.get(
                    f"{scheme}://{domain}",
                    timeout=10,
                    verify=False,
                    allow_redirects=True
                )
                headers = {k.lower(): v for k, v in response.headers.items()}

                # Check for missing security headers
                for header, info in SECURITY_HEADERS.items():
                    if header.lower() in headers:
                        result["headers_present"].append(header)
                    else:
                        result["headers_missing"].append(header)
                        findings.append({
                            "title": f"Missing security header: {header}",
                            "description": info["description"],
                            "risk": info["risk"],
                            "risk_score": info["risk_score"],
                            "source": "headers_scanner",
                            "evidence": f"Header {header} not found in response from {scheme}://{domain}",
                            "remediation": info["remediation"]
                        })

                # Check for dangerous headers
                for header, info in DANGEROUS_HEADERS.items():
                    if header.lower() in headers:
                        result["dangerous_headers"].append({
                            "header": header,
                            "value": headers[header.lower()]
                        })
                        findings.append({
                            "title": f"Information disclosure via {header} header",
                            "description": info["description"],
                            "risk": info["risk"],
                            "risk_score": info["risk_score"],
                            "source": "headers_scanner",
                            "evidence": f"{header}: {headers[header.lower()]}",
                            "remediation": info["remediation"]
                        })
                break
            except requests.exceptions.SSLError:
                continue
            except requests.exceptions.ConnectionError:
                continue

    except Exception as e:
        print(f"[Headers Scanner] Error checking {domain}: {e}")

    result["findings"] = findings
    print(f"[Headers Scanner] {len(findings)} findings for {domain}")
    return result