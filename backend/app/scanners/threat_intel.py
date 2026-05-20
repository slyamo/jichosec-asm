import requests
import json
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

SHODAN_API_KEY    = os.getenv("SHODAN_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY")


# ----------------------------------------
# Source 1 — AbuseIPDB
# Checks if IP has been reported for abuse
# ----------------------------------------

def check_abuseipdb(ip: str) -> dict:
    print(f"    [AbuseIPDB] Checking {ip}...")
    result = {
        "source":       "abuseipdb",
        "is_malicious": False,
        "data":         {}
    }
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key":    ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress":    ip,
                "maxAgeInDays": 90
            },
            timeout=10
        )
        if response.status_code == 200:
            data = response.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            result["data"] = {
                "abuse_score":      abuse_score,
                "total_reports":    data.get("totalReports", 0),
                "country":          data.get("countryCode", "Unknown"),
                "isp":              data.get("isp", "Unknown"),
                "usage_type":       data.get("usageType", "Unknown"),
                "last_reported":    data.get("lastReportedAt", None),
            }
            result["is_malicious"] = abuse_score > 25
            print(f"    [AbuseIPDB] Score: {abuse_score}/100 — {'⚠️ MALICIOUS' if result['is_malicious'] else '✓ Clean'}")
        else:
            print(f"    [AbuseIPDB] Error: {response.status_code}")
    except Exception as e:
        print(f"    [AbuseIPDB] Exception: {e}")
    return result


# ----------------------------------------
# Source 2 — VirusTotal
# Checks IP/domain against 70+ AV engines
# ----------------------------------------

def check_virustotal_ip(ip: str) -> dict:
    print(f"    [VirusTotal] Checking {ip}...")
    result = {
        "source":       "virustotal",
        "is_malicious": False,
        "data":         {}
    }
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10
        )
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless   = stats.get("harmless", 0)
            result["data"] = {
                "malicious":  malicious,
                "suspicious": suspicious,
                "harmless":   harmless,
                "total":      malicious + suspicious + harmless
            }
            result["is_malicious"] = malicious > 2
            print(f"    [VirusTotal] {malicious} engines flagged — {'⚠️ MALICIOUS' if result['is_malicious'] else '✓ Clean'}")
        else:
            print(f"    [VirusTotal] Error: {response.status_code}")
    except Exception as e:
        print(f"    [VirusTotal] Exception: {e}")
    return result


def check_virustotal_domain(domain: str) -> dict:
    print(f"    [VirusTotal] Checking domain {domain}...")
    result = {
        "source":       "virustotal_domain",
        "is_malicious": False,
        "data":         {}
    }
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10
        )
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless   = stats.get("harmless", 0)
            result["data"] = {
                "malicious":  malicious,
                "suspicious": suspicious,
                "harmless":   harmless,
            }
            result["is_malicious"] = malicious > 2
            print(f"    [VirusTotal] {malicious} engines flagged domain — {'⚠️ MALICIOUS' if result['is_malicious'] else '✓ Clean'}")
        else:
            print(f"    [VirusTotal] Error: {response.status_code}")
    except Exception as e:
        print(f"    [VirusTotal] Exception: {e}")
    return result


# ----------------------------------------
# Source 3 — Shodan
# Gets full internet exposure info for an IP
# ----------------------------------------

def check_shodan(ip: str) -> dict:
    print(f"    [Shodan] Checking {ip}...")
    result = {
        "source":       "shodan",
        "is_malicious": False,
        "data":         {}
    }
    try:
        response = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_API_KEY},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            result["data"] = {
                "ports":        ports,
                "vulns":        list(vulns),
                "org":          data.get("org", "Unknown"),
                "country":      data.get("country_name", "Unknown"),
                "os":           data.get("os", "Unknown"),
                "hostnames":    data.get("hostnames", []),
                "tags":         data.get("tags", []),
            }
            result["is_malicious"] = len(vulns) > 0
            print(f"    [Shodan] {len(ports)} ports, {len(vulns)} CVEs found — {'⚠️ VULNERABLE' if result['is_malicious'] else '✓ Clean'}")
        elif response.status_code == 404:
            print(f"    [Shodan] IP not in Shodan database")
        else:
            print(f"    [Shodan] Error: {response.status_code}")
    except Exception as e:
        print(f"    [Shodan] Exception: {e}")
    return result


# ----------------------------------------
# Main threat intel function
# Runs all three checks for an asset
# ----------------------------------------

def run_threat_intel(ip: str, subdomain: str) -> dict:
    print(f"\n[Threat Intel] Checking {subdomain} ({ip})")

    intel_results = []
    findings      = []

    # Run all three checks
    abuse_result = check_abuseipdb(ip)
    vt_ip_result = check_virustotal_ip(ip)
    vt_dm_result = check_virustotal_domain(subdomain)
    shodan_result = check_shodan(ip)

    intel_results = [abuse_result, vt_ip_result, vt_dm_result, shodan_result]

    # Generate findings from results
    if abuse_result["is_malicious"]:
        score = abuse_result["data"].get("abuse_score", 0)
        findings.append({
            "title":       f"IP {ip} has high abuse score",
            "description": f"AbuseIPDB confidence score: {score}/100",
            "risk":        "critical" if score > 75 else "high",
            "risk_score":  9.0 if score > 75 else 7.0,
            "source":      "abuseipdb",
            "evidence":    json.dumps(abuse_result["data"]),
            "remediation": "Investigate this IP immediately. Consider blocking it at the firewall."
        })

    if vt_ip_result["is_malicious"]:
        malicious = vt_ip_result["data"].get("malicious", 0)
        findings.append({
            "title":       f"IP {ip} flagged by {malicious} antivirus engines",
            "description": f"VirusTotal: {malicious} engines marked this IP as malicious",
            "risk":        "critical",
            "risk_score":  9.5,
            "source":      "virustotal",
            "evidence":    json.dumps(vt_ip_result["data"]),
            "remediation": "Block this IP immediately and investigate all traffic to/from it."
        })

    if vt_dm_result["is_malicious"]:
        malicious = vt_dm_result["data"].get("malicious", 0)
        findings.append({
            "title":       f"Domain {subdomain} flagged by {malicious} antivirus engines",
            "description": f"VirusTotal: {malicious} engines marked this domain as malicious",
            "risk":        "critical",
            "risk_score":  9.5,
            "source":      "virustotal",
            "evidence":    json.dumps(vt_dm_result["data"]),
            "remediation": "Take down or investigate this domain immediately."
        })

    if shodan_result["is_malicious"]:
        vulns = shodan_result["data"].get("vulns", [])
        findings.append({
            "title":       f"{len(vulns)} CVEs found on {ip}",
            "description": f"Shodan detected known vulnerabilities: {', '.join(vulns[:5])}",
            "risk":        "critical",
            "risk_score":  9.0,
            "source":      "shodan",
            "evidence":    json.dumps(shodan_result["data"]),
            "remediation": "Apply patches immediately for all listed CVEs."
        })

    print(f"    [+] Threat intel complete — {len(findings)} threat findings generated")

    return {
        "ip":           ip,
        "subdomain":    subdomain,
        "intel":        intel_results,
        "findings":     findings,
        "checked_at":   datetime.now().isoformat()
    }