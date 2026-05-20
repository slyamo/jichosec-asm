import dns.resolver
import dns.zone
import dns.query
import dns.exception
from datetime import datetime

def check_dns_security(domain: str) -> dict:
    print(f"[DNS Scanner] Checking {domain}...")
    findings = []
    result = {
        "domain": domain,
        "spf":     None,
        "dmarc":   None,
        "dnssec":  False,
        "mx":      [],
        "ns":      [],
        "findings": []
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    # Check SPF record
    try:
        answers = resolver.resolve(domain, 'TXT')
        spf_found = False
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith('v=spf1'):
                spf_found = True
                result["spf"] = txt
                print(f"[DNS Scanner] SPF found: {txt[:50]}")
                break
        if not spf_found:
            findings.append({
                "title": "Missing SPF record",
                "description": f"{domain} has no SPF record, allowing email spoofing",
                "risk": "high",
                "risk_score": 7.0,
                "source": "dns_scanner",
                "evidence": "No TXT record starting with v=spf1 found",
                "remediation": "Add an SPF TXT record to your DNS, e.g. v=spf1 include:_spf.google.com ~all"
            })
    except Exception:
        findings.append({
            "title": "Missing SPF record",
            "description": f"{domain} has no SPF record, allowing email spoofing",
            "risk": "high",
            "risk_score": 7.0,
            "source": "dns_scanner",
            "evidence": "TXT record lookup failed",
            "remediation": "Add an SPF TXT record to your DNS"
        })

    # Check DMARC record
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, 'TXT')
        dmarc_found = False
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith('v=DMARC1'):
                dmarc_found = True
                result["dmarc"] = txt
                print(f"[DNS Scanner] DMARC found: {txt[:50]}")
                if 'p=none' in txt:
                    findings.append({
                        "title": "DMARC policy set to none",
                        "description": f"{domain} has DMARC but policy is set to none, meaning no action is taken on failing emails",
                        "risk": "medium",
                        "risk_score": 5.0,
                        "source": "dns_scanner",
                        "evidence": txt,
                        "remediation": "Change DMARC policy from p=none to p=quarantine or p=reject"
                    })
                break
        if not dmarc_found:
            findings.append({
                "title": "Missing DMARC record",
                "description": f"{domain} has no DMARC record, making it vulnerable to email phishing",
                "risk": "high",
                "risk_score": 7.0,
                "source": "dns_scanner",
                "evidence": "No DMARC TXT record found at _dmarc." + domain,
                "remediation": "Add a DMARC record, e.g. v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain
            })
    except Exception:
        findings.append({
            "title": "Missing DMARC record",
            "description": f"{domain} has no DMARC record, making it vulnerable to email phishing",
            "risk": "high",
            "risk_score": 7.0,
            "source": "dns_scanner",
            "evidence": "DMARC lookup failed for _dmarc." + domain,
            "remediation": "Add a DMARC record to your DNS"
        })

    # Check MX records
    try:
        answers = resolver.resolve(domain, 'MX')
        result["mx"] = [str(r.exchange) for r in answers]
        print(f"[DNS Scanner] MX records: {result['mx']}")
    except Exception:
        findings.append({
            "title": "No MX records found",
            "description": f"{domain} has no mail exchange records configured",
            "risk": "low",
            "risk_score": 2.0,
            "source": "dns_scanner",
            "evidence": "MX record lookup returned no results",
            "remediation": "Configure MX records if email is needed for this domain"
        })

    # Check NS records
    try:
        answers = resolver.resolve(domain, 'NS')
        result["ns"] = [str(r) for r in answers]
        print(f"[DNS Scanner] NS records: {result['ns']}")
    except Exception:
        print(f"[DNS Scanner] Could not retrieve NS records for {domain}")

    # Check zone transfer vulnerability
    for ns in result["ns"][:2]:
        try:
            ns = ns.rstrip('.')
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            if zone:
                findings.append({
                    "title": "DNS zone transfer allowed",
                    "description": f"Nameserver {ns} allows zone transfers, exposing all DNS records",
                    "risk": "critical",
                    "risk_score": 9.0,
                    "source": "dns_scanner",
                    "evidence": f"Zone transfer succeeded from {ns}",
                    "remediation": "Disable zone transfers on all nameservers except authorized secondaries"
                })
        except Exception:
            pass

    result["findings"] = findings
    print(f"[DNS Scanner] {len(findings)} findings for {domain}")
    return result