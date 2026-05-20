import httpx
import asyncio
import socket
import requests
import json
import re
from datetime import datetime

def fetch_crtsh(domain: str) -> set:
    print(f"[crt.sh] Searching certificates for {domain}...")
    found = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower().replace("*.", "")
                    if domain in sub and " " not in sub:
                        found.add(sub)
    except Exception as e:
        print(f"[crt.sh] Error: {e}")
    print(f"[crt.sh] Found {len(found)} subdomains")
    return found

def fetch_hackertarget(domain: str) -> set:
    print(f"[HackerTarget] Searching for {domain}...")
    found = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=15)
        if response.status_code == 200 and "error" not in response.text.lower():
            for line in response.text.strip().split("\n"):
                if "," in line:
                    sub = line.split(",")[0].strip().lower()
                    if domain in sub:
                        found.add(sub)
    except Exception as e:
        print(f"[HackerTarget] Error: {e}")
    print(f"[HackerTarget] Found {len(found)} subdomains")
    return found

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "blog",
    "dev", "staging", "test", "api", "admin", "portal", "vpn",
    "remote", "secure", "login", "app", "shop", "store", "web",
    "cdn", "static", "assets", "media", "img", "images", "upload",
    "support", "help", "docs", "status", "dashboard", "panel",
    "webmail", "email", "backup", "old", "beta", "auth", "payment"
]

def fetch_wordlist(domain: str) -> set:
    print(f"[Wordlist] Brute-forcing common subdomains for {domain}...")
    found = set()
    for sub in COMMON_SUBDOMAINS:
        found.add(f"{sub}.{domain}")
    print(f"[Wordlist] Generated {len(found)} candidates")
    return found

def resolve_subdomain(subdomain: str):
    try:
        return socket.gethostbyname(subdomain)
    except socket.gaierror:
        return None

async def probe_subdomain(subdomain: str, client: httpx.AsyncClient) -> dict:
    result = {"subdomain": subdomain, "alive": False, "status_code": None, "title": None, "technologies": []}
    for scheme in ["https", "http"]:
        try:
            response = await client.get(f"{scheme}://{subdomain}", timeout=8, follow_redirects=True)
            result["alive"] = True
            result["status_code"] = response.status_code
            title_match = re.search(r"<title>(.*?)</title>", response.text, re.IGNORECASE)
            if title_match:
                result["title"] = title_match.group(1).strip()[:100]
            techs = []
            if response.headers.get("server"):
                techs.append(response.headers["server"])
            if response.headers.get("x-powered-by"):
                techs.append(response.headers["x-powered-by"])
            result["technologies"] = techs
            break
        except Exception:
            continue
    return result

async def run_subdomain_scan(domain: str) -> dict:
    print(f"\n{'='*50}")
    print(f"Scanning: {domain} at {datetime.now()}")
    print(f"{'='*50}\n")

    all_subdomains = set([domain])
    all_subdomains.update(fetch_crtsh(domain))
    all_subdomains.update(fetch_hackertarget(domain))
    all_subdomains.update(fetch_wordlist(domain))

    print(f"\n[+] Total unique subdomains to check: {len(all_subdomains)}\n")

    resolved = {}
    for sub in all_subdomains:
        ip = resolve_subdomain(sub)
        if ip:
            resolved[sub] = ip
            print(f"    ✓ {sub} → {ip}")

    print(f"\n[+] {len(resolved)} subdomains resolved\n")

    live_assets = []
    async with httpx.AsyncClient(verify=False) as client:
        results = await asyncio.gather(*[probe_subdomain(sub, client) for sub in resolved.keys()])
        for result in results:
            if result["alive"]:
                result["ip_address"] = resolved.get(result["subdomain"])
                live_assets.append(result)
                print(f"    ✓ {result['subdomain']} [{result['status_code']}]")

    print(f"\n[+] {len(live_assets)} live assets found\n")

    return {
        "domain": domain,
        "scanned_at": datetime.now().isoformat(),
        "total_subdomains_checked": len(all_subdomains),
        "total_resolved": len(resolved),
        "total_live": len(live_assets),
        "assets": live_assets
    }