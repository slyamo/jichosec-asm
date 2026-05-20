import requests
import re
import json

SECRET_PATTERNS = {
    "AWS Access Key":       r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key":       r'[0-9a-zA-Z/+]{40}',
    "GitHub Token":         r'ghp_[0-9a-zA-Z]{36}',
    "Google API Key":       r'AIza[0-9A-Za-z\-_]{35}',
    "Slack Token":          r'xox[baprs]-[0-9a-zA-Z]{10,48}',
    "Private Key":          r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
    "Generic API Key":      r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\']?[0-9a-zA-Z\-_]{16,}',
    "Generic Secret":       r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\']?[0-9a-zA-Z\-_!@#$%]{8,}',
    "Database URL":         r'(mongodb|mysql|postgresql|redis)://[^\s"\']+',
    "JWT Token":            r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
}

def search_github(domain: str) -> dict:
    print(f"[Secret Scanner] Searching GitHub for secrets related to {domain}...")
    findings = []
    result = {
        "domain": domain,
        "repos_checked": 0,
        "secrets_found": 0,
        "findings": []
    }

    org_name = domain.split('.')[0]

    try:
        search_url = f"https://api.github.com/search/repositories?q={org_name}&per_page=5"
        headers = {"Accept": "application/vnd.github.v3+json"}
        response = requests.get(search_url, headers=headers, timeout=10)

        if response.status_code == 200:
            repos = response.json().get("items", [])
            result["repos_checked"] = len(repos)

            for repo in repos[:3]:
                repo_name = repo["full_name"]
                print(f"[Secret Scanner] Checking repo: {repo_name}")

                contents_url = f"https://api.github.com/repos/{repo_name}/contents"
                contents_response = requests.get(contents_url, headers=headers, timeout=10)

                if contents_response.status_code == 200:
                    files = contents_response.json()
                    for file in files:
                        if isinstance(file, dict) and file.get("type") == "file":
                            name = file.get("name", "")
                            if any(name.endswith(ext) for ext in ['.env', '.config', '.json', '.yaml', '.yml', '.txt']):
                                file_response = requests.get(file.get("download_url", ""), timeout=10)
                                if file_response.status_code == 200:
                                    content = file_response.text
                                    for secret_type, pattern in SECRET_PATTERNS.items():
                                        matches = re.findall(pattern, content)
                                        if matches:
                                            result["secrets_found"] += 1
                                            findings.append({
                                                "title": f"Potential {secret_type} exposed in GitHub",
                                                "description": f"Found potential {secret_type} in {repo_name}/{name}",
                                                "risk": "critical",
                                                "risk_score": 9.5,
                                                "source": "secret_scanner",
                                                "evidence": f"Pattern matched in {repo_name}/{name}",
                                                "remediation": f"Remove the {secret_type} from the repository immediately, rotate the credentials, and use environment variables instead"
                                            })

        print(f"[Secret Scanner] Checked {result['repos_checked']} repos, found {result['secrets_found']} potential secrets")

    except Exception as e:
        print(f"[Secret Scanner] Error: {e}")

    result["findings"] = findings
    return result