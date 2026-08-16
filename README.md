# JichoSec ASM

*An Automated Attack Surface Management Tool for Continuous Discovery and Risk Assessment of Organizational Web Assets*

JichoSec (from the Swahili word "Jicho" meaning eye) is a free, open source web-based security tool that automatically discovers everything an organization has exposed on the internet, scans each asset across seven security dimensions, and presents findings in a plain-language dashboard with actionable remediation guidance and a downloadable PDF report.

Built as a final year project at USIU-Africa, 2026.

---

## The Problem It Solves

Organizations routinely create subdomains, deploy APIs, and launch web services without maintaining an inventory of what they have exposed online. Attackers find these forgotten assets before security teams do. Commercial attack surface management tools can be expensive, placing them out of reach for most Kenyan organizations. JichoSec ASM provides the same capability for free.

---

## Features

- Subdomain discovery via certificate transparency logs, passive DNS, and wordlist enumeration
- Port scanning across 22 common TCP ports with service detection and banner grabbing
- SSL certificate inspection including expiry checking and self-signed detection
- HTTP security headers analysis covering 6 required headers and 3 dangerous disclosure headers
- DNS security checking for SPF records, DMARC records, and zone transfer vulnerability
- Threat intelligence via Shodan, VirusTotal, and AbuseIPDB APIs
- Public repository security analysis for exposed credentials on GitHub
- Risk scoring with Critical, High, Medium, and Low classifications and scores out of 10
- Security Health Score gauge showing overall posture as a single number out of 100
- Plain-language dashboard designed for non-technical users
- Automated PDF report generation using ReportLab
- User authentication with bcrypt password hashing and JWT tokens
- Data isolation ensuring each user only sees their own scans

---

## Tech Stack
Layer - Technology
- Frontend - React 18, Vite 8, Axios, Recharts
- Backend - Python 3.12, FastAPI, Uvicorn
- Database - SQLite via SQLAlchemy ORM
- Authentication - passlib bcrypt, python-jose JWT
- Scanning - httpx, dnspython, ssl, socket, requests
- Reporting - ReportLab
- External APIs - Shodan, VirusTotal, AbuseIPDB, GitHub, crt.sh, HackerTarget

---

## Prerequisites

- Python 3.10 or higher
- Node.js 18 or higher
- Git

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/slyamo/jichosec-asm.git
cd jichosec-asm
```

### 2. Set up the Python virtual environment

```bash
python -m venv venv
```

Activate it:

```bash
# Windows
venv\Scripts\activate

# Linux and macOS
source venv/bin/activate
```

### 3. Install backend dependencies

```bash
pip install -r backend/requirements.txt
```

### 4. Configure environment variables

Create a `.env` file inside the `backend` folder:

```env
APP_ENV=development
SECRET_KEY=your-secret-key-change-this
DATABASE_URL=sqlite:///./asm.db
SHODAN_API_KEY=your-shodan-key
VIRUSTOTAL_API_KEY=your-virustotal-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
```

Get free API keys from:
- Shodan: https://account.shodan.io
- VirusTotal: https://www.virustotal.com/gui/join-us
- AbuseIPDB: https://www.abuseipdb.com/register

### 5. Start the backend

```bash
cd backend
uvicorn app.main:app --reload --port 8080
```

The backend runs at `http://localhost:8080`
Interactive API docs available at `http://localhost:8080/docs`

### 6. Install frontend dependencies

Open a second terminal:

```bash
cd frontend
npm install
```

### 7. Start the frontend

```bash
npm run dev
```

The frontend runs at `http://localhost:5173`

---

## Usage

1. Open `http://localhost:5173` in your browser
2. Create an account on the login page
3. Click **New Scan** in the sidebar
4. Enter a domain name such as `example.com`
5. Press Enter and wait for the scan to complete
6. View results across the Home, Scans, Assets, and Security Issues pages
7. Click **Download PDF Report** on any completed scan

---

## API Endpoints

 Method - Endpoint - Description 

- POST - `/auth/register` - Register a new user account
- POST - `/auth/login` - Authenticate and receive JWT token
- GET - `/auth/me` - Get current logged in user details
- POST - `/scans/` - Initiate a new domain scan
- GET - `/scans/` - List all scans for the authenticated user
- GET - `/scans/{scan_id}` - Get full results for a specific scan
- GET - `/reports/{scan_id}/pdf` - Generate and download PDF report

All protected endpoints require a Bearer token in the Authorization header.

---

## How the Backend Retrieves Statistics

All statistics displayed on the dashboard are calculated dynamically from the database on every request. No values are hardcoded.

When the frontend calls `GET /scans/` the backend queries the SQLite database filtering by the authenticated user's ID extracted from the JWT token:

```python
query = db.query(Scan).order_by(Scan.created_at.desc())
if user_id:
    query = query.filter(Scan.user_id == user_id)
```

When the frontend calls `GET /scans/{scan_id}` the backend retrieves all assets, findings, and threat intelligence records associated with that scan:

```python
assets   = db.query(Asset).filter(Asset.scan_id == scan_id).all()
findings = db.query(Finding).filter(Finding.asset_id == asset.id).all()
intel    = db.query(ThreatIntel).filter(ThreatIntel.asset_id == asset.id).all()
```

The Security Health Score on the dashboard is calculated in the frontend from the returned findings data:

```javascript
const healthScore = total === 0 ? 100 : Math.max(0,
  Math.round(100 - (critical * 15 + high * 7 + medium * 3 + low * 1))
)
```

You can verify all API responses live at `http://localhost:8080/docs`.

---

## Database

JichoSec ASM uses SQLite with five tables:
- users - id, email, name, password, created_at
- scans - id, user_id, domain, status, created_at, updated_at
- assets - id, scan_id, subdomain, ip_address, open_ports, technologies, status_code, created_at
- findings - id, asset_id, title, description, risk, risk_score, source, evidence, remediation, created_at
- threat_intel - id, asset_id, source, is_malicious, raw_data, checked_at

The database file `asm.db` is created automatically in the `backend` folder when the server starts for the first time.

---

## Safe Test Domains

These domains are specifically designated for security tool testing:

 Domain - Maintained By
- scanme.nmap.org - Nmap Project
- testphp.vulnweb.com - Acunetix
- testasp.vulnweb.com - Acunetix

---

## Legal Disclaimer

JichoSec ASM is intended for use on systems you own or have explicit written permission to test. Unauthorized scanning of systems you do not own is illegal under the Computer Misuse and Cybercrimes Act of Kenya (2018) and equivalent legislation in other jurisdictions. The developers are not responsible for any misuse of this tool.

---

## SDG Alignment

This project contributes to:
- **SDG 9** (Industry, Innovation and Infrastructure) by strengthening digital infrastructure security for organizations that cannot afford commercial solutions
- **SDG 16** (Peace, Justice and Strong Institutions) by promoting more secure digital governance

---

## Author

Sylvia

Developed as a final year project at USIU Africa, 2026.

GitHub: https://github.com/slyamo/jichosec-asm

---

