from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import Scan, Asset, Finding, ThreatIntel, ScanStatus
from app.scanners.subdomain_scanner import run_subdomain_scan
from app.scanners.port_scanner import run_port_scan
from app.scanners.threat_intel import run_threat_intel
from app.scanners.ssl_scanner import check_ssl
from app.scanners.dns_scanner import check_dns_security
from app.scanners.headers_scanner import check_headers
from app.scanners.secret_scanner import search_github
from pydantic import BaseModel
from app.routes.auth_routes import get_current_user
from fastapi import APIRouter, Depends, HTTPException, Header
from typing import Optional
import json

router = APIRouter(prefix="/scans", tags=["Scans"])

class ScanRequest(BaseModel):
    domain: str

class ScanResponse(BaseModel):
    scan_id: str
    domain: str
    status: str
    message: str

@router.post("/", response_model=ScanResponse)
async def create_scan(request: ScanRequest, db: Session = Depends(get_db), authorization: Optional[str] = Header(None)):
    user_id = None
    if authorization and authorization.startswith("Bearer "):
        from app.services.auth_service import decode_token, get_user_by_email
        payload = decode_token(authorization.replace("Bearer ", ""))
        if payload:
            user = get_user_by_email(db, payload.get("sub"))
            if user:
                user_id = user.id

    domain = request.domain.strip().lower()
    domain = domain.replace("https://", "").replace("http://", "").replace("www.", "")

    scan = Scan(domain=domain, status=ScanStatus.running, user_id=user_id)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    total_findings = 0

    try:
        # Step 1 - Subdomain discovery
        results = await run_subdomain_scan(domain)

        for asset_data in results["assets"]:

            # Save asset
            asset = Asset(
                scan_id=scan.id,
                subdomain=asset_data["subdomain"],
                ip_address=asset_data.get("ip_address"),
                status_code=asset_data.get("status_code"),
                technologies=json.dumps(asset_data.get("technologies", [])),
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)

            if asset_data.get("ip_address"):
                ip = asset_data["ip_address"]
                subdomain = asset_data["subdomain"]

                # Step 2 - Port scanning
                port_results = await run_port_scan(ip, subdomain)
                asset.open_ports = json.dumps(port_results["open_ports"])
                db.commit()

                for f in port_results["findings"]:
                    db.add(Finding(
                        asset_id=asset.id,
                        title=f["title"],
                        description=f["description"],
                        risk=f["risk"],
                        risk_score=f["risk_score"],
                        source=f["source"],
                        evidence=f["evidence"],
                        remediation=f["remediation"]
                    ))
                    total_findings += 1

                # Step 3 - Threat intelligence
                intel_results = run_threat_intel(ip, subdomain)

                for intel in intel_results["intel"]:
                    db.add(ThreatIntel(
                        asset_id=asset.id,
                        source=intel["source"],
                        is_malicious=1 if intel["is_malicious"] else 0,
                        raw_data=json.dumps(intel["data"])
                    ))

                for f in intel_results["findings"]:
                    db.add(Finding(
                        asset_id=asset.id,
                        title=f["title"],
                        description=f["description"],
                        risk=f["risk"],
                        risk_score=f["risk_score"],
                        source=f["source"],
                        evidence=f["evidence"],
                        remediation=f["remediation"]
                    ))
                    total_findings += 1

                # Step 4 - SSL check
                ssl_results = check_ssl(subdomain)
                for f in ssl_results["findings"]:
                    db.add(Finding(
                        asset_id=asset.id,
                        title=f["title"],
                        description=f["description"],
                        risk=f["risk"],
                        risk_score=f["risk_score"],
                        source=f["source"],
                        evidence=f["evidence"],
                        remediation=f["remediation"]
                    ))
                    total_findings += 1

                # Step 5 - Headers check
                headers_results = check_headers(subdomain)
                for f in headers_results["findings"]:
                    db.add(Finding(
                        asset_id=asset.id,
                        title=f["title"],
                        description=f["description"],
                        risk=f["risk"],
                        risk_score=f["risk_score"],
                        source=f["source"],
                        evidence=f["evidence"],
                        remediation=f["remediation"]
                    ))
                    total_findings += 1

                db.commit()

        # Step 6 - DNS security check (once per domain)
        dns_results = check_dns_security(domain)
        first_asset = db.query(Asset).filter(Asset.scan_id == scan.id).first()
        if first_asset:
            for f in dns_results["findings"]:
                db.add(Finding(
                    asset_id=first_asset.id,
                    title=f["title"],
                    description=f["description"],
                    risk=f["risk"],
                    risk_score=f["risk_score"],
                    source=f["source"],
                    evidence=f["evidence"],
                    remediation=f["remediation"]
                ))
                total_findings += 1

        # Step 7 - Secret scanning (once per domain)
        secret_results = search_github(domain)
        if first_asset:
            for f in secret_results["findings"]:
                db.add(Finding(
                    asset_id=first_asset.id,
                    title=f["title"],
                    description=f["description"],
                    risk=f["risk"],
                    risk_score=f["risk_score"],
                    source=f["source"],
                    evidence=f["evidence"],
                    remediation=f["remediation"]
                ))
                total_findings += 1

        scan.status = ScanStatus.completed
        db.commit()

    except Exception as e:
        scan.status = ScanStatus.failed
        db.commit()
        raise HTTPException(status_code=500, detail=str(e))

    return ScanResponse(
        scan_id=scan.id,
        domain=domain,
        status="completed",
        message="Found {} assets and {} findings".format(results['total_live'], total_findings)
    )


@router.get("/")
def list_scans(db: Session = Depends(get_db), authorization: Optional[str] = Header(None)):
    user_id = None
    if authorization and authorization.startswith("Bearer "):
        from app.services.auth_service import decode_token, get_user_by_email
        payload = decode_token(authorization.replace("Bearer ", ""))
        if payload:
            user = get_user_by_email(db, payload.get("sub"))
            if user:
                user_id = user.id
    query = db.query(Scan).order_by(Scan.created_at.desc())
    if user_id:
        query = query.filter(Scan.user_id == user_id)
    return [
        {
            "scan_id":    s.id,
            "domain":     s.domain,
            "status":     s.status,
            "created_at": s.created_at
        }
        for s in query.all()
    ]


@router.get("/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()

    return {
        "scan_id":      scan.id,
        "domain":       scan.domain,
        "status":       scan.status,
        "created_at":   scan.created_at,
        "total_assets": len(assets),
        "assets": [
            {
                "subdomain":    a.subdomain,
                "ip_address":   a.ip_address,
                "status_code":  a.status_code,
                "open_ports":   json.loads(a.open_ports) if a.open_ports else [],
                "technologies": json.loads(a.technologies) if a.technologies else [],
                "threat_intel": [
                    {
                        "source":       t.source,
                        "is_malicious": bool(t.is_malicious),
                        "data":         json.loads(t.raw_data) if t.raw_data else {}
                    }
                    for t in a.threat_intel
                ],
                "findings": [
                    {
                        "title":       f.title,
                        "risk":        f.risk,
                        "risk_score":  f.risk_score,
                        "description": f.description,
                        "remediation": f.remediation,
                        "source":      f.source
                    }
                    for f in a.findings
                ]
            }
            for a in assets
        ]
    }