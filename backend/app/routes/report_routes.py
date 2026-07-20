from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import Scan, Asset, Finding, ThreatIntel
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from datetime import datetime
from io import BytesIO
from reportlab.platypus import Image
import json

import os
print("Running from:", os.getcwd())
print("Reports.py is at:", os.path.abspath(__file__))

router = APIRouter(prefix="/reports", tags=["Reports"])

NAVY  = colors.HexColor('#1B2B3A')
GOLD  = colors.HexColor('#00FFFF')
RED   = colors.HexColor("#FD2525")
ORANGE = colors.HexColor("#FA832D")
BLUE  = colors.HexColor("#47D1F8")
GREEN = colors.HexColor('#39FF14')
GRAY  = colors.HexColor('#8899aa')
LIGHT = colors.HexColor('#E2EAF0')
WHITE = colors.white

def risk_color(risk):
    return {
        'critical': RED,
        'high':     ORANGE,
        'medium':   BLUE,
        'low':      GREEN
    }.get(risk, GRAY)

@router.get("/{scan_id}/pdf")
def generate_pdf_report(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()

    all_findings = []
    threat_intel_summary = []
    total_findings = 0
    critical_count = 0
    max_score = 0.0
    assets_data = []

    for asset in assets:
        findings = db.query(Finding).filter(Finding.asset_id == asset.id).all()
        intel    = db.query(ThreatIntel).filter(ThreatIntel.asset_id == asset.id).all()

        findings_data = []
        for f in findings:
            total_findings += 1
            if f.risk == 'critical':
                critical_count += 1
            if f.risk_score > max_score:
                max_score = f.risk_score
            entry = {
                "title":       f.title,
                "description": f.description,
                "risk":        f.risk,
                "risk_score":  f.risk_score,
                "source":      f.source or 'scanner',
                "remediation": f.remediation,
                "subdomain":   asset.subdomain
            }
            findings_data.append(entry)
            all_findings.append(entry)

        for t in intel:
            raw = json.loads(t.raw_data) if t.raw_data else {}
            if t.source == "abuseipdb":
                detail = "Abuse score: {}/100".format(raw.get('abuse_score', 0))
            elif t.source == "virustotal":
                detail = "Malicious engines: {}".format(raw.get('malicious', 0))
            elif t.source == "shodan":
                detail = "Ports: {}, CVEs: {}".format(len(raw.get('ports', [])), len(raw.get('vulns', [])))
            else:
                detail = "No data"
            threat_intel_summary.append({
                "source":       t.source.upper(),
                "is_malicious": bool(t.is_malicious),
                "detail":       detail
            })

        ports = json.loads(asset.open_ports) if asset.open_ports else []
        techs = json.loads(asset.technologies) if asset.technologies else []
        assets_data.append({
            "subdomain": asset.subdomain,
            "ip":        asset.ip_address or 'N/A',
            "ports":     ', '.join([':{} {}'.format(p['port'], p['service']) for p in ports]) or 'None',
            "findings":  findings_data,
            "tech":      ', '.join(techs) or 'Unknown'
        })

    all_findings.sort(key=lambda x: x["risk_score"], reverse=True)
    risk_score = round(min(max_score, 10.0), 1)

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=15*mm,
        bottomMargin=20*mm
    )

    styles = getSampleStyleSheet()
    story  = []

    h1_style   = ParagraphStyle('h1',   fontSize=13, textColor=NAVY,  fontName='Helvetica-Bold', letterSpacing=2, spaceBefore=16, spaceAfter=8)
    body_style = ParagraphStyle('body', fontSize=10, textColor=colors.HexColor('#444444'), fontName='Helvetica', spaceAfter=4, leading=16)
    small_style= ParagraphStyle('small',fontSize=9,  textColor=GRAY,  fontName='Helvetica', spaceAfter=2)

    logo = Image('j.png', width=21*mm, height=21*mm)
    brand = Paragraph(
    '<font color="#00FFFF">Jicho</font><font color="#FFFFFF">Sec</font>',
    ParagraphStyle(
        'brand',
        fontSize=28,
        fontName='Helvetica',
        leading=20
    )
)

    cover_data = [
        [logo], [brand]
        
    ]
    cover_table = Table(cover_data, colWidths=[170*mm],rowHeights=[25*mm, 13*mm])
    cover_table.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), NAVY),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING',    (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('LEFTPADDING',   (0,0), (-1,-1), 8),
    ]))
    story.append(cover_table)

    info_data = [
        [Paragraph('Security Assessment Report',
                   ParagraphStyle('rt', fontSize=14, textColor=WHITE, fontName='Helvetica'))],
        [Paragraph('Domain: <font color="#39FF14"><b>{}</b></font> '.format(scan.domain),
                   ParagraphStyle('dom', fontSize=9, textColor=GRAY, fontName='Helvetica'))],
        [Paragraph('Scan ID: {}'.format(scan.id),
                   ParagraphStyle('meta', fontSize=9, textColor=GRAY, fontName='Helvetica'))],
        [Paragraph('Generated: {}'.format(datetime.now().strftime("%d %B %Y %H:%M UTC")),
                   ParagraphStyle('meta2', fontSize=9, textColor=GRAY, fontName='Helvetica'))],
    ]
    info_table = Table(info_data, colWidths=[170*mm])
    info_table.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), NAVY),
        ('LEFTPADDING',   (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('TOPPADDING',    (0,0), (-1,-1), 15),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 16))

    story.append(Paragraph('EXECUTIVE SUMMARY', h1_style))
    story.append(HRFlowable(width="100%", thickness=2, color=NAVY))
    story.append(Spacer(1, 8))

    summary_data = [
        ['ASSETS FOUND', 'TOTAL FINDINGS', 'CRITICAL', 'RISK SCORE'],
        [str(len(assets)), str(total_findings), str(critical_count), '{}/10'.format(risk_score)]
    ]
    summary_table = Table(summary_data, colWidths=[42*mm, 42*mm, 42*mm, 42*mm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND',   (0,0), (-1,0), NAVY),
        ('TEXTCOLOR',    (0,0), (-1,0), GOLD),
        ('FONTNAME',     (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',     (0,0), (-1,0), 8),
        ('FONTNAME',     (0,1), (-1,1), 'Helvetica-Bold'),
        ('FONTSIZE',     (0,1), (-1,1), 20),
        ('TEXTCOLOR',    (0,1), (0,1),  NAVY),
        ('TEXTCOLOR',    (1,1), (1,1),  RED),
        ('TEXTCOLOR',    (2,1), (2,1),  RED),
        ('TEXTCOLOR',    (3,1), (3,1),  colors.HexColor("#413E35")),
        ('ALIGN',        (0,0), (-1,-1), 'CENTER'),
        ('VALIGN',       (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING',   (0,0), (-1,-1), 10),
        ('BOTTOMPADDING',(0,0), (-1,-1), 19),
        ('BOX',         (0,0), (-1,-1), 0.5, colors.HexColor('#000000')),
        ('BACKGROUND',   (0,1), (-1,1), WHITE),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph(
        'This report presents findings of an automated attack surface assessment '
        'conducted by JichoSec ASM against <b>{}</b>. '
        'The assessment identified <b>{} assets</b> and <b>{} security findings</b>, '
        'of which <b>{} are critical severity</b> and require immediate attention.'.format(
            scan.domain, len(assets), total_findings, critical_count),
        body_style
    ))
    story.append(Spacer(1, 16))

    story.append(Paragraph('DISCOVERED ASSETS ({})'.format(len(assets)), h1_style))
    story.append(HRFlowable(width="100%", thickness=2, color=NAVY))
    story.append(Spacer(1, 8))

    asset_table_data = [['SUBDOMAIN', 'IP ADDRESS', 'OPEN PORTS', 'TECHNOLOGIES']]
    for a in assets_data:
        asset_table_data.append([
            Paragraph(a['subdomain'], ParagraphStyle('atn', fontSize=9, fontName='Helvetica-Bold', textColor=NAVY)),
            Paragraph(a['ip'],        ParagraphStyle('ati', fontSize=9, fontName='Courier',         textColor=GRAY)),
            Paragraph(a['ports'],     ParagraphStyle('atp', fontSize=8, fontName='Helvetica',       textColor=colors.HexColor('#444444'))),
            Paragraph(a['tech'],      ParagraphStyle('att', fontSize=8, fontName='Helvetica',       textColor=GRAY)),
        ])

    at = Table(asset_table_data, colWidths=[55*mm, 35*mm, 50*mm, 30*mm])
    at.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0), NAVY),
        ('TEXTCOLOR',     (0,0), (-1,0), GOLD),
        ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,0), 8),
        ('ALIGN',         (0,0), (-1,0), 'LEFT'),
        ('TOPPADDING',    (0,0), (-1,-1), 7),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('LEFTPADDING',   (0,0), (-1,-1), 6),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [WHITE, WHITE]),
        ('GRID',          (0,0), (-1,-1), 0.5, colors.HexColor('#000000')),
        ('LINEAFTER',     (0,0), (0,-1), 2, NAVY),
    ]))
    story.append(at)
    story.append(Spacer(1, 16))

    story.append(Paragraph('SECURITY FINDINGS ({})'.format(total_findings), h1_style))
    story.append(HRFlowable(width="100%", thickness=2, color=NAVY))
    story.append(Spacer(1, 8))

    if total_findings == 0:
        story.append(Paragraph('No security findings detected.', body_style))
    else:
        for f in all_findings:
            rc = risk_color(f['risk'])
            finding_data = [
                [
                    Paragraph(f['title'], ParagraphStyle('ft', fontSize=11, fontName='Helvetica-Bold', textColor=LIGHT)),
                    Paragraph(f['risk'].upper(), ParagraphStyle('fr', fontSize=9, fontName='Helvetica-Bold', textColor=rc, alignment=TA_CENTER))
                ],
                [
                    Paragraph(f['description'], ParagraphStyle('fd', fontSize=9, fontName='Helvetica', textColor=GRAY, leading=14)),
                    ''
                ],
                [
                    Paragraph('Fix: {}'.format(f['remediation']), ParagraphStyle('fix', fontSize=9, fontName='Helvetica', textColor=NAVY, leading=14)),
                    ''
                ],
                [
                    Paragraph('Source: {}   Score: {}   Asset: {}'.format(f['source'].upper(), f['risk_score'], f['subdomain']),
                              ParagraphStyle('fm', fontSize=8, fontName='Helvetica', textColor=GRAY)),
                    ''
                ],
            ]
            ft = Table(finding_data, colWidths=[145*mm, 25*mm])
            ft.setStyle(TableStyle([
                ('LINEAFTER',     (0,0), (0,-1), 3, rc),
                ('BACKGROUND',    (0,0), (-1,0), NAVY),
                ('TOPPADDING',    (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('LEFTPADDING',   (0,0), (-1,-1), 8),
                ('BOX',          (0,0), (-1,-1), 0.5, colors.HexColor("#000000")),
                ('SPAN',          (0,1), (1,1)),
                ('SPAN',          (0,2), (1,2)),
                ('SPAN',          (0,3), (1,3)),
                ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
                ('ALIGN',         (1,0), (1,0),   'CENTER'),
            ]))
            story.append(ft)
            story.append(Spacer(1, 6))

    story.append(Spacer(1, 16))
    story.append(Paragraph('THREAT INTELLIGENCE', h1_style))
    story.append(HRFlowable(width="100%", thickness=2, color=NAVY))
    story.append(Spacer(1, 8))

    if threat_intel_summary:
        intel_data = [['SOURCE', 'STATUS', 'DETAIL']]
        for t in threat_intel_summary:
            status_color = RED if t['is_malicious'] else GREEN
            status_text  = 'FLAGGED' if t['is_malicious'] else 'CLEAN'
            intel_data.append([
                Paragraph(t['source'], ParagraphStyle('is', fontSize=9, fontName='Helvetica-Bold', textColor=NAVY)),
                Paragraph(status_text, ParagraphStyle('ist', fontSize=9, fontName='Helvetica-Bold', textColor=status_color)),
                Paragraph(t['detail'], ParagraphStyle('id', fontSize=9, fontName='Helvetica', textColor=GRAY)),
            ])
        it = Table(intel_data, colWidths=[40*mm, 40*mm, 90*mm])
        it.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,0), NAVY),
            ('TEXTCOLOR',     (0,0), (-1,0), GOLD),
            ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',      (0,0), (-1,0), 8),
            ('TOPPADDING',    (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 8),
            ('LEFTPADDING',   (0,0), (-1,-1), 8),
            ('ROWBACKGROUNDS',(0,1), (-1,-1), [WHITE, LIGHT]),
            ('GRID',          (0,0), (-1,-1), 0.5, colors.HexColor('#E0DDD5')),
        ]))
        story.append(it)
    else:
        story.append(Paragraph('No threat intelligence data available.', body_style))

    story.append(Spacer(1, 24))
    footer_data = [[
        Paragraph('JichoSec ASM - Confidential Security Report',
                  ParagraphStyle('fl', fontSize=9, textColor=GOLD, fontName='Helvetica-Bold')),
        Paragraph(datetime.now().strftime("%d %B %Y %H:%M UTC"),
                  ParagraphStyle('fr', fontSize=9, textColor=GRAY, fontName='Helvetica', alignment=TA_CENTER)),
    ]]
    footer_table = Table(footer_data, colWidths=[100*mm, 70*mm])
    footer_table.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), NAVY),
        ('TOPPADDING',    (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING',   (0,0), (-1,-1), 12),
    ]))
    story.append(footer_table)

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=jichosec-{}-report.pdf".format(scan.domain)}
    )