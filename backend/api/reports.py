# pyrefly: ignore [missing-import]
import io
# pyrefly: ignore [missing-import]
import datetime
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, Depends, HTTPException, status
# pyrefly: ignore [missing-import]
from fastapi.responses import StreamingResponse
# pyrefly: ignore [missing-import]
from sqlalchemy.orm import Session
# pyrefly: ignore [missing-import]
from sqlalchemy import func, or_
# pyrefly: ignore [missing-import]
from database.db import get_db
# pyrefly: ignore [missing-import]
from database.models import ThreatLog, User
from api.auth import get_current_user

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

router = APIRouter(prefix="/reports", tags=["Reports & Dashboard"])

def build_pdf_buffer(log: ThreatLog, current_user: User) -> io.BytesIO:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a')
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#64748b')
    )
    
    heading2_style = ParagraphStyle(
        'SectionHeading',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=10,
        spaceAfter=6
    )
    
    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )

    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#1e293b')
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("🛡️ THREATSHIELD AI — THREAT FORENSICS REPORT", title_style))
    story.append(Paragraph(f"Unified Threat Detection & Analysis Platform | Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#3b82f6'), spaceAfter=12))

    # 2. Status Badge Color
    status_lower = (log.status or "").lower()
    if "high" in status_lower:
        status_bg = colors.HexColor('#fee2e2')
        status_text_color = colors.HexColor('#991b1b')
    elif "suspicious" in status_lower:
        status_bg = colors.HexColor('#fef3c7')
        status_text_color = colors.HexColor('#92400e')
    else:
        status_bg = colors.HexColor('#dcfce7')
        status_text_color = colors.HexColor('#166534')

    status_badge_style = ParagraphStyle(
        'StatusBadge',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=status_text_color
    )

    # 3. Overview Summary Table
    created_str = log.created_at.strftime("%Y-%m-%d %H:%M:%S") if log.created_at else "N/A"
    summary_data = [
        [Paragraph("Report ID:", cell_bold), Paragraph(f"TS-{log.id:06d}", body_style),
         Paragraph("Analyst Account:", cell_bold), Paragraph(current_user.email, body_style)],
        [Paragraph("Scan Type:", cell_bold), Paragraph(log.scan_type.upper(), body_style),
         Paragraph("Scan Timestamp:", cell_bold), Paragraph(created_str, body_style)],
        [Paragraph("Target / Entity:", cell_bold), Paragraph(str(log.target)[:50], body_style),
         Paragraph("Risk Score:", cell_bold), Paragraph(f"<b>{log.risk_score} / 100</b>", cell_bold)],
        [Paragraph("Security Status:", cell_bold), Paragraph(f"<b>{log.status}</b>", status_badge_style),
         Paragraph("Classification:", cell_bold), Paragraph("Automated Forensics Verdict", body_style)],
    ]

    summary_table = Table(summary_data, colWidths=[90, 180, 100, 170])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 14))

    # 4. Security Checklist / Findings Breakdown
    story.append(Paragraph("Security Inspection Checks", heading2_style))
    
    details = log.details or {}
    checks = details.get("checks", [])
    
    if checks:
        check_table_data = [
            [Paragraph("Check Name", cell_bold), Paragraph("Status", cell_bold), Paragraph("Severity", cell_bold), Paragraph("Forensic Finding", cell_bold)]
        ]
        
        for c in checks:
            passed = c.get("passed", True)
            sev = c.get("severity", "safe")
            stat_text = "PASSED" if passed else "FLAGGED"
            stat_color = colors.HexColor('#166534') if passed else colors.HexColor('#dc2626')
            
            p_stat = Paragraph(f"<font color='{stat_color.hexval()}'><b>{stat_text}</b></font>", body_style)
            p_sev = Paragraph(sev.upper(), body_style)
            p_name = Paragraph(c.get("name", "Rule"), cell_bold)
            p_msg = Paragraph(c.get("message", "-"), body_style)
            
            check_table_data.append([p_name, p_stat, p_sev, p_msg])
            
        check_table = Table(check_table_data, colWidths=[120, 65, 65, 290])
        check_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f1f5f9')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(check_table)
    else:
        story.append(Paragraph("No detailed checklist recorded for this scan.", body_style))
        
    story.append(Spacer(1, 14))

    # 5. Technical & Threat Intelligence Details
    story.append(Paragraph("Technical & Threat Intelligence Details", heading2_style))
    
    tech_data = []
    
    # VirusTotal
    vt = details.get("virustotal")
    if vt and vt.get("status") == "success":
        vt_text = f"Malicious: {vt.get('malicious', 0)} | Suspicious: {vt.get('suspicious', 0)} | Harmless: {vt.get('harmless', 0)} | Reputation: {vt.get('reputation', 0)}"
        tech_data.append([Paragraph("VirusTotal Multi-Engine:", cell_bold), Paragraph(vt_text, body_style)])

    # OTX
    otx = details.get("otx")
    if otx and otx.get("status") == "success":
        otx_text = f"Threat Level: {otx.get('threat_level', 'None')} | Threat Pulses: {otx.get('pulse_count', 0)}"
        tech_data.append([Paragraph("AlienVault OTX Pulse:", cell_bold), Paragraph(otx_text, body_style)])

    # SSL Info
    ssl = details.get("ssl_info")
    if ssl and isinstance(ssl, dict) and "error" not in ssl:
        ssl_text = f"Issuer: {ssl.get('issuer', 'N/A')} | Status: {ssl.get('status', 'N/A')} | Days Left: {ssl.get('days_remaining', 'N/A')}"
        tech_data.append([Paragraph("SSL / TLS Certificate:", cell_bold), Paragraph(ssl_text, body_style)])

    # WHOIS Info
    whois = details.get("whois_info")
    if whois and isinstance(whois, dict):
        whois_text = f"Registrar: {whois.get('registrar', 'N/A')} | Created: {whois.get('created_date', 'N/A')} | Age: {whois.get('domain_age_human', 'N/A')}"
        tech_data.append([Paragraph("WHOIS Domain Info:", cell_bold), Paragraph(whois_text, body_style)])

    # Hashes / Entropy (File scan)
    if details.get("sha256") or details.get("entropy") is not None:
        file_meta = f"Entropy: {details.get('entropy', 'N/A')}/8.0 ({details.get('entropy_status', '')}) | Detected Type: {details.get('detected_type', 'N/A')}"
        tech_data.append([Paragraph("File Forensics:", cell_bold), Paragraph(file_meta, body_style)])
        if details.get("sha256"):
            tech_data.append([Paragraph("SHA-256 Hash:", cell_bold), Paragraph(str(details.get("sha256")), body_style)])
        if details.get("sha1"):
            tech_data.append([Paragraph("SHA-1 Hash:", cell_bold), Paragraph(str(details.get("sha1")), body_style)])
        if details.get("md5"):
            tech_data.append([Paragraph("MD5 Hash:", cell_bold), Paragraph(str(details.get("md5")), body_style)])

    # Email Specific
    if details.get("auth_results"):
        ar = details.get("auth_results", {})
        ar_text = f"SPF: {ar.get('spf', 'N/A').upper()} | DKIM: {ar.get('dkim', 'N/A').upper()} | DMARC: {ar.get('dmarc', 'N/A').upper()}"
        tech_data.append([Paragraph("Email Auth (SPF/DKIM):", cell_bold), Paragraph(ar_text, body_style)])

    if tech_data:
        tech_table = Table(tech_data, colWidths=[150, 390])
        tech_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(tech_table)
    else:
        story.append(Paragraph("Standard forensic metadata recorded.", body_style))

    story.append(Spacer(1, 14))

    # 6. Actionable Security Recommendations
    story.append(Paragraph("Actionable Recommendations & Remediation", heading2_style))
    recs = []
    if log.risk_score >= 60:
        recs.append("<b>[BLOCK] Critical Threat Action:</b> Quarantine target immediately. Block the domain/IP in enterprise firewalls or isolate file from host.")
        recs.append("<b>Investigation:</b> Investigate endpoints that communicated with this entity. Review system logs for signs of compromise.")
        recs.append("<b>Incident Response:</b> Escalate this threat log to the SOC incident queue for IOC extraction.")
    elif log.risk_score >= 25:
        recs.append("<b>[CAUTION] Precautionary Action:</b> Do not interact or input credentials. Verify origin with sender/admin via out-of-band communication.")
        recs.append("<b>Monitoring:</b> Submit target to secondary sandbox or automated detonation environment for behavioural confirmation.")
    else:
        recs.append("<b>[CLEAN] Routine Clearance:</b> No malicious indicators detected. Maintain regular cybersecurity hygiene and endpoint monitoring.")

    rec_data = [[Paragraph(f"• {r}", body_style)] for r in recs]
    rec_table = Table(rec_data, colWidths=[540])
    rec_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f1f5f9')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(rec_table)
    story.append(Spacer(1, 18))

    # Footer note
    footer_text = "CONFIDENTIAL • Generated by ThreatShield AI Unified Threat Detection & Analysis Platform • For Authorized Security Operations Use Only"
    story.append(Paragraph(footer_text, subtitle_style))

    doc.build(story)
    buffer.seek(0)
    return buffer

# 1. Get Dashboard Summary Stats for current user
@router.get("/stats")
def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        user_filter = or_(ThreatLog.user_id == current_user.id, ThreatLog.user_id == None)
        
        total_scans = db.query(ThreatLog).filter(user_filter).count()
        
        threats_detected = db.query(ThreatLog).filter(
            user_filter,
            ThreatLog.status.in_(["High Risk", "Suspicious"])
        ).count()
        
        # Count by Type
        by_type_query = db.query(
            ThreatLog.scan_type, func.count(ThreatLog.id)
        ).filter(user_filter).group_by(ThreatLog.scan_type).all()
        by_type = {t: c for t, c in by_type_query}
        for t in ["url", "email", "file"]:
            if t not in by_type:
                by_type[t] = 0
                
        # Count by Status
        by_status_query = db.query(
            ThreatLog.status, func.count(ThreatLog.id)
        ).filter(user_filter).group_by(ThreatLog.status).all()
        by_status = {s: c for s, c in by_status_query}
        for s in ["Safe", "Suspicious", "High Risk"]:
            if s not in by_status:
                by_status[s] = 0

        # Recent activities (last 6 scans)
        recent_scans = db.query(ThreatLog).filter(user_filter).order_by(ThreatLog.created_at.desc()).limit(6).all()
        recent_list = []
        for log in recent_scans:
            recent_list.append({
                "id": log.id,
                "scan_type": log.scan_type,
                "target": log.target,
                "risk_score": log.risk_score,
                "status": log.status,
                "created_at": log.created_at.strftime("%Y-%m-%d %H:%M:%S")
            })

        return {
            "total_scans": total_scans,
            "threats_detected": threats_detected,
            "reports_generated": total_scans,
            "by_type": by_type,
            "by_status": by_status,
            "recent_activity": recent_list
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load statistics: {str(e)}"
        )

# 2. Get All Historical Scan Reports for current user
@router.get("/")
def get_all_reports(
    scan_type: str = None, 
    status: str = None, 
    search: str = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        user_filter = or_(ThreatLog.user_id == current_user.id, ThreatLog.user_id == None)
        query = db.query(ThreatLog).filter(user_filter)
        
        if scan_type:
            query = query.filter(ThreatLog.scan_type == scan_type)
            
        if status:
            query = query.filter(ThreatLog.status == status)
            
        if search:
            query = query.filter(ThreatLog.target.ilike(f"%{search}%"))
            
        reports = query.order_by(ThreatLog.created_at.desc()).all()
        
        result = []
        for log in reports:
            result.append({
                "id": log.id,
                "scan_type": log.scan_type,
                "target": log.target,
                "risk_score": log.risk_score,
                "status": log.status,
                "created_at": log.created_at.strftime("%Y-%m-%d %H:%M:%S")
            })
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch reports: {str(e)}"
        )

# 3. Get Specific Scan Details
@router.get("/{report_id}")
def get_report_details(
    report_id: int, 
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_filter = or_(ThreatLog.user_id == current_user.id, ThreatLog.user_id == None)
    log = db.query(ThreatLog).filter(ThreatLog.id == report_id, user_filter).first()
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found or access denied."
        )
    return {
        "id": log.id,
        "scan_type": log.scan_type,
        "target": log.target,
        "risk_score": log.risk_score,
        "status": log.status,
        "created_at": log.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        "details": log.details
    }

# 4. Download Professional PDF Report
@router.get("/{report_id}/pdf")
def download_pdf_report(
    report_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_filter = or_(ThreatLog.user_id == current_user.id, ThreatLog.user_id == None)
    log = db.query(ThreatLog).filter(ThreatLog.id == report_id, user_filter).first()
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found or access denied."
        )
        
    try:
        pdf_buffer = build_pdf_buffer(log, current_user)
        filename = f"ThreatShield_Report_{log.scan_type.upper()}_{log.id}.pdf"
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate PDF report: {str(e)}"
        )

# 5. Delete Specific Threat Log
@router.delete("/{report_id}")
def delete_report(
    report_id: int, 
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_filter = or_(ThreatLog.user_id == current_user.id, ThreatLog.user_id == None)
    log = db.query(ThreatLog).filter(ThreatLog.id == report_id, user_filter).first()
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found or access denied."
        )
    db.delete(log)
    db.commit()
    return {"message": "Report deleted successfully.", "id": report_id}
