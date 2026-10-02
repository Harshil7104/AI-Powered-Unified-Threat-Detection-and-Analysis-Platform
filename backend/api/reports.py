from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from database.db import get_db
from database.models import ThreatLog
import datetime

router = APIRouter(prefix="/reports", tags=["Reports & Dashboard"])

# 1. Get Dashboard Summary Stats
@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    try:
        total_scans = db.query(ThreatLog).count()
        
        threats_detected = db.query(ThreatLog).filter(
            ThreatLog.status.in_(["High Risk", "Suspicious"])
        ).count()
        
        # Count by Type
        by_type_query = db.query(ThreatLog.scan_type, func.count(ThreatLog.id)).group_by(ThreatLog.scan_type).all()
        by_type = {t: c for t, c in by_type_query}
        # Ensure all types have keys
        for t in ["url", "email", "file"]:
            if t not in by_type:
                by_type[t] = 0
                
        # Count by Status
        by_status_query = db.query(ThreatLog.status, func.count(ThreatLog.id)).group_by(ThreatLog.status).all()
        by_status = {s: c for s, c in by_status_query}
        for s in ["Safe", "Suspicious", "High Risk"]:
            if s not in by_status:
                by_status[s] = 0

        # Recent activities (last 6 scans)
        recent_scans = db.query(ThreatLog).order_by(ThreatLog.created_at.desc()).limit(6).all()
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

        # Calculate a mock threat index change or simple stats
        return {
            "total_scans": total_scans,
            "threats_detected": threats_detected,
            "reports_generated": total_scans, # Each scan is a report
            "by_type": by_type,
            "by_status": by_status,
            "recent_activity": recent_list
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load statistics: {str(e)}"
        )

# 2. Get All Historical Scan Reports
@router.get("/")
def get_all_reports(
    scan_type: str = None, 
    status: str = None, 
    search: str = None, 
    db: Session = Depends(get_db)
):
    try:
        query = db.query(ThreatLog)
        
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
def get_report_details(report_id: int, db: Session = Depends(get_db)):
    log = db.query(ThreatLog).filter(ThreatLog.id == report_id).first()
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found."
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

# 4. Delete Specific Threat Log
@router.delete("/{report_id}")
def delete_report(report_id: int, db: Session = Depends(get_db)):
    log = db.query(ThreatLog).filter(ThreatLog.id == report_id).first()
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found."
        )
    db.delete(log)
    db.commit()
    return {"message": "Report deleted successfully.", "id": report_id}
