import hashlib
import os
import requests
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from database.db import get_db
from database.models import ThreatLog
from dotenv import load_dotenv
from pathlib import Path

# Load env variables using path relative to backend directory
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

VIRUSTOTAL_API = os.getenv("VIRUSTOTAL_API", "")

router = APIRouter(prefix="/file", tags=["File Scanner"])

# Suspicious extensions
SUSPICIOUS_EXTENSIONS = {
    ".exe": "Executable Application (high risk of malware)",
    ".dll": "Dynamic Link Library (possible system override)",
    ".bat": "Batch Script (system command execution)",
    ".cmd": "Command Script (system command execution)",
    ".vbs": "VBScript File (scripted execution)",
    ".js": "JavaScript File (standalone script execution)",
    ".scr": "Screen Saver (executable masquerading as screensaver)",
    ".msi": "Windows Installer package",
    ".sh": "Shell Script (Unix execution)",
    ".docm": "Word Document with Macros (active content)",
    ".xlsm": "Excel Spreadsheet with Macros (active content)",
}

def get_virustotal_file_report(file_hash: str, api_key: str):
    if not api_key:
        return {"status": "unconfigured", "message": "VirusTotal API key not configured."}
        
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        resp = requests.get(url, headers=headers, timeout=4)
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            attributes = data.get("attributes", {})
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            return {
                "status": "success",
                "malicious": last_analysis_stats.get("malicious", 0),
                "suspicious": last_analysis_stats.get("suspicious", 0),
                "harmless": last_analysis_stats.get("harmless", 0),
                "undetected": last_analysis_stats.get("undetected", 0),
                "reputation": attributes.get("reputation", 0),
                "type_description": attributes.get("type_description", "Unknown File Type"),
                "size": attributes.get("size", 0)
            }
        elif resp.status_code == 404:
            return {"status": "not_found", "message": "File hash not found in VirusTotal database."}
        else:
            return {"status": "error", "message": f"VirusTotal returned status {resp.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.post("/scan")
async def scan_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    try:
        # 1. Read file contents and calculate hashes
        contents = await file.read()
        file_size = len(contents)
        
        md5_hash = hashlib.md5(contents).hexdigest()
        sha256_hash = hashlib.sha256(contents).hexdigest()
        
        # Reset file cursor just in case
        await file.seek(0)
        
        checks = []
        risk_points = 0
        
        # 2. Check File Extension
        filename = file.filename or "unknown"
        _, ext = os.path.splitext(filename.lower())
        
        is_suspicious_ext = ext in SUSPICIOUS_EXTENSIONS
        if is_suspicious_ext:
            risk_points += 40
            checks.append({
                "name": "File Extension Analysis",
                "passed": False,
                "severity": "danger",
                "message": f"File extension '{ext}' is flagged: {SUSPICIOUS_EXTENSIONS[ext]}."
            })
        else:
            checks.append({
                "name": "File Extension Analysis",
                "passed": True,
                "severity": "safe",
                "message": f"File extension '{ext or 'unknown'}' is standard."
            })
            
        # 3. File Size Check (e.g. exceptionally large scripts, or extremely small executables)
        if is_suspicious_ext and file_size < 5000:
            risk_points += 15
            checks.append({
                "name": "File Size Anomaly",
                "passed": False,
                "severity": "warning",
                "message": f"Executable file is unusually small ({file_size} bytes), which might indicate a downloader/stub payload."
            })
        else:
            checks.append({
                "name": "File Size Check",
                "passed": True,
                "severity": "safe",
                "message": f"File size is normal ({file_size} bytes)."
            })

        # 4. Query VirusTotal with SHA-256 Hash
        vt_report = get_virustotal_file_report(sha256_hash, VIRUSTOTAL_API)
        
        if vt_report and vt_report.get("status") == "success":
            malicious = vt_report.get("malicious", 0)
            suspicious = vt_report.get("suspicious", 0)
            
            if malicious > 0:
                risk_points += min(malicious * 25, 60)
                checks.append({
                    "name": "VirusTotal Detection",
                    "passed": False,
                    "severity": "danger",
                    "message": f"File flagged as malicious by {malicious} engine(s) on VirusTotal."
                })
            else:
                checks.append({
                    "name": "VirusTotal Detection",
                    "passed": True,
                    "severity": "safe",
                    "message": "VirusTotal scanned this file hash and found 0 malicious detections."
                })
        elif vt_report and vt_report.get("status") == "not_found":
            checks.append({
                "name": "VirusTotal Detection",
                "passed": True,
                "severity": "warning",
                "message": "File hash not found in VirusTotal database (unscanned or unique file)."
            })
        else:
            checks.append({
                "name": "VirusTotal Detection",
                "passed": True,
                "severity": "warning",
                "message": f"VirusTotal query unavailable: {vt_report.get('message') or 'API Error'}"
            })

        # Final calculations
        final_score = min(risk_points, 100)
        if final_score >= 60:
            status = "High Risk"
        elif final_score >= 25:
            status = "Suspicious"
        else:
            status = "Safe"
            
        result = {
            "filename": filename,
            "size": file_size,
            "md5": md5_hash,
            "sha256": sha256_hash,
            "risk_score": final_score,
            "status": status,
            "checks": checks,
            "virustotal": vt_report
        }
        
        # 5. Log to database
        db_log = ThreatLog(
            scan_type="file",
            target=filename,
            risk_score=final_score,
            status=status,
            details=result
        )
        db.add(db_log)
        db.commit()
        db.refresh(db_log)
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal file scan error: {str(e)}")
