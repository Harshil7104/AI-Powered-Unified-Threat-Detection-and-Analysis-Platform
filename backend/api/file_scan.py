import hashlib
import os
import math
from collections import Counter
from typing import Dict, Any, Optional
import requests
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File     
# pyrefly: ignore [missing-import]
from sqlalchemy.orm import Session  
from database.db import get_db
from database.models import ThreatLog, User
from api.auth import get_current_user
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv
# pyrefly: ignore [missing-import]  
from pathlib import Path

# Load env variables
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
    ".iso": "Disk Image File (often used to deliver loader stubs)",
    ".hta": "HTML Application (executes outside browser sandbox)",
    ".wsf": "Windows Script File",
    ".ps1": "PowerShell Script"
}

def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)

def detect_file_magic_type(data: bytes) -> Dict[str, Any]:
    if not data:
        return {"type": "empty", "category": "Empty File", "expected_extensions": []}
    
    if data.startswith(b"MZ"):
        return {"type": "executable", "category": "Windows Executable/DLL (PE)", "expected_extensions": [".exe", ".dll", ".sys", ".scr"]}
    elif data.startswith(b"%PDF"):
        return {"type": "pdf", "category": "PDF Document", "expected_extensions": [".pdf"]}
    elif data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
        return {"type": "archive_or_office", "category": "ZIP Archive / Office OpenXML Document", "expected_extensions": [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"]}
    elif data.startswith(b"\x7fELF"):
        return {"type": "elf", "category": "Linux Executable (ELF)", "expected_extensions": [".elf", ".bin", ""]}
    elif data.startswith(b"\xff\xd8\xff"):
        return {"type": "jpeg", "category": "JPEG Image", "expected_extensions": [".jpg", ".jpeg"]}
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        return {"type": "png", "category": "PNG Image", "expected_extensions": [".png"]}
    elif data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return {"type": "gif", "category": "GIF Image", "expected_extensions": [".gif"]}
    elif data.startswith(b"Rar!\x1a\x07"):
        return {"type": "rar", "category": "RAR Archive", "expected_extensions": [".rar"]}
    elif data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return {"type": "7z", "category": "7-Zip Archive", "expected_extensions": [".7z"]}
    elif data.startswith(b"\x1f\x8b"):
        return {"type": "gzip", "category": "GZIP Compressed File", "expected_extensions": [".gz", ".tgz"]}
    elif data.startswith(b"BM"):
        return {"type": "bmp", "category": "Bitmap Image", "expected_extensions": [".bmp"]}
    elif data.startswith(b"{\\rtf"):
        return {"type": "rtf", "category": "Rich Text Document", "expected_extensions": [".rtf"]}
    
    prefix_text = data[:256].decode("utf-8", errors="ignore").lower()
    if prefix_text.startswith("#!"):
        return {"type": "script", "category": "Shell Script", "expected_extensions": [".sh", ".bash", ".py", ".pl"]}
    elif "<!doctype html" in prefix_text or "<html" in prefix_text:
        return {"type": "html", "category": "HTML Document", "expected_extensions": [".html", ".htm"]}
    elif "@echo" in prefix_text:
        return {"type": "batch", "category": "Batch Script", "expected_extensions": [".bat", ".cmd"]}
        
    return {"type": "generic", "category": "Generic Binary/Text Data", "expected_extensions": []}

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
async def scan_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        # 1. Read file contents and calculate MD5, SHA-1, and SHA-256 hashes
        contents = await file.read()
        file_size = len(contents)
        
        md5_hash = hashlib.md5(contents).hexdigest()
        sha1_hash = hashlib.sha1(contents).hexdigest()
        sha256_hash = hashlib.sha256(contents).hexdigest()
        
        await file.seek(0)
        
        checks = []
        risk_points = 0
        
        filename = file.filename or "unknown"
        _, ext = os.path.splitext(filename.lower())
        
        # 2. Shannon Entropy Analysis
        entropy = calculate_shannon_entropy(contents)
        entropy_status = "Normal"
        if entropy >= 7.2:
            risk_points += 30
            entropy_status = "High Entropy (Likely Packed/Encrypted)"
            checks.append({
                "name": "Shannon Entropy Analysis",
                "passed": False,
                "severity": "danger",
                "message": f"High entropy ({entropy}/8.0). File exhibits high randomness, typical of packed or encrypted malware payloads."
            })
        elif entropy >= 6.5:
            entropy_status = "Moderate Entropy"
            checks.append({
                "name": "Shannon Entropy Analysis",
                "passed": True,
                "severity": "warning",
                "message": f"Moderate entropy ({entropy}/8.0), typical of compressed or binary data."
            })
        else:
            checks.append({
                "name": "Shannon Entropy Analysis",
                "passed": True,
                "severity": "safe",
                "message": f"Normal entropy ({entropy}/8.0). Data density is within standard thresholds."
            })

        # 3. Magic-Byte Detection & File Type Comparison
        magic_info = detect_file_magic_type(contents)
        detected_category = magic_info["category"]
        expected_exts = magic_info["expected_extensions"]
        
        is_executable_disguised = magic_info["type"] == "executable" and ext in [
            ".pdf", ".jpg", ".jpeg", ".png", ".txt", ".docx", ".xlsx", ".gif", ".mp3", ".mp4"
        ]
        
        has_extension_mismatch = False
        if is_executable_disguised:
            risk_points += 55
            has_extension_mismatch = True
            checks.append({
                "name": "File Type & Extension Match",
                "passed": False,
                "severity": "danger",
                "message": f"Critical Deception! File header has Windows Executable (MZ) signature but uses deceptive extension '{ext}'."
            })
        elif expected_exts and ext not in expected_exts and magic_info["type"] not in ["generic", "empty"]:
            risk_points += 25
            has_extension_mismatch = True
            checks.append({
                "name": "File Type & Extension Match",
                "passed": False,
                "severity": "warning",
                "message": f"Mismatch detected: Header bytes indicate '{detected_category}', but extension is '{ext}'."
            })
        else:
            checks.append({
                "name": "File Type & Extension Match",
                "passed": True,
                "severity": "safe",
                "message": f"File signature matches extension '{ext or 'standard'}' ({detected_category})."
            })

        # 4. Check File Extension
        is_suspicious_ext = ext in SUSPICIOUS_EXTENSIONS
        if is_suspicious_ext:
            risk_points += 35
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
            
        # 5. File Size Check
        if is_suspicious_ext and file_size < 5000:
            risk_points += 15
            checks.append({
                "name": "File Size Anomaly",
                "passed": False,
                "severity": "warning",
                "message": f"Executable file is unusually small ({file_size} bytes), which often indicates a downloader stub."
            })
        else:
            checks.append({
                "name": "File Size Check",
                "passed": True,
                "severity": "safe",
                "message": f"File size is normal ({file_size} bytes)."
            })

        # 6. Query VirusTotal with SHA-256 Hash
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
                "severity": "safe",
                "message": "File hash not found in VirusTotal database (unscanned or unique file)."
            })
        else:
            checks.append({
                "name": "VirusTotal Detection",
                "passed": True,
                "severity": "warning",
                "message": f"VirusTotal query unavailable: {vt_report.get('message') or 'API Error'}"
            })

        # Final score
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
            "sha1": sha1_hash,
            "sha256": sha256_hash,
            "entropy": entropy,
            "entropy_status": entropy_status,
            "detected_type": detected_category,
            "type_mismatch": has_extension_mismatch,
            "risk_score": final_score,
            "status": status,
            "checks": checks,
            "virustotal": vt_report
        }
        
        # 7. Log to database linked with current_user
        db_log = ThreatLog(
            user_id=current_user.id,
            scan_type="file",
            target=filename,
            risk_score=final_score,
            status=status,
            details=result
        )
        db.add(db_log)
        db.commit()
        db.refresh(db_log)
        
        result["report_id"] = db_log.id
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal file scan error: {str(e)}")
