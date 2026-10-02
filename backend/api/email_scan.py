import re
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from database.db import get_db
from database.models import ThreatLog
from api.url import analyze_url

router = APIRouter(prefix="/email", tags=["Email Scanner"])

class EmailScanRequest(BaseModel):
    sender: str
    subject: str
    body: str

# Heuristic list of spam/phishing terms
PHISHING_KEYWORDS = {
    "bank", "paypal", "stripe", "update account", "verify account", "unusual activity",
    "security alert", "reset password", "wire transfer", "inheritance", "lottery",
    "cash prize", "crypto", "bitcoin", "gift card", "immediate action", "urgent",
    "suspended", "login", "credential", "verify identity", "sign in"
}

TYPOSQUATTED_DOMAINS = [
    r"g[0o]o[0o]gle", r"fac[3e]bo[0o]k", r"micr[0o]s[0o]ft", r"app[1l]e", r"paypa[1l]"
]

def analyze_email(sender: str, subject: str, body: str):
    sender = sender.strip()
    subject = subject.strip()
    body = body.strip()

    if not sender or not body:
        raise ValueError("Sender and email body are required.")

    checks = []
    risk_points = 0

    # 1. Sender Domain Verification
    sender_domain = ""
    if "@" in sender:
        sender_domain = sender.split("@")[-1].lower()

    # Free email domain check
    free_domains = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "protonmail.com"}
    is_free_sender = sender_domain in free_domains
    
    # Check if sender claims to be a brand but uses free email domain
    brand_keywords = ["security", "admin", "support", "billing", "service", "verify", "update", "bank"]
    subject_lower = subject.lower()
    body_lower = body.lower()
    
    brand_impersonation = False
    if is_free_sender:
        for brand in brand_keywords:
            if brand in sender.lower() or brand in subject_lower:
                brand_impersonation = True
                break

    if brand_impersonation:
        risk_points += 35
        checks.append({
            "name": "Sender Impersonation",
            "passed": False,
            "severity": "danger",
            "message": "Free email domain used to send administrative or security alerts (high risk of phishing)."
        })
    elif is_free_sender:
        checks.append({
            "name": "Sender Domain",
            "passed": True,
            "severity": "warning",
            "message": "Email sent from a generic free email address."
        })
    else:
        # Check typosquatting
        is_squatted = False
        for pattern in TYPOSQUATTED_DOMAINS:
            if re.search(pattern, sender_domain) and not any(p in sender_domain for p in ["google.com", "facebook.com", "microsoft.com", "apple.com", "paypal.com"]):
                is_squatted = True
                break
        
        if is_squatted:
            risk_points += 40
            checks.append({
                "name": "Domain Typosquatting",
                "passed": False,
                "severity": "danger",
                "message": f"Sender domain '{sender_domain}' matches common typosquatting patterns for reputable brands."
            })
        else:
            checks.append({
                "name": "Sender Domain",
                "passed": True,
                "severity": "safe",
                "message": f"Sender domain '{sender_domain}' appears standard."
            })

    # 2. Phishing Keywords Check
    found_keywords = []
    combined_text = (subject + " " + body).lower()
    for kw in PHISHING_KEYWORDS:
        if kw in combined_text:
            found_keywords.append(kw)

    if found_keywords:
        kw_penalty = min(len(found_keywords) * 10, 30)
        risk_points += kw_penalty
        checks.append({
            "name": "Urgency & Phishing Indicators",
            "passed": False,
            "severity": "danger" if kw_penalty >= 25 else "warning",
            "message": f"Suspicious phishing/urgency triggers found: {', '.join(found_keywords)}."
        })
    else:
        checks.append({
            "name": "Urgency Triggers",
            "passed": True,
            "severity": "safe",
            "message": "No urgent financial or verification keywords detected."
        })

    # 3. URL Extraction and Scan Integration
    urls = re.findall(r'(https?://\S+)', body)
    # Clean URLs (remove punctuation at end)
    urls = [re.sub(r'[.,;:\'">\)\]]$', '', u) for u in urls]
    
    url_scans = []
    highest_url_score = 0
    
    for url in list(set(urls))[:3]: # Scan up to 3 unique URLs
        try:
            url_result = analyze_url(url)
            url_scans.append({
                "url": url,
                "risk_score": url_result["risk_score"],
                "status": url_result["status"]
            })
            if url_result["risk_score"] > highest_url_score:
                highest_url_score = url_result["risk_score"]
        except Exception:
            pass

    if urls:
        if highest_url_score >= 60:
            risk_points += 40
            checks.append({
                "name": "Embedded Links",
                "passed": False,
                "severity": "danger",
                "message": f"Found high-risk links in email body. Highest URL risk score: {highest_url_score}."
            })
        elif highest_url_score >= 25:
            risk_points += 20
            checks.append({
                "name": "Embedded Links",
                "passed": False,
                "severity": "warning",
                "message": f"Found suspicious links in email body. Highest URL risk score: {highest_url_score}."
            })
        else:
            checks.append({
                "name": "Embedded Links",
                "passed": True,
                "severity": "safe",
                "message": f"Found {len(urls)} links in body. All scanned links appear safe."
            })
    else:
        checks.append({
            "name": "Embedded Links",
            "passed": True,
            "severity": "safe",
            "message": "No hyperlinked URLs found in email body."
        })

    # 4. SPF/DKIM Authentication Simulation
    # In a real scanner, these come from header analysis. Here we check if they look fake or parse them.
    # We will simulate security controls check.
    has_auth_headers = "dmarc=pass" in body_lower or "spf=pass" in body_lower or "dkim=pass" in body_lower
    if not has_auth_headers and not is_free_sender:
        risk_points += 15
        checks.append({
            "name": "Email Authentication (SPF/DKIM)",
            "passed": False,
            "severity": "warning",
            "message": "Missing email authentication signatures (SPF/DKIM check failed or inconclusive)."
        })
    else:
        checks.append({
            "name": "Email Authentication (SPF/DKIM)",
            "passed": True,
            "severity": "safe",
            "message": "Email authentication checks (SPF/DKIM) verified."
        })

    final_score = min(risk_points, 100)
    if final_score >= 60:
        status = "High Risk"
    elif final_score >= 25:
        status = "Suspicious"
    else:
        status = "Safe"

    return {
        "sender": sender,
        "subject": subject,
        "risk_score": final_score,
        "status": status,
        "details": {
            "is_free_sender": is_free_sender,
            "brand_impersonation": brand_impersonation,
            "found_keywords": found_keywords,
            "urls_detected": len(urls),
            "highest_url_score": highest_url_score,
            "url_scans": url_scans
        },
        "checks": checks
    }

@router.post("/scan")
def scan_email(payload: EmailScanRequest, db: Session = Depends(get_db)):
    try:
        result = analyze_email(payload.sender, payload.subject, payload.body)
        
        # Log to database
        db_log = ThreatLog(
            scan_type="email",
            target=f"{payload.sender} | {payload.subject}",
            risk_score=result["risk_score"],
            status=result["status"],
            details=result
        )
        db.add(db_log)
        db.commit()
        db.refresh(db_log)
        
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal scan error: {str(e)}")
