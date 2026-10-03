import re
import email
from email import policy
from email.parser import HeaderParser
from typing import Optional, List, Dict, Any
# pyrefly: ignore [missing-import]
from fastapi import APIRouter, Depends, HTTPException
# pyrefly: ignore [missing-import]
from sqlalchemy.orm import Session
# pyrefly: ignore [missing-import]
from pydantic import BaseModel
# pyrefly: ignore [missing-import]
from database.db import get_db
# pyrefly: ignore [missing-import]
from database.models import ThreatLog, User
# pyrefly: ignore [missing-import]
from api.auth import get_current_user
from api.url import analyze_url

router = APIRouter(prefix="/email", tags=["Email Scanner"])

class EmailScanRequest(BaseModel):
    sender: Optional[str] = ""
    subject: Optional[str] = ""
    body: Optional[str] = ""
    headers: Optional[str] = None
    raw_eml: Optional[str] = None

PHISHING_KEYWORDS = {
    "bank", "paypal", "stripe", "update account", "verify account", "unusual activity",
    "security alert", "reset password", "wire transfer", "inheritance", "lottery",
    "cash prize", "crypto", "bitcoin", "gift card", "immediate action", "urgent",
    "suspended", "login", "credential", "verify identity", "sign in"
}

TYPOSQUATTED_DOMAINS = [
    r"g[0o]o[0o]gle", r"fac[3e]bo[0o]k", r"micr[0o]s[0o]ft", r"app[1l]e", r"paypa[1l]"
]

DANGEROUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".scr", ".vbs", ".js", ".iso", ".msi", 
    ".docm", ".xlsm", ".pptm", ".hta", ".wsf", ".cpl", ".pif"
}

def extract_domain(email_str: str) -> str:
    if not email_str:
        return ""
    # Support "Display Name <user@domain.com>" or "user@domain.com"
    match = re.search(r'<([^>]+)>', email_str)
    addr = match.group(1) if match else email_str.strip()
    if "@" in addr:
        return addr.split("@")[-1].strip().lower().rstrip(">")
    return ""

def parse_auth_headers(headers_dict: Dict[str, str], raw_headers: str) -> Dict[str, Any]:
    auth_results_header = headers_dict.get("Authentication-Results", "")
    received_spf_header = headers_dict.get("Received-SPF", "")
    dkim_sig_header = headers_dict.get("DKIM-Signature", "")
    
    combined = f"{raw_headers} {auth_results_header} {received_spf_header}".lower()
    
    # 1. SPF Verdict
    spf_verdict = "unknown"
    spf_match = re.search(r'spf\s*=\s*([a-z]+)', combined)
    if spf_match:
        spf_verdict = spf_match.group(1).lower()
    elif "pass" in received_spf_header.lower():
        spf_verdict = "pass"
    elif "fail" in received_spf_header.lower():
        spf_verdict = "fail"
    elif "softfail" in received_spf_header.lower():
        spf_verdict = "softfail"
        
    # 2. DKIM Verdict
    dkim_verdict = "unknown"
    dkim_match = re.search(r'dkim\s*=\s*([a-z]+)', combined)
    if dkim_match:
        dkim_verdict = dkim_match.group(1).lower()
    elif dkim_sig_header:
        dkim_verdict = "present"
        
    # 3. DMARC Verdict
    dmarc_verdict = "unknown"
    dmarc_match = re.search(r'dmarc\s*=\s*([a-z]+)', combined)
    if dmarc_match:
        dmarc_verdict = dmarc_match.group(1).lower()

    return {
        "spf": spf_verdict,
        "dkim": dkim_verdict,
        "dmarc": dmarc_verdict,
        "has_auth_headers": bool(auth_results_header or received_spf_header or dkim_sig_header)
    }

def analyze_email_payload(
    sender: str,
    subject: str,
    body: str,
    headers: Optional[str] = None,
    raw_eml: Optional[str] = None
) -> Dict[str, Any]:
    attachments: List[str] = []
    headers_dict: Dict[str, str] = {}
    raw_headers_str = headers or ""
    
    # If raw .eml is provided, parse through python email parser
    if raw_eml and raw_eml.strip():
        try:
            msg = email.message_from_string(raw_eml, policy=policy.default)
            if not sender and msg.get("From"):
                sender = str(msg.get("From"))
            if not subject and msg.get("Subject"):
                subject = str(msg.get("Subject"))
            
            # Extract headers
            for k, v in msg.items():
                headers_dict[k] = str(v)
            raw_headers_str = "\n".join([f"{k}: {v}" for k, v in msg.items()])
            
            # Extract body & attachments
            if msg.is_multipart():
                body_parts = []
                for part in msg.walk():
                    content_disp = str(part.get("Content-Disposition", ""))
                    filename = part.get_filename()
                    if filename:
                        attachments.append(filename)
                    elif "attachment" in content_disp:
                        attachments.append(filename or "unnamed_attachment")
                    elif part.get_content_type() in ["text/plain", "text/html"]:
                        try:
                            payload_text = part.get_payload(decode=True)
                            if payload_text:
                                body_parts.append(payload_text.decode("utf-8", errors="ignore"))
                        except Exception:
                            pass
                if not body and body_parts:
                    body = "\n".join(body_parts)
            else:
                try:
                    payload_text = msg.get_payload(decode=True)
                    if not body and payload_text:
                        body = payload_text.decode("utf-8", errors="ignore")
                except Exception:
                    pass
        except Exception:
            pass

    # If headers string provided directly
    if raw_headers_str and not headers_dict:
        try:
            parsed_headers = HeaderParser().parsestr(raw_headers_str)
            for k, v in parsed_headers.items():
                headers_dict[k] = str(v)
        except Exception:
            pass

    sender = (sender or "").strip()
    subject = (subject or "").strip()
    body = (body or "").strip()

    if not sender and not body:
        raise ValueError("Either Sender and Body or a valid Raw EML must be provided.")

    checks = []
    risk_points = 0

    # 1. Sender Domain Verification
    sender_domain = extract_domain(sender)
    free_domains = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "protonmail.com", "icloud.com"}
    is_free_sender = sender_domain in free_domains
    
    brand_keywords = ["security", "admin", "support", "billing", "service", "verify", "update", "bank", "account", "paypal", "apple", "microsoft"]
    subject_lower = subject.lower()
    sender_lower = sender.lower()
    
    brand_impersonation = False
    if is_free_sender:
        for brand in brand_keywords:
            if brand in sender_lower or brand in subject_lower:
                brand_impersonation = True
                break

    if brand_impersonation:
        risk_points += 35
        checks.append({
            "name": "Sender Impersonation",
            "passed": False,
            "severity": "danger",
            "message": f"Free email provider (@{sender_domain}) used while claiming to be an administrative or financial alert."
        })
    elif is_free_sender:
        checks.append({
            "name": "Sender Domain",
            "passed": True,
            "severity": "warning",
            "message": f"Email sent from generic consumer provider (@{sender_domain})."
        })
    else:
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
                "message": f"Sender domain '{sender_domain}' matches brand typosquatting heuristics."
            })
        else:
            checks.append({
                "name": "Sender Domain",
                "passed": True,
                "severity": "safe",
                "message": f"Sender domain '{sender_domain or 'Standard'}' appears valid."
            })

    # 2. Header Alignment Checks (From vs Reply-To vs Return-Path)
    reply_to = headers_dict.get("Reply-To", "")
    return_path = headers_dict.get("Return-Path", "")
    reply_to_domain = extract_domain(reply_to)
    return_path_domain = extract_domain(return_path)

    has_alignment_issue = False
    if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
        # Check if one is a subdomain of the other
        if not (reply_to_domain.endswith(f".{sender_domain}") or sender_domain.endswith(f".{reply_to_domain}")):
            risk_points += 30
            has_alignment_issue = True
            checks.append({
                "name": "Reply-To Alignment",
                "passed": False,
                "severity": "danger",
                "message": f"Reply-To mismatch: Replies are routed to a different domain ('{reply_to_domain}') than sender ('{sender_domain}')."
            })
            
    if return_path_domain and sender_domain and return_path_domain != sender_domain:
        if not (return_path_domain.endswith(f".{sender_domain}") or sender_domain.endswith(f".{return_path_domain}")):
            risk_points += 15
            has_alignment_issue = True
            checks.append({
                "name": "Return-Path Alignment",
                "passed": False,
                "severity": "warning",
                "message": f"Return-Path mismatch: Delivery bounces return to '{return_path_domain}' instead of sender domain."
            })

    if not has_alignment_issue:
        checks.append({
            "name": "Header Alignment",
            "passed": True,
            "severity": "safe",
            "message": "Sender, Reply-To, and Return-Path headers are aligned."
        })

    # 3. SPF / DKIM / DMARC Header Detection
    auth_results = parse_auth_headers(headers_dict, raw_headers_str)
    spf = auth_results["spf"]
    dkim = auth_results["dkim"]
    dmarc = auth_results["dmarc"]

    if spf == "fail":
        risk_points += 30
        checks.append({
            "name": "SPF Authentication",
            "passed": False,
            "severity": "danger",
            "message": "SPF check failed (sender IP is not authorized by the domain's SPF record)."
        })
    elif spf == "softfail":
        risk_points += 15
        checks.append({
            "name": "SPF Authentication",
            "passed": False,
            "severity": "warning",
            "message": "SPF check returned softfail (~all)."
        })
    elif spf == "pass":
        checks.append({
            "name": "SPF Authentication",
            "passed": True,
            "severity": "safe",
            "message": "SPF verification passed."
        })
    else:
        if not is_free_sender and auth_results["has_auth_headers"]:
            checks.append({
                "name": "SPF Authentication",
                "passed": True,
                "severity": "warning",
                "message": "SPF status inconclusive or omitted in headers."
            })

    if dkim == "fail":
        risk_points += 30
        checks.append({
            "name": "DKIM Signature",
            "passed": False,
            "severity": "danger",
            "message": "DKIM cryptographic signature verification failed."
        })
    elif dkim in ["pass", "present"]:
        checks.append({
            "name": "DKIM Signature",
            "passed": True,
            "severity": "safe",
            "message": "DKIM cryptographic signature verified."
        })

    if dmarc == "fail":
        risk_points += 30
        checks.append({
            "name": "DMARC Policy",
            "passed": False,
            "severity": "danger",
            "message": "DMARC policy alignment check failed."
        })
    elif dmarc == "pass":
        checks.append({
            "name": "DMARC Policy",
            "passed": True,
            "severity": "safe",
            "message": "DMARC alignment passed."
        })

    # 4. Attachment Security Analysis
    has_suspicious_attachment = False
    if attachments:
        flagged_att = []
        for att in attachments:
            ext = "." + att.split(".")[-1].lower() if "." in att else ""
            if ext in DANGEROUS_ATTACHMENT_EXTENSIONS:
                flagged_att.append(att)
        if flagged_att:
            risk_points += 45
            has_suspicious_attachment = True
            checks.append({
                "name": "Email Attachments",
                "passed": False,
                "severity": "danger",
                "message": f"Dangerous attachment(s) detected: {', '.join(flagged_att)}."
            })
        else:
            checks.append({
                "name": "Email Attachments",
                "passed": True,
                "severity": "safe",
                "message": f"{len(attachments)} attachment(s) inspected, standard formats."
            })

    # 5. Phishing Keywords Check
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
            "message": f"Suspicious phishing triggers found: {', '.join(found_keywords)}."
        })
    else:
        checks.append({
            "name": "Urgency Triggers",
            "passed": True,
            "severity": "safe",
            "message": "No typical urgent financial or verification keywords detected."
        })

    # 6. URL Extraction and Scan Integration
    urls = re.findall(r'(https?://[^\s<>"]+)', body)
    urls = [re.sub(r'[.,;:\'">\)\]]$', '', u) for u in urls]
    
    url_scans = []
    highest_url_score = 0
    
    for u in list(set(urls))[:3]:
        try:
            url_result = analyze_url(u)
            url_scans.append({
                "url": u,
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
                "message": f"Found {len(urls)} link(s) in body. All scanned links verified safe."
            })
    else:
        checks.append({
            "name": "Embedded Links",
            "passed": True,
            "severity": "safe",
            "message": "No hyperlinked URLs found in email body."
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
            "sender_domain": sender_domain,
            "reply_to": reply_to,
            "return_path": return_path,
            "auth_results": auth_results,
            "attachments": attachments,
            "found_keywords": found_keywords,
            "urls_detected": len(urls),
            "highest_url_score": highest_url_score,
            "url_scans": url_scans
        },
        "checks": checks
    }

@router.post("/scan")
def scan_email(
    payload: EmailScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        result = analyze_email_payload(
            sender=payload.sender or "",
            subject=payload.subject or "",
            body=payload.body or "",
            headers=payload.headers,
            raw_eml=payload.raw_eml
        )
        
        target_label = f"{result['sender'] or 'Unknown Sender'} | {result['subject'] or 'No Subject'}"
        
        # Log to database associated with current_user
        db_log = ThreatLog(
            user_id=current_user.id,
            scan_type="email",
            target=target_label[:255],
            risk_score=result["risk_score"],
            status=result["status"],
            details=result
        )
        db.add(db_log)
        db.commit()
        db.refresh(db_log)
        
        result["report_id"] = db_log.id
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal email scan error: {str(e)}")
