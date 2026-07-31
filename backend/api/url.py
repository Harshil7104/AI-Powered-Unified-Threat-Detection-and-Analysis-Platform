from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import re
from urllib.parse import urlparse
import ipaddress

router = APIRouter(prefix="/url", tags=["URL Scanner"])

class URLScanRequest(BaseModel):
    url: str

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", 
    "ow.ly", "rb.gy", "cutt.ly", "shorturl.at", "rebrand.ly", "bl.ink", 
    "tiny.cc", "clck.ru", "v.gd", "qr.ae"
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "banking", 
    "update", "secure", "security", "paypal", "apple", "google", "microsoft", 
    "password", "credential", "claim", "bonus", "free", "wallet", "crypto", 
    "webmail", "support", "service", "billing", "confirm", "recovery"
]

def analyze_url(raw_url: str):
    url = raw_url.strip()
    if not url:
        raise ValueError("URL cannot be empty")
        
    parse_target = url if re.match(r'^[a-zA-Z]+://', url) else f"http://{url}"
    parsed = urlparse(parse_target)
    
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full_str = url.lower()
    
    checks = []
    risk_points = 0
    
    # 1. HTTPS Check
    is_https = parsed.scheme.lower() == "https"
    if is_https:
        checks.append({
            "name": "HTTPS Protocol",
            "passed": True,
            "severity": "safe",
            "message": "URL uses secure HTTPS protocol."
        })
    else:
        risk_points += 25
        checks.append({
            "name": "HTTPS Protocol",
            "passed": False,
            "severity": "warning",
            "message": "URL does not use HTTPS (insecure connection)."
        })
        
    # 2. URL Length Check
    url_len = len(url)
    if url_len <= 54:
        checks.append({
            "name": "URL Length",
            "passed": True,
            "severity": "safe",
            "message": f"URL length is normal ({url_len} characters)."
        })
    elif url_len <= 75:
        risk_points += 10
        checks.append({
            "name": "URL Length",
            "passed": True,
            "severity": "warning",
            "message": f"URL length is moderately long ({url_len} characters)."
        })
    else:
        risk_points += 25
        checks.append({
            "name": "URL Length",
            "passed": False,
            "severity": "danger",
            "message": f"URL is unusually long ({url_len} characters), often used for link hiding."
        })
        
    # 3. IP Address Host Check
    is_ip = False
    try:
        if hostname:
            ipaddress.ip_address(hostname)
            is_ip = True
    except ValueError:
        is_ip = False
        
    if is_ip:
        risk_points += 30
        checks.append({
            "name": "IP Address Host",
            "passed": False,
            "severity": "danger",
            "message": f"URL uses raw IP address ('{hostname}') instead of domain name."
        })
    else:
        checks.append({
            "name": "IP Address Host",
            "passed": True,
            "severity": "safe",
            "message": "URL uses a standard domain name."
        })

    # 4. Suspicious Words Check
    found_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in full_str]
    if found_keywords:
        keyword_penalty = min(len(found_keywords) * 15, 30)
        risk_points += keyword_penalty
        checks.append({
            "name": "Suspicious Keywords",
            "passed": False,
            "severity": "danger" if keyword_penalty >= 25 else "warning",
            "message": f"Found suspicious keyword(s): {', '.join(found_keywords)}."
        })
    else:
        checks.append({
            "name": "Suspicious Keywords",
            "passed": True,
            "severity": "safe",
            "message": "No typical phishing or scam keywords found."
        })
        
    # 5. Shortener Detection
    is_shortener = hostname.lower() in SHORTENER_DOMAINS
    if is_shortener:
        risk_points += 20
        checks.append({
            "name": "URL Shortener",
            "passed": False,
            "severity": "warning",
            "message": f"URL uses a known URL shortener service ('{hostname}')."
        })
    else:
        checks.append({
            "name": "URL Shortener",
            "passed": True,
            "severity": "safe",
            "message": "URL is not from a known URL shortener domain."
        })
        
    final_score = min(risk_points, 100)
    if final_score >= 60:
        status = "High Risk"
    elif final_score >= 25:
        status = "Suspicious"
    else:
        status = "Safe"
        
    return {
        "url": url,
        "risk_score": final_score,
        "status": status,
        "details": {
            "is_https": is_https,
            "url_length": url_len,
            "is_ip_address": is_ip,
            "found_keywords": found_keywords,
            "is_shortener": is_shortener,
            "hostname": hostname
        },
        "checks": checks
    }

@router.post("/scan")
def scan_url(payload: URLScanRequest):
    try:
        return analyze_url(payload.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal scan error: {str(e)}")