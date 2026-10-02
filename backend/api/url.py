from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from database.db import get_db
from database.models import ThreatLog
from pydantic import BaseModel
import re
from urllib.parse import urlparse
import ipaddress
import ssl
import socket
import base64
import requests
import os
from datetime import datetime
from dotenv import load_dotenv
from pathlib import Path

# Load dotenv variables using an absolute path to the backend/.env folder
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

VIRUSTOTAL_API = os.getenv("VIRUSTOTAL_API", "")
OTX_API = os.getenv("OTX_API", "")

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

def get_ssl_details(hostname: str):
    if not hostname:
        return None
        
    # Check if host is raw IP (SSL certs usually don't match or bind to raw local IPs, skip handshake if IP to prevent timeout)
    try:
        ipaddress.ip_address(hostname)
        return {
            "is_valid": False,
            "status": "No SSL (Raw IP)",
            "message": "Raw IP address used; SSL certificate not queried."
        }
    except ValueError:
        pass

    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Parse issuer
                issuer = dict(x[0] for x in cert.get('issuer', []))
                issuer_name = issuer.get('organizationName', issuer.get('commonName', 'Unknown'))
                
                # Parse subject
                subject = dict(x[0] for x in cert.get('subject', []))
                common_name = subject.get('commonName', 'Unknown')
                
                # Parse dates
                not_before_str = cert.get('notBefore')
                not_after_str = cert.get('notAfter')
                
                # Format: 'Mar 14 00:00:00 2024 GMT'
                date_fmt = "%b %d %H:%M:%S %Y %Z"
                valid_from = datetime.strptime(not_before_str, date_fmt)
                valid_to = datetime.strptime(not_after_str, date_fmt)
                
                now = datetime.utcnow()
                days_left = (valid_to - now).days
                is_valid = valid_from <= now <= valid_to
                
                return {
                    "common_name": common_name,
                    "issuer": issuer_name,
                    "valid_from": valid_from.strftime("%Y-%m-%d"),
                    "valid_to": valid_to.strftime("%Y-%m-%d"),
                    "days_remaining": days_left,
                    "is_valid": is_valid,
                    "status": "Valid" if is_valid else "Expired"
                }
    except Exception as e:
        return {
            "is_valid": False,
            "status": "No SSL/Error",
            "error": str(e)
        }

def query_whois(server, domain):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((server, 43))
        s.send((domain + "\r\n").encode("utf-8"))
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        return response.decode("utf-8", errors="ignore")
    except Exception:
        return ""

def get_whois_details(domain: str):
    if not domain:
        return None
        
    # Check if host is raw IP
    try:
        ipaddress.ip_address(domain)
        return {
            "registrar": "N/A (Raw IP)",
            "created_date": "N/A",
            "expiry_date": "N/A",
            "whois_server": "N/A"
        }
    except ValueError:
        pass

    # Extract clean domain name (e.g. sub.example.com -> example.com for WHOIS)
    parts = domain.split(".")
    if len(parts) > 2:
        # Simple extraction for common two-part TLDs (e.g. co.uk, com.au)
        if parts[-2] in ["com", "co", "org", "net", "gov", "edu", "ac"]:
            clean_domain = ".".join(parts[-3:])
        else:
            clean_domain = ".".join(parts[-2:])
    else:
        clean_domain = domain

    try:
        iana_resp = query_whois("whois.iana.org", clean_domain)
        if not iana_resp:
            return {"registrar": "Unknown", "created_date": "Unknown", "expiry_date": "Unknown", "error": "WHOIS server unreachable"}
            
        refer_match = re.search(r"(?:refer|whois):\s*([a-zA-Z0-9\.\-]+)", iana_resp, re.IGNORECASE)
        whois_server = refer_match.group(1).strip() if refer_match else "whois.iana.org"
        
        whois_resp = query_whois(whois_server, clean_domain)
        if not whois_resp:
            whois_resp = iana_resp
            
        # Parse details
        registrar_match = re.search(r"Registrar:\s*(.*)", whois_resp, re.IGNORECASE)
        created_match = re.search(r"(?:Creation Date|Created|Registration Time|created-date|registered):\s*(.*)", whois_resp, re.IGNORECASE)
        expiry_match = re.search(r"(?:Registry Expiry Date|Expiration Date|Expires|Expiry Date|expire-date|expiration):\s*(.*)", whois_resp, re.IGNORECASE)
        
        registrar = registrar_match.group(1).strip() if registrar_match else "Unknown"
        created = created_match.group(1).strip() if created_match else "Unknown"
        expiry = expiry_match.group(1).strip() if expiry_match else "Unknown"
        
        def clean_date(d_str):
            if d_str == "Unknown":
                return d_str
            m = re.search(r"(\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2})?)", d_str)
            if m:
                return m.group(1)
            # Try to catch DD-MM-YYYY or DD.MM.YYYY
            m2 = re.search(r"(\d{2}[\-\.]\d{2}[\-\.]\d{4})", d_str)
            if m2:
                return m2.group(1)
            return d_str.split()[0] if d_str else "Unknown"
            
        return {
            "registrar": registrar,
            "created_date": clean_date(created),
            "expiry_date": clean_date(expiry),
            "whois_server": whois_server
        }
    except Exception as e:
        return {
            "registrar": "Unknown",
            "created_date": "Unknown",
            "expiry_date": "Unknown",
            "error": str(e)
        }

def get_virustotal_report(raw_url: str, api_key: str):
    if not api_key:
        return {"status": "unconfigured", "message": "VirusTotal API key not configured"}
        
    try:
        url_id = base64.urlsafe_b64encode(raw_url.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
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
                "reputation": attributes.get("reputation", 0)
            }
        elif resp.status_code == 404:
            # Try to submit for scan
            scan_url = "https://www.virustotal.com/api/v3/urls"
            data = {"url": raw_url}
            scan_resp = requests.post(scan_url, headers=headers, data=data, timeout=4)
            if scan_resp.status_code == 200:
                return {"status": "scanning", "message": "URL submitted for scanning."}
            return {"status": "not_found", "message": "URL not found in database and submission failed."}
        else:
            return {"status": "error", "message": f"VirusTotal returned status {resp.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def get_otx_report(hostname: str, api_key: str):
    if not hostname:
        return None
    
    # Check if host is raw IP
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        pass

    headers = {}
    if api_key:
        headers["X-OTX-API-KEY"] = api_key
        
    try:
        indicator_type = "IPv4" if is_ip else "domain"
        url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{hostname}/general"
        resp = requests.get(url, headers=headers, timeout=4)
        if resp.status_code == 200:
            data = resp.json()
            pulse_info = data.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            pulse_count = len(pulses)
            tags = set()
            for pulse in pulses:
                for tag in pulse.get("tags", []):
                    tags.add(tag)
            return {
                "status": "success",
                "pulse_count": pulse_count,
                "tags": list(tags)[:10],
                "threat_level": "High" if pulse_count > 5 else ("Medium" if pulse_count > 0 else "None")
            }
        else:
            return {"status": "error", "message": f"OTX returned status {resp.status_code}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

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

    # --- ADVANCED MODULES ---

    # 6. SSL Check
    ssl_info = get_ssl_details(hostname)
    if ssl_info:
        if "error" in ssl_info:
            if is_https:
                checks.append({
                    "name": "SSL Validity",
                    "passed": False,
                    "severity": "warning",
                    "message": f"Could not retrieve SSL certificate: {ssl_info['error']}"
                })
        else:
            if not ssl_info.get("is_valid", True):
                risk_points += 20
                checks.append({
                    "name": "SSL Validity",
                    "passed": False,
                    "severity": "danger",
                    "message": f"SSL Certificate is invalid or expired ({ssl_info.get('status')})."
                })
            else:
                checks.append({
                    "name": "SSL Validity",
                    "passed": True,
                    "severity": "safe",
                    "message": f"SSL certificate is active. Expires in {ssl_info.get('days_remaining')} days."
                })

    # 7. WHOIS Info
    whois_info = get_whois_details(hostname)

    # 8. VirusTotal threat report
    vt_info = get_virustotal_report(url, VIRUSTOTAL_API)
    if vt_info and vt_info.get("status") == "success":
        malicious = vt_info.get("malicious", 0)
        suspicious = vt_info.get("suspicious", 0)
        if malicious > 0:
            risk_points += min(malicious * 20, 50)
            checks.append({
                "name": "VirusTotal Detection",
                "passed": False,
                "severity": "danger",
                "message": f"URL flagged as malicious by {malicious} engine(s) on VirusTotal."
            })
        else:
            checks.append({
                "name": "VirusTotal Detection",
                "passed": True,
                "severity": "safe",
                "message": "VirusTotal scanned this URL and found 0 malicious detections."
            })

    # 9. OTX report
    otx_info = get_otx_report(hostname, OTX_API)
    if otx_info and otx_info.get("status") == "success":
        pulse_count = otx_info.get("pulse_count", 0)
        if pulse_count > 0:
            risk_points += min(pulse_count * 10, 30)
            checks.append({
                "name": "AlienVault OTX Pulse",
                "passed": False,
                "severity": "warning",
                "message": f"AlienVault OTX identified {pulse_count} active threat intelligence pulse(s) for this domain."
            })
        else:
            checks.append({
                "name": "AlienVault OTX Pulse",
                "passed": True,
                "severity": "safe",
                "message": "No active threat pulses found on AlienVault OTX for this domain."
            })

    # Final threat scoring evaluation
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
        "checks": checks,
        "ssl_info": ssl_info,
        "whois_info": whois_info,
        "virustotal": vt_info,
        "otx": otx_info
    }

@router.post("/scan")
def scan_url(payload: URLScanRequest, db: Session = Depends(get_db)):
    try:
        result = analyze_url(payload.url)
        # Log scan result to database
        db_log = ThreatLog(
            scan_type="url",
            target=result["url"],
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