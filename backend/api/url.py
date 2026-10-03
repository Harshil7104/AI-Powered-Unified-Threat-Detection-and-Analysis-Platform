# pyrefly: ignore [missing-import]
from fastapi import APIRouter, HTTPException, Depends
# pyrefly: ignore [missing-import]
from sqlalchemy.orm import Session 
# pyrefly: ignore [missing-import]
from database.db import get_db  
# pyrefly: ignore [missing-import]
from database.models import ThreatLog, User
# pyrefly: ignore [missing-import]
from api.auth import get_current_user
# pyrefly: ignore [missing-import]
from pydantic import BaseModel
# pyrefly: ignore [missing-import]
import re
from urllib.parse import urlparse
import ipaddress
import ssl
import socket
import base64
import requests
import os
from datetime import datetime
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv  
# pyrefly: ignore [missing-import]
from pathlib import Path

# Load dotenv variables
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
                
                issuer = dict(x[0] for x in cert.get('issuer', []))
                issuer_name = issuer.get('organizationName', issuer.get('commonName', 'Unknown'))
                
                subject = dict(x[0] for x in cert.get('subject', []))
                common_name = subject.get('commonName', 'Unknown')
                
                not_before_str = cert.get('notBefore')
                not_after_str = cert.get('notAfter')
                
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
        
    try:
        ipaddress.ip_address(domain)
        return {
            "registrar": "N/A (Raw IP)",
            "created_date": "N/A",
            "expiry_date": "N/A",
            "whois_server": "N/A",
            "domain_age_days": None,
            "domain_age_human": "N/A"
        }
    except ValueError:
        pass

    parts = domain.split(".")
    if len(parts) > 2:
        if parts[-2] in ["com", "co", "org", "net", "gov", "edu", "ac"]:
            clean_domain = ".".join(parts[-3:])
        else:
            clean_domain = ".".join(parts[-2:])
    else:
        clean_domain = domain

    try:
        iana_resp = query_whois("whois.iana.org", clean_domain)
        if not iana_resp:
            return {
                "registrar": "Unknown", "created_date": "Unknown", "expiry_date": "Unknown",
                "domain_age_days": None, "domain_age_human": "Unknown",
                "error": "WHOIS server unreachable"
            }
            
        refer_match = re.search(r"(?:refer|whois):\s*([a-zA-Z0-9\.\-]+)", iana_resp, re.IGNORECASE)
        whois_server = refer_match.group(1).strip() if refer_match else "whois.iana.org"
        
        whois_resp = query_whois(whois_server, clean_domain)
        if not whois_resp:
            whois_resp = iana_resp
            
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
            m2 = re.search(r"(\d{2}[\-\.]\d{2}[\-\.]\d{4})", d_str)
            if m2:
                return m2.group(1)
            return d_str.split()[0] if d_str else "Unknown"
            
        c_date = clean_date(created)
        
        # Calculate domain age
        age_days = None
        age_human = "Unknown"
        if c_date != "Unknown":
            try:
                date_match = re.search(r"(\d{4})-(\d{2})-(\d{2})", c_date)
                if date_match:
                    created_dt = datetime(int(date_match.group(1)), int(date_match.group(2)), int(date_match.group(3)))
                    age_days = (datetime.utcnow() - created_dt).days
                    if age_days >= 365:
                        yrs = age_days // 365
                        mos = (age_days % 365) // 30
                        age_human = f"{yrs} yr(s), {mos} mo(s) ({age_days} days)"
                    else:
                        age_human = f"{age_days} days"
            except Exception:
                pass

        return {
            "registrar": registrar,
            "created_date": c_date,
            "expiry_date": clean_date(expiry),
            "whois_server": whois_server,
            "domain_age_days": age_days,
            "domain_age_human": age_human
        }
    except Exception as e:
        return {
            "registrar": "Unknown",
            "created_date": "Unknown",
            "expiry_date": "Unknown",
            "domain_age_days": None,
            "domain_age_human": "Unknown",
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

def analyze_redirects(target_url: str):
    redirect_chain = []
    final_url = target_url
    has_redirect = False
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    try:
        # First attempt with HEAD request
        resp = requests.head(target_url, allow_redirects=True, timeout=3, headers=headers)
        final_url = resp.url
        if resp.history:
            has_redirect = True
            for h in resp.history:
                redirect_chain.append({"url": h.url, "status_code": h.status_code})
            redirect_chain.append({"url": resp.url, "status_code": resp.status_code})
    except Exception:
        try:
            # Fallback with GET request (streaming to avoid downloading full payload)
            resp = requests.get(target_url, allow_redirects=True, timeout=3, headers=headers, stream=True)
            final_url = resp.url
            if resp.history:
                has_redirect = True
                for h in resp.history:
                    redirect_chain.append({"url": h.url, "status_code": h.status_code})
                redirect_chain.append({"url": resp.url, "status_code": resp.status_code})
        except Exception:
            pass

    orig_parsed = urlparse(target_url if re.match(r'^[a-zA-Z]+://', target_url) else f"http://{target_url}")
    final_parsed = urlparse(final_url)
    
    orig_host = (orig_parsed.hostname or "").lower().removeprefix("www.")
    final_host = (final_parsed.hostname or "").lower().removeprefix("www.")
    
    cross_domain = bool(orig_host and final_host and orig_host != final_host)
    
    return {
        "has_redirect": has_redirect,
        "final_url": final_url,
        "hops": len(redirect_chain) if redirect_chain else 0,
        "chain": redirect_chain,
        "cross_domain": cross_domain,
        "original_host": orig_host,
        "final_host": final_host
    }

def analyze_subdomains(hostname: str):
    if not hostname:
        return {"is_nested": False, "subdomain_count": 0, "subdomains": [], "brand_impersonation": None, "base_domain": ""}
        
    try:
        ipaddress.ip_address(hostname)
        return {"is_nested": False, "subdomain_count": 0, "subdomains": [], "brand_impersonation": None, "base_domain": hostname}
    except ValueError:
        pass
        
    parts = hostname.lower().split(".")
    if len(parts) <= 2:
        return {"is_nested": False, "subdomain_count": 0, "subdomains": [], "brand_impersonation": None, "base_domain": hostname}
        
    if parts[-2] in ["com", "co", "org", "net", "gov", "edu", "ac"] and len(parts) > 2:
        base_domain = ".".join(parts[-3:])
        subdomain_parts = parts[:-3]
    else:
        base_domain = ".".join(parts[-2:])
        subdomain_parts = parts[:-2]
        
    subdomain_count = len(subdomain_parts)
    is_nested = subdomain_count >= 2
    
    brands = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook", "chase", "wellsfargo", "bankofamerica", "binance", "coinbase"]
    subdomain_str = ".".join(subdomain_parts)
    brand_found = None
    for brand in brands:
        if brand in subdomain_str and brand not in base_domain:
            brand_found = brand
            break
            
    return {
        "is_nested": is_nested,
        "subdomain_count": subdomain_count,
        "subdomains": subdomain_parts,
        "brand_impersonation": brand_found,
        "base_domain": base_domain
    }

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
    # Only flag brand names if the hostname is not that actual brand
    found_keywords = []
    for word in SUSPICIOUS_KEYWORDS:
        if word in full_str:
            if word in ["google", "paypal", "apple", "microsoft"] and hostname.lower().endswith(f"{word}.com"):
                continue
            found_keywords.append(word)

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

    # --- ADVANCED ENHANCEMENTS ---

    # 6. Suspicious / Nested Subdomain Detection
    subdomain_info = analyze_subdomains(hostname)
    if subdomain_info.get("brand_impersonation"):
        risk_points += 35
        checks.append({
            "name": "Subdomain Impersonation",
            "passed": False,
            "severity": "danger",
            "message": f"Subdomain impersonates brand '{subdomain_info['brand_impersonation']}' under root domain '{subdomain_info['base_domain']}'."
        })
    elif subdomain_info.get("is_nested"):
        risk_points += 15
        checks.append({
            "name": "Nested Subdomains",
            "passed": False,
            "severity": "warning",
            "message": f"Hostname has {subdomain_info['subdomain_count']} nested subdomains, which is frequently seen in phishing kits."
        })
    else:
        checks.append({
            "name": "Subdomain Structure",
            "passed": True,
            "severity": "safe",
            "message": "Subdomain hierarchy is standard with no suspicious nesting."
        })

    # 7. Redirect Chain & Final URL Analysis
    redirect_info = analyze_redirects(url)
    if redirect_info.get("cross_domain"):
        risk_points += 25
        checks.append({
            "name": "Redirect Chain",
            "passed": False,
            "severity": "warning",
            "message": f"URL redirects off-domain ({redirect_info['original_host']} -> {redirect_info['final_host']}). Final URL: {redirect_info['final_url']}."
        })
    elif redirect_info.get("hops", 0) > 2:
        risk_points += 15
        checks.append({
            "name": "Redirect Chain",
            "passed": False,
            "severity": "warning",
            "message": f"URL exhibits multiple redirect hops ({redirect_info['hops']} hops), potentially concealing final destination."
        })
    elif redirect_info.get("has_redirect"):
        checks.append({
            "name": "Redirect Chain",
            "passed": True,
            "severity": "safe",
            "message": f"URL redirects normally ({redirect_info['hops']} hop). Final destination: {redirect_info['final_url']}."
        })
    else:
        checks.append({
            "name": "Redirect Chain",
            "passed": True,
            "severity": "safe",
            "message": "Direct link with no intermediate redirects."
        })

    # 8. SSL Check
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

    # 9. WHOIS Info & Domain Age Calculation
    whois_info = get_whois_details(hostname)
    if whois_info:
        age_days = whois_info.get("domain_age_days")
        age_str = whois_info.get("domain_age_human", "Unknown")
        if age_days is not None:
            if age_days < 30:
                risk_points += 25
                checks.append({
                    "name": "Domain Age (WHOIS)",
                    "passed": False,
                    "severity": "danger",
                    "message": f"Newly registered domain ({age_str}). Phishing campaigns frequently deploy disposable domains under 30 days old."
                })
            elif age_days < 180:
                risk_points += 10
                checks.append({
                    "name": "Domain Age (WHOIS)",
                    "passed": True,
                    "severity": "warning",
                    "message": f"Domain is relatively new ({age_str})."
                })
            else:
                checks.append({
                    "name": "Domain Age (WHOIS)",
                    "passed": True,
                    "severity": "safe",
                    "message": f"Domain is established and mature ({age_str})."
                })

    # 10. VirusTotal threat report
    vt_info = get_virustotal_report(url, VIRUSTOTAL_API)
    if vt_info and vt_info.get("status") == "success":
        malicious = vt_info.get("malicious", 0)
        suspicious = vt_info.get("suspicious", 0)
        reputation = vt_info.get("reputation", 0)
        harmless = vt_info.get("harmless", 0)
        
        # Consider a true threat if malicious >= 3, or if malicious > 0 with non-positive reputation
        is_truly_malicious = (malicious >= 3) or (malicious > 0 and reputation <= 0 and harmless < 40)
        if is_truly_malicious:
            risk_points += min(malicious * 20, 50)
            checks.append({
                "name": "VirusTotal Detection",
                "passed": False,
                "severity": "danger",
                "message": f"URL flagged as malicious by {malicious} engine(s) on VirusTotal."
            })
        elif malicious > 0:
            checks.append({
                "name": "VirusTotal Detection",
                "passed": True,
                "severity": "warning",
                "message": f"URL flagged by {malicious} minor engine(s), but verified harmless by {harmless} major engines (Reputation: {reputation})."
            })
        else:
            checks.append({
                "name": "VirusTotal Detection",
                "passed": True,
                "severity": "safe",
                "message": "VirusTotal scanned this URL and found 0 malicious detections."
            })

    # 11. OTX report
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
            "hostname": hostname,
            "final_url": redirect_info.get("final_url", url),
            "redirect_hops": redirect_info.get("hops", 0),
            "domain_age": whois_info.get("domain_age_human") if whois_info else "Unknown",
            "nested_subdomains": subdomain_info.get("subdomain_count", 0)
        },
        "checks": checks,
        "ssl_info": ssl_info,
        "whois_info": whois_info,
        "redirect_info": redirect_info,
        "subdomain_info": subdomain_info,
        "virustotal": vt_info,
        "otx": otx_info
    }

@router.post("/scan")
def scan_url(
    payload: URLScanRequest, 
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        result = analyze_url(payload.url)
        # Log scan result to database with user association
        db_log = ThreatLog(
            user_id=current_user.id,
            scan_type="url",
            target=result["url"],
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
        raise HTTPException(status_code=500, detail=f"Internal scan error: {str(e)}")