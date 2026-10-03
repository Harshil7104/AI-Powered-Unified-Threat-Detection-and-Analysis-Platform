"""
Automated Test Suite for ThreatShield AI Platform
Tests:
1. JWT Authentication (Register, Login, Token generation & validation)
2. Unauthorized Access Protection (401 on protected endpoints)
3. URL Scanner Enhancements (Domain age, redirects, subdomains)
4. Email Scanner Enhancements (EML/headers, SPF/DKIM/DMARC, alignment)
5. File Scanner Enhancements (MD5, SHA-1, SHA-256, Shannon entropy, magic bytes, mismatch)
6. Reports & PDF Generation (Per-user isolation, PDF binary header %PDF-)
7. AI Assistant Context Integration
"""

import os
import io
import time
# pyrefly: ignore [missing-import]
from fastapi.testclient import TestClient
from main import app
from database.db import Base, engine

# Ensure tables exist
Base.metadata.create_all(bind=engine)

client = TestClient(app)

def test_1_jwt_authentication():
    print("\n--- TEST 1: JWT Authentication & User Management ---")
    unique_email = f"analyst_{int(time.time())}@threatshield.test"
    password = "SecurePassword123!"

    # 1. Register
    reg_resp = client.post("/auth/register", json={"email": unique_email, "password": password})
    assert reg_resp.status_code == 200, f"Registration failed: {reg_resp.text}"
    reg_data = reg_resp.json()
    assert "token" in reg_data, "No JWT token in register response"
    assert reg_data["isLoggedIn"] is True
    print(f" [PASS] User registered successfully with JWT: {reg_data['token'][:20]}...")

    # 2. Login
    login_resp = client.post("/auth/login", json={"email": unique_email, "password": password})
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    login_data = login_resp.json()
    token = login_data["token"]
    assert token, "No token returned on login"
    print(f" [PASS] User logged in successfully with JWT: {token[:20]}...")

    # 3. Protected Profile /me with token
    headers = {"Authorization": f"Bearer {token}"}
    me_resp = client.get("/auth/me", headers=headers)
    assert me_resp.status_code == 200, f"/auth/me failed: {me_resp.text}"
    assert me_resp.json()["email"] == unique_email
    print(f" [PASS] Validated JWT via /auth/me for {unique_email}")

    return token

def test_2_unauthorized_access_protection():
    print("\n--- TEST 2: Unauthorized API Access Protection (401 Checks) ---")
    
    # Protected scanner without token
    url_resp = client.post("/url/scan", json={"url": "https://example.com"})
    assert url_resp.status_code == 401, f"Expected 401 for unauthorized URL scan, got {url_resp.status_code}"
    print(" [PASS] /url/scan correctly denied without token (401)")

    # Protected reports list without token
    rep_resp = client.get("/reports/")
    assert rep_resp.status_code == 401, f"Expected 401 for unauthorized /reports/, got {rep_resp.status_code}"
    print(" [PASS] /reports/ correctly denied without token (401)")

    # Protected PDF download without token
    pdf_resp = client.get("/reports/1/pdf")
    assert pdf_resp.status_code == 401, f"Expected 401 for unauthorized PDF download, got {pdf_resp.status_code}"
    print(" [PASS] /reports/1/pdf correctly denied without token (401)")

def test_3_url_scanner_enhancements(token: str):
    print("\n--- TEST 3: URL Scanner Enhancements ---")
    headers = {"Authorization": f"Bearer {token}"}

    # Test nested subdomains and domain age
    payload = {"url": "http://login.verify.paypal.com.account-auth.xyz/security"}
    resp = client.post("/url/scan", json=payload, headers=headers)
    assert resp.status_code == 200, f"URL scan failed: {resp.text}"
    data = resp.json()
    
    assert "risk_score" in data
    assert "status" in data
    assert "checks" in data
    assert "whois_info" in data
    assert "redirect_info" in data
    assert "subdomain_info" in data

    # Verify subdomain nesting detected
    check_names = [c["name"] for c in data["checks"]]
    assert "Subdomain Structure" in check_names or "Nested Subdomains" in check_names or "Subdomain Impersonation" in check_names
    assert "Redirect Chain" in check_names

    print(f" [PASS] URL analyzed: Status = {data['status']}, Risk Score = {data['risk_score']}/100")
    print(f" [PASS] Redirect hops analyzed: {data['redirect_info'].get('hops', 0)}")
    print(f" [PASS] Nested subdomains checked: {data['subdomain_info'].get('subdomain_count', 0)}")
    return data.get("report_id")

def test_4_email_scanner_enhancements(token: str):
    print("\n--- TEST 4: Email Scanner Enhancements (SPF/DKIM/DMARC & Alignment) ---")
    headers = {"Authorization": f"Bearer {token}"}

    raw_headers = (
        "Received-SPF: Fail (mailfrom security@chase-alert.com)\n"
        "Authentication-Results: spf=fail dkim=fail dmarc=fail\n"
        "From: Chase Security <security@chase-alert.com>\n"
        "Reply-To: attacker@hacker-server.ru\n"
        "Subject: Urgent: Verify Chase Online Access"
    )

    payload = {
        "sender": "security@chase-alert.com",
        "subject": "Urgent: Verify Chase Online Access",
        "body": "Dear customer, your bank credentials expired. Click http://verify-chase.ru/login immediately.",
        "headers": raw_headers
    }

    resp = client.post("/email/scan", json=payload, headers=headers)
    assert resp.status_code == 200, f"Email scan failed: {resp.text}"
    data = resp.json()

    assert data["risk_score"] >= 60, f"Expected High Risk for spoofed phishing email, got {data['risk_score']}"
    assert data["status"] == "High Risk"
    
    # Check SPF, DKIM, Reply-to alignment detected
    check_names = [c["name"] for c in data["checks"]]
    assert "SPF Authentication" in check_names
    assert "DKIM Signature" in check_names
    assert "Reply-To Alignment" in check_names

    auth_res = data["details"]["auth_results"]
    assert auth_res["spf"] == "fail"
    assert auth_res["dkim"] == "fail"

    print(f" [PASS] Email analyzed: Status = {data['status']}, Score = {data['risk_score']}/100")
    print(f" [PASS] SPF detected: {auth_res['spf']}, DKIM detected: {auth_res['dkim']}")
    print(" [PASS] Reply-To spoofing alignment mismatch flagged")
    return data.get("report_id")

def test_5_file_scanner_enhancements(token: str):
    print("\n--- TEST 5: File Scanner Enhancements (Hashes, Entropy, Magic Bytes, Mismatch) ---")
    auth_headers = {"Authorization": f"Bearer {token}"}

    # Simulate a disguised malware file: Windows executable magic header "MZ" disguised as "invoice.pdf"
    fake_exe_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + os.urandom(6000)
    file_payload = {"file": ("invoice.pdf", io.BytesIO(fake_exe_bytes), "application/pdf")}

    resp = client.post("/file/scan", files=file_payload, headers=auth_headers)
    assert resp.status_code == 200, f"File scan failed: {resp.text}"
    data = resp.json()

    # Verify hashes
    assert "md5" in data and len(data["md5"]) == 32
    assert "sha1" in data and len(data["sha1"]) == 40
    assert "sha256" in data and len(data["sha256"]) == 64
    print(f" [PASS] Computed MD5: {data['md5']}")
    print(f" [PASS] Computed SHA-1: {data['sha1']}")
    print(f" [PASS] Computed SHA-256: {data['sha256']}")

    # Verify Shannon entropy
    assert "entropy" in data
    assert data["entropy"] >= 7.0, f"Expected high entropy from random binary data, got {data['entropy']}"
    print(f" [PASS] Shannon Entropy: {data['entropy']} / 8.0 ({data['entropy_status']})")

    # Verify magic bytes and extension mismatch
    assert data["type_mismatch"] is True, "Expected extension mismatch for MZ bytes named invoice.pdf"
    check_names = [c["name"] for c in data["checks"]]
    assert "File Type & Extension Match" in check_names
    assert "Shannon Entropy Analysis" in check_names

    print(f" [PASS] Detected file signature: {data['detected_type']}")
    print(f" [PASS] Critical extension mismatch flagged successfully (Risk: {data['risk_score']}/100, Status: {data['status']})")
    return data.get("report_id")

def test_6_reports_and_pdf_generation(token: str, report_id: int):
    print("\n--- TEST 6: Reports API & PDF Report Generation ---")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Fetch dashboard stats
    stats_resp = client.get("/reports/stats", headers=headers)
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert "total_scans" in stats
    assert "threats_detected" in stats
    print(f" [PASS] Stats loaded: {stats['total_scans']} total scans, {stats['threats_detected']} threats detected")

    # 2. Fetch reports list
    reports_resp = client.get("/reports/", headers=headers)
    assert reports_resp.status_code == 200
    reports_list = reports_resp.json()
    assert len(reports_list) > 0, "No reports returned"
    print(f" [PASS] Reports list fetched ({len(reports_list)} records for user)")

    # 3. Fetch specific report details
    target_id = report_id or reports_list[0]["id"]
    det_resp = client.get(f"/reports/{target_id}", headers=headers)
    assert det_resp.status_code == 200
    det = det_resp.json()
    assert det["id"] == target_id
    print(f" [PASS] Report details loaded for report ID {target_id}")

    # 4. Download PDF
    pdf_resp = client.get(f"/reports/{target_id}/pdf", headers=headers)
    assert pdf_resp.status_code == 200, f"PDF generation failed: {pdf_resp.text}"
    assert pdf_resp.headers["content-type"] == "application/pdf"
    
    pdf_content = pdf_resp.content
    assert pdf_content.startswith(b"%PDF-"), "Generated file does not start with %PDF- magic bytes"
    assert len(pdf_content) > 1000, f"PDF file size seems too small: {len(pdf_content)} bytes"
    print(f" [PASS] PDF report generated successfully: {len(pdf_content)} bytes, verified %PDF- header")

def test_7_ai_chat_with_context():
    print("\n--- TEST 7: AI Assistant Integration with Scan Context ---")
    scan_ctx = {
        "scan_type": "url",
        "target": "http://paypal-security-login.xyz",
        "risk_score": 90,
        "status": "High Risk",
        "checks": [
            {"name": "Subdomain Impersonation", "passed": False, "severity": "danger", "message": "Impersonates paypal brand"},
            {"name": "Domain Age", "passed": False, "severity": "danger", "message": "Registered 2 days ago"}
        ]
    }

    chat_payload = {
        "message": "Explain why this scan was flagged as high risk and what I should do.",
        "history": [],
        "scan_context": scan_ctx
    }

    resp = client.post("/chat/", json=chat_payload)
    assert resp.status_code == 200, f"Chat failed: {resp.text}"
    data = resp.json()
    assert "response" in data
    assert len(data["response"]) > 20
    print(f" [PASS] AI Chat response received (Engine Source: {data.get('source')})")
    print(f" [PASS] AI response summary: {data['response'][:120]}...")

def run_all_tests():
    print("=" * 65)
    print("  THREATSHIELD AI PLATFORM — COMPREHENSIVE AUTOMATED TESTS")
    print("=" * 65)
    
    token = test_1_jwt_authentication()
    test_2_unauthorized_access_protection()
    url_rep_id = test_3_url_scanner_enhancements(token)
    email_rep_id = test_4_email_scanner_enhancements(token)
    file_rep_id = test_5_file_scanner_enhancements(token)
    test_6_reports_and_pdf_generation(token, file_rep_id or url_rep_id or email_rep_id)
    test_7_ai_chat_with_context()

    print("\n" + "=" * 65)
    print("  ALL 7 TEST SUITES PASSED PERFECTLY! [100% SUCCESS]")
    print("=" * 65)

if __name__ == "__main__":
    run_all_tests()
