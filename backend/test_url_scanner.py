from api.url import analyze_url

def run_tests():
    print("--- Running Advanced URL Scanner Integration Tests ---")
    
    # Test Case 1: Clean Safe HTTPS URL (e.g. google.com)
    print("\n[TEST 1] Running scan on https://google.com...")
    res1 = analyze_url("https://google.com")
    print(f"Result: Score={res1['risk_score']} | Status={res1['status']}")
    
    # Base checks
    assert res1['status'] == 'Safe', f"Expected Safe, got {res1['status']}"
    assert res1['details']['is_https'] == True
    assert res1['details']['is_shortener'] == False
    assert res1['details']['is_ip_address'] == False
    
    # SSL checks
    assert 'ssl_info' in res1, "ssl_info key missing in scan results"
    ssl = res1['ssl_info']
    print(f"SSL Status: {ssl.get('status')} | Common Name: {ssl.get('common_name')} | Issuer: {ssl.get('issuer')}")
    assert ssl['is_valid'] == True, "Expected valid SSL for google.com"
    assert 'Google' in ssl['issuer'] or 'GTS' in ssl['issuer'], f"Unexpected SSL Issuer: {ssl['issuer']}"
    print("[OK] SSL certificate details fetched successfully!")

    # WHOIS checks
    assert 'whois_info' in res1, "whois_info key missing in scan results"
    whois = res1['whois_info']
    print(f"WHOIS Registrar: {whois.get('registrar')} | Created: {whois.get('created_date')} | Expires: {whois.get('expiry_date')}")
    assert whois['registrar'] != 'Unknown', "Expected registrar for google.com to be retrieved"
    print("[OK] WHOIS domain registration details fetched successfully!")

    # Threat Intelligence integrations presence checks
    assert 'virustotal' in res1, "virustotal key missing in scan results"
    assert 'otx' in res1, "otx key missing in scan results"
    print(f"VirusTotal Status: {res1['virustotal'].get('status')}")
    print(f"AlienVault OTX Status: {res1['otx'].get('status')}")
    print("[OK] Threat intelligence structures integrated successfully!")

    # Test Case 2: Insecure IP Address URL
    print("\n[TEST 2] Running scan on http://192.168.1.1/login...")
    res2 = analyze_url("http://192.168.1.1/login")
    print(f"Result: Score={res2['risk_score']} | Status={res2['status']}")
    
    # Assert SSL is flagged as raw IP / N/A
    assert res2['ssl_info']['status'] in ["No SSL (Raw IP)", "No SSL/Error"]
    assert res2['whois_info']['registrar'] == "N/A (Raw IP)"
    print("[OK] Raw IP exclusions for SSL/WHOIS tested successfully!")

    print("\n[SUCCESS] All advanced integration checks completed successfully!")

if __name__ == "__main__":
    run_tests()
