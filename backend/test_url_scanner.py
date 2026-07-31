from api.url import analyze_url

def run_tests():
    print("--- Running Week 2 URL Scanner Rule Tests ---")
    
    # Test Case 1: Clean Safe HTTPS URL
    res1 = analyze_url("https://google.com")
    print(f"\nTest 1 (Safe HTTPS): Score={res1['risk_score']} | Status={res1['status']}")
    assert res1['status'] == 'Safe', f"Expected Safe, got {res1['status']}"
    assert res1['details']['is_https'] == True
    assert res1['details']['is_shortener'] == False
    assert res1['details']['is_ip_address'] == False
    print("[OK] Test 1 Passed!")

    # Test Case 2: Insecure IP Address URL with Suspicious Keywords
    res2 = analyze_url("http://192.168.1.1/login-verify-account-update")
    print(f"\nTest 2 (IP + Insecure + Keywords): Score={res2['risk_score']} | Status={res2['status']}")
    assert res2['status'] in ['High Risk', 'Suspicious'], f"Expected High Risk/Suspicious, got {res2['status']}"
    assert res2['details']['is_https'] == False
    assert res2['details']['is_ip_address'] == True
    assert 'login' in res2['details']['found_keywords']
    print("[OK] Test 2 Passed!")

    # Test Case 3: Known URL Shortener
    res3 = analyze_url("https://bit.ly/3x89a")
    print(f"\nTest 3 (Shortener): Score={res3['risk_score']} | Status={res3['status']}")
    assert res3['details']['is_shortener'] == True
    print("[OK] Test 3 Passed!")

    # Test Case 4: Long URL threshold
    long_url = "https://example.com/" + "a" * 80
    res4 = analyze_url(long_url)
    print(f"\nTest 4 (Unusually Long URL): Score={res4['risk_score']} | Status={res4['status']}")
    assert res4['details']['url_length'] > 75
    print("[OK] Test 4 Passed!")

    print("\n[SUCCESS] All 4 URL Threat Scanner Rule Tests Passed Successfully!")

if __name__ == "__main__":
    run_tests()
