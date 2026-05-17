"""
Test script to verify URL feature extraction fixes
"""
from feature_extraction import extract_features, is_ipv4, is_ipv6, is_ip_address
from train_model import make_fake_ssl

def test_ip_detection():
    """Test IP address detection"""
    print("Testing IP address detection...")
    
    # IPv4 tests
    assert is_ipv4("192.168.1.1") == True, "Valid IPv4 should be detected"
    assert is_ipv4("8.8.8.8") == True, "Valid IPv4 should be detected"
    assert is_ipv4("255.255.255.255") == True, "Valid IPv4 should be detected"
    assert is_ipv4("0.0.0.0") == True, "Valid IPv4 should be detected"
    assert is_ipv4("999.999.999.999") == False, "Invalid IPv4 should be rejected"
    assert is_ipv4("192.168.1") == False, "Invalid IPv4 should be rejected"
    assert is_ipv4("192.168.1.1.1") == False, "Invalid IPv4 should be rejected"
    
    # IPv6 tests
    assert is_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == True, "Valid IPv6 should be detected"
    assert is_ipv6("::1") == True, "Valid IPv6 should be detected"
    assert is_ipv6("fe80::1") == True, "Valid IPv6 should be detected"
    assert is_ipv6("192.168.1.1") == False, "IPv4 should not be detected as IPv6"
    
    # is_ip_address tests
    assert is_ip_address("192.168.1.1") == True, "IPv4 should be detected as IP"
    assert is_ip_address("2001:0db8:85a3::") == True, "IPv6 should be detected as IP"
    assert is_ip_address("google.com") == False, "Domain should not be detected as IP"
    
    print("✓ IP address detection tests passed")

def test_feature_extraction():
    """Test feature extraction with various URL types"""
    print("\nTesting feature extraction...")
    
    test_urls = [
        ("https://google.com", "Regular HTTPS domain"),
        ("http://example.com", "Regular HTTP domain"),
        ("http://192.168.1.1/login.php", "IPv4 address"),
        ("http://10.0.0.1/verify.html", "IPv4 address"),
        ("https://sub.example.com", "Subdomain"),
        ("https://a.b.c.example.com", "Multiple subdomains"),
        ("http://secure-login-verify.com", "Suspicious keyword"),
        ("http://user@phishing.com", "URL with @ symbol"),
        ("https://my-domain.com", "Domain with hyphen"),
        ("http://example.com/path/to/file.html", "URL with path"),
        ("http://example.com?query=param", "URL with query"),
    ]
    
    for url, description in test_urls:
        print(f"\n  Testing: {description}")
        print(f"  URL: {url}")
        ssl_data = make_fake_ssl(url)
        features = extract_features(url, ssl_data=ssl_data)
        
        feature_names = [
            "url_length", "has_https", "dot_count", "has_at",
            "has_hyphen", "subdomain_count", "has_keyword", "has_ip", "ssl_risk_score"
        ]
        
        for name, value in zip(feature_names, features):
            print(f"    {name}: {value}")
        
        # Verify specific cases
        if "192.168.1.1" in url or "10.0.0.1" in url:
            assert features[7] == 1, f"IP address should be detected: {url}"
            assert features[5] == 0, f"IP address should have 0 subdomains: {url}"
        
        if "sub.example.com" in url:
            assert features[5] == 1, f"Should have 1 subdomain: {url}"
        
        if "a.b.c.example.com" in url:
            assert features[5] == 3, f"Should have 3 subdomains: {url}"
        
        if "@" in url:
            assert features[3] == 1, f"Should detect @ symbol: {url}"
        
        if "secure-login" in url.lower():
            assert features[6] == 1, f"Should detect suspicious keyword: {url}"
    
    print("\n✓ Feature extraction tests passed")

def test_dot_count_fix():
    """Test that dot count only counts dots in hostname"""
    print("\nTesting dot count fix...")
    
    # URL with dots in path should only count dots in hostname
    url1 = "http://example.com/path/to/file.html"
    features1 = extract_features(url1, ssl_data=make_fake_ssl(url1))
    assert features1[2] == 1, f"Should count only 1 dot in hostname: {url1}"
    
    # URL with dots in query should only count dots in hostname
    url2 = "http://example.com?param=value.other"
    features2 = extract_features(url2, ssl_data=make_fake_ssl(url2))
    assert features2[2] == 1, f"Should count only 1 dot in hostname: {url2}"
    
    # Regular domain
    url3 = "http://google.com"
    features3 = extract_features(url3, ssl_data=make_fake_ssl(url3))
    assert features3[2] == 1, f"Should count 1 dot in hostname: {url3}"
    
    # Subdomain
    url4 = "http://sub.example.com"
    features4 = extract_features(url4, ssl_data=make_fake_ssl(url4))
    assert features4[2] == 2, f"Should count 2 dots in hostname: {url4}"
    
    print("✓ Dot count fix tests passed")

def test_ssl_improvement():
    """Test improved SSL fake function"""
    print("\nTesting SSL improvement...")
    
    # HTTPS with domain
    ssl1 = make_fake_ssl("https://google.com")
    assert ssl1["ssl_risk_score"] == 0, "HTTPS domain should have score 0"
    
    # HTTP with domain
    ssl2 = make_fake_ssl("http://example.com")
    assert ssl2["ssl_risk_score"] == 1, "HTTP domain should have score 1"
    
    # HTTPS with IP
    ssl3 = make_fake_ssl("https://192.168.1.1")
    assert ssl3["ssl_risk_score"] == 1, "HTTPS with IP should have score 1"
    
    # HTTP with IP
    ssl4 = make_fake_ssl("http://10.0.0.1")
    assert ssl4["ssl_risk_score"] == 2, "HTTP with IP should have score 2"
    
    print("✓ SSL improvement tests passed")

if __name__ == "__main__":
    try:
        test_ip_detection()
        test_feature_extraction()
        test_dot_count_fix()
        test_ssl_improvement()
        print("\n" + "="*50)
        print("All tests passed successfully!")
        print("="*50)
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        raise
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        raise
