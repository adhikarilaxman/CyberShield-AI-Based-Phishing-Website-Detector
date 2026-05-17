"""
Test SSL check function to verify it's working correctly
"""
from ssl_check import check_ssl_certificate

# Test with a real HTTPS URL
print("Testing SSL check with google.com...")
try:
    result = check_ssl_certificate("https://google.com")
    print("SSL check result:")
    for key, value in result.items():
        print(f"  {key}: {value}")
except Exception as e:
    print(f"Error: {e}")

# Test with HTTP URL
print("\nTesting SSL check with http://example.com...")
try:
    result = check_ssl_certificate("http://example.com")
    print("SSL check result:")
    for key, value in result.items():
        print(f"  {key}: {value}")
except Exception as e:
    print(f"Error: {e}")
