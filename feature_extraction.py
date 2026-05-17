import re
from urllib.parse import urlparse
from ssl_check import check_ssl_certificate

SUSPICIOUS_KEYWORDS = ['login', 'verify', 'bank', 'secure', 'update',
                       'account', 'confirm', 'signin', 'password', 'ebayisapi']

def is_ipv4(hostname):
    """
    Check if hostname is a valid IPv4 address.
    Validates that each octet is between 0-255.
    """
    if not hostname:
        return False
    octets = hostname.split('.')
    if len(octets) != 4:
        return False
    for octet in octets:
        if not octet.isdigit():
            return False
        num = int(octet)
        if num < 0 or num > 255:
            return False
    return True

def is_ipv6(hostname):
    """
    Check if hostname is an IPv6 address.
    """
    if not hostname:
        return False
    # IPv6 addresses contain colons
    if ':' not in hostname:
        return False
    # Basic IPv6 pattern check
    ipv6_pattern = r'^[0-9a-fA-F:]+$'
    if not re.match(ipv6_pattern, hostname):
        return False
    # Check for valid IPv6 structure (simplified)
    parts = hostname.split(':')
    if len(parts) < 3 or len(parts) > 8:
        return False
    return True

def is_ip_address(hostname):
    """
    Check if hostname is either IPv4 or IPv6.
    """
    return is_ipv4(hostname) or is_ipv6(hostname)

def extract_features(url, ssl_data=None):
    """
    Extracts 9 features from the URL.
    Accepts an optional pre-computed ssl_data dict to avoid a duplicate SSL network call.
    """
    # Add https:// prefix if no protocol is specified
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed   = urlparse(url)
    hostname = parsed.hostname or ""
    full_url = url.lower()

    # Feature 1–8
    url_length      = len(url)
    has_https       = 1 if url.startswith("https://") else 0
    dot_count       = hostname.count(".")  # Count dots only in hostname
    has_at          = 1 if "@" in url else 0
    has_hyphen      = 1 if "-" in hostname else 0
    
    # Fix subdomain count: exclude IP addresses
    if is_ip_address(hostname):
        subdomain_count = 0
    else:
        subdomain_count = max(0, hostname.count(".") - 1)
    
    has_keyword     = 1 if any(kw in full_url for kw in SUSPICIOUS_KEYWORDS) else 0
    has_ip          = 1 if is_ip_address(hostname) else 0

    # Feature 9: SSL risk score — reuse cached result if provided
    if ssl_data is None:
        ssl_data = check_ssl_certificate(url)
    ssl_risk = ssl_data["ssl_risk_score"]

    return [
        url_length,
        has_https,
        dot_count,
        has_at,
        has_hyphen,
        subdomain_count,
        has_keyword,
        has_ip,
        ssl_risk
    ]
