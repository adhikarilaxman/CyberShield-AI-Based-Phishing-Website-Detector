import ssl
import socket
import datetime
from urllib.parse import urlparse

def check_ssl_certificate(url):
    """
    Checks SSL certificate of a URL.
    Returns a dict with all details + a risk score (0 = safe, higher = more suspicious).
    """
    # Add https:// prefix if no protocol is specified
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    result = {
        "has_https":       False,
        "cert_found":      False,
        "is_expired":      False,
        "expiring_soon":   False,
        "days_remaining":  None,
        "issuer":          "Unknown",
        "is_self_signed":  False,
        "domain_match":    False,
        "ssl_risk_score":  0,
        "error":           None
    }

    # Check 1 — Does URL use HTTPS?
    if not url.startswith("https://"):
        result["has_https"] = False
        result["ssl_risk_score"] += 1
        result["error"] = "No HTTPS"
        return result

    result["has_https"] = True

    # Parse the hostname
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            result["error"] = "Could not parse hostname"
            result["ssl_risk_score"] += 1
            return result
    except Exception as e:
        result["error"] = str(e)
        result["ssl_risk_score"] += 1
        return result

    # Check 2 — Can we fetch the certificate?
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        result["cert_found"] = True

        # Check 3 — Expiry date
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_date = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            now = datetime.datetime.utcnow()
            delta = expire_date - now
            result["days_remaining"] = delta.days

            if delta.days < 0:
                result["is_expired"] = True
                result["ssl_risk_score"] += 1
            elif delta.days < 30:
                result["expiring_soon"] = True
                result["ssl_risk_score"] += 1

        # Check 4 — Issuer (self-signed check)
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        subject_dict = dict(x[0] for x in cert.get("subject", []))

        issuer_org = issuer_dict.get("organizationName", "Unknown")
        subject_org = subject_dict.get("organizationName", "Unknown")
        result["issuer"] = issuer_org

        # Self-signed = issuer and subject are the same
        if issuer_dict == subject_dict:
            result["is_self_signed"] = True
            result["ssl_risk_score"] += 1

        # Domain match check
        cert_cn = subject_dict.get("commonName", "")
        if cert_cn:
            if cert_cn.startswith("*."):
                # Wildcard cert — check if hostname ends with the wildcard base
                wildcard_base = cert_cn[2:]
                result["domain_match"] = hostname.endswith(wildcard_base)
            else:
                result["domain_match"] = (cert_cn == hostname)

            if not result["domain_match"]:
                result["ssl_risk_score"] += 1

    except ssl.SSLCertVerificationError:
        result["cert_found"] = False
        result["is_self_signed"] = True
        result["ssl_risk_score"] += 2
        result["error"] = "SSL verification failed (likely self-signed)"

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["cert_found"] = False
        result["ssl_risk_score"] += 1
        result["error"] = f"Could not connect: {str(e)}"

    except Exception as e:
        result["error"] = str(e)

    return result
