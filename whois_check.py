import whois
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse


def check_whois(url):
    """
    Performs a WHOIS lookup on the domain from the URL.
    Returns a dict with domain info + a whois_risk_score.
    """
    # Add https:// prefix if no protocol is specified
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    result = {
        "domain":           None,
        "registrar":        "Unknown",
        "creation_date":    None,
        "expiration_date":  None,
        "domain_age_days":  None,
        "domain_age_str":   "Unknown",
        "is_new_domain":    False,
        "country":          "Unknown",
        "whois_risk_score": 0,
        "error":            None
    }

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or url
        # Strip www.
        if hostname.startswith("www."):
            hostname = hostname[4:]
        result["domain"] = hostname

        w = whois.whois(hostname)

        # Registrar
        result["registrar"] = w.registrar or "Unknown"

        # Country
        result["country"] = w.country or "Unknown"

        # --- Creation date ---
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        # Normalise to naive datetime if it came back as a string
        if isinstance(creation, str):
            for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%d-%b-%Y"):
                try:
                    creation = datetime.strptime(creation, fmt)
                    break
                except ValueError:
                    creation = None

        # Strip timezone info to make comparison safe (naive datetime)
        if isinstance(creation, datetime):
            if creation.tzinfo is not None:
                creation = creation.replace(tzinfo=None)

            result["creation_date"] = creation.strftime("%Y-%m-%d")
            now = datetime.now()
            age_days = (now - creation).days
            result["domain_age_days"] = age_days

            # Human-readable age
            if age_days < 30:
                result["domain_age_str"] = f"{age_days} day{'s' if age_days != 1 else ''}"
            elif age_days < 365:
                months = age_days // 30
                result["domain_age_str"] = f"{months} month{'s' if months != 1 else ''}"
            else:
                years  = age_days // 365
                months = (age_days % 365) // 30
                result["domain_age_str"] = f"{years} yr{'s' if years > 1 else ''}, {months} mo"

            # Domains < 6 months old are suspicious
            if age_days < 180:
                result["is_new_domain"] = True
                result["whois_risk_score"] += 1

        # --- Expiration date ---
        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]

        if isinstance(expiration, str):
            for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%d-%b-%Y"):
                try:
                    expiration = datetime.strptime(expiration, fmt)
                    break
                except ValueError:
                    expiration = None

        if isinstance(expiration, datetime):
            result["expiration_date"] = expiration.strftime("%Y-%m-%d")

    except Exception as e:
        result["error"] = f"WHOIS lookup failed: {str(e)}"
        result["whois_risk_score"] += 1

    return result
