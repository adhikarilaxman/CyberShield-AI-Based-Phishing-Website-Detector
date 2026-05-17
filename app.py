from flask import Flask, render_template, request, send_file
import pickle
import random
import io
from datetime import datetime
from urllib.parse import urlparse
from feature_extraction import extract_features
from ssl_check import check_ssl_certificate
# Delay heavy imports (pandas, whois, openpyxl) until routes that need them

app = Flask(__name__)

# In-memory store — cleared when app restarts
recent_reports = []

# Load the trained model
try:
    with open('model.pkl', 'rb') as f:
        model = pickle.load(f)
except FileNotFoundError:
    print("model.pkl not found. Please run train_model.py first.")
    model = None
except Exception as e:
    # Could be missing sklearn or other dependency when unpickling
    print(f"Could not load model.pkl: {e}")
    # Fall back to a lightweight heuristic model so the app can run
    try:
        from fallback_model import FallbackModel
        model = FallbackModel()
        print("Loaded fallback heuristic model (no scikit-learn required).")
    except Exception as e2:
        print(f"Failed to load fallback model: {e2}")
        model = None

SUSPICIOUS_KEYWORDS = ['login', 'verify', 'bank', 'secure', 'update',
                       'account', 'confirm', 'signin', 'password', 'ebayisapi',
                       'support', 'billing', 'wallet', 'recover', 'suspension']

def rule_based_score(url, features_list, ssl_data):
    """
    Returns (score, reasons).
    score >= 4  → override to Phishing regardless of ML.
    Each signal adds to the score; reasons list explains what triggered.
    """
    score   = 0
    reasons = []
    lower   = url.lower()

    # 1. Suspicious keywords in URL (each keyword found adds 1, max 3)
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower]
    if hits:
        pts = min(len(hits), 3)
        score += pts
        reasons.append(f"Suspicious keywords found: {', '.join(hits[:3])}")

    # 2. Has @ symbol — almost always phishing
    if features_list[3] == 1:
        score += 3
        reasons.append("URL contains '@' symbol")

    # 3. IP address as hostname
    if features_list[7] == 1:
        score += 3
        reasons.append("IP address used as hostname")

    # 4. Very long URL
    if features_list[0] > 100:
        score += 2
        reasons.append(f"Very long URL ({features_list[0]} chars)")
    elif features_list[0] > 75:
        score += 1
        reasons.append(f"Long URL ({features_list[0]} chars)")

    # 5. Excessive subdomains (> 2)
    if features_list[5] > 2:
        score += 2
        reasons.append(f"Excessive subdomains ({features_list[5]})")
    elif features_list[5] == 2:
        score += 1

    # 6. Hyphen in domain
    if features_list[4] == 1:
        score += 1
        reasons.append("Hyphen present in domain")

    # 7. High dot count relative to URL (lots of dots = suspicious path/subdomain abuse)
    if features_list[2] > 5:
        score += 1
        reasons.append(f"High dot count ({features_list[2]})")

    # 8. SSL risk
    ssl_risk = ssl_data.get('ssl_risk_score', 0)
    if ssl_risk >= 2:
        score += 2
        reasons.append(f"SSL risk score: {ssl_risk}/4")
    elif ssl_risk == 1:
        score += 1

    # 9. No HTTPS
    if features_list[1] == 0:
        score += 1
        reasons.append("No HTTPS")

    return score, reasons


@app.route('/')
def index():
    display_reports = list(reversed(recent_reports[-4:]))
    return render_template('index.html', reports=display_reports)


@app.route('/reports')
def reports():
    all_reports = list(reversed(recent_reports))
    total      = len(all_reports)
    critical   = sum(1 for r in all_reports if r['status'] == 'CRITICAL')
    suspicious = sum(1 for r in all_reports if r['status'] == 'SUSPICIOUS')
    safe       = sum(1 for r in all_reports if r['status'] == 'SAFE')
    return render_template('reports.html',
                           reports=all_reports,
                           total=total,
                           critical=critical,
                           suspicious=suspicious,
                           safe=safe)


@app.route('/export')
def export():
    """Generate and download an Excel report."""
    if not recent_reports:
        return "No scan data to export yet. Run some URL scans first.", 400

    # Import here to avoid requiring openpyxl at app import time
    from excel_export import generate_excel

    xlsx_bytes = generate_excel(list(recent_reports))
    filename   = f"CyberShield_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return send_file(
        io.BytesIO(xlsx_bytes),
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


@app.route('/predict', methods=['POST'])
def predict():
    if not model:
        return "Model not trained. Please run train_model.py first.", 500

    url = request.form.get('url', '').strip()
    if not url:
        return "No URL provided", 400

    # Add https:// prefix if no protocol is specified
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    # Run SSL check ONCE — reuse in feature extraction and template
    ssl_data      = check_ssl_certificate(url)
    features_list = extract_features(url, ssl_data=ssl_data)
    # Import whois-check lazily to avoid heavy deps at import-time
    try:
        import pandas as pd
    except Exception:
        pd = None

    from whois_check import check_whois
    whois_data    = check_whois(url)

    # ── ML prediction ───────────────────────────────────────────────────────
    feature_names = [
        "url_length", "has_https", "dot_count", "has_at",
        "has_hyphen", "subdomain_count", "has_keyword", "has_ip", "ssl_risk_score"
    ]
    # Build prediction input — prefer pandas DataFrame if available
    if pd is not None:
        X_pred = pd.DataFrame([features_list], columns=feature_names)
    else:
        X_pred = [features_list]
    ml_pred        = model.predict(X_pred)[0]
    ml_proba       = model.predict_proba(X_pred)[0]

    # ── Rule-based layer ────────────────────────────────────────────────────
    rb_score, rb_reasons = rule_based_score(url, features_list, ssl_data)

    # ── Hybrid decision ─────────────────────────────────────────────────────
    # Rule-based overrides ML when strong signals detected (score >= 4)
    if rb_score >= 4:
        prediction  = "Phishing"
        # Confidence: blend rule-based signal strength with ML phishing prob
        rule_conf   = min(50 + rb_score * 5, 97)
        ml_conf     = ml_proba[1] * 100
        confidence  = round(max(rule_conf, ml_conf), 2)
    elif ml_pred == 1:
        prediction  = "Phishing"
        confidence  = round(ml_proba[1] * 100, 2)
    else:
        # ML says Legitimate, rule score 2-3 → demote confidence
        prediction  = "Legitimate"
        penalty     = rb_score * 4          # each rule signal lowers confidence
        confidence  = round(max(ml_proba[0] * 100 - penalty, 50), 2)

    # ── Status label ────────────────────────────────────────────────────────
    if prediction == "Phishing":
        status = "CRITICAL" if confidence > 80 else "SUSPICIOUS"
    else:
        status = "SAFE"

    # ── Save to in-memory log ───────────────────────────────────────────────
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else url

    recent_reports.append({
        "id":         f"#TR-{random.randint(1000, 9999)}",
        "domain":     domain,
        "prediction": prediction,
        "status":     status,
        "confidence": confidence,
        "time":       datetime.now().strftime("%I:%M %p")
    })
    if len(recent_reports) > 100:
        recent_reports.pop(0)

    # ── Features dict for display ───────────────────────────────────────────
    features_dict = {
        'URL Length':                 features_list[0],
        'Has HTTPS':                  'Yes' if features_list[1] == 1 else 'No',
        'Number of Dots':             features_list[2],
        'Has "@" Symbol':             'Yes' if features_list[3] == 1 else 'No',
        'Has Hyphen in Domain':       'Yes' if features_list[4] == 1 else 'No',
        'Number of Subdomains':       features_list[5],
        'Has Suspicious Keywords':    'Yes' if features_list[6] == 1 else 'No',
        'Has IP Address as Hostname': 'Yes' if features_list[7] == 1 else 'No',
        'SSL Risk Score':             features_list[8],
    }

    return render_template('result.html',
                           url=url,
                           prediction=prediction,
                           confidence=confidence,
                           features=features_dict,
                           ssl=ssl_data,
                           whois=whois_data,
                           rb_score=rb_score,
                           rb_reasons=rb_reasons)


if __name__ == '__main__':
    app.run(debug=True)
