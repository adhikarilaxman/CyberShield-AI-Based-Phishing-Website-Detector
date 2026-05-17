"""
Test why github.com URL is being flagged as phishing
"""
from feature_extraction import extract_features
from ssl_check import check_ssl_certificate
from train_model import make_fake_ssl

url = "https://github.com/adhikarilaxman"
print(f"Testing URL: {url}")
print()

# Extract features
ssl_data = check_ssl_certificate(url)
features = extract_features(url, ssl_data=ssl_data)

feature_names = [
    "url_length", "has_https", "dot_count", "has_at",
    "has_hyphen", "subdomain_count", "has_keyword", "has_ip", "ssl_risk_score"
]

print("Extracted Features:")
for name, value in zip(feature_names, features):
    print(f"  {name}: {value}")

print()
print("SSL Data:")
for key, value in ssl_data.items():
    print(f"  {key}: {value}")
