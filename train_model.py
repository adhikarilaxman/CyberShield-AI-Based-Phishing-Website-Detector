import pickle
from feature_extraction import extract_features


def make_fake_ssl(url):
    """
    During training we skip live SSL network calls.
    We approximate ssl_risk_score from URL structure only to better match real SSL checks.
    
    Scoring logic (matches ssl_check.py behavior):
      - No HTTPS          → score 1  (cannot have valid cert)
      - Has HTTPS         → score 0  (assume cert present; ML learns other signals)
      - IP address as hostname → score 1  (suspicious, unlikely to have valid cert)
    """
    from urllib.parse import urlparse
    from feature_extraction import is_ip_address
    
    # Add https:// prefix if no protocol is specified
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    
    has_https = url.lower().startswith("https://")
    is_ip = is_ip_address(hostname)
    
    # Base score: no HTTPS
    ssl_risk_score = 1 if not has_https else 0
    
    # Additional risk: IP address as hostname
    if is_ip:
        ssl_risk_score += 1
    
    return {"ssl_risk_score": ssl_risk_score}


def main():
    # Delay heavy imports until runtime so helper functions can be imported
    # without requiring pandas/scikit-learn to be installed.
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.linear_model import LogisticRegression
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

    print("Loading dataset...")
    df = pd.read_csv('dataset.csv')
    print(f"  {len(df)} rows loaded  ({df['label'].sum()} phishing, "
          f"{(df['label']==0).sum()} legitimate)")

    print("Extracting features (no live SSL calls)...")
    features_list = df['url'].apply(
        lambda url: extract_features(url, ssl_data=make_fake_ssl(url))
    )

    X = pd.DataFrame(features_list.tolist(), columns=[
        "url_length", "has_https", "dot_count", "has_at",
        "has_hyphen", "subdomain_count", "has_keyword", "has_ip", "ssl_risk_score"
    ])
    y = df['label']

    print("Splitting dataset (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000),
        "Decision Tree":       DecisionTreeClassifier(random_state=42,
                                                       max_depth=8,
                                                       min_samples_split=4),
        "Random Forest":       RandomForestClassifier(n_estimators=100,
                                                       random_state=42,
                                                       max_depth=8),
    }

    best_model = None
    best_acc   = 0.0

    for name, mdl in models.items():
        print(f"\n--- Training {name} ---")
        mdl.fit(X_train, y_train)
        preds = mdl.predict(X_test)
        acc   = accuracy_score(y_test, preds)
        print(f"Accuracy : {acc:.4f}")
        print("Report   :\n", classification_report(y_test, preds))
        print("Confusion:\n", confusion_matrix(y_test, preds))

        if acc > best_acc:
            best_acc   = acc
            best_model = mdl
            best_name  = name

    print(f"\nSaving best model ({best_name}, acc={best_acc:.4f}) as model.pkl")
    with open('model.pkl', 'wb') as f:
        pickle.dump(best_model, f)
    print("Done! model.pkl saved.")


if __name__ == '__main__':
    main()
