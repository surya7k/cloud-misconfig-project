import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os


DATA_PROCESSED = "data/processed"
MODELS_DIR     = "models"


# ✅ CHANGED: added allow_wildcard_action, allow_wildcard_resource, all_ports_open
FEATURE_COLS = [
    "public_access_enabled", "encryption_enabled",
    "versioning_enabled", "logging_enabled",
    "has_wildcard_permission", "has_admin_privilege",
    "has_priv_esc_potential", "policy_length",
    "inbound_rule_count", "outbound_rule_count",
    "open_ports_to_world", "ssh_open_to_world", "rdp_open_to_world",
    "allow_wildcard_action", "allow_wildcard_resource", "all_ports_open",
]


def load_data():
    df = pd.read_csv(f"{DATA_PROCESSED}/labeled_features.csv")
    X = df[FEATURE_COLS].values
    y = df["label"].values
    return X, y, df


def evaluate_model(name, model, X, y):
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scoring = ["precision", "recall", "f1"]
    scores = cross_validate(model, X, y, cv=cv, scoring=scoring)

    print(f"\n── {name} (5-Fold Cross Validation) ──")
    print(f"  Precision : {scores['test_precision'].mean():.3f} ± {scores['test_precision'].std():.3f}")
    print(f"  Recall    : {scores['test_recall'].mean():.3f} ± {scores['test_recall'].std():.3f}")
    print(f"  F1 Score  : {scores['test_f1'].mean():.3f} ± {scores['test_f1'].std():.3f}")
    return scores


def main():
    os.makedirs(MODELS_DIR, exist_ok=True)

    X, y, df = load_data()
    print(f"Dataset: {len(df)} records | Misconfigured: {y.sum()} | Secure: {(y==0).sum()}")

    # Scale features for Logistic Regression
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ── Logistic Regression (baseline) ──────────────────────────────────────
    lr = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
    lr_scores = evaluate_model("Logistic Regression (Baseline)", lr, X_scaled, y)

    # ── Random Forest (primary) ──────────────────────────────────────────────
    # ✅ CHANGED: tuned hyperparameters to improve recall and F1
    rf = RandomForestClassifier(
        n_estimators=200,      # keep this increase
        class_weight="balanced",
        random_state=42
    )
    rf_scores = evaluate_model("Random Forest (Primary)", rf, X_scaled, y)

    # ── Train final Random Forest on all data for feature importance ─────────
    rf.fit(X_scaled, y)
    joblib.dump(rf, f"{MODELS_DIR}/random_forest.pkl")
    joblib.dump(scaler, f"{MODELS_DIR}/scaler.pkl")

    print("\n── Feature Importance (Random Forest) ──")
    importances = pd.Series(rf.feature_importances_, index=FEATURE_COLS)
    importances = importances.sort_values(ascending=False)
    for feat, score in importances.items():
        print(f"  {feat:<30} {score:.4f}")

    # ── Save results summary ─────────────────────────────────────────────────
    results = pd.DataFrame({
        "model": ["Logistic Regression", "Random Forest"],
        "precision_mean": [lr_scores["test_precision"].mean(), rf_scores["test_precision"].mean()],
        "recall_mean":    [lr_scores["test_recall"].mean(),    rf_scores["test_recall"].mean()],
        "f1_mean":        [lr_scores["test_f1"].mean(),        rf_scores["test_f1"].mean()],
    })
    results.to_csv(f"{DATA_PROCESSED}/model_results.csv", index=False)
    print("\n── Model Comparison ──")
    print(results.to_string(index=False))


if __name__ == "__main__":
    main()
