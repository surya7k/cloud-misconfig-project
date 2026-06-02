import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_validate, cross_val_predict
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_score, recall_score, f1_score, fbeta_score,
    roc_curve, auc, precision_recall_curve
)
import joblib
import os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

try:
    from src.schema import (
        BASE_FEATURE_COLS,
        EXTENDED_FEATURE_COLS,
        FEATURE_COLS,
        S3_DERIVED_COLS,
        S3_THRESHOLD_DEFAULT,
    )
except ModuleNotFoundError:
    from schema import (
        BASE_FEATURE_COLS,
        EXTENDED_FEATURE_COLS,
        FEATURE_COLS,
        S3_DERIVED_COLS,
        S3_THRESHOLD_DEFAULT,
    )


DATA_PROCESSED = "data/processed"
MODELS_DIR     = "models"
OUTPUTS_DIR    = "outputs"

S3_THRESHOLD = S3_THRESHOLD_DEFAULT  # overridden by F2-optimal threshold during training


def find_optimal_s3_threshold(y_true, y_proba, s3_mask):
    """Find the S3 threshold that maximizes F2 score (recall-weighted) while keeping recall >= 0.80.
    Among tied F2 scores, picks the highest threshold to maximize precision."""
    yt = y_true[s3_mask]
    proba = y_proba[s3_mask]

    best_thresh = 0.40
    best_f2 = 0.0
    best_precision = 0.0

    for t in np.arange(0.20, 0.60, 0.01):
        preds = (proba >= t).astype(int)
        if preds.sum() == 0:
            continue
        f2 = fbeta_score(yt, preds, beta=2, zero_division=0)
        r = recall_score(yt, preds, zero_division=0)
        p = precision_score(yt, preds, zero_division=0)
        if r >= 0.80 and (f2 > best_f2 or (f2 == best_f2 and p > best_precision)):
            best_f2 = f2
            best_thresh = t
            best_precision = p

    return best_thresh, best_f2


def add_s3_derived_features(df):
    """Add S3-specific interaction features derived from existing columns."""
    s3_mask = (df["resource_type"] == "s3")

    df["s3_missing_control_count"] = 0
    df.loc[s3_mask, "s3_missing_control_count"] = (
        (1 - df.loc[s3_mask, "encryption_enabled"]) +
        (1 - df.loc[s3_mask, "versioning_enabled"]) +
        (1 - df.loc[s3_mask, "logging_enabled"]) +
        df.loc[s3_mask, "public_access_enabled"]
    )

    df["s3_no_encrypt_no_version"] = 0
    df.loc[s3_mask, "s3_no_encrypt_no_version"] = (
        (df.loc[s3_mask, "encryption_enabled"] == 0) &
        (df.loc[s3_mask, "versioning_enabled"] == 0)
    ).astype(int)

    df["s3_public_no_logging"] = 0
    df.loc[s3_mask, "s3_public_no_logging"] = (
        (df.loc[s3_mask, "public_access_enabled"] == 1) &
        (df.loc[s3_mask, "logging_enabled"] == 0)
    ).astype(int)

    return df


def compute_sample_weights(df):
    """Compute sample weights — S3 misconfigured records weighted by severity."""
    weights = np.ones(len(df))
    s3_misc_mask = (df["resource_type"] == "s3") & (df["label"] == 1)
    weights[s3_misc_mask.values] = df.loc[s3_misc_mask, "s3_missing_control_count"].clip(lower=1).values
    return weights


def load_data():
    df = pd.read_csv(f"{DATA_PROCESSED}/labeled_features.csv")
    df[BASE_FEATURE_COLS] = df[BASE_FEATURE_COLS].fillna(0)
    df = add_s3_derived_features(df)
    # Extended features may be missing on rows from older parsers — default to 0
    for col in EXTENDED_FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0
        df[col] = df[col].fillna(0)
    X = df[FEATURE_COLS].values
    y = df["label"].values
    sample_weights = compute_sample_weights(df)
    return X, y, df, sample_weights


def evaluate_model(name, model, X, y, sample_weights=None):
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scoring = ["precision", "recall", "f1"]
    params = {"sample_weight": sample_weights} if sample_weights is not None else {}
    scores = cross_validate(model, X, y, cv=cv, scoring=scoring, params=params)

    # Collect out-of-fold predictions for confusion matrix
    cv2 = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    y_pred = cross_val_predict(model, X, y, cv=cv2, params=params)

    # Also get probabilities for S3 threshold adjustment
    cv3 = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    y_proba = cross_val_predict(model, X, y, cv=cv3, method='predict_proba', params=params)[:, 1]

    print(f"\n── {name} (5-Fold Cross Validation) ──")
    print(f"  Precision : {scores['test_precision'].mean():.3f} +/- {scores['test_precision'].std():.3f}")
    print(f"  Recall    : {scores['test_recall'].mean():.3f} +/- {scores['test_recall'].std():.3f}")
    print(f"  F1 Score  : {scores['test_f1'].mean():.3f} +/- {scores['test_f1'].std():.3f}")

    # Classification report
    print(f"\n  Classification Report:")
    print(classification_report(y, y_pred, target_names=["Secure", "Misconfigured"]))

    # Confusion matrix
    cm = confusion_matrix(y, y_pred)
    print(f"  Confusion Matrix:")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")

    return scores, y_pred, y_proba, cm


def evaluate_per_resource_type(name, y_true, y_pred, y_proba, df):
    """Break down precision/recall/F1 by resource type, with S3 threshold adjustment."""
    print(f"\n── {name}: Per-Resource-Type Breakdown ──")
    results = []
    for rtype in ["s3", "iam", "security_group"]:
        mask = (df["resource_type"] == rtype).values
        if mask.sum() == 0:
            continue
        yt = y_true[mask]
        # Apply lower threshold for S3 resources
        if rtype == "s3":
            yp = (y_proba[mask] >= S3_THRESHOLD).astype(int)
        else:
            yp = y_pred[mask]
        p = precision_score(yt, yp, zero_division=0)
        r = recall_score(yt, yp, zero_division=0)
        f = f1_score(yt, yp, zero_division=0)
        n = int(mask.sum())
        misc = int(yt.sum())
        print(f"  {rtype:<20} n={n:>3}  misc={misc:>3}  P={p:.3f}  R={r:.3f}  F1={f:.3f}")
        results.append({"model": name, "resource_type": rtype, "n": n,
                        "misconfigured": misc, "precision": p, "recall": r, "f1": f})
    return results


def generate_visualizations(rf_cm, lr_cm, rf_scores, lr_scores, importances,
                            rf_proba, lr_proba, y, df):
    """Generate 4 visualization PNGs."""
    os.makedirs(OUTPUTS_DIR, exist_ok=True)

    # ── Plot 1: Confusion Matrix Heatmap ──────────────────────────────────
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    labels = ["Secure", "Misconfigured"]
    for ax, cm, title in [(axes[0], rf_cm, "Random Forest"),
                           (axes[1], lr_cm, "Logistic Regression")]:
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                    xticklabels=labels, yticklabels=labels)
        ax.set_title(title)
        ax.set_ylabel('Actual')
        ax.set_xlabel('Predicted')
    fig.suptitle('Confusion Matrices (5-Fold Cross Validation)', fontsize=14)
    plt.tight_layout()
    plt.savefig(f"{OUTPUTS_DIR}/confusion_matrix.png", dpi=150)
    plt.close()
    print(f"  Saved {OUTPUTS_DIR}/confusion_matrix.png")

    # ── Plot 2: Feature Importance Bar Chart ──────────────────────────────
    fig, ax = plt.subplots(figsize=(10, 7))
    sorted_imp = importances.sort_values(ascending=True)

    # Color by resource type
    s3_features = {"public_access_enabled", "encryption_enabled",
                   "versioning_enabled", "logging_enabled",
                   "s3_missing_control_count", "s3_no_encrypt_no_version",
                   "s3_public_no_logging"}
    iam_features = {"has_wildcard_permission", "has_admin_privilege",
                    "has_priv_esc_potential", "policy_length",
                    "allow_wildcard_action", "allow_wildcard_resource"}
    colors = []
    for feat in sorted_imp.index:
        if feat in s3_features:
            colors.append('#3498db')  # blue
        elif feat in iam_features:
            colors.append('#e67e22')  # orange
        else:
            colors.append('#2ecc71')  # green

    ax.barh(range(len(sorted_imp)), sorted_imp.values, color=colors)
    ax.set_yticks(range(len(sorted_imp)))
    ax.set_yticklabels(sorted_imp.index)
    ax.set_xlabel('Importance')
    ax.set_title('Random Forest Feature Importance')

    # Legend
    from matplotlib.patches import Patch
    legend_elements = [Patch(facecolor='#3498db', label='S3'),
                       Patch(facecolor='#e67e22', label='IAM'),
                       Patch(facecolor='#2ecc71', label='Security Group')]
    ax.legend(handles=legend_elements, loc='lower right')

    plt.tight_layout()
    plt.savefig(f"{OUTPUTS_DIR}/feature_importance.png", dpi=150)
    plt.close()
    print(f"  Saved {OUTPUTS_DIR}/feature_importance.png")

    # ── Plot 3: Model Comparison Bar Chart ────────────────────────────────
    fig, ax = plt.subplots(figsize=(8, 5))
    metrics = ['Precision', 'Recall', 'F1']
    rf_vals = [rf_scores['test_precision'].mean(), rf_scores['test_recall'].mean(),
               rf_scores['test_f1'].mean()]
    lr_vals = [lr_scores['test_precision'].mean(), lr_scores['test_recall'].mean(),
               lr_scores['test_f1'].mean()]

    x = np.arange(len(metrics))
    width = 0.3
    bars1 = ax.bar(x - width/2, rf_vals, width, label='Random Forest', color='#2ecc71')
    bars2 = ax.bar(x + width/2, lr_vals, width, label='Logistic Regression', color='#3498db')

    # Target threshold lines
    ax.axhline(y=0.75, color='red', linestyle='--', alpha=0.7, label='F1 Target (0.75)')
    ax.axhline(y=0.80, color='orange', linestyle='--', alpha=0.7, label='Recall Target (0.80)')

    ax.set_xticks(x)
    ax.set_xticklabels(metrics)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel('Score')
    ax.set_title('Model Comparison: Random Forest vs Logistic Regression')
    ax.legend(loc='lower right')

    # Annotate bars
    for bar in bars1:
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.01,
                f'{bar.get_height():.3f}', ha='center', va='bottom', fontsize=9)
    for bar in bars2:
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.01,
                f'{bar.get_height():.3f}', ha='center', va='bottom', fontsize=9)

    plt.tight_layout()
    plt.savefig(f"{OUTPUTS_DIR}/model_comparison.png", dpi=150)
    plt.close()
    print(f"  Saved {OUTPUTS_DIR}/model_comparison.png")

    # ── Plot 4: ROC Curve ─────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(7, 6))

    rf_fpr, rf_tpr, _ = roc_curve(y, rf_proba)
    rf_auc = auc(rf_fpr, rf_tpr)
    ax.plot(rf_fpr, rf_tpr, label=f'Random Forest (AUC = {rf_auc:.3f})', color='#2ecc71', lw=2)

    lr_fpr, lr_tpr, _ = roc_curve(y, lr_proba)
    lr_auc = auc(lr_fpr, lr_tpr)
    ax.plot(lr_fpr, lr_tpr, label=f'Logistic Regression (AUC = {lr_auc:.3f})', color='#3498db', lw=2)

    ax.plot([0, 1], [0, 1], 'k--', alpha=0.5, label='Random Baseline')
    ax.set_xlabel('False Positive Rate')
    ax.set_ylabel('True Positive Rate')
    ax.set_title('ROC Curve Comparison')
    ax.legend(loc='lower right')
    plt.tight_layout()
    plt.savefig(f"{OUTPUTS_DIR}/roc_curve.png", dpi=150)
    plt.close()
    print(f"  Saved {OUTPUTS_DIR}/roc_curve.png")

    # ── Plot 5: S3 Precision-Recall Curve ─────────────────────────────────
    s3_mask = (df["resource_type"] == "s3").values
    s3_y = y[s3_mask]
    s3_rf_proba = rf_proba[s3_mask]
    s3_lr_proba = lr_proba[s3_mask]

    fig, ax = plt.subplots(figsize=(7, 6))

    rf_prec, rf_rec, rf_thresh = precision_recall_curve(s3_y, s3_rf_proba)
    lr_prec, lr_rec, lr_thresh = precision_recall_curve(s3_y, s3_lr_proba)

    ax.plot(rf_rec, rf_prec, label='Random Forest', color='#2ecc71', lw=2)
    ax.plot(lr_rec, lr_prec, label='Logistic Regression', color='#3498db', lw=2)

    # Mark the chosen F2-optimal threshold
    s3_rf_pred = (s3_rf_proba >= S3_THRESHOLD).astype(int)
    opt_p = precision_score(s3_y, s3_rf_pred, zero_division=0)
    opt_r = recall_score(s3_y, s3_rf_pred, zero_division=0)
    ax.scatter([opt_r], [opt_p], color='red', s=100, zorder=5,
              label=f'RF @ t={S3_THRESHOLD:.2f} (P={opt_p:.2f}, R={opt_r:.2f})')

    ax.axvline(x=0.80, color='orange', linestyle='--', alpha=0.7, label='Recall Target (0.80)')
    ax.set_xlabel('Recall')
    ax.set_ylabel('Precision')
    ax.set_title('S3 Precision-Recall Curve')
    ax.set_xlim(0, 1.05)
    ax.set_ylim(0, 1.05)
    ax.legend(loc='lower left')
    plt.tight_layout()
    plt.savefig(f"{OUTPUTS_DIR}/s3_pr_curve.png", dpi=150)
    plt.close()
    print(f"  Saved {OUTPUTS_DIR}/s3_pr_curve.png")


def main():
    os.makedirs(MODELS_DIR, exist_ok=True)

    X, y, df, sample_weights = load_data()
    print(f"Dataset: {len(df)} records | Misconfigured: {int(y.sum())} | Secure: {int((y==0).sum())}")
    print(f"Features: {len(FEATURE_COLS)} ({len(BASE_FEATURE_COLS)} base + "
          f"{len(S3_DERIVED_COLS)} S3 derived + {len(EXTENDED_FEATURE_COLS)} extended)")

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ── Logistic Regression (baseline) ──────────────────────────────────────
    lr = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
    lr_scores, lr_pred, lr_proba, lr_cm = evaluate_model(
        "Logistic Regression (Baseline)", lr, X_scaled, y, sample_weights)

    # ── Random Forest (primary) ──────────────────────────────────────────────
    rf = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=42
    )
    rf_scores, rf_pred, rf_proba, rf_cm = evaluate_model(
        "Random Forest (Primary)", rf, X_scaled, y, sample_weights)

    # ── Find optimal S3 threshold using F2 score ─────────────────────────────
    global S3_THRESHOLD
    s3_mask = (df["resource_type"] == "s3").values
    optimal_thresh, best_f2 = find_optimal_s3_threshold(y, rf_proba, s3_mask)
    S3_THRESHOLD = optimal_thresh
    print(f"\n── S3 Threshold Optimization (F2 Score) ──")
    print(f"  Optimal threshold: {S3_THRESHOLD:.2f} (F2={best_f2:.3f})")

    # ── Per-resource-type evaluation ─────────────────────────────────────────
    per_resource_results = []
    per_resource_results.extend(evaluate_per_resource_type("Logistic Regression", y, lr_pred, lr_proba, df))
    per_resource_results.extend(evaluate_per_resource_type("Random Forest", y, rf_pred, rf_proba, df))
    per_resource_df = pd.DataFrame(per_resource_results)
    per_resource_df.to_csv(f"{DATA_PROCESSED}/per_resource_results.csv", index=False)
    print(f"\n  Saved per-resource results to {DATA_PROCESSED}/per_resource_results.csv")

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

    # ── Generate visualizations ──────────────────────────────────────────────
    print("\n── Generating Visualizations ──")
    generate_visualizations(rf_cm, lr_cm, rf_scores, lr_scores, importances,
                            rf_proba, lr_proba, y, df)

    print("\nDone!")


if __name__ == "__main__":
    main()
