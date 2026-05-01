"""SHAP-based per-prediction explanations for the trained Random Forest.

Returns the per-feature contributions to the misconfigured-class probability.
Positive values push toward MISCONFIGURED; negative push toward SECURE.
"""
import joblib
import numpy as np
import shap

from src.predict import FEATURE_COLS, extract_features


_EXPLAINER = None
_MODEL = None
_SCALER = None


def _load():
    global _EXPLAINER, _MODEL, _SCALER
    if _EXPLAINER is None:
        _MODEL = joblib.load("models/random_forest.pkl")
        _SCALER = joblib.load("models/scaler.pkl")
        _EXPLAINER = shap.TreeExplainer(_MODEL)
    return _MODEL, _SCALER, _EXPLAINER


def explain_config(config):
    """Return list of (feature_name, shap_value) sorted by absolute contribution.

    SHAP values are with respect to the MISCONFIGURED class (label=1).
    """
    _, scaler, explainer = _load()
    features = extract_features(config)
    x = np.array([[features[c] for c in FEATURE_COLS]])
    x_scaled = scaler.transform(x)

    sv = explainer.shap_values(x_scaled)

    # shap returns different shapes across versions:
    #   list of [n_samples, n_features] per class  (older API)
    #   ndarray [n_samples, n_features, n_classes]  (newer API)
    if isinstance(sv, list):
        contributions = sv[1][0]
    elif sv.ndim == 3:
        contributions = sv[0, :, 1]
    else:
        contributions = sv[0]

    pairs = list(zip(FEATURE_COLS, [float(v) for v in contributions]))
    pairs.sort(key=lambda kv: abs(kv[1]), reverse=True)
    return pairs


if __name__ == "__main__":
    import json
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "data/samples/insecure_s3.json"
    with open(path) as f:
        cfg = json.load(f)
    print(f"\nTop SHAP contributions for {path}:")
    for name, val in explain_config(cfg)[:8]:
        direction = "→ misconfigured" if val > 0 else "→ secure"
        print(f"  {name:35s} {val:+.4f}  {direction}")
