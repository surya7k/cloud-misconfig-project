"""Held-out evaluation against the curated real-world sample set.

These samples in data/samples/realworld/ were transcribed from public AWS
templates / Terraform modules / tutorials AFTER the model was trained, and
none of them appear in labeled_features.csv. This script measures
generalization beyond cross-validation.

Each sample carries an `_expected_verdict` string. The ALB sample is dual:
"MISCONFIGURED per labeling rules / SECURE in context (legitimate public
ALB)". We report both interpretations so the paper can call out the
context-blindness limitation honestly.

Outputs:
  outputs/realworld_holdout.csv          per-sample predictions
  outputs/realworld_holdout_summary.csv  aggregate metrics (strict + context-aware)
"""
import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score

from src.predict import score_config

REALWORLD_DIR = Path("data/samples/realworld")
OUTPUTS = Path("outputs")
OUTPUTS.mkdir(exist_ok=True)

PER_SAMPLE_CSV = OUTPUTS / "realworld_holdout.csv"
SUMMARY_CSV = OUTPUTS / "realworld_holdout_summary.csv"


def parse_expected(verdict: str):
    """Return (strict_label, context_label) where 1 = misconfigured.

    Most samples have a clean SECURE / MISCONFIGURED string. The ALB case is
    the one dual-interpretation sample: rule-strict says MISCONFIGURED but
    in real deployment context it is SECURE.
    """
    v = verdict.upper()
    has_context_secure = "SECURE IN CONTEXT" in v
    starts_misconfigured = v.startswith("MISCONFIGURED")
    strict = 1 if starts_misconfigured else 0
    context = 0 if has_context_secure else strict
    return strict, context


def load_samples():
    rows = []
    for path in sorted(REALWORLD_DIR.glob("*.json")):
        config = json.loads(path.read_text())
        verdict = config.get("_expected_verdict", "")
        if not verdict:
            continue
        strict, context = parse_expected(verdict)
        rows.append({
            "file": path.name,
            "resource_type": config.get("resource_type", ""),
            "resource_name": config.get("resource_name", path.stem),
            "expected_verdict": verdict,
            "y_strict": strict,
            "y_context": context,
            "config": config,
        })
    return rows


def metrics(y_true, y_pred):
    return {
        "n": len(y_true),
        "accuracy": sum(int(t == p) for t, p in zip(y_true, y_pred)) / len(y_true),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
    }


def main():
    samples = load_samples()
    if not samples:
        print(f"No samples found in {REALWORLD_DIR}")
        return

    per_sample = []
    for s in samples:
        result = score_config(s["config"])
        per_sample.append({
            "file": s["file"],
            "resource_type": s["resource_type"],
            "resource_name": s["resource_name"],
            "expected_verdict": s["expected_verdict"],
            "y_strict": s["y_strict"],
            "y_context": s["y_context"],
            "y_pred": result["prediction"],
            "p_misconfigured": round(result["probability_misconfigured"], 3),
            "risk_level": result["risk_level"],
            "agree_strict": int(result["prediction"] == s["y_strict"]),
            "agree_context": int(result["prediction"] == s["y_context"]),
        })

    df = pd.DataFrame(per_sample)
    df.to_csv(PER_SAMPLE_CSV, index=False)

    y_pred = df["y_pred"].tolist()

    summary_rows = []
    summary_rows.append({"interpretation": "strict (matches labeling rules)",
                         **metrics(df["y_strict"].tolist(), y_pred)})
    summary_rows.append({"interpretation": "context-aware (ALB treated as SECURE)",
                         **metrics(df["y_context"].tolist(), y_pred)})

    for rtype in sorted(df["resource_type"].unique()):
        sub = df[df["resource_type"] == rtype]
        if len(sub) == 0:
            continue
        summary_rows.append({
            "interpretation": f"strict — {rtype} (n={len(sub)})",
            **metrics(sub["y_strict"].tolist(), sub["y_pred"].tolist()),
        })

    summary = pd.DataFrame(summary_rows)
    summary.to_csv(SUMMARY_CSV, index=False)

    print("\nPer-sample predictions")
    print("-" * 100)
    print(df[["file", "resource_type", "y_strict", "y_pred",
              "p_misconfigured", "agree_strict"]].to_string(index=False))

    print("\nAggregate held-out metrics")
    print("-" * 100)
    for r in summary_rows:
        print(f"  {r['interpretation']:<48}  "
              f"n={r['n']:<3}  acc={r['accuracy']:.2f}  "
              f"P={r['precision']:.2f}  R={r['recall']:.2f}  F1={r['f1']:.2f}")

    print(f"\nSaved {PER_SAMPLE_CSV} and {SUMMARY_CSV}")


if __name__ == "__main__":
    main()
