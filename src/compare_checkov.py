"""Quantitative comparison: Checkov (rule-based) vs Random Forest (ML).

Runs Checkov against the TerraGoat and CfnGoat templates the ML pipeline already
trained on, then evaluates both Checkov's verdicts and the RF model's predictions
against the ground-truth labels in labeled_features.csv.

Outputs:
  outputs/checkov_terragoat.json
  outputs/checkov_cfngoat.json
  outputs/checkov_comparison.csv
  outputs/checkov_comparison.png
"""
import json
import re
import subprocess
import sys
import warnings
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold, cross_val_predict

from src.predict import FEATURE_COLS, S3_THRESHOLD
from src.train import (
    add_s3_derived_features,
    BASE_FEATURE_COLS,
    EXTENDED_FEATURE_COLS,
)

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

OUTPUTS = Path("outputs")
OUTPUTS.mkdir(exist_ok=True)

CHECKOV_TERRAGOAT_JSON = OUTPUTS / "checkov_terragoat.json"
CHECKOV_CFNGOAT_JSON = OUTPUTS / "checkov_cfngoat.json"
CHECKOV_CLOUDGOAT_JSON = OUTPUTS / "checkov_cloudgoat.json"
COMPARISON_CSV = OUTPUTS / "checkov_comparison.csv"
COMPARISON_PNG = OUTPUTS / "checkov_comparison.png"

LABELED_CSV = "data/processed/labeled_features.csv"
RF_PATH = "models/random_forest.pkl"
SCALER_PATH = "models/scaler.pkl"

# Map Checkov resource type prefixes to our resource_type categories
TF_TYPE_MAP = {
    "aws_s3_bucket": "s3",
    "aws_s3_bucket_public_access_block": "s3",
    "aws_iam_user_policy": "iam",
    "aws_iam_role_policy": "iam",
    "aws_iam_policy": "iam",
    "aws_security_group": "security_group",
}

CFN_TYPE_MAP = {
    "AWS::S3::Bucket": "s3",
    "AWS::IAM::Policy": "iam",
    "AWS::IAM::ManagedPolicy": "iam",
    "AWS::IAM::Role": "iam",
    "AWS::EC2::SecurityGroup": "security_group",
}


def run_checkov():
    """Run Checkov against terragoat and cfngoat sources."""
    if not CHECKOV_TERRAGOAT_JSON.exists() or CHECKOV_TERRAGOAT_JSON.stat().st_size < 1000:
        print("Running Checkov on terragoat/terraform/aws/ ...")
        with open(CHECKOV_TERRAGOAT_JSON, "w") as f:
            subprocess.run(
                [sys.executable, "-m", "checkov.main", "-d", "terragoat/terraform/aws/", "-o", "json",
                 "--soft-fail", "--quiet"],
                stdout=f, stderr=subprocess.DEVNULL,
            )

    if not CHECKOV_CFNGOAT_JSON.exists() or CHECKOV_CFNGOAT_JSON.stat().st_size < 1000:
        print("Running Checkov on cfngoat/cfngoat.yaml ...")
        with open(CHECKOV_CFNGOAT_JSON, "w") as f:
            subprocess.run(
                [sys.executable, "-m", "checkov.main", "-f", "cfngoat/cfngoat.yaml", "-o", "json",
                 "--soft-fail", "--quiet"],
                stdout=f, stderr=subprocess.DEVNULL,
            )

    cg_path = Path("cloudgoat/cloudgoat/scenarios/aws")
    if cg_path.exists() and (
        not CHECKOV_CLOUDGOAT_JSON.exists()
        or CHECKOV_CLOUDGOAT_JSON.stat().st_size < 1000
    ):
        print("Running Checkov on cloudgoat/cloudgoat/scenarios/aws/ ...")
        with open(CHECKOV_CLOUDGOAT_JSON, "w") as f:
            subprocess.run(
                [sys.executable, "-m", "checkov.main", "-d", str(cg_path), "-o", "json",
                 "--soft-fail", "--quiet"],
                stdout=f, stderr=subprocess.DEVNULL,
            )


def parse_checkov_terraform(path):
    """Parse terraform-framework Checkov output → {(rtype, short_name): bool_failed}."""
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, list):
        data = [data]

    verdicts = {}  # (rtype, short_name) -> int (1 = misconfigured per Checkov)
    for entry in data:
        if entry.get("check_type") != "terraform":
            continue
        results = entry.get("results", {})
        for check in results.get("failed_checks", []):
            addr = check.get("resource", "")
            tf_type, _, name = addr.partition(".")
            rtype = TF_TYPE_MAP.get(tf_type)
            if not rtype:
                continue
            verdicts[(rtype, name)] = 1
        for check in results.get("passed_checks", []):
            addr = check.get("resource", "")
            tf_type, _, name = addr.partition(".")
            rtype = TF_TYPE_MAP.get(tf_type)
            if not rtype:
                continue
            verdicts.setdefault((rtype, name), 0)
    return verdicts


def parse_checkov_cfn(path):
    """Parse cloudformation-framework Checkov output → {(rtype, logical_id): bool_failed}."""
    with open(path) as f:
        data = json.load(f)
    if not isinstance(data, list):
        data = [data]

    verdicts = {}
    for entry in data:
        if entry.get("check_type") != "cloudformation":
            continue
        results = entry.get("results", {})
        for check in results.get("failed_checks", []):
            # Checkov CFN resource format: "AWS::S3::Bucket.LogicalId"
            res = check.get("resource", "")
            if "." not in res:
                continue
            cfn_type, _, logical_id = res.rpartition(".")
            rtype = CFN_TYPE_MAP.get(cfn_type)
            if not rtype:
                continue
            verdicts[(rtype, logical_id)] = 1
        for check in results.get("passed_checks", []):
            res = check.get("resource", "")
            if "." not in res:
                continue
            cfn_type, _, logical_id = res.rpartition(".")
            rtype = CFN_TYPE_MAP.get(cfn_type)
            if not rtype:
                continue
            verdicts.setdefault((rtype, logical_id), 0)
    return verdicts


def build_comparison_df():
    """Match labeled rows to Checkov verdicts and add RF predictions."""
    df = pd.read_csv(LABELED_CSV)

    # Filter to TerraGoat + CfnGoat + CloudGoat rows by name prefix
    mask = df["resource_name"].str.startswith(("terragoat-", "cfngoat-", "cloudgoat-")) \
        & ~df["resource_name"].str.startswith("terragoat-dbapp-")
    df = df[mask].copy()

    df["origin"] = df["resource_name"].str.split("-", n=1).str[0]

    # Short name (Checkov-side resource address suffix) varies by origin:
    #   terragoat-<name>           → <name>
    #   cfngoat-<name>             → <name>
    #   cloudgoat-<scenario>-<name>→ <name>     (strip scenario prefix too)
    def short_name(row):
        rn = row["resource_name"]
        if row["origin"] == "cloudgoat":
            # cloudgoat-<scenario>-<name> → <name>; scenario may contain underscores
            # so split off cloudgoat- then strip leading <scenario>- (split on first '-' after)
            rest = rn[len("cloudgoat-"):]
            # Scenario directory names contain only letters/digits/underscores;
            # the resource name comes after the first '-' that follows the scenario.
            return rest.split("-", 1)[1] if "-" in rest else rest
        return re.sub(r"^(terragoat|cfngoat)-", "", rn)
    df["short_name"] = df.apply(short_name, axis=1)

    tg_verdicts = parse_checkov_terraform(CHECKOV_TERRAGOAT_JSON)
    cfn_verdicts = parse_checkov_cfn(CHECKOV_CFNGOAT_JSON)
    cg_verdicts = (
        parse_checkov_terraform(CHECKOV_CLOUDGOAT_JSON)
        if CHECKOV_CLOUDGOAT_JSON.exists() else {}
    )

    def lookup(row):
        key = (row["resource_type"], row["short_name"])
        if row["origin"] == "terragoat":
            return tg_verdicts.get(key)
        if row["origin"] == "cloudgoat":
            return cg_verdicts.get(key)
        return cfn_verdicts.get(key)

    df["checkov_pred"] = df.apply(lookup, axis=1)

    # Drop rows we couldn't match (Checkov didn't scan / different naming)
    matched = df.dropna(subset=["checkov_pred"]).copy()
    matched["checkov_pred"] = matched["checkov_pred"].astype(int)

    # RF predictions — use out-of-fold cross_val_predict for an honest evaluation.
    # The single trained RF was fit on ALL labeled data, including these matched
    # rows; in-sample predictions would be data leakage. Cross-validated predictions
    # give out-of-fold scores comparable to the headline F1.
    full_df = pd.read_csv(LABELED_CSV)
    full_df[BASE_FEATURE_COLS] = full_df[BASE_FEATURE_COLS].fillna(0)
    full_df = add_s3_derived_features(full_df)
    for col in EXTENDED_FEATURE_COLS:
        if col not in full_df.columns:
            full_df[col] = 0
        full_df[col] = full_df[col].fillna(0)

    scaler = joblib.load(SCALER_PATH)
    X_full = scaler.transform(full_df[FEATURE_COLS].values.astype(float))
    y_full = full_df["label"].astype(int).values

    rf = RandomForestClassifier(
        n_estimators=200, class_weight="balanced", random_state=42, n_jobs=-1,
    )
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    proba_full = cross_val_predict(rf, X_full, y_full, cv=cv, method="predict_proba")[:, 1]

    full_df["rf_proba_oof"] = proba_full
    full_df["resource_name_idx"] = full_df["resource_name"]
    proba_lookup = full_df.set_index("resource_name_idx")["rf_proba_oof"]

    matched = add_s3_derived_features(matched)
    matched["rf_proba"] = matched["resource_name"].map(proba_lookup)
    thresh = np.where(matched["resource_type"].values == "s3", S3_THRESHOLD, 0.50)
    matched["rf_pred"] = (matched["rf_proba"].values >= thresh).astype(int)

    return matched, df


def metrics_table(matched):
    rows = []
    for label, col in [("Checkov (rules)", "checkov_pred"), ("Random Forest (ML)", "rf_pred")]:
        # Overall
        y = matched["label"].astype(int).values
        yp = matched[col].astype(int).values
        rows.append({
            "model": label, "resource_type": "overall", "n": len(y),
            "precision": precision_score(y, yp, zero_division=0),
            "recall":    recall_score(y, yp, zero_division=0),
            "f1":        f1_score(y, yp, zero_division=0),
        })
        # Per resource type
        for rtype in ["s3", "iam", "security_group"]:
            sub = matched[matched["resource_type"] == rtype]
            if len(sub) == 0:
                continue
            ys = sub["label"].astype(int).values
            yps = sub[col].astype(int).values
            rows.append({
                "model": label, "resource_type": rtype, "n": len(ys),
                "precision": precision_score(ys, yps, zero_division=0),
                "recall":    recall_score(ys, yps, zero_division=0),
                "f1":        f1_score(ys, yps, zero_division=0),
            })
    return pd.DataFrame(rows)


def plot_comparison(metrics, out_path):
    overall = metrics[metrics["resource_type"] == "overall"].set_index("model")

    metric_names = ["precision", "recall", "f1"]
    models = ["Checkov (rules)", "Random Forest (ML)"]
    x = np.arange(len(metric_names))
    width = 0.35

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5),
                                   gridspec_kw={"width_ratios": [1, 1.4]})

    # Overall comparison
    for i, m in enumerate(models):
        vals = [overall.loc[m, k] for k in metric_names]
        offset = (i - 0.5) * width
        bars = ax1.bar(x + offset, vals, width,
                       label=m,
                       color="#3a7bd5" if i == 0 else "#27ae60")
        for b, v in zip(bars, vals):
            ax1.text(b.get_x() + b.get_width()/2, v + 0.015, f"{v:.2f}",
                     ha="center", fontsize=9)
    ax1.set_xticks(x)
    ax1.set_xticklabels(["Precision", "Recall", "F1"])
    ax1.set_ylim(0, 1.1)
    ax1.set_title("Overall: Checkov rules vs Random Forest")
    ax1.axhline(0.75, ls="--", color="grey", alpha=0.5, label="F1 target (0.75)")
    ax1.axhline(0.80, ls=":", color="red", alpha=0.5, label="Recall target (0.80)")
    ax1.legend(loc="lower left", fontsize=8)
    ax1.set_ylabel("Score")

    # Per resource type, F1 only
    per = metrics[metrics["resource_type"] != "overall"].copy()
    rtypes = ["s3", "iam", "security_group"]
    rtype_labels = ["S3", "IAM", "Security Group"]
    xr = np.arange(len(rtypes))
    for i, m in enumerate(models):
        vals = []
        for rt in rtypes:
            row = per[(per["model"] == m) & (per["resource_type"] == rt)]
            vals.append(row["f1"].iloc[0] if len(row) else 0.0)
        offset = (i - 0.5) * width
        bars = ax2.bar(xr + offset, vals, width,
                       label=m,
                       color="#3a7bd5" if i == 0 else "#27ae60")
        for b, v in zip(bars, vals):
            ax2.text(b.get_x() + b.get_width()/2, v + 0.015, f"{v:.2f}",
                     ha="center", fontsize=9)
    ax2.set_xticks(xr)
    ax2.set_xticklabels(rtype_labels)
    ax2.set_ylim(0, 1.1)
    ax2.set_title("F1 by resource type")
    ax2.legend(loc="lower right", fontsize=8)
    ax2.set_ylabel("F1 score")

    fig.suptitle("Rule-based detection (Checkov) vs Machine-learning (Random Forest)",
                 fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out_path, dpi=140, bbox_inches="tight")
    plt.close(fig)


def main():
    run_checkov()

    matched, all_filtered = build_comparison_df()
    print(f"\nMatched {len(matched)} of {len(all_filtered)} TerraGoat/CfnGoat rows "
          f"to a Checkov verdict.")
    print(f"  by resource type: {matched['resource_type'].value_counts().to_dict()}")
    print(f"  by origin:        {matched['origin'].value_counts().to_dict()}")
    print(f"  ground-truth misconfigured: "
          f"{int(matched['label'].sum())} / {len(matched)}")

    metrics = metrics_table(matched)
    metrics.to_csv(COMPARISON_CSV, index=False)
    print(f"\nWrote {COMPARISON_CSV}")
    print(metrics.round(3).to_string(index=False))

    plot_comparison(metrics, COMPARISON_PNG)
    print(f"\nSaved {COMPARISON_PNG}")


if __name__ == "__main__":
    main()
