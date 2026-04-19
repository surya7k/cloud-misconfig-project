#!/usr/bin/env python3
"""
Predict whether an AWS resource configuration is secure or misconfigured.
Loads the trained Random Forest model and outputs a risk score.

Usage:
    python src/predict.py data/samples/insecure_s3.json
    python src/predict.py data/samples/secure_iam.json
    python src/predict.py data/samples/open_sg.json
"""
import json
import sys
import joblib
import numpy as np

FEATURE_COLS = [
    "public_access_enabled", "encryption_enabled",
    "versioning_enabled", "logging_enabled",
    "has_wildcard_permission", "has_admin_privilege",
    "has_priv_esc_potential", "policy_length",
    "inbound_rule_count", "outbound_rule_count",
    "open_ports_to_world", "ssh_open_to_world", "rdp_open_to_world",
    "allow_wildcard_action", "allow_wildcard_resource", "all_ports_open",
    "s3_missing_control_count", "s3_no_encrypt_no_version", "s3_public_no_logging",
]

S3_THRESHOLD = 0.40

PRIV_ESC_ACTIONS = {
    "iam:AttachUserPolicy", "iam:CreatePolicyVersion",
    "iam:PutUserPolicy", "iam:AttachRolePolicy",
    "iam:PassRole", "iam:SetDefaultPolicyVersion"
}


def extract_features(config):
    """Extract 16 features from a raw config JSON."""
    features = {col: 0 for col in FEATURE_COLS}
    rtype = config.get("resource_type", "")

    if rtype == "s3":
        features["public_access_enabled"] = int(config.get("public_access_enabled", 0))
        features["encryption_enabled"] = int(config.get("encryption_enabled", 0))
        features["versioning_enabled"] = int(config.get("versioning_enabled", 0))
        features["logging_enabled"] = int(config.get("logging_enabled", 0))

    elif rtype == "iam":
        statements = config.get("policy", {}).get("Statement", [])
        policy_str = json.dumps(config.get("policy", {}))
        features["policy_length"] = len(policy_str)

        for stmt in statements:
            if stmt.get("Effect", "Allow") == "Deny":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            if "*" in actions:
                features["has_wildcard_permission"] = 1
                features["allow_wildcard_action"] = 1
            if "*" in actions and "*" in resources:
                features["has_admin_privilege"] = 1
                features["allow_wildcard_resource"] = 1
            if any(a in PRIV_ESC_ACTIONS for a in actions):
                features["has_priv_esc_potential"] = 1

    elif rtype == "security_group":
        inbound = config.get("inbound_rules", [])
        outbound = config.get("outbound_rules", [])
        features["inbound_rule_count"] = len(inbound)
        features["outbound_rule_count"] = len(outbound)

        for rule in inbound:
            cidr = rule.get("cidr", "")
            if cidr in ["0.0.0.0/0", "::/0"]:
                features["open_ports_to_world"] += 1
                fp = rule.get("from_port", 0)
                tp = rule.get("to_port", 0)
                if fp <= 22 <= tp:
                    features["ssh_open_to_world"] = 1
                if fp <= 3389 <= tp:
                    features["rdp_open_to_world"] = 1
                if fp == 0 and tp >= 65535:
                    features["all_ports_open"] = 1

    # S3 derived interaction features
    if rtype == "s3":
        features["s3_missing_control_count"] = (
            (1 - features["encryption_enabled"]) +
            (1 - features["versioning_enabled"]) +
            (1 - features["logging_enabled"]) +
            features["public_access_enabled"]
        )
        features["s3_no_encrypt_no_version"] = int(
            features["encryption_enabled"] == 0 and features["versioning_enabled"] == 0
        )
        features["s3_public_no_logging"] = int(
            features["public_access_enabled"] == 1 and features["logging_enabled"] == 0
        )

    return features


def predict(config_path):
    model = joblib.load("models/random_forest.pkl")
    scaler = joblib.load("models/scaler.pkl")

    with open(config_path) as f:
        config = json.load(f)

    features = extract_features(config)
    X = np.array([[features[col] for col in FEATURE_COLS]])
    X_scaled = scaler.transform(X)

    probability = model.predict_proba(X_scaled)[0]
    rtype = config.get("resource_type", "")

    # Apply lower threshold for S3 resources
    threshold = S3_THRESHOLD if rtype == "s3" else 0.50
    prediction = int(probability[1] >= threshold)
    confidence = max(probability)

    risk_level = "HIGH" if prediction == 1 and confidence > 0.8 else \
                 "MEDIUM" if prediction == 1 else "LOW"

    rtype = config.get("resource_type", "unknown")
    name = config.get("resource_name", config_path)

    print(f"\n{'='*50}")
    print(f"  Resource:   {name}")
    print(f"  Type:       {rtype}")
    print(f"  Prediction: {'MISCONFIGURED' if prediction == 1 else 'SECURE'}")
    print(f"  Confidence: {confidence:.1%}")
    print(f"  Risk Level: {risk_level}")
    print(f"  P(secure)={probability[0]:.3f}  P(misconfigured)={probability[1]:.3f}")
    print(f"{'='*50}")

    # Show which features triggered the prediction
    if prediction == 1:
        print("\n  Risk factors detected:")
        if rtype == "s3":
            if not features["encryption_enabled"]:
                print("    - Encryption not enabled")
            if not features["versioning_enabled"]:
                print("    - Versioning not enabled")
            if not features["logging_enabled"]:
                print("    - Logging not enabled")
            if features["public_access_enabled"]:
                print("    - Public access enabled")
        elif rtype == "iam":
            if features["has_wildcard_permission"]:
                print("    - Wildcard permission (Action: *)")
            if features["has_admin_privilege"]:
                print("    - Admin privilege (Action: * + Resource: *)")
            if features["has_priv_esc_potential"]:
                print("    - Privilege escalation potential")
        elif rtype == "security_group":
            if features["open_ports_to_world"]:
                print(f"    - {features['open_ports_to_world']} port(s) open to world")
            if features["ssh_open_to_world"]:
                print("    - SSH (port 22) open to 0.0.0.0/0")
            if features["rdp_open_to_world"]:
                print("    - RDP (port 3389) open to 0.0.0.0/0")
            if features["all_ports_open"]:
                print("    - All ports (0-65535) open to world")
    else:
        print("\n  No risk factors detected.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python src/predict.py <config.json>")
        sys.exit(1)
    predict(sys.argv[1])
