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
    # Original S3
    "public_access_enabled", "encryption_enabled",
    "versioning_enabled", "logging_enabled",
    # Original IAM
    "has_wildcard_permission", "has_admin_privilege",
    "has_priv_esc_potential", "policy_length",
    # Original SG
    "inbound_rule_count", "outbound_rule_count",
    "open_ports_to_world", "ssh_open_to_world", "rdp_open_to_world",
    # Effect-aware IAM
    "allow_wildcard_action", "allow_wildcard_resource",
    "all_ports_open",
    # S3 derived interactions
    "s3_missing_control_count", "s3_no_encrypt_no_version", "s3_public_no_logging",
    # NEW — Week 10 expansion
    "bucket_policy_wildcard", "mfa_delete_enabled", "tls_enforced",
    "dangerous_service_wildcard", "has_no_condition",
    "db_port_open_to_world", "egress_unrestricted",
]

S3_THRESHOLD = 0.40

PRIV_ESC_ACTIONS = {
    "iam:AttachUserPolicy", "iam:CreatePolicyVersion",
    "iam:PutUserPolicy", "iam:AttachRolePolicy",
    "iam:PassRole", "iam:SetDefaultPolicyVersion"
}

# Service-wildcard actions that are dangerous but less than full admin (`*`).
# Each entry is the prefix before ":*", e.g. "s3" matches "s3:*".
DANGEROUS_SERVICE_PREFIXES = {
    "s3", "iam", "ec2", "lambda", "rds", "kms",
    "secretsmanager", "ssm", "sts", "dynamodb",
}

# Database / data-store ports that should never be open to the world
DB_PORTS_OF_CONCERN = {
    3306,   # MySQL / MariaDB
    5432,   # PostgreSQL
    1433,   # MSSQL
    1521,   # Oracle
    27017,  # MongoDB
    6379,   # Redis
    9200,   # Elasticsearch
    11211,  # Memcached
    5984,   # CouchDB
    7000, 7001, 9042,  # Cassandra
}


def extract_features(config):
    """Extract numerical features from a raw config JSON."""
    features = {col: 0 for col in FEATURE_COLS}
    rtype = config.get("resource_type", "")

    if rtype == "s3":
        features["public_access_enabled"] = int(config.get("public_access_enabled", 0))
        features["encryption_enabled"] = int(config.get("encryption_enabled", 0))
        features["versioning_enabled"] = int(config.get("versioning_enabled", 0))
        features["logging_enabled"] = int(config.get("logging_enabled", 0))
        # New S3 features
        features["bucket_policy_wildcard"] = int(config.get("bucket_policy_wildcard", 0))
        features["mfa_delete_enabled"] = int(config.get("mfa_delete_enabled", 0))
        features["tls_enforced"] = int(config.get("tls_enforced", 0))

    elif rtype == "iam":
        statements = config.get("policy", {}).get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        policy_str = json.dumps(config.get("policy", {}))
        features["policy_length"] = len(policy_str)

        no_condition_seen = 0
        dangerous_service_count = 0

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

            for a in actions:
                if isinstance(a, str) and a.endswith(":*"):
                    prefix = a.split(":", 1)[0]
                    if prefix in DANGEROUS_SERVICE_PREFIXES:
                        dangerous_service_count += 1

            if "Condition" not in stmt or not stmt.get("Condition"):
                no_condition_seen = 1

        features["dangerous_service_wildcard"] = dangerous_service_count
        features["has_no_condition"] = no_condition_seen

    elif rtype == "security_group":
        inbound = config.get("inbound_rules", [])
        outbound = config.get("outbound_rules", [])
        features["inbound_rule_count"] = len(inbound)
        features["outbound_rule_count"] = len(outbound)

        db_open = 0
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
                # Any DB port covered by this rule's range
                for db_port in DB_PORTS_OF_CONCERN:
                    if fp <= db_port <= tp:
                        db_open += 1
                        break  # count one DB-exposure per rule
        features["db_port_open_to_world"] = db_open

        for rule in outbound:
            cidr = rule.get("cidr", "")
            if cidr in ["0.0.0.0/0", "::/0"]:
                fp = rule.get("from_port", 0)
                tp = rule.get("to_port", 0)
                # Treat full-range OR protocol "-1"/"all" as unrestricted egress
                proto = str(rule.get("protocol", "")).lower()
                if proto in ("-1", "all") or (fp == 0 and tp >= 65535):
                    features["egress_unrestricted"] = 1
                    break

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


def collect_risk_factors(features, rtype):
    """Return human-readable list of triggered risk factors."""
    factors = []
    if rtype == "s3":
        if not features["encryption_enabled"]:
            factors.append("Encryption not enabled")
        if not features["versioning_enabled"]:
            factors.append("Versioning not enabled")
        if not features["logging_enabled"]:
            factors.append("Logging not enabled")
        if features["public_access_enabled"]:
            factors.append("Public access enabled")
        if features["bucket_policy_wildcard"]:
            factors.append("Bucket policy grants Principal: \"*\" (Allow)")
        if not features["mfa_delete_enabled"]:
            factors.append("MFA delete not enabled")
        if not features["tls_enforced"]:
            factors.append("TLS not enforced (no aws:SecureTransport condition)")
    elif rtype == "iam":
        if features["has_wildcard_permission"]:
            factors.append("Wildcard permission (Action: *)")
        if features["has_admin_privilege"]:
            factors.append("Admin privilege (Action: * + Resource: *)")
        if features["has_priv_esc_potential"]:
            factors.append("Privilege escalation potential")
        if features["dangerous_service_wildcard"]:
            n = features["dangerous_service_wildcard"]
            factors.append(
                f"{n} dangerous service wildcard(s) (e.g. s3:*, iam:*)"
            )
        if features["has_no_condition"]:
            factors.append("Allow statement(s) without Condition (no MFA/IP/etc. guardrails)")
    elif rtype == "security_group":
        if features["open_ports_to_world"]:
            factors.append(f"{features['open_ports_to_world']} port(s) open to world")
        if features["ssh_open_to_world"]:
            factors.append("SSH (port 22) open to 0.0.0.0/0")
        if features["rdp_open_to_world"]:
            factors.append("RDP (port 3389) open to 0.0.0.0/0")
        if features["all_ports_open"]:
            factors.append("All ports (0-65535) open to world")
        if features["db_port_open_to_world"]:
            factors.append(
                f"{features['db_port_open_to_world']} database port(s) open to world "
                f"(MySQL/Postgres/Mongo/Redis/etc.)"
            )
        if features["egress_unrestricted"]:
            factors.append("Unrestricted egress to 0.0.0.0/0 (potential exfil path)")
    return factors


_MODEL = None
_SCALER = None


def _load_artifacts():
    global _MODEL, _SCALER
    if _MODEL is None:
        _MODEL = joblib.load("models/random_forest.pkl")
        _SCALER = joblib.load("models/scaler.pkl")
    return _MODEL, _SCALER


def score_config(config):
    """Predict risk for a config dict.

    Returns: {
        resource_type, resource_name, prediction, probability, threshold,
        confidence, risk_level, risk_factors, features
    }
    """
    model, scaler = _load_artifacts()
    features = extract_features(config)
    rtype = config.get("resource_type", "")

    X = np.array([[features[col] for col in FEATURE_COLS]])
    X_scaled = scaler.transform(X)
    probability = model.predict_proba(X_scaled)[0]

    threshold = S3_THRESHOLD if rtype == "s3" else 0.50
    prediction = int(probability[1] >= threshold)
    confidence = float(max(probability))

    risk_level = "HIGH" if prediction == 1 and confidence > 0.8 else \
                 "MEDIUM" if prediction == 1 else "LOW"

    return {
        "resource_type": rtype,
        "resource_name": config.get("resource_name", ""),
        "prediction": prediction,
        "probability_misconfigured": float(probability[1]),
        "probability_secure": float(probability[0]),
        "threshold": threshold,
        "confidence": confidence,
        "risk_level": risk_level,
        "risk_factors": collect_risk_factors(features, rtype),
        "features": features,
    }


def predict(config_path):
    with open(config_path) as f:
        config = json.load(f)

    result = score_config(config)
    name = result["resource_name"] or config_path
    rtype = result["resource_type"] or "unknown"

    print(f"\n{'='*50}")
    print(f"  Resource:   {name}")
    print(f"  Type:       {rtype}")
    print(f"  Prediction: {'MISCONFIGURED' if result['prediction'] == 1 else 'SECURE'}")
    print(f"  Confidence: {result['confidence']:.1%}")
    print(f"  Risk Level: {result['risk_level']}")
    print(f"  P(secure)={result['probability_secure']:.3f}  "
          f"P(misconfigured)={result['probability_misconfigured']:.3f}")
    print(f"{'='*50}")

    if result["prediction"] == 1:
        print("\n  Risk factors detected:")
        for factor in result["risk_factors"]:
            print(f"    - {factor}")
    else:
        print("\n  No risk factors detected.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python src/predict.py <config.json>")
        sys.exit(1)
    predict(sys.argv[1])
