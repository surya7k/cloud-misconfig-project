import pandas as pd

def add_labels(df):
    """Add ground truth labels based on your staged configurations."""
    labeled = df.copy()
    labeled["label"] = 0  # default to secure
    
    # S3: misconfigured if ANY security feature missing
    s3_mask = (labeled["resource_type"] == "s3")
    labeled.loc[
        s3_mask & (
            (labeled["encryption_enabled"] == 0) |
            (labeled["versioning_enabled"] == 0) |
            (labeled["logging_enabled"] == 0) |
            (labeled["public_access_enabled"] == 1)
        ),
        "label"
    ] = 1
    
    # IAM: wildcard / admin / priv-esc = misconfigured.
    # Week 10 expansion: also flag (a) two or more dangerous service wildcards
    # (s3:*, iam:*, etc.) and (b) Allow with Resource: "*" but no Condition
    # block (no MFA/IP guardrails) — CIS/AWS-best-practices violations even
    # when no literal Action: "*" is present.
    iam_mask = (labeled["resource_type"] == "iam")
    if "dangerous_service_wildcard" not in labeled.columns:
        labeled["dangerous_service_wildcard"] = 0
    if "has_no_condition" not in labeled.columns:
        labeled["has_no_condition"] = 0
    if "allow_wildcard_resource" not in labeled.columns:
        labeled["allow_wildcard_resource"] = 0

    labeled.loc[
        iam_mask & (
            (labeled["has_wildcard_permission"] == 1) |
            (labeled["has_admin_privilege"] == 1) |
            (labeled["has_priv_esc_potential"] == 1) |
            (labeled["dangerous_service_wildcard"].fillna(0) >= 2) |
            (
                (labeled["has_no_condition"].fillna(0) == 1) &
                (labeled["allow_wildcard_resource"].fillna(0) == 1)
            )
        ),
        "label"
    ] = 1
    
    # Security Groups: open to world OR too many rules = misconfigured
    sg_mask = (labeled["resource_type"] == "security_group")
    labeled.loc[
        sg_mask & (
            (labeled["open_ports_to_world"] > 0) |
            (labeled["inbound_rule_count"] > 1)
        ),
        "label"
    ] = 1
    
    return labeled

if __name__ == "__main__":
    df = pd.read_csv("data/processed/raw_features.csv")
    labeled_df = add_labels(df)
    labeled_df.to_csv("data/processed/labeled_features.csv", index=False)
    print("Labeled data preview:")
    print(labeled_df[["resource_name", "label"] + 
                     ["public_access_enabled", "has_wildcard_permission", 
                      "open_ports_to_world"]].to_string())
