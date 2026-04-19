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
    
    # IAM: wildcard OR priv-esc = misconfigured
    iam_mask = (labeled["resource_type"] == "iam")
    labeled.loc[
        iam_mask & (
            (labeled["has_wildcard_permission"] == 1) |
            (labeled["has_admin_privilege"] == 1) |
            (labeled["has_priv_esc_potential"] == 1)
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
