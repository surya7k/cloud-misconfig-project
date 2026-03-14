import re
import json
import pandas as pd
import os


TERRAGOAT_S3  = "terragoat/terraform/aws/s3.tf"
TERRAGOAT_IAM = "terragoat/terraform/aws/iam.tf"
TERRAGOAT_EC2 = "terragoat/terraform/aws/ec2.tf"
DATA_PROCESSED = "data/processed"



# ── Helpers ──────────────────────────────────────────────────────────────────


def extract_blocks(tf_content, resource_type):
    """Extract all resource blocks of a given type from a .tf file."""
    pattern = rf'resource\s+"{re.escape(resource_type)}"\s+"([\w-]+)"\s+\{{'
    matches = list(re.finditer(pattern, tf_content))
    blocks = []
    for i, match in enumerate(matches):
        start = match.start()
        name = match.group(1)
        depth = 0
        pos = match.end() - 1
        while pos < len(tf_content):
            if tf_content[pos] == '{':
                depth += 1
            elif tf_content[pos] == '}':
                depth -= 1
                if depth == 0:
                    blocks.append((name, tf_content[start:pos+1]))
                    break
            pos += 1
    return blocks



# ── S3 Parser ────────────────────────────────────────────────────────────────


def parse_terragoat_s3(filepath):
    records = []
    with open(filepath) as f:
        content = f.read()

    blocks = extract_blocks(content, "aws_s3_bucket")
    for name, block in blocks:
        record = {
            "resource_type": "s3",
            "resource_name": f"terragoat-{name}",
            "public_access_enabled": 1 if re.search(r'acl\s*=\s*"public', block) else 0,
            "encryption_enabled": 1 if "server_side_encryption_configuration" in block else 0,
            "versioning_enabled": 1 if re.search(r'versioning\s*\{[^}]*enabled\s*=\s*true', block, re.DOTALL) else 0,
            "logging_enabled": 1 if re.search(r'logging\s*\{', block) else 0,
            "has_wildcard_permission": 0,
            "has_admin_privilege": 0,
            "has_priv_esc_potential": 0,
            "policy_length": 0,
            "inbound_rule_count": 0,
            "outbound_rule_count": 0,
            "open_ports_to_world": 0,
            "ssh_open_to_world": 0,
            "rdp_open_to_world": 0,
            # ✅ NEW: default new feature columns to 0 for S3 rows
            "allow_wildcard_action": 0,
            "allow_wildcard_resource": 0,
            "all_ports_open": 0,
        }
        records.append(record)
    return records



# ── IAM Parser ───────────────────────────────────────────────────────────────


PRIV_ESC_ACTIONS = {
    "iam:AttachUserPolicy", "iam:CreatePolicyVersion",
    "iam:PutUserPolicy", "iam:AttachRolePolicy",
    "iam:PassRole", "iam:SetDefaultPolicyVersion"
}


def parse_terragoat_iam(filepath):
    records = []
    with open(filepath) as f:
        content = f.read()

    blocks = extract_blocks(content, "aws_iam_user_policy")
    for name, block in blocks:
        heredoc_match = re.search(r'<<EOF(.*?)EOF', block, re.DOTALL)
        if not heredoc_match:
            continue

        policy_str = heredoc_match.group(1).strip()
        try:
            policy = json.loads(policy_str)
        except json.JSONDecodeError:
            continue

        statements = policy.get("Statement", [])

        # ✅ CHANGED: collect actions/resources only from Allow statements
        allow_actions_flat = []
        allow_has_wildcard_resource = 0
        for stmt in statements:
            if stmt.get("Effect", "Allow") == "Deny":
                continue  # skip Deny — only flag Allow statements
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            allow_actions_flat.extend(actions)
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            if "*" in resources:
                allow_has_wildcard_resource = 1

        # ✅ CHANGED: has_wildcard and has_admin now based on Allow-only actions
        allow_wildcard_action = int(any("*" in a for a in allow_actions_flat))
        allow_wildcard_resource = allow_has_wildcard_resource
        has_wildcard = allow_wildcard_action
        has_admin = int(allow_wildcard_action == 1 and allow_wildcard_resource == 1)

        # priv esc check also scoped to Allow actions
        has_priv_esc = int(any(a in PRIV_ESC_ACTIONS for a in allow_actions_flat))

        record = {
            "resource_type": "iam",
            "resource_name": f"terragoat-{name}",
            "public_access_enabled": 0,
            "encryption_enabled": 0,
            "versioning_enabled": 0,
            "logging_enabled": 0,
            "has_wildcard_permission": has_wildcard,
            "has_admin_privilege": has_admin,
            "has_priv_esc_potential": has_priv_esc,
            "policy_length": len(policy_str),
            "inbound_rule_count": 0,
            "outbound_rule_count": 0,
            "open_ports_to_world": 0,
            "ssh_open_to_world": 0,
            "rdp_open_to_world": 0,
            # ✅ NEW: effect-aware IAM features
            "allow_wildcard_action": allow_wildcard_action,
            "allow_wildcard_resource": allow_wildcard_resource,
            "all_ports_open": 0,
        }
        records.append(record)
    return records



# ── Security Group Parser ─────────────────────────────────────────────────────


def parse_terragoat_sg(filepath):
    records = []
    with open(filepath) as f:
        content = f.read()

    blocks = extract_blocks(content, "aws_security_group")
    for name, block in blocks:
        ingress_blocks = re.findall(r'ingress\s*\{([^}]*)\}', block, re.DOTALL)
        egress_blocks  = re.findall(r'egress\s*\{([^}]*)\}',  block, re.DOTALL)

        open_ports   = 0
        ssh_open     = 0
        rdp_open     = 0
        all_ports_open = 0  # ✅ NEW

        for ing in ingress_blocks:
            if re.search(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', ing):
                from_port = int(re.search(r'from_port\s*=\s*(\d+)', ing).group(1))
                to_port   = int(re.search(r'to_port\s*=\s*(\d+)',   ing).group(1))
                open_ports += 1
                if from_port <= 22   <= to_port: ssh_open = 1
                if from_port <= 3389 <= to_port: rdp_open = 1
                # ✅ NEW: flag if full port range is exposed to world
                if from_port == 0 and to_port == 65535:
                    all_ports_open = 1

        record = {
            "resource_type": "security_group",
            "resource_name": f"terragoat-{name}",
            "public_access_enabled": 0,
            "encryption_enabled": 0,
            "versioning_enabled": 0,
            "logging_enabled": 0,
            "has_wildcard_permission": 0,
            "has_admin_privilege": 0,
            "has_priv_esc_potential": 0,
            "policy_length": 0,
            "inbound_rule_count": len(ingress_blocks),
            "outbound_rule_count": len(egress_blocks),
            "open_ports_to_world": open_ports,
            "ssh_open_to_world": ssh_open,
            "rdp_open_to_world": rdp_open,
            # ✅ NEW: effect-aware/port-range features defaulted for SG
            "allow_wildcard_action": 0,
            "allow_wildcard_resource": 0,
            "all_ports_open": all_ports_open,
        }
        records.append(record)
    return records



# ── Labeling ─────────────────────────────────────────────────────────────────


def label_row(row):
    if row["resource_type"] == "s3":
        if (row["encryption_enabled"] == 0 or
            row["versioning_enabled"] == 0 or
            row["logging_enabled"] == 0 or
            row["public_access_enabled"] == 1):
            return 1
        return 0
    elif row["resource_type"] == "iam":
        if (row["has_wildcard_permission"] == 1 or
            row["has_admin_privilege"] == 1 or
            row["has_priv_esc_potential"] == 1):
            return 1
        return 0
    elif row["resource_type"] == "security_group":
        if row["open_ports_to_world"] > 0 or row["inbound_rule_count"] > 1:
            return 1
        return 0
    return 0



# ── Main ─────────────────────────────────────────────────────────────────────


def main():
    all_records = []
    print("Parsing TerraGoat S3...")
    all_records.extend(parse_terragoat_s3(TERRAGOAT_S3))
    print("Parsing TerraGoat IAM...")
    all_records.extend(parse_terragoat_iam(TERRAGOAT_IAM))
    print("Parsing TerraGoat Security Groups...")
    all_records.extend(parse_terragoat_sg(TERRAGOAT_EC2))

    df = pd.DataFrame(all_records)
    df["label"] = df.apply(label_row, axis=1)

    # Synthetic secure baselines to balance classes
    secure_baselines = [
        {"resource_type": "s3", "resource_name": "baseline-secure-s3-1",
         "public_access_enabled": 0, "encryption_enabled": 1,
         "versioning_enabled": 1, "logging_enabled": 1,
         "has_wildcard_permission": 0, "has_admin_privilege": 0,
         "has_priv_esc_potential": 0, "policy_length": 0,
         "inbound_rule_count": 0, "outbound_rule_count": 0,
         "open_ports_to_world": 0, "ssh_open_to_world": 0,
         "rdp_open_to_world": 0,
         "allow_wildcard_action": 0, "allow_wildcard_resource": 0, "all_ports_open": 0,  # ✅ NEW
         "label": 0},
        {"resource_type": "s3", "resource_name": "baseline-secure-s3-2",
         "public_access_enabled": 0, "encryption_enabled": 1,
         "versioning_enabled": 1, "logging_enabled": 1,
         "has_wildcard_permission": 0, "has_admin_privilege": 0,
         "has_priv_esc_potential": 0, "policy_length": 0,
         "inbound_rule_count": 0, "outbound_rule_count": 0,
         "open_ports_to_world": 0, "ssh_open_to_world": 0,
         "rdp_open_to_world": 0,
         "allow_wildcard_action": 0, "allow_wildcard_resource": 0, "all_ports_open": 0,  # ✅ NEW
         "label": 0},
        {"resource_type": "s3", "resource_name": "baseline-secure-s3-3",
         "public_access_enabled": 0, "encryption_enabled": 1,
         "versioning_enabled": 1, "logging_enabled": 1,
         "has_wildcard_permission": 0, "has_admin_privilege": 0,
         "has_priv_esc_potential": 0, "policy_length": 0,
         "inbound_rule_count": 0, "outbound_rule_count": 0,
         "open_ports_to_world": 0, "ssh_open_to_world": 0,
         "rdp_open_to_world": 0,
         "allow_wildcard_action": 0, "allow_wildcard_resource": 0, "all_ports_open": 0,  # ✅ NEW
         "label": 0},
        {"resource_type": "iam", "resource_name": "baseline-secure-iam-1",
         "public_access_enabled": 0, "encryption_enabled": 0,
         "versioning_enabled": 0, "logging_enabled": 0,
         "has_wildcard_permission": 0, "has_admin_privilege": 0,
         "has_priv_esc_potential": 0, "policy_length": 120,
         "inbound_rule_count": 0, "outbound_rule_count": 0,
         "open_ports_to_world": 0, "ssh_open_to_world": 0,
         "rdp_open_to_world": 0,
         "allow_wildcard_action": 0, "allow_wildcard_resource": 0, "all_ports_open": 0,  # ✅ NEW
         "label": 0},
        {"resource_type": "iam", "resource_name": "baseline-secure-iam-2",
         "public_access_enabled": 0, "encryption_enabled": 0,
         "versioning_enabled": 0, "logging_enabled": 0,
         "has_wildcard_permission": 0, "has_admin_privilege": 0,
         "has_priv_esc_potential": 0, "policy_length": 95,
         "inbound_rule_count": 0, "outbound_rule_count": 0,
         "open_ports_to_world": 0, "ssh_open_to_world": 0,
         "rdp_open_to_world": 0,
         "allow_wildcard_action": 0, "allow_wildcard_resource": 0, "all_ports_open": 0,  # ✅ NEW
         "label": 0},
        {"resource_type": "iam", "resource_name": "baseline-secure-iam-3",
         "public_access_enabled": 0, "encryption_enabled": 0,
         "versioning_enabled": 0, "logging_enabled": 0,
         "has_wildcard_permission": 0, "has_admin_privilege": 0,
         "has_priv_esc_potential": 0, "policy_length": 110,
         "inbound_rule_count": 0, "outbound_rule_count": 0,
         "open_ports_to_world": 0, "ssh_open_to_world": 0,
         "rdp_open_to_world": 0,
         "allow_wildcard_action": 0, "allow_wildcard_resource": 0, "all_ports_open": 0,  # ✅ NEW
         "label": 0},
        {"resource_type": "security_group", "resource_name": "baseline-secure-sg-1",
         "public_access_enabled": 0, "encryption_enabled": 0,
         "versioning_enabled": 0, "logging_enabled": 0,
         "has_wildcard_permission": 0, "has_admin_privilege": 0,
         "has_priv_esc_potential": 0, "policy_length": 0,
         "inbound_rule_count": 1, "outbound_rule_count": 1,
         "open_ports_to_world": 0, "ssh_open_to_world": 0,
         "rdp_open_to_world": 0,
         "allow_wildcard_action": 0, "allow_wildcard_resource": 0, "all_ports_open": 0,  # ✅ NEW
         "label": 0},
        {"resource_type": "security_group", "resource_name": "baseline-secure-sg-2",
         "public_access_enabled": 0, "encryption_enabled": 0,
         "versioning_enabled": 0, "logging_enabled": 0,
         "has_wildcard_permission": 0, "has_admin_privilege": 0,
         "has_priv_esc_potential": 0, "policy_length": 0,
         "inbound_rule_count": 1, "outbound_rule_count": 1,
         "open_ports_to_world": 0, "ssh_open_to_world": 0,
         "rdp_open_to_world": 0,
         "allow_wildcard_action": 0, "allow_wildcard_resource": 0, "all_ports_open": 0,  # ✅ NEW
         "label": 0},
        {"resource_type": "security_group", "resource_name": "baseline-secure-sg-3",
         "public_access_enabled": 0, "encryption_enabled": 0,
         "versioning_enabled": 0, "logging_enabled": 0,
         "has_wildcard_permission": 0, "has_admin_privilege": 0,
         "has_priv_esc_potential": 0, "policy_length": 0,
         "inbound_rule_count": 1, "outbound_rule_count": 1,
         "open_ports_to_world": 0, "ssh_open_to_world": 0,
         "rdp_open_to_world": 0,
         "allow_wildcard_action": 0, "allow_wildcard_resource": 0, "all_ports_open": 0,  # ✅ NEW
         "label": 0},
    ]
    df = pd.concat([df, pd.DataFrame(secure_baselines)], ignore_index=True)

    # Merge with existing labeled data
    existing = pd.read_csv(f"{DATA_PROCESSED}/labeled_features.csv")
    combined = pd.concat([existing, df], ignore_index=True)
    combined = combined.fillna(0)

    output_path = f"{DATA_PROCESSED}/labeled_features.csv"
    combined.to_csv(output_path, index=False)

    print(f"\nDone! Total records: {len(combined)}")
    print(f"Misconfigured: {int(combined['label'].sum())}")
    print(f"Secure: {int((combined['label'] == 0).sum())}")
    print("\nTerraGoat records added:")
    print(df[["resource_type", "resource_name", "label"]].to_string())



if __name__ == "__main__":
    main()
