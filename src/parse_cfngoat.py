import yaml
import json
import re
import pandas as pd
import os

CFNGOAT_YAML    = "cfngoat/cfngoat.yaml"
TERRAGOAT_DBAPP = "terragoat/terraform/aws/db-app.tf"
DATA_PROCESSED  = "data/processed"

PRIV_ESC_ACTIONS = {
    "iam:AttachUserPolicy", "iam:CreatePolicyVersion",
    "iam:PutUserPolicy", "iam:AttachRolePolicy",
    "iam:PassRole", "iam:SetDefaultPolicyVersion"
}

# Handle CloudFormation intrinsic function tags safely
def _cfn_constructor(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    elif isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)

yaml.add_multi_constructor('', _cfn_constructor, Loader=yaml.SafeLoader)



# ── Cfngoat YAML Parser ───────────────────────────────────────────────────────

def parse_cfngoat(filepath):
    records = []
    with open(filepath) as f:
        template = yaml.load(f, Loader=yaml.SafeLoader)
    resources = template.get("Resources", {})

    for logical_id, resource in resources.items():
        rtype = resource.get("Type", "")
        props = resource.get("Properties", {})

        # ── S3 ──────────────────────────────────────────────────────────────
        if rtype == "AWS::S3::Bucket":
            acl = props.get("AccessControl", "Private")
            encryption = props.get("BucketEncryption", None)
            versioning = props.get("VersioningConfiguration", {})
            logging_cfg = props.get("LoggingConfiguration", None)

            record = {
                "resource_type": "s3",
                "resource_name": f"cfngoat-{logical_id}",
                "public_access_enabled": 1 if acl in ["PublicRead", "PublicReadWrite", "AuthenticatedRead"] else 0,
                "encryption_enabled": 1 if encryption else 0,
                "versioning_enabled": 1 if versioning.get("Status") == "Enabled" else 0,
                "logging_enabled": 1 if logging_cfg else 0,
                "has_wildcard_permission": 0,
                "has_admin_privilege": 0,
                "has_priv_esc_potential": 0,
                "policy_length": 0,
                "inbound_rule_count": 0,
                "outbound_rule_count": 0,
                "open_ports_to_world": 0,
                "ssh_open_to_world": 0,
                "rdp_open_to_world": 0,
            }
            records.append(record)

        # ── IAM Policy ───────────────────────────────────────────────────────
        elif rtype == "AWS::IAM::Policy":
            doc = props.get("PolicyDocument", {})
            statements = doc.get("Statement", [])
            policy_str = json.dumps(doc, default=str)
            actions_flat = []
            for stmt in statements:
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                actions_flat.extend(actions)

            has_wildcard = int(any("*" in a for a in actions_flat))
            has_admin = int(
                any("*" in a for a in actions_flat) and
                any(stmt.get("Resource") == "*" for stmt in statements)
            )
            has_priv_esc = int(any(a in PRIV_ESC_ACTIONS for a in actions_flat))

            record = {
                "resource_type": "iam",
                "resource_name": f"cfngoat-{logical_id}",
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
            }
            records.append(record)

        # ── Security Groups ──────────────────────────────────────────────────
        elif rtype == "AWS::EC2::SecurityGroup":
            ingress = props.get("SecurityGroupIngress", [])
            egress  = props.get("SecurityGroupEgress",  [])

            open_ports = 0
            ssh_open   = 0
            rdp_open   = 0

            for rule in ingress:
                cidr = rule.get("CidrIp", "")
                # Skip rules scoped to VPC CIDR (like !GetAtt WebVPC.CidrBlock)
                if cidr == "0.0.0.0/0" or cidr == "::/0":
                    fp = int(rule.get("FromPort", 0))
                    tp = int(rule.get("ToPort",   0))
                    open_ports += 1
                    if fp <= 22  <= tp: ssh_open = 1
                    if fp <= 3389 <= tp: rdp_open = 1

            record = {
                "resource_type": "security_group",
                "resource_name": f"cfngoat-{logical_id}",
                "public_access_enabled": 0,
                "encryption_enabled": 0,
                "versioning_enabled": 0,
                "logging_enabled": 0,
                "has_wildcard_permission": 0,
                "has_admin_privilege": 0,
                "has_priv_esc_potential": 0,
                "policy_length": 0,
                "inbound_rule_count": len(ingress),
                "outbound_rule_count": len(egress),
                "open_ports_to_world": open_ports,
                "ssh_open_to_world": ssh_open,
                "rdp_open_to_world": rdp_open,
            }
            records.append(record)

    return records


# ── TerraGoat db-app.tf Parser ───────────────────────────────────────────────

def parse_dbapp_tf(filepath):
    import re
    records = []
    with open(filepath) as f:
        content = f.read()

    # Find aws_iam_role_policy blocks
    pattern = r'resource\s+"aws_iam_role_policy"\s+"([\w-]+)"\s+\{'
    matches = list(re.finditer(pattern, content))

    for match in matches:
        name = match.group(1)
        # Extract heredoc policy
        heredoc = re.search(r'<<EOF(.*?)EOF', content[match.start():], re.DOTALL)
        if not heredoc:
            continue
        policy_str = heredoc.group(1).strip()
        try:
            policy = json.loads(policy_str)
        except json.JSONDecodeError:
            continue

        statements = policy.get("Statement", [])
        actions_flat = []
        for stmt in statements:
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            actions_flat.extend(actions)

        record = {
            "resource_type": "iam",
            "resource_name": f"terragoat-dbapp-{name}",
            "public_access_enabled": 0,
            "encryption_enabled": 0,
            "versioning_enabled": 0,
            "logging_enabled": 0,
            "has_wildcard_permission": int(any("*" in a for a in actions_flat)),
            "has_admin_privilege": int(
                any("*" in a for a in actions_flat) and
                any(stmt.get("Resource") == "*" for stmt in statements)
            ),
            "has_priv_esc_potential": int(any(a in PRIV_ESC_ACTIONS for a in actions_flat)),
            "policy_length": len(policy_str),
            "inbound_rule_count": 0,
            "outbound_rule_count": 0,
            "open_ports_to_world": 0,
            "ssh_open_to_world": 0,
            "rdp_open_to_world": 0,
        }
        records.append(record)
    return records


# ── Labeling ─────────────────────────────────────────────────────────────────

def label_row(row):
    if row["resource_type"] == "s3":
        return 1 if (row["encryption_enabled"] == 0 or
                     row["versioning_enabled"] == 0 or
                     row["logging_enabled"] == 0 or
                     row["public_access_enabled"] == 1) else 0
    elif row["resource_type"] == "iam":
        return 1 if (row["has_wildcard_permission"] == 1 or
                     row["has_admin_privilege"] == 1 or
                     row["has_priv_esc_potential"] == 1) else 0
    elif row["resource_type"] == "security_group":
        return 1 if (row["open_ports_to_world"] > 0 or
                     row["inbound_rule_count"] > 1) else 0
    return 0


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    all_records = []

    print("Parsing Cfngoat YAML...")
    all_records.extend(parse_cfngoat(CFNGOAT_YAML))

    print("Parsing TerraGoat db-app.tf...")
    all_records.extend(parse_dbapp_tf(TERRAGOAT_DBAPP))

    df = pd.DataFrame(all_records)
    df["label"] = df.apply(label_row, axis=1)

    # Merge with existing labeled data
    existing = pd.read_csv(f"{DATA_PROCESSED}/labeled_features.csv")
    combined = pd.concat([existing, df], ignore_index=True)
    combined = combined.fillna(0)

    # Remove duplicates by resource_name
    combined = combined.drop_duplicates(subset=["resource_name"], keep="first")

    output_path = f"{DATA_PROCESSED}/labeled_features.csv"
    combined.to_csv(output_path, index=False)

    print(f"\nDone! Total records: {len(combined)}")
    print(f"Misconfigured: {int(combined['label'].sum())}")
    print(f"Secure: {int((combined['label'] == 0).sum())}")
    print("\nNew records added:")
    print(df[["resource_type", "resource_name", "label"]].to_string())

if __name__ == "__main__":
    main()
