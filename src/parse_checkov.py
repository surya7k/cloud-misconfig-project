import re
import json
import pandas as pd
import os

DATA_PROCESSED = "data/processed"
CHECKOV_BASE = "checkov/tests/terraform/checks/resource/aws"

S3_FOLDERS = [
    "example_S3GlobalViewACL",
    "example_S3AllowsAnyPrincipal",
    "example_S3BucketObjectEncryptedWithCMK",
    "example_S3SecureDataTransport",
    "example_S3AccessPointPubliclyAccessible",
]

IAM_FOLDERS = [
    "example_IAMAdminPolicyDocument",
    "example_IAMPrivilegeEscalation",
    "example_IAMStarResourcePolicyDocument",
    "example_IAMManagedAdminPolicy",
    "example_IAMWriteAccess",
    "example_IAMPermissionsManagement",
    "example_IAMDataExfiltration",
    "example_IAMCredentialsExposure",
    "example_IAMPolicyAttachedToGroupOrRoles", 
]


SG_FOLDERS = [
    "example_SecurityGroupUnrestrictedIngress22",
    "example_SecurityGroupUnrestrictedIngress3389",
    "example_SecurityGroupUnrestrictedIngress80", 
    "example_SecurityGroupUnrestrictedIngressAny",
    "example_SecurityGroupUnrestrictedEgressAny",
    "example_SecurityGroupRuleDescription",
]

PRIV_ESC_ACTIONS = {
    "iam:AttachUserPolicy", "iam:CreatePolicyVersion",
    "iam:PutUserPolicy", "iam:AttachRolePolicy",
    "iam:PassRole", "iam:SetDefaultPolicyVersion",
    "iam:UpdateLoginProfile", "iam:CreateLoginProfile",
    "iam:AddUserToGroup"
}


# ── Helpers 

def get_label_from_name(resource_name):
    name_lower = resource_name.lower()
    if "fail" in name_lower:
        return 1
    elif "pass" in name_lower:
        return 0
    return None


def extract_blocks(content, resource_type):
    pattern = rf'resource\s+"{re.escape(resource_type)}"\s+"([\w-]+)"\s+\{{'
    matches = list(re.finditer(pattern, content))
    blocks = []
    for match in matches:
        name = match.group(1)
        depth = 0
        pos = match.end() - 1
        while pos < len(content):
            if content[pos] == '{':
                depth += 1
            elif content[pos] == '}':
                depth -= 1
                if depth == 0:
                    blocks.append((name, content[match.start():pos+1]))
                    break
            pos += 1
    return blocks


def read_tf_files(folder_path):
    content = ""
    if not os.path.exists(folder_path):
        return content
    for fname in os.listdir(folder_path):
        if fname.endswith(".tf"):
            with open(os.path.join(folder_path, fname)) as f:
                content += f.read() + "\n"
    return content


# ✅ NEW: parse jsonencode({...}) policy blocks into statement list
def extract_jsonencode_statements(block):
    """
    Pull Statement list out of jsonencode({...}) policy blocks.
    Converts HCL-ish jsonencode content to extractable actions/resources
    using regex since it's not valid JSON.
    """
    statements = []
    # Find jsonencode block for policy or inline_policy
    je_match = re.search(
        r'(?:policy|inline_policy)\s*=\s*jsonencode\s*\(\s*\{(.*?)\}\s*\)',
        block, re.DOTALL
    )
    if not je_match:
        return statements, ""

    je_content = je_match.group(1)

    # Extract each Statement block
    stmt_matches = re.findall(
        r'\{([^{}]*(?:\[[^\]]*\])[^{}]*|[^{}]*)\}', je_content, re.DOTALL
    )
    for stmt_str in stmt_matches:
        effect_m  = re.search(r'Effect\s*=\s*"([^"]+)"', stmt_str)
        action_m  = re.search(r'Action\s*=\s*\[([^\]]*)\]', stmt_str, re.DOTALL)
        action_s  = re.search(r'Action\s*=\s*"([^"]+)"', stmt_str)
        resource_m = re.search(r'Resource\s*=\s*"([^"]+)"', stmt_str)

        effect = effect_m.group(1) if effect_m else "Allow"
        if effect == "Deny":
            continue

        actions = []
        if action_m:
            actions = re.findall(r'"([^"]+)"', action_m.group(1))
        elif action_s:
            actions = [action_s.group(1)]

        resource = resource_m.group(1) if resource_m else ""

        statements.append({
            "Effect": effect,
            "Action": actions,
            "Resource": resource
        })

    return statements, je_content


# ✅ NEW: unified policy feature extractor used by both heredoc and jsonencode
def extract_iam_features(block):
    """
    Returns (statements, policy_str, allow_actions_flat, allow_wildcard_resource)
    by trying heredoc first, then jsonencode.
    """
    statements = []
    policy_str = ""

    # Try heredoc first
    heredoc_match = re.search(
        r'(?:policy|inline_policy)\s*=\s*<<(\w+)\n(.*?)\n\1', block, re.DOTALL
    )
    if heredoc_match:
        policy_str = heredoc_match.group(2).strip()
        try:
            policy = json.loads(policy_str)
            statements = policy.get("Statement", [])
        except json.JSONDecodeError:
            pass
    else:
        # Fall back to jsonencode
        statements, policy_str = extract_jsonencode_statements(block)

    allow_actions_flat = []
    allow_wildcard_resource = 0
    for stmt in statements:
        effect = stmt.get("Effect", "Allow")
        if effect == "Deny":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        allow_actions_flat.extend(actions)
        resource = stmt.get("Resource", "")
        if isinstance(resource, list):
            if "*" in resource:
                allow_wildcard_resource = 1
        elif resource == "*":
            allow_wildcard_resource = 1

    return statements, policy_str, allow_actions_flat, allow_wildcard_resource


# ── S3 Parser ─────────────────────────────────────────────────────────────────

def parse_checkov_s3(folders):
    records = []
    for folder in folders:
        path = os.path.join(CHECKOV_BASE, folder)
        content = read_tf_files(path)
        if not content:
            continue

        for name, block in extract_blocks(content, "aws_s3_bucket"):
            label = get_label_from_name(name)
            if label is None:
                continue
            record = {
                "resource_type": "s3",
                "resource_name": f"checkov-s3-{folder[-15:]}-{name}",
                "public_access_enabled": 1 if re.search(
                    r'acl\s*=\s*"public|AllUsers|AuthenticatedUsers', block) else 0,
                "encryption_enabled": 1 if re.search(
                    r'server_side_encryption_configuration|bucket_key_enabled', block) else 0,
                "versioning_enabled": 1 if re.search(
                    r'versioning\s*\{[^}]*enabled\s*=\s*true', block, re.DOTALL) else 0,
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
                # ✅ NEW columns
                "allow_wildcard_action": 0,
                "allow_wildcard_resource": 0,
                "all_ports_open": 0,
                "label": label,
            }
            records.append(record)

        for name, block in extract_blocks(content, "aws_s3_bucket_acl"):
            label = get_label_from_name(name)
            if label is None:
                continue
            public_uris = [
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
            ]
            dangerous_perms = ["FULL_CONTROL", "WRITE", "WRITE_ACP", "READ_ACP"]
            is_public = 0
            for uri in public_uris:
                if uri in block:
                    for perm in dangerous_perms:
                        if perm in block:
                            is_public = 1
                            break
            record = {
                "resource_type": "s3",
                "resource_name": f"checkov-s3acl-{folder[-15:]}-{name}",
                "public_access_enabled": is_public,
                "encryption_enabled": 0,
                "versioning_enabled": 0,
                "logging_enabled": 0,
                "has_wildcard_permission": 0,
                "has_admin_privilege": 0,
                "has_priv_esc_potential": 0,
                "policy_length": 0,
                "inbound_rule_count": 0,
                "outbound_rule_count": 0,
                "open_ports_to_world": 0,
                "ssh_open_to_world": 0,
                "rdp_open_to_world": 0,
                # ✅ NEW columns
                "allow_wildcard_action": 0,
                "allow_wildcard_resource": 0,
                "all_ports_open": 0,
                "label": label,
            }
            records.append(record)

    return records


# ── IAM Parser ────────────────────────────────────────────────────────────────

def parse_checkov_iam(folders):
    records = []
    for folder in folders:
        path = os.path.join(CHECKOV_BASE, folder)
        content = read_tf_files(path)
        if not content:
            continue

        for rtype in ["aws_iam_policy", "aws_iam_role_policy",
                      "aws_iam_user_policy", "aws_iam_group_policy",
                      "aws_ssoadmin_permission_set_inline_policy"]:
            for name, block in extract_blocks(content, rtype):
                label = get_label_from_name(name)
                if label is None:
                    continue

                # ✅ CHANGED: use unified extractor that handles both heredoc + jsonencode
                statements, policy_str, allow_actions_flat, allow_wildcard_resource = \
                    extract_iam_features(block)

                allow_wildcard_action = int(any("*" in a for a in allow_actions_flat))
                has_admin = int(allow_wildcard_action == 1 and allow_wildcard_resource == 1)
                has_priv_esc = int(any(a in PRIV_ESC_ACTIONS for a in allow_actions_flat))

                record = {
                    "resource_type": "iam",
                    "resource_name": f"checkov-iam-{folder[-20:]}-{name}",
                    "public_access_enabled": 0,
                    "encryption_enabled": 0,
                    "versioning_enabled": 0,
                    "logging_enabled": 0,
                    "has_wildcard_permission": allow_wildcard_action,
                    "has_admin_privilege": has_admin,
                    "has_priv_esc_potential": has_priv_esc,
                    "policy_length": len(policy_str),
                    "inbound_rule_count": 0,
                    "outbound_rule_count": 0,
                    "open_ports_to_world": 0,
                    "ssh_open_to_world": 0,
                    "rdp_open_to_world": 0,
                    # ✅ NEW columns
                    "allow_wildcard_action": allow_wildcard_action,
                    "allow_wildcard_resource": allow_wildcard_resource,
                    "all_ports_open": 0,
                    "label": label,
                }
                records.append(record)

    return records


# ── Security Group Parser ─────────────────────────────────────────────────────

def parse_checkov_sg(folders):
    records = []
    for folder in folders:
        path = os.path.join(CHECKOV_BASE, folder)
        content = read_tf_files(path)
        if not content:
            continue

        for name, block in extract_blocks(content, "aws_security_group"):
            label = get_label_from_name(name)
            if label is None:
                continue

            ingress_blocks = re.findall(r'ingress\s*\{([^}]*)\}', block, re.DOTALL)
            egress_blocks  = re.findall(r'egress\s*\{([^}]*)\}',  block, re.DOTALL)

            open_ports   = 0
            ssh_open     = 0
            rdp_open     = 0
            all_ports_open = 0  # ✅ NEW

            for ing in ingress_blocks:
                is_world = (
                    re.search(r'cidr_blocks\s*=\s*\[.*?0\.0\.0\.0/0', ing, re.DOTALL) or
                    re.search(r'ipv6_cidr_blocks\s*=\s*\[.*?::/0', ing, re.DOTALL)
                )
                if is_world:
                    fp_m = re.search(r'from_port\s*=\s*(\d+)', ing)
                    tp_m = re.search(r'to_port\s*=\s*(\d+)',   ing)
                    if fp_m and tp_m:
                        fp = int(fp_m.group(1))
                        tp = int(tp_m.group(1))
                        open_ports += 1
                        if fp <= 22   <= tp: ssh_open = 1
                        if fp <= 3389 <= tp: rdp_open = 1
                        # ✅ NEW: catch full port range exposure
                        if fp == 0 and tp == 65535:
                            all_ports_open = 1

            record = {
                "resource_type": "security_group",
                "resource_name": f"checkov-sg-{folder[-20:]}-{name}",
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
                # ✅ NEW columns
                "allow_wildcard_action": 0,
                "allow_wildcard_resource": 0,
                "all_ports_open": all_ports_open,
                "label": label,
            }
            records.append(record)

    return records


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("Parsing Checkov S3 fixtures...")
    s3_records  = parse_checkov_s3(S3_FOLDERS)
    print(f"  → {len(s3_records)} S3 records")

    print("Parsing Checkov IAM fixtures...")
    iam_records = parse_checkov_iam(IAM_FOLDERS)
    print(f"  → {len(iam_records)} IAM records")

    print("Parsing Checkov Security Group fixtures...")
    sg_records  = parse_checkov_sg(SG_FOLDERS)
    print(f"  → {len(sg_records)} SG records")

    df = pd.DataFrame(s3_records + iam_records + sg_records)

    existing = pd.read_csv(f"{DATA_PROCESSED}/labeled_features.csv")
    combined = pd.concat([existing, df], ignore_index=True)
    combined = combined.fillna(0)
    combined = combined.drop_duplicates(subset=["resource_name"], keep="first")

    combined.to_csv(f"{DATA_PROCESSED}/labeled_features.csv", index=False)

    print(f"\nDone! Total: {len(combined)} | "
          f"Misconfigured: {int(combined['label'].sum())} | "
          f"Secure: {int((combined['label']==0).sum())}")
    print(f"\nBreakdown of new records added:")
    print(f"  S3:  {len(s3_records)} "
          f"({sum(r['label']==1 for r in s3_records)} misc, "
          f"{sum(r['label']==0 for r in s3_records)} secure)")
    print(f"  IAM: {len(iam_records)} "
          f"({sum(r['label']==1 for r in iam_records)} misc, "
          f"{sum(r['label']==0 for r in iam_records)} secure)")
    print(f"  SG:  {len(sg_records)} "
          f"({sum(r['label']==1 for r in sg_records)} misc, "
          f"{sum(r['label']==0 for r in sg_records)} secure)")

if __name__ == "__main__":
    main()
