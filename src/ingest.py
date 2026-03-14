import json
import os
import pandas as pd

DATA_RAW = "data/raw"
DATA_PROCESSED = "data/processed"

# ── S3 ──────────────────────────────────────────────────────────────────────

def parse_s3_bucket(bucket_name, prefix):
    """Parse all 4 S3 JSON files for one bucket into a feature dict."""
    record = {"resource_type": "s3", "resource_name": bucket_name}

    # Public access (ACL)
    try:
        with open(f"{DATA_RAW}/s3_{prefix}_acl.json") as f:
            acl = json.load(f)
        grants = acl.get("Grants", [])
        public_grantees = [
            g for g in grants
            if g.get("Grantee", {}).get("URI", "")
            in [
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
            ]
        ]
        record["public_access_enabled"] = 1 if public_grantees else 0
    except Exception:
        record["public_access_enabled"] = 0

    # Encryption
    try:
        with open(f"{DATA_RAW}/s3_{prefix}_encryption.json") as f:
            enc = json.load(f)
        rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        record["encryption_enabled"] = 1 if rules else 0
    except Exception:
        record["encryption_enabled"] = 0

    # Versioning
    try:
        with open(f"{DATA_RAW}/s3_{prefix}_versioning.json") as f:
            ver = json.load(f)
        record["versioning_enabled"] = 1 if ver.get("Status") == "Enabled" else 0
    except Exception:
        record["versioning_enabled"] = 0

    # Logging
    try:
        with open(f"{DATA_RAW}/s3_{prefix}_logging.json") as f:
            log = json.load(f)
        record["logging_enabled"] = 1 if log.get("LoggingEnabled") else 0
    except Exception:
        record["logging_enabled"] = 0

    return record


# ── IAM ─────────────────────────────────────────────────────────────────────

def has_wildcard(statements):
    for stmt in statements:
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if "*" in actions:
            return 1
    return 0

def has_admin_privilege(statements):
    for stmt in statements:
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources and stmt.get("Effect") == "Allow":
            return 1
    return 0

def has_priv_esc(statements):
    priv_esc_actions = {
        "iam:AttachUserPolicy", "iam:CreatePolicyVersion",
        "iam:PutUserPolicy", "iam:AttachRolePolicy",
        "iam:PassRole", "iam:SetDefaultPolicyVersion"
    }
    for stmt in statements:
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if any(a in priv_esc_actions for a in actions):
            return 1
    return 0
def has_allow_wildcard_action(statements):
    for stmt in statements:
        if stmt.get("Effect", "Allow") == "Deny":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        if "*" in actions:
            return 1
    return 0

def has_allow_wildcard_resource(statements):
    for stmt in statements:
        if stmt.get("Effect", "Allow") == "Deny":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources:
            return 1
    return 0

def parse_iam_policy(policy_name, filename):
    """Parse an IAM policy JSON file into a feature dict."""
    record = {"resource_type": "iam", "resource_name": policy_name}

    try:
        with open(f"{DATA_RAW}/{filename}") as f:
            raw = f.read()

        # Files have two JSON objects concatenated — split and parse both
        decoder = json.JSONDecoder()
        objects = []
        idx = 0
        while idx < len(raw):
            raw_stripped = raw[idx:].strip()
            if not raw_stripped:
                break
            obj, offset = decoder.raw_decode(raw.strip(), idx)
            objects.append(obj)
            idx += offset + 1

        statements = []
        policy_doc_str = ""
        for obj in objects:
            # Get policy version document
            if "PolicyVersion" in obj:
                doc = obj["PolicyVersion"].get("Document", {})
                statements = doc.get("Statement", [])
                policy_doc_str = json.dumps(doc)

        record["has_wildcard_permission"]  = has_wildcard(statements)
        record["has_admin_privilege"]      = has_admin_privilege(statements)
        record["has_priv_esc_potential"]   = has_priv_esc(statements)
        record["policy_length"]            = len(policy_doc_str)
        record["allow_wildcard_action"]    = has_allow_wildcard_action(statements)
        record["allow_wildcard_resource"]  = has_allow_wildcard_resource(statements)


    except Exception as e:
        print(f"  Warning parsing {filename}: {e}")
        record.update({
            "has_wildcard_permission": 0,
            "has_admin_privilege": 0,
            "has_priv_esc_potential": 0,
            "policy_length": 0,
            "allow_wildcard_action": 0,
            "allow_wildcard_resource": 0
        })


    return record


# ── Security Groups ──────────────────────────────────────────────────────────

def is_open_to_world(ip_ranges):
    return any(
        r.get("CidrIp") in ["0.0.0.0/0", "::/0"]
        for r in ip_ranges
    )

def parse_security_groups(filename):
    """Parse all security groups from one JSON file into feature dicts."""
    records = []
    try:
        with open(f"{DATA_RAW}/{filename}") as f:
            data = json.load(f)

        for sg in data.get("SecurityGroups", []):
            record = {
                "resource_type": "security_group",
                "resource_name": sg.get("GroupName", "unknown")
            }
            inbound = sg.get("IpPermissions", [])
            outbound = sg.get("IpPermissionsEgress", [])

            open_ports = []
            for rule in inbound:
                ip_ranges = rule.get("IpRanges", [])
                if is_open_to_world(ip_ranges):
                    from_port = rule.get("FromPort", -1)
                    to_port = rule.get("ToPort", -1)
                    open_ports.append((from_port, to_port))

            record["inbound_rule_count"] = len(inbound)
            record["outbound_rule_count"] = len(outbound)
            record["open_ports_to_world"] = len(open_ports)
            record["ssh_open_to_world"] = int(
                any(fp <= 22 <= tp for fp, tp in open_ports)
            )
            record["rdp_open_to_world"] = int(
                any(fp <= 3389 <= tp for fp, tp in open_ports)
            )
            record["all_ports_open"] = int(
                any(fp == 0 and tp >= 65535 for fp, tp in open_ports)
            )

            records.append(record)

    except Exception as e:
        print(f"  Warning parsing {filename}: {e}")

    return records


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(DATA_PROCESSED, exist_ok=True)
    all_records = []

    # S3
    print("Parsing S3 buckets...")
    all_records.append(parse_s3_bucket("misconfigured-test-bucket-ist584", "misconfigured"))
    all_records.append(parse_s3_bucket("secure-test-bucket-ist584", "secure"))

    # IAM
    print("Parsing IAM policies...")
    all_records.append(parse_iam_policy("MisconfiguredWildcardPolicy", "iam_wildcard_policy.json"))
    all_records.append(parse_iam_policy("MisconfiguredPrivEscPolicy",  "iam_privesc_policy.json"))
    all_records.append(parse_iam_policy("SecureReadOnlyPolicy",        "iam_secure_policy.json"))

    # Security Groups
    print("Parsing Security Groups...")
    all_records.extend(parse_security_groups("security_groups.json"))

    # Build DataFrame
    df = pd.DataFrame(all_records)
    df = df.fillna(0)

    # Save
    output_path = f"{DATA_PROCESSED}/raw_features.csv"
    df.to_csv(output_path, index=False)
    print(f"\nDone! Saved {len(df)} records to {output_path}")
    print("\nPreview:")
    print(df.to_string())


if __name__ == "__main__":
    main()
