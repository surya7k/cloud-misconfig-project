"""Parse CloudGoat (Rhino Security Labs) intentionally-vulnerable AWS scenarios
into the project's labeled feature schema.

Each AWS scenario at cloudgoat/cloudgoat/scenarios/aws/<scenario>/terraform/*.tf
is walked. S3 buckets, IAM policies (aws_iam_policy / aws_iam_role_policy /
aws_iam_user_policy), and Security Groups are extracted and feature-engineered
into the same 26-column schema used elsewhere in the pipeline.

CloudGoat IAM policies use both heredoc-JSON and jsonencode-HCL forms; the
parser uses regex heuristics that match patterns in BOTH forms rather than
strict JSON parsing.
"""
import re
from pathlib import Path

import pandas as pd

from src.parse_terragoat import extract_blocks, PRIV_ESC_ACTIONS, label_row


SCENARIOS_DIR = Path("cloudgoat/cloudgoat/scenarios/aws")
DATA_PROCESSED = "data/processed"

# Service wildcards that are dangerous but less than full admin
DANGEROUS_SERVICE_PREFIXES = {
    "s3", "iam", "ec2", "lambda", "rds", "kms",
    "secretsmanager", "ssm", "sts", "dynamodb",
}

# Database / data-store ports that should never be open to the world
DB_PORTS_OF_CONCERN = {
    3306, 5432, 1433, 1521, 27017, 6379, 9200,
    11211, 5984, 7000, 7001, 9042,
}

IAM_RESOURCE_TYPES = ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _scan_actions(block):
    """Return all action strings appearing in the block, regardless of HCL/JSON form.

    Matches patterns like:
      "Action": "iam:PassRole"          (JSON heredoc)
      "Action": ["s3:GetObject", ...]   (JSON list)
      Action = "iam:PassRole"           (HCL jsonencode)
      Action = ["s3:GetObject", ...]    (HCL jsonencode list)
    """
    # Find all quoted strings inside Action declarations (single or list form).
    actions = []
    for m in re.finditer(
        r'"?Action"?\s*[:=]\s*(?:\[(.*?)\]|"([^"]+)")',
        block, re.DOTALL,
    ):
        list_body, single = m.groups()
        if single:
            actions.append(single)
        if list_body:
            actions.extend(re.findall(r'"([^"]+)"', list_body))
    return actions


def _scan_resources(block):
    """Return all resource strings declared in Resource blocks."""
    resources = []
    for m in re.finditer(
        r'"?Resource"?\s*[:=]\s*(?:\[(.*?)\]|"([^"]+)")',
        block, re.DOTALL,
    ):
        list_body, single = m.groups()
        if single:
            resources.append(single)
        if list_body:
            resources.extend(re.findall(r'"([^"]+)"', list_body))
    return resources


def _has_condition_block(block):
    """Detect a Condition declaration in either HCL or JSON form."""
    return bool(re.search(r'"?Condition"?\s*[:=]\s*\{', block))


def _has_deny_with_wildcard(block):
    """Heuristic: True if the policy contains a Deny statement to suppress wildcards.

    CloudGoat policies are nearly always Allow-only, but this protects against
    the rare case (e.g. AWS-managed policy boilerplate) where a Deny statement
    pre-empts what we'd otherwise flag.
    """
    return bool(re.search(r'"?Effect"?\s*[:=]\s*"Deny"', block))


# ── S3 Parser ────────────────────────────────────────────────────────────────

def parse_s3(content, scenario):
    records = []
    for name, block in extract_blocks(content, "aws_s3_bucket"):
        # Standard 4 controls
        public = 1 if re.search(r'acl\s*=\s*"public', block) else 0
        encrypt = 1 if "server_side_encryption_configuration" in block else 0
        version = 1 if re.search(r'versioning\s*\{[^}]*enabled\s*=\s*true', block, re.DOTALL) else 0
        logging = 1 if re.search(r'logging\s*\{', block) else 0

        # Extended S3 features (default 0; CloudGoat S3 buckets rarely opt in)
        records.append({
            "resource_type": "s3",
            "resource_name": f"cloudgoat-{scenario}-{name}",
            "source": "cloudgoat",
            "public_access_enabled": public,
            "encryption_enabled": encrypt,
            "versioning_enabled": version,
            "logging_enabled": logging,
            "has_wildcard_permission": 0, "has_admin_privilege": 0,
            "has_priv_esc_potential": 0, "policy_length": 0,
            "inbound_rule_count": 0, "outbound_rule_count": 0,
            "open_ports_to_world": 0, "ssh_open_to_world": 0,
            "rdp_open_to_world": 0, "allow_wildcard_action": 0,
            "allow_wildcard_resource": 0, "all_ports_open": 0,
            "bucket_policy_wildcard": 0,
            "mfa_delete_enabled": 0,
            "tls_enforced": 0,
            "dangerous_service_wildcard": 0,
            "has_no_condition": 0,
            "db_port_open_to_world": 0,
            "egress_unrestricted": 0,
        })

    # Detect explicit aws_s3_bucket_policy resources granting Principal: "*"
    for _policy_name, block in extract_blocks(content, "aws_s3_bucket_policy"):
        if not re.search(r'"?Principal"?\s*[:=]\s*"\*"', block):
            continue
        # Try to map this to an existing bucket record by bucket reference; if
        # we can't, skip (we only flag the wildcard via a bucket whose record
        # we already have). Cheap inference: look for `bucket = aws_s3_bucket.<name>`.
        m = re.search(r'bucket\s*=\s*aws_s3_bucket\.([\w-]+)', block)
        if not m:
            continue
        target = f"cloudgoat-{scenario}-{m.group(1)}"
        for r in records:
            if r["resource_name"] == target:
                r["bucket_policy_wildcard"] = 1
                break

    return records


# ── IAM Parser ───────────────────────────────────────────────────────────────

def parse_iam(content, scenario):
    records = []
    for tf_type in IAM_RESOURCE_TYPES:
        for name, block in extract_blocks(content, tf_type):
            # Heuristic action/resource scan covers both jsonencode and heredoc forms
            actions = _scan_actions(block)
            resources = _scan_resources(block)

            # If a Deny statement is present and would override, conservatively skip
            # the over-permissive flags. CloudGoat almost never does this — but be safe.
            deny_present = _has_deny_with_wildcard(block)

            has_wildcard = int(any(a == "*" for a in actions) and not deny_present)
            has_admin = int(bool(has_wildcard) and any(r == "*" for r in resources))
            has_priv_esc = int(any(a in PRIV_ESC_ACTIONS for a in actions))

            allow_wildcard_action = has_wildcard
            allow_wildcard_resource = int(any(r == "*" for r in resources))

            dangerous_service_count = 0
            for a in actions:
                if isinstance(a, str) and a.endswith(":*"):
                    prefix = a.split(":", 1)[0]
                    if prefix in DANGEROUS_SERVICE_PREFIXES:
                        dangerous_service_count += 1

            no_condition = int(not _has_condition_block(block))

            # Length proxy — strip whitespace to get a more comparable measure
            policy_length = len(re.sub(r"\s+", " ", block))

            records.append({
                "resource_type": "iam",
                "resource_name": f"cloudgoat-{scenario}-{name}",
                "source": "cloudgoat",
                "public_access_enabled": 0, "encryption_enabled": 0,
                "versioning_enabled": 0, "logging_enabled": 0,
                "has_wildcard_permission": has_wildcard,
                "has_admin_privilege": has_admin,
                "has_priv_esc_potential": has_priv_esc,
                "policy_length": policy_length,
                "inbound_rule_count": 0, "outbound_rule_count": 0,
                "open_ports_to_world": 0, "ssh_open_to_world": 0,
                "rdp_open_to_world": 0,
                "allow_wildcard_action": allow_wildcard_action,
                "allow_wildcard_resource": allow_wildcard_resource,
                "all_ports_open": 0,
                "bucket_policy_wildcard": 0,
                "mfa_delete_enabled": 0,
                "tls_enforced": 0,
                "dangerous_service_wildcard": dangerous_service_count,
                "has_no_condition": no_condition,
                "db_port_open_to_world": 0,
                "egress_unrestricted": 0,
            })
    return records


# ── Security Group Parser ────────────────────────────────────────────────────

def _parse_port(text, key):
    m = re.search(rf'{key}\s*=\s*(\d+)', text)
    return int(m.group(1)) if m else None


def parse_sg(content, scenario):
    records = []
    for name, block in extract_blocks(content, "aws_security_group"):
        ingress_blocks = re.findall(r'ingress\s*\{([^}]*)\}', block, re.DOTALL)
        egress_blocks = re.findall(r'egress\s*\{([^}]*)\}', block, re.DOTALL)

        open_ports = ssh_open = rdp_open = all_ports_open = 0
        db_open = 0

        for ing in ingress_blocks:
            if not re.search(
                r'cidr_blocks\s*=\s*\[\s*"(?:0\.0\.0\.0/0|::/0)"',
                ing,
            ):
                continue
            fp = _parse_port(ing, "from_port")
            tp = _parse_port(ing, "to_port")
            if fp is None or tp is None:
                continue
            open_ports += 1
            if fp <= 22 <= tp:
                ssh_open = 1
            if fp <= 3389 <= tp:
                rdp_open = 1
            if fp == 0 and tp >= 65535:
                all_ports_open = 1
            for db_port in DB_PORTS_OF_CONCERN:
                if fp <= db_port <= tp:
                    db_open += 1
                    break  # count one DB exposure per rule

        egress_unrestricted = 0
        for eg in egress_blocks:
            if not re.search(
                r'cidr_blocks\s*=\s*\[\s*"(?:0\.0\.0\.0/0|::/0)"',
                eg,
            ):
                continue
            proto = re.search(r'protocol\s*=\s*"([^"]+)"', eg)
            proto_v = proto.group(1).lower() if proto else ""
            fp = _parse_port(eg, "from_port") or 0
            tp = _parse_port(eg, "to_port") or 0
            if proto_v in ("-1", "all") or (fp == 0 and tp >= 65535):
                egress_unrestricted = 1
                break

        records.append({
            "resource_type": "security_group",
            "resource_name": f"cloudgoat-{scenario}-{name}",
            "source": "cloudgoat",
            "public_access_enabled": 0, "encryption_enabled": 0,
            "versioning_enabled": 0, "logging_enabled": 0,
            "has_wildcard_permission": 0, "has_admin_privilege": 0,
            "has_priv_esc_potential": 0, "policy_length": 0,
            "inbound_rule_count": len(ingress_blocks),
            "outbound_rule_count": len(egress_blocks),
            "open_ports_to_world": open_ports,
            "ssh_open_to_world": ssh_open,
            "rdp_open_to_world": rdp_open,
            "allow_wildcard_action": 0,
            "allow_wildcard_resource": 0,
            "all_ports_open": all_ports_open,
            "bucket_policy_wildcard": 0,
            "mfa_delete_enabled": 0,
            "tls_enforced": 0,
            "dangerous_service_wildcard": 0,
            "has_no_condition": 0,
            "db_port_open_to_world": db_open,
            "egress_unrestricted": egress_unrestricted,
        })
    return records


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if not SCENARIOS_DIR.exists():
        print(f"CloudGoat not found at {SCENARIOS_DIR}. "
              f"Run: git clone --depth 1 https://github.com/RhinoSecurityLabs/cloudgoat.git cloudgoat")
        return

    all_records = []
    for scenario in sorted(SCENARIOS_DIR.iterdir()):
        if not scenario.is_dir():
            continue
        tf_dir = scenario / "terraform"
        if not tf_dir.exists():
            continue
        for tf_file in sorted(tf_dir.glob("*.tf")):
            try:
                content = tf_file.read_text(errors="ignore")
            except Exception:
                continue
            all_records.extend(parse_s3(content, scenario.name))
            all_records.extend(parse_iam(content, scenario.name))
            all_records.extend(parse_sg(content, scenario.name))

    if not all_records:
        print("No CloudGoat resources found.")
        return

    df = pd.DataFrame(all_records)
    df["label"] = df.apply(label_row, axis=1)

    existing = pd.read_csv(f"{DATA_PROCESSED}/labeled_features.csv")
    combined = pd.concat([existing, df], ignore_index=True)
    combined = combined.fillna(0)
    combined = combined.drop_duplicates(subset=["resource_name"], keep="first")
    combined.to_csv(f"{DATA_PROCESSED}/labeled_features.csv", index=False)

    cg_only = combined[combined["resource_name"].str.startswith("cloudgoat-")]
    print(f"Added {len(df)} CloudGoat records ({len(cg_only)} retained after dedup)")
    print(f"  by resource_type: {cg_only['resource_type'].value_counts().to_dict()}")
    print(f"  misconfigured: {int(cg_only['label'].sum())} of {len(cg_only)}")
    print(f"\nCloudGoat scenarios contributing rows: "
          f"{cg_only['resource_name'].str.extract(r'cloudgoat-([^-]+(?:_[^-]+)*?)-').iloc[:,0].nunique()}")
    print(f"Total dataset: {len(combined)} | "
          f"Misc: {int(combined['label'].sum())} | "
          f"Secure: {int((combined['label']==0).sum())}")


if __name__ == "__main__":
    main()
