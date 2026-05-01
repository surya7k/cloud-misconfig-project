#!/usr/bin/env python3
"""
Parse AWS Security Reference Architecture (SRA) examples for secure training data.
All resources from this repo represent security best practices → label=0 (secure).
"""

import os
import re
import json
import subprocess
import logging

import yaml
import numpy as np
import pandas as pd

# Handle CloudFormation intrinsic function tags safely (same as parse_cfngoat.py)
def _cfn_constructor(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    elif isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)

yaml.add_multi_constructor('', _cfn_constructor, Loader=yaml.SafeLoader)


DATA_PROCESSED = "data/processed"
AWSSRA_DIR = "data/raw/awssra"
AWSSRA_REPO = "https://github.com/aws-samples/aws-security-reference-architecture-examples"

PRIV_ESC_ACTIONS = {
    "iam:PassRole", "iam:CreateUser", "iam:AttachUserPolicy",
    "iam:CreateAccessKey", "iam:CreatePolicyVersion",
    "iam:PutUserPolicy", "iam:AttachRolePolicy",
    "iam:SetDefaultPolicyVersion",
}

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)


# ── Helpers ──────────────────────────────────────────────────────────────────

def make_s3_record(name):
    """Return a base S3 record dict with NaN for non-S3 features."""
    return {
        "resource_type": "s3",
        "resource_name": f"awssra-{name}",
        "source": "awssra",
        "label": 0,
        # S3 features — defaults (will be overridden by caller)
        "public_access_enabled": 0,
        "encryption_enabled": 0,
        "versioning_enabled": 0,
        "logging_enabled": 0,
        # IAM features → not applicable
        "has_wildcard_permission": np.nan,
        "has_admin_privilege": np.nan,
        "has_priv_esc_potential": np.nan,
        "policy_length": np.nan,
        "allow_wildcard_action": np.nan,
        "allow_wildcard_resource": np.nan,
        # SG features → not applicable
        "inbound_rule_count": np.nan,
        "outbound_rule_count": np.nan,
        "open_ports_to_world": np.nan,
        "ssh_open_to_world": np.nan,
        "rdp_open_to_world": np.nan,
        "all_ports_open": np.nan,
        # Extended S3 features — AWSSRA baselines are secure
        "bucket_policy_wildcard": 0,
        "mfa_delete_enabled": 1,
        "tls_enforced": 1,
        # Extended IAM/SG features → not applicable
        "dangerous_service_wildcard": np.nan,
        "has_no_condition": np.nan,
        "db_port_open_to_world": np.nan,
        "egress_unrestricted": np.nan,
    }


def make_iam_record(name):
    """Return a base IAM record dict with NaN for non-IAM features."""
    return {
        "resource_type": "iam",
        "resource_name": f"awssra-{name}",
        "source": "awssra",
        "label": 0,
        # S3 features → not applicable
        "public_access_enabled": np.nan,
        "encryption_enabled": np.nan,
        "versioning_enabled": np.nan,
        "logging_enabled": np.nan,
        # IAM features — defaults
        "has_wildcard_permission": 0,
        "has_admin_privilege": 0,
        "has_priv_esc_potential": 0,
        "policy_length": 0,
        "allow_wildcard_action": 0,
        "allow_wildcard_resource": 0,
        # SG features → not applicable
        "inbound_rule_count": np.nan,
        "outbound_rule_count": np.nan,
        "open_ports_to_world": np.nan,
        "ssh_open_to_world": np.nan,
        "rdp_open_to_world": np.nan,
        "all_ports_open": np.nan,
        # Extended S3 features → not applicable
        "bucket_policy_wildcard": np.nan,
        "mfa_delete_enabled": np.nan,
        "tls_enforced": np.nan,
        # Extended IAM features — AWSSRA baselines are secure
        "dangerous_service_wildcard": 0,
        "has_no_condition": 0,
        # Extended SG features → not applicable
        "db_port_open_to_world": np.nan,
        "egress_unrestricted": np.nan,
    }


def make_sg_record(name):
    """Return a base SecurityGroup record dict with NaN for non-SG features."""
    return {
        "resource_type": "security_group",
        "resource_name": f"awssra-{name}",
        "source": "awssra",
        "label": 0,
        # S3 features → not applicable
        "public_access_enabled": np.nan,
        "encryption_enabled": np.nan,
        "versioning_enabled": np.nan,
        "logging_enabled": np.nan,
        # IAM features → not applicable
        "has_wildcard_permission": np.nan,
        "has_admin_privilege": np.nan,
        "has_priv_esc_potential": np.nan,
        "policy_length": np.nan,
        "allow_wildcard_action": np.nan,
        "allow_wildcard_resource": np.nan,
        # SG features — defaults
        "inbound_rule_count": 0,
        "outbound_rule_count": 0,
        "open_ports_to_world": 0,
        "ssh_open_to_world": 0,
        "rdp_open_to_world": 0,
        "all_ports_open": 0,
        # Extended S3/IAM features → not applicable
        "bucket_policy_wildcard": np.nan,
        "mfa_delete_enabled": np.nan,
        "tls_enforced": np.nan,
        "dangerous_service_wildcard": np.nan,
        "has_no_condition": np.nan,
        # Extended SG features — AWSSRA baselines are secure
        "db_port_open_to_world": 0,
        "egress_unrestricted": 0,
    }


def normalize_actions(actions):
    """Ensure actions is always a list of strings."""
    if isinstance(actions, str):
        return [actions]
    if isinstance(actions, list):
        return [str(a) for a in actions]
    return []


def normalize_resources(resources):
    """Ensure resources is always a list of strings."""
    if isinstance(resources, str):
        return [resources]
    if isinstance(resources, list):
        return [str(r) for r in resources]
    return []


def analyze_iam_policy(policy_doc):
    """Analyze an IAM policy document and return feature values."""
    if not isinstance(policy_doc, dict):
        return 0, 0, 0, 0, 0, 0, 0

    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    policy_str = json.dumps(policy_doc, default=str)
    policy_length = len(policy_str)

    allow_actions_flat = []
    allow_wildcard_resource = 0

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        effect = stmt.get("Effect", "Allow")
        if effect == "Deny":
            continue

        actions = normalize_actions(stmt.get("Action", []))
        allow_actions_flat.extend(actions)

        resources = normalize_resources(stmt.get("Resource", []))
        if "*" in resources:
            allow_wildcard_resource = 1

    allow_wildcard_action = int(any("*" in a for a in allow_actions_flat))
    has_wildcard = allow_wildcard_action
    has_admin = int(allow_wildcard_action == 1 and allow_wildcard_resource == 1)
    has_priv_esc = int(any(a in PRIV_ESC_ACTIONS for a in allow_actions_flat))

    return (has_wildcard, has_admin, has_priv_esc, policy_length,
            allow_wildcard_action, allow_wildcard_resource)


def analyze_sg_rules(ingress_rules, egress_rules):
    """Analyze security group rules and return feature values."""
    inbound_count = len(ingress_rules) if ingress_rules else 0
    outbound_count = len(egress_rules) if egress_rules else 0
    open_ports = 0
    ssh_open = 0
    rdp_open = 0
    all_ports_open = 0

    for rule in (ingress_rules or []):
        if not isinstance(rule, dict):
            continue
        cidr = str(rule.get("CidrIp", rule.get("cidr_blocks", "")))
        cidr6 = str(rule.get("CidrIpv6", rule.get("ipv6_cidr_blocks", "")))

        is_world = ("0.0.0.0/0" in cidr or "::/0" in cidr6 or
                     "0.0.0.0/0" in cidr6 or "::/0" in cidr)
        if not is_world:
            continue

        fp = int(rule.get("FromPort", rule.get("from_port", 0)))
        tp = int(rule.get("ToPort", rule.get("to_port", 0)))
        protocol = str(rule.get("IpProtocol", rule.get("protocol", "")))

        open_ports += 1
        if fp <= 22 <= tp:
            ssh_open = 1
        if fp <= 3389 <= tp:
            rdp_open = 1
        if (fp == 0 and tp == 65535) or protocol == "-1":
            all_ports_open = 1

    return inbound_count, outbound_count, open_ports, ssh_open, rdp_open, all_ports_open


# ── Clone Logic ─────────────���────────────────────────────────────────────────

def ensure_repo_cloned():
    """Clone the AWS SRA repo if not already present."""
    if os.path.isdir(AWSSRA_DIR):
        log.info(f"  AWS SRA repo already present at {AWSSRA_DIR}")
        return True
    log.info(f"  Cloning AWS SRA repo to {AWSSRA_DIR}...")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", AWSSRA_REPO, AWSSRA_DIR],
            check=True, capture_output=True, text=True
        )
        log.info(f"  Clone complete.")
        return True
    except subprocess.CalledProcessError as e:
        log.error(f"  Failed to clone repo: {e.stderr}")
        return False


# ── File Discovery ───────────────────────────────────────────────────────────

def discover_files():
    """Recursively find all .tf, .yaml, and .json files under the SRA repo."""
    tf_files = []
    cfn_files = []

    for root, _dirs, files in os.walk(AWSSRA_DIR):
        for fname in files:
            fpath = os.path.join(root, fname)
            if fname.endswith(".tf"):
                tf_files.append(fpath)
            elif fname.endswith(".yaml") or fname.endswith(".yml"):
                cfn_files.append(fpath)
            elif fname.endswith(".json"):
                cfn_files.append(fpath)

    return tf_files, cfn_files


def is_cloudformation(filepath):
    """Check if a file is a CloudFormation template."""
    try:
        if filepath.endswith(".json"):
            with open(filepath) as f:
                data = json.load(f)
            return isinstance(data, dict) and (
                "AWSTemplateFormatVersion" in data or "Resources" in data
            )
        else:
            with open(filepath) as f:
                data = yaml.load(f, Loader=yaml.SafeLoader)
            return isinstance(data, dict) and (
                "AWSTemplateFormatVersion" in data or "Resources" in data
            )
    except Exception:
        return False


# ── Terraform Parsing ────────────────────────────────────────────────────────

def extract_tf_blocks(content, resource_type):
    """Extract resource blocks from Terraform content (same regex approach as other parsers)."""
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
                    blocks.append((name, content[match.start():pos + 1]))
                    break
            pos += 1
    return blocks


def parse_tf_file(filepath, content):
    """Parse a single Terraform file for S3, IAM, and SG resources."""
    records = []
    relpath = os.path.relpath(filepath, AWSSRA_DIR)

    # ── S3 Buckets ───────────────────────────────────────────────────────
    # Collect companion resources for correlation
    encryption_configs = {name for name, _ in extract_tf_blocks(content, "aws_s3_bucket_server_side_encryption_configuration")}
    versioning_configs = {name for name, _ in extract_tf_blocks(content, "aws_s3_bucket_versioning")}
    logging_configs = {name for name, _ in extract_tf_blocks(content, "aws_s3_bucket_logging")}
    public_access_blocks = {}
    for name, block in extract_tf_blocks(content, "aws_s3_bucket_public_access_block"):
        block_all = (
            re.search(r'block_public_acls\s*=\s*true', block) and
            re.search(r'block_public_policy\s*=\s*true', block)
        )
        public_access_blocks[name] = block_all

    for name, block in extract_tf_blocks(content, "aws_s3_bucket"):
        rec = make_s3_record(f"tf-{relpath}-{name}")

        # Check inline encryption (older TF style)
        if "server_side_encryption_configuration" in block:
            rec["encryption_enabled"] = 1
        # Check companion resource by naming convention (name often matches or references bucket)
        for enc_name in encryption_configs:
            if name in enc_name or enc_name in name:
                rec["encryption_enabled"] = 1

        # Inline versioning
        if re.search(r'versioning\s*\{[^}]*enabled\s*=\s*true', block, re.DOTALL):
            rec["versioning_enabled"] = 1
        for ver_name in versioning_configs:
            if name in ver_name or ver_name in name:
                # Check if status = "Enabled"
                for vn, vblock in extract_tf_blocks(content, "aws_s3_bucket_versioning"):
                    if vn == ver_name and re.search(r'status\s*=\s*"Enabled"', vblock):
                        rec["versioning_enabled"] = 1

        # Inline logging
        if re.search(r'logging\s*\{', block):
            rec["logging_enabled"] = 1
        for log_name in logging_configs:
            if name in log_name or log_name in name:
                rec["logging_enabled"] = 1

        # Inline ACL check
        if re.search(r'acl\s*=\s*"public', block):
            rec["public_access_enabled"] = 1
        # Companion public access block
        for pab_name, blocks_all in public_access_blocks.items():
            if name in pab_name or pab_name in name:
                if blocks_all:
                    rec["public_access_enabled"] = 0

        records.append(rec)

    # ── IAM Policies ─────────────────────────────────────────────────────
    for rtype in ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_policy_document"]:
        for name, block in extract_tf_blocks(content, rtype):
            rec = make_iam_record(f"tf-{relpath}-{rtype}-{name}")

            # Try heredoc JSON policy
            heredoc_match = re.search(r'<<(\w+)\n(.*?)\n\1', block, re.DOTALL)
            policy_doc = None
            if heredoc_match:
                policy_str = heredoc_match.group(2).strip()
                try:
                    policy_doc = json.loads(policy_str)
                except json.JSONDecodeError:
                    pass

            # Try jsonencode
            if policy_doc is None:
                je_match = re.search(r'jsonencode\s*\(\s*(\{.*?\})\s*\)', block, re.DOTALL)
                if je_match:
                    # Best-effort: try parsing as JSON (won't work for HCL syntax)
                    try:
                        policy_doc = json.loads(je_match.group(1))
                    except json.JSONDecodeError:
                        pass

            if policy_doc:
                (hw, ha, hp, pl, awa, awr) = analyze_iam_policy(policy_doc)
                rec["has_wildcard_permission"] = hw
                rec["has_admin_privilege"] = ha
                rec["has_priv_esc_potential"] = hp
                rec["policy_length"] = pl
                rec["allow_wildcard_action"] = awa
                rec["allow_wildcard_resource"] = awr
            else:
                # Estimate policy_length from block
                rec["policy_length"] = len(block)

            records.append(rec)

    # ── Security Groups ──────────────────────────────────────────────────
    for name, block in extract_tf_blocks(content, "aws_security_group"):
        rec = make_sg_record(f"tf-{relpath}-{name}")

        ingress_blocks = re.findall(r'ingress\s*\{([^}]*)\}', block, re.DOTALL)
        egress_blocks = re.findall(r'egress\s*\{([^}]*)\}', block, re.DOTALL)

        rec["inbound_rule_count"] = len(ingress_blocks)
        rec["outbound_rule_count"] = len(egress_blocks)

        for ing in ingress_blocks:
            is_world = (
                re.search(r'cidr_blocks\s*=\s*\[.*?0\.0\.0\.0/0', ing, re.DOTALL) or
                re.search(r'ipv6_cidr_blocks\s*=\s*\[.*?::/0', ing, re.DOTALL)
            )
            if is_world:
                fp_m = re.search(r'from_port\s*=\s*(\d+)', ing)
                tp_m = re.search(r'to_port\s*=\s*(\d+)', ing)
                protocol_m = re.search(r'protocol\s*=\s*"(-?\d+|[^"]+)"', ing)
                if fp_m and tp_m:
                    fp = int(fp_m.group(1))
                    tp = int(tp_m.group(1))
                    rec["open_ports_to_world"] += 1
                    if fp <= 22 <= tp:
                        rec["ssh_open_to_world"] = 1
                    if fp <= 3389 <= tp:
                        rec["rdp_open_to_world"] = 1
                    if fp == 0 and tp == 65535:
                        rec["all_ports_open"] = 1
                elif protocol_m and protocol_m.group(1) == "-1":
                    rec["open_ports_to_world"] += 1
                    rec["all_ports_open"] = 1

        records.append(rec)

    return records


# ── CloudFormation Parsing ───────────────────────────────────────────────────

def parse_cfn_file(filepath, template):
    """Parse a CloudFormation template for S3, IAM, and SG resources."""
    records = []
    resources = template.get("Resources", {})
    if not isinstance(resources, dict):
        return records

    relpath = os.path.relpath(filepath, AWSSRA_DIR)

    for logical_id, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        rtype = resource.get("Type", "")
        props = resource.get("Properties", {})
        if not isinstance(props, dict):
            props = {}

        # ── S3 Bucket ────────────────────────────────────────────────────
        if rtype == "AWS::S3::Bucket":
            rec = make_s3_record(f"cfn-{relpath}-{logical_id}")

            # Encryption
            if props.get("BucketEncryption"):
                rec["encryption_enabled"] = 1

            # Versioning
            vc = props.get("VersioningConfiguration", {})
            if isinstance(vc, dict) and vc.get("Status") == "Enabled":
                rec["versioning_enabled"] = 1

            # Logging
            if props.get("LoggingConfiguration"):
                rec["logging_enabled"] = 1

            # Public access block
            pab = props.get("PublicAccessBlockConfiguration", {})
            if isinstance(pab, dict):
                if (pab.get("BlockPublicAcls") and pab.get("BlockPublicPolicy") and
                    pab.get("IgnorePublicAcls") and pab.get("RestrictPublicBuckets")):
                    rec["public_access_enabled"] = 0

            # ACL
            acl = props.get("AccessControl", "")
            if acl in ("PublicRead", "PublicReadWrite", "AuthenticatedRead"):
                rec["public_access_enabled"] = 1

            records.append(rec)

        # ── IAM Policy / ManagedPolicy ───────────────────────────────────
        elif rtype in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
            rec = make_iam_record(f"cfn-{relpath}-{logical_id}")
            policy_doc = props.get("PolicyDocument", {})
            if isinstance(policy_doc, dict):
                (hw, ha, hp, pl, awa, awr) = analyze_iam_policy(policy_doc)
                rec["has_wildcard_permission"] = hw
                rec["has_admin_privilege"] = ha
                rec["has_priv_esc_potential"] = hp
                rec["policy_length"] = pl
                rec["allow_wildcard_action"] = awa
                rec["allow_wildcard_resource"] = awr
            records.append(rec)

        # ── IAM Role (inline policies) ───────────────────────────────────
        elif rtype == "AWS::IAM::Role":
            inline_policies = props.get("Policies", [])
            if isinstance(inline_policies, list):
                for i, pol in enumerate(inline_policies):
                    if not isinstance(pol, dict):
                        continue
                    pol_name = pol.get("PolicyName", f"inline-{i}")
                    policy_doc = pol.get("PolicyDocument", {})
                    rec = make_iam_record(f"cfn-{relpath}-{logical_id}-{pol_name}")
                    if isinstance(policy_doc, dict):
                        (hw, ha, hp, pl, awa, awr) = analyze_iam_policy(policy_doc)
                        rec["has_wildcard_permission"] = hw
                        rec["has_admin_privilege"] = ha
                        rec["has_priv_esc_potential"] = hp
                        rec["policy_length"] = pl
                        rec["allow_wildcard_action"] = awa
                        rec["allow_wildcard_resource"] = awr
                    records.append(rec)

            # Also check AssumeRolePolicyDocument
            assume_doc = props.get("AssumeRolePolicyDocument", {})
            if isinstance(assume_doc, dict) and assume_doc.get("Statement"):
                rec = make_iam_record(f"cfn-{relpath}-{logical_id}-assume")
                (hw, ha, hp, pl, awa, awr) = analyze_iam_policy(assume_doc)
                rec["has_wildcard_permission"] = hw
                rec["has_admin_privilege"] = ha
                rec["has_priv_esc_potential"] = hp
                rec["policy_length"] = pl
                rec["allow_wildcard_action"] = awa
                rec["allow_wildcard_resource"] = awr
                records.append(rec)

        # ── Security Group ───────────────────────────────────────────────
        elif rtype == "AWS::EC2::SecurityGroup":
            rec = make_sg_record(f"cfn-{relpath}-{logical_id}")

            ingress = props.get("SecurityGroupIngress", [])
            egress = props.get("SecurityGroupEgress", [])
            if not isinstance(ingress, list):
                ingress = []
            if not isinstance(egress, list):
                egress = []

            rec["inbound_rule_count"] = len(ingress)
            rec["outbound_rule_count"] = len(egress)

            for rule in ingress:
                if not isinstance(rule, dict):
                    continue
                cidr = str(rule.get("CidrIp", ""))
                cidr6 = str(rule.get("CidrIpv6", ""))
                if cidr == "0.0.0.0/0" or cidr6 == "::/0":
                    fp = int(rule.get("FromPort", 0))
                    tp = int(rule.get("ToPort", 0))
                    protocol = str(rule.get("IpProtocol", ""))
                    rec["open_ports_to_world"] += 1
                    if fp <= 22 <= tp:
                        rec["ssh_open_to_world"] = 1
                    if fp <= 3389 <= tp:
                        rec["rdp_open_to_world"] = 1
                    if (fp == 0 and tp == 65535) or protocol == "-1":
                        rec["all_ports_open"] = 1

            records.append(rec)

    return records


# ── Main ──────────────────────���──────────────────────────────────────────────

def parse_awssra():
    """Main entry point. Returns list of record dicts."""
    if not ensure_repo_cloned():
        return []

    tf_files, candidate_cfn_files = discover_files()
    log.info(f"  Found {len(tf_files)} .tf files, {len(candidate_cfn_files)} .yaml/.json candidates")

    all_records = []

    # Parse Terraform files
    for fpath in tf_files:
        try:
            with open(fpath) as f:
                content = f.read()
            records = parse_tf_file(fpath, content)
            all_records.extend(records)
        except Exception as e:
            log.warning(f"  Warning: skipping {fpath}: {e}")

    # Parse CloudFormation files
    for fpath in candidate_cfn_files:
        try:
            if not is_cloudformation(fpath):
                continue
            if fpath.endswith(".json"):
                with open(fpath) as f:
                    template = json.load(f)
            else:
                with open(fpath) as f:
                    template = yaml.load(f, Loader=yaml.SafeLoader)
            if not isinstance(template, dict):
                continue
            records = parse_cfn_file(fpath, template)
            all_records.extend(records)
        except Exception as e:
            log.warning(f"  Warning: skipping {fpath}: {e}")

    return all_records


def main():
    print("Parsing AWS SRA examples...")
    records = parse_awssra()

    if not records:
        print("  No records extracted from AWS SRA.")
        return

    df = pd.DataFrame(records)
    raw_count = len(df)

    # ── Fix 1: Drop SRA S3 records where companion matching failed ────────
    # These have all S3 features = 0 but are labeled secure — ambiguous signal
    s3_cols = ["encryption_enabled", "versioning_enabled",
               "logging_enabled", "public_access_enabled"]
    sra_s3_mask = df["resource_type"] == "s3"
    bad_s3 = sra_s3_mask & (df[s3_cols].sum(axis=1) == 0)
    df = df[~bad_s3].reset_index(drop=True)
    print(f"  Dropped {bad_s3.sum()} ambiguous SRA S3 records (all features=0)")

    # ── Fix 2: Cap SRA IAM secure records ─────────────────────────────────
    # 496 IAM records at 19:1 ratio crushes precision; keep only unique
    # feature vectors, then cap at 100 if still too many
    iam_features = ["has_wildcard_permission", "has_admin_privilege",
                    "has_priv_esc_potential", "policy_length",
                    "allow_wildcard_action", "allow_wildcard_resource"]
    iam_mask = (df["resource_type"] == "iam") & (df["label"] == 0)
    iam_df = df[iam_mask]
    n_unique = iam_df[iam_features].drop_duplicates().shape[0]
    print(f"  Unique IAM feature vectors: {n_unique} / {len(iam_df)}")

    # Deduplicate IAM by feature vector first, then cap at 100
    iam_dedup_idx = iam_df.drop_duplicates(subset=iam_features).index
    iam_dup_idx = iam_df.index.difference(iam_dedup_idx)
    df = df.drop(index=iam_dup_idx).reset_index(drop=True)
    print(f"  Deduplicated IAM: dropped {len(iam_dup_idx)} duplicate feature vectors")

    # If still over 100 after dedup, cap
    iam_mask = (df["resource_type"] == "iam") & (df["label"] == 0)
    iam_secure_idx = df[iam_mask].index
    if len(iam_secure_idx) > 100:
        drop_idx = iam_secure_idx[100:]
        df = df.drop(index=drop_idx).reset_index(drop=True)
        print(f"  Capped SRA IAM secure to 100 (dropped {len(drop_idx)} excess records)")

    print(f"  Records after filtering: {len(df)} (from {raw_count} raw)")

    # Add s3_missing_control_count for S3 rows
    s3_feature_cols = ["public_access_enabled", "encryption_enabled",
                       "versioning_enabled", "logging_enabled"]
    s3_mask = df["resource_type"] == "s3"
    df["s3_missing_control_count"] = np.nan
    if s3_mask.any():
        df.loc[s3_mask, "s3_missing_control_count"] = df.loc[s3_mask, s3_feature_cols].apply(
            lambda row: (row == 0).sum(), axis=1
        )

    # Load existing data and append
    existing = pd.read_csv(f"{DATA_PROCESSED}/labeled_features.csv")
    combined = pd.concat([existing, df], ignore_index=True)
    combined = combined.drop_duplicates(subset=["resource_name"], keep="first")

    combined.to_csv(f"{DATA_PROCESSED}/labeled_features.csv", index=False)

    s3_count = sum(1 for _, r in df.iterrows() if r["resource_type"] == "s3")
    iam_count = sum(1 for _, r in df.iterrows() if r["resource_type"] == "iam")
    sg_count = sum(1 for _, r in df.iterrows() if r["resource_type"] == "security_group")

    print(f"\nparse_awssra: added {len(df)} records (all label=0, secure)")
    print(f"  S3: {s3_count} | IAM: {iam_count} | SG: {sg_count}")
    print(f"  Total dataset: {len(combined)} records")


if __name__ == "__main__":
    main()
