"""Translate AWS-native JSON output into the project's internal scoring schema.

Auto-detects which AWS resource the pasted JSON represents and converts it to
the format expected by `src/predict.py:score_config()`.

Supported input formats:

  IAM POLICY
    - Bare policy document with `Version` / `Statement`
    - Output of `aws iam get-policy-version`           (`{"PolicyVersion": {"Document": ...}}`)
    - Output of `aws iam get-role-policy` /
              `aws iam get-user-policy` /
              `aws iam get-policy`                     (`{"PolicyDocument": "<JSON-string-or-object>"}`)

  SECURITY GROUP
    - Single SG dict with `IpPermissions` at top level
    - Output of `aws ec2 describe-security-groups`     (`{"SecurityGroups": [...]}`)

  S3 BUCKET (merged format — see CLI snippet in the Streamlit app):
    {
      "BucketName": "my-bucket",
      "Encryption":         <output of get-bucket-encryption>      | null,
      "Versioning":         <output of get-bucket-versioning>      | {},
      "Logging":            <output of get-bucket-logging>         | {},
      "PublicAccessBlock":  <output of get-public-access-block>    | null,
      "Policy":             <output of get-bucket-policy>          | null
    }

  INTERNAL SCHEMA — passed through unchanged (presence of `resource_type`).
"""
import json
from typing import Optional


def detect_format(payload: dict) -> Optional[str]:
    """Return one of: 'internal', 'iam', 'sg', 's3', or None if unrecognized."""
    if not isinstance(payload, dict):
        return None

    if "resource_type" in payload:
        return "internal"

    # IAM
    if "Statement" in payload and "Version" in payload:
        return "iam"
    if "PolicyVersion" in payload and isinstance(payload["PolicyVersion"], dict) \
            and "Document" in payload["PolicyVersion"]:
        return "iam"
    if "PolicyDocument" in payload:
        return "iam"

    # Security Group
    if "IpPermissions" in payload:
        return "sg"
    if "SecurityGroups" in payload and isinstance(payload["SecurityGroups"], list) \
            and payload["SecurityGroups"]:
        return "sg"

    # S3 (merged)
    s3_keys = {"Encryption", "Versioning", "Logging", "PublicAccessBlock", "Policy"}
    if "BucketName" in payload and any(k in payload for k in s3_keys):
        return "s3"

    return None


# ── IAM ──────────────────────────────────────────────────────────────────────

def _extract_iam_document(payload: dict) -> Optional[dict]:
    """Return the policy document regardless of which AWS API output shape was pasted."""
    if "Statement" in payload and "Version" in payload:
        return payload

    if "PolicyVersion" in payload and isinstance(payload["PolicyVersion"], dict):
        doc = payload["PolicyVersion"].get("Document")
        if isinstance(doc, str):
            try:
                return json.loads(doc)
            except json.JSONDecodeError:
                return None
        if isinstance(doc, dict):
            return doc

    if "PolicyDocument" in payload:
        doc = payload["PolicyDocument"]
        if isinstance(doc, str):
            try:
                return json.loads(doc)
            except json.JSONDecodeError:
                return None
        if isinstance(doc, dict):
            return doc

    return None


def translate_iam(payload: dict, name_hint: Optional[str] = None) -> Optional[dict]:
    doc = _extract_iam_document(payload)
    if doc is None:
        return None
    name = (
        name_hint
        or payload.get("PolicyName")
        or (payload.get("PolicyVersion") or {}).get("VersionId")
        or "user-pasted-iam-policy"
    )
    return {
        "resource_type": "iam",
        "resource_name": f"custom-{name}",
        "policy": doc,
    }


# ── Security Group ──────────────────────────────────────────────────────────

def _aws_rule_to_internal(rule: dict) -> list:
    """An AWS IpPermission can declare multiple CIDRs. Expand into one rule per CIDR."""
    out = []
    fp = rule.get("FromPort")
    tp = rule.get("ToPort")
    proto = rule.get("IpProtocol", "-1")
    if proto == "-1":
        # AWS uses -1 to mean "all protocols, all ports"
        if fp is None:
            fp = 0
        if tp is None:
            tp = 65535

    for cidr_block in rule.get("IpRanges", []) or []:
        cidr = cidr_block.get("CidrIp")
        if cidr:
            out.append({"from_port": fp or 0, "to_port": tp or 0,
                        "protocol": proto, "cidr": cidr})
    for cidr_block in rule.get("Ipv6Ranges", []) or []:
        cidr = cidr_block.get("CidrIpv6")
        if cidr:
            out.append({"from_port": fp or 0, "to_port": tp or 0,
                        "protocol": proto, "cidr": cidr})

    # If neither v4 nor v6 ranges are present (e.g., security-group-to-security-group
    # references), still emit a rule so inbound_rule_count reflects reality, with
    # a placeholder cidr that the model will treat as non-public.
    if not out and (rule.get("UserIdGroupPairs") or rule.get("PrefixListIds")):
        out.append({"from_port": fp or 0, "to_port": tp or 0,
                    "protocol": proto, "cidr": "sg-internal"})

    return out


def translate_sg(payload: dict) -> Optional[dict]:
    if "SecurityGroups" in payload and payload["SecurityGroups"]:
        sg = payload["SecurityGroups"][0]
    elif "IpPermissions" in payload:
        sg = payload
    else:
        return None

    inbound = []
    for rule in sg.get("IpPermissions") or []:
        inbound.extend(_aws_rule_to_internal(rule))
    outbound = []
    for rule in sg.get("IpPermissionsEgress") or []:
        outbound.extend(_aws_rule_to_internal(rule))

    name = sg.get("GroupName") or sg.get("GroupId") or "user-pasted-sg"

    return {
        "resource_type": "security_group",
        "resource_name": f"custom-{name}",
        "inbound_rules": inbound,
        "outbound_rules": outbound,
    }


# ── S3 (merged format from get-bucket-* calls) ──────────────────────────────

def _is_truthy_bpa(pab_block: dict) -> bool:
    """Public-Access-Block flags: True means PUBLIC ACCESS IS BLOCKED (secure)."""
    cfg = pab_block.get("PublicAccessBlockConfiguration") or {}
    blocks = [cfg.get("BlockPublicAcls"), cfg.get("IgnorePublicAcls"),
              cfg.get("BlockPublicPolicy"), cfg.get("RestrictPublicBuckets")]
    # All four True means fully blocked.
    return all(b is True for b in blocks if b is not None)


def translate_s3(payload: dict) -> Optional[dict]:
    name = payload.get("BucketName") or "user-pasted-s3"
    out = {
        "resource_type": "s3",
        "resource_name": f"custom-{name}",
        "public_access_enabled": 0,
        "encryption_enabled": 0,
        "versioning_enabled": 0,
        "logging_enabled": 0,
        "bucket_policy_wildcard": 0,
        "mfa_delete_enabled": 0,
        "tls_enforced": 0,
    }

    # Encryption
    enc = payload.get("Encryption")
    if isinstance(enc, dict) and enc.get("ServerSideEncryptionConfiguration"):
        out["encryption_enabled"] = 1

    # Versioning + MFA delete
    ver = payload.get("Versioning") or {}
    if isinstance(ver, dict):
        if ver.get("Status") == "Enabled":
            out["versioning_enabled"] = 1
        if ver.get("MFADelete") == "Enabled":
            out["mfa_delete_enabled"] = 1

    # Logging
    log = payload.get("Logging") or {}
    if isinstance(log, dict) and log.get("LoggingEnabled"):
        out["logging_enabled"] = 1

    # Public Access Block: if PAB is present and fully blocking, public_access stays 0.
    # If PAB is absent, that means "no PAB configured" — treat as public_access_enabled=1
    # only if there's no other signal saying otherwise. Conservative default: 0.
    pab = payload.get("PublicAccessBlock")
    if isinstance(pab, dict) and not _is_truthy_bpa(pab):
        # Some block flags are False or missing → potential public exposure
        out["public_access_enabled"] = 1

    # Bucket policy parsing
    pol_field = payload.get("Policy")
    policy_doc = None
    if isinstance(pol_field, dict):
        # `get-bucket-policy` returns `{"Policy": "<JSON-string>"}` — handle that wrapper too
        if "Policy" in pol_field and isinstance(pol_field["Policy"], str):
            try:
                policy_doc = json.loads(pol_field["Policy"])
            except json.JSONDecodeError:
                policy_doc = None
        elif "Statement" in pol_field:
            policy_doc = pol_field
    elif isinstance(pol_field, str):
        try:
            policy_doc = json.loads(pol_field)
        except json.JSONDecodeError:
            policy_doc = None

    if isinstance(policy_doc, dict):
        out["bucket_policy_wildcard"] = _bucket_policy_has_wildcard(policy_doc)
        out["tls_enforced"] = _bucket_policy_enforces_tls(policy_doc)

    return out


def _bucket_policy_has_wildcard(doc: dict) -> int:
    for stmt in doc.get("Statement", []) or []:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect", "Allow") != "Allow":
            continue
        principal = stmt.get("Principal")
        if principal == "*":
            return 1
        if isinstance(principal, dict):
            for v in principal.values():
                if v == "*" or (isinstance(v, list) and "*" in v):
                    return 1
    return 0


def _bucket_policy_enforces_tls(doc: dict) -> int:
    """True if any statement Denies access when SecureTransport is false."""
    for stmt in doc.get("Statement", []) or []:
        if not isinstance(stmt, dict):
            continue
        cond = stmt.get("Condition") or {}
        if not isinstance(cond, dict):
            continue
        # Look for `Bool: {aws:SecureTransport: "false"}` with Effect Deny,
        # or `Bool: {aws:SecureTransport: "true"}` with Effect Allow.
        for op in ("Bool", "BoolIfExists"):
            block = cond.get(op) or {}
            if not isinstance(block, dict):
                continue
            for k, v in block.items():
                if k.lower() != "aws:securetransport":
                    continue
                effect = stmt.get("Effect", "Allow")
                # Most common pattern: Effect=Deny with SecureTransport=false
                if effect == "Deny" and str(v).lower() == "false":
                    return 1
                if effect == "Allow" and str(v).lower() == "true":
                    return 1
    return 0


# ── Public API ──────────────────────────────────────────────────────────────

def translate(payload: dict) -> tuple:
    """Translate an AWS-native (or already-internal) JSON payload.

    Returns (translated_dict, detected_format). detected_format is one of
    'internal', 'iam', 'sg', 's3', or None when unrecognized. When None, the
    caller should display an error explaining the supported formats.
    """
    fmt = detect_format(payload)
    if fmt == "internal":
        return payload, "internal"
    if fmt == "iam":
        result = translate_iam(payload)
        return (result, "iam") if result else (None, None)
    if fmt == "sg":
        result = translate_sg(payload)
        return (result, "sg") if result else (None, None)
    if fmt == "s3":
        result = translate_s3(payload)
        return (result, "s3") if result else (None, None)
    return None, None
