"""Shared feature schema and security constants for training and inference."""

BASE_FEATURE_COLS = [
    "public_access_enabled", "encryption_enabled",
    "versioning_enabled", "logging_enabled",
    "has_wildcard_permission", "has_admin_privilege",
    "has_priv_esc_potential", "policy_length",
    "inbound_rule_count", "outbound_rule_count",
    "open_ports_to_world", "ssh_open_to_world", "rdp_open_to_world",
    "allow_wildcard_action", "allow_wildcard_resource", "all_ports_open",
]

S3_DERIVED_COLS = [
    "s3_missing_control_count",
    "s3_no_encrypt_no_version",
    "s3_public_no_logging",
]

EXTENDED_FEATURE_COLS = [
    "bucket_policy_wildcard", "mfa_delete_enabled", "tls_enforced",
    "dangerous_service_wildcard", "has_no_condition",
    "db_port_open_to_world", "egress_unrestricted",
]

FEATURE_COLS = BASE_FEATURE_COLS + S3_DERIVED_COLS + EXTENDED_FEATURE_COLS

S3_THRESHOLD_DEFAULT = 0.40

PRIV_ESC_ACTIONS = {
    "iam:AttachUserPolicy", "iam:CreatePolicyVersion",
    "iam:PutUserPolicy", "iam:AttachRolePolicy",
    "iam:PassRole", "iam:SetDefaultPolicyVersion",
}

DANGEROUS_SERVICE_PREFIXES = {
    "s3", "iam", "ec2", "lambda", "rds", "kms",
    "secretsmanager", "ssm", "sts", "dynamodb",
}

DB_PORTS_OF_CONCERN = {
    3306, 5432, 1433, 1521, 27017, 6379, 9200,
    11211, 5984, 7000, 7001, 9042,
}
