import pandas as pd
import random

random.seed(42)

DATA_PROCESSED = "data/processed"


def make_s3(name, public, encrypt, version, logging, label,
            bucket_policy_wildcard=0, mfa_delete_enabled=0, tls_enforced=0):
    return {
        "resource_type": "s3", "resource_name": name,
        "public_access_enabled": public, "encryption_enabled": encrypt,
        "versioning_enabled": version, "logging_enabled": logging,
        "has_wildcard_permission": 0, "has_admin_privilege": 0,
        "has_priv_esc_potential": 0, "policy_length": 0,
        "inbound_rule_count": 0, "outbound_rule_count": 0,
        "open_ports_to_world": 0, "ssh_open_to_world": 0,
        "rdp_open_to_world": 0, "allow_wildcard_action": 0,
        "allow_wildcard_resource": 0, "all_ports_open": 0,
        "bucket_policy_wildcard": bucket_policy_wildcard,
        "mfa_delete_enabled": mfa_delete_enabled,
        "tls_enforced": tls_enforced,
        "dangerous_service_wildcard": 0,
        "has_no_condition": 0,
        "db_port_open_to_world": 0,
        "egress_unrestricted": 0,
        "label": label,
    }


def make_iam(name, wildcard, admin, priv_esc, policy_len, label,
             dangerous_service_wildcard=0, has_no_condition=0):
    return {
        "resource_type": "iam", "resource_name": name,
        "public_access_enabled": 0, "encryption_enabled": 0,
        "versioning_enabled": 0, "logging_enabled": 0,
        "has_wildcard_permission": wildcard, "has_admin_privilege": admin,
        "has_priv_esc_potential": priv_esc, "policy_length": policy_len,
        "inbound_rule_count": 0, "outbound_rule_count": 0,
        "open_ports_to_world": 0, "ssh_open_to_world": 0,
        "rdp_open_to_world": 0, "allow_wildcard_action": wildcard,
        "allow_wildcard_resource": admin, "all_ports_open": 0,
        "bucket_policy_wildcard": 0, "mfa_delete_enabled": 0, "tls_enforced": 0,
        "dangerous_service_wildcard": dangerous_service_wildcard,
        "has_no_condition": has_no_condition,
        "db_port_open_to_world": 0, "egress_unrestricted": 0,
        "label": label,
    }


def make_sg(name, inbound, outbound, open_ports, ssh, rdp, all_ports, label,
            db_port_open_to_world=0, egress_unrestricted=0):
    return {
        "resource_type": "security_group", "resource_name": name,
        "public_access_enabled": 0, "encryption_enabled": 0,
        "versioning_enabled": 0, "logging_enabled": 0,
        "has_wildcard_permission": 0, "has_admin_privilege": 0,
        "has_priv_esc_potential": 0, "policy_length": 0,
        "inbound_rule_count": inbound, "outbound_rule_count": outbound,
        "open_ports_to_world": open_ports, "ssh_open_to_world": ssh,
        "rdp_open_to_world": rdp, "allow_wildcard_action": 0,
        "allow_wildcard_resource": 0, "all_ports_open": all_ports,
        "bucket_policy_wildcard": 0, "mfa_delete_enabled": 0, "tls_enforced": 0,
        "dangerous_service_wildcard": 0, "has_no_condition": 0,
        "db_port_open_to_world": db_port_open_to_world,
        "egress_unrestricted": egress_unrestricted,
        "label": label,
    }


def main():
    records = []

    # ── Misconfigured S3 (11 records) ────────────────────────────────────────
    # Original cases — missing one of the 4 base controls
    records.append(make_s3("syn-misc-s3-no-encrypt-1",    0, 0, 1, 1, 1))
    records.append(make_s3("syn-misc-s3-no-encrypt-2",    0, 0, 1, 1, 1))
    records.append(make_s3("syn-misc-s3-no-version-1",    0, 1, 0, 1, 1))
    records.append(make_s3("syn-misc-s3-no-version-2",    0, 1, 0, 1, 1))
    records.append(make_s3("syn-misc-s3-no-logging-1",    0, 1, 1, 0, 1))
    records.append(make_s3("syn-misc-s3-no-logging-2",    0, 1, 1, 0, 1))
    records.append(make_s3("syn-misc-s3-public-1",        1, 1, 1, 1, 1))
    records.append(make_s3("syn-misc-s3-public-2",        1, 0, 1, 1, 1))
    records.append(make_s3("syn-misc-s3-multi-1",         0, 0, 0, 1, 1))
    records.append(make_s3("syn-misc-s3-multi-2",         0, 1, 0, 0, 1))
    records.append(make_s3("syn-misc-s3-multi-3",         1, 0, 0, 0, 1))

    # Week 10: misconfigured S3 driven by NEW features only
    # (the 4 base controls are correctly set, but new dimensions fail)
    records.append(make_s3("syn-misc-s3-policy-wildcard-1", 0, 1, 1, 1, 1,
                           bucket_policy_wildcard=1))
    records.append(make_s3("syn-misc-s3-policy-wildcard-2", 0, 1, 1, 1, 1,
                           bucket_policy_wildcard=1))
    records.append(make_s3("syn-misc-s3-no-tls-1", 0, 1, 1, 1, 1,
                           tls_enforced=0, mfa_delete_enabled=0))
    records.append(make_s3("syn-misc-s3-no-tls-2", 0, 1, 1, 1, 1,
                           tls_enforced=0))
    # Public bucket WITH a wildcard bucket policy — worst case
    records.append(make_s3("syn-misc-s3-public-and-wildcard", 1, 0, 0, 0, 1,
                           bucket_policy_wildcard=1, tls_enforced=0))

    # ── Secure S3 (10 records) — now with full security posture ─────────────
    for i in range(1, 11):
        records.append(make_s3(f"syn-secure-s3-{i}", 0, 1, 1, 1, 0,
                               bucket_policy_wildcard=0,
                               mfa_delete_enabled=1,
                               tls_enforced=1))

    # ── Misconfigured IAM (11 records) ──────────────────────────────────────
    # Original wildcard / privesc / admin cases — also assert no_condition=1
    records.append(make_iam("syn-misc-iam-wildcard-1",   1, 1, 0, 95,  1, has_no_condition=1))
    records.append(make_iam("syn-misc-iam-wildcard-2",   1, 1, 0, 110, 1, has_no_condition=1))
    records.append(make_iam("syn-misc-iam-wildcard-3",   1, 0, 0, 80,  1, has_no_condition=1))
    records.append(make_iam("syn-misc-iam-privesc-1",    0, 0, 1, 145, 1, has_no_condition=1))
    records.append(make_iam("syn-misc-iam-privesc-2",    0, 0, 1, 160, 1, has_no_condition=1))
    records.append(make_iam("syn-misc-iam-privesc-3",    0, 0, 1, 130, 1, has_no_condition=1))
    records.append(make_iam("syn-misc-iam-admin-1",      1, 1, 1, 200, 1, has_no_condition=1))
    records.append(make_iam("syn-misc-iam-admin-2",      1, 1, 0, 175, 1, has_no_condition=1))
    records.append(make_iam("syn-misc-iam-admin-3",      1, 1, 1, 220, 1, has_no_condition=1))
    records.append(make_iam("syn-misc-iam-wildcard-4",   1, 0, 0, 70,  1, has_no_condition=1))
    records.append(make_iam("syn-misc-iam-privesc-4",    0, 0, 1, 190, 1, has_no_condition=1))

    # Week 10: NEW IAM misconfig drivers
    # Service wildcard: not full admin, but s3:* / iam:* / ec2:* without conditions
    records.append(make_iam("syn-misc-iam-service-wild-1", 0, 0, 0, 140, 1,
                            dangerous_service_wildcard=1, has_no_condition=1))
    records.append(make_iam("syn-misc-iam-service-wild-2", 0, 0, 0, 165, 1,
                            dangerous_service_wildcard=2, has_no_condition=1))
    records.append(make_iam("syn-misc-iam-service-wild-3", 0, 0, 0, 180, 1,
                            dangerous_service_wildcard=3, has_no_condition=1))

    # ── Secure IAM (10 records) — assert conditions ARE present ────────────
    for i in range(1, 11):
        records.append(make_iam(f"syn-secure-iam-{i}", 0, 0, 0,
                                95 + (i * 12), 0,
                                dangerous_service_wildcard=0,
                                has_no_condition=0))

    # ── Misconfigured SG (9 records) ──────────────────────────────────────
    records.append(make_sg("syn-misc-sg-ssh-1",      2, 1, 1, 1, 0, 0, 1))
    records.append(make_sg("syn-misc-sg-ssh-2",      1, 1, 1, 1, 0, 0, 1))
    records.append(make_sg("syn-misc-sg-rdp-1",      1, 1, 1, 0, 1, 0, 1))
    records.append(make_sg("syn-misc-sg-rdp-2",      2, 1, 1, 0, 1, 0, 1))
    records.append(make_sg("syn-misc-sg-allports-1", 1, 1, 1, 1, 1, 1, 1))
    records.append(make_sg("syn-misc-sg-allports-2", 1, 0, 1, 0, 0, 1, 1))
    records.append(make_sg("syn-misc-sg-open-1",     3, 2, 2, 1, 1, 0, 1))
    records.append(make_sg("syn-misc-sg-open-2",     2, 1, 2, 1, 0, 0, 1))
    records.append(make_sg("syn-misc-sg-open-3",     1, 1, 1, 0, 0, 0, 1))

    # Week 10: NEW SG misconfig drivers — DB ports + unrestricted egress
    records.append(make_sg("syn-misc-sg-mysql-open",    1, 1, 1, 0, 0, 0, 1,
                           db_port_open_to_world=1))
    records.append(make_sg("syn-misc-sg-postgres-open", 1, 1, 1, 0, 0, 0, 1,
                           db_port_open_to_world=1))
    records.append(make_sg("syn-misc-sg-multi-db-open", 2, 1, 2, 0, 0, 0, 1,
                           db_port_open_to_world=2))
    records.append(make_sg("syn-misc-sg-mongo-redis",   2, 1, 2, 0, 0, 0, 1,
                           db_port_open_to_world=2,
                           egress_unrestricted=1))
    records.append(make_sg("syn-misc-sg-egress-only",   1, 1, 0, 0, 0, 0, 1,
                           egress_unrestricted=1))

    # ── Secure SG (12 records) — restricted egress, no DB exposure ────────
    for i in range(1, 13):
        records.append(make_sg(f"syn-secure-sg-{i}", 1, 1, 0, 0, 0, 0, 0,
                               db_port_open_to_world=0,
                               egress_unrestricted=0))

    df = pd.DataFrame(records)

    existing = pd.read_csv(f"{DATA_PROCESSED}/labeled_features.csv")
    combined = pd.concat([existing, df], ignore_index=True)
    combined = combined.fillna(0)
    combined = combined.drop_duplicates(subset=["resource_name"], keep="first")
    combined.to_csv(f"{DATA_PROCESSED}/labeled_features.csv", index=False)

    print(f"Added {len(records)} synthetic records")
    print(f"Total: {len(combined)} | Misc: {int(combined['label'].sum())} | Secure: {int((combined['label']==0).sum())}")
    print(f"\nSynthetic breakdown:")
    print(f"  S3:  {sum(1 for r in records if r['resource_type']=='s3')} "
          f"({sum(1 for r in records if r['resource_type']=='s3' and r['label']==1)} misc, "
          f"{sum(1 for r in records if r['resource_type']=='s3' and r['label']==0)} secure)")
    print(f"  IAM: {sum(1 for r in records if r['resource_type']=='iam')} "
          f"({sum(1 for r in records if r['resource_type']=='iam' and r['label']==1)} misc, "
          f"{sum(1 for r in records if r['resource_type']=='iam' and r['label']==0)} secure)")
    print(f"  SG:  {sum(1 for r in records if r['resource_type']=='security_group')} "
          f"({sum(1 for r in records if r['resource_type']=='security_group' and r['label']==1)} misc, "
          f"{sum(1 for r in records if r['resource_type']=='security_group' and r['label']==0)} secure)")


if __name__ == "__main__":
    main()
