import pandas as pd
import random

random.seed(42)

DATA_PROCESSED = "data/processed"

def make_s3(name, public, encrypt, version, logging, label):
    return {
        "resource_type": "s3", "resource_name": name,
        "public_access_enabled": public, "encryption_enabled": encrypt,
        "versioning_enabled": version, "logging_enabled": logging,
        "has_wildcard_permission": 0, "has_admin_privilege": 0,
        "has_priv_esc_potential": 0, "policy_length": 0,
        "inbound_rule_count": 0, "outbound_rule_count": 0,
        "open_ports_to_world": 0, "ssh_open_to_world": 0,
        "rdp_open_to_world": 0, "allow_wildcard_action": 0,
        "allow_wildcard_resource": 0, "all_ports_open": 0, "label": label,
    }

def make_iam(name, wildcard, admin, priv_esc, policy_len, label):
    return {
        "resource_type": "iam", "resource_name": name,
        "public_access_enabled": 0, "encryption_enabled": 0,
        "versioning_enabled": 0, "logging_enabled": 0,
        "has_wildcard_permission": wildcard, "has_admin_privilege": admin,
        "has_priv_esc_potential": priv_esc, "policy_length": policy_len,
        "inbound_rule_count": 0, "outbound_rule_count": 0,
        "open_ports_to_world": 0, "ssh_open_to_world": 0,
        "rdp_open_to_world": 0, "allow_wildcard_action": wildcard,
        "allow_wildcard_resource": admin, "all_ports_open": 0, "label": label,
    }

def make_sg(name, inbound, outbound, open_ports, ssh, rdp, all_ports, label):
    return {
        "resource_type": "security_group", "resource_name": name,
        "public_access_enabled": 0, "encryption_enabled": 0,
        "versioning_enabled": 0, "logging_enabled": 0,
        "has_wildcard_permission": 0, "has_admin_privilege": 0,
        "has_priv_esc_potential": 0, "policy_length": 0,
        "inbound_rule_count": inbound, "outbound_rule_count": outbound,
        "open_ports_to_world": open_ports, "ssh_open_to_world": ssh,
        "rdp_open_to_world": rdp, "allow_wildcard_action": 0,
        "allow_wildcard_resource": 0, "all_ports_open": all_ports, "label": label,
    }


def main():
    records = []

    # ── Misconfigured S3 (11 records) 
    # Missing exactly one security feature each — the hard cases the model misses
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

    # ── Secure S3 (10 records) 
    records.append(make_s3("syn-secure-s3-1",  0, 1, 1, 1, 0))
    records.append(make_s3("syn-secure-s3-2",  0, 1, 1, 1, 0))
    records.append(make_s3("syn-secure-s3-3",  0, 1, 1, 1, 0))
    records.append(make_s3("syn-secure-s3-4",  0, 1, 1, 1, 0))
    records.append(make_s3("syn-secure-s3-5",  0, 1, 1, 1, 0))
    records.append(make_s3("syn-secure-s3-6",  0, 1, 1, 1, 0))
    records.append(make_s3("syn-secure-s3-7",  0, 1, 1, 1, 0))
    records.append(make_s3("syn-secure-s3-8",  0, 1, 1, 1, 0))
    records.append(make_s3("syn-secure-s3-9",  0, 1, 1, 1, 0))
    records.append(make_s3("syn-secure-s3-10", 0, 1, 1, 1, 0))

    # ── Misconfigured IAM (11 records) ───────────────────────────────────────
    records.append(make_iam("syn-misc-iam-wildcard-1",   1, 1, 0, 95,  1))
    records.append(make_iam("syn-misc-iam-wildcard-2",   1, 1, 0, 110, 1))
    records.append(make_iam("syn-misc-iam-wildcard-3",   1, 0, 0, 80,  1))
    records.append(make_iam("syn-misc-iam-privesc-1",    0, 0, 1, 145, 1))
    records.append(make_iam("syn-misc-iam-privesc-2",    0, 0, 1, 160, 1))
    records.append(make_iam("syn-misc-iam-privesc-3",    0, 0, 1, 130, 1))
    records.append(make_iam("syn-misc-iam-admin-1",      1, 1, 1, 200, 1))
    records.append(make_iam("syn-misc-iam-admin-2",      1, 1, 0, 175, 1))
    records.append(make_iam("syn-misc-iam-admin-3",      1, 1, 1, 220, 1))
    records.append(make_iam("syn-misc-iam-wildcard-4",   1, 0, 0, 70,  1))
    records.append(make_iam("syn-misc-iam-privesc-4",    0, 0, 1, 190, 1))

    # ── Secure IAM (10 records) 
    # Varied policy lengths to give the model signal that length alone != safe
    records.append(make_iam("syn-secure-iam-1",  0, 0, 0, 95,  0))
    records.append(make_iam("syn-secure-iam-2",  0, 0, 0, 120, 0))
    records.append(make_iam("syn-secure-iam-3",  0, 0, 0, 80,  0))
    records.append(make_iam("syn-secure-iam-4",  0, 0, 0, 145, 0))
    records.append(make_iam("syn-secure-iam-5",  0, 0, 0, 160, 0))
    records.append(make_iam("syn-secure-iam-6",  0, 0, 0, 200, 0))
    records.append(make_iam("syn-secure-iam-7",  0, 0, 0, 110, 0))
    records.append(make_iam("syn-secure-iam-8",  0, 0, 0, 175, 0))
    records.append(make_iam("syn-secure-iam-9",  0, 0, 0, 90,  0))
    records.append(make_iam("syn-secure-iam-10", 0, 0, 0, 130, 0))

    # ── Misconfigured SG (9 records) 
    records.append(make_sg("syn-misc-sg-ssh-1",      2, 1, 1, 1, 0, 0, 1))
    records.append(make_sg("syn-misc-sg-ssh-2",      1, 1, 1, 1, 0, 0, 1))
    records.append(make_sg("syn-misc-sg-rdp-1",      1, 1, 1, 0, 1, 0, 1))
    records.append(make_sg("syn-misc-sg-rdp-2",      2, 1, 1, 0, 1, 0, 1))
    records.append(make_sg("syn-misc-sg-allports-1", 1, 1, 1, 1, 1, 1, 1))
    records.append(make_sg("syn-misc-sg-allports-2", 1, 0, 1, 0, 0, 1, 1))
    records.append(make_sg("syn-misc-sg-open-1",     3, 2, 2, 1, 1, 0, 1))
    records.append(make_sg("syn-misc-sg-open-2",     2, 1, 2, 1, 0, 0, 1))
    records.append(make_sg("syn-misc-sg-open-3",     1, 1, 1, 0, 0, 0, 1))

    # ── Secure SG (12 records) 
    records.append(make_sg("syn-secure-sg-1",  1, 1, 0, 0, 0, 0, 0))
    records.append(make_sg("syn-secure-sg-2",  1, 1, 0, 0, 0, 0, 0))
    records.append(make_sg("syn-secure-sg-3",  1, 0, 0, 0, 0, 0, 0))
    records.append(make_sg("syn-secure-sg-4",  1, 1, 0, 0, 0, 0, 0))
    records.append(make_sg("syn-secure-sg-5",  2, 1, 0, 0, 0, 0, 0))
    records.append(make_sg("syn-secure-sg-6",  1, 2, 0, 0, 0, 0, 0))
    records.append(make_sg("syn-secure-sg-7",  0, 1, 0, 0, 0, 0, 0))
    records.append(make_sg("syn-secure-sg-8",  1, 1, 0, 0, 0, 0, 0))
    records.append(make_sg("syn-secure-sg-9",  2, 2, 0, 0, 0, 0, 0))
    records.append(make_sg("syn-secure-sg-10", 1, 1, 0, 0, 0, 0, 0))
    records.append(make_sg("syn-secure-sg-11", 1, 0, 0, 0, 0, 0, 0))
    records.append(make_sg("syn-secure-sg-12", 0, 0, 0, 0, 0, 0, 0))

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
