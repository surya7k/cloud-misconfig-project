# CLAUDE.md — Cloud Misconfiguration Detection Project

## Project Summary

IST 584 (Penn State) capstone project: a supervised machine-learning pipeline that detects
AWS misconfigurations across **S3 buckets**, **IAM policies**, and **EC2 Security Groups**.
The pipeline ingests real and synthetic cloud configurations, extracts security-relevant
features, labels them as secure (0) or misconfigured (1), and trains **Random Forest**
(primary) and **Logistic Regression** (baseline) classifiers.

**Research question:** Can a supervised ML model trained on AWS S3, IAM, and security group
configuration data produce a useful risk score to identify cloud misconfigurations?

**Motivation:** Cloud misconfigurations remain a top breach vector (e.g., 2019 Capital One
breach via misconfigured WAF and overly permissive IAM/S3). Traditional rule-based tools
(AWS Config Rules, CIS benchmarks) rely on predefined bad patterns and miss complex
interactions between resource attributes. This project uses ML to learn those interactions
and output a probabilistic misconfiguration risk score.

**Current status:** Week 8 — model validation phase.
- Targets: **F1 > 0.75**, **Recall > 0.80**
- Latest results (5-fold CV):
  - Random Forest — Precision: 0.937, Recall: 0.791, F1: 0.856
  - Logistic Regression — Precision: 0.877, Recall: 0.641, F1: 0.730
- Random Forest meets both targets; Logistic Regression recall still trails.

---

## Document Index

### `src/` — Pipeline source code

| File | Purpose |
|---|---|
| `src/ingest.py` | Parses raw JSON configs (S3 ACL/encryption/versioning/logging, IAM policies, Security Groups) from `data/raw/` into `data/processed/raw_features.csv`. Core feature-extraction logic for all three resource types. |
| `src/label.py` | Applies ground-truth labeling rules to `raw_features.csv` → `labeled_features.csv`. S3: missing any security feature = misconfigured. IAM: wildcard/admin/priv-esc = misconfigured. SG: open ports or >1 inbound rule = misconfigured. |
| `src/parse_terragoat.py` | Parses TerraGoat Terraform files (`s3.tf`, `iam.tf`, `ec2.tf`) for S3/IAM/SG resources. Includes effect-aware IAM analysis (skips Deny statements). Adds synthetic secure baselines for class balancing. Appends to `labeled_features.csv`. |
| `src/parse_cfngoat.py` | Parses CfnGoat CloudFormation YAML (`cfngoat.yaml`) and TerraGoat `db-app.tf` for S3/IAM/SG resources. Applies same labeling rules. Appends to `labeled_features.csv`. |
| `src/parse_checkov.py` | Parses Checkov test fixtures (Terraform `.tf` files) across S3, IAM, and SG example folders. Handles both heredoc and `jsonencode()` policy formats. Uses pass/fail naming convention for labels. Appends to `labeled_features.csv`. |
| `src/generate_synthetic.py` | Generates 63 hand-crafted synthetic records (S3, IAM, SG — both secure and misconfigured) to augment the dataset with edge cases the model might miss (e.g., single-feature-missing S3 buckets). |
| `src/build_dataset.py` | Orchestrator script — runs the full pipeline in order: `ingest` → `label` → `parse_terragoat` → `parse_cfngoat` → `parse_checkov` → `generate_synthetic`. |
| `src/train.py` | Trains and evaluates models. 5-fold stratified cross-validation on 16 features. Saves Random Forest model and scaler to `models/`. Outputs feature importances and model comparison to `data/processed/model_results.csv`. |

### `data/` — Raw inputs and processed outputs

| File | Purpose |
|---|---|
| `data/raw/s3_*.json` | Simulated AWS S3 bucket configurations (ACL, encryption, versioning, logging) for both misconfigured and secure buckets. |
| `data/raw/iam_*.json` | Simulated IAM policy documents — wildcard, privilege-escalation, and secure read-only policies. |
| `data/raw/security_groups.json` | Simulated EC2 Security Group definitions with varying inbound/outbound rules. |
| `data/processed/raw_features.csv` | Feature matrix from `ingest.py` (before labeling). |
| `data/processed/labeled_features.csv` | Final labeled dataset (179 records). All pipeline parsers append here. Used by `train.py`. |
| `data/processed/model_results.csv` | Precision/recall/F1 means for each model from the latest training run. |

### `models/` — Serialized model artifacts

| File | Purpose |
|---|---|
| `models/random_forest.pkl` | Trained Random Forest classifier (joblib). |
| `models/scaler.pkl` | Fitted `StandardScaler` used for feature normalization. |

### `cfngoat/` — Bridgecrew CfnGoat (vulnerable CloudFormation templates)

| File | Purpose |
|---|---|
| `cfngoat/cfngoat.yaml` | Intentionally misconfigured CloudFormation template — parsed by `parse_cfngoat.py` for S3/IAM/SG training data. |
| `cfngoat/eks.yaml` | EKS CloudFormation template (not currently parsed). |

### `terragoat/` — Bridgecrew TerraGoat (vulnerable Terraform configs)

Intentionally insecure Terraform configurations. Key files parsed by the pipeline:
- `terragoat/terraform/aws/s3.tf` — S3 bucket definitions
- `terragoat/terraform/aws/iam.tf` — IAM user policies
- `terragoat/terraform/aws/ec2.tf` — Security group definitions
- `terragoat/terraform/aws/db-app.tf` — IAM role policies (parsed by `parse_cfngoat.py`)

### `checkov/` — Bridgecrew Checkov (static analysis tool repo)

Large vendored repo. Only the Terraform test fixtures under
`checkov/tests/terraform/checks/resource/aws/example_*` are used — parsed by `parse_checkov.py`
for S3, IAM, and Security Group training samples.

### `IST 584 Docs/` — Course deliverables and weekly reports

| File | Purpose |
|---|---|
| `Capstone Project Topic Final Proposal.docx` | Original project proposal (Jan 25, 2026) — research question, scope, and timeline. |
| `IST 584 Notes.docx` | Project notes — motivation (Capital One breach), data sources, training process, feature engineering plan, and expected outcomes. |
| `IST 584 Week 3.docx` | Literature review — industry threat reports (Unit 42, CrowdStrike, Gigamon), ML approaches to cloud security, technical/security/performance requirements, and references. |
| `IST 584 Week 4.docx` | Week 4 update — technical approach finalization, system architecture diagram, and detailed milestone plan (Weeks 4–13). |
| `IST 584 Week 5.docx` | Week 5 update — codebase architecture design, feature engineering details, model selection rationale (Random Forest for feature importance), and evaluation method. |
| `Week 6 IST 584.docx` | Week 6 update — first working pipeline (ingest → label → feature extraction), challenges with labeling consistency and null-field handling. |
| `IST 584 Week 7 Demo - Surya Karthik.pptx` | Week 7 demo presentation. |
| `IST 564 - IWA3.docx` | IWA3 assignment — threats and vulnerabilities analysis (Cambridge Analytica / election security). |
| `IST 564 IWA3 - Part 2.docx` | IWA3 Part 2 — risk decision assessment for cybersecurity infrastructure improvements. |

### Other

| File | Purpose |
|---|---|
| `venv/` | Python virtual environment (not tracked). |

---

## Feature Columns (16)

| Feature | Resource Type | Description |
|---|---|---|
| `public_access_enabled` | S3 | Bucket ACL grants public/authenticated access |
| `encryption_enabled` | S3 | Server-side encryption configured |
| `versioning_enabled` | S3 | Object versioning enabled |
| `logging_enabled` | S3 | Access logging enabled |
| `has_wildcard_permission` | IAM | Policy contains `Action: "*"` |
| `has_admin_privilege` | IAM | `Action: "*"` + `Resource: "*"` with Allow effect |
| `has_priv_esc_potential` | IAM | Contains privilege-escalation actions (e.g., `iam:AttachUserPolicy`) |
| `policy_length` | IAM | Character length of policy document |
| `allow_wildcard_action` | IAM | Effect-aware: Allow statement with `Action: "*"` |
| `allow_wildcard_resource` | IAM | Effect-aware: Allow statement with `Resource: "*"` |
| `inbound_rule_count` | SG | Number of inbound rules |
| `outbound_rule_count` | SG | Number of outbound rules |
| `open_ports_to_world` | SG | Count of ports exposed to `0.0.0.0/0` |
| `ssh_open_to_world` | SG | Port 22 open to `0.0.0.0/0` |
| `rdp_open_to_world` | SG | Port 3389 open to `0.0.0.0/0` |
| `all_ports_open` | SG | Full port range (0–65535) open to world |

---

## Security Standards and Data Sources

Labels are derived from established cloud security standards:
- **CIS AWS Foundations Benchmark** — defines secure vs. insecure configurations
- **AWS Config Managed Rules** — predefined compliance checks for AWS resources
- **AWS Security Hub controls** — aggregated security findings

Training data sources:
- **Staged AWS account configs** — controlled S3/IAM/SG configurations (JSON) for initial testing
- **TerraGoat** (Bridgecrew) — intentionally insecure Terraform templates
- **CfnGoat** (Bridgecrew) — intentionally insecure CloudFormation templates
- **Checkov test fixtures** — Terraform examples with pass/fail naming convention
- **Synthetic records** — hand-crafted edge cases for class balancing

Literature references (from Week 3 review):
- Palo Alto Networks Unit 42 Cloud Threat Report (2024) — IAM role exploitation
- CrowdStrike Top 11 AWS Misconfigurations (2025) — S3, IAM, SG patterns
- Gigamon AWS Security Challenges (2025) — configuration drift and excessive permissions
- E-Palli Publishers (2024) — AI-based cloud security misconfiguration detection
- Academia.edu (2025) — RAG-based IaC misconfiguration detection

---

## Project Timeline

| Week | Milestone |
|---|---|
| 2–3 | Finalize scope, research questions, AWS schemas |
| 4 | Finalize research methodology |
| 5 | Collect AWS config data, IaC samples, define schemas |
| 6 | Apply labeling rules (CIS/AWS), build initial pipeline |
| 7 | Baseline rule-based detection, expand dataset with TerraGoat/CfnGoat/Checkov |
| 8 | Train and evaluate models (Random Forest, Logistic Regression) — **current** |
| 9 | Feature importance analysis, analyze misconfigurations and false positives |
| 10 | Evaluate model performance, compare ML vs. rule-based baseline |
| 11 | Interpret results, security findings |
| 12–13 | Final report and documentation |

---

## Pipeline Architecture

```
AWS Config / Security Hub → Data Ingestion → Feature Engineering & Labeling → Supervised ML Model → Risk Scoring & Evaluation
```

1. **Data Ingestion** — S3/IAM/SG configs loaded from JSON (staged AWS account) + IaC templates (TerraGoat, CfnGoat, Checkov)
2. **Feature Engineering** — raw attributes converted to 16 numerical features
3. **Label Generation** — CIS/AWS Config rules applied to classify secure (0) vs. misconfigured (1)
4. **Model Training** — Random Forest (primary, chosen for feature importance) and Logistic Regression (baseline)
5. **Risk Score Output** — probabilistic misconfiguration risk score per resource
6. **Evaluation** — precision, recall, F1-score, confusion matrix; ML model compared against rule-based baseline

---

## Key Tools and Dependencies

- **scikit-learn** — Random Forest, Logistic Regression, StratifiedKFold CV, StandardScaler
- **pandas / numpy** — Data manipulation and feature engineering
- **joblib** — Model serialization
- **PyYAML** — CloudFormation template parsing
- **Bandit** — Python security linter (static analysis)
- **AWS IAM Access Analyzer** — IAM policy validation (reference tooling)
- **Checkov** — IaC static analysis (vendored as training data source)
- **CfnGoat / TerraGoat** — Intentionally vulnerable IaC templates (training data sources)

---

## Pipeline Execution

```bash
# Full rebuild (ingest → label → parse all sources → synthetic → train)
python src/build_dataset.py
python src/train.py

# Individual steps
python src/ingest.py              # raw JSON → raw_features.csv
python src/label.py               # raw_features → labeled_features.csv
python src/parse_terragoat.py     # append TerraGoat records
python src/parse_cfngoat.py       # append CfnGoat records
python src/parse_checkov.py       # append Checkov records
python src/generate_synthetic.py  # append synthetic records
python src/train.py               # train + evaluate models
```

---

## Coding and Workflow Preferences

- Run pipeline scripts from the project root (paths are relative).
- `labeled_features.csv` is the single source of truth — all parsers append to it and deduplicate by `resource_name`.
- Use `python src/build_dataset.py` to rebuild the full dataset from scratch, then `python src/train.py` to retrain.
- Models are evaluated with 5-fold stratified cross-validation; no separate test split.
- Class imbalance is handled via `class_weight="balanced"` and synthetic data augmentation.
- New data sources should follow the existing parser pattern: extract features into the standard 16-column schema, apply `label_row()` logic, and append to `labeled_features.csv`.

---

## Known Challenges

- **Labeling consistency** — some config records have partial/missing fields, causing rule-based labeling to default to "secure" instead of flagging as missing (identified Week 6).
- **Class imbalance** — most real-world IaC templates are misconfigured; synthetic secure baselines and `class_weight="balanced"` mitigate this.
- **Logistic Regression recall** — LR recall (0.641) is below the 0.80 target; likely due to non-linear feature interactions that LR cannot capture.
