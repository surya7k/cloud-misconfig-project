# Cloud Misconfiguration Detection — IST 584 Capstone

A supervised machine-learning system that scores AWS S3 buckets, IAM
policies, and EC2 Security Groups for misconfiguration risk — and beats a
mature rule-based baseline (Checkov) on the dataset.

> **Author:** Surya Karthik · Penn State IST 584 (Spring 2026)
> **Status:** Prototype complete · all targets met · paper draft in progress

---

## TL;DR

- **Trained on 434 labeled AWS resources** spanning real configs, four
  intentionally-vulnerable IaC corpora (TerraGoat, CfnGoat, CloudGoat,
  Checkov fixtures), AWS Security Reference Architecture (secure
  baselines), and hand-crafted synthetic edge cases. **26 features**.
- **Random Forest, 5-fold stratified CV: F1 = 0.89 · Precision = 0.88 · Recall = 0.90.**
  Both project targets (F1 > 0.75, Recall > 0.80) met.
- **Held-out evaluation on 8 unseen real-world configs: F1 = 0.86** —
  tracks CV with no catastrophic generalization drop.
- **Beats Checkov on the shared test surface: F1 1.00 vs 0.89.** The gap
  is on Security Groups (Checkov F1 0.58 vs RF 1.00), where rules over-fire
  on legitimate patterns the model learns to ignore.
- **End-to-end prototype:** Streamlit demo with SHAP per-feature
  explanations, CLI scorer, AWS-CLI JSON translator for live configs,
  and a reproducible `build_dataset.py → train.py` pipeline.

---

## What to look at (for graders)

| If you want to see... | Look at |
|---|---|
| The headline metrics | [Results](#results) section below + [data/processed/model_results.csv](data/processed/model_results.csv) |
| The ML pipeline source | [src/train.py](src/train.py), [src/build_dataset.py](src/build_dataset.py), [src/predict.py](src/predict.py) |
| AI + security integration | [app.py](app.py) (Streamlit + SHAP) and [src/explain.py](src/explain.py) |
| Rule-based baseline comparison | [src/compare_checkov.py](src/compare_checkov.py) → [outputs/checkov_comparison.png](outputs/checkov_comparison.png) |
| Generalization beyond CV | [src/evaluate_holdout.py](src/evaluate_holdout.py) → [outputs/realworld_holdout_summary.csv](outputs/realworld_holdout_summary.csv) |
| Feature importance | [outputs/feature_importance.png](outputs/feature_importance.png) |
| Confusion matrix / ROC / PR | [outputs/](outputs/) |
| Data sources & how labels are assigned | [src/label.py](src/label.py) and [Data sources](#data-sources--references) below |
| Honest limitations | [Limitations & threats to validity](#limitations--threats-to-validity) |

---

## Motivation

Cloud misconfigurations remain a top breach vector — the 2019 Capital
One incident (100M+ records exposed) traced back to a misconfigured WAF
combined with overly permissive IAM and S3. Existing rule-based tools
(AWS Config Rules, CIS benchmarks, Checkov, Prowler) match predefined
patterns but miss interactions across attributes — e.g. *"public S3
bucket without logging AND without versioning"* is qualitatively
different from any single missing control.

**Research question:** Can a supervised ML model trained on AWS S3, IAM,
and Security Group configuration data produce a useful risk score, and
add value over rule-based static analysis?

---

## Results

### 5-fold stratified cross-validation (n = 434, 26 features)

| Model               | Precision | Recall    | F1        | Meets target? |
|---------------------|-----------|-----------|-----------|---------------|
| **Random Forest**   | **0.88**  | **0.90**  | **0.89**  | F1 > 0.75 + Recall > 0.80 |
| Logistic Regression | 0.86      | 0.89      | 0.88      | F1 > 0.75 + Recall > 0.80 |

### Per resource type (Random Forest)

| Resource         | n    | Precision | Recall | F1    |
|------------------|------|-----------|--------|-------|
| S3               | 94   | 0.72      | 1.00   | 0.84  |
| IAM              | 230  | 0.96      | 0.90   | 0.93  |
| Security Group   | 110  | 0.95      | 0.83   | 0.89  |

![Model comparison](outputs/model_comparison.png)
![Confusion matrix](outputs/confusion_matrix.png)
![Feature importance](outputs/feature_importance.png)
![ROC curve](outputs/roc_curve.png)
![S3 PR curve](outputs/s3_pr_curve.png)

---

## Random Forest vs. Checkov (rule-based) — head-to-head

On **123 TerraGoat / CfnGoat / CloudGoat resources** where both produced
verdicts (RF predictions are out-of-fold via 5-fold CV, not in-sample):

| Model               | Precision | Recall | F1       |
|---------------------|-----------|--------|----------|
| Checkov (rules)     | 0.80      | 1.00   | 0.89     |
| Random Forest (ML)  | **1.00**  | 1.00   | **1.00** |

By resource type:

| Resource         | Checkov F1 | Random Forest F1 |
|------------------|-----------:|-----------------:|
| S3               | 1.00       | 1.00             |
| IAM              | 0.98       | 1.00             |
| Security Group   | 0.58       | **1.00**         |

After expanding the labels to capture dangerous service wildcards
(`s3:*`, `iam:*`, `ec2:*`) and unconditioned wildcard-resource grants
(`Resource: "*"` without a `Condition`), Checkov and the model agree on
S3 and IAM. **The remaining gap is on Security Groups,** where Checkov's
strict open-port rules over-fire on legitimate patterns (internal-only
SGs, load-balancer configs) that the labels — and the model — treat as
appropriate. This is where ML's value over rules is clearest in this
dataset.

![Checkov vs RF](outputs/checkov_comparison.png)

---

## Held-out evaluation (real-world samples)

To check generalization beyond cross-validation, the trained Random
Forest is scored against `data/samples/realworld/` — 8 configurations
transcribed from public AWS reference architectures, Terraform module
registries, and tutorial repositories. **None of these resources appear
in `labeled_features.csv`.**

| Interpretation                                | n | Acc  | Precision | Recall | F1   |
|-----------------------------------------------|---|------|-----------|--------|------|
| Strict (matches labeling rules)               | 8 | 0.88 | 1.00      | 0.75   | 0.86 |
| Context-aware (intentional public ALB = secure) | 8 | 1.00 | 1.00      | 1.00   | 1.00 |

Held-out F1 (0.86) tracks the 5-fold CV F1 (0.89) — evidence the model
generalizes rather than memorizing the training distribution. The single
strict-label miss is `rw_tf_modules_alb_sg.json`: the rules flag any
`0.0.0.0/0` ingress as MISCONFIGURED, but the model's `p = 0.27` reflects
that ports 80/443 open to the world on an Application Load Balancer is
the intended pattern.

```bash
python -m src.evaluate_holdout
```

---

## Live demo (Streamlit)

```bash
streamlit run app.py
```

Pick a sample config, edit the JSON live, and watch the risk score and
SHAP feature contributions update in real time. The app surfaces:

- **Prediction** (SECURE / MISCONFIGURED) with calibrated probability
- **Risk level** (LOW / MEDIUM / HIGH)
- **Risk factors** (human-readable list of triggered controls)
- **SHAP bar chart** of per-feature contributions to the prediction

Built-in sample configs:

- `data/samples/insecure_s3.json` — public bucket, no controls
- `data/samples/secure_iam.json` — read-only S3 access policy
- `data/samples/wildcard_iam.json` — admin wildcard with priv-esc actions
- `data/samples/open_sg.json` — Security Group with SSH (22) open to `0.0.0.0/0`

---

## CLI inference

```bash
python src/predict.py data/samples/insecure_s3.json
```

```
==================================================
  Resource:   demo-insecure-bucket
  Type:       s3
  Prediction: MISCONFIGURED
  Confidence: 90.2%
  Risk Level: HIGH
  P(secure)=0.098  P(misconfigured)=0.902
==================================================

  Risk factors detected:
    - Encryption not enabled
    - Versioning not enabled
    - Logging not enabled
    - Public access enabled
```

Per-prediction SHAP explanation:

```bash
python -m src.explain data/samples/insecure_s3.json
```

Score live AWS CLI / Console JSON without manual reformatting:

```bash
aws iam get-policy-version --policy-arn ... --version-id v1 \
  | python -m src.aws_translator | python src/predict.py /dev/stdin
```

---

## Quickstart

```bash
git clone https://github.com/surya7k/cloud-misconfig-project.git
cd cloud-misconfig-project
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

python src/build_dataset.py   # ingest → label → all parsers → synthetic
python src/train.py           # 5-fold CV, save model + plots
streamlit run app.py          # launch demo
```

Other commands:

```bash
python -m src.compare_checkov     # ML vs rule-based head-to-head
python -m src.evaluate_holdout    # held-out real-world test
python src/predict.py <config>    # CLI inference on one config
```

---

## Pipeline

```
AWS configs / IaC sources → ingestion → feature engineering & labeling
                          → supervised ML model → risk score & evaluation
```

1. **Ingestion** — parses raw S3/IAM/SG JSON, plus IaC templates from
   TerraGoat (Terraform), CfnGoat (CloudFormation), CloudGoat (attack
   scenarios), Checkov fixtures, and AWSSRA (secure baselines).
2. **Feature engineering** — 26 numerical features per resource,
   including effect-aware IAM analysis and S3 derived interaction
   features (e.g. `s3_public_no_logging`).
3. **Labeling** — CIS AWS Foundations + AWS Config Managed Rules +
   AWS Security Hub controls applied via [src/label.py](src/label.py).
4. **Training** — Random Forest (primary, chosen for feature
   importance) and Logistic Regression (linear baseline). 5-fold
   stratified CV; class imbalance handled via `class_weight="balanced"`
   and synthetic secure baselines.
5. **Risk scoring** — calibrated probability + risk level + SHAP
   explanation per prediction.
6. **Evaluation** — CV metrics, per-resource breakdown, head-to-head
   vs. Checkov, and held-out evaluation on real-world samples.

---

## Project structure

```
src/
  ingest.py             # raw JSON → raw_features.csv
  label.py              # CIS / AWS Config / Security Hub labeling rules
  parse_terragoat.py    # parse TerraGoat Terraform
  parse_cfngoat.py      # parse CfnGoat CloudFormation + db-app Terraform
  parse_checkov.py      # parse Checkov test fixtures
  parse_cloudgoat.py    # parse CloudGoat attack scenarios
  parse_awssra.py       # parse AWS Security Reference Architecture (secure)
  generate_synthetic.py # hand-crafted edge cases
  build_dataset.py      # orchestrator
  train.py              # train + evaluate Random Forest and Logistic Regression
  predict.py            # single-config CLI inference
  explain.py            # SHAP per-prediction explanations
  compare_checkov.py    # ML vs rule-based head-to-head
  evaluate_holdout.py   # held-out evaluation on data/samples/realworld/
  aws_translator.py     # normalize AWS CLI / Console JSON for predict.py
app.py                  # Streamlit live demo
data/
  raw/                  # source JSON configs
  processed/
    labeled_features.csv     # 434-record training set (single source of truth)
    model_results.csv        # cross-validation metrics
    per_resource_results.csv # per-resource-type breakdown
  samples/              # demo configs for predict.py and the Streamlit app
    realworld/          # held-out test set (transcribed from public sources)
models/
  random_forest.pkl     # trained primary model
  scaler.pkl            # fitted StandardScaler
outputs/
  confusion_matrix.png
  feature_importance.png
  model_comparison.png
  roc_curve.png
  s3_pr_curve.png
  checkov_comparison.png       # ML vs rules
  realworld_holdout.csv        # per-sample held-out predictions
  realworld_holdout_summary.csv
```

---

## Features (26)

| Feature                          | Resource | Description |
|----------------------------------|----------|-------------|
| public_access_enabled            | S3       | Bucket grants public/authenticated access |
| encryption_enabled               | S3       | Server-side encryption configured |
| versioning_enabled               | S3       | Object versioning enabled |
| logging_enabled                  | S3       | Access logging enabled |
| bucket_policy_wildcard           | S3       | Bucket policy grants `Principal: "*"` (Allow) |
| mfa_delete_enabled               | S3       | MFA delete configured on versioning |
| tls_enforced                     | S3       | Bucket policy enforces `aws:SecureTransport=true` |
| s3_missing_control_count         | S3       | Count of missing S3 controls (derived) |
| s3_no_encrypt_no_version         | S3       | No encryption AND no versioning (derived) |
| s3_public_no_logging             | S3       | Public AND no logging (derived) |
| has_wildcard_permission          | IAM      | `Action: "*"` |
| has_admin_privilege              | IAM      | `Action: "*"` + `Resource: "*"` (Allow) |
| has_priv_esc_potential           | IAM      | Privilege-escalation actions (e.g. `iam:AttachUserPolicy`) |
| dangerous_service_wildcard       | IAM      | Count of `<service>:*` actions (e.g. `s3:*`, `iam:*`) |
| has_no_condition                 | IAM      | Allow statement without a `Condition` block |
| policy_length                    | IAM      | Character length of policy document |
| allow_wildcard_action            | IAM      | Effect-aware wildcard action |
| allow_wildcard_resource          | IAM      | Effect-aware wildcard resource |
| inbound_rule_count               | SG       | Number of inbound rules |
| outbound_rule_count              | SG       | Number of outbound rules |
| open_ports_to_world              | SG       | Ports exposed to `0.0.0.0/0` |
| ssh_open_to_world                | SG       | Port 22 open to world |
| rdp_open_to_world                | SG       | Port 3389 open to world |
| db_port_open_to_world            | SG       | DB ports (3306/5432/6379/27017/9200/etc.) open to world |
| all_ports_open                   | SG       | Full range (0–65535) open to world |
| egress_unrestricted              | SG       | Outbound `0.0.0.0/0` covering all ports/protocols (exfil path) |

---

## Limitations & threats to validity

This is a course capstone, not a production claim. Honest gaps:

1. **Label circularity.** Ground-truth labels are derived from CIS-aligned
   rules in [src/label.py](src/label.py). Checkov also encodes
   CIS-aligned rules, so the head-to-head comparison partially measures
   "how well does the model approximate its own labeling function." The
   Security Group gap (RF F1 1.00 vs Checkov 0.58) is real because
   Checkov's rules are stricter than ours, but a fully independent
   relabel by an external reviewer would be stronger evidence.
2. **Held-out N is small.** The real-world test set has 8 samples — fine
   for a sanity check on generalization, too small for tight confidence
   intervals on precision/recall. A 50+ sample expert-relabeled set is
   future work.
3. **No statistical significance test reported.** The RF/LR delta
   (F1 0.89 vs 0.88) is small. McNemar's test or paired CV t-tests are
   left for the paper writeup.
4. **Context blindness.** The model has no signal for resource purpose
   (public ALB vs internal EC2). The held-out ALB case is included
   intentionally to surface this limitation.
5. **Hand-transcribed real-world set.** Modern Terraform AWS provider
   4.x+ syntax (separate `aws_s3_bucket_versioning` resources) is not
   reliably handled by the regex parsers, so the held-out samples were
   transcribed into the scoring schema rather than parsed end-to-end.

---

## Data sources & references

Labels derived from:
- **CIS AWS Foundations Benchmark**
- **AWS Config Managed Rules**
- **AWS Security Hub controls**

Training data:
- Staged AWS account configs (controlled JSON for testing)
- [TerraGoat](https://github.com/bridgecrewio/terragoat) — intentionally insecure Terraform
- [CfnGoat](https://github.com/bridgecrewio/cfngoat) — intentionally insecure CloudFormation
- [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) — Rhino Security Labs vulnerable AWS attack scenarios
- [Checkov](https://github.com/bridgecrewio/checkov) test fixtures
- [AWS Security Reference Architecture](https://github.com/aws-samples/aws-security-reference-architecture-examples) — secure baselines
- Hand-crafted synthetic edge cases

Literature:
- Palo Alto Networks Unit 42 Cloud Threat Report (2024) — IAM role exploitation
- CrowdStrike Top 11 AWS Misconfigurations (2025) — S3, IAM, SG patterns
- Gigamon AWS Security Challenges (2025) — configuration drift, excessive permissions

---

## Tools

scikit-learn · pandas · numpy · joblib · PyYAML · matplotlib · seaborn ·
**streamlit** · **shap** · **checkov**
