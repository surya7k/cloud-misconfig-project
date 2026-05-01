# Real-world sample configurations

These configurations are based on patterns drawn from publicly-available AWS templates,
Terraform modules, and tutorials. They are NOT raw IaC files — they are
hand-transcribed into the JSON scoring schema used by `predict.py` and the
Streamlit demo.

The framing for the demo is: *"I extracted these from real public templates
and converted them to our scoring format. The model has never seen them."*

| File | Source | Expected verdict |
|---|---|---|
| `rw_aws_samples_secure_s3.json` | AWS reference architecture pattern (aws-samples) | SECURE |
| `rw_aws_samples_data_lake_s3.json` | AWS data lake reference architecture | SECURE |
| `rw_hashicorp_learn_basic_s3.json` | HashiCorp Learn Terraform tutorial | MISCONFIGURED (no controls) |
| `rw_tf_modules_iam_readonly.json` | terraform-aws-modules/terraform-aws-iam | SECURE |
| `rw_cdk_lambda_default_role.json` | AWS CDK default Lambda execution role | SECURE |
| `rw_lambda_overprivileged_role.json` | Common Lambda tutorial anti-pattern | MISCONFIGURED |
| `rw_tf_modules_alb_sg.json` | terraform-aws-modules/terraform-aws-security-group | MISCONFIGURED per rules / **legitimate in context** |
| `rw_stackoverflow_ssh_open.json` | Common StackOverflow / quickstart pattern | MISCONFIGURED |

## Held-out evaluation

These samples function as a held-out test set: none of them appear in
`labeled_features.csv`, and the trained Random Forest sees them only at
inference time. Run the evaluation with:

```bash
python -m src.evaluate_holdout
```

Outputs `outputs/realworld_holdout.csv` (per-sample predictions) and
`outputs/realworld_holdout_summary.csv` (aggregate metrics under both
strict and context-aware interpretations).

## Threats to validity

This is a useful generalization check but not a definitive thesis-grade
evaluation:

1. **Author-assigned ground truth** — verdicts reflect the project
   author's judgment derived from the same labeling rules in
   `src/label.py`, not an independent expert relabel. This measures
   generalization across configuration *patterns*, not across labeling
   judgment.
2. **Hand-transcribed**, not parsed end-to-end — the project's regex-based
   parsers do not reliably handle modern Terraform AWS provider 4.x+
   syntax (e.g. `aws_s3_bucket_versioning` as a separate resource), so
   these samples sidestep parser limitations.
3. **Small N** — 8 samples gives only loose confidence intervals on
   precision/recall. Future work: curate ~50+ samples and apply manual
   ground-truth labels by an independent reviewer.

## The ALB security group case

`rw_tf_modules_alb_sg.json` is included intentionally to surface a known
limitation: the model flags it as MISCONFIGURED because ports 80/443 are
open to `0.0.0.0/0`, but for an internet-facing Application Load Balancer
this is *intended*. The model has no signal about the resource's purpose —
it cannot distinguish "public-facing ALB (intentional)" from "EC2 instance
with HTTP exposed (probably unintentional)". This is a real-world gap that
context-aware features (resource tags, naming conventions, surrounding
infrastructure) could address in future work.
