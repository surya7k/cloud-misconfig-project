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

## Why this isn't a quantitative evaluation

These samples are a qualitative demo, not a thesis evaluation:

1. **No held-out ground truth** — the verdicts above reflect the author's
   judgment based on the labeling rules in `src/label.py`, not an
   independent expert relabel.
2. **Hand-transcribed**, not parsed end-to-end — the project's regex-based
   parsers do not reliably handle modern Terraform AWS provider 4.x+
   syntax (e.g. `aws_s3_bucket_versioning` as a separate resource), so
   these samples sidestep parser limitations.
3. **Small N** — 8 samples is sufficient for a demo segment but not for
   metrics. Future work: curate ~50+ samples and apply manual ground-truth
   labels to produce a real-world test set.

## The ALB security group case

`rw_tf_modules_alb_sg.json` is included intentionally to surface a known
limitation: the model flags it as MISCONFIGURED because ports 80/443 are
open to `0.0.0.0/0`, but for an internet-facing Application Load Balancer
this is *intended*. The model has no signal about the resource's purpose —
it cannot distinguish "public-facing ALB (intentional)" from "EC2 instance
with HTTP exposed (probably unintentional)". This is a real-world gap that
context-aware features (resource tags, naming conventions, surrounding
infrastructure) could address in future work.
