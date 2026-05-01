"""Streamlit demo for the cloud misconfiguration risk model.

Run from project root:
    streamlit run app.py
"""
import json
import warnings
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import shap
import streamlit as st

from src.aws_translator import translate as aws_translate
from src.predict import FEATURE_COLS, score_config

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

SAMPLE_DIR = Path("data/samples")
MODEL_PATH = "models/random_forest.pkl"
SCALER_PATH = "models/scaler.pkl"

CUSTOM_OPTION = "📋 Custom — paste your own AWS config"

CUSTOM_PLACEHOLDER = """// Paste your AWS native JSON here. Auto-detected formats:
//
//   IAM policy        — output of `aws iam get-policy-version`
//   Security group    — output of `aws ec2 describe-security-groups`
//   S3 bucket         — combined output (see "AWS CLI export commands"
//                       expander at the bottom of the page)
//
// You can also paste a config in the project's internal scoring schema.

{}
"""


@st.cache_resource
def load_artifacts():
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    explainer = shap.TreeExplainer(model)
    return model, scaler, explainer


def shap_for(config, scaler, explainer):
    from src.predict import extract_features
    features = extract_features(config)
    x = np.array([[features[c] for c in FEATURE_COLS]])
    x_scaled = scaler.transform(x)
    sv = explainer.shap_values(x_scaled)
    if isinstance(sv, list):
        contributions = sv[1][0]
    elif sv.ndim == 3:
        contributions = sv[0, :, 1]
    else:
        contributions = sv[0]
    return list(zip(FEATURE_COLS, [float(v) for v in contributions]))


def plot_shap_bar(contribs, top_n=8):
    pairs = sorted(contribs, key=lambda kv: abs(kv[1]), reverse=True)[:top_n]
    pairs = list(reversed(pairs))
    names = [p[0] for p in pairs]
    values = [p[1] for p in pairs]
    colors = ["#d9534f" if v > 0 else "#5cb85c" for v in values]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.barh(names, values, color=colors)
    ax.axvline(0, color="black", linewidth=0.6)
    ax.set_xlabel("SHAP contribution to P(misconfigured)")
    ax.set_title(f"Top {top_n} feature contributions")
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    fig.tight_layout()
    return fig


def list_samples():
    if not SAMPLE_DIR.exists():
        return []
    return sorted(
        str(p.relative_to(SAMPLE_DIR)).replace("\\", "/")
        for p in SAMPLE_DIR.rglob("*.json")
    )


# ---------------- UI ----------------

st.set_page_config(
    page_title="Cloud Misconfig Risk Scorer",
    page_icon=":lock:",
    layout="wide",
)

st.title("AWS Cloud Misconfiguration Risk Scorer")
st.caption(
    "IST 584 capstone — Random Forest classifier trained on S3, IAM, "
    "and Security Group configurations from real configs, TerraGoat, "
    "CfnGoat, Checkov fixtures, CloudGoat, AWSSRA, and synthetic edge cases."
)

model, scaler, explainer = load_artifacts()

left, right = st.columns([1, 1], gap="large")

with left:
    st.subheader("Configuration input")

    sample_files = list_samples()
    options = [CUSTOM_OPTION] + sample_files

    default_idx = (
        options.index("insecure_s3.json")
        if "insecure_s3.json" in options else 0
    )
    choice = st.selectbox("Load sample", options, index=default_idx, key="sample_choice")

    if choice == CUSTOM_OPTION:
        sample_text = ""  # blank — user pastes their own
        sample_path = None
    else:
        sample_path = SAMPLE_DIR / choice
        with open(sample_path) as f:
            sample_text = f.read()

    # Reset the text area when the user switches samples
    if st.session_state.get("last_sample") != choice:
        st.session_state["config_text"] = sample_text
        st.session_state["last_sample"] = choice

    text_label = (
        "Paste AWS native JSON (or internal schema)"
        if choice == CUSTOM_OPTION
        else "Edit JSON (changes update the score live)"
    )
    config_text = st.text_area(
        text_label,
        height=380,
        key="config_text",
        placeholder=CUSTOM_PLACEHOLDER if choice == CUSTOM_OPTION else None,
    )

    score_btn = st.button("Score this config", type="primary", use_container_width=True)

# ---------- Score the current config ----------

with right:
    st.subheader("Risk verdict")

    if not config_text.strip():
        st.info("Paste an AWS native JSON config (IAM, Security Group, or S3) on "
                "the left, or pick a sample from the dropdown.")
        st.stop()

    try:
        raw_payload = json.loads(config_text)
    except json.JSONDecodeError as e:
        st.error(f"Invalid JSON: {e}")
        st.stop()

    # Auto-detect AWS-native vs internal schema. translate() returns the
    # internal-schema dict + a label for what was detected.
    config, detected = aws_translate(raw_payload)
    if config is None:
        st.error(
            "Couldn't recognize the JSON format. Supported inputs:\n\n"
            "- AWS IAM policy (`aws iam get-policy-version` output, or a bare "
            "policy document with `Version` + `Statement`)\n"
            "- AWS Security Group (`aws ec2 describe-security-groups` output, "
            "or a single SG with `IpPermissions`)\n"
            "- AWS S3 bucket (combined format — see CLI snippet below)\n"
            "- Internal scoring schema (top-level `resource_type` field)"
        )
        st.stop()

    if detected != "internal":
        format_labels = {
            "iam": "AWS IAM policy",
            "sg":  "AWS Security Group",
            "s3":  "AWS S3 bucket (merged)",
        }
        st.info(
            f"✅ Detected **{format_labels.get(detected, detected)}** — "
            f"translated to the model's scoring schema."
        )
        with st.expander("View translated config"):
            st.json(config)

    try:
        result = score_config(config)
    except Exception as e:
        st.error(f"Scoring failed: {e}")
        st.stop()

    rl = result["risk_level"]
    pred = "MISCONFIGURED" if result["prediction"] == 1 else "SECURE"
    color = {"HIGH": "#c0392b", "MEDIUM": "#e67e22", "LOW": "#27ae60"}[rl]
    badge = f"""
    <div style="background:{color};color:white;padding:14px 18px;border-radius:8px;
                font-weight:600;font-size:1.15rem;margin-bottom:12px;">
        {pred}  &nbsp;·&nbsp;  Risk: {rl}
    </div>
    """
    st.markdown(badge, unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3)
    c1.metric("P(misconfigured)", f"{result['probability_misconfigured']:.1%}")
    c2.metric("P(secure)", f"{result['probability_secure']:.1%}")
    c3.metric("Decision threshold", f"{result['threshold']:.2f}")

    rt = result["resource_type"] or "unknown"
    st.caption(
        f"Resource type: **{rt}**  ·  "
        f"Confidence: **{result['confidence']:.1%}**  ·  "
        f"Resource name: `{result['resource_name'] or '(unnamed)'}`"
    )

    if result["risk_factors"]:
        st.markdown("**Risk factors detected:**")
        for f in result["risk_factors"]:
            st.markdown(f"- {f}")
    else:
        st.success("No rule-based risk factors detected.")

st.divider()
st.subheader("Why did the model decide this? (SHAP)")

try:
    contribs = shap_for(config, scaler, explainer)
    fig = plot_shap_bar(contribs, top_n=8)
    st.pyplot(fig, use_container_width=True)
    st.caption(
        "Red bars push the prediction toward MISCONFIGURED, "
        "green bars push toward SECURE. Bar length = magnitude of contribution "
        "to the P(misconfigured) output of the Random Forest."
    )
except Exception as e:
    st.warning(f"Could not compute SHAP explanation: {e}")

# ---------- AWS CLI export snippets ----------

with st.expander("🔧 AWS CLI export commands — copy-paste from your AWS account"):
    st.markdown(
        "Run any of these on a machine with AWS CLI configured for your account, "
        "then paste the output into the **Custom** dropdown above."
    )

    st.markdown("**IAM policy** (managed policy)")
    st.code(
        "POLICY_ARN=\"arn:aws:iam::123456789012:policy/MyPolicy\"\n"
        "aws iam get-policy-version \\\n"
        "  --policy-arn \"$POLICY_ARN\" \\\n"
        "  --version-id $(aws iam get-policy --policy-arn \"$POLICY_ARN\" "
        "--query 'Policy.DefaultVersionId' --output text)",
        language="bash",
    )
    st.caption(
        "Or for an inline policy on a role: "
        "`aws iam get-role-policy --role-name MyRole --policy-name MyInline`"
    )

    st.markdown("**Security Group**")
    st.code(
        "SG_ID=\"sg-0123456789abcdef0\"\n"
        "aws ec2 describe-security-groups --group-ids \"$SG_ID\"",
        language="bash",
    )

    st.markdown("**S3 bucket** (combines 5 API calls into the merged format)")
    st.code(
        "BUCKET=\"my-bucket\"\n"
        "echo \"{\n"
        "  \\\"BucketName\\\": \\\"$BUCKET\\\",\n"
        "  \\\"Encryption\\\":        $(aws s3api get-bucket-encryption        "
        "--bucket $BUCKET 2>/dev/null || echo null),\n"
        "  \\\"Versioning\\\":        $(aws s3api get-bucket-versioning        "
        "--bucket $BUCKET 2>/dev/null || echo '{}'),\n"
        "  \\\"Logging\\\":           $(aws s3api get-bucket-logging           "
        "--bucket $BUCKET 2>/dev/null || echo '{}'),\n"
        "  \\\"PublicAccessBlock\\\": $(aws s3api get-public-access-block      "
        "--bucket $BUCKET 2>/dev/null || echo null),\n"
        "  \\\"Policy\\\":            $(aws s3api get-bucket-policy            "
        "--bucket $BUCKET 2>/dev/null || echo null)\n"
        "}\"",
        language="bash",
    )
    st.caption(
        "Each get-* call may return an error if the feature isn't configured "
        "(e.g., bucket has no policy). The `|| echo null` fallbacks make sure "
        "the merged JSON stays valid in those cases."
    )

with st.expander("Model details"):
    st.markdown(
        f"""
- **Model**: Random Forest (200 estimators, class_weight=balanced)
- **Features**: {len(FEATURE_COLS)} numerical features across S3 / IAM / Security Group
- **Decision thresholds**: S3 = 0.40 (recall-optimized), IAM/SG = 0.50
- **Validation**: 5-fold stratified cross-validation
- **Targets**: F1 > 0.75, Recall > 0.80
"""
    )
