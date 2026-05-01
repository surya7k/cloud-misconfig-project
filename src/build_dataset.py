#!/usr/bin/env python3
import subprocess, sys

print("🔨 Building full dataset...")
steps = [
    "python src/ingest.py",
    "python src/label.py",
    "python src/parse_terragoat.py",
    "python src/parse_cfngoat.py",
    "python -m src.parse_cloudgoat",
    "python src/parse_checkov.py",
    "python src/parse_awssra.py",
    "python src/generate_synthetic.py"
]

for step in steps:
    print(f"Running: {step}")
    result = subprocess.run(step, shell=True)
    if result.returncode != 0:
        print(f"❌ Failed: {step}")
        sys.exit(1)

print("\n✅ FULL DATASET COMPLETE")
import pandas as pd
df = pd.read_csv('data/processed/labeled_features.csv')
print(f"Total: {len(df)} | Secure: {sum(df.label==0)} | Misconfigured: {sum(df.label==1)}")
