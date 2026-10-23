"""
UNSW-NB15 Preprocessing Pipeline (Separate from CSE-CIC-IDS2018)
Team Neural Breach — Role 2: Network Feature Extraction & Preprocessing

Processes the official UNSW-NB15 benchmark partitions:
  - UNSW_NB15_training-set.csv
  - UNSW_NB15_testing-set.csv
  - NUSW-NB15_features.csv (feature dictionary)

Key design decisions:
  - UNSW-NB15 uses a DIFFERENT schema from CICFlowMeter (44 cols vs 80 cols).
  - They must NOT be concatenated or treated as interchangeable.
  - The official train/test split is preserved exactly.
  - 'attack_cat' (multi-class) and 'label' (binary) are both preserved.
"""

import os
import json
import hashlib
import numpy as np
import pandas as pd
from collections import Counter
from datetime import datetime, timezone

# ── Paths ──────────────────────────────────────────────────────────────
PROJECT_ROOT = "/Users/priyanshu/Desktop/aiml project team neural breach"
RAW_UNSW_DIR = os.path.join(PROJECT_ROOT, "data", "raw", "UNSW-NB15")
OUT_UNSW_DIR = os.path.join(PROJECT_ROOT, "data", "processed", "UNSW-NB15")
REPORTS_DIR  = os.path.join(PROJECT_ROOT, "reports", "data_preprocessing")

os.makedirs(OUT_UNSW_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# ── Expected UNSW-NB15 Column Schema ──────────────────────────────────
# Note: The CSV files use 'id' as the first column and have 44 columns total.
# 'attack_cat' (string multi-class) is NOT present in the published CSV files
# (only 'label' as binary 0/1). However, the dataset documentation specifies
# 9 attack categories. We check for 'attack_cat' and handle its presence/absence.

UNSW_EXPECTED_COLUMNS = [
    "id", "dur", "xProt", "xServ", "xState",
    "spkts", "dpkts", "sbytes", "dbytes", "rate",
    "sttl", "dttl", "sload", "dload",
    "sloss", "dloss", "sinpkt", "dinpkt",
    "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin",
    "tcprtt", "synack", "ackdat",
    "smean", "dmean",
    "trans_depth", "response_body_len",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd",
    "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
    "label",
]

# Numeric feature columns (everything except categorical and label)
CATEGORICAL_COLUMNS = {"xProt", "xServ", "xState"}
ID_COLUMNS = {"id"}
LABEL_COLUMNS = {"label", "attack_cat"}

# 9 attack categories defined in the UNSW-NB15 dataset documentation
UNSW_ATTACK_CATEGORIES = [
    "Normal", "Fuzzers", "Analysis", "Backdoor", "DoS",
    "Exploits", "Generic", "Reconnaissance", "Shellcode", "Worms"
]


def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def process_unsw_file(csv_path: str, split_name: str) -> dict:
    """
    Process one UNSW-NB15 CSV file.
    Returns a processing report dict.
    """
    fname = os.path.basename(csv_path)
    fsize = os.path.getsize(csv_path)
    log(f"Processing: {fname} ({fsize / (1024**2):.1f} MB) [split: {split_name}]")

    report = {
        "source_file": csv_path,
        "source_basename": fname,
        "source_size_bytes": fsize,
        "split_name": split_name,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "schema": {},
        "rows_read": 0,
        "rows_retained": 0,
        "missing_values_per_column": {},
        "inf_values_replaced": 0,
        "binary_label_dist": {},
        "attack_cat_dist": {},
        "data_types": {},
        "output_file": None,
        "output_rows": 0,
        "output_size_bytes": 0,
    }

    # Read the CSV
    df = pd.read_csv(csv_path, low_memory=False)
    report["rows_read"] = len(df)
    report["schema"]["actual_columns"] = list(df.columns)
    report["schema"]["num_columns"] = len(df.columns)

    # Verify columns match expected
    actual_set = set(df.columns)
    expected_set = set(UNSW_EXPECTED_COLUMNS)
    report["schema"]["missing_expected"] = sorted(expected_set - actual_set)
    report["schema"]["extra_actual"] = sorted(actual_set - expected_set)
    report["schema"]["match"] = actual_set == expected_set

    # Check for 'attack_cat' column
    has_attack_cat = "attack_cat" in df.columns
    report["schema"]["has_attack_cat"] = has_attack_cat
    log(f"  Columns: {len(df.columns)}, attack_cat present: {has_attack_cat}")

    # Record missing values per column
    missing = df.isnull().sum()
    report["missing_values_per_column"] = {
        col: int(cnt) for col, cnt in missing.items() if cnt > 0
    }
    log(f"  Missing values: {dict(report['missing_values_per_column'])}" if report["missing_values_per_column"] else "  No missing values")

    # Replace inf values in numeric columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    inf_mask = np.isinf(df[numeric_cols]).sum().sum()
    report["inf_values_replaced"] = int(inf_mask)
    if inf_mask > 0:
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
        log(f"  Replaced {inf_mask} infinite values with NaN")

    # Binary label distribution
    if "label" in df.columns:
        label_counts = df["label"].value_counts().to_dict()
        report["binary_label_dist"] = {str(k): int(v) for k, v in label_counts.items()}
        log(f"  Binary labels: {report['binary_label_dist']}")

    # Attack category distribution (if present)
    if has_attack_cat:
        cat_counts = df["attack_cat"].value_counts().to_dict()
        report["attack_cat_dist"] = {str(k): int(v) for k, v in cat_counts.items()}
        log(f"  Attack categories: {report['attack_cat_dist']}")

    # Record data types
    report["data_types"] = {col: str(dtype) for col, dtype in df.dtypes.items()}

    # Add provenance columns
    df["_Source_File"] = fname
    df["_Split"] = split_name

    report["rows_retained"] = len(df)
    report["output_rows"] = len(df)

    # Write to Parquet
    out_name = fname.replace(".csv", ".parquet")
    out_path = os.path.join(OUT_UNSW_DIR, out_name)
    df.to_parquet(out_path, engine="pyarrow", compression="snappy", index=False)
    report["output_file"] = out_path
    report["output_size_bytes"] = os.path.getsize(out_path)
    report["finished_at"] = datetime.now(timezone.utc).isoformat()

    log(f"  ✓ Output: {out_name} ({report['output_size_bytes'] / (1024**2):.1f} MB, {report['output_rows']:,} rows)")
    return report


def process_feature_dictionary() -> dict:
    """Parse the UNSW-NB15 feature dictionary for reference."""
    feat_path = os.path.join(RAW_UNSW_DIR, "NUSW-NB15_features.csv")
    if not os.path.exists(feat_path):
        return {"error": "Feature dictionary file not found"}

    df = pd.read_csv(feat_path, encoding="latin-1")
    features = []
    for _, row in df.iterrows():
        features.append({
            "number": int(row.iloc[0]) if pd.notna(row.iloc[0]) else None,
            "name": str(row.iloc[1]).strip() if pd.notna(row.iloc[1]) else None,
            "type": str(row.iloc[2]).strip() if pd.notna(row.iloc[2]) else None,
            "description": str(row.iloc[3]).strip() if len(row) > 3 and pd.notna(row.iloc[3]) else None,
        })

    log(f"  Feature dictionary: {len(features)} features documented")
    return {"features": features, "count": len(features)}


def process_all_unsw():
    """Process all UNSW-NB15 files and generate reports."""
    log("=" * 70)
    log("UNSW-NB15 PREPROCESSING PIPELINE — Team Neural Breach")
    log("=" * 70)

    all_reports = []

    # Process training set
    train_path = os.path.join(RAW_UNSW_DIR, "UNSW_NB15_training-set.csv")
    if os.path.exists(train_path):
        report = process_unsw_file(train_path, "train")
        all_reports.append(report)

    # Process testing set
    test_path = os.path.join(RAW_UNSW_DIR, "UNSW_NB15_testing-set.csv")
    if os.path.exists(test_path):
        report = process_unsw_file(test_path, "test")
        all_reports.append(report)

    # Parse feature dictionary
    feat_report = process_feature_dictionary()

    # Save report
    full_report = {
        "pipeline": "UNSW-NB15",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "file_reports": all_reports,
        "feature_dictionary": feat_report,
    }

    report_path = os.path.join(REPORTS_DIR, "unsw_preprocessing_report.json")
    with open(report_path, "w") as f:
        json.dump(full_report, f, indent=2, default=str)
    log(f"\nSaved report: {report_path}")

    # Summary
    total_rows = sum(r["rows_retained"] for r in all_reports)
    log(f"\n{'='*70}")
    log(f"UNSW-NB15 PROCESSING SUMMARY")
    log(f"{'='*70}")
    log(f"  Files processed:     {len(all_reports)}")
    log(f"  Total rows retained: {total_rows:,}")
    log(f"  Output directory:    {OUT_UNSW_DIR}")

    return full_report


if __name__ == "__main__":
    process_all_unsw()
