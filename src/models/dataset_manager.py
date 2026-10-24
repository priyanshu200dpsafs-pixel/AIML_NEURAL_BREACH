#!/usr/bin/env python3
"""
Dataset Manager — Real Benchmark Data Ingestion & Partitioning
Team: Neural Breach | AI/ML Cyber Defense Platform
Role 3: Machine Learning & Anomaly Detection

Handles schema reconciliation, stratified capture-aware splitting across all 10
CSE-CIC-IDS2018 captures, UNSW-NB15, and CTU-13.
Ensures zero data leakage: preprocessors (StandardScaler, LabelEncoder) are fitted
strictly on training partitions only.
"""

import os
import sys
import glob
import json
import time
import hashlib
from collections import Counter
from typing import Dict, List, Tuple, Any

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CSE_DIR = os.path.join(PROJECT_ROOT, "data", "processed", "CSE-CIC-IDS2018_v2")
UNSW_DIR = os.path.join(PROJECT_ROOT, "data", "processed", "UNSW-NB15")
CTU_DIR = os.path.join(PROJECT_ROOT, "data", "processed", "CTU-13")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "role3_real_data")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports", "model_training")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Metadata and identifier columns that must be strictly excluded from predictive inputs
METADATA_AND_ID_COLS = {
    "Timestamp", "Label", "_Raw_Label", "_Clean_Label", "_Source_File",
    "Src IP", "Dst IP", "Src Port", "Flow ID"
}


def get_cse_feature_lists() -> Tuple[List[str], List[str]]:
    """
    Extract common canonical features across all 10 CSE-CIC-IDS2018 files.
    Returns:
        (baseline_features_77, port_features_78)
    """
    files = sorted(glob.glob(os.path.join(CSE_DIR, "*.parquet")))
    if not files:
        raise FileNotFoundError(f"No parquet files found in {CSE_DIR}")

    common_features = None
    for f in files:
        schema = pq.read_schema(f)
        feats = set(schema.names) - METADATA_AND_ID_COLS
        if common_features is None:
            common_features = feats
        else:
            common_features &= feats

    baseline_features = sorted(list(common_features - {"Dst Port"}))
    port_features = sorted(list(common_features))
    return baseline_features, port_features


def load_cse_master_data(
    max_train_samples: int = 1_200_000,
    max_val_samples: int = 300_000,
    max_test_samples: int = 500_000,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Build stratified, capture-aware partitions across all 10 daily captures of CSE-CIC-IDS2018.
    Strategy:
      - 100% of all rare cyber attacks are retained (SQLi, XSS, Brute Force Web, LOIC-UDP, Slowloris, GoldenEye, Infiltration).
      - Multi-class balance across all 15 classes from all 10 days.
      - Chronological ordering is preserved within each daily capture.
      - Preprocessors (StandardScaler, LabelEncoder) fitted strictly on the Training set.
    """
    print("=" * 70)
    print("  LOADING CSE-CIC-IDS2018 MASTER DATASET (10 Daily Captures)")
    print("=" * 70)

    baseline_features, port_features = get_cse_feature_lists()
    print(f"[*] Identified {len(baseline_features)} baseline features (excl. Dst Port)")
    print(f"[*] Identified {len(port_features)} features with port (incl. Dst Port)")

    # Save feature lists
    with open(os.path.join(MODELS_DIR, "feature_columns_baseline.json"), "w") as fp:
        json.dump(baseline_features, fp, indent=2)
    with open(os.path.join(MODELS_DIR, "feature_columns_with_port.json"), "w") as fp:
        json.dump(port_features, fp, indent=2)

    files = sorted(glob.glob(os.path.join(CSE_DIR, "*.parquet")))
    
    # Rare attack classes where 100% of records are preserved
    RARE_ATTACK_CLASSES = {
        "SQL Injection", "Brute Force -XSS", "Brute Force -Web",
        "DDOS attack-LOIC-UDP", "DoS attacks-Slowloris", "DoS attacks-GoldenEye",
        "Infiltration"
    }

    train_dfs = []
    val_dfs = []
    test_dfs = []
    manifest_rows = []

    np.random.seed(random_state)

    for fp in files:
        fn = os.path.basename(fp)
        day_str = fn.split("_")[0]
        meta = pq.read_metadata(fp)
        total_file_rows = meta.num_rows

        # Read only required features and clean label
        read_cols = port_features + ["_Clean_Label"]
        tab = pq.read_table(fp, columns=read_cols)
        df = tab.to_pandas()
        
        # Replace infs and NaNs cleanly
        df[port_features] = df[port_features].fillna(0.0).replace([np.inf, -np.inf], 0.0).astype(np.float32)

        classes_in_file = Counter(df["_Clean_Label"])
        print(f"\n[*] Processing [{fn}]: {total_file_rows:,} rows | Classes: {dict(classes_in_file)}")

        for lbl, count in classes_in_file.items():
            sub = df[df["_Clean_Label"] == lbl]

            # Infiltration special track: Feb 28 -> 100% Train; Mar 01 -> 100% Test (Held-out day)
            if lbl == "Infiltration" and "Wednesday-28-02" in fn:
                train_dfs.append(sub)
                manifest_rows.append({
                    "capture_day": day_str, "source_file": fn, "class_label": lbl,
                    "split_partition": "TRAIN", "rows_count": len(sub),
                    "strategy": "Capture-Day Train (100% Infiltration on Feb 28)"
                })
                continue
            elif lbl == "Infiltration" and "Thursday-01-03" in fn:
                test_dfs.append(sub)
                manifest_rows.append({
                    "capture_day": day_str, "source_file": fn, "class_label": lbl,
                    "split_partition": "TEST_HELD_OUT", "rows_count": len(sub),
                    "strategy": "Held-Out Capture Day (100% Infiltration on Mar 01)"
                })
                continue

            # Rare attacks: Retain 100% across Train (70%), Val (15%), Test (15%)
            if lbl in RARE_ATTACK_CLASSES:
                n = len(sub)
                n_tr = int(n * 0.70)
                n_va = int(n * 0.15)
                sub_tr = sub.iloc[:n_tr]
                sub_va = sub.iloc[n_tr:n_tr + n_va]
                sub_te = sub.iloc[n_tr + n_va:]
            elif lbl == "Benign":
                # For Benign, sample proportionally to prevent memory explosion
                # Target: ~80,000 benign per day for train, ~20,000 for val, ~30,000 for test
                target_tr = min(len(sub), 80_000)
                target_va = min(len(sub) - target_tr, 20_000)
                target_te = min(len(sub) - target_tr - target_va, 30_000)
                
                sub_tr = sub.iloc[:target_tr]
                sub_va = sub.iloc[target_tr:target_tr + target_va]
                sub_te = sub.iloc[target_tr + target_va:target_tr + target_va + target_te]
            else:
                # Volumetric attack (HOIC, LOIC-HTTP, Hulk, Bot, FTP, SSH, SlowHTTPTest):
                # Sample up to 60k train, 15k val, 20k test per day to ensure balanced representation
                target_tr = min(len(sub), 60_000)
                target_va = min(len(sub) - target_tr, 15_000)
                target_te = min(len(sub) - target_tr - target_va, 20_000)

                sub_tr = sub.iloc[:target_tr]
                sub_va = sub.iloc[target_tr:target_tr + target_va]
                sub_te = sub.iloc[target_tr + target_va:target_tr + target_va + target_te]

            train_dfs.append(sub_tr)
            val_dfs.append(sub_va)
            test_dfs.append(sub_te)

            manifest_rows.append({
                "capture_day": day_str, "source_file": fn, "class_label": lbl,
                "split_partition": "TRAIN", "rows_count": len(sub_tr),
                "strategy": "Stratified Chronological"
            })
            manifest_rows.append({
                "capture_day": day_str, "source_file": fn, "class_label": lbl,
                "split_partition": "VALIDATION", "rows_count": len(sub_va),
                "strategy": "Stratified Chronological"
            })
            manifest_rows.append({
                "capture_day": day_str, "source_file": fn, "class_label": lbl,
                "split_partition": "TEST", "rows_count": len(sub_te),
                "strategy": "Stratified Chronological"
            })

    train_df = pd.concat(train_dfs, ignore_index=True)
    val_df = pd.concat(val_dfs, ignore_index=True)
    test_df = pd.concat(test_dfs, ignore_index=True)

    print("\n" + "=" * 70)
    print(f"  PARTITIONS GENERATED SUCCESSFULLY:")
    print(f"  -> Train: {len(train_df):,} flows ({dict(Counter(train_df['_Clean_Label']))})")
    print(f"  -> Val:   {len(val_df):,} flows")
    print(f"  -> Test:  {len(test_df):,} flows")
    print("=" * 70)

    # Encode Labels on TRAIN ONLY
    le = LabelEncoder()
    # All canonical 15 classes
    canonical_classes = sorted(list(train_df["_Clean_Label"].unique()))
    le.fit(canonical_classes)
    label_mapping = {int(i): cls for i, cls in enumerate(le.classes_)}

    train_df["Target"] = le.transform(train_df["_Clean_Label"])
    val_df["Target"] = le.transform(val_df["_Clean_Label"])
    test_df["Target"] = le.transform(test_df["_Clean_Label"])

    with open(os.path.join(MODELS_DIR, "label_mapping.json"), "w") as fp:
        json.dump(label_mapping, fp, indent=2)
    joblib.dump(le, os.path.join(MODELS_DIR, "label_encoder.joblib"))

    # Fit StandardScaler on TRAIN ONLY
    print("[*] Fitting StandardScaler on Train partition only...")
    scaler_base = StandardScaler()
    scaler_base.fit(train_df[baseline_features].values)
    joblib.dump(scaler_base, os.path.join(MODELS_DIR, "scaler_baseline.joblib"))

    scaler_port = StandardScaler()
    scaler_port.fit(train_df[port_features].values)
    joblib.dump(scaler_port, os.path.join(MODELS_DIR, "scaler_with_port.joblib"))

    # Save split manifest
    manifest_df = pd.DataFrame(manifest_rows)
    manifest_df.to_csv(os.path.join(REPORTS_DIR, "split_manifest.csv"), index=False)
    print(f"[+] Saved split manifest to {os.path.join(REPORTS_DIR, 'split_manifest.csv')}")

    return {
        "train_df": train_df,
        "val_df": val_df,
        "test_df": test_df,
        "baseline_features": baseline_features,
        "port_features": port_features,
        "label_mapping": label_mapping,
        "scaler_base": scaler_base,
        "scaler_port": scaler_port
    }


def load_unsw_benchmark() -> Dict[str, Any]:
    """
    Load the separate UNSW-NB15 benchmark dataset.
    Train: 82,332 rows, Test: 175,341 rows across 42 numeric predictive features.
    """
    p_train = os.path.join(UNSW_DIR, "UNSW_NB15_training-set.parquet")
    p_test = os.path.join(UNSW_DIR, "UNSW_NB15_testing-set.parquet")

    df_train = pq.read_table(p_train).to_pandas()
    df_test = pq.read_table(p_test).to_pandas()

    features = [c for c in df_train.columns if c not in ["id", "label", "_Source_File", "_Split"]]
    
    # Fill NAs
    df_train[features] = df_train[features].fillna(0.0).astype(np.float32)
    df_test[features] = df_test[features].fillna(0.0).astype(np.float32)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(df_train[features].values)
    X_test = scaler.transform(df_test[features].values)

    y_train = df_train["label"].values.astype(int)
    y_test = df_test["label"].values.astype(int)

    return {
        "X_train": X_train,
        "y_train": y_train,
        "X_test": X_test,
        "y_test": y_test,
        "features": features,
        "scaler": scaler
    }


def load_ctu13_evaluation() -> Dict[str, Any]:
    """
    Load the CTU-13 Scenario 1 Neris botnet flow evaluation dataset.
    Contains 14,521 flows, all labeled Botnet-Neris.
    """
    p = os.path.join(CTU_DIR, "ctu13_scenario1_flows.parquet")
    df = pq.read_table(p).to_pandas()
    return df


if __name__ == "__main__":
    data = load_cse_master_data()
    print("[✓] Master data loader test complete!")
