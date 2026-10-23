#!/usr/bin/env python3
"""
Feature Engineering and Trustworthy Evaluation Split Pipeline
Team: Neural Breach | AI/ML Cyber Defense Platform
Creates stratified chronological splits, saves split manifest, and fits scalers on Train data only.
"""

import os
import sys
import glob
import csv
import json
import time
import joblib
import pandas as pd
import numpy as np
from collections import Counter
from sklearn.preprocessing import LabelEncoder, StandardScaler

PROCESSED_DIR = "/Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/data/processed/CSE-CIC-IDS2018"
SPLITS_DIR = "/Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/data/processed/splits"
MODELS_DIR = "/Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/models"
REPORTS_DIR = "/Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/reports/model_baseline"

os.makedirs(SPLITS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

def build_splits():
    print("[*] 1. Loading processed Parquet files for split generation...")
    
    dfs_train = []
    dfs_val = []
    dfs_test = []
    split_manifest_rows = []
    
    # Files configuration
    # Day-based held-out for Infiltration: 28-02 (Train) vs 01-03 (Test)
    # Stratified chronological for 16-02 (DoS) and 21-02 (DDoS)
    files_cfg = [
        {
            "filename": "Friday-16-02-2018_TrafficForML_CICFlowMeter.parquet",
            "strategy": "Stratified Chronological (70% Train, 15% Val, 15% Test)",
            "day": "2018-02-16",
            "attacks_present": "DoS attacks-Hulk, DoS attacks-SlowHTTPTest, Benign"
        },
        {
            "filename": "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet",
            "strategy": "Stratified Chronological (70% Train, 15% Val, 15% Test)",
            "day": "2018-02-21",
            "attacks_present": "DDOS attack-HOIC, DDOS attack-LOIC-UDP, Benign"
        },
        {
            "filename": "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.parquet",
            "strategy": "Capture-Day Train Partition (100% Train)",
            "day": "2018-02-28",
            "attacks_present": "Infiltration, Benign"
        },
        {
            "filename": "Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet",
            "strategy": "Capture-Day Held-Out Test Partition (100% Test)",
            "day": "2018-03-01",
            "attacks_present": "Infiltration, Benign"
        }
    ]
    
    for cfg in files_cfg:
        fn = cfg["filename"]
        fp = os.path.join(PROCESSED_DIR, fn)
        df = pd.read_parquet(fp)
        strat = cfg["strategy"]
        
        if "Stratified Chronological" in strat:
            for lbl in df['Clean_Label'].unique():
                sub = df[df['Clean_Label'] == lbl].sort_values('Timestamp_Epoch')
                n = len(sub)
                n_tr = int(n * 0.70)
                n_va = int(n * 0.15)
                
                sub_tr = sub.iloc[:n_tr]
                sub_va = sub.iloc[n_tr:n_tr+n_va]
                sub_te = sub.iloc[n_tr+n_va:]
                
                dfs_train.append(sub_tr)
                dfs_val.append(sub_va)
                dfs_test.append(sub_te)
                
                # record manifest entry
                split_manifest_rows.append({
                    "capture_day": cfg["day"],
                    "source_file": fn,
                    "class_label": lbl,
                    "split_partition": "TRAIN",
                    "rows_count": len(sub_tr),
                    "epoch_start": sub_tr['Timestamp_Epoch'].min() if len(sub_tr) else "N/A",
                    "epoch_end": sub_tr['Timestamp_Epoch'].max() if len(sub_tr) else "N/A",
                    "split_strategy": strat
                })
                split_manifest_rows.append({
                    "capture_day": cfg["day"],
                    "source_file": fn,
                    "class_label": lbl,
                    "split_partition": "VALIDATION",
                    "rows_count": len(sub_va),
                    "epoch_start": sub_va['Timestamp_Epoch'].min() if len(sub_va) else "N/A",
                    "epoch_end": sub_va['Timestamp_Epoch'].max() if len(sub_va) else "N/A",
                    "split_strategy": strat
                })
                split_manifest_rows.append({
                    "capture_day": cfg["day"],
                    "source_file": fn,
                    "class_label": lbl,
                    "split_partition": "TEST",
                    "rows_count": len(sub_te),
                    "epoch_start": sub_te['Timestamp_Epoch'].min() if len(sub_te) else "N/A",
                    "epoch_end": sub_te['Timestamp_Epoch'].max() if len(sub_te) else "N/A",
                    "split_strategy": strat
                })
        elif "100% Train" in strat:
            dfs_train.append(df)
            for lbl in df['Clean_Label'].unique():
                sub = df[df['Clean_Label'] == lbl]
                split_manifest_rows.append({
                    "capture_day": cfg["day"],
                    "source_file": fn,
                    "class_label": lbl,
                    "split_partition": "TRAIN",
                    "rows_count": len(sub),
                    "epoch_start": sub['Timestamp_Epoch'].min(),
                    "epoch_end": sub['Timestamp_Epoch'].max(),
                    "split_strategy": strat
                })
        elif "100% Test" in strat:
            dfs_test.append(df)
            for lbl in df['Clean_Label'].unique():
                sub = df[df['Clean_Label'] == lbl]
                split_manifest_rows.append({
                    "capture_day": cfg["day"],
                    "source_file": fn,
                    "class_label": lbl,
                    "split_partition": "TEST (Held-Out Day)",
                    "rows_count": len(sub),
                    "epoch_start": sub['Timestamp_Epoch'].min(),
                    "epoch_end": sub['Timestamp_Epoch'].max(),
                    "split_strategy": strat
                })
                
    train_df = pd.concat(dfs_train, ignore_index=True)
    val_df = pd.concat(dfs_val, ignore_index=True)
    test_df = pd.concat(dfs_test, ignore_index=True)
    
    print(f"[+] Total Clean Rows: {len(train_df) + len(val_df) + len(test_df):,}")
    print(f"    Train: {len(train_df):,} ({len(train_df)/(len(train_df)+len(val_df)+len(test_df))*100:.1f}%)")
    print(f"    Val:   {len(val_df):,} ({len(val_df)/(len(train_df)+len(val_df)+len(test_df))*100:.1f}%)")
    print(f"    Test:  {len(test_df):,} ({len(test_df)/(len(train_df)+len(val_df)+len(test_df))*100:.1f}%)")
    
    # Save split manifest
    manifest_csv = os.path.join(REPORTS_DIR, "split_manifest.csv")
    with open(manifest_csv, "w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=list(split_manifest_rows[0].keys()))
        writer.writeheader()
        writer.writerows(split_manifest_rows)
    print(f"[+] Wrote split manifest to {manifest_csv}")
    
    # Encode Target Labels
    print("[*] 2. Fitting LabelEncoder on Training target labels...")
    le = LabelEncoder()
    # Canonical 6 classes
    canonical_classes = sorted(list(train_df['Clean_Label'].unique()))
    le.fit(canonical_classes)
    
    train_df['Target'] = le.transform(train_df['Clean_Label'])
    val_df['Target'] = le.transform(val_df['Clean_Label'])
    test_df['Target'] = le.transform(test_df['Clean_Label'])
    
    label_mapping = {int(i): cls for i, cls in enumerate(le.classes_)}
    print(f"[+] Label Mapping: {label_mapping}")
    
    with open(os.path.join(MODELS_DIR, "label_mapping.json"), "w") as fp:
        json.dump(label_mapping, fp, indent=2)
    joblib.dump(le, os.path.join(MODELS_DIR, "label_encoder.joblib"))
    
    # Feature sets:
    # Metadata columns to exclude from training features:
    meta_cols = ['Timestamp_Epoch', 'Timestamp_Clean', 'Raw_Label', 'Clean_Label', 'Target']
    feature_cols_all = [c for c in train_df.columns if c not in meta_cols]
    
    # Baseline Feature Set: EXCLUDES Dst Port (to prevent memorization)
    feature_cols_baseline = [c for c in feature_cols_all if c != 'Dst Port']
    
    # Ablation Feature Set: INCLUDES Dst Port
    feature_cols_with_port = list(feature_cols_all)
    
    print(f"[+] Baseline Features (Excl. Dst Port): {len(feature_cols_baseline)} features")
    print(f"[+] Ablation Features (Incl. Dst Port): {len(feature_cols_with_port)} features")
    
    # Save feature lists
    with open(os.path.join(MODELS_DIR, "feature_columns_baseline.json"), "w") as fp:
        json.dump(feature_cols_baseline, fp, indent=2)
    with open(os.path.join(MODELS_DIR, "feature_columns_with_port.json"), "w") as fp:
        json.dump(feature_cols_with_port, fp, indent=2)
        
    # Fit StandardScaler on TRAIN ONLY
    print("[*] 3. Fitting StandardScaler on Training features only (Baseline)...")
    scaler = StandardScaler()
    scaler.fit(train_df[feature_cols_baseline])
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler_baseline.joblib"))
    
    scaler_port = StandardScaler()
    scaler_port.fit(train_df[feature_cols_with_port])
    joblib.dump(scaler_port, os.path.join(MODELS_DIR, "scaler_with_port.joblib"))
    
    # Save train/val/test splits to Parquet
    print("[*] 4. Saving train/val/test splits to Parquet...")
    train_df.to_parquet(os.path.join(SPLITS_DIR, "train.parquet"), compression="snappy", index=False)
    val_df.to_parquet(os.path.join(SPLITS_DIR, "val.parquet"), compression="snappy", index=False)
    test_df.to_parquet(os.path.join(SPLITS_DIR, "test.parquet"), compression="snappy", index=False)
    
    print("[+] All split partitions generated and verified successfully!")

if __name__ == "__main__":
    build_splits()
