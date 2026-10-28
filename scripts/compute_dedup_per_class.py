#!/usr/bin/env python3
"""
Compute per-class classification metrics and support before and after deduplication
for both 77-feature models and the 78-feature port-dependent model.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import classification_report, accuracy_score, f1_score

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.models.dataset_manager import load_cse_master_data

SUPERVISED_DIR = os.path.join(PROJECT_ROOT, "models", "role3_retrain_v2", "supervised")

def main():
    print("[*] Loading master dataset...")
    data = load_cse_master_data()
    train_df = data["train_df"]
    test_df = data["test_df"]
    base_feats = data["baseline_features"]
    port_feats = data["port_features"]
    label_map = data["label_mapping"]
    inv_label_map = {v: k for k, v in label_map.items()}

    print(f"Train rows: {len(train_df):,}, Test rows: {len(test_df):,}")
    print(f"Base features: {len(base_feats)}, Port features: {len(port_feats)}")

    print("[*] Hashing 77-feature representations...")
    train_77_hashes = set(pd.util.hash_pandas_object(train_df[base_feats], index=False))
    test_77_hashes = pd.util.hash_pandas_object(test_df[base_feats], index=False)
    mask_77_non_overlap = ~test_77_hashes.isin(train_77_hashes).values

    print("[*] Hashing 78-feature representations (with Dst Port)...")
    train_78_hashes = set(pd.util.hash_pandas_object(train_df[port_feats], index=False))
    test_78_hashes = pd.util.hash_pandas_object(test_df[port_feats], index=False)
    mask_78_non_overlap = ~test_78_hashes.isin(train_78_hashes).values

    print(f"77-feature non-overlapping test flows: {mask_77_non_overlap.sum():,} / {len(test_df):,} ({mask_77_non_overlap.sum()/len(test_df):.2%})")
    print(f"78-feature non-overlapping test flows: {mask_78_non_overlap.sum():,} / {len(test_df):,} ({mask_78_non_overlap.sum()/len(test_df):.2%})")

    # Load models
    lgb_primary = joblib.load(os.path.join(SUPERVISED_DIR, "supervised_lightgbm_primary.joblib"))
    lgb_port = joblib.load(os.path.join(SUPERVISED_DIR, "supervised_lightgbm_with_port.joblib"))
    xgb_bench = joblib.load(os.path.join(SUPERVISED_DIR, "supervised_xgboost_benchmark.joblib"))

    y_test_str = test_df["_Clean_Label"].values
    # Mapping from integer code to class name
    int_to_str = {int(k): v for k, v in label_map.items()}
    target_names = [int_to_str[i] for i in range(len(int_to_str))]

    print("\n[*] Evaluating LightGBM Primary (77 features)...")
    preds_lgb = lgb_primary.predict(test_df[base_feats].values)
    preds_lgb_str = np.array([int_to_str[int(i)] for i in preds_lgb])
    rep_lgb_full = classification_report(y_test_str, preds_lgb_str, labels=target_names, output_dict=True, zero_division=0)
    rep_lgb_dedup = classification_report(y_test_str[mask_77_non_overlap], preds_lgb_str[mask_77_non_overlap], labels=target_names, output_dict=True, zero_division=0)

    print("[*] Evaluating LightGBM with Port (78 features)...")
    preds_port = lgb_port.predict(test_df[port_feats].values)
    preds_port_str = np.array([int_to_str[int(i)] for i in preds_port])
    rep_port_full = classification_report(y_test_str, preds_port_str, labels=target_names, output_dict=True, zero_division=0)
    rep_port_dedup = classification_report(y_test_str[mask_78_non_overlap], preds_port_str[mask_78_non_overlap], labels=target_names, output_dict=True, zero_division=0)

    print("[*] Evaluating XGBoost Benchmark (77 features)...")
    preds_xgb = xgb_bench.predict(test_df[base_feats].values)
    preds_xgb_str = np.array([int_to_str[int(i)] for i in preds_xgb])
    rep_xgb_full = classification_report(y_test_str, preds_xgb_str, labels=target_names, output_dict=True, zero_division=0)
    rep_xgb_dedup = classification_report(y_test_str[mask_77_non_overlap], preds_xgb_str[mask_77_non_overlap], labels=target_names, output_dict=True, zero_division=0)

    results = {
        "summary": {
            "test_total": len(test_df),
            "77_feature": {
                "overlapping": int((~mask_77_non_overlap).sum()),
                "deduplicated": int(mask_77_non_overlap.sum()),
                "overlap_pct": float((~mask_77_non_overlap).sum() / len(test_df))
            },
            "78_feature": {
                "overlapping": int((~mask_78_non_overlap).sum()),
                "deduplicated": int(mask_78_non_overlap.sum()),
                "overlap_pct": float((~mask_78_non_overlap).sum() / len(test_df))
            }
        },
        "lightgbm_77": {
            "full": rep_lgb_full,
            "dedup": rep_lgb_dedup
        },
        "lightgbm_78_port": {
            "full": rep_port_full,
            "dedup": rep_port_dedup
        },
        "xgboost_77": {
            "full": rep_xgb_full,
            "dedup": rep_xgb_dedup
        }
    }

    out_file = os.path.join(PROJECT_ROOT, "reports", "final_acceptance", "per_class_dedup_comparison.json")
    with open(out_file, "w") as fp:
        json.dump(results, fp, indent=2)
    print(f"\n[+] Saved complete per-class results to {out_file}")

if __name__ == "__main__":
    main()
