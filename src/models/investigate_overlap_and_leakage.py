#!/usr/bin/env python3
"""
Team Neural Breach — Cross-Partition Overlap, Session Leakage & Deduplicated Split Audit
Role 3 & Role 4 Corrections

Investigates:
  1. Full-dataset exact feature duplicates between Train, Val, and Test.
  2. Per-class and per-day breakdown of overlapping flows.
  3. Label consistency between overlapping flows (Matching vs Contradictory labels).
  4. Inspection of physical flow characteristics (packet counts, flags, durations, identifiers).
  5. Empirical metric impact: Recomputes LightGBM and XGBoost performance on a strictly Deduplicated Holdout Test Set.
"""

import os
import sys
import json
import time
from collections import Counter
import numpy as np
import pandas as pd
import joblib

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.models.dataset_manager import load_cse_master_data
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix

MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "role3_retrain_v2")
SUPERVISED_DIR = os.path.join(MODELS_DIR, "supervised")


def run_overlap_audit():
    print("=" * 80)
    print("  INVESTIGATING CROSS-PARTITION FEATURE OVERLAP & DATA LEAKAGE")
    print("=" * 80)

    t0 = time.time()
    print("[*] Ingesting master dataset partitions...")
    data = load_cse_master_data()
    train_df = data["train_df"]
    val_df = data["val_df"]
    test_df = data["test_df"]
    base_feats = data["baseline_features"]
    label_map = data["label_mapping"]
    inv_label_map = {v: k for k, v in label_map.items()}
    benign_idx = inv_label_map["Benign"]
    infil_idx = inv_label_map["Infiltration"]
    print(f"[+] Loaded in {time.time()-t0:.2f}s: Train={len(train_df):,}, Val={len(val_df):,}, Test={len(test_df):,}")

    # Load models
    lgb_primary = joblib.load(os.path.join(SUPERVISED_DIR, "supervised_lightgbm_primary.joblib"))
    xgb_bench = joblib.load(os.path.join(SUPERVISED_DIR, "supervised_xgboost_benchmark.joblib"))

    # Compute row hashes on baseline features for exact match detection
    print("\n[*] Hashing feature vectors across all partitions...")
    t_h = time.time()
    train_hashes = pd.util.hash_pandas_object(train_df[base_feats], index=False)
    test_hashes = pd.util.hash_pandas_object(test_df[base_feats], index=False)
    val_hashes = pd.util.hash_pandas_object(val_df[base_feats], index=False)
    print(f"[+] Hashed in {time.time()-t_h:.2f}s.")

    # Convert Train and Val hashes to sets
    train_hash_set = set(train_hashes)
    val_hash_set = set(val_hashes)

    # 1. Exact overlap between Test and Train
    test_in_train_mask = test_hashes.isin(train_hash_set).values
    overlap_count = int(test_in_train_mask.sum())
    overlap_pct = (overlap_count / len(test_df)) * 100
    print(f"\n[+] Total Test Flows matching Train Feature Vectors: {overlap_count:,} / {len(test_df):,} ({overlap_pct:.2f}%)")

    # 2. Overlap between Test and Val
    test_in_val_mask = test_hashes.isin(val_hash_set).values
    overlap_val_count = int(test_in_val_mask.sum())
    print(f"[+] Total Test Flows matching Val Feature Vectors:   {overlap_val_count:,} / {len(test_df):,} ({overlap_val_count/len(test_df)*100:.2f}%)")

    # 3. Class breakdown of overlapping test flows
    overlap_test_df = test_df[test_in_train_mask].copy()
    overlap_by_class = Counter(overlap_test_df["_Clean_Label"])
    total_by_class = Counter(test_df["_Clean_Label"])

    print("\n" + "=" * 70)
    print("  OVERLAP BREAKDOWN BY ATTACK CLASS (Test Flows appearing in Train)")
    print("=" * 70)
    print(f"{'Class Label':25s} | {'Overlap Count':14s} | {'Total in Test':14s} | {'Overlap %':10s}")
    print("-" * 70)
    for cls in sorted(total_by_class.keys()):
        ov_c = overlap_by_class.get(cls, 0)
        tot_c = total_by_class[cls]
        pct = (ov_c / tot_c) * 100 if tot_c > 0 else 0.0
        print(f"{cls:25s} | {ov_c:14,d} | {tot_c:14,d} | {pct:9.2f}%")

    # 4. Physical telemetry characteristics of overlapping flows
    # Inspect top overlapping feature vectors
    print("\n[*] Inspecting physical flow characteristics of overlapping feature vectors...")
    common_hashes = Counter(test_hashes[test_in_train_mask]).most_common(5)
    for rank, (h_val, freq) in enumerate(common_hashes, 1):
        sample_row = test_df[test_hashes == h_val].iloc[0]
        lbl = sample_row["_Clean_Label"]
        dur = sample_row["Flow Duration"]
        tot_fwd = sample_row["Tot Fwd Pkts"]
        tot_bwd = sample_row["Tot Bwd Pkts"]
        fwd_len = sample_row["TotLen Fwd Pkts"]
        bwd_len = sample_row["TotLen Bwd Pkts"]
        ack_cnt = sample_row["ACK Flag Cnt"]
        syn_cnt = sample_row["SYN Flag Cnt"]
        rst_cnt = sample_row["RST Flag Cnt"]
        print(f"  Top #{rank} (Hash {h_val}, Freq in Test: {freq:,}): Class={lbl}, Dur={dur}, FwdPkts={tot_fwd}, BwdPkts={tot_bwd}, FwdLen={fwd_len}, BwdLen={bwd_len}, ACK={ack_cnt}, SYN={syn_cnt}, RST={rst_cnt}")

    # 5. Label Agreement Analysis:
    # When a feature hash in Test matches Train, does the label match?
    print("\n[*] Auditing Label Agreement on overlapping hashes...")
    train_hash_to_labels = {}
    for h, lbl in zip(train_hashes, train_df["_Clean_Label"]):
        if h not in train_hash_to_labels:
            train_hash_to_labels[h] = set()
        train_hash_to_labels[h].add(lbl)

    matching_label_count = 0
    contradictory_label_count = 0
    contradictory_pairs = []

    for h, test_lbl in zip(test_hashes[test_in_train_mask], overlap_test_df["_Clean_Label"]):
        train_lbls = train_hash_to_labels[h]
        if test_lbl in train_lbls:
            matching_label_count += 1
        else:
            contradictory_label_count += 1
            if len(contradictory_pairs) < 5:
                contradictory_pairs.append((test_lbl, list(train_lbls)))

    print(f"  -> Matching Label Flows:      {matching_label_count:,} ({matching_label_count/overlap_count*100:.2f}%)")
    print(f"  -> Contradictory Label Flows:  {contradictory_label_count:,} ({contradictory_label_count/overlap_count*100:.2f}%)")
    if contradictory_pairs:
        print(f"  -> Sample Contradictions (Test Label vs Train Labels): {contradictory_pairs}")

    # 6. EMPIRICAL METRIC IMPACT: Evaluate Frozen Models on Deduplicated Test Set
    # Deduplicated Test Set: All test flows whose 77-feature vector does NOT exist in Train
    dedup_test_df = test_df[~test_in_train_mask].copy()
    print("\n" + "=" * 70)
    print(f"  EVALUATING FROZEN MODELS ON STRICTLY DEDUPLICATED TEST SET ({len(dedup_test_df):,} flows)")
    print("=" * 70)

    X_dedup = dedup_test_df[base_feats].values.astype(np.float32)
    y_dedup = dedup_test_df["Target"].values.astype(int)

    # Recompute LightGBM
    lgb_probs_dedup = lgb_primary.predict_proba(X_dedup)
    lgb_preds_dedup = np.argmax(lgb_probs_dedup, axis=1)
    cm_lgb_dedup = confusion_matrix(y_dedup, lgb_preds_dedup, labels=range(len(label_map)))
    acc_lgb_dedup = float(accuracy_score(y_dedup, lgb_preds_dedup))
    macro_f1_lgb_dedup = float(f1_score(y_dedup, lgb_preds_dedup, average="macro", zero_division=0))
    benign_fp_lgb_dedup = int(cm_lgb_dedup[benign_idx, :].sum() - cm_lgb_dedup[benign_idx, benign_idx])
    benign_tot_lgb_dedup = int(cm_lgb_dedup[benign_idx, :].sum())
    fpr_lgb_dedup = float(benign_fp_lgb_dedup / benign_tot_lgb_dedup)
    att_tot_dedup = int((y_dedup != benign_idx).sum())
    missed_lgb_dedup = int((lgb_preds_dedup[y_dedup != benign_idx] == benign_idx).sum())
    recall_lgb_dedup = float((att_tot_dedup - missed_lgb_dedup) / att_tot_dedup)
    infil_tot_dedup = int((y_dedup == infil_idx).sum())
    infil_tp_lgb_dedup = int((lgb_preds_dedup[y_dedup == infil_idx] == infil_idx).sum())
    infil_rec_lgb_dedup = float(infil_tp_lgb_dedup / infil_tot_dedup) if infil_tot_dedup > 0 else 0.0

    # Recompute XGBoost
    xgb_probs_dedup = xgb_bench.predict_proba(X_dedup)
    xgb_preds_dedup = np.argmax(xgb_probs_dedup, axis=1)
    cm_xgb_dedup = confusion_matrix(y_dedup, xgb_preds_dedup, labels=range(len(label_map)))
    acc_xgb_dedup = float(accuracy_score(y_dedup, xgb_preds_dedup))
    macro_f1_xgb_dedup = float(f1_score(y_dedup, xgb_preds_dedup, average="macro", zero_division=0))
    benign_fp_xgb_dedup = int(cm_xgb_dedup[benign_idx, :].sum() - cm_xgb_dedup[benign_idx, benign_idx])
    benign_tot_xgb_dedup = int(cm_xgb_dedup[benign_idx, :].sum())
    fpr_xgb_dedup = float(benign_fp_xgb_dedup / benign_tot_xgb_dedup)
    missed_xgb_dedup = int((xgb_preds_dedup[y_dedup != benign_idx] == benign_idx).sum())
    recall_xgb_dedup = float((att_tot_dedup - missed_xgb_dedup) / att_tot_dedup)
    infil_tp_xgb_dedup = int((xgb_preds_dedup[y_dedup == infil_idx] == infil_idx).sum())
    infil_rec_xgb_dedup = float(infil_tp_xgb_dedup / infil_tot_dedup) if infil_tot_dedup > 0 else 0.0

    print(f"\n[Deduplicated Test Set Results ({len(dedup_test_df):,} flows)]:")
    print(f"  LightGBM Primary:")
    print(f"    Full Test Set Acc: 75.62% -> Deduplicated Acc: {acc_lgb_dedup*100:5.2f}% (Delta: {acc_lgb_dedup*100 - 75.62:+.2f}%)")
    print(f"    Full Test FPR:     35.87% -> Deduplicated FPR: {fpr_lgb_dedup*100:5.2f}% (Delta: {fpr_lgb_dedup*100 - 35.87:+.2f}%)")
    print(f"    Full Attack Rec:   94.91% -> Deduplicated Rec: {recall_lgb_dedup*100:5.2f}% (Delta: {recall_lgb_dedup*100 - 94.91:+.2f}%)")
    print(f"    Full Infil Rec:    86.74% -> Deduplicated Infil Rec: {infil_rec_lgb_dedup*100:5.2f}% (Delta: {infil_rec_lgb_dedup*100 - 86.74:+.2f}%)")

    print(f"\n  XGBoost Benchmark:")
    print(f"    Full Test Set Acc: 84.57% -> Deduplicated Acc: {acc_xgb_dedup*100:5.2f}% (Delta: {acc_xgb_dedup*100 - 84.57:+.2f}%)")
    print(f"    Full Test FPR:      1.02% -> Deduplicated FPR: {fpr_xgb_dedup*100:5.2f}% (Delta: {fpr_xgb_dedup*100 - 1.02:+.2f}%)")
    print(f"    Full Attack Rec:   71.67% -> Deduplicated Rec: {recall_xgb_dedup*100:5.2f}% (Delta: {recall_xgb_dedup*100 - 71.67:+.2f}%)")
    print(f"    Full Infil Rec:    26.52% -> Deduplicated Infil Rec: {infil_rec_xgb_dedup*100:5.2f}% (Delta: {infil_rec_xgb_dedup*100 - 26.52:+.2f}%)")

    results_out = {
        "total_test_flows": len(test_df),
        "overlapping_flows_in_train": overlap_count,
        "overlap_percentage": overlap_pct,
        "overlap_in_val": overlap_val_count,
        "overlap_by_class": dict(overlap_by_class),
        "total_by_class": dict(total_by_class),
        "matching_label_count": matching_label_count,
        "contradictory_label_count": contradictory_label_count,
        "deduplicated_test_set_size": len(dedup_test_df),
        "deduplicated_metrics": {
            "lightgbm": {
                "accuracy": acc_lgb_dedup, "macro_f1": macro_f1_lgb_dedup,
                "benign_fpr": fpr_lgb_dedup, "attack_recall": recall_lgb_dedup,
                "infiltration_recall": infil_rec_lgb_dedup
            },
            "xgboost": {
                "accuracy": acc_xgb_dedup, "macro_f1": macro_f1_xgb_dedup,
                "benign_fpr": fpr_xgb_dedup, "attack_recall": recall_xgb_dedup,
                "infiltration_recall": infil_rec_xgb_dedup
            }
        }
    }

    out_json = os.path.join(PROJECT_ROOT, "reports", "final_acceptance", "overlap_investigation_results.json")
    with open(out_json, "w") as fp:
        json.dump(results_out, fp, indent=2)
    print(f"\n[+] Saved overlap investigation results to: {out_json}")


if __name__ == "__main__":
    run_overlap_audit()
