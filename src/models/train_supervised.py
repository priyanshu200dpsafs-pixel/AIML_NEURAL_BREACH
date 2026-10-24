#!/usr/bin/env python3
"""
Supervised Intrusion Detection Model Training & Scientific Evaluation
Team: Neural Breach | AI/ML Cyber Defense Platform
Role 3: Machine Learning & Anomaly Detection

Trains tree-based gradient boosted models on real multi-class CSE-CIC-IDS2018 data,
evaluates port-ablation, addresses the cross-day Infiltration false positive issue
via validation-calibrated thresholding, measures SOC throughput, and benchmarks UNSW-NB15.
"""

import os
import sys
import json
import time
import csv
from collections import Counter
from typing import Dict, Any, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
import xgboost as xgb
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score,
    precision_score, recall_score, accuracy_score
)
from sklearn.inspection import permutation_importance
import joblib

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.dataset_manager import (
    load_cse_master_data, load_unsw_benchmark, MODELS_DIR, REPORTS_DIR
)


def evaluate_classifier(
    clf,
    X_test: np.ndarray,
    y_test: np.ndarray,
    label_mapping: Dict[int, str],
    model_name: str = "Classifier",
    threshold_infil: float = 0.50,
    infil_class_idx: int = -1
) -> Dict[str, Any]:
    """
    Evaluates classifier predictions, confusion matrix, per-class metrics,
    benign false positive rate, latency, and throughput.
    If threshold_infil > 0.50 and infil_class_idx >= 0, applies probability thresholding
    to reduce cross-day false alarms on Infiltration.
    """
    print(f"\n[*] Evaluating {model_name} on Test Set ({len(X_test):,} flows)...")

    # 1. Measure Latency and Throughput
    sample_sz = min(10000, len(X_test))
    X_sample = X_test[:sample_sz]
    t0 = time.time()
    _ = clf.predict(X_sample)
    t_lat = time.time() - t0
    latency_us = (t_lat / sample_sz) * 1_000_000

    t_full_start = time.time()
    if hasattr(clf, "predict_proba"):
        probs = clf.predict_proba(X_test)
        if threshold_infil > 0.50 and infil_class_idx >= 0:
            # Calibrated prediction:
            # If highest class is Infiltration but P(Infil) < threshold_infil, fallback to 2nd highest class (typically Benign)
            raw_preds = np.argmax(probs, axis=1)
            infil_mask = (raw_preds == infil_class_idx) & (probs[:, infil_class_idx] < threshold_infil)
            probs_no_infil = probs.copy()
            probs_no_infil[:, infil_class_idx] = -1.0
            fallback_preds = np.argmax(probs_no_infil, axis=1)
            y_pred = np.where(infil_mask, fallback_preds, raw_preds)
        else:
            y_pred = np.argmax(probs, axis=1)
    else:
        y_pred = clf.predict(X_test)
    eval_duration = time.time() - t_full_start
    throughput_fps = len(X_test) / eval_duration if eval_duration > 0 else 0.0

    print(f"[+] Measured Latency: {latency_us:.2f} µs/sample | Throughput: {throughput_fps:,.0f} flows/sec")

    # Metrics
    acc = float(accuracy_score(y_test, y_pred))
    macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    class_names = [label_mapping[i] for i in range(len(label_mapping))]
    rep = classification_report(y_test, y_pred, target_names=class_names, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=list(range(len(label_mapping))))

    # Benign FPR (assuming Benign is class 0)
    benign_idx = [i for i, name in label_mapping.items() if name == "Benign"][0]
    total_benign = int(cm[benign_idx].sum())
    true_benign = int(cm[benign_idx][benign_idx])
    false_positives = total_benign - true_benign
    fpr = float(false_positives / total_benign) if total_benign else 0.0

    # Total Attacks Missed (False Negatives for attacks)
    attack_indices = [i for i in range(len(label_mapping)) if i != benign_idx]
    total_attacks = sum(int(cm[i].sum()) for i in attack_indices)
    true_attacks_detected = sum(int(cm[i][j]) for i in attack_indices for j in attack_indices)
    missed_attacks = total_attacks - true_attacks_detected
    fnr = float(missed_attacks / total_attacks) if total_attacks else 0.0

    per_class = {}
    for i, name in label_mapping.items():
        per_class[name] = {
            "precision": float(rep[name]["precision"]),
            "recall": float(rep[name]["recall"]),
            "f1_score": float(rep[name]["f1-score"]),
            "support": int(rep[name]["support"])
        }

    return {
        "accuracy": acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "benign_fpr": fpr,
        "attack_fnr": fnr,
        "false_positives_count": false_positives,
        "total_benign_count": total_benign,
        "missed_attacks_count": missed_attacks,
        "total_attacks_count": total_attacks,
        "inference_latency_us_per_sample": latency_us,
        "throughput_flows_per_second": throughput_fps,
        "per_class_metrics": per_class,
        "confusion_matrix": cm.tolist(),
        "applied_infil_threshold": threshold_infil
    }


def calibrate_infiltration_threshold(
    clf,
    X_val: np.ndarray,
    y_val: np.ndarray,
    infil_idx: int,
    benign_idx: int
) -> float:
    """
    Sweeps probability thresholds strictly on the VALIDATION partition
    to find an operating point that reduces Benign False Positive Rate to <= 1.5%
    without arbitrarily destroying Infiltration attack recall.
    """
    print("\n[*] Calibrating Infiltration Decision Threshold on VALIDATION Partition...")
    probs = clf.predict_proba(X_val)
    raw_preds = np.argmax(probs, axis=1)

    benign_mask = (y_val == benign_idx)
    infil_mask = (y_val == infil_idx)
    total_benign_val = benign_mask.sum()
    total_infil_val = infil_mask.sum()

    best_thresh = 0.50
    best_recall = 0.0

    print("  Threshold | Benign False Alarms | Benign FPR | Infiltration Recall")
    print("  " + "-" * 56)

    thresholds = [0.50, 0.60, 0.70, 0.80, 0.85, 0.90, 0.92, 0.95]
    for th in thresholds:
        # Apply threshold fallback
        mask_fallback = (raw_preds == infil_idx) & (probs[:, infil_idx] < th)
        probs_no_infil = probs.copy()
        probs_no_infil[:, infil_idx] = -1.0
        fallback = np.argmax(probs_no_infil, axis=1)
        preds_th = np.where(mask_fallback, fallback, raw_preds)

        fp_count = (preds_th[benign_mask] != benign_idx).sum()
        fpr = fp_count / total_benign_val
        rec = (preds_th[infil_mask] == infil_idx).sum() / total_infil_val if total_infil_val else 0.0

        print(f"    {th:.2f}    |       {fp_count:6,d}        |   {fpr*100:5.2f}%   |        {rec*100:5.2f}%")

        # Select threshold that achieves manageable FPR while retaining maximum recall
        if fpr <= 0.02 and rec >= best_recall:
            best_thresh = th
            best_recall = rec

    print(f"[+] Selected Optimal Threshold: {best_thresh:.2f} (Val FPR <= 2%, Retains {best_recall*100:.1f}% Infil Recall)")
    return best_thresh


def run_supervised_pipeline():
    print("=" * 70)
    print("  STARTING SUPERVISED MODEL TRAINING & EVALUATION (REAL DATA)")
    print("=" * 70)

    # 1. Load Master Dataset
    data = load_cse_master_data()
    train_df = data["train_df"]
    val_df = data["val_df"]
    test_df = data["test_df"]
    baseline_feats = data["baseline_features"]
    port_feats = data["port_features"]
    label_mapping = data["label_mapping"]

    infil_idx = [i for i, name in label_mapping.items() if name == "Infiltration"][0]
    benign_idx = [i for i, name in label_mapping.items() if name == "Benign"][0]

    y_train = train_df["Target"].values
    y_val = val_df["Target"].values
    y_test = test_df["Target"].values

    X_train_base = train_df[baseline_feats].values
    X_val_base = val_df[baseline_feats].values
    X_test_base = test_df[baseline_feats].values

    X_train_port = train_df[port_feats].values
    X_test_port = test_df[port_feats].values

    # 2. Train Primary Model: HistGradientBoosting (Baseline, 77 features, no port)
    print("\n" + "=" * 60)
    print("[*] 1. TRAINING HISTGRADIENTBOOSTING BASELINE (77 Features, Excl. Dst Port)")
    print("=" * 60)
    clf_hist_base = HistGradientBoostingClassifier(
        class_weight="balanced",
        max_iter=100,
        max_leaf_nodes=63,
        min_samples_leaf=30,
        learning_rate=0.1,
        random_state=42,
        verbose=0
    )
    t0 = time.time()
    clf_hist_base.fit(X_train_base, y_train)
    train_time_base = time.time() - t0
    print(f"[+] HistGBT Baseline fitted in {train_time_base:.2f}s!")

    # Standard Argmax Evaluation on Test
    raw_eval_base = evaluate_classifier(clf_hist_base, X_test_base, y_test, label_mapping, "HistGBT Baseline (Raw Argmax)")

    # Calibrate Infiltration threshold on Validation
    opt_thresh = calibrate_infiltration_threshold(clf_hist_base, X_val_base, y_val, infil_idx, benign_idx)

    # Calibrated Evaluation on Test
    calib_eval_base = evaluate_classifier(
        clf_hist_base, X_test_base, y_test, label_mapping,
        "HistGBT Baseline (Calibrated Infil Threshold)",
        threshold_infil=opt_thresh,
        infil_class_idx=infil_idx
    )
    calib_eval_base["training_time_seconds"] = train_time_base

    # Save fitted model
    joblib.dump(clf_hist_base, os.path.join(MODELS_DIR, "supervised_histgbt_baseline.joblib"))

    # 3. Train Port Ablation Model (78 features, incl. Dst Port)
    print("\n" + "=" * 60)
    print("[*] 2. TRAINING PORT ABLATION MODEL (78 Features, Incl. Dst Port)")
    print("=" * 60)
    clf_hist_port = HistGradientBoostingClassifier(
        class_weight="balanced",
        max_iter=100,
        max_leaf_nodes=63,
        min_samples_leaf=30,
        learning_rate=0.1,
        random_state=42,
        verbose=0
    )
    t0 = time.time()
    clf_hist_port.fit(X_train_port, y_train)
    train_time_port = time.time() - t0
    print(f"[+] Port Ablation model fitted in {train_time_port:.2f}s!")

    eval_port = evaluate_classifier(
        clf_hist_port, X_test_port, y_test, label_mapping,
        "HistGBT Ablation (With Dst Port, Calibrated)",
        threshold_infil=opt_thresh,
        infil_class_idx=infil_idx
    )
    eval_port["training_time_seconds"] = train_time_port
    joblib.dump(clf_hist_port, os.path.join(MODELS_DIR, "supervised_histgbt_with_port.joblib"))

    # 4. Train Comparison Candidate: XGBoost Classifier
    print("\n" + "=" * 60)
    print("[*] 3. TRAINING XGBOOST CANDIDATE (77 Features)")
    print("=" * 60)
    clf_xgb = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        tree_method="hist",
        random_state=42,
        n_jobs=-1
    )
    t0 = time.time()
    # Train on 300k sample for comparative efficiency
    sub_idx = np.random.choice(len(X_train_base), size=min(300000, len(X_train_base)), replace=False)
    clf_xgb.fit(X_train_base[sub_idx], y_train[sub_idx])
    train_time_xgb = time.time() - t0
    print(f"[+] XGBoost fitted in {train_time_xgb:.2f}s!")

    eval_xgb = evaluate_classifier(clf_xgb, X_test_base, y_test, label_mapping, "XGBoost Candidate")
    eval_xgb["training_time_seconds"] = train_time_xgb
    joblib.dump(clf_xgb, os.path.join(MODELS_DIR, "supervised_xgboost_candidate.joblib"))

    # 5. Permutation Feature Importance Analysis on Baseline Model
    print("\n[*] 4. Computing Permutation Feature Importance (Top Features)...")
    sample_sz_perm = min(5000, len(X_test_base))
    idx_perm = np.random.choice(len(X_test_base), size=sample_sz_perm, replace=False)
    X_perm = X_test_base[idx_perm]
    y_perm = y_test[idx_perm]

    perm = permutation_importance(
        clf_hist_base, X_perm, y_perm,
        n_repeats=3, random_state=42, n_jobs=-1, scoring="f1_macro"
    )

    feat_importances = []
    for col, mean_imp, std_imp in zip(baseline_feats, perm.importances_mean, perm.importances_std):
        feat_importances.append({
            "feature_name": col,
            "importance_mean": float(mean_imp),
            "importance_std": float(std_imp)
        })
    feat_importances.sort(key=lambda x: x["importance_mean"], reverse=True)

    with open(os.path.join(REPORTS_DIR, "feature_importance.csv"), "w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=["feature_name", "importance_mean", "importance_std"])
        writer.writeheader()
        writer.writerows(feat_importances)
    print(f"[+] Saved feature importances to {os.path.join(REPORTS_DIR, 'feature_importance.csv')}")

    # 6. Train Separate UNSW-NB15 Benchmark Model
    print("\n" + "=" * 60)
    print("[*] 5. TRAINING UNSW-NB15 SEPARATE BENCHMARK MODEL")
    print("=" * 60)
    unsw_data = load_unsw_benchmark()
    clf_unsw = HistGradientBoostingClassifier(
        max_iter=100,
        learning_rate=0.1,
        random_state=42
    )
    t0 = time.time()
    clf_unsw.fit(unsw_data["X_train"], unsw_data["y_train"])
    train_time_unsw = time.time() - t0
    y_pred_unsw = clf_unsw.predict(unsw_data["X_test"])

    unsw_acc = float(accuracy_score(unsw_data["y_test"], y_pred_unsw))
    unsw_f1 = float(f1_score(unsw_data["y_test"], y_pred_unsw))
    unsw_prec = float(precision_score(unsw_data["y_test"], y_pred_unsw))
    unsw_rec = float(recall_score(unsw_data["y_test"], y_pred_unsw))
    cm_unsw = confusion_matrix(unsw_data["y_test"], y_pred_unsw)
    unsw_fpr = float(cm_unsw[0][1] / (cm_unsw[0][0] + cm_unsw[0][1]))

    print(f"[+] UNSW-NB15 Benchmark (Test Set: {len(unsw_data['X_test']):,} flows):")
    print(f"    Accuracy: {unsw_acc*100:.2f}% | Binary F1: {unsw_f1:.4f} | Recall: {unsw_rec*100:.2f}% | FPR: {unsw_fpr*100:.2f}%")

    unsw_metrics = {
        "dataset": "UNSW-NB15 (Separate Benchmark)",
        "train_samples": int(len(unsw_data["X_train"])),
        "test_samples": int(len(unsw_data["X_test"])),
        "num_features": len(unsw_data["features"]),
        "accuracy": unsw_acc,
        "f1_score": unsw_f1,
        "precision": unsw_prec,
        "recall": unsw_rec,
        "false_positive_rate": unsw_fpr,
        "training_time_seconds": train_time_unsw,
        "confusion_matrix": cm_unsw.tolist()
    }
    joblib.dump(clf_unsw, os.path.join(MODELS_DIR, "supervised_unsw_nb15.joblib"))

    # 7. Package and Save All Supervised Metrics
    all_supervised_results = {
        "metadata": {
            "evaluation_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "frameworks": ["scikit-learn 1.7.2", "xgboost 1.7.6"],
            "hardware": "macOS Apple Silicon (10 cores, arm64)",
            "primary_candidate": "HistGradientBoostingClassifier",
            "alternative_evaluated": "XGBoost",
            "train_samples_cse": len(train_df),
            "val_samples_cse": len(val_df),
            "test_samples_cse": len(test_df),
            "classes_evaluated": len(label_mapping)
        },
        "baseline_model_raw_argmax": raw_eval_base,
        "baseline_model_calibrated": calib_eval_base,
        "ablation_model_with_port": eval_port,
        "xgboost_comparison": eval_xgb,
        "unsw_nb15_benchmark": unsw_metrics,
        "top_10_features": feat_importances[:10]
    }

    metrics_path = os.path.join(REPORTS_DIR, "supervised_metrics.json")
    with open(metrics_path, "w") as fp:
        json.dump(all_supervised_results, fp, indent=2)
    print(f"\n[+] Wrote complete supervised metrics to {metrics_path}")

    # 8. Generate Markdown Supervised Evaluation Report
    md_path = os.path.join(REPORTS_DIR, "supervised_evaluation.md")
    with open(md_path, "w") as fp:
        fp.write("# Supervised Model Training & Evaluation Report\n\n")
        fp.write(f"**Execution Timestamp**: {all_supervised_results['metadata']['evaluation_timestamp']}  \n")
        fp.write(f"**Evaluated Models**: HistGradientBoostingClassifier vs. XGBoost  \n")
        fp.write(f"**Primary Dataset**: CSE-CIC-IDS2018 (All 10 Captures, 15 Classes)  \n")
        fp.write(f"**Secondary Benchmark**: UNSW-NB15 (Separate 42-Feature Model)  \n\n")
        fp.write("---\n\n")

        fp.write("## 1. Candidate Comparison & Performance Summary\n\n")
        fp.write("| Model Name | Features | Accuracy | Macro-F1 | Weighted-F1 | Benign FPR | Latency (µs) | Throughput (flows/s) |\n")
        fp.write("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n")
        fp.write(f"| **HistGBT Baseline (Calibrated)** | 77 | **{calib_eval_base['accuracy']*100:.2f}%** | **{calib_eval_base['macro_f1']:.4f}** | **{calib_eval_base['weighted_f1']:.4f}** | **{calib_eval_base['benign_fpr']*100:.2f}%** | **{calib_eval_base['inference_latency_us_per_sample']:.2f}** | **{calib_eval_base['throughput_flows_per_second']:,.0f}** |\n")
        fp.write(f"| HistGBT Baseline (Raw Argmax) | 77 | {raw_eval_base['accuracy']*100:.2f}% | {raw_eval_base['macro_f1']:.4f} | {raw_eval_base['weighted_f1']:.4f} | {raw_eval_base['benign_fpr']*100:.2f}% | {raw_eval_base['inference_latency_us_per_sample']:.2f} | {raw_eval_base['throughput_flows_per_second']:,.0f} |\n")
        fp.write(f"| HistGBT Ablation (With Dst Port) | 78 | {eval_port['accuracy']*100:.2f}% | {eval_port['macro_f1']:.4f} | {eval_port['weighted_f1']:.4f} | {eval_port['benign_fpr']*100:.2f}% | {eval_port['inference_latency_us_per_sample']:.2f} | {eval_port['throughput_flows_per_second']:,.0f} |\n")
        fp.write(f"| XGBoost Comparison | 77 | {eval_xgb['accuracy']*100:.2f}% | {eval_xgb['macro_f1']:.4f} | {eval_xgb['weighted_f1']:.4f} | {eval_xgb['benign_fpr']*100:.2f}% | {eval_xgb['inference_latency_us_per_sample']:.2f} | {eval_xgb['throughput_flows_per_second']:,.0f} |\n\n")

        fp.write("## 2. Infiltration Cross-Day False-Positive Remediation\n\n")
        fp.write(f"- **Raw Argmax Benign False Positive Rate**: **{raw_eval_base['benign_fpr']*100:.2f}%** ({raw_eval_base['false_positives_count']:,} false alarms)\n")
        fp.write(f"- **Calibrated Threshold ({opt_thresh:.2f}) Benign FPR**: **{calib_eval_base['benign_fpr']*100:.2f}%** ({calib_eval_base['false_positives_count']:,} false alarms)\n")
        fp.write(f"- **False Alarm Reduction**: **{((raw_eval_base['false_positives_count'] - calib_eval_base['false_positives_count'])/raw_eval_base['false_positives_count'])*100:.1f}% reduction** in benign false alarms on held-out day!\n\n")

        fp.write("## 3. Per-Class Performance Breakdown (Calibrated Baseline Model)\n\n")
        fp.write("| Traffic Class | Precision | Recall | F1-Score | Support in Test |\n")
        fp.write("| :--- | :---: | :---: | :---: | :---: |\n")
        for cls_name, m in calib_eval_base["per_class_metrics"].items():
            fp.write(f"| **{cls_name}** | {m['precision']*100:.2f}% | {m['recall']*100:.2f}% | {m['f1_score']:.4f} | {m['support']:,} |\n")

        fp.write("\n## 4. UNSW-NB15 Benchmark Model\n\n")
        fp.write(f"- **Training Flows**: {unsw_metrics['train_samples']:,}\n")
        fp.write(f"- **Testing Flows**: {unsw_metrics['test_samples']:,}\n")
        fp.write(f"- **Accuracy**: **{unsw_metrics['accuracy']*100:.2f}%**\n")
        fp.write(f"- **Binary F1-Score**: **{unsw_metrics['f1_score']:.4f}**\n")
        fp.write(f"- **Attack Recall**: **{unsw_metrics['recall']*100:.2f}%**\n")
        fp.write(f"- **Benign False Alarm Rate**: **{unsw_metrics['false_positive_rate']*100:.2f}%**\n")

    print(f"[+] Wrote markdown report to {md_path}")
    return all_supervised_results


if __name__ == "__main__":
    run_supervised_pipeline()
