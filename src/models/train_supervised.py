#!/usr/bin/env python3
"""
Supervised Baseline ML Engine & Feature Ablation
Team: Neural Breach | AI/ML Cyber Defense Platform
Trains HistGradientBoostingClassifier with balanced class-weights, evaluates metrics,
measures inference latency, computes permutation feature importances, and tests Dst Port ablation.
"""

import os
import sys
import json
import time
import joblib
import csv
import pandas as pd
import numpy as np
from collections import Counter
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score,
    precision_score, recall_score, accuracy_score
)
from sklearn.inspection import permutation_importance

SPLITS_DIR = "/Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/data/processed/splits"
MODELS_DIR = "/Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/models"
REPORTS_DIR = "/Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/reports/model_baseline"

def evaluate_model(clf, X_test, y_test, label_mapping, model_name="Model"):
    print(f"\n[*] Evaluating {model_name} on Test set ({len(X_test):,} rows)...")
    
    # Measure inference latency over 10,000 samples
    test_sample = X_test[:10000]
    t0 = time.time()
    _ = clf.predict(test_sample)
    latency_total = time.time() - t0
    latency_per_sample_us = (latency_total / len(test_sample)) * 1_000_000
    print(f"[+] Inference Latency: {latency_per_sample_us:.2f} microseconds per flow (measured on 10,000 calls).")
    
    t_start = time.time()
    y_pred = clf.predict(X_test)
    pred_time = time.time() - t_start
    print(f"[+] Full Test Inference Time: {pred_time:.2f}s ({len(X_test)/pred_time:,.0f} flows/sec)")
    
    # Metrics
    acc = float(accuracy_score(y_test, y_pred))
    macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
    
    class_names = [label_mapping[i] for i in range(len(label_mapping))]
    report_dict = classification_report(y_test, y_pred, target_names=class_names, output_dict=True, zero_division=0)
    
    cm = confusion_matrix(y_test, y_pred)
    
    # False Positive Rate on Benign (class 0)
    # Benign is index 0: FP is benign classified as any attack
    # Total actual benign = cm[0].sum()
    # True benign = cm[0][0]
    # False positives = total actual benign - true benign
    benign_idx = 0
    total_benign = int(cm[benign_idx].sum())
    true_benign = int(cm[benign_idx][benign_idx])
    false_positives = total_benign - true_benign
    fpr = float(false_positives / total_benign) if total_benign else 0.0
    
    # Per-class summary
    per_class_metrics = {}
    for i, cls_name in enumerate(class_names):
        per_class_metrics[cls_name] = {
            "precision": float(report_dict[cls_name]["precision"]),
            "recall": float(report_dict[cls_name]["recall"]),
            "f1_score": float(report_dict[cls_name]["f1-score"]),
            "support": int(report_dict[cls_name]["support"])
        }
        
    return {
        "accuracy": acc,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "benign_fpr": fpr,
        "false_positives_count": false_positives,
        "total_benign_count": total_benign,
        "inference_latency_us_per_sample": latency_per_sample_us,
        "per_class_metrics": per_class_metrics,
        "confusion_matrix": cm.tolist()
    }

def main():
    print("=== STARTING SUPERVISED BASELINE MODEL ENGINE ===")
    
    # 1. Load label mapping and feature definitions
    with open(os.path.join(MODELS_DIR, "label_mapping.json")) as f:
        label_mapping_raw = json.load(f)
    label_mapping = {int(k): str(v) for k, v in label_mapping_raw.items()}
    
    with open(os.path.join(MODELS_DIR, "feature_columns_baseline.json")) as f:
        features_baseline = json.load(f)
        
    with open(os.path.join(MODELS_DIR, "feature_columns_with_port.json")) as f:
        features_with_port = json.load(f)
        
    print(f"[+] Loaded {len(label_mapping)} classes: {label_mapping}")
    print(f"[+] Baseline features (excl. Dst Port): {len(features_baseline)}")
    print(f"[+] Ablation features (incl. Dst Port): {len(features_with_port)}")
    
    # 2. Load Train and Test Data
    print("\n[*] Loading Train & Test splits from Parquet...")
    train_df = pd.read_parquet(os.path.join(SPLITS_DIR, "train.parquet"))
    test_df = pd.read_parquet(os.path.join(SPLITS_DIR, "test.parquet"))
    
    print(f"[+] Train shape: {train_df.shape} | Test shape: {test_df.shape}")
    
    y_train = train_df['Target'].values
    y_test = test_df['Target'].values
    
    # Compute Class Weights Strategy
    class_counts = Counter(y_train)
    total_samples = len(y_train)
    n_classes = len(label_mapping)
    print("\n[*] Class Distribution in Training Set:")
    for c_idx in sorted(class_counts.keys()):
        cnt = class_counts[c_idx]
        weight = total_samples / (n_classes * cnt)
        print(f"  Class {c_idx} ({label_mapping[c_idx]:25s}): {cnt:,} samples | Imbalance weight: {weight:.4f}")
        
    # =========================================================================
    # EXPERIMENT 1: BASELINE MODEL (WITHOUT Dst Port) - HistGradientBoosting
    # =========================================================================
    print("\n" + "=" * 60)
    print("[*] TRAINING BASELINE MODEL (77 Features, Excludes Dst Port)")
    print("=" * 60)
    X_train_base = train_df[features_baseline].values
    X_test_base = test_df[features_baseline].values
    
    clf_baseline = HistGradientBoostingClassifier(
        class_weight='balanced',
        max_iter=100,
        max_leaf_nodes=31,
        min_samples_leaf=20,
        learning_rate=0.1,
        random_state=42,
        verbose=0
    )
    
    t0 = time.time()
    clf_baseline.fit(X_train_base, y_train)
    train_time_base = time.time() - t0
    print(f"[+] Baseline Model Fitted in {train_time_base:.2f}s!")
    
    metrics_baseline = evaluate_model(clf_baseline, X_test_base, y_test, label_mapping, "Baseline (No Port)")
    metrics_baseline["training_time_seconds"] = train_time_base
    metrics_baseline["num_features"] = len(features_baseline)
    metrics_baseline["features_used"] = features_baseline
    
    # Save Baseline Model
    joblib.dump(clf_baseline, os.path.join(MODELS_DIR, "supervised_baseline_no_port.joblib"))
    print(f"[+] Saved baseline model to models/supervised_baseline_no_port.joblib")
    
    # =========================================================================
    # EXPERIMENT 2: ABLATION MODEL (WITH Dst Port)
    # =========================================================================
    print("\n" + "=" * 60)
    print("[*] TRAINING ABLATION MODEL (78 Features, Includes Dst Port)")
    print("=" * 60)
    X_train_port = train_df[features_with_port].values
    X_test_port = test_df[features_with_port].values
    
    clf_port = HistGradientBoostingClassifier(
        class_weight='balanced',
        max_iter=100,
        max_leaf_nodes=31,
        min_samples_leaf=20,
        learning_rate=0.1,
        random_state=42,
        verbose=0
    )
    
    t0 = time.time()
    clf_port.fit(X_train_port, y_train)
    train_time_port = time.time() - t0
    print(f"[+] Ablation Model Fitted in {train_time_port:.2f}s!")
    
    metrics_port = evaluate_model(clf_port, X_test_port, y_test, label_mapping, "Ablation (With Dst Port)")
    metrics_port["training_time_seconds"] = train_time_port
    metrics_port["num_features"] = len(features_with_port)
    metrics_port["features_used"] = features_with_port
    
    joblib.dump(clf_port, os.path.join(MODELS_DIR, "supervised_ablation_with_port.joblib"))
    print(f"[+] Saved ablation model to models/supervised_ablation_with_port.joblib")
    
    # =========================================================================
    # PERMUTATION FEATURE IMPORTANCE (BASELINE MODEL)
    # =========================================================================
    print("\n[*] Computing Permutation Feature Importance on Baseline Model...")
    sample_idx = np.random.choice(len(X_test_base), size=10000, replace=False)
    X_sample = X_test_base[sample_idx]
    y_sample = y_test[sample_idx]
    
    perm_res = permutation_importance(
        clf_baseline, X_sample, y_sample,
        n_repeats=5, random_state=42, n_jobs=-1, scoring="f1_macro"
    )
    
    feat_importances = []
    for col, mean_imp, std_imp in zip(features_baseline, perm_res.importances_mean, perm_res.importances_std):
        feat_importances.append({
            "feature_name": col,
            "importance_mean": float(mean_imp),
            "importance_std": float(std_imp)
        })
        
    feat_importances.sort(key=lambda x: x["importance_mean"], reverse=True)
    
    # Save feature_importance.csv
    feat_csv_path = os.path.join(REPORTS_DIR, "feature_importance.csv")
    with open(feat_csv_path, "w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=["feature_name", "importance_mean", "importance_std"])
        writer.writeheader()
        writer.writerows(feat_importances)
    print(f"[+] Wrote feature importances to {feat_csv_path}")
    
    # Top 10 features display
    print("\n[+] Top 10 Most Predictive Features:")
    for fi in feat_importances[:10]:
        print(f"   {fi['feature_name']:25s}: {fi['importance_mean']:.5f} (+/- {fi['importance_std']:.5f})")
        
    # Save all metrics to baseline_metrics.json
    all_metrics = {
        "metadata": {
            "evaluation_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "framework": "scikit-learn HistGradientBoostingClassifier (LightGBM-architecture native GBDT)",
            "alternative_rationale": "LightGBM failed on macOS arm64 due to missing Homebrew libomp.dylib runtime. HistGradientBoostingClassifier was utilized as the drop-in histogram GBDT replacement.",
            "random_seed": 42,
            "train_samples": int(len(train_df)),
            "test_samples": int(len(test_df)),
            "class_weight_strategy": "balanced"
        },
        "baseline_model_no_port": metrics_baseline,
        "ablation_model_with_port": metrics_port,
        "top_10_features": feat_importances[:10]
    }
    
    metrics_json_path = os.path.join(REPORTS_DIR, "baseline_metrics.json")
    with open(metrics_json_path, "w") as fp:
        json.dump(all_metrics, fp, indent=2)
    print(f"[+] Wrote metrics to {metrics_json_path}")
    
if __name__ == "__main__":
    main()
