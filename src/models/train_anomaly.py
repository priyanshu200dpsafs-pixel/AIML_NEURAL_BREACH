#!/usr/bin/env python3
"""
Anomaly Detection ML Engine (Unsupervised / Benign-Only)
Team: Neural Breach | AI/ML Cyber Defense Platform
Trains an IsolationForest model purely on verified Benign network flows,
then measures False Positive Rate on unseen benign traffic and Detection Rate (Recall)
on held-out attacks (especially Infiltration and DoS/DDoS variants).
"""

import os
import sys
import json
import time
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

SPLITS_DIR = "/Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/data/processed/splits"
MODELS_DIR = "/Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/models"
REPORTS_DIR = "/Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/reports/model_baseline"

def evaluate_anomaly_detector(iso_forest, X_test, y_test, label_mapping, features):
    print(f"\n[*] Evaluating IsolationForest on Test set ({len(X_test):,} flows)...")
    
    # Measure latency on 10,000 samples
    sample_size = 10000
    X_sample = X_test[:sample_size]
    t0 = time.time()
    _ = iso_forest.predict(X_sample)
    latency_us = ((time.time() - t0) / sample_size) * 1_000_000
    print(f"[+] Anomaly Inference Latency: {latency_us:.2f} microseconds per flow.")
    
    # Full test evaluation
    t_start = time.time()
    # IsolationForest outputs: -1 for anomaly/outlier, 1 for inlier (benign)
    raw_preds = iso_forest.predict(X_test)
    scores = iso_forest.decision_function(X_test) # lower score = more abnormal
    eval_time = time.time() - t_start
    print(f"[+] Full Test Evaluation Time: {eval_time:.2f}s ({len(X_test)/eval_time:,.0f} flows/sec)")
    
    # Convert predictions to binary: 1 = Attack (flagged as anomaly), 0 = Benign (flagged as inlier)
    # raw_preds == -1 is Anomaly (Attack)
    is_anomaly = (raw_preds == -1).astype(int)
    
    # Calculate performance for Benign (class 0)
    benign_mask = (y_test == 0)
    total_benign = int(benign_mask.sum())
    # False positives are benign flows flagged as anomaly (is_anomaly == 1)
    false_positives = int(is_anomaly[benign_mask].sum())
    fpr = float(false_positives / total_benign) if total_benign else 0.0
    true_benign = total_benign - false_positives
    
    print(f"\n--- Benign Traffic Performance ---")
    print(f"Total Benign Flows: {total_benign:,}")
    print(f"True Benign Identified (Inliers): {true_benign:,} ({true_benign/total_benign*100:.2f}%)")
    print(f"False Positives (False Alarms): {false_positives:,} ({fpr*100:.2f}%)")
    print(f"False Positive Rate (FPR): {fpr:.4f}")
    
    # Calculate Detection Rate (Recall) per attack family
    print(f"\n--- Held-Out Attack Detection Rates ---")
    attack_results = {}
    total_attacks = 0
    total_attacks_detected = 0
    
    for c_idx in sorted(label_mapping.keys()):
        cls_name = label_mapping[c_idx]
        if c_idx == 0:
            continue
            
        cls_mask = (y_test == c_idx)
        cls_total = int(cls_mask.sum())
        if cls_total == 0:
            continue
            
        detected = int(is_anomaly[cls_mask].sum())
        det_rate = float(detected / cls_total)
        total_attacks += cls_total
        total_attacks_detected += detected
        
        attack_results[cls_name] = {
            "total_samples": cls_total,
            "detected_as_anomaly": detected,
            "detection_rate": det_rate,
            "missed_as_inlier": cls_total - detected,
            "mean_anomaly_score": float(scores[cls_mask].mean())
        }
        print(f"  {cls_name:25s}: {detected:,} / {cls_total:,} detected ({det_rate*100:.2f}%) | Mean Score: {scores[cls_mask].mean():.4f}")
        
    overall_attack_recall = float(total_attacks_detected / total_attacks) if total_attacks else 0.0
    print(f"\n[+] Overall Attack Detection Rate (Macro Attack Recall): {overall_attack_recall*100:.2f}% ({total_attacks_detected:,}/{total_attacks:,})")
    
    return {
        "benign_performance": {
            "total_benign_samples": total_benign,
            "true_benign": true_benign,
            "false_positives": false_positives,
            "false_positive_rate": fpr,
            "mean_benign_score": float(scores[benign_mask].mean())
        },
        "overall_attack_detection_rate": overall_attack_recall,
        "total_attacks_evaluated": total_attacks,
        "total_attacks_detected": total_attacks_detected,
        "per_attack_metrics": attack_results,
        "inference_latency_us_per_sample": latency_us,
        "evaluation_throughput_fps": len(X_test) / eval_time
    }

def main():
    print("=== STARTING UNSUPERVISED ANOMALY DETECTION ENGINE ===")
    
    # 1. Load label mapping and feature columns
    with open(os.path.join(MODELS_DIR, "label_mapping.json")) as f:
        label_mapping_raw = json.load(f)
    label_mapping = {int(k): str(v) for k, v in label_mapping_raw.items()}
    
    with open(os.path.join(MODELS_DIR, "feature_columns_baseline.json")) as f:
        features = json.load(f)
        
    print(f"[+] Loaded {len(label_mapping)} classes.")
    print(f"[+] Features used (77 baseline features, no port): {len(features)}")
    
    # 2. Load Train and Test Data
    print("\n[*] Loading splits from Parquet...")
    train_df = pd.read_parquet(os.path.join(SPLITS_DIR, "train.parquet"))
    test_df = pd.read_parquet(os.path.join(SPLITS_DIR, "test.parquet"))
    
    # Filter pure benign training data
    train_benign = train_df[train_df['Target'] == 0]
    print(f"[+] Total Training Flows: {len(train_df):,}")
    print(f"[+] Pure Benign Training Flows: {len(train_benign):,} ({len(train_benign)/len(train_df)*100:.2f}%)")
    
    X_train_benign = train_benign[features].values
    X_test = test_df[features].values
    y_test = test_df['Target'].values
    
    # 3. Train IsolationForest
    # We use n_estimators=100, max_samples=1024, contamination=0.01 (assuming <= 1% anomalous noise in benign baseline)
    print("\n[*] Training IsolationForest on pure Benign network flows...")
    iso_forest = IsolationForest(
        n_estimators=100,
        max_samples=1024,
        contamination=0.01, # strict baseline for low false-positive rate
        random_state=42,
        n_jobs=-1,
        verbose=0
    )
    
    t0 = time.time()
    iso_forest.fit(X_train_benign)
    fit_time = time.time() - t0
    print(f"[+] IsolationForest fitted in {fit_time:.2f}s!")
    
    # 4. Evaluate Anomaly Detector
    metrics = evaluate_anomaly_detector(iso_forest, X_test, y_test, label_mapping, features)
    metrics["model_parameters"] = {
        "n_estimators": 100,
        "max_samples": 1024,
        "contamination": 0.01,
        "random_state": 42,
        "training_samples_benign": len(X_train_benign),
        "training_time_seconds": fit_time,
        "num_features": len(features)
    }
    
    # 5. Save model and metrics
    model_save_path = os.path.join(MODELS_DIR, "anomaly_detector_isolation_forest.joblib")
    joblib.dump(iso_forest, model_save_path)
    print(f"\n[+] Saved anomaly detection model to {model_save_path}")
    
    metrics_save_path = os.path.join(REPORTS_DIR, "anomaly_metrics.json")
    with open(metrics_save_path, "w") as fp:
        json.dump(metrics, fp, indent=2)
    print(f"[+] Saved anomaly detection metrics to {metrics_save_path}")

if __name__ == "__main__":
    main()
