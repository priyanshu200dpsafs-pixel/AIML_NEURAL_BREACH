#!/usr/bin/env python3
"""
Role 3 Retraining V2 — Hybrid AI Cyber Defense Engine
Team: Neural Breach | AI/ML Cyber Defense Platform
Role 3: Machine Learning & Anomaly Detection Specialist

Executes the approved master plan:
1. Primary Supervised Candidate: LightGBM (77-feature port-agnostic canonical schema).
2. Supervised Port Ablation: LightGBM (+Dst Port, 78 features).
3. Benchmark Comparisons: XGBoost, HistGradientBoosting, Random Forest.
4. Anomaly Detection Tier: Isolation Forest vs. PyTorch Deep Autoencoder (Benign-only fitting).
5. Multi-Track Evaluation: Track A (known attacks), Track B (cross-day holdout), Track C (unseen attacks).
6. Dedicated UNSW-NB15 Benchmark Model (42 features).
7. Comprehensive Inference Latency & Throughput Benchmark.
8. Artifact & Deliverable Export to models/role3_retrain_v2/ and reports/model_training/retrain_v2/.
"""

import os
import sys
import json
import time
import glob
import joblib
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import torch
import torch.nn as nn
from typing import Dict, List, Any, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import lightgbm as lgb
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from src.models.metrics_engine import (
    evaluate_cyber_detection_predictions, compute_operating_curve, wilson_score_interval
)
from src.models.dataset_manager import (
    load_cse_master_data, load_unsw_benchmark, load_ctu13_evaluation,
    CSE_DIR, UNSW_DIR, CTU_DIR
)
from src.models.train_anomaly import DeepAutoencoder

MODELS_DIR = os.path.join(PROJECT_ROOT, "models", "role3_retrain_v2")
SUPERVISED_MODELS_DIR = os.path.join(MODELS_DIR, "supervised")
ANOMALY_MODELS_DIR = os.path.join(MODELS_DIR, "anomaly")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports", "model_training", "retrain_v2")

os.makedirs(SUPERVISED_MODELS_DIR, exist_ok=True)
os.makedirs(ANOMALY_MODELS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


def main():
    print("=" * 80)
    print("  TEAM NEURAL BREACH — ROLE 3 RETRAINING V2 PIPELINE")
    print("  Hybrid AI Cyber Defense Engine: Real Data, Reliable Detection")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # 1. Ingestion & Stratified Master Partitioning
    # -------------------------------------------------------------------------
    t0 = time.time()
    data = load_cse_master_data()
    train_df = data["train_df"]
    val_df = data["val_df"]
    test_df = data["test_df"]
    baseline_features = data["baseline_features"]
    port_features = data["port_features"]
    label_mapping = data["label_mapping"]
    
    print(f"[*] Ingestion complete in {time.time() - t0:.2f}s:")
    print(f"    Train: {len(train_df):,} | Val: {len(val_df):,} | Test: {len(test_df):,}")

    X_train_base = train_df[baseline_features].values.astype(np.float32)
    y_train = train_df["Target"].values.astype(int)

    X_val_base = val_df[baseline_features].values.astype(np.float32)
    y_val = val_df["Target"].values.astype(int)

    X_test_base = test_df[baseline_features].values.astype(np.float32)
    y_test = test_df["Target"].values.astype(int)

    benign_idx = [k for k, v in label_mapping.items() if v == "Benign"][0]
    infil_idx = [k for k, v in label_mapping.items() if v == "Infiltration"][0]

    # Save canonical feature list and label mapping
    with open(os.path.join(SUPERVISED_MODELS_DIR, "feature_columns.json"), "w") as fp:
        json.dump(baseline_features, fp, indent=2)
    with open(os.path.join(SUPERVISED_MODELS_DIR, "feature_columns_with_port.json"), "w") as fp:
        json.dump(port_features, fp, indent=2)
    with open(os.path.join(SUPERVISED_MODELS_DIR, "label_mapping.json"), "w") as fp:
        json.dump(label_mapping, fp, indent=2)

    # -------------------------------------------------------------------------
    # 2. Candidate 1: LightGBM Primary Candidate (77 Baseline Features)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  TRAINING CANDIDATE 1: LightGBM Classifier (Primary Candidate - 77 Features)")
    print("=" * 70)
    t_start = time.time()
    lgb_clf = lgb.LGBMClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=8,
        num_leaves=63,
        subsample=0.8,
        colsample_bytree=0.8,
        class_weight="balanced",
        random_state=42,
        n_jobs=4,
        verbose=-1
    )
    lgb_clf.fit(X_train_base, y_train)
    lgb_train_time = time.time() - t_start
    print(f"[+] LightGBM fitted in {lgb_train_time:.2f}s")

    # Evaluate LightGBM on untouched Test partition
    t_pred_start = time.time()
    y_pred_lgb = lgb_clf.predict(X_test_base)
    lgb_inference_time = time.time() - t_pred_start
    lgb_latency_us = (lgb_inference_time / len(X_test_base)) * 1e6
    lgb_throughput = len(X_test_base) / lgb_inference_time

    lgb_probs_test = lgb_clf.predict_proba(X_test_base)
    lgb_metrics = evaluate_cyber_detection_predictions(
        y_true=y_test, y_pred=y_pred_lgb, label_mapping=label_mapping, y_proba=lgb_probs_test
    )
    lgb_metrics["summary"]["training_time_seconds"] = lgb_train_time
    lgb_metrics["summary"]["inference_latency_us"] = lgb_latency_us
    lgb_metrics["summary"]["throughput_flows_sec"] = lgb_throughput

    print(f"    LightGBM Test Accuracy : {lgb_metrics['summary']['accuracy']*100:.2f}%")
    print(f"    LightGBM Macro-F1      : {lgb_metrics['summary']['macro_f1']:.4f}")
    print(f"    LightGBM Weighted-F1   : {lgb_metrics['summary']['weighted_f1']:.4f}")
    print(f"    LightGBM Benign FPR    : {lgb_metrics['summary']['benign_fpr']*100:.2f}% ({lgb_metrics['summary']['false_positives_count']:,d} FPs)")
    print(f"    LightGBM Missed Attacks: {lgb_metrics['summary']['missed_attacks_count']:,d} ({lgb_metrics['summary']['attack_fnr']*100:.2f}% FNR)")
    print(f"    LightGBM Latency       : {lgb_latency_us:.2f} µs/sample | Throughput: {lgb_throughput:,.0f} flows/s")

    # Save fitted LightGBM release candidate
    joblib.dump(lgb_clf, os.path.join(SUPERVISED_MODELS_DIR, "supervised_lightgbm_primary.joblib"))

    # Feature importances (split & gain)
    feat_imp = pd.DataFrame({
        "feature_name": baseline_features,
        "importance_gain": lgb_clf.booster_.feature_importance(importance_type="gain"),
        "importance_split": lgb_clf.booster_.feature_importance(importance_type="split")
    }).sort_values(by="importance_gain", ascending=False)
    feat_imp.to_csv(os.path.join(REPORTS_DIR, "feature_importance.csv"), index=False)

    # -------------------------------------------------------------------------
    # 3. Candidate 2: LightGBM Destination Port Ablation (78 Features)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  TRAINING CANDIDATE 2: LightGBM Port Ablation (+Dst Port - 78 Features)")
    print("=" * 70)
    X_train_port = train_df[port_features].values.astype(np.float32)
    X_test_port = test_df[port_features].values.astype(np.float32)

    t_start = time.time()
    lgb_port_clf = lgb.LGBMClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=8,
        num_leaves=63,
        subsample=0.8,
        colsample_bytree=0.8,
        class_weight="balanced",
        random_state=42,
        n_jobs=4,
        verbose=-1
    )
    lgb_port_clf.fit(X_train_port, y_train)
    lgb_port_train_time = time.time() - t_start
    print(f"[+] LightGBM Port Ablation fitted in {lgb_port_train_time:.2f}s")

    t_pred_start = time.time()
    y_pred_lgb_port = lgb_port_clf.predict(X_test_port)
    lgb_port_latency_us = ((time.time() - t_pred_start) / len(X_test_port)) * 1e6
    lgb_port_metrics = evaluate_cyber_detection_predictions(
        y_true=y_test, y_pred=y_pred_lgb_port, label_mapping=label_mapping
    )
    lgb_port_metrics["summary"]["training_time_seconds"] = lgb_port_train_time
    lgb_port_metrics["summary"]["inference_latency_us"] = lgb_port_latency_us
    lgb_port_metrics["summary"]["throughput_flows_sec"] = 1e6 / lgb_port_latency_us

    print(f"    Port Ablation Acc      : {lgb_port_metrics['summary']['accuracy']*100:.2f}%")
    print(f"    Port Ablation Macro-F1 : {lgb_port_metrics['summary']['macro_f1']:.4f}")
    print(f"    Port Ablation Benign FPR: {lgb_port_metrics['summary']['benign_fpr']*100:.2f}%")
    joblib.dump(lgb_port_clf, os.path.join(SUPERVISED_MODELS_DIR, "supervised_lightgbm_with_port.joblib"))

    # -------------------------------------------------------------------------
    # 4. Candidate 3: Random Forest Baseline (Representative 200k Sample)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  TRAINING CANDIDATE 3: Random Forest Baseline (Representative Sample)")
    print("=" * 70)
    rf_sample_idx = np.random.RandomState(42).choice(len(X_train_base), size=min(200_000, len(X_train_base)), replace=False)
    X_train_rf = X_train_base[rf_sample_idx]
    y_train_rf = y_train[rf_sample_idx]

    t_start = time.time()
    rf_clf = RandomForestClassifier(n_estimators=50, max_depth=12, n_jobs=4, random_state=42)
    rf_clf.fit(X_train_rf, y_train_rf)
    rf_train_time = time.time() - t_start

    t_pred_start = time.time()
    y_pred_rf = rf_clf.predict(X_test_base)
    rf_latency_us = ((time.time() - t_pred_start) / len(X_test_base)) * 1e6
    rf_metrics = evaluate_cyber_detection_predictions(
        y_true=y_test, y_pred=y_pred_rf, label_mapping=label_mapping
    )
    rf_metrics["summary"]["training_time_seconds"] = rf_train_time
    rf_metrics["summary"]["inference_latency_us"] = rf_latency_us
    rf_metrics["summary"]["throughput_flows_sec"] = 1e6 / rf_latency_us

    print(f"    Random Forest Acc      : {rf_metrics['summary']['accuracy']*100:.2f}%")
    print(f"    Random Forest Macro-F1 : {rf_metrics['summary']['macro_f1']:.4f}")
    print(f"    Random Forest Benign FPR: {rf_metrics['summary']['benign_fpr']*100:.2f}%")
    joblib.dump(rf_clf, os.path.join(SUPERVISED_MODELS_DIR, "supervised_random_forest.joblib"))

    # -------------------------------------------------------------------------
    # 5. Load Existing Benchmarks (XGBoost & HistGBT) for Unified Comparison
    # -------------------------------------------------------------------------
    print("\n[*] Evaluating Existing Benchmarks on Identical Test Partition...")
    xgb_old = joblib.load(os.path.join(PROJECT_ROOT, "models", "role3_corrected", "supervised_xgboost_corrected.joblib"))
    hist_old = joblib.load(os.path.join(PROJECT_ROOT, "models", "role3_corrected", "supervised_histgbt_corrected.joblib"))

    t_start = time.time()
    y_pred_xgb = xgb_old.predict(X_test_base)
    xgb_latency_us = ((time.time() - t_start) / len(X_test_base)) * 1e6
    xgb_metrics = evaluate_cyber_detection_predictions(
        y_true=y_test, y_pred=y_pred_xgb, label_mapping=label_mapping
    )
    xgb_metrics["summary"]["inference_latency_us"] = xgb_latency_us
    xgb_metrics["summary"]["throughput_flows_sec"] = 1e6 / xgb_latency_us

    t_start = time.time()
    y_pred_hist = hist_old.predict(X_test_base)
    hist_latency_us = ((time.time() - t_start) / len(X_test_base)) * 1e6
    hist_metrics = evaluate_cyber_detection_predictions(
        y_true=y_test, y_pred=y_pred_hist, label_mapping=label_mapping
    )
    hist_metrics["summary"]["inference_latency_us"] = hist_latency_us
    hist_metrics["summary"]["throughput_flows_sec"] = 1e6 / hist_latency_us

    # Copy / preserve XGBoost in retrain_v2
    joblib.dump(xgb_old, os.path.join(SUPERVISED_MODELS_DIR, "supervised_xgboost_benchmark.joblib"))
    joblib.dump(hist_old, os.path.join(SUPERVISED_MODELS_DIR, "supervised_histgbt_benchmark.joblib"))

    # -------------------------------------------------------------------------
    # 6. Cross-Day Generalization Matrix (Track B - All 10 Captures)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  EVALUATING TRACK B: CROSS-DAY GENERALIZATION MATRIX (LightGBM)")
    print("=" * 70)
    cross_day_results = []
    files = sorted(glob.glob(os.path.join(CSE_DIR, "*.parquet")))
    for f in files:
        fn = os.path.basename(f)
        day_str = fn.split("_")[0]

        tab_day = pq.read_table(f, columns=baseline_features + ["_Clean_Label"])
        df_day = tab_day.to_pandas()
        df_day[baseline_features] = df_day[baseline_features].fillna(0.0).replace([np.inf, -np.inf], 0.0).astype(np.float32)

        day_benign = df_day[df_day["_Clean_Label"] == "Benign"].head(10_000)
        day_attack = df_day[df_day["_Clean_Label"] != "Benign"].head(10_000)
        day_slice = pd.concat([day_benign, day_attack], ignore_index=True)
        if len(day_slice) == 0: continue

        X_day = day_slice[baseline_features].values
        preds_day = lgb_clf.predict(X_day)

        n_benign = len(day_benign)
        n_attack = len(day_attack)
        fp_day = int((preds_day[:n_benign] != benign_idx).sum()) if n_benign > 0 else 0
        fpr_day = float(fp_day / n_benign) if n_benign > 0 else 0.0
        tp_day = int((preds_day[n_benign:] != benign_idx).sum()) if n_attack > 0 else 0
        rec_day = float(tp_day / n_attack) if n_attack > 0 else 0.0
        attack_types = sorted(list(set(day_attack["_Clean_Label"].unique())))

        print(f"  [{day_str:20}]: Benign FPR={fpr_day*100:5.2f}% ({fp_day}/{n_benign}) | "
              f"Attack Recall={rec_day*100:5.2f}% ({tp_day}/{n_attack}) | Attacks: {attack_types}")

        cross_day_results.append({
            "capture_day": day_str,
            "filename": fn,
            "benign_tested": n_benign,
            "benign_false_positives": fp_day,
            "benign_fpr": fpr_day,
            "attacks_tested": n_attack,
            "attacks_detected": tp_day,
            "attack_recall": rec_day,
            "attack_categories": attack_types
        })

    # -------------------------------------------------------------------------
    # 7. Infiltration Deep Investigation: Threshold Calibration on Validation
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  INFILTRATION INVESTIGATION & VALIDATION THRESHOLD POLICIES")
    print("=" * 70)
    lgb_probs_val = lgb_clf.predict_proba(X_val_base)
    val_operating_points = compute_operating_curve(
        y_true=y_val, y_proba=lgb_probs_val, label_mapping=label_mapping,
        target_fpr_budgets=[0.001, 0.005, 0.010, 0.020, 0.050]
    )

    p_attack_test = 1.0 - lgb_probs_test[:, benign_idx]
    y_test_is_attack = (y_test != benign_idx)

    test_operating_eval = []
    for pt in val_operating_points:
        thresh = pt["calibrated_threshold"]
        test_preds_attack = (p_attack_test >= thresh)
        test_tp = int((test_preds_attack & y_test_is_attack).sum())
        test_fp = int((test_preds_attack & ~y_test_is_attack).sum())
        total_test_benign = int((~y_test_is_attack).sum())
        total_test_attack = int(y_test_is_attack.sum())

        actual_test_fpr = float(test_fp / total_test_benign)
        actual_test_recall = float(test_tp / total_test_attack)
        binary_prec = float(test_tp / (test_tp + test_fp)) if (test_tp + test_fp) > 0 else 0.0
        binary_f1 = float(2 * binary_prec * actual_test_recall / (binary_prec + actual_test_recall)) if (binary_prec + actual_test_recall) > 0 else 0.0

        test_operating_eval.append({
            "target_fpr_budget": pt["target_fpr_budget"],
            "validation_threshold": thresh,
            "validation_fpr": pt["actual_benign_fpr"],
            "validation_recall": pt["attack_recall"],
            "test_fpr": actual_test_fpr,
            "test_recall": actual_test_recall,
            "test_precision": binary_prec,
            "test_f1": binary_f1,
            "test_false_alarms": test_fp,
            "test_attacks_detected": test_tp,
            "test_attacks_missed": total_test_attack - test_tp
        })

    # -------------------------------------------------------------------------
    # 8. Anomaly Detection Tier: Isolation Forest vs. Deep Autoencoder
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  TRAINING & EVALUATING ANOMALY DETECTION TIER (Benign-Only Fitting)")
    print("=" * 70)
    # Fit StandardScaler strictly on pure Benign training data
    benign_train_mask = (y_train == benign_idx)
    X_train_benign = X_train_base[benign_train_mask]
    print(f"[*] Fitting Anomaly StandardScaler on {len(X_train_benign):,} pure Benign training flows...")
    scaler_anom = StandardScaler()
    scaler_anom.fit(X_train_benign)
    joblib.dump(scaler_anom, os.path.join(ANOMALY_MODELS_DIR, "scaler_anomaly.joblib"))

    X_val_scaled = scaler_anom.transform(X_val_base)
    X_test_scaled = scaler_anom.transform(X_test_base)

    # A. Isolation Forest Baseline
    print("[*] Fitting Isolation Forest on pure Benign scaled flows...")
    t_start = time.time()
    iso_forest = IsolationForest(n_estimators=100, max_samples=100_000, contamination=0.01, random_state=42, n_jobs=4)
    iso_forest.fit(scaler_anom.transform(X_train_benign[:100_000]))
    iso_train_time = time.time() - t_start
    print(f"[+] Isolation Forest fitted in {iso_train_time:.2f}s")
    joblib.dump(iso_forest, os.path.join(ANOMALY_MODELS_DIR, "anomaly_isolation_forest.joblib"))

    val_iso_scores = iso_forest.decision_function(X_val_scaled)
    test_iso_scores = iso_forest.decision_function(X_test_scaled)

    # B. PyTorch Deep Reconstruction Autoencoder
    print("[*] Training PyTorch Deep Reconstruction Autoencoder...")
    t_start = time.time()
    ae = DeepAutoencoder(input_dim=len(baseline_features), latent_dim=12)
    criterion = nn.MSELoss()
    optimizer = torch.optim.AdamW(ae.parameters(), lr=1e-3, weight_decay=1e-5)

    train_tensor = torch.tensor(scaler_anom.transform(X_train_benign[:200_000]), dtype=torch.float32)
    batch_size = 512
    ae.train()
    for epoch in range(5):
        perm = torch.randperm(len(train_tensor))
        running_loss = 0.0
        n_batches = 0
        for i in range(0, len(train_tensor), batch_size):
            batch_x = train_tensor[perm[i:i + batch_size]]
            optimizer.zero_grad()
            recon = ae(batch_x)
            loss = criterion(recon, batch_x)
            loss.backward()
            optimizer.step()
            running_loss += loss.item()
            n_batches += 1
        print(f"    Epoch {epoch+1}/5 - Loss: {running_loss/n_batches:.4f}")
    ae_train_time = time.time() - t_start
    ae.eval()
    print(f"[+] PyTorch Autoencoder trained in {ae_train_time:.2f}s")
    torch.save(ae.state_dict(), os.path.join(ANOMALY_MODELS_DIR, "anomaly_deep_autoencoder.pt"))

    # Compute reconstruction errors
    with torch.no_grad():
        t_val = torch.tensor(X_val_scaled, dtype=torch.float32)
        val_ae_mse = ((t_val - ae(t_val)) ** 2).mean(dim=1).numpy()

        t_test = torch.tensor(X_test_scaled, dtype=torch.float32)
        test_ae_mse = ((t_test - ae(t_test)) ** 2).mean(dim=1).numpy()

    # Calibrate Operating Thresholds on Benign Validation Data
    val_benign_mask = (y_val == benign_idx)
    test_benign_mask = (y_test == benign_idx)

    anomaly_eval_points = []
    for budget in [0.001, 0.005, 0.010, 0.020, 0.050]:
        # Autoencoder: Higher MSE = More Anomalous
        thresh_ae = float(np.percentile(val_ae_mse[val_benign_mask], 100.0 * (1.0 - budget)))
        ae_val_fpr = float((val_ae_mse[val_benign_mask] >= thresh_ae).sum() / val_benign_mask.sum())
        ae_test_fpr = float((test_ae_mse[test_benign_mask] >= thresh_ae).sum() / test_benign_mask.sum())
        ae_test_rec = float((test_ae_mse[~test_benign_mask] >= thresh_ae).sum() / (~test_benign_mask).sum())

        # Isolation Forest: Lower decision_function = More Anomalous
        thresh_iso = float(np.percentile(val_iso_scores[val_benign_mask], 100.0 * budget))
        iso_val_fpr = float((val_iso_scores[val_benign_mask] <= thresh_iso).sum() / val_benign_mask.sum())
        iso_test_fpr = float((test_iso_scores[test_benign_mask] <= thresh_iso).sum() / test_benign_mask.sum())
        iso_test_rec = float((test_iso_scores[~test_benign_mask] <= thresh_iso).sum() / (~test_benign_mask).sum())

        anomaly_eval_points.append({
            "target_fpr_budget": budget,
            "autoencoder": {
                "threshold_mse": thresh_ae,
                "validation_fpr": ae_val_fpr,
                "test_fpr": ae_test_fpr,
                "attack_recall": ae_test_rec
            },
            "isolation_forest": {
                "threshold_score": thresh_iso,
                "validation_fpr": iso_val_fpr,
                "test_fpr": iso_test_fpr,
                "attack_recall": iso_test_rec
            }
        })

    # Track C: Unseen-Attack Anomaly Breakdown at 1% FPR Budget
    thresh_ae_1pct = float(np.percentile(val_ae_mse[val_benign_mask], 99.0))
    ae_flags_test = (test_ae_mse >= thresh_ae_1pct)

    unseen_attack_breakdown = {}
    for i, class_name in label_mapping.items():
        if i == benign_idx: continue
        class_mask = (y_test == i)
        sup = int(class_mask.sum())
        det = int((ae_flags_test & class_mask).sum())
        rec = float(det / sup) if sup > 0 else 0.0
        unseen_attack_breakdown[class_name] = {
            "test_support": sup,
            "detected_anomalies": det,
            "zero_day_recall_at_1pct_fpr": rec
        }

    # -------------------------------------------------------------------------
    # 9. Dedicated UNSW-NB15 Benchmark Model (42 Features)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  TRAINING DEDICATED UNSW-NB15 BENCHMARK MODEL (42 Features)")
    print("=" * 70)
    unsw_data = load_unsw_benchmark()
    X_train_unsw = unsw_data["X_train"]
    y_train_unsw = unsw_data["y_train"]
    X_test_unsw = unsw_data["X_test"]
    y_test_unsw = unsw_data["y_test"]

    t_start = time.time()
    unsw_clf = lgb.LGBMClassifier(n_estimators=100, max_depth=8, learning_rate=0.1, random_state=42, n_jobs=4, verbose=-1)
    unsw_clf.fit(X_train_unsw, y_train_unsw)
    unsw_train_time = time.time() - t_start

    preds_unsw = unsw_clf.predict(X_test_unsw)
    unsw_acc = float((preds_unsw == y_test_unsw).mean())
    unsw_tp = int(((preds_unsw == 1) & (y_test_unsw == 1)).sum())
    unsw_fp = int(((preds_unsw == 1) & (y_test_unsw == 0)).sum())
    unsw_fn = int(((preds_unsw == 0) & (y_test_unsw == 1)).sum())
    unsw_tn = int(((preds_unsw == 0) & (y_test_unsw == 0)).sum())
    unsw_rec = float(unsw_tp / (unsw_tp + unsw_fn))
    unsw_prec = float(unsw_tp / (unsw_tp + unsw_fp))
    unsw_f1 = float(2 * unsw_prec * unsw_rec / (unsw_prec + unsw_rec))
    unsw_fpr = float(unsw_fp / (unsw_fp + unsw_tn))

    print(f"    UNSW-NB15 Accuracy     : {unsw_acc*100:.2f}%")
    print(f"    UNSW-NB15 F1-Score     : {unsw_f1:.4f}")
    print(f"    UNSW-NB15 Attack Recall: {unsw_rec*100:.2f}%")
    print(f"    UNSW-NB15 Benign FPR   : {unsw_fpr*100:.2f}%")
    joblib.dump(unsw_clf, os.path.join(SUPERVISED_MODELS_DIR, "supervised_unsw_nb15.joblib"))

    # -------------------------------------------------------------------------
    # 10. Comprehensive Latency & Throughput Benchmark
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  MEASURING COMPREHENSIVE INFERENCE LATENCY & THROUGHPUT BENCHMARK")
    print("=" * 70)
    batch_sizes = [1, 64, 256, 1024, 10000]
    latency_results = {"supervised_lightgbm": {}, "supervised_xgboost": {}, "deep_autoencoder": {}, "preprocessing": {}}

    # Preprocessing timing
    sample_df = test_df.head(1000)[baseline_features]
    t_pre_start = time.time()
    for _ in range(50):
        _ = sample_df.fillna(0.0).values.astype(np.float32)
    pre_latency_us = ((time.time() - t_pre_start) / (50 * 1000)) * 1e6
    latency_results["preprocessing"]["per_flow_latency_us"] = pre_latency_us

    # Model timings across batch sizes
    for bs in batch_sizes:
        batch_X = X_test_base[:bs]
        
        # LightGBM
        t_start = time.time()
        iters = max(10, 5000 // bs)
        for _ in range(iters):
            _ = lgb_clf.predict(batch_X)
        lgb_batch_latency = ((time.time() - t_start) / (iters * bs)) * 1e6
        latency_results["supervised_lightgbm"][f"batch_{bs}"] = {
            "per_sample_us": lgb_batch_latency,
            "throughput_fps": 1e6 / lgb_batch_latency
        }

        # XGBoost
        t_start = time.time()
        for _ in range(iters):
            _ = xgb_old.predict(batch_X)
        xgb_batch_latency = ((time.time() - t_start) / (iters * bs)) * 1e6
        latency_results["supervised_xgboost"][f"batch_{bs}"] = {
            "per_sample_us": xgb_batch_latency,
            "throughput_fps": 1e6 / xgb_batch_latency
        }

        # Autoencoder
        t_start = time.time()
        batch_tensor = torch.tensor(X_test_scaled[:bs], dtype=torch.float32)
        with torch.no_grad():
            for _ in range(iters):
                _ = ae(batch_tensor)
        ae_batch_latency = ((time.time() - t_start) / (iters * bs)) * 1e6
        latency_results["deep_autoencoder"][f"batch_{bs}"] = {
            "per_sample_us": ae_batch_latency,
            "throughput_fps": 1e6 / ae_batch_latency
        }

    with open(os.path.join(REPORTS_DIR, "latency_benchmark.json"), "w") as fp:
        json.dump(latency_results, fp, indent=2)

    # -------------------------------------------------------------------------
    # 11. Save Structured JSON Deliverables
    # -------------------------------------------------------------------------
    print("\n[*] Exporting structured machine-readable deliverables...")
    supervised_payload = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "primary_candidate": "LightGBM 4.7.0",
            "features_evaluated": 77,
            "classes_evaluated": len(label_mapping),
            "test_flows_count": len(test_df)
        },
        "lightgbm_primary_candidate": lgb_metrics,
        "lightgbm_port_ablation": lgb_port_metrics,
        "xgboost_benchmark": xgb_metrics,
        "histgbt_benchmark": hist_metrics,
        "random_forest_baseline": rf_metrics,
        "cross_day_generalization_matrix": cross_day_results,
        "validation_calibrated_operating_points": test_operating_eval,
        "unsw_nb15_benchmark": {
            "accuracy": unsw_acc,
            "precision": unsw_prec,
            "recall": unsw_rec,
            "f1_score": unsw_f1,
            "benign_fpr": unsw_fpr,
            "train_samples": len(X_train_unsw),
            "test_samples": len(X_test_unsw)
        }
    }
    with open(os.path.join(REPORTS_DIR, "supervised_metrics.json"), "w") as fp:
        json.dump(supervised_payload, fp, indent=2)

    anomaly_payload = {
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "benign_train_samples": len(X_train_benign),
            "models": ["PyTorch Deep Autoencoder (77->48->24->12->24->48->77)", "Isolation Forest"]
        },
        "operating_points_comparison": anomaly_eval_points,
        "unseen_attack_breakdown_1pct_fpr": unseen_attack_breakdown
    }
    with open(os.path.join(REPORTS_DIR, "anomaly_metrics.json"), "w") as fp:
        json.dump(anomaly_payload, fp, indent=2)

    print("\n" + "=" * 80)
    print("  ROLE 3 RETRAINING V2 COMPLETE — ALL ARTIFACTS SAVED SUCCESSFULLY")
    print("=" * 80)


if __name__ == "__main__":
    main()
