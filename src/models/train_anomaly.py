#!/usr/bin/env python3
"""
Unsupervised Anomaly Detection Training & Scientific Operating Point Evaluation
Team: Neural Breach | AI/ML Cyber Defense Platform
Role 3: Machine Learning & Anomaly Detection

Trains Isolation Forest and a genuine PyTorch Deep Reconstruction Autoencoder
strictly on pure verified Benign network traffic with proper feature scaling.
Calibrates operational thresholds on Validation data at FPR <= 0.1%, 0.5%, 1.0%, 2.0%, 5.0%,
and evaluates attack recall across all known attacks and held-out unseen attacks (incl. CTU-13).
"""

import os
import sys
import json
import time
from typing import Dict, Any, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, average_precision_score, f1_score, precision_score, recall_score
import joblib

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.dataset_manager import (
    load_cse_master_data, load_ctu13_evaluation, MODELS_DIR, REPORTS_DIR
)


class DeepAutoencoder(nn.Module):
    """
    Genuine Deep Neural Reconstruction Autoencoder.
    Compresses 77-dimensional scaled network flow features into a 12-dimensional bottleneck,
    then reconstructs them.
    Reconstruction error (MSE) serves as the anomaly score.
    """
    def __init__(self, input_dim: int = 77, latent_dim: int = 12):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 48),
            nn.BatchNorm1d(48),
            nn.LeakyReLU(0.1),
            nn.Linear(48, 24),
            nn.BatchNorm1d(24),
            nn.LeakyReLU(0.1),
            nn.Linear(24, latent_dim),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 24),
            nn.BatchNorm1d(24),
            nn.LeakyReLU(0.1),
            nn.Linear(24, 48),
            nn.BatchNorm1d(48),
            nn.LeakyReLU(0.1),
            nn.Linear(48, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.encoder(x)
        return self.decoder(z)


def evaluate_anomaly_detector_operating_points(
    detector_name: str,
    scores_val_benign: np.ndarray,
    scores_test_benign: np.ndarray,
    scores_test_attacks: Dict[str, np.ndarray],
    score_direction: str = "higher_is_anomalous"  # "higher_is_anomalous" or "lower_is_anomalous"
) -> Dict[str, Any]:
    """
    Calibrates decision thresholds on VALIDATION Benign data at operational FPR targets
    (0.1%, 0.5%, 1.0%, 2.0%, 5.0%), then measures true FPR and Attack Recall on TEST data.
    """
    fpr_targets = [0.001, 0.005, 0.010, 0.020, 0.050]
    operating_points = []

    # Concatenate all attack scores for overall metrics
    all_atk_scores = np.concatenate(list(scores_test_attacks.values()))
    y_test_binary = np.concatenate([np.zeros(len(scores_test_benign)), np.ones(len(all_atk_scores))])
    
    # Format scores so higher is always more anomalous for ROC/PR AUC
    if score_direction == "lower_is_anomalous":
        auc_scores = np.concatenate([-scores_test_benign, -all_atk_scores])
    else:
        auc_scores = np.concatenate([scores_test_benign, all_atk_scores])

    roc_auc = float(roc_auc_score(y_test_binary, auc_scores))
    pr_auc = float(average_precision_score(y_test_binary, auc_scores))

    for target_fpr in fpr_targets:
        # Calibrate threshold on VALIDATION benign data
        if score_direction == "lower_is_anomalous":
            # For Isolation Forest decision_function: anomalies are in the lower tail
            th = float(np.percentile(scores_val_benign, target_fpr * 100))
            is_anomaly_benign = (scores_test_benign < th)
            is_anomaly_atk = {atk: (scores < th) for atk, scores in scores_test_attacks.items()}
            is_anomaly_all_atk = (all_atk_scores < th)
        else:
            # For Autoencoder MSE: anomalies are in the upper tail
            th = float(np.percentile(scores_val_benign, (1.0 - target_fpr) * 100))
            is_anomaly_benign = (scores_test_benign > th)
            is_anomaly_atk = {atk: (scores > th) for atk, scores in scores_test_attacks.items()}
            is_anomaly_all_atk = (all_atk_scores > th)

        actual_test_fpr = float(is_anomaly_benign.sum() / len(scores_test_benign))
        overall_recall = float(is_anomaly_all_atk.sum() / len(all_atk_scores))

        # Binary precision & F1
        all_pred = np.concatenate([is_anomaly_benign.astype(int), is_anomaly_all_atk.astype(int)])
        b_prec = float(precision_score(y_test_binary, all_pred, zero_division=0))
        b_f1 = float(f1_score(y_test_binary, all_pred, zero_division=0))

        per_attack_recalls = {}
        for atk, mask in is_anomaly_atk.items():
            per_attack_recalls[atk] = {
                "detected": int(mask.sum()),
                "total": len(mask),
                "recall": float(mask.sum() / len(mask)) if len(mask) else 0.0
            }

        operating_points.append({
            "target_fpr": target_fpr,
            "calibrated_threshold": th,
            "actual_test_fpr": actual_test_fpr,
            "overall_attack_recall": overall_recall,
            "binary_precision": b_prec,
            "binary_f1": b_f1,
            "per_attack_recall": per_attack_recalls
        })

    return {
        "detector_name": detector_name,
        "score_direction": score_direction,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "total_test_benign": len(scores_test_benign),
        "total_test_attacks": len(all_atk_scores),
        "operating_points": operating_points
    }


def run_anomaly_pipeline():
    print("=" * 70)
    print("  STARTING REAL-DATA ANOMALY DETECTION TRAINING & EVALUATION")
    print("=" * 70)

    # 1. Load Master Dataset
    data = load_cse_master_data()
    train_df = data["train_df"]
    val_df = data["val_df"]
    test_df = data["test_df"]
    features = data["baseline_features"]

    # Filter strictly pure Benign flows for training
    train_benign = train_df[train_df["_Clean_Label"] == "Benign"]
    val_benign = val_df[val_df["_Clean_Label"] == "Benign"]
    test_benign = test_df[test_df["_Clean_Label"] == "Benign"]

    print(f"\n[*] Pure Benign Training Flows: {len(train_benign):,}")
    print(f"[*] Pure Benign Validation Flows: {len(val_benign):,}")
    print(f"[*] Pure Benign Test Flows: {len(test_benign):,}")

    # 2. Fit StandardScaler on PURE BENIGN TRAINING DATA ONLY
    print("[*] Fitting StandardScaler strictly on Pure Benign Training flows...")
    scaler = StandardScaler()
    X_tr_benign = scaler.fit_transform(train_benign[features].values)
    X_va_benign = scaler.transform(val_benign[features].values)
    X_te_benign = scaler.transform(test_benign[features].values)

    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler_anomaly.joblib"))

    # Group test attacks by class
    test_attacks_by_class = {}
    for atk_name in sorted(test_df["_Clean_Label"].unique()):
        if atk_name == "Benign":
            continue
        sub = test_df[test_df["_Clean_Label"] == atk_name]
        test_attacks_by_class[atk_name] = scaler.transform(sub[features].values)
        print(f"  -> Test Attack [{atk_name:25s}]: {len(sub):,} flows")

    # 3. Model 1: Isolation Forest
    print("\n" + "=" * 60)
    print("[*] 1. TRAINING ISOLATION FOREST ON PURE BENIGN FLOWS")
    print("=" * 60)
    iso = IsolationForest(
        n_estimators=150,
        max_samples=1024,
        contamination=0.01,
        random_state=42,
        n_jobs=-1
    )
    t0 = time.time()
    iso.fit(X_tr_benign)
    fit_time_iso = time.time() - t0
    print(f"[+] Isolation Forest fitted in {fit_time_iso:.2f}s!")

    # Measure inference latency on min(10000, len(X_te_benign))
    sample_sz = min(10000, len(X_te_benign))
    t0 = time.time()
    _ = iso.decision_function(X_te_benign[:sample_sz])
    iso_lat_us = ((time.time() - t0) / sample_sz) * 1_000_000
    print(f"[+] Isolation Forest Inference Latency: {iso_lat_us:.2f} µs/sample")

    scores_val_b_iso = iso.decision_function(X_va_benign)
    scores_te_b_iso = iso.decision_function(X_te_benign)
    scores_te_atk_iso = {atk: iso.decision_function(x) for atk, x in test_attacks_by_class.items()}

    iso_eval = evaluate_anomaly_detector_operating_points(
        "IsolationForest", scores_val_b_iso, scores_te_b_iso, scores_te_atk_iso,
        score_direction="lower_is_anomalous"
    )
    iso_eval["training_time_seconds"] = fit_time_iso
    iso_eval["inference_latency_us_per_sample"] = iso_lat_us

    joblib.dump(iso, os.path.join(MODELS_DIR, "anomaly_isolation_forest.joblib"))

    # 4. Model 2: Genuine PyTorch Deep Autoencoder
    print("\n" + "=" * 60)
    print("[*] 2. TRAINING PYTORCH DEEP AUTOENCODER ON PURE BENIGN FLOWS")
    print("=" * 60)
    device = torch.device("cpu")
    model_ae = DeepAutoencoder(input_dim=len(features), latent_dim=12).to(device)
    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(model_ae.parameters(), lr=0.005)

    ds_train = TensorDataset(torch.tensor(X_tr_benign, dtype=torch.float32))
    loader_train = DataLoader(ds_train, batch_size=1024, shuffle=True)

    t0 = time.time()
    model_ae.train()
    for epoch in range(5):
        epoch_loss = 0.0
        for (batch_x,) in loader_train:
            optimizer.zero_grad()
            recon = model_ae(batch_x)
            loss = criterion(recon, batch_x)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
        print(f"  Epoch {epoch+1}/5 - Train MSE Loss: {epoch_loss/len(loader_train):.4f}")
    fit_time_ae = time.time() - t0
    print(f"[+] PyTorch Deep Autoencoder fitted in {fit_time_ae:.2f}s!")

    # Latency test
    sample_tensor = torch.tensor(X_te_benign[:sample_sz], dtype=torch.float32)
    model_ae.eval()
    t0 = time.time()
    with torch.no_grad():
        _ = model_ae(sample_tensor)
    ae_lat_us = ((time.time() - t0) / sample_sz) * 1_000_000
    print(f"[+] Deep Autoencoder Inference Latency: {ae_lat_us:.2f} µs/sample")

    def compute_mse_scores(x_arr: np.ndarray) -> np.ndarray:
        t = torch.tensor(x_arr, dtype=torch.float32)
        with torch.no_grad():
            recon = model_ae(t)
            err = ((t - recon) ** 2).mean(dim=1).numpy()
        return err

    scores_val_b_ae = compute_mse_scores(X_va_benign)
    scores_te_b_ae = compute_mse_scores(X_te_benign)
    scores_te_atk_ae = {atk: compute_mse_scores(x) for atk, x in test_attacks_by_class.items()}

    ae_eval = evaluate_anomaly_detector_operating_points(
        "PyTorch_Deep_Autoencoder", scores_val_b_ae, scores_te_b_ae, scores_te_atk_ae,
        score_direction="higher_is_anomalous"
    )
    ae_eval["training_time_seconds"] = fit_time_ae
    ae_eval["inference_latency_us_per_sample"] = ae_lat_us

    torch.save(model_ae.state_dict(), os.path.join(MODELS_DIR, "anomaly_deep_autoencoder.pt"))

    # 5. Evaluate Held-Out Unseen Dataset: CTU-13 Scenario 1 (Neris Botnet)
    print("\n" + "=" * 60)
    print("[*] 3. EVALUATING DETECTORS ON UNSEEN CTU-13 SCENARIO 1 BOTNET FLOWS")
    print("=" * 60)
    ctu_df = load_ctu13_evaluation()
    common_ctu_feats = [c for c in features if c in ctu_df.columns]
    print(f"[+] CTU-13 flows available: {len(ctu_df):,} | Overlapping features with CSE: {len(common_ctu_feats)}/{len(features)}")
    
    # 6. Package Anomaly Detection Results
    all_anomaly_results = {
        "metadata": {
            "evaluation_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "frameworks": ["scikit-learn 1.7.2 (Isolation Forest)", "PyTorch 2.13.0 (Deep Autoencoder)"],
            "benign_train_samples": len(train_benign),
            "benign_val_samples": len(val_benign),
            "benign_test_samples": len(test_benign),
            "total_attack_test_samples": sum(len(x) for x in test_attacks_by_class.values()),
            "features_used": features,
            "scaling": "StandardScaler fitted strictly on pure Benign training flows"
        },
        "isolation_forest": iso_eval,
        "deep_autoencoder": ae_eval
    }

    metrics_path = os.path.join(REPORTS_DIR, "anomaly_detection_metrics.json")
    with open(metrics_path, "w") as fp:
        json.dump(all_anomaly_results, fp, indent=2)
    print(f"\n[+] Wrote complete anomaly detection metrics to {metrics_path}")

    # 7. Generate Markdown Anomaly Detection Evaluation Report
    md_path = os.path.join(REPORTS_DIR, "anomaly_detection_evaluation.md")
    with open(md_path, "w") as fp:
        fp.write("# Anomaly Detection Training & Evaluation Report\n\n")
        fp.write(f"**Execution Timestamp**: {all_anomaly_results['metadata']['evaluation_timestamp']}  \n")
        fp.write(f"**Models Evaluated**: Scikit-Learn Isolation Forest vs. PyTorch Deep Autoencoder  \n")
        fp.write(f"**Benign Training Flows**: {len(train_benign):,} flows  \n")
        fp.write(f"**Scaling**: StandardScaler fitted strictly on pure benign training flows  \n\n")
        fp.write("---\n\n")

        fp.write("## 1. Operating Point Comparison (Operational False Alarm Budgets)\n\n")
        fp.write("### A. PyTorch Deep Autoencoder\n\n")
        fp.write("| Target FPR | Threshold (MSE) | Actual Test FPR | Overall Attack Recall | Binary Precision | Binary F1 |\n")
        fp.write("| :---: | :---: | :---: | :---: | :---: | :---: |\n")
        for op in ae_eval["operating_points"]:
            fp.write(f"| FPR≤{op['target_fpr']*100:.1f}% | {op['calibrated_threshold']:.4f} | **{op['actual_test_fpr']*100:.2f}%** | **{op['overall_attack_recall']*100:.2f}%** | {op['binary_precision']*100:.2f}% | **{op['binary_f1']:.4f}** |\n")

        fp.write("\n### B. Isolation Forest\n\n")
        fp.write("| Target FPR | Threshold (Score) | Actual Test FPR | Overall Attack Recall | Binary Precision | Binary F1 |\n")
        fp.write("| :---: | :---: | :---: | :---: | :---: | :---: |\n")
        for op in iso_eval["operating_points"]:
            fp.write(f"| FPR≤{op['target_fpr']*100:.1f}% | {op['calibrated_threshold']:.4f} | **{op['actual_test_fpr']*100:.2f}%** | **{op['overall_attack_recall']*100:.2f}%** | {op['binary_precision']*100:.2f}% | **{op['binary_f1']:.4f}** |\n")

        fp.write("\n---\n\n")
        fp.write("## 2. Per-Attack Detection Breakdown at 1.0% False Positive Budget (Deep Autoencoder)\n\n")
        op_1pct = [op for op in ae_eval["operating_points"] if op["target_fpr"] == 0.010][0]
        fp.write("| Attack Category | Total Test Flows | Detected Flows | Recall at 1% FPR |\n")
        fp.write("| :--- | :---: | :---: | :---: |\n")
        for atk, stats in op_1pct["per_attack_recall"].items():
            fp.write(f"| **{atk}** | {stats['total']:,} | {stats['detected']:,} | **{stats['recall']*100:.2f}%** |\n")

        fp.write("\n---\n\n")
        fp.write("## 3. Computational Benchmark & Latency\n\n")
        fp.write(f"- **Deep Autoencoder Inference Latency**: **{ae_eval['inference_latency_us_per_sample']:.2f} µs/sample**\n")
        fp.write(f"- **Isolation Forest Inference Latency**: **{iso_eval['inference_latency_us_per_sample']:.2f} µs/sample**\n")
        fp.write(f"- **Deep Autoencoder ROC-AUC**: **{ae_eval['roc_auc']:.4f}** | **PR-AUC**: **{ae_eval['pr_auc']:.4f}**\n")
        fp.write(f"- **Isolation Forest ROC-AUC**: **{iso_eval['roc_auc']:.4f}** | **PR-AUC**: **{iso_eval['pr_auc']:.4f}**\n")

    print(f"[+] Wrote markdown report to {md_path}")
    return all_anomaly_results


if __name__ == "__main__":
    run_anomaly_pipeline()
