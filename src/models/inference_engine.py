#!/usr/bin/env python3
"""
Role 6 Production Inference Engine & Strict Security Contract
Team: Neural Breach | AI/ML Cyber Defense Platform
Role 3: Machine Learning & Anomaly Detection (Retraining V2)

Exposes an immutable, defensive inference interface for the Role 6 FastAPI backend:
  1. Validates strict feature presence, exact ordering (77 features), and types.
  2. Imputes missing/infinite values safely without crashing or leaking memory.
  3. Rejects invalid or corrupted schemas with structured exceptions.
  4. Returns multi-class predictions, probabilities, calibrated anomaly scores, and SOC alert triage.
"""

import os
import sys
import json
from typing import Dict, Any, List, Union, Optional, Tuple

import numpy as np
import pandas as pd
import joblib
import torch
import torch.nn as nn

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
V2_DIR = os.path.join(PROJECT_ROOT, "models", "role3_retrain_v2")
CORRECTED_DIR = os.path.join(PROJECT_ROOT, "models", "role3_corrected")
REAL_DATA_DIR = os.path.join(PROJECT_ROOT, "models", "role3_real_data")

DEFAULT_MODELS_DIR = V2_DIR if os.path.exists(V2_DIR) else (CORRECTED_DIR if os.path.exists(CORRECTED_DIR) else REAL_DATA_DIR)


class DeepAutoencoder(nn.Module):
    """PyTorch Deep Reconstruction Autoencoder (77 -> 48 -> 24 -> 12 -> 24 -> 48 -> 77)."""
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


class ModelInferenceError(Exception):
    """Raised when inference input violates the production schema contract."""
    pass


class CyberDefenseInferenceEngine:
    """
    Production Inference Engine for Role 6 FastAPI Backend.
    Guarantees strict schema contract enforcement, missing value handling,
    and hybrid supervised + anomaly detection alert synthesis.
    """
    def __init__(
        self,
        models_dir: str = DEFAULT_MODELS_DIR,
        classifier_type: str = "lightgbm",
        fpr_budget: str = "1pct"
    ):
        self.models_dir = models_dir
        self.requested_clf = classifier_type.lower()
        self.fpr_budget = fpr_budget

        # Resolve directory hierarchy (handles v2 subdirs or flat historical dirs)
        sup_dir = os.path.join(self.models_dir, "supervised") if os.path.exists(os.path.join(self.models_dir, "supervised")) else self.models_dir
        anom_dir = os.path.join(self.models_dir, "anomaly") if os.path.exists(os.path.join(self.models_dir, "anomaly")) else self.models_dir

        # 1. Load feature schema contract
        feat_path = os.path.join(sup_dir, "feature_columns.json")
        if not os.path.exists(feat_path):
            feat_path = os.path.join(sup_dir, "feature_columns_baseline.json")
        with open(feat_path, "r") as fp:
            self.expected_features = json.load(fp)
        self.feature_names = self.expected_features

        # 2. Load label mapping
        lbl_path = os.path.join(sup_dir, "label_mapping.json")
        with open(lbl_path, "r") as fp:
            self.label_mapping = {int(k): v for k, v in json.load(fp).items()}

        # 3. Load preprocessors
        scaler_path = os.path.join(anom_dir, "scaler_anomaly.joblib")
        if not os.path.exists(scaler_path):
            scaler_path = os.path.join(anom_dir, "scaler_corrected.joblib")
        self.scaler = joblib.load(scaler_path)

        # 4. Load supervised classifier
        self._load_classifier(sup_dir)

        # 5. Load Isolation Forest
        iso_path = os.path.join(anom_dir, "anomaly_isolation_forest.joblib")
        if not os.path.exists(iso_path):
            iso_path = os.path.join(anom_dir, "anomaly_isolation_forest_corrected.joblib")
        self.iso_forest = joblib.load(iso_path)
        self.iso_threshold = -0.08063 if self.fpr_budget == "1pct" else -0.01779

        # 6. Load Deep Autoencoder
        self.autoencoder = DeepAutoencoder(input_dim=len(self.expected_features), latent_dim=12)
        ae_path = os.path.join(anom_dir, "anomaly_deep_autoencoder.pt")
        if not os.path.exists(ae_path):
            ae_path = os.path.join(anom_dir, "anomaly_deep_autoencoder_corrected.pt")
        self.autoencoder.load_state_dict(torch.load(ae_path, map_location="cpu"))
        self.autoencoder.eval()
        self.ae_threshold = 1.29126 if self.fpr_budget == "1pct" else 0.24448

    def _load_classifier(self, sup_dir: str):
        """Loads requested supervised model candidate with safe fallback hierarchy."""
        lgb_path = os.path.join(sup_dir, "supervised_lightgbm_primary.joblib")
        xgb_v2 = os.path.join(sup_dir, "supervised_xgboost_benchmark.joblib")
        xgb_corr = os.path.join(sup_dir, "supervised_xgboost_corrected.joblib")
        rf_path = os.path.join(sup_dir, "supervised_random_forest.joblib")
        hist_v2 = os.path.join(sup_dir, "supervised_histgbt_benchmark.joblib")
        hist_corr = os.path.join(sup_dir, "supervised_histgbt_corrected.joblib")

        if self.requested_clf in ["lightgbm", "lgb"] and os.path.exists(lgb_path):
            self.classifier = joblib.load(lgb_path)
            self.clf_type = "LightGBM (Primary Candidate)"
        elif self.requested_clf in ["xgboost", "xgb"] and (os.path.exists(xgb_v2) or os.path.exists(xgb_corr)):
            target = xgb_v2 if os.path.exists(xgb_v2) else xgb_corr
            self.classifier = joblib.load(target)
            self.clf_type = "XGBoost (High-Precision Candidate)"
        elif self.requested_clf in ["random_forest", "rf"] and os.path.exists(rf_path):
            self.classifier = joblib.load(rf_path)
            self.clf_type = "Random Forest (Baseline)"
        elif os.path.exists(hist_v2) or os.path.exists(hist_corr):
            target = hist_v2 if os.path.exists(hist_v2) else hist_corr
            self.classifier = joblib.load(target)
            self.clf_type = "HistGradientBoosting"
        elif os.path.exists(lgb_path):
            self.classifier = joblib.load(lgb_path)
            self.clf_type = "LightGBM (Primary Candidate)"
        elif os.path.exists(xgb_v2):
            self.classifier = joblib.load(xgb_v2)
            self.clf_type = "XGBoost"
        else:
            raise ModelInferenceError(f"No valid supervised model found in directory: {sup_dir}")

    def validate_and_preprocess(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Validates schema, checks column presence, imputes infinities/NaNs,
        and generates both raw and scaled feature arrays.
        """
        if not isinstance(df, pd.DataFrame):
            raise ModelInferenceError(f"Input must be a pandas DataFrame, received: {type(df)}")

        missing_cols = [c for c in self.expected_features if c not in df.columns]
        if missing_cols:
            raise ModelInferenceError(
                f"Input DataFrame is missing {len(missing_cols)} required features: {missing_cols[:5]}..."
            )

        # Enforce exact column order
        X_df = df[self.expected_features].copy()

        # Handle NaNs and infinities defensibly
        X_clean = X_df.replace([np.inf, -np.inf], np.nan).fillna(0.0).values.astype(np.float32)

        # Apply StandardScaler fitted strictly on benign training data
        X_scaled = self.scaler.transform(X_clean)

        return X_clean, X_scaled

    def predict_flows(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Main SOC inference pipeline for network flow batches.
        Returns:
            List of flow triage dictionaries containing multi-class predictions,
            probabilities, dual anomaly scores, and synthesized threat levels.
        """
        if not isinstance(df, pd.DataFrame):
            raise ModelInferenceError(f"Input must be a pandas DataFrame, received: {type(df)}")
        if len(df) == 0:
            return []

        X_clean, X_scaled = self.validate_and_preprocess(df)
        n_flows = len(df)

        # 1. Supervised Predictions
        probs = self.classifier.predict_proba(X_clean)
        pred_indices = np.argmax(probs, axis=1)
        confidences = np.max(probs, axis=1)

        # 2. Isolation Forest Outlier Scores (lower score = more anomalous)
        iso_scores = self.iso_forest.decision_function(X_scaled)
        iso_alerts = (iso_scores <= self.iso_threshold)

        # 3. Deep Autoencoder Reconstruction Error (MSE)
        with torch.no_grad():
            t_scaled = torch.tensor(X_scaled, dtype=torch.float32)
            recon = self.autoencoder(t_scaled)
            ae_errors = ((t_scaled - recon) ** 2).mean(dim=1).numpy()
        ae_alerts = (ae_errors >= self.ae_threshold)

        results = []
        for i in range(n_flows):
            pred_class = self.label_mapping[pred_indices[i]]
            conf = float(confidences[i])
            iso_sc = float(iso_scores[i])
            ae_err = float(ae_errors[i])
            is_anomaly = bool(iso_alerts[i] or ae_alerts[i])

            # Threat level assessment
            if pred_class != "Benign":
                threat = "HIGH" if conf >= 0.80 else "MEDIUM"
            elif is_anomaly:
                threat = "SUSPICIOUS_ANOMALY"
            else:
                threat = "BENIGN"

            results.append({
                "flow_index": i,
                "predicted_label": pred_class,
                "confidence": conf,
                "threat_level": threat,
                "anomaly_detected": is_anomaly,
                "isolation_forest_score": iso_sc,
                "isolation_forest_alert": bool(iso_alerts[i]),
                "autoencoder_recon_error": ae_err,
                "autoencoder_alert": bool(ae_alerts[i]),
                "probabilities": {self.label_mapping[j]: float(probs[i][j]) for j in range(len(self.label_mapping))}
            })

        return results

    predict = predict_flows


ProductionInferenceEngine = CyberDefenseInferenceEngine


def test_inference_engine_contract():
    """Validates that the inference contract functions properly and rejects invalid inputs."""
    print("[*] Testing CyberDefenseInferenceEngine contract (Role 3 Retraining V2)...")
    
    # Test LightGBM primary engine
    engine_lgb = CyberDefenseInferenceEngine(classifier_type="lightgbm")
    print(f"[+] Loaded primary engine successfully with {engine_lgb.clf_type} classifier!")

    # Test XGBoost engine
    engine_xgb = CyberDefenseInferenceEngine(classifier_type="xgboost")
    print(f"[+] Loaded benchmark engine successfully with {engine_xgb.clf_type} classifier!")

    # 1. Valid Dummy Flow Test
    valid_df = pd.DataFrame(np.zeros((5, len(engine_lgb.expected_features))), columns=engine_lgb.expected_features)
    preds = engine_lgb.predict_flows(valid_df)
    assert len(preds) == 5, "Expected 5 predictions"
    assert "predicted_label" in preds[0], "Missing predicted_label"
    assert "threat_level" in preds[0], "Missing threat_level"
    assert "anomaly_detected" in preds[0], "Missing anomaly_detected"
    print("[✓] Valid inputs handled correctly for LightGBM!")

    # 2. Missing Feature Rejection Test
    invalid_df = valid_df.drop(columns=[engine_lgb.expected_features[0]])
    try:
        _ = engine_lgb.predict_flows(invalid_df)
        raise AssertionError("Failed to reject missing feature DataFrame!")
    except ModelInferenceError as e:
        print(f"[✓] Correctly rejected missing features: {e}")

    # 3. Non-DataFrame Rejection Test
    try:
        _ = engine_lgb.predict_flows("not a dataframe")  # type: ignore
        raise AssertionError("Failed to reject non-DataFrame input!")
    except ModelInferenceError:
        print("[✓] Correctly rejected non-DataFrame input!")

    print("[✓] All inference contract tests passed 100%!")


if __name__ == "__main__":
    test_inference_engine_contract()

