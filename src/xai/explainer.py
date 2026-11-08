#!/usr/bin/env python3
"""
Explainable AI (XAI) Engine for Network Threat Detection
Team Neural Breach — Role 5: XAI & Threat Intelligence

Implements:
  1. SHAP TreeExplainer for fast, exact Shapley values on tree ensembles (LightGBM/XGBoost).
  2. LIME TabularExplainer for local surrogate model explanations.
  3. Autoencoder Reconstruction Attribution for zero-day/unsupervised anomaly decomposition.
  4. Domain-aware cybersecurity interpretation engine mapping mathematical feature importances
     to concrete network security phenomena (flag anomalies, packet asymmetry, timing dilation).
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
import shap
import lime
import lime.lime_tabular
import torch

logger = logging.getLogger("neural_breach.xai.explainer")

# Knowledge base linking network features to cybersecurity interpretations
FEATURE_INTERPRETATION_RULES = {
    "Flow Duration": {
        "high": "Prolonged flow duration indicative of connection-holding exhaustion (Slowloris/GoldenEye) or volumetric flood.",
        "low": "Extremely brief connection duration characteristic of rapid port scanning or automated brute-force probing."
    },
    "Tot Fwd Pkts": {
        "high": "High forward packet volume sent toward target without proportional dialogue, common in unidirectional packet floods.",
        "low": "Minimal forward packet exchange consistent with stealth probing or single-packet reconnaissance."
    },
    "Tot Bwd Pkts": {
        "low": "Severe response deficit (zero/near-zero backward packets) indicates server non-responsiveness, dropping, or one-way flood.",
        "high": "High return packet volume reflecting heavy data exfiltration or intensive server error replies."
    },
    "Flow Byts/s": {
        "high": "Massive byte transmission rate indicative of high-throughput denial of service (e.g. HOIC or UDP flood).",
        "low": "Low byte velocity characteristic of 'low-and-slow' resource starvation tactics."
    },
    "Flow Pkts/s": {
        "high": "Extremely high packet frequency exhausting router/state-table connection tracking limits.",
        "low": "Sub-normal packet cadence typical of stealth evasion and timing dilation."
    },
    "SYN Flag Cnt": {
        "high": "Elevated SYN flag assertions indicating TCP handshake flooding or distributed scanning probes.",
        "low": "Absence of standard initial handshakes or non-TCP protocol flow."
    },
    "ACK Flag Cnt": {
        "high": "High ACK flag assertions indicative of ACK reflection/exhaustion attacks or continuous session streaming.",
        "low": "Lack of ACK confirmations indicating unanswered connection attempts."
    },
    "RST Flag Cnt": {
        "high": "Frequent connection resets signalling aborted connections, service crashes, or port knock rejections.",
        "low": "Normal graceful or unreset connection lifecycle."
    },
    "PSH Flag Cnt": {
        "high": "Intensive PSH flag usage forcing immediate TCP buffer flush to the application layer, common in HTTP/L7 attacks.",
        "low": "Standard buffered socket transmissions."
    },
    "Init Fwd Win Byts": {
        "low": "Near-zero forward initial TCP window size indicates handcrafted raw sockets or severe client buffer starvation.",
        "high": "Oversized TCP window advertised by client trying to ingest or burst maximum stream capacity."
    },
    "Init Bwd Win Byts": {
        "low": "Target host returned zero/near-zero window, indicating target socket buffer saturation and denial of service.",
        "high": "Standard or expanded receiver buffer space."
    },
    "Bwd Pkt Len Std": {
        "high": "Wide variation in response packet sizes, reflecting heterogeneous server responses or payload exfiltration.",
        "low": "Uniform response sizes typical of standardized automated daemon replies (e.g. SSH banner drops or HTTP 404s)."
    },
    "Flow IAT Mean": {
        "high": "Prolonged inter-arrival intervals indicating deliberate timing delays to evade signature-based threshold alerts.",
        "low": "Ultra-low inter-arrival latency indicating automated high-concurrency attack tooling."
    },
    "Protocol": {
        "high": "Transport protocol identifier (e.g., Protocol 17 UDP or Protocol 6 TCP).",
        "low": "Low-numbered network transport protocol (e.g. ICMP or raw IP)."
    }
}


class NetworkFlowExplainer:
    """
    Explainable AI engine providing SHAP, LIME, and Autoencoder feature attribution
    for the Neural Breach Cyber Defense Platform.
    """
    def __init__(
        self,
        classifier: Any,
        feature_names: List[str],
        label_mapping: Dict[int, str],
        background_samples: Optional[np.ndarray] = None,
        autoencoder: Optional[Any] = None,
        scaler: Optional[Any] = None
    ):
        self.classifier = classifier
        self.feature_names = feature_names
        self.label_mapping = label_mapping
        self.inv_label_mapping = {v: k for k, v in label_mapping.items()}
        self.autoencoder = autoencoder
        self.scaler = scaler

        # 1. Initialize SHAP TreeExplainer for high-throughput exact Shapley values
        try:
            self.shap_explainer = shap.TreeExplainer(self.classifier)
            self.shap_ready = True
        except Exception as e:
            logger.warning(f"Could not initialize shap.TreeExplainer directly: {e}. Fallback to Kernel/Explainer.")
            self.shap_explainer = None
            self.shap_ready = False

        # 2. Setup reference data for LIME
        if background_samples is not None:
            self.background = background_samples
        else:
            # Safe default reference matrix of zeros with proper dimension
            self.background = np.zeros((25, len(self.feature_names)), dtype=np.float32)

        try:
            self.lime_explainer = lime.lime_tabular.LimeTabularExplainer(
                training_data=self.background,
                feature_names=self.feature_names,
                class_names=[self.label_mapping[i] for i in sorted(self.label_mapping.keys())],
                mode="classification",
                random_state=42
            )
            self.lime_ready = True
        except Exception as e:
            logger.warning(f"Could not initialize LIME explainer: {e}")
            self.lime_explainer = None
            self.lime_ready = False

    def _interpret_feature(self, feature: str, value: float, importance: float) -> str:
        """Translates numerical feature value and importance into SOC analyst explanation."""
        rule = FEATURE_INTERPRETATION_RULES.get(feature)
        if rule:
            direction = "high" if value > 0 else "low"
            # Special case for duration or counts
            if "Byts" in feature or "Pkts" in feature or "Duration" in feature:
                direction = "high" if value > 10 else "low"
            return rule.get(direction, f"{feature} value ({value:.2f}) strongly drives prediction.")
        
        if importance > 0:
            return f"Feature '{feature}' (value: {value:.2f}) exhibited anomalous distribution driving attack classification."
        else:
            return f"Feature '{feature}' (value: {value:.2f}) aligned with baseline expectations, counteracting attack score."

    def explain_with_shap(
        self,
        features: np.ndarray,
        target_class_idx: int,
        top_k: int = 5
    ) -> Dict[str, Any]:
        """
        Computes exact Tree-SHAP feature attributions for a single flow.
        """
        if not self.shap_ready or self.shap_explainer is None:
            return self._fallback_explanation(features, target_class_idx, top_k, "SHAP_UNAVAILABLE")

        row = features.reshape(1, -1)
        shap_values = self.shap_explainer.shap_values(row)

        # Handle different SHAP output structures across tree models
        # For multi-class LightGBM/XGBoost, shap_values can be:
        # a) ndarray of shape (1, n_features, n_classes)
        # b) list of n_classes ndarrays of shape (1, n_features)
        if isinstance(shap_values, list):
            class_shap = shap_values[target_class_idx][0]
        elif isinstance(shap_values, np.ndarray):
            if shap_values.ndim == 3:
                # Shape (1, n_features, n_classes) or (1, n_classes, n_features)
                if shap_values.shape[2] == len(self.label_mapping):
                    class_shap = shap_values[0, :, target_class_idx]
                else:
                    class_shap = shap_values[0, target_class_idx, :]
            elif shap_values.ndim == 2:
                class_shap = shap_values[0]
            else:
                class_shap = shap_values.flatten()[:len(self.feature_names)]
        else:
            class_shap = np.array(shap_values).flatten()[:len(self.feature_names)]

        # Rank features by absolute Shapley impact
        sorted_indices = np.argsort(np.abs(class_shap))[::-1][:top_k]

        top_features = []
        for idx in sorted_indices:
            feat_name = self.feature_names[idx]
            raw_val = float(features[idx])
            imp = float(class_shap[idx])
            direction = "INCREASES_ATTACK_LIKELIHOOD" if imp > 0 else "REDUCES_ATTACK_LIKELIHOOD"
            if self.label_mapping.get(target_class_idx) == "Benign":
                direction = "SUPPORTS_BENIGN_PROFILE" if imp > 0 else "DEVIATES_FROM_BENIGN"

            top_features.append({
                "feature": feat_name,
                "importance": round(imp, 4),
                "value": round(raw_val, 4),
                "direction": direction,
                "interpretation": self._interpret_feature(feat_name, raw_val, imp)
            })

        class_name = self.label_mapping.get(target_class_idx, f"Class_{target_class_idx}")
        top_names = [f["feature"] for f in top_features[:3]]
        summary = (
            f"Prediction of '{class_name}' is predominantly driven by {', '.join(top_names)}."
        )

        return {
            "method": "SHAP",
            "target_class": class_name,
            "target_class_index": int(target_class_idx),
            "top_features": top_features,
            "summary": summary
        }

    def explain_with_lime(
        self,
        features: np.ndarray,
        target_class_idx: int,
        top_k: int = 5
    ) -> Dict[str, Any]:
        """
        Computes local surrogate linear explanation using LIME Tabular.
        """
        if not self.lime_ready or self.lime_explainer is None:
            return self._fallback_explanation(features, target_class_idx, top_k, "LIME_UNAVAILABLE")

        row = features.flatten().astype(np.float64)
        predict_fn = getattr(self.classifier, "predict_proba", None)
        if predict_fn is None:
            return self._fallback_explanation(features, target_class_idx, top_k, "NO_PROBA_METHOD")

        try:
            exp = self.lime_explainer.explain_instance(
                data_row=row,
                predict_fn=predict_fn,
                labels=[target_class_idx],
                num_features=top_k
            )
            raw_exp = exp.as_list(label=target_class_idx)

            top_features = []
            for rule_str, weight in raw_exp:
                # Extract clean feature name from rule string e.g. "Flow Duration > 10.0"
                matched_feat = next((f for f in self.feature_names if f in rule_str), rule_str)
                feat_idx = self.feature_names.index(matched_feat) if matched_feat in self.feature_names else 0
                raw_val = float(row[feat_idx])

                direction = "INCREASES_ATTACK_LIKELIHOOD" if weight > 0 else "REDUCES_ATTACK_LIKELIHOOD"
                top_features.append({
                    "feature": matched_feat,
                    "condition": rule_str,
                    "importance": round(float(weight), 4),
                    "value": round(raw_val, 4),
                    "direction": direction,
                    "interpretation": self._interpret_feature(matched_feat, raw_val, float(weight))
                })

            class_name = self.label_mapping.get(target_class_idx, f"Class_{target_class_idx}")
            top_names = [f["feature"] for f in top_features[:3]]
            summary = f"LIME local surrogate indicates {', '.join(top_names)} as key factors for '{class_name}'."

            return {
                "method": "LIME",
                "target_class": class_name,
                "target_class_index": int(target_class_idx),
                "top_features": top_features,
                "summary": summary
            }
        except Exception as e:
            logger.warning(f"LIME calculation failed: {e}. Falling back to variance attribution.")
            return self._fallback_explanation(features, target_class_idx, top_k, f"LIME_ERROR: {str(e)}")

    def explain_autoencoder_anomaly(
        self,
        features_scaled: np.ndarray,
        top_k: int = 5
    ) -> Dict[str, Any]:
        """
        Explains unsupervised anomalies by calculating per-feature reconstruction error (MSE)
        from the PyTorch Deep Autoencoder. Features with largest reconstruction error
        represent the anomalous dimensions that violate benign baseline patterns.
        """
        if self.autoencoder is None:
            return {
                "method": "AUTOENCODER_RECONSTRUCTION",
                "top_features": [],
                "summary": "Autoencoder not configured for feature attribution."
            }

        row = features_scaled.reshape(1, -1)
        with torch.no_grad():
            t_in = torch.tensor(row, dtype=torch.float32)
            t_out = self.autoencoder(t_in)
            diff = (t_in - t_out).numpy()[0]
            per_feature_mse = diff ** 2

        sorted_indices = np.argsort(per_feature_mse)[::-1][:top_k]
        top_features = []
        for idx in sorted_indices:
            feat_name = self.feature_names[idx]
            err = float(per_feature_mse[idx])
            top_features.append({
                "feature": feat_name,
                "importance": round(err, 4),
                "reconstruction_error": round(err, 4),
                "direction": "BASELINE_DEVIATION",
                "interpretation": f"Feature '{feat_name}' exhibited high reconstruction deviation ({err:.3f}), breaching benign subspace boundaries."
            })

        top_names = [f["feature"] for f in top_features[:3]]
        summary = f"Autoencoder anomaly driven by abnormal reconstruction error in: {', '.join(top_names)}."

        return {
            "method": "AUTOENCODER_RECONSTRUCTION",
            "top_features": top_features,
            "summary": summary
        }

    def _fallback_explanation(
        self,
        features: np.ndarray,
        target_class_idx: int,
        top_k: int,
        reason: str
    ) -> Dict[str, Any]:
        """Heuristic fallback explanation based on non-zero normalized magnitude."""
        mags = np.abs(features)
        sorted_indices = np.argsort(mags)[::-1][:top_k]
        top_features = []
        for idx in sorted_indices:
            feat_name = self.feature_names[idx]
            val = float(features[idx])
            top_features.append({
                "feature": feat_name,
                "importance": round(val, 4),
                "value": round(val, 4),
                "direction": "HIGH_MAGNITUDE",
                "interpretation": self._interpret_feature(feat_name, val, 1.0)
            })

        return {
            "method": f"FALLBACK ({reason})",
            "target_class": self.label_mapping.get(target_class_idx, "Unknown"),
            "target_class_index": int(target_class_idx),
            "top_features": top_features,
            "summary": f"Fallback explanation based on top feature values due to {reason}."
        }

    def explain(
        self,
        features_clean: np.ndarray,
        predicted_class_idx: int,
        method: str = "shap",
        top_k: int = 5,
        features_scaled: Optional[np.ndarray] = None,
        is_anomaly: bool = False
    ) -> Dict[str, Any]:
        """
        Unified explanation interface called by Role 6 backend pipeline.
        Supports 'shap', 'lime', or auto-routing to autoencoder reconstruction attribution.
        """
        method_norm = method.lower().strip()
        
        # If model predicted Benign but anomaly detectors triggered, prioritize autoencoder explanation
        pred_label = self.label_mapping.get(predicted_class_idx, "Benign")
        if pred_label == "Benign" and is_anomaly and features_scaled is not None and self.autoencoder is not None:
            return self.explain_autoencoder_anomaly(features_scaled, top_k=top_k)

        if method_norm == "lime":
            return self.explain_with_lime(features_clean, predicted_class_idx, top_k=top_k)
        else:
            return self.explain_with_shap(features_clean, predicted_class_idx, top_k=top_k)
