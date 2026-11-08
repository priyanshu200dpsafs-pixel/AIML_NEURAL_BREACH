#!/usr/bin/env python3
"""
Role 5 Unified Threat Intelligence & XAI Integration Service
Team Neural Breach — Role 5: XAI & Threat Intelligence

Integrates:
  1. SHAP / LIME explanation engine (feature rankings, directions, domain interpretations).
  2. Verified MITRE ATT&CK mapping (tactics, techniques, URLs, mitigations).
  3. Transparent Threat Prioritizer (score 0-100, CRITICAL/HIGH/MEDIUM/LOW/INFO).
  4. Structured JSON response adhering to the Role 5 / Role 6 agreed contract.
"""

import os
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union

import numpy as np
import pandas as pd

from src.xai.explainer import NetworkFlowExplainer
from src.xai.mitre_mapper import MitreThreatIntelligence
from src.xai.prioritization import ThreatPrioritizer


class ThreatIntelService:
    """
    High-level threat intelligence and explainability coordinator.
    Acts as the single point of entry for Role 6 backend pipeline to enrich alerts.
    """
    def __init__(
        self,
        classifier: Any = None,
        feature_names: Optional[List[str]] = None,
        label_mapping: Optional[Dict[int, str]] = None,
        autoencoder: Optional[Any] = None,
        scaler: Optional[Any] = None,
        stix_path: Optional[str] = None
    ):
        self.feature_names = feature_names or []
        self.label_mapping = label_mapping or {}
        self.inv_label_mapping = {v: k for k, v in self.label_mapping.items()}
        
        # Initialize sub-modules
        self.mitre_mapper = MitreThreatIntelligence(stix_path=stix_path) if stix_path else MitreThreatIntelligence()
        self.prioritizer = ThreatPrioritizer()
        
        if classifier is not None and self.feature_names and self.label_mapping:
            self.explainer = NetworkFlowExplainer(
                classifier=classifier,
                feature_names=self.feature_names,
                label_mapping=self.label_mapping,
                autoencoder=autoencoder,
                scaler=scaler
            )
        else:
            self.explainer = None

    def enrich_alert(
        self,
        flow_features: Union[Dict[str, float], np.ndarray, pd.Series],
        prediction_result: Dict[str, Any],
        explainer_type: str = "shap",
        top_k: int = 5,
        alert_id: Optional[str] = None,
        features_scaled: Optional[np.ndarray] = None
    ) -> Dict[str, Any]:
        """
        Enriches a raw model prediction with XAI explanations, MITRE ATT&CK intelligence,
        transparent threat priority scoring, and SOC investigation playbooks.
        Conforms strictly to the agreed JSON contract.
        """
        # 1. Normalize flow features
        if isinstance(flow_features, dict):
            feat_dict = flow_features
            feat_array = np.array([feat_dict.get(col, 0.0) for col in self.feature_names], dtype=np.float32)
        elif isinstance(flow_features, pd.Series):
            feat_dict = flow_features.to_dict()
            feat_array = np.array([feat_dict.get(col, 0.0) for col in self.feature_names], dtype=np.float32)
        else:
            feat_array = np.asarray(flow_features, dtype=np.float32).flatten()
            feat_dict = {name: float(feat_array[i]) for i, name in enumerate(self.feature_names) if i < len(feat_array)}

        # Extract prediction details
        pred_label = prediction_result.get("predicted_label", "Benign")
        confidence = float(prediction_result.get("confidence", 0.0))
        is_anomaly = bool(prediction_result.get("anomaly_detected", False))
        iso_alert = bool(prediction_result.get("isolation_forest_alert", False))
        ae_alert = bool(prediction_result.get("autoencoder_alert", False))
        probabilities = prediction_result.get("probabilities", {})

        target_class_idx = self.inv_label_mapping.get(pred_label, 0)

        # 2. Compute Explainable AI feature attributions
        if self.explainer is not None:
            explanation = self.explainer.explain(
                features_clean=feat_array,
                predicted_class_idx=target_class_idx,
                method=explainer_type,
                top_k=top_k,
                features_scaled=features_scaled,
                is_anomaly=is_anomaly
            )
        else:
            explanation = {
                "method": "UNCONFIGURED",
                "top_features": [],
                "summary": "Explainer not initialized with model weights."
            }

        # 3. Retrieve MITRE ATT&CK Threat Intelligence
        effective_threat = pred_label if pred_label != "Benign" else ("SUSPICIOUS_ANOMALY" if is_anomaly else "Benign")
        mitre_data = self.mitre_mapper.get_mapping(effective_threat)

        # 4. Calculate Threat Priority & SOC Analyst Playbooks
        priority_data = self.prioritizer.calculate_priority(
            predicted_label=pred_label,
            confidence=confidence,
            is_anomaly=is_anomaly,
            iso_alert=iso_alert,
            ae_alert=ae_alert,
            flow_features=feat_dict
        )

        # 5. Synthesize complete unified alert record
        now_utc = datetime.now(timezone.utc).isoformat()
        final_alert_id = alert_id or f"ALT-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"

        enriched_alert = {
            "alert_id": final_alert_id,
            "timestamp": now_utc,
            "observe_only_mode": True,
            "action_enforced": "NONE_OBSERVE_ONLY",
            "prediction": {
                "label": pred_label,
                "is_attack": pred_label != "Benign",
                "confidence": round(confidence, 4),
                "classifier_type": prediction_result.get("classifier_type", "Primary Ensemble"),
                "probabilities": {k: round(v, 4) for k, v in probabilities.items()}
            },
            "anomaly_detection": {
                "is_anomaly": is_anomaly,
                "isolation_forest_score": round(float(prediction_result.get("isolation_forest_score", 0.0)), 4),
                "isolation_forest_alert": iso_alert,
                "autoencoder_recon_error": round(float(prediction_result.get("autoencoder_recon_error", 0.0)), 4),
                "autoencoder_alert": ae_alert
            },
            "threat_priority": {
                "level": priority_data["level"],
                "score": priority_data["score"],
                "urgency": priority_data["urgency"],
                "scoring_factors": priority_data["scoring_factors"]
            },
            "explanation": explanation,
            "threat_intelligence": {
                "attack_category": pred_label,
                "effective_threat": effective_threat,
                "mitre_attack": {
                    "mapping_status": mitre_data.get("mapping_status", "CONFIRMED"),
                    "semantic_accuracy_note": mitre_data.get("semantic_accuracy_note", ""),
                    "tactics": mitre_data.get("tactics", []),
                    "primary_technique": mitre_data.get("primary_technique", {}),
                    "secondary_techniques": mitre_data.get("secondary_techniques", [])
                },
                "mitigations": mitre_data.get("mitigations", []),
                "recommendations": priority_data["recommendations"]
            },
            "flow_metadata": {
                "flow_index": prediction_result.get("flow_index", 0),
                "protocol": int(feat_dict.get("Protocol", 6)),
                "flow_duration_ms": round(float(feat_dict.get("Flow Duration", 0.0)) / 1000.0, 2),
                "total_fwd_pkts": int(feat_dict.get("Tot Fwd Pkts", 0)),
                "total_bwd_pkts": int(feat_dict.get("Tot Bwd Pkts", 0)),
                "flow_bytes_per_sec": round(float(feat_dict.get("Flow Byts/s", 0.0)), 2)
            }
        }

        return enriched_alert


def explain_and_enrich_alert(
    flow_features: Union[Dict[str, float], np.ndarray, pd.Series],
    prediction_result: Dict[str, Any],
    service: ThreatIntelService,
    explainer_type: str = "shap",
    top_k: int = 5
) -> Dict[str, Any]:
    """Convenience functional wrapper for Role 6 integration."""
    return service.enrich_alert(
        flow_features=flow_features,
        prediction_result=prediction_result,
        explainer_type=explainer_type,
        top_k=top_k
    )
