"""Detection Adapter Bridge: Connects the Role 7 background worker to the official
frozen Role 3/5/6 AI/ML Cyber Defense detection & threat intelligence pipeline.

Strict observe-only mode is enforced. No models are retrained or mutated.
"""
from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional

import pandas as pd

from src.models.inference_engine import CyberDefenseInferenceEngine, ModelInferenceError
from src.xai.threat_intel_service import ThreatIntelService
from src.backend.config import settings as role6_settings

log = logging.getLogger("neural_breach.detection_adapter")


class Role6DetectionAdapter:
    """Production adapter bridge implementing worker.DetectionAdapter protocol.
    Runs frozen multi-model inference (Supervised + Isolation Forest + Autoencoder)
    and enriches with Role 5 XAI (SHAP/LIME) and MITRE ATT&CK intelligence.
    """

    def __init__(
        self,
        classifier_type: str = "lightgbm",
        fpr_budget: str = "1pct",
        models_dir: Optional[str] = None,
        stix_path: Optional[str] = None,
        explain: bool = True,
        top_k: int = 5
    ):
        models_dir = models_dir or role6_settings.MODELS_DIR
        stix_path = stix_path or role6_settings.STIX_PATH
        self.explain = explain
        self.top_k = top_k

        log.info("Loading frozen CyberDefenseInferenceEngine (%s, budget=%s)...", classifier_type, fpr_budget)
        self.engine = CyberDefenseInferenceEngine(
            models_dir=models_dir,
            classifier_type=classifier_type,
            fpr_budget=fpr_budget
        )

        log.info("Initializing Role 5 ThreatIntelService with MITRE STIX catalog...")
        self.threat_service = ThreatIntelService(
            classifier=self.engine.classifier,
            feature_names=self.engine.expected_features,
            label_mapping=self.engine.label_mapping,
            autoencoder=self.engine.autoencoder,
            scaler=self.engine.scaler,
            stix_path=stix_path
        )
        log.info("Role6DetectionAdapter initialized successfully in OBSERVE-ONLY mode.")

    @property
    def expected_features(self) -> List[str]:
        return self.engine.expected_features

    def process(self, flows: List[Dict[str, float]]) -> List[Dict[str, Any]]:
        """Run the frozen Role 3/5/6 pipeline on the incoming network flow batch.
        Returns one result dict per alert-worthy flow. Pure benign flows are omitted.
        """
        if not flows:
            return []

        # 1. Convert to DataFrame and validate 77-feature schema
        df = pd.DataFrame(flows)
        missing_cols = [c for c in self.engine.expected_features if c not in df.columns]
        if missing_cols:
            raise ValueError(
                f"SchemaValidationViolation: Input flows missing {len(missing_cols)} required features: {missing_cols[:5]}"
            )

        # 2. Preprocess and scale features
        X_clean, X_scaled = self.engine.validate_and_preprocess(df)

        # 3. Multi-model inference
        raw_predictions = self.engine.predict_flows(df)

        results: List[Dict[str, Any]] = []

        for i, pred in enumerate(raw_predictions):
            row_features = df.iloc[i].to_dict()
            scaled_row = X_scaled[i]

            is_attack = (pred["predicted_label"] != "Benign")
            is_anomaly = bool(pred.get("anomaly_detected", False))

            # Benign, non-anomalous flows do not generate alerts
            if not is_attack and not is_anomaly:
                continue

            # 4. Enrich with SHAP explanations and MITRE ATT&CK mapping
            if self.explain:
                alert = self.threat_service.enrich_alert(
                    flow_features=row_features,
                    prediction_result=pred,
                    explainer_type="shap",
                    top_k=self.top_k,
                    features_scaled=scaled_row
                )
            else:
                priority = self.threat_service.prioritizer.calculate_priority(
                    predicted_label=pred["predicted_label"],
                    confidence=pred["confidence"],
                    is_anomaly=pred["anomaly_detected"],
                    iso_alert=pred["isolation_forest_alert"],
                    ae_alert=pred["autoencoder_alert"],
                    flow_features=row_features
                )
                effective_threat = (
                    pred["predicted_label"]
                    if pred["predicted_label"] != "Benign"
                    else ("SUSPICIOUS_ANOMALY" if pred["anomaly_detected"] else "Benign")
                )
                mitre_data = self.threat_service.mitre_mapper.get_mapping(effective_threat)
                alert = {
                    "alert_id": f"ALT-{pred['flow_index']}",
                    "timestamp": pd.Timestamp.now(tz="UTC").isoformat(),
                    "observe_only_mode": True,
                    "action_enforced": "NONE_OBSERVE_ONLY",
                    "prediction": {
                        "label": pred["predicted_label"],
                        "is_attack": is_attack,
                        "confidence": round(pred["confidence"], 4),
                        "classifier_type": self.engine.clf_type,
                        "probabilities": {k: round(v, 4) for k, v in pred["probabilities"].items()}
                    },
                    "threat_priority": {
                        "level": priority["level"],
                        "score": priority["score"],
                        "urgency": priority["urgency"],
                        "scoring_factors": priority["scoring_factors"]
                    },
                    "threat_intelligence": {
                        "attack_category": pred["predicted_label"],
                        "effective_threat": effective_threat,
                        "mitre_attack": mitre_data,
                        "recommendations": priority["recommendations"]
                    }
                }

            # Enforce observe-only invariant
            alert["observe_only_mode"] = True
            alert["action_enforced"] = "NONE_OBSERVE_ONLY"

            label = pred["predicted_label"]
            attack_category = alert.get("threat_intelligence", {}).get("attack_category", label)
            threat_level = alert.get("threat_priority", {}).get("level", "UNKNOWN")
            priority_score = float(alert.get("threat_priority", {}).get("score", 0.0))

            results.append({
                "flow_index": i,
                "label": label,
                "attack_category": attack_category,
                "threat_level": threat_level,
                "priority_score": priority_score,
                "dedup_key": f"{label}|{attack_category}",
                "payload": alert
            })

        return results


def create_detection_adapter(
    classifier_type: str = "lightgbm",
    fpr_budget: str = "1pct"
) -> Role6DetectionAdapter:
    """Factory function for dynamic loading via NB_DETECTION_ADAPTER."""
    return Role6DetectionAdapter(classifier_type=classifier_type, fpr_budget=fpr_budget)
