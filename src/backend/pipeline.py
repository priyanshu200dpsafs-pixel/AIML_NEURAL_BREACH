#!/usr/bin/env python3
"""
Real-Time Detection & Security Alert Pipeline
Team Neural Breach — Role 6: Backend & Real-Time Detection

Integrates:
  - Role 3: Frozen CyberDefenseInferenceEngine (LightGBM/XGBoost + Autoencoder + Isolation Forest)
  - Role 5: ThreatIntelService (SHAP/LIME, MITRE ATT&CK, Threat Prioritization, SOC Playbooks)
  - Role 6: AlertManager (Deduplication, storage) and WebSocketManager (Live streaming)
"""

import os
import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from src.models.inference_engine import CyberDefenseInferenceEngine, ModelInferenceError
from src.xai.threat_intel_service import ThreatIntelService
from src.backend.config import settings
from src.backend.alert_manager import alert_store, AlertManager
from src.backend.websocket_manager import ws_manager, WebSocketManager

logger = logging.getLogger("neural_breach.backend.pipeline")


class RealTimeDetectionPipeline:
    """
    End-to-end real-time network flow detection and alert generation pipeline.
    Maintains strict observe-only mode and zero-leakage inference contracts.
    """
    def __init__(
        self,
        classifier_type: str = settings.DEFAULT_CLASSIFIER,
        fpr_budget: str = settings.FPR_BUDGET,
        alert_manager: Optional[AlertManager] = None,
        websocket_manager: Optional[WebSocketManager] = None
    ):
        self.classifier_type = classifier_type
        self.fpr_budget = fpr_budget
        self.alert_manager = alert_manager or alert_store
        self.websocket_manager = websocket_manager or ws_manager

        # 1. Load frozen Role 3 inference engine (Observe-Only Mode)
        logger.info(f"Initializing frozen CyberDefenseInferenceEngine ({classifier_type})...")
        self.engine = CyberDefenseInferenceEngine(
            models_dir=settings.MODELS_DIR,
            classifier_type=self.classifier_type,
            fpr_budget=self.fpr_budget
        )

        # 2. Initialize Role 5 Threat Intelligence & XAI Service
        logger.info("Initializing Role 5 ThreatIntelService with SHAP & MITRE STIX catalog...")
        self.threat_service = ThreatIntelService(
            classifier=self.engine.classifier,
            feature_names=self.engine.expected_features,
            label_mapping=self.engine.label_mapping,
            autoencoder=self.engine.autoencoder,
            scaler=self.engine.scaler,
            stix_path=settings.STIX_PATH
        )

    @property
    def expected_features(self) -> List[str]:
        return self.engine.expected_features

    @property
    def label_mapping(self) -> Dict[int, str]:
        return self.engine.label_mapping

    async def process_flows(
        self,
        df: pd.DataFrame,
        explain: bool = True,
        explainer_type: str = "shap",
        top_k: int = 5,
        broadcast_ws: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Executes inference, enrichment, deduplication, and WebSocket alert broadcast
        for an incoming batch of network flows.
        """
        if not isinstance(df, pd.DataFrame):
            raise ModelInferenceError(f"Input must be a DataFrame, received {type(df)}")
        if len(df) == 0:
            return []

        # 1. Validate features, impute NaNs, produce clean and scaled matrices
        X_clean, X_scaled = self.engine.validate_and_preprocess(df)

        # 2. Run multi-model prediction pipeline (Supervised + Isolation Forest + Deep Autoencoder)
        raw_predictions = self.engine.predict_flows(df)

        enriched_alerts = []
        for i, pred in enumerate(raw_predictions):
            row_features = df.iloc[i].to_dict()
            scaled_row = X_scaled[i]

            # 3. Enrich prediction with Role 5 XAI, MITRE ATT&CK, and Threat Prioritization
            if explain:
                alert = self.threat_service.enrich_alert(
                    flow_features=row_features,
                    prediction_result=pred,
                    explainer_type=explainer_type,
                    top_k=top_k,
                    features_scaled=scaled_row
                )
            else:
                # Fast path without computing full SHAP values
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
                        "is_attack": pred["predicted_label"] != "Benign",
                        "confidence": round(pred["confidence"], 4),
                        "classifier_type": self.engine.clf_type,
                        "probabilities": {k: round(v, 4) for k, v in pred["probabilities"].items()}
                    },
                    "anomaly_detection": {
                        "is_anomaly": pred["anomaly_detected"],
                        "isolation_forest_score": round(pred["isolation_forest_score"], 4),
                        "isolation_forest_alert": pred["isolation_forest_alert"],
                        "autoencoder_recon_error": round(pred["autoencoder_recon_error"], 4),
                        "autoencoder_alert": pred["autoencoder_alert"]
                    },
                    "threat_priority": {
                        "level": priority["level"],
                        "score": priority["score"],
                        "urgency": priority["urgency"],
                        "scoring_factors": priority["scoring_factors"]
                    },
                    "explanation": {
                        "method": "DISABLED",
                        "top_features": [],
                        "summary": "Explainability disabled via request parameters."
                    },
                    "threat_intelligence": {
                        "attack_category": pred["predicted_label"],
                        "effective_threat": effective_threat,
                        "mitre_attack": {
                            "mapping_status": mitre_data.get("mapping_status", "CONFIRMED"),
                            "semantic_accuracy_note": mitre_data.get("semantic_accuracy_note", ""),
                            "tactics": mitre_data.get("tactics", []),
                            "primary_technique": mitre_data.get("primary_technique", {}),
                            "secondary_techniques": mitre_data.get("secondary_techniques", [])
                        },
                        "mitigations": mitre_data.get("mitigations", []),
                        "recommendations": priority["recommendations"]
                    },
                    "flow_metadata": {
                        "flow_index": pred["flow_index"],
                        "protocol": int(row_features.get("Protocol", 6)),
                        "flow_duration_ms": round(float(row_features.get("Flow Duration", 0.0)) / 1000.0, 2),
                        "total_fwd_pkts": int(row_features.get("Tot Fwd Pkts", 0)),
                        "total_bwd_pkts": int(row_features.get("Tot Bwd Pkts", 0)),
                        "flow_bytes_per_sec": round(float(row_features.get("Flow Byts/s", 0.0)), 2)
                    }
                }

            # 4. Ingest into AlertManager with deduplication
            stored_alert, is_new = self.alert_manager.add_alert(alert)

            # 5. Broadcast to connected WebSockets if new alert or escalated repeat
            if broadcast_ws and self.websocket_manager is not None:
                if stored_alert["prediction"]["is_attack"] or stored_alert["anomaly_detection"]["is_anomaly"]:
                    asyncio.create_task(self.websocket_manager.broadcast_alert(stored_alert))

            enriched_alerts.append(stored_alert)

        return enriched_alerts

    async def simulate_stream(
        self,
        sample_size: int = 20,
        attack_ratio: float = 0.5,
        stream_delay_seconds: float = 0.02,
        broadcast_ws: bool = True,
        test_split_path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Samples authentic flows from the benchmark test partition (data/processed/splits/test.parquet),
        streams them through the detection pipeline, and broadcasts alerts in real time.
        """
        test_path = test_split_path or settings.TEST_SPLIT_PATH
        if not os.path.exists(test_path):
            raise FileNotFoundError(
                f"Benchmark test dataset not found at '{test_path}'. "
                "To synchronize the dataset from Google Drive, run 'python scripts/sync_data_drive.py' "
                "or specify a valid path via the NEURAL_BREACH_TEST_SPLIT_PATH environment variable."
            )

        # Load slice of test partition
        table = pq.read_table(test_path)
        df_all = table.to_pandas()

        # Separate benign and attack rows
        label_col = "Clean_Label" if "Clean_Label" in df_all.columns else "Label"
        df_attacks = df_all[df_all[label_col] != "Benign"]
        df_benign = df_all[df_all[label_col] == "Benign"]

        n_attacks = int(sample_size * attack_ratio)
        n_benign = sample_size - n_attacks

        sampled_parts = []
        if n_attacks > 0 and len(df_attacks) > 0:
            sampled_parts.append(df_attacks.sample(min(n_attacks, len(df_attacks)), random_state=42))
        if n_benign > 0 and len(df_benign) > 0:
            sampled_parts.append(df_benign.sample(min(n_benign, len(df_benign)), random_state=42))

        df_sample = pd.concat(sampled_parts).sample(frac=1.0, random_state=42).reset_index(drop=True)

        results = []
        for idx in range(len(df_sample)):
            single_flow_df = df_sample.iloc[[idx]]
            processed = await self.process_flows(
                df=single_flow_df,
                explain=True,
                explainer_type="shap",
                top_k=5,
                broadcast_ws=broadcast_ws
            )
            results.extend(processed)
            if stream_delay_seconds > 0:
                await asyncio.sleep(stream_delay_seconds)

        return results
