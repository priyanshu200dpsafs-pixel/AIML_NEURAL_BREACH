#!/usr/bin/env python3
"""
Automated Test Suite for Role 5: Explainable AI & Threat Intelligence
Team Neural Breach — AI/ML Cyber Defense Platform
"""

import os
import json
import pytest
import numpy as np
import pandas as pd

from src.xai.mitre_mapper import MitreThreatIntelligence, VERIFIED_MITRE_CATALOG
from src.xai.explainer import NetworkFlowExplainer
from src.xai.prioritization import ThreatPrioritizer
from src.xai.threat_intel_service import ThreatIntelService
from src.models.inference_engine import CyberDefenseInferenceEngine


@pytest.fixture(scope="module")
def inference_engine():
    """Shared inference engine fixture."""
    return CyberDefenseInferenceEngine(classifier_type="lightgbm")


@pytest.fixture(scope="module")
def threat_service(inference_engine):
    """Shared Threat Intelligence Service fixture."""
    return ThreatIntelService(
        classifier=inference_engine.classifier,
        feature_names=inference_engine.expected_features,
        label_mapping=inference_engine.label_mapping,
        autoencoder=inference_engine.autoencoder,
        scaler=inference_engine.scaler
    )


class TestMitreThreatIntelligence:
    """Tests for MITRE ATT&CK mapping and STIX 2.1 compliance."""

    def test_stix_21_verification(self):
        """Validates that 100% of catalog techniques exist in official enterprise-attack.json."""
        mapper = MitreThreatIntelligence()
        result = mapper.validate_against_stix()
        if result["status"] != "SKIPPED":
            assert result["status"] == "PASS", f"STIX validation failed: {result}"
            assert result["all_verified"] is True
            assert result["total_techniques_checked"] > 10
            assert len(result["missing_from_stix"]) == 0

    def test_all_15_classes_mapped(self, inference_engine):
        """Verifies that every class in label_mapping.json has a valid MITRE profile."""
        mapper = MitreThreatIntelligence()
        for idx, label in inference_engine.label_mapping.items():
            profile = mapper.get_mapping(label)
            assert "primary_technique" in profile, f"Missing primary technique for {label}"
            assert "tactics" in profile, f"Missing tactics for {label}"
            assert "mitigations" in profile, f"Missing mitigations for {label}"
            primary = profile["primary_technique"]
            assert "id" in primary
            assert "name" in primary
            assert "url" in primary
            assert primary["url"].startswith("https://attack.mitre.org")

    def test_suspicious_anomaly_mapping(self):
        """Verifies mapping for unsupervised zero-day anomaly detections is marked as unconfirmed."""
        mapper = MitreThreatIntelligence()
        profile = mapper.get_mapping("SUSPICIOUS_ANOMALY")
        assert len(profile["tactics"]) >= 2
        assert profile["primary_technique"]["id"] == "T1071"
        assert len(profile["secondary_techniques"]) >= 2
        assert profile["mapping_status"] == "UNCONFIRMED_GENERIC_ANOMALY"
        assert "UNCONFIRMED" in profile["semantic_accuracy_note"]

    def test_semantic_accuracy_ratings(self):
        """Verifies semantic validation ratings: distinguishing confirmed flow signatures from unconfirmed surrogates."""
        mapper = MitreThreatIntelligence()
        # Direct flow signatures
        assert mapper.get_mapping("DDOS attack-HOIC")["mapping_status"] == "CONFIRMED_FLOW_SIGNATURE"
        assert mapper.get_mapping("SSH-Bruteforce")["mapping_status"] == "CONFIRMED_FLOW_SIGNATURE"
        assert mapper.get_mapping("DoS attacks-Slowloris")["mapping_status"] == "CONFIRMED_FLOW_SIGNATURE"
        # Flow surrogates requiring Layer-7 or host confirmation
        assert mapper.get_mapping("Infiltration")["mapping_status"] == "UNCONFIRMED_FLOW_SURROGATE"
        assert mapper.get_mapping("SQL Injection")["mapping_status"] == "UNCONFIRMED_FLOW_SURROGATE"
        assert mapper.get_mapping("Brute Force -XSS")["mapping_status"] == "UNCONFIRMED_FLOW_SURROGATE"
        # Generic unclassified input
        assert mapper.get_mapping("RandomUnknownThreat")["mapping_status"] == "UNCONFIRMED_UNKNOWN"


class TestExplainableAI:
    """Tests for SHAP, LIME, and Autoencoder feature attribution."""

    def test_shap_explanation_structure(self, inference_engine, threat_service):
        """Tests SHAP TreeExplainer calculation and feature ranking."""
        dummy_flow = np.zeros(len(inference_engine.expected_features), dtype=np.float32)
        # Give some realistic variation
        dummy_flow[inference_engine.expected_features.index("Flow Duration")] = 500000.0
        dummy_flow[inference_engine.expected_features.index("Tot Fwd Pkts")] = 250.0

        exp = threat_service.explainer.explain_with_shap(dummy_flow, target_class_idx=12, top_k=5)
        assert exp["method"] == "SHAP"
        assert len(exp["top_features"]) == 5
        assert "target_class" in exp
        assert "summary" in exp

        # Verify each feature explanation dict
        for feat in exp["top_features"]:
            assert "feature" in feat
            assert "importance" in feat
            assert "value" in feat
            assert feat["direction"] in [
                "INCREASES_ATTACK_LIKELIHOOD",
                "REDUCES_ATTACK_LIKELIHOOD",
                "SUPPORTS_BENIGN_PROFILE",
                "DEVIATES_FROM_BENIGN"
            ]
            assert len(feat["interpretation"]) > 10

    def test_lime_explanation_structure(self, inference_engine, threat_service):
        """Tests LIME Tabular surrogate model explanation."""
        dummy_flow = np.zeros(len(inference_engine.expected_features), dtype=np.float32)
        exp = threat_service.explainer.explain_with_lime(dummy_flow, target_class_idx=12, top_k=5)
        assert exp["method"] == "LIME"
        assert len(exp["top_features"]) <= 5
        assert len(exp["summary"]) > 0

    def test_autoencoder_anomaly_attribution(self, inference_engine, threat_service):
        """Tests Autoencoder per-feature reconstruction error decomposition."""
        dummy_scaled = np.ones(len(inference_engine.expected_features), dtype=np.float32) * 5.0
        exp = threat_service.explainer.explain_autoencoder_anomaly(dummy_scaled, top_k=5)
        assert exp["method"] == "AUTOENCODER_RECONSTRUCTION"
        assert len(exp["top_features"]) == 5
        for feat in exp["top_features"]:
            assert feat["reconstruction_error"] >= 0.0
            assert feat["direction"] == "BASELINE_DEVIATION"


class TestThreatPrioritization:
    """Tests for transparent threat prioritization and playbooks."""

    def test_benign_score_and_tier(self):
        prioritizer = ThreatPrioritizer()
        p = prioritizer.calculate_priority(
            predicted_label="Benign",
            confidence=0.99,
            is_anomaly=False
        )
        assert p["score"] == 0.0
        assert p["level"] == "INFO"
        assert p["urgency"] == "INFORMATIONAL"

    def test_critical_threat_scoring(self):
        prioritizer = ThreatPrioritizer()
        p = prioritizer.calculate_priority(
            predicted_label="Infiltration",
            confidence=0.98,
            is_anomaly=True,
            iso_alert=True,
            ae_alert=True,
            flow_features={"Flow Duration": 75000000.0, "Flow Byts/s": 2500000.0, "Tot Fwd Pkts": 5000.0}
        )
        assert p["score"] >= 80.0
        assert p["level"] == "CRITICAL"
        assert p["urgency"] == "IMMEDIATE"
        assert len(p["recommendations"]["investigation_steps"]) >= 3
        assert len(p["recommendations"]["containment_playbook"]) >= 2
        assert len(p["recommendations"]["telemetry_queries"]) >= 1

    def test_anomaly_corroboration_impact(self):
        prioritizer = ThreatPrioritizer()
        p_no_anom = prioritizer.calculate_priority(
            predicted_label="SSH-Bruteforce",
            confidence=0.85,
            is_anomaly=False
        )
        p_with_anom = prioritizer.calculate_priority(
            predicted_label="SSH-Bruteforce",
            confidence=0.85,
            is_anomaly=True,
            iso_alert=True,
            ae_alert=True
        )
        assert p_with_anom["score"] > p_no_anom["score"]
        assert p_with_anom["scoring_factors"]["anomaly_corroboration"] == 15.0


class TestThreatIntelServiceContract:
    """Tests for Role 5 unified JSON output contract."""

    def test_enrich_alert_complete_schema(self, inference_engine, threat_service):
        dummy_df = pd.DataFrame(
            np.zeros((1, len(inference_engine.expected_features))),
            columns=inference_engine.expected_features
        )
        preds = inference_engine.predict_flows(dummy_df)
        assert len(preds) == 1

        enriched = threat_service.enrich_alert(
            flow_features=dummy_df.iloc[0],
            prediction_result=preds[0],
            explainer_type="shap",
            top_k=5
        )

        # Validate required contract keys
        required_keys = [
            "alert_id",
            "timestamp",
            "observe_only_mode",
            "action_enforced",
            "prediction",
            "anomaly_detection",
            "threat_priority",
            "explanation",
            "threat_intelligence",
            "flow_metadata"
        ]
        for k in required_keys:
            assert k in enriched, f"Missing contract key: {k}"

        assert enriched["observe_only_mode"] is True
        assert enriched["action_enforced"] == "NONE_OBSERVE_ONLY"
        assert enriched["threat_priority"]["level"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        assert "primary_technique" in enriched["threat_intelligence"]["mitre_attack"]
        assert "investigation_steps" in enriched["threat_intelligence"]["recommendations"]
