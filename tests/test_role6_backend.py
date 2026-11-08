#!/usr/bin/env python3
"""
Automated Test Suite for Role 6: Backend & Real-Time Detection
Team Neural Breach — AI/ML Cyber Defense Platform
"""

import asyncio
import pytest
import numpy as np
import pandas as pd
from fastapi.testclient import TestClient

from src.backend.app import app
from src.backend.alert_manager import alert_store
from src.models.inference_engine import CyberDefenseInferenceEngine


@pytest.fixture(scope="module")
def client():
    """FastAPI TestClient with lifespan context execution."""
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def sample_valid_flow():
    """Returns a valid 77-feature dictionary."""
    engine = CyberDefenseInferenceEngine(classifier_type="lightgbm")
    # Clean zero-valued baseline with a few populated fields
    flow = {col: 0.0 for col in engine.expected_features}
    flow["Flow Duration"] = 125000.0
    flow["Tot Fwd Pkts"] = 15.0
    flow["Tot Bwd Pkts"] = 12.0
    flow["Flow Byts/s"] = 4500.0
    flow["Protocol"] = 6.0
    return flow


class TestRole6BackendHealthAndContract:
    """Verifies health check, model loading, and observe-only mode enforcement."""

    def test_root_endpoint(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["observe_only_mode"] is True
        assert data["action_enforced"] == "NONE_OBSERVE_ONLY"

    def test_health_check_endpoint(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "HEALTHY"
        assert data["observe_only_mode"] is True
        assert data["action_enforced"] == "NONE_OBSERVE_ONLY"
        assert data["expected_features_count"] == 77
        assert data["models_loaded"]["supervised_classifier"] is True
        assert data["models_loaded"]["isolation_forest"] is True
        assert data["models_loaded"]["deep_autoencoder"] is True
        assert data["models_loaded"]["scaler"] is True
        assert data["uptime_seconds"] >= 0.0


class TestPredictionPipeline:
    """Tests inference, schema validation, and XAI integration."""

    def test_predict_single_flow_shap(self, client, sample_valid_flow):
        payload = {
            "flows": [sample_valid_flow],
            "explain": True,
            "explainer_type": "shap",
            "top_k": 5
        }
        response = client.post("/api/v1/predict", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["total_flows"] == 1
        assert data["observe_only_mode"] is True
        assert len(data["alerts"]) == 1

        alert = data["alerts"][0]
        assert "alert_id" in alert
        assert alert["observe_only_mode"] is True
        assert alert["action_enforced"] == "NONE_OBSERVE_ONLY"
        assert "prediction" in alert
        assert "threat_priority" in alert
        assert "explanation" in alert
        assert alert["explanation"]["method"] == "SHAP"
        assert len(alert["explanation"]["top_features"]) == 5
        assert "threat_intelligence" in alert
        assert "primary_technique" in alert["threat_intelligence"]["mitre_attack"]
        assert "recommendations" in alert["threat_intelligence"]

    def test_predict_with_lime(self, client, sample_valid_flow):
        payload = {
            "flows": [sample_valid_flow],
            "explain": True,
            "explainer_type": "lime",
            "top_k": 5
        }
        response = client.post("/api/v1/predict", json=payload)
        assert response.status_code == 200
        data = response.json()
        alert = data["alerts"][0]
        assert alert["explanation"]["method"] == "LIME"

    def test_predict_missing_features_rejected(self, client, sample_valid_flow):
        # Create invalid flow missing required columns
        corrupted_flow = sample_valid_flow.copy()
        del corrupted_flow["Flow Duration"]
        del corrupted_flow["Protocol"]

        payload = {"flows": [corrupted_flow]}
        response = client.post("/api/v1/predict", json=payload)
        assert response.status_code == 422
        data = response.json()
        assert "detail" in data
        assert "SchemaValidationViolation" in str(data)

    def test_predict_empty_flows_rejected(self, client):
        response = client.post("/api/v1/predict", json={"flows": []})
        assert response.status_code == 400


class TestAlertDeduplicationAndStorage:
    """Verifies alert repository, deduplication, and querying."""

    def test_deduplication_repeat_count(self, client, sample_valid_flow):
        alert_store.clear()
        payload = {"flows": [sample_valid_flow]}

        # Send same flow twice in burst
        resp1 = client.post("/api/v1/predict", json=payload)
        assert resp1.status_code == 200
        alert1 = resp1.json()["alerts"][0]
        assert alert1["repeat_count"] == 1

        resp2 = client.post("/api/v1/predict", json=payload)
        assert resp2.status_code == 200
        alert2 = resp2.json()["alerts"][0]

        # Should be deduplicated into existing alert
        assert alert2["repeat_count"] >= 2
        assert alert2["alert_id"] == alert1["alert_id"]
        # In-memory store should contain only 1 distinct alert
        assert alert_store.total_alerts_generated == 1
        assert alert_store.total_flows_evaluated == 2

    def test_alert_query_and_filtering(self, client, sample_valid_flow):
        # Fetch alerts
        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert "alerts" in data
        assert data["total_matching"] >= 1

        # Test filtering by limit
        resp_lim = client.get("/api/v1/alerts?limit=1")
        assert resp_lim.status_code == 200
        assert len(resp_lim.json()["alerts"]) <= 1

    def test_get_alert_by_id(self, client, sample_valid_flow):
        # Get existing alert ID
        resp = client.get("/api/v1/alerts")
        alerts = resp.json()["alerts"]
        assert len(alerts) > 0
        aid = alerts[0]["alert_id"]

        resp_single = client.get(f"/api/v1/alerts/{aid}")
        assert resp_single.status_code == 200
        assert resp_single.json()["alert_id"] == aid

        # Non-existent ID returns 404
        resp_404 = client.get("/api/v1/alerts/NON_EXISTENT_ID")
        assert resp_404.status_code == 404

    def test_stats_endpoint(self, client):
        resp = client.get("/api/v1/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_flows_evaluated" in data
        assert "alerts_by_threat_level" in data
        assert "top_mitre_techniques" in data
        assert data["observe_only_mode"] is True


class TestWebSocketStream:
    """Verifies WebSocket real-time connectivity and handshake."""

    def test_websocket_connection_and_ping(self, client):
        with client.websocket_connect("/ws/alerts") as ws:
            # Receive initial connection handshake
            handshake_text = ws.receive_text()
            assert "CONNECTED" in handshake_text
            assert "Observe-Only Mode" in handshake_text

            # Test ping/pong
            ws.send_text("ping")
            pong = ws.receive_text()
            assert "PONG" in pong


class TestSimulationStream:
    """Verifies streaming simulation against authentic benchmark test partition."""

    def test_simulate_stream_benchmark_flows(self, client):
        payload = {
            "sample_size": 5,
            "attack_ratio": 0.6,
            "stream_delay_seconds": 0.0,
            "broadcast_websocket": False
        }
        resp = client.post("/api/v1/alerts/simulate", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "COMPLETED"
        assert data["sample_size"] == 5
        assert len(data["alerts"]) == 5
        assert data["observe_only_mode"] is True
