#!/usr/bin/env python3
"""
End-to-End Pipeline & Concurrency Stress Test Suite
Team Neural Breach — Roles 5 & 6 Integration
"""

import json
import asyncio
import pytest
import numpy as np
import pandas as pd
import httpx
from fastapi.testclient import TestClient

from src.backend.app import app
from src.backend.alert_manager import alert_store
from src.models.inference_engine import CyberDefenseInferenceEngine


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def valid_flow_template():
    engine = CyberDefenseInferenceEngine(classifier_type="lightgbm")
    flow = {col: 0.0 for col in engine.expected_features}
    flow["Flow Duration"] = 5500000.0
    flow["Tot Fwd Pkts"] = 120.0
    flow["Tot Bwd Pkts"] = 4.0
    flow["Flow Byts/s"] = 150000.0
    flow["Protocol"] = 6.0
    flow["Init Fwd Win Byts"] = 8192.0
    return flow


class TestEndToEndPipeline:
    """Verifies end-to-end integration between Role 3, Role 5, and Role 6."""

    def test_end_to_end_alert_delivery(self, client, valid_flow_template):
        alert_store.clear()
        
        # 1. Dispatch prediction request
        payload = {
            "flows": [valid_flow_template],
            "explain": True,
            "explainer_type": "shap",
            "top_k": 5
        }
        res = client.post("/api/v1/predict", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert len(data["alerts"]) == 1
        alert = data["alerts"][0]

        # 2. Verify Observe-Only Guarantee
        assert alert["observe_only_mode"] is True
        assert alert["action_enforced"] == "NONE_OBSERVE_ONLY"

        # 3. Verify Model Prediction
        pred = alert["prediction"]
        assert "label" in pred
        assert "confidence" in pred
        assert 0.0 <= pred["confidence"] <= 1.0
        assert len(pred["probabilities"]) == 15

        # 4. Verify Dual Anomaly Detection
        anom = alert["anomaly_detection"]
        assert isinstance(anom["is_anomaly"], bool)
        assert isinstance(anom["isolation_forest_score"], float)
        assert isinstance(anom["autoencoder_recon_error"], float)

        # 5. Verify XAI Explanations
        exp = alert["explanation"]
        assert exp["method"] == "SHAP"
        assert len(exp["top_features"]) == 5
        for feat in exp["top_features"]:
            assert feat["feature"] in valid_flow_template
            assert feat["direction"] in [
                "INCREASES_ATTACK_LIKELIHOOD",
                "REDUCES_ATTACK_LIKELIHOOD",
                "SUPPORTS_BENIGN_PROFILE",
                "DEVIATES_FROM_BENIGN"
            ]
            assert len(feat["interpretation"]) > 5

        # 6. Verify MITRE ATT&CK Threat Intelligence
        threat_intel = alert["threat_intelligence"]
        mitre = threat_intel["mitre_attack"]
        assert "primary_technique" in mitre
        assert mitre["primary_technique"]["url"].startswith("https://attack.mitre.org")
        assert len(threat_intel["recommendations"]["investigation_steps"]) >= 1

        # 7. Verify Threat Priority Score
        priority = alert["threat_priority"]
        assert 0.0 <= priority["score"] <= 100.0
        assert priority["level"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        assert priority["urgency"] in ["IMMEDIATE", "HIGH", "ELEVATED", "ROUTINE", "INFORMATIONAL"]

        # 8. Verify Queryable in Alert History
        hist_res = client.get(f"/api/v1/alerts/{alert['alert_id']}")
        assert hist_res.status_code == 200
        assert hist_res.json()["alert_id"] == alert["alert_id"]


class TestWebSocketLiveStreamingDelivery:
    """Verifies that generated alerts are broadcast in real time to connected WebSockets."""

    def test_live_websocket_delivery(self, client, valid_flow_template):
        with client.websocket_connect("/ws/alerts") as ws:
            # 1. Receive initial welcome handshake
            handshake = ws.receive_text()
            assert "CONNECTED" in handshake

            # 2. Trigger an inference request via HTTP
            unique_flow = valid_flow_template.copy()
            unique_flow["Flow Duration"] = 8999999.0
            unique_flow["Tot Fwd Pkts"] = 999.0

            post_resp = client.post("/api/v1/predict", json={"flows": [unique_flow], "explain": False})
            assert post_resp.status_code == 200
            generated_alert = post_resp.json()["alerts"][0]

            # 3. Receive the streamed alert on WebSocket if it was an attack/anomaly
            if generated_alert["prediction"]["is_attack"] or generated_alert["anomaly_detection"]["is_anomaly"]:
                streamed_msg = ws.receive_text()
                alert_payload = json.loads(streamed_msg)
                assert alert_payload["alert_id"] == generated_alert["alert_id"]
                assert alert_payload["observe_only_mode"] is True


class TestConcurrencyAndBatchThroughput:
    """Stress tests concurrent requests and multi-flow batch processing."""

    def test_batch_processing_multiple_flows(self, client, valid_flow_template):
        batch_size = 25
        flows_batch = []
        for i in range(batch_size):
            f = valid_flow_template.copy()
            f["Flow Duration"] = float(i * 10000)
            flows_batch.append(f)

        resp = client.post(
            "/api/v1/predict",
            json={"flows": flows_batch, "explain": True, "explainer_type": "shap", "top_k": 3}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_flows"] == batch_size
        assert len(data["alerts"]) == batch_size

    def test_concurrent_async_requests(self, valid_flow_template):
        """Simulates 30 concurrent HTTP clients sending requests simultaneously."""
        num_requests = 30

        async def make_requests():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as async_client:
                tasks = []
                for i in range(num_requests):
                    f = valid_flow_template.copy()
                    f["Flow Duration"] = float(1000 + i * 500)
                    payload = {"flows": [f], "explain": False}
                    tasks.append(async_client.post("/api/v1/predict", json=payload))
                
                responses = await asyncio.gather(*tasks)
                for r in responses:
                    assert r.status_code == 200
                    assert r.json()["total_flows"] == 1

        asyncio.run(make_requests())
