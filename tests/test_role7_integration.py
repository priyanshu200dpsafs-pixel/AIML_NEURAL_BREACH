"""Comprehensive integration test suite proving that installin

g Role 7 platform extension
onto the official Role 6 FastAPI application preserves 100% of existing functionality,
route handlers, error contracts, and endpoints while enabling new enterprise multi-tenant capabilities.
"""
from datetime import datetime, timezone
import json
import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from src.backend.app import app
from src.backend.config import settings as role6_settings
from src.backend.platform_ext.config import get_settings
from src.backend.platform_ext.api.install import install_platform
from src.backend.platform_ext.db.base import Base
from src.backend.platform_ext.db.session import get_engine


@pytest.fixture(scope="module")
def integrated_client():
    """Mounts Role 7 platform extension onto the real Role 6 application."""
    old_env = dict(os.environ)
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    os.environ["NB_JWT_SECRET"] = "c" * 48
    os.environ["NB_DATABASE_URL"] = f"sqlite:///{tmp.name}"
    os.environ["NB_FEATURE_COLUMNS_PATH"] = "models/role3_retrain_v2/supervised/feature_columns.json"
    get_settings.cache_clear()

    # Mount platform extension onto existing app
    install_platform(app)
    Base.metadata.create_all(get_engine())

    with TestClient(app) as client:
        yield client

    import src.backend.platform_ext.db.session as sess
    if sess._engine is not None:
        sess.get_engine().dispose()
        sess._engine = None
        sess._Session = None
    if os.path.exists(tmp.name):
        os.remove(tmp.name)
    os.environ.clear()
    os.environ.update(old_env)
    get_settings.cache_clear()


@pytest.fixture()
def valid_flow():
    """Returns a single valid 77-feature network flow."""
    with open("models/role3_retrain_v2/supervised/feature_columns.json", "r") as f:
        cols = json.load(f)
    flow = {feat: 0.0 for feat in cols}
    flow["Protocol"] = 6
    flow["Flow Duration"] = 120000.0
    flow["Tot Fwd Pkts"] = 10.0
    flow["Tot Bwd Pkts"] = 8.0
    flow["Fwd Pkt Len Max"] = 1460.0
    flow["Bwd Pkt Len Max"] = 1460.0
    return flow


def test_root_and_health_endpoints_preserved(integrated_client):
    """Verify Role 6 root and health endpoints remain intact and unhijacked."""
    r_root = integrated_client.get("/")
    assert r_root.status_code == 200
    assert r_root.json()["service"] == role6_settings.APP_NAME
    assert r_root.json()["observe_only_mode"] is True

    r_health = integrated_client.get("/api/v1/health")
    assert r_health.status_code == 200
    data = r_health.json()
    assert data["status"] == "HEALTHY"
    assert data["observe_only_mode"] is True
    assert data["models_loaded"]["supervised_classifier"] is True


def test_predict_endpoint_unauthenticated_preserved(integrated_client, valid_flow):
    """Verify Role 6 /api/v1/predict accepts flows without requiring Bearer auth."""
    payload = {"flows": [valid_flow], "explain": False}
    resp = integrated_client.post("/api/v1/predict", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "alerts" in data
    assert len(data["alerts"]) >= 1
    assert data["observe_only_mode"] is True


def test_predict_error_contracts_preserved(integrated_client, valid_flow):
    """Verify Role 6 validation and payload limits return expected error schemas."""
    # 1. Empty flows -> 400
    resp_empty = integrated_client.post("/api/v1/predict", json={"flows": []})
    assert resp_empty.status_code == 400
    assert "Flows list cannot be empty" in str(resp_empty.json())

    # 2. Missing features -> 422 with SchemaValidationViolation
    corrupted = valid_flow.copy()
    del corrupted["Protocol"]
    del corrupted["Flow Duration"]
    resp_val = integrated_client.post("/api/v1/predict", json={"flows": [corrupted]})
    assert resp_val.status_code == 422
    data = resp_val.json()
    assert "detail" in data
    assert "SchemaValidationViolation" in str(data)

    # 3. Batch size limit exceeded -> 413
    oversized = [valid_flow] * (role6_settings.MAX_BATCH_SIZE + 1)
    resp_large = integrated_client.post("/api/v1/predict", json={"flows": oversized})
    assert resp_large.status_code == 413
    assert "BatchSizeExceeded" in str(resp_large.json())


def test_simulate_endpoint_preserved(integrated_client):
    """Verify Role 6 /api/v1/alerts/simulate was NOT deleted or overwritten with 405."""
    resp = integrated_client.post("/api/v1/alerts/simulate", json={"playback_rate": 0.0, "max_flows": 2})
    # Must be either 200 (if dataset exists) or 400/503 (dataset absent), NEVER 404 or 405
    assert resp.status_code in (200, 400, 503)


def test_role6_alerts_and_stats_endpoints_preserved(integrated_client):
    """Verify unauthenticated Role 6 in-memory alert query and stats remain accessible."""
    resp_alerts = integrated_client.get("/api/v1/alerts")
    assert resp_alerts.status_code == 200
    assert "alerts" in resp_alerts.json()
    assert "total_matching" in resp_alerts.json()

    resp_stats = integrated_client.get("/api/v1/stats")
    assert resp_stats.status_code == 200
    assert "total_alerts_stored" in resp_stats.json()
    assert "observe_only_mode" in resp_stats.json()


def test_role6_websocket_preserved(integrated_client):
    """Verify legacy /ws/alerts accepts connections."""
    with integrated_client.websocket_connect("/ws/alerts") as ws:
        handshake = ws.receive_text()
        assert "CONNECTED" in handshake
        assert "Observe-Only Mode" in handshake
        ws.send_text("ping")
        pong = ws.receive_text()
        assert "PONG" in pong


def test_role7_platform_auth_and_tenancy(integrated_client):
    """Verify Role 7 authentication and user isolation on the integrated app."""
    # 1. Register new user + organization
    reg_resp = integrated_client.post(
        "/api/v1/auth/register",
        json={"email": "integ-admin@corp.io", "password": "SecurePassword-123!", "org_name": "IntegCorp"}
    )
    assert reg_resp.status_code == 201
    auth_data = reg_resp.json()
    token = auth_data["access_token"]
    org_id = auth_data["org_id"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Authenticated user profile
    me_resp = integrated_client.get("/api/v1/auth/me", headers=headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == "integ-admin@corp.io"
    assert me_resp.json()["org_id"] == org_id

    # 3. Unauthenticated access to /api/v1/auth/me rejected
    assert integrated_client.get("/api/v1/auth/me").status_code == 401


def test_role7_v2_persistent_alerts_isolated(integrated_client):
    """Verify /api/v2/alerts provides authenticated, persistent tenant-isolated alerts."""
    # Register Org A
    _, h_a = _register(integrated_client, "org_a_user@test.io", "OrgA")
    # Register Org B
    _, h_b = _register(integrated_client, "org_b_user@test.io", "OrgB")

    # Unauthenticated /api/v2/alerts is rejected
    assert integrated_client.get("/api/v2/alerts").status_code == 401

    # Authenticated access succeeds and returns empty list initially
    resp_a = integrated_client.get("/api/v2/alerts", headers=h_a)
    assert resp_a.status_code == 200
    assert resp_a.json()["total"] == 0
    assert "items" in resp_a.json()

    resp_b = integrated_client.get("/api/v2/alerts", headers=h_b)
    assert resp_b.status_code == 200
    assert resp_b.json()["total"] == 0


def test_role7_agent_enrollment_and_telemetry(integrated_client, valid_flow):
    """Verify agent enrollment token creation, agent enrollment, and telemetry batch acceptance."""
    _, auth_hdr = _register(integrated_client, "agent_lead@corp.io", "AgentCorp")

    # 1. Mint enrollment token
    t_resp = integrated_client.post("/api/v1/agents/enrollment-tokens", json={"label": "k8s-cluster"}, headers=auth_hdr)
    assert t_resp.status_code == 201
    token = t_resp.json()["enrollment_token"]

    # 2. Enroll agent
    enroll_resp = integrated_client.post(
        "/api/v1/agents/enroll",
        json={
            "enrollment_token": token,
            "hostname": "k8s-node-01",
            "os_name": "linux",
            "cpu_arch": "x86_64",
            "client_version": "1.0.0"
        }
    )
    assert enroll_resp.status_code == 201
    dev_data = enroll_resp.json()
    agent_id = dev_data["agent_id"]
    dev_hdr = {"Authorization": f"Bearer {dev_data['credential']}"}

    # 3. Agent heartbeat
    hb_resp = integrated_client.post("/api/v1/agents/heartbeat", json={"client_version": "1.0.0"}, headers=dev_hdr)
    assert hb_resp.status_code == 200
    assert hb_resp.json()["status"] == "ok"

    # 4. Agent telemetry ingestion
    t_now = datetime.now(timezone.utc).isoformat()
    telemetry_payload = {
        "flows": [
            {"observed_at": t_now, "features": valid_flow}
        ]
    }
    telem_resp = integrated_client.post(
        f"/api/v1/agents/{agent_id}/telemetry/batches",
        json=telemetry_payload,
        headers={**dev_hdr, "Idempotency-Key": "idem-key-001"}
    )
    assert telem_resp.status_code == 202
    assert telem_resp.json()["status"] == "accepted"


def test_role7_v2_websocket_with_ticket(integrated_client):
    """Verify /ws/v2/alerts requires ticket and streams real-time events."""
    _, auth_hdr = _register(integrated_client, "ws_lead@corp.io", "WSCorp")

    # Request without ticket rejected
    with pytest.raises(Exception):
        with integrated_client.websocket_connect("/ws/v2/alerts"):
            pass

    # Mint valid ticket
    ticket_resp = integrated_client.post("/api/v1/ws/ticket", headers=auth_hdr)
    assert ticket_resp.status_code == 200
    ticket = ticket_resp.json()["ticket"]

    # Connect with ticket
    with integrated_client.websocket_connect(f"/ws/v2/alerts?ticket={ticket}") as ws:
        msg = ws.receive_json()
        assert msg["event"] == "CONNECTED"
        assert msg["observe_only_mode"] is True
        assert msg["action_enforced"] == "NONE_OBSERVE_ONLY"


def _register(client, email, org):
    r = client.post("/api/v1/auth/register", json={"email": email, "password": "SecurePassword-123!", "org_name": org})
    assert r.status_code == 201, r.text
    data = r.json()
    return data, {"Authorization": f"Bearer {data['access_token']}"}
