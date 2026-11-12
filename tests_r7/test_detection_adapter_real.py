"""Integration test verifying Role6DetectionAdapter with real frozen models,
real SHAP/LIME explainability, MITRE ATT&CK mapping, and alert database persistence.
"""
from datetime import datetime, timezone
import os
import tempfile
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.backend.platform_ext.adapters.detection_adapter import Role6DetectionAdapter, create_detection_adapter
from src.backend.platform_ext.db.base import Base
from src.backend.platform_ext.db.models import Organization, Device, TelemetryBatch, Job, Alert, NetworkFlow
from src.backend.platform_ext.services.alert_service import upsert_alert, serialize
from src.backend.platform_ext.services.worker import _process


@pytest.fixture(scope="module")
def real_adapter():
    """Load real adapter with frozen models and STIX data."""
    adapter = create_detection_adapter(classifier_type="lightgbm", fpr_budget="1pct")
    return adapter


@pytest.fixture()
def db_session():
    """Create isolated SQLite database for testing adapter persistence."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    engine = create_engine(f"sqlite:///{tmp.name}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    yield session

    session.close()
    engine.dispose()
    if os.path.exists(tmp.name):
        os.remove(tmp.name)


def test_real_adapter_initialization_and_contract(real_adapter):
    """Verify adapter loaded all 77 required features from frozen model."""
    assert len(real_adapter.expected_features) == 77
    assert "Flow Duration" in real_adapter.expected_features
    assert "Protocol" in real_adapter.expected_features
    assert real_adapter.engine.classifier is not None
    assert real_adapter.threat_service is not None


def test_real_adapter_rejects_missing_features(real_adapter):
    """Verify adapter enforces strict 77-feature contract validation."""
    incomplete_flow = {"Protocol": 6, "Flow Duration": 1000}
    with pytest.raises(ValueError, match="SchemaValidationViolation"):
        real_adapter.process([incomplete_flow])


def test_real_adapter_executes_real_inference_and_xai(real_adapter):
    """Execute real inference against frozen models and verify XAI + MITRE enrichment."""
    # Synthetic suspicious flow structured with all 77 features
    attack_flow = {feat: 0.0 for feat in real_adapter.expected_features}
    attack_flow["Protocol"] = 6
    attack_flow["Flow Duration"] = 5000000.0
    attack_flow["Tot Fwd Pkts"] = 50.0
    attack_flow["Tot Bwd Pkts"] = 0.0
    attack_flow["Fwd Pkt Len Max"] = 1460.0
    attack_flow["Flow Byts/s"] = 15000000.0

    results = real_adapter.process([attack_flow])

    # Must produce at least one alert for attack traffic
    assert len(results) >= 1
    res = results[0]

    assert "flow_index" in res
    assert "label" in res
    assert "attack_category" in res
    assert "threat_level" in res
    assert "priority_score" in res
    assert "payload" in res

    payload = res["payload"]
    # Verify observe-only invariant
    assert payload["observe_only_mode"] is True
    assert payload["action_enforced"] == "NONE_OBSERVE_ONLY"

    # Verify real prediction details
    assert "prediction" in payload
    assert payload["prediction"]["is_attack"] is True
    assert payload["prediction"]["confidence"] > 0.0
    assert "probabilities" in payload["prediction"]

    # Verify real XAI explanation structure
    assert "explanation" in payload
    assert payload["explanation"]["method"] == "SHAP"
    assert len(payload["explanation"]["top_features"]) > 0
    top_feature = payload["explanation"]["top_features"][0]
    assert "feature" in top_feature
    assert "importance" in top_feature
    assert "direction" in top_feature

    # Verify real MITRE ATT&CK mapping
    assert "threat_intelligence" in payload
    threat_intel = payload["threat_intelligence"]
    assert "mitre_attack" in threat_intel
    mitre = threat_intel["mitre_attack"]
    assert len(mitre.get("tactics", [])) > 0
    assert "primary_technique" in mitre


def test_real_adapter_worker_job_end_to_end_persistence(real_adapter, db_session):
    """Verify that a worker job processes a real batch and persists alerts to database."""
    now_utc = datetime.now(timezone.utc)
    # 1. Setup tenant and device
    org = Organization(id="org-test-1", name="Test Org", created_at=now_utc)
    dev = Device(
        id="dev-test-1",
        org_id=org.id,
        hostname="sensor-1",
        os_name="linux",
        cpu_arch="x86_64",
        client_version="1.0.0",
        created_at=now_utc
    )
    db_session.add_all([org, dev])
    db_session.commit()

    # 2. Setup batch with attack flow
    attack_flow = {feat: 0.0 for feat in real_adapter.expected_features}
    attack_flow["Protocol"] = 6
    attack_flow["Flow Duration"] = 5000000.0
    attack_flow["Tot Fwd Pkts"] = 100.0

    batch = TelemetryBatch(
        id="batch-test-1",
        org_id=org.id,
        device_id=dev.id,
        idempotency_key="idem-1",
        payload_sha256="fake-hash",
        flow_count=1,
        status="accepted",
        received_at=now_utc
    )
    flow_row = NetworkFlow(
        id=1,
        org_id=org.id,
        device_id=dev.id,
        batch_id=batch.id,
        seq=0,
        observed_at=now_utc,
        features=attack_flow
    )
    job = Job(
        id="job-test-1",
        kind="infer_batch",
        org_id=org.id,
        batch_id=batch.id,
        status="queued",
        run_after=now_utc,
        created_at=now_utc
    )
    db_session.add_all([batch, flow_row, job])
    db_session.commit()

    # 3. Execute worker processing logic
    n_alerts = _process(db_session, job, real_adapter)
    db_session.commit()

    assert n_alerts >= 1
    assert batch.status == "processed"

    # 4. Verify persistent alert query
    saved_alert = db_session.query(Alert).filter(Alert.org_id == org.id, Alert.device_id == dev.id).first()
    assert saved_alert is not None
    assert saved_alert.label != "Benign"
    assert saved_alert.threat_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert saved_alert.repeat_count == 1
    assert saved_alert.payload["observe_only_mode"] is True

    # 5. Verify serialization
    data = serialize(saved_alert)
    assert data["alert_id"] == saved_alert.id
    assert data["org_id"] == org.id
    assert data["details"]["observe_only_mode"] is True
