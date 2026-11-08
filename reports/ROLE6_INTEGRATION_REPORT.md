# TEAM NEURAL BREACH — ROLE 6 INTEGRATION REPORT
## Cybersecurity Backend Service, Real-Time Detection Pipeline & SOC Alert Delivery

**Project:** AI/ML-Based Network Intrusion Detection & Threat Defense Platform  
**Team:** Neural Breach  
**Role:** Role 6 — Backend & Real-Time Detection Engineer  
**Integration Partner:** Role 5 — Explainable AI & Threat Intelligence Specialist  
**Date:** November 2026  
**Status:** Certified as Research Prototype with Documented Caveats (Observe-Only Mode)  
**Test Pass Rate:** 100% (21/21 Backend & E2E Integration Tests Passing)  

---

### 1. Executive Summary & Core Mission

The mission of **Role 6 (Backend & Real-Time Detection)** is to bridge the team's frozen machine learning models and Role 5's Explainable AI / Threat Intelligence modules into a functioning, low-latency research prototype cybersecurity backend service.

Key deliverables completed:
1. **Asynchronous FastAPI Service:** Built a modern API providing health-check, multi-flow prediction, historical alert querying, SOC telemetry metrics, and benchmark simulation endpoints.
2. **Frozen Model Pipeline Integration:** Ingested the pre-trained, audited models from Role 3 (LightGBM Primary Classifier, XGBoost High-Precision Candidate, PyTorch Deep Autoencoder, and Scikit-Learn Isolation Forest) with zero retraining and strict schema enforcement across 77 features.
3. **Real-Time Detection & Deduplication Pipeline:** Implemented sliding-window alert deduplication to prevent SOC alert fatigue during burst attacks while tracking `repeat_count`, `first_seen`, and `last_seen`.
4. **WebSocket Alert Streaming:** Delivered a real-time WebSocket broadcast hub (`/ws/alerts`) streaming structured alerts to active SOC analyst dashboards.
5. **Immutable Observe-Only Invariant:** Permanently locked the platform in observe-only telemetry monitoring mode. Automated inline packet dropping is disabled and disauthorized across all routes, and `OBSERVE_ONLY_MODE` cannot be overridden via environment variables or configuration tampering.
6. **Role 5 Integration:** Seamlessly enriched every alert with SHAP/LIME feature attributions, verified MITRE ATT&CK tactics/techniques, transparent composite priority scores, and actionable SOC playbooks.

---

### 2. System Architecture

The Neural Breach backend operates on an asynchronous event-driven architecture designed for low latency and zero data leakage:

```
                                  SOC Analysts & Dashboard Clients
                               ┌───────────────────────────────────┐
                               │     Web Browser / SOC Console     │
                               └─────────▲───────────────▲─────────┘
                                         │               │
                                  REST Requests      WebSocket
                                  (HTTP / JSON)     Alert Stream
                                         │               │
  ┌──────────────────────────────────────┴───────────────┴──────────────────────────────────────┐
  │                         FASTAPI BACKEND SERVICE (src/backend/)                               │
  │                                                                                             │
  │   ┌────────────────────────┐  ┌────────────────────────┐  ┌─────────────────────────────┐   │
  │   │  API Routers & Schemas │  │ WebSocket Hub Manager  │  │   Sliding-Window Dedup      │   │
  │   │  (Pydantic V2 Models)  │  │ (Multi-Client Broadcast│  │   & LRU Alert Store         │   │
  │   └───────────┬────────────┘  └──────────▲─────────────┘  └──────────────▲──────────────┘   │
  │               │                          │                               │                  │
  │               ▼                          │                               │                  │
  │   ┌──────────────────────────────────────┴───────────────────────────────┴──────────────┐   │
  │   │                Real-Time Detection Pipeline (src/backend/pipeline.py)               │   │
  │   └──────────────────────────────────────┬─────────────────────────────────────────────┘   │
  └──────────────────────────────────────────┼─────────────────────────────────────────────────┘
                                             │
                      ┌──────────────────────┴──────────────────────┐
                      ▼                                             ▼
  ┌───────────────────────────────────────┐     ┌──────────────────────────────────────────────┐
  │   Role 3 Frozen Inference Engine      │     │  Role 5 XAI & Threat Intelligence Service    │
  │   (src/models/inference_engine.py)    │     │  (src/xai/threat_intel_service.py)           │
  │                                       │     │                                              │
  │   - 77-Feature Schema Contract        │     │  - Tree-SHAP & LIME Feature Attribution      │
  │   - LightGBM / XGBoost Multi-Class    │     │  - Autoencoder Reconstruction Attribution    │
  │   - Isolation Forest Anomaly Score    │     │  - MITRE ATT&CK STIX 2.1 Enterprise Matrix   │
  │   - PyTorch Deep Autoencoder (MSE)    │     │  - Transparent Priority Scoring (0 - 100)    │
  │   - Zero-Leakage StandardScaler       │     │  - Actionable SOC Playbooks & Hunting Queries│
  └───────────────────────────────────────┘     └──────────────────────────────────────────────┘
```

---

### 3. Strict Observe-Only Mode Governance & Fixed Invariant

In compliance with the project charter, ethical cybersecurity standards, and independent Phase 4 audit verdicts:
- **Zero Automated Inline Blocking:** The backend is architected exclusively for passive telemetry monitoring, real-time alert generation, and security analyst triage.
- **Fixed Invariant Enforcement:** `OBSERVE_ONLY_MODE` is implemented as an immutable, frozen Pydantic setting (`src/backend/config.py`). Attempting to set `NEURAL_BREACH_OBSERVE_ONLY_MODE=false` or configure `OBSERVE_ONLY_MODE=False` raises a `ValidationError` immediately, halting execution.
- **Mandatory Flag Enforcement:** Every health check, prediction response, alert record, and WebSocket frame strictly includes:
  ```json
  "observe_only_mode": true,
  "action_enforced": "NONE_OBSERVE_ONLY"
  ```
- **Operational Rationale:** As established in the Phase 4 audit, flow-level telemetry lacks Layer-7 packet payload inspection, and tabular models exhibit blind spots to adversarial timing dilation and payload padding. Automated packet dropping would introduce severe denial of service against legitimate enterprise operations.

---

### 4. Frozen Model Integration & Preprocessor Contract

The backend integrates the audited models located in `models/role3_retrain_v2/` without any retraining:

1. **Supervised Classifier:**
   - Primary: LightGBM Multi-Class Classifier (`supervised_lightgbm_primary.joblib`)
   - Candidate: XGBoost Classifier (`supervised_xgboost_benchmark.joblib`)
2. **Unsupervised Anomaly Detectors:**
   - Scikit-Learn Isolation Forest (`anomaly_isolation_forest.joblib`) calibrated at $1\%$ False Positive Rate ($\tau = -0.08063$).
   - PyTorch Deep Reconstruction Autoencoder (`anomaly_deep_autoencoder.pt`, architecture: $77 \to 48 \to 24 \to 12 \to 24 \to 48 \to 77$, calibrated threshold $\tau = 1.29126$).
3. **Feature Governance (77 Port-Agnostic Features):**
   - Enforces the strict 77-feature contract from `models/role3_retrain_v2/supervised/feature_columns.json`.
   - Explicitly omits destination port (`Dst Port`) to prevent shortcut learning on standard ports 21/22.
   - Robustly imputes missing values and mathematical infinities (`np.inf`, `-np.inf`) to `0.0` before scaling with the benign-fitted `StandardScaler`.

---

### 5. Alert Deduplication & Aggregation Engine

High-volume attacks (e.g. HOIC or UDP flood) can generate thousands of individual flow records per second, threatening to overwhelm the SOC analyst interface. 

Role 6 implements an in-memory **Sliding-Window Deduplication Engine** (`AlertManager`):
- **Cryptographic Flow Fingerprint:**
  $$\text{Signature} = \text{SHA256}(\text{Label} \,\|\, \text{Protocol} \,\|\, \lfloor \text{Duration}_{\text{sec}} \rfloor \,\|\, \text{TotFwdPkts} \,\|\, \text{Method})$$
- **Sliding Window:** Configured to $60 \text{ seconds}$ by default (`DEDUPLICATION_WINDOW_SECONDS = 60`).
- **Burst Aggregation:** If identical attack signatures arrive within the window:
  - `repeat_count` increments automatically ($N \to N + 1$).
  - `last_seen` timestamp updates to the current UTC time.
  - Alert list remains clean and free of redundant rows.
- **LRU Memory Protection:** The repository enforces a fixed ring buffer capacity ($10,000$ alerts by default) via `OrderedDict`, automatically purging the oldest alerts when memory limits are reached.

---

### 6. WebSocket Alert Streaming Hub

The backend exposes a high-throughput, asynchronous WebSocket streaming endpoint at `/ws/alerts`:
- **Protocol:** JSON-encoded frames transmitted over RFC 6455 WebSockets.
- **Connection Handshake:** On connection, the server transmits a welcome handshake declaring operational status, timestamp, and observe-only confirmation.
- **Non-Blocking Broadcasting:** Generated alerts for confirmed attacks or anomalous flows are dispatched asynchronously (`asyncio.create_task`) without stalling the incoming HTTP inference pipeline.
- **Graceful Lifecycle Management:** Detects disconnected or dropped client sockets, purges stale connections, and supports client keep-alive pings (`{"event": "PONG"}`).

---

### 7. REST API Endpoint Specifications

| Method | Endpoint | Description | Request Body / Query Params | Response Code |
| :--- | :--- | :--- | :--- | :---: |
| `GET` | `/` | Operational root verification | None | `200 OK` |
| `GET` | `/api/v1/health` | Service health, model provenance & memory stats | None | `200 OK` |
| `POST` | `/api/v1/predict` | Flow inference with XAI & MITRE enrichment | `PredictRequest` (flows, explain, explainer_type, top_k) | `200 OK` / `413 Too Large` / `422 Unprocessable` |
| `GET` | `/api/v1/alerts` | Paginated, filtered historical alerts | `threat_level`, `attack_category`, `min_score`, `limit`, `offset` | `200 OK` |
| `GET` | `/api/v1/alerts/{id}` | Single alert detailed lookup | `alert_id` (path param) | `200 OK` / `404 Not Found` |
| `GET` | `/api/v1/stats` | SOC threat landscape & telemetry metrics | None | `200 OK` |
| `POST` | `/api/v1/alerts/simulate` | Streams authentic benchmark test flows live | `SimulationRequest` (sample_size, attack_ratio, delay, broadcast, test_split_path) | `200 OK` / `503 Unavailable` |
| `WS` | `/ws/alerts` | Live WebSocket alert broadcast feed | WebSocket Handshake | `101 Switching Protocols` |

---

### 8. Automated Verification & Regression Testing

The Role 6 backend was subjected to comprehensive automated testing across four test suites (`tests/test_role6_backend.py` and `tests/test_e2e_pipeline.py`):

| Test Category | Test Case Name | Verified Behavior | Status |
| :--- | :--- | :--- | :---: |
| **Health & Contract** | `test_root_endpoint` | Confirms service name, version, and observe-only flags. | **PASS** |
| **Health & Contract** | `test_health_check_endpoint` | Validates all 5 models loaded, uptime, and 77 features. | **PASS** |
| **Prediction Pipeline** | `test_predict_single_flow_shap` | Verifies full SHAP explanation, top 5 features, and MITRE mapping. | **PASS** |
| **Prediction Pipeline** | `test_predict_with_lime` | Verifies LIME surrogate explanation routing. | **PASS** |
| **Schema Validation** | `test_predict_missing_features_rejected`| Asserts HTTP 422 structured error when columns are missing. | **PASS** |
| **Input Validation** | `test_predict_empty_flows_rejected` | Asserts HTTP 400 when empty list is posted. | **PASS** |
| **Deduplication** | `test_deduplication_repeat_count` | Asserts repeat burst flows increment `repeat_count`. | **PASS** |
| **Querying** | `test_alert_query_and_filtering` | Verifies pagination and threat level filtering. | **PASS** |
| **Alert Lookup** | `test_get_alert_by_id` | Verifies single retrieval and HTTP 404 on missing ID. | **PASS** |
| **Analytics** | `test_stats_endpoint` | Verifies SOC threat distribution and MITRE statistics. | **PASS** |
| **WebSocket** | `test_websocket_connection_and_ping` | Verifies handshake and ping/pong keep-alives. | **PASS** |
| **Benchmark Sim** | `test_simulate_stream_benchmark_flows`| Streams genuine flows from `test.parquet`. | **PASS** |
| **Hardening** | `test_observe_only_mode_invariant_override_rejection` | Asserts `ValidationError` when attempting to disable observe-only mode. | **PASS** |
| **Hardening** | `test_valid_prediction_runbook_example` | Executes complete 77-feature sample flow from `sample_valid_flow.json`. | **PASS** |
| **Hardening** | `test_missing_simulation_dataset_error_handling` | Asserts HTTP 503 and structured setup guidance when dataset absent. | **PASS** |
| **Hardening** | `test_batch_size_limit_rejection` | Asserts HTTP 413 when batch size exceeds `MAX_BATCH_SIZE` (500). | **PASS** |
| **Hardening** | `test_cors_configuration_no_wildcard` | Asserts no wildcard in CORS; restricts to explicit local dashboard origins. | **PASS** |
| **E2E Integration** | `test_end_to_end_alert_delivery` | Full pipeline: raw flow $\to$ prediction $\to$ XAI $\to$ MITRE $\to$ alert. | **PASS** |
| **Live Broadcast** | `test_live_websocket_delivery` | Verifies WebSocket client receives alert pushed via HTTP predict. | **PASS** |
| **Batch Throughput**| `test_batch_processing_multiple_flows`| Processes 25 simultaneous flows with zero drops. | **PASS** |
| **Concurrency Stress**| `test_concurrent_async_requests` | 30 simultaneous asynchronous HTTP clients with 100% success. | **PASS** |

**Role 6 Suite Result:** `21 passed in 7.33s (100% Pass Rate)`.  
**Master Project Test Suite Result:** `41 passed in 12.0s (100% Pass Rate)`.

---

### 9. Operational Runbook & Setup Guide

#### 9.1. Prerequisites & Environment
- Python 3.10+ (tested on Python 3.13.7)
- Core dependencies: `fastapi>=0.115.0`, `uvicorn>=0.30.0`, `pydantic>=2.9.0`, `pydantic-settings>=2.5.0`, `shap>=0.46.0`, `lime>=0.2.0.1`, `scikit-learn>=1.5.0`, `lightgbm>=4.5.0`, `xgboost>=1.7.0`, `torch>=2.2.0`, `pyarrow>=17.0.0`, `pandas>=2.2.0`, `numpy>=1.26.0,<3.0.0`, `httpx>=0.27.0`
- Install all dependencies via:
  ```bash
  pip install -r requirements.txt
  ```

#### 9.2. Launching the Backend Service
The server defaults strictly to `127.0.0.1` (localhost) for secure local evaluation:

```bash
# Standard launch (binds to 127.0.0.1:8000)
python3 -m src.backend.run_server

# Custom port or workers
python3 -m src.backend.run_server --host 127.0.0.1 --port 8080 --workers 2

# Direct uvicorn execution
uvicorn src.backend.app:app --host 127.0.0.1 --port 8000 --reload
```

#### 9.3. Verifying Health Check
```bash
curl -s http://127.0.0.1:8000/api/v1/health | jq .
```

#### 9.4. Dispatched Flow Prediction (Complete 77-Feature Contract)
The inference contract strictly enforces all 77 port-agnostic features. A pre-validated, label-free sample flow is provided in `scripts/sample_valid_flow.json`:

```bash
# Using the verified 77-feature sample JSON payload:
curl -X POST http://127.0.0.1:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d @scripts/sample_valid_flow.json | jq .
```

Python programmatic invocation:
```python
import json
import urllib.request

with open("scripts/sample_valid_flow.json") as f:
    payload = json.load(f)

req = urllib.request.Request(
    "http://127.0.0.1:8000/api/v1/predict",
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"}
)
with urllib.request.urlopen(req) as resp:
    result = json.loads(resp.read().decode())
    print("Alert ID:", result["alerts"][0]["alert_id"])
    print("Predicted Threat:", result["alerts"][0]["prediction"]["label"])
    print("Priority Level:", result["alerts"][0]["threat_priority"]["level"])
```

#### 9.5. Simulating Real-Time Benchmark Traffic & Dataset Requirements
The simulation endpoint replays authentic network flows from the CSE-CIC-IDS2018 test split:
- **Default Path:** `data/processed/splits/test.parquet`
- **Configurable Environment Variable:** `NEURAL_BREACH_TEST_SPLIT_PATH`
- **Request Override:** Pass `"test_split_path": "/path/to/test.parquet"` in the request body.
- **Handling Missing Dataset:** If the file is absent, the endpoint returns an HTTP 503 error with exact recovery instructions:
  ```bash
  # Synchronize processed benchmark datasets from Google Drive:
  python scripts/sync_data_drive.py
  ```

Executing simulation stream:
```bash
curl -X POST http://127.0.0.1:8000/api/v1/alerts/simulate \
  -H "Content-Type: application/json" \
  -d '{
    "sample_size": 25,
    "attack_ratio": 0.5,
    "stream_delay_seconds": 0.05,
    "broadcast_websocket": true
  }' | jq .
```

#### 9.6. Connecting to WebSocket Alert Stream
Using `wscat` or a browser dashboard WebSocket client:
```bash
wscat -c ws://127.0.0.1:8000/ws/alerts
```

#### 9.7. Security Governance: Requirements Before Remote Network Exposure
The current API service is engineered strictly as an **unauthenticated research prototype** intended for local evaluation and isolated lab testbeds:
1. **No Built-in Authentication:** The endpoints do not enforce API keys, mTLS, or OAuth2/JWT tokens.
2. **No Built-in Rate Limiting:** While in-memory deduplication mitigates alert fatigue, volumetric DDoS against the API itself is not throttled at the application layer beyond `MAX_BATCH_SIZE = 500`.
3. **Mandatory Production Architecture:** Before exposing the service beyond `127.0.0.1`, operators must:
   - Deploy behind a reverse proxy (NGINX, Envoy, Caddy, or Cloudflare).
   - Terminate TLS (HTTPS / WSS).
   - Enforce client authentication (JWT Bearer tokens or mTLS client certificates).
   - Restrict network access via firewall CIDR allowlists or VPN boundaries.

---

### 10. Final Sign-Off Verdict
Role 6 has successfully developed, hardened, tested, and integrated the complete FastAPI backend service, real-time alert pipeline, WebSocket broadcast engine, and deduplication repository. All requirements for Roles 5 and 6 have been satisfied with 100% test pass rates and strict, tamper-proof observe-only compliance.
