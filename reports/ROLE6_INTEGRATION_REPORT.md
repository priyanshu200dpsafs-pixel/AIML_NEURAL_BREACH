# TEAM NEURAL BREACH — ROLE 6 INTEGRATION REPORT
## Cybersecurity Backend Service, Real-Time Detection Pipeline & SOC Alert Delivery

**Project:** AI/ML-Based Network Intrusion Detection & Threat Defense Platform  
**Team:** Neural Breach  
**Role:** Role 6 — Backend & Real-Time Detection Engineer  
**Integration Partner:** Role 5 — Explainable AI & Threat Intelligence Specialist  
**Date:** November 2026  
**Status:** Certified & Production-Integrated (Observe-Only Mode)  
**Test Pass Rate:** 100% (16/16 Backend & E2E Integration Tests Passing)  

---

### 1. Executive Summary & Core Mission

The mission of **Role 6 (Backend & Real-Time Detection)** is to bridge the team's frozen machine learning models and Role 5's Explainable AI / Threat Intelligence modules into a production-grade, low-latency cybersecurity backend service.

Key deliverables completed:
1. **High-Performance FastAPI Service:** Built a fully asynchronous API providing health-check, multi-flow prediction, historical alert querying, SOC telemetry metrics, and benchmark simulation endpoints.
2. **Frozen Model Pipeline Integration:** Ingested the pre-trained, audited models from Role 3 (LightGBM Primary Classifier, XGBoost High-Precision Candidate, PyTorch Deep Autoencoder, and Scikit-Learn Isolation Forest) with zero retraining and strict schema enforcement across 77 features.
3. **Real-Time Detection & Deduplication Pipeline:** Implemented sliding-window alert deduplication to prevent SOC alert fatigue during burst attacks while tracking `repeat_count`, `first_seen`, and `last_seen`.
4. **WebSocket Alert Streaming:** Delivered a real-time WebSocket broadcast hub (`/ws/alerts`) streaming structured alerts to active SOC analyst dashboards.
5. **Strict Observe-Only Mode Governance:** Permanently configured the platform in observe-only telemetry monitoring mode. Automated inline packet dropping is disabled and disauthorized across all routes.
6. **Role 5 Integration:** Seamlessly enriched every alert with SHAP/LIME feature attributions, verified MITRE ATT&CK tactics/techniques, transparent composite priority scores, and actionable SOC playbooks.

---

### 2. System Architecture

The Neural Breach backend operates on an asynchronous event-driven architecture designed for high throughput and zero data leakage:

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

### 3. Strict Observe-Only Mode Governance

In compliance with the project charter and ethical cybersecurity standards:
- **Zero Automated Inline Blocking:** The backend is architected exclusively for passive monitoring, real-time alert generation, and security analyst triage.
- **Mandatory Flag Enforcement:** Every health check, prediction response, alert record, and WebSocket frame includes:
  ```json
  "observe_only_mode": true,
  "action_enforced": "NONE_OBSERVE_ONLY"
  ```
- **Operational Rationale:** As documented in the Phase 4 Red-Team Audit, network flow telemetry lacks Layer-7 packet payload inspection, and tabular models exhibit known blind spots to adversarial timing dilation and payload padding. Automated packet dropping would introduce catastrophic denial of service against legitimate enterprise operations.

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
   - Explicitly omits destination port (`Dst Port`) to prevent shortcut learning and over-reliance on standard ports 21/22.
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
| `POST` | `/api/v1/predict` | Flow inference with XAI & MITRE enrichment | `PredictRequest` (flows, explain, explainer_type, top_k) | `200 OK` / `422 Unprocessable` |
| `GET` | `/api/v1/alerts` | Paginated, filtered historical alerts | `threat_level`, `attack_category`, `min_score`, `limit`, `offset` | `200 OK` |
| `GET` | `/api/v1/alerts/{id}` | Single alert detailed lookup | `alert_id` (path param) | `200 OK` / `404 Not Found` |
| `GET` | `/api/v1/stats` | SOC threat landscape & telemetry metrics | None | `200 OK` |
| `POST` | `/api/v1/alerts/simulate` | Streams authentic benchmark test flows live | `SimulationRequest` (sample_size, attack_ratio, delay, broadcast) | `200 OK` |
| `WS` | `/ws/alerts` | Live WebSocket alert broadcast feed | WebSocket Handshake | `101 Switching Protocols` |

---

### 8. Automated Verification & Stress Testing

The Role 6 backend was subjected to comprehensive automated testing across four test suites (`tests/test_role6_backend.py` and `tests/test_e2e_pipeline.py`):

#### 8.1. Summary of Test Results

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
| **E2E Integration** | `test_end_to_end_alert_delivery` | Full pipeline: raw flow $\to$ prediction $\to$ XAI $\to$ MITRE $\to$ alert. | **PASS** |
| **Live Broadcast** | `test_live_websocket_delivery` | Verifies WebSocket client receives alert pushed via HTTP predict. | **PASS** |
| **Batch Throughput**| `test_batch_processing_multiple_flows`| Processes 25 simultaneous flows with zero drops. | **PASS** |
| **Concurrency Stress**| `test_concurrent_async_requests` | 30 simultaneous asynchronous HTTP clients with 100% success. | **PASS** |

**Total Suite Result:** `16 passed in 7.45s (100% Pass Rate)`.

---

### 9. Operational Runbook & Setup Guide

#### 9.1. Prerequisites
- Python 3.10+
- Dependencies: `fastapi`, `uvicorn`, `pydantic`, `pydantic-settings`, `shap`, `lime`, `scikit-learn`, `lightgbm`, `xgboost`, `torch`, `pyarrow`, `pandas`, `numpy`, `httpx`

#### 9.2. Launching the Backend Service
From the repository root:

```bash
# Standard launch (default port 8000 on 0.0.0.0)
python3 -m src.backend.run_server

# Custom port or workers
python3 -m src.backend.run_server --host 127.0.0.1 --port 8080 --workers 2

# Direct uvicorn execution
uvicorn src.backend.app:app --host 0.0.0.0 --port 8000 --reload
```

#### 9.3. Verifying Health Check
```bash
curl -s http://localhost:8000/api/v1/health | jq .
```

#### 9.4. Dispatched Flow Prediction Example
```bash
curl -X POST http://localhost:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d '{
    "flows": [{
      "Flow Duration": 125000.0,
      "Tot Fwd Pkts": 15.0,
      "Tot Bwd Pkts": 12.0,
      "Flow Byts/s": 4500.0,
      "Protocol": 6.0
    }],
    "explain": true,
    "explainer_type": "shap",
    "top_k": 5
  }' | jq .
```

#### 9.5. Simulating Real-Time Benchmark Traffic
```bash
curl -X POST http://localhost:8000/api/v1/alerts/simulate \
  -H "Content-Type: application/json" \
  -d '{
    "sample_size": 25,
    "attack_ratio": 0.5,
    "stream_delay_seconds": 0.05,
    "broadcast_websocket": true
  }' | jq .
```

#### 9.6. Connecting to WebSocket Alert Stream
Using `wscat` or standard browser WebSocket client:
```bash
wscat -c ws://localhost:8000/ws/alerts
```

---

### 10. Sign-Off Certification
Role 6 has successfully developed, tested, and integrated the complete FastAPI backend service, real-time alert pipeline, WebSocket broadcast engine, and deduplication repository. All requirements for Roles 5 and 6 have been satisfied with 100% test pass rates and strict observe-only compliance.
