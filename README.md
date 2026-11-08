# AI/ML-Based Cyber Defense Platform: Neural Breach
**Team**: Neural Breach  
**Project**: AI/ML-Based Network Intrusion Detection & Real-Time Threat Defense Platform  
**Target Environment**: Python 3.10+ (tested on Python 3.13.7) | FastAPI | SHAP | LIME | LightGBM | XGBoost | PyTorch | PyArrow | Scikit-learn  
**Cloud Storage**: Google Drive Shared Repository ([Shared Link](https://drive.google.com/drive/folders/1UHwqXR3qM-OHZc5nHNgkAVJ_Ewl_9Rha?usp=sharing))  
**Mode**: Observe-Only Threat Detection & SOC Triage (Immutable Invariant)

---

## 1. Executive Summary

This repository houses the complete, end-to-end, multi-stage cybersecurity platform engineered by **Team Neural Breach**. The platform integrates rigorous data engineering, machine learning threat detection models, adversarial red-team auditing, explainable AI (SHAP/LIME), MITRE ATT&CK threat intelligence, and a production-grade FastAPI real-time SOC streaming backend.

### Core Capabilities Across Platform Roles:
1. **Role 1 & 2 — Data Engineering & Preprocessing:** Verified multi-million flow data foundation (CSE-CIC-IDS2018, UNSW-NB15, CTU-13), strict leakage-free temporal and group-aware splitting, schema harmonization, Scapy PCAP flow extraction, and automated Google Drive synchronization.
2. **Role 3 — Supervised & Unsupervised Detection Models:** Frozen trained models covering LightGBM/XGBoost supervised multi-class threat classifiers and deep Autoencoder/Isolation Forest unsupervised anomaly detectors with calibrated operational thresholds.
3. **Role 4 — Model Evaluation & Red-Team Audit:** Rigorous empirical evaluation across zero-day attacks, evasion perturbations, distribution shifts, latency/throughput profiling, and independent release gate certification.
4. **Role 5 — Explainable AI (XAI) & Threat Intelligence:** Dual-mode feature attribution (Tree-SHAP and LIME tabular surrogates) plus Autoencoder reconstruction loss decomposition; verified mapping of all 15 attack classes and statistical anomalies to MITRE ATT&CK Enterprise tactics and techniques with explicit semantic accuracy annotations (`CONFIRMED_FLOW_SIGNATURE`, `UNCONFIRMED_FLOW_SURROGATE`, `UNCONFIRMED_GENERIC_ANOMALY`); transparent 0–100 threat prioritization scoring and SOC triage playbooks.
5. **Role 6 — Backend & Real-Time Detection Engine:** High-performance asynchronous FastAPI service (`127.0.0.1:8000`), real-time alert ingestion and batching, in-memory alert repository with SHA-256 deduplication and repeat count burst tracking, bi-directional WebSocket live streaming (`/ws/alerts`), authentic CSE-CIC-IDS2018 benchmark traffic simulation, and strict observe-only invariant enforcement (`NONE_OBSERVE_ONLY`).

---

## 2. Repository Structure

```
aiml_project_team_neural_breach/
├── README.md                                  <- Master project architecture & evaluation guide
├── TEAM_DATASET_ACCESS_GUIDE.md               <- Data access, schema reference, and team onboarding
├── ROLE5_IMPLEMENTATION_REPORT.md             <- Role 5 XAI, MITRE ATT&CK & Prioritization report
├── ROLE6_INTEGRATION_REPORT.md                <- Role 6 Backend, WebSocket & Streaming report
├── requirements.txt                           <- Complete project runtime dependencies
├── pytest.ini                                 <- Pytest test configuration and testpaths
├── scripts/                                   <- Automation, setup & synchronization utilities
│   ├── sync_data_drive.py                     <- Google Drive dataset resolver and synchronization
│   ├── setup_mitre_data.py                    <- MITRE ATT&CK STIX 2.1 Enterprise bundle downloader
│   ├── sample_valid_flow.json                 <- Validated 77-feature label-free sample flow for runbooks
│   └── compute_dedup_per_class.py             <- Per-class deduplication & integrity calculator
├── src/                                       <- Production source code
│   ├── backend/                               <- Role 6: FastAPI detection backend & services
│   │   ├── app.py                             <- FastAPI application, routes, CORS & error handlers
│   │   ├── config.py                          <- Pydantic settings with immutable observe-only invariant
│   │   ├── pipeline.py                        <- End-to-end detection, inference & simulation pipeline
│   │   ├── alert_manager.py                   <- Alert repository, cryptographic deduplication & query
│   │   ├── websocket_manager.py               <- Real-time WebSocket connection hub & broadcaster
│   │   ├── schemas.py                         <- Pydantic request/response schemas & contracts
│   │   └── run_server.py                      <- CLI server launcher (defaults to 127.0.0.1:8000)
│   ├── xai/                                   <- Role 5: Explainable AI & Threat Intelligence
│   │   ├── explainer.py                       <- Tree-SHAP, LIME surrogate & Autoencoder attribution
│   │   ├── mitre_mapper.py                    <- Verified STIX 2.1 catalog & semantic accuracy ratings
│   │   ├── prioritization.py                  <- Threat priority composite scorer (0-100) & playbooks
│   │   └── threat_intel_service.py            <- Unified contract service connecting XAI to backend
│   ├── models/                                <- Role 3 & 4: Inference, evaluation & audit engines
│   │   ├── inference_engine.py                <- Multi-model unified inference engine
│   │   ├── metrics_engine.py                  <- Performance metrics & evaluation calculator
│   │   ├── dataset_manager.py                 <- Partition loader and batch generator
│   │   ├── role4_redteam_eval.py              <- Red-team robustness & perturbation evaluator
│   │   ├── run_final_acceptance_audit.py      <- Independent final release gate auditor
│   │   └── train_retrain_v2.py                <- Model retraining pipeline
│   └── data/
│       └── preprocessing/                     <- Role 2: Data engineering and extraction modules
│           ├── csv_validator.py               <- Chunked CSV ingestion & schema validation
│           ├── feature_policy.py              <- Feature governance & 77 port-agnostic feature policy
│           ├── preprocess_cse.py              <- Streaming CSE-CIC-IDS2018 processor
│           ├── preprocess_unsw.py             <- Partitioned UNSW-NB15 processor
│           ├── pcap_extractor.py              <- Scapy bidirectional PCAP flow extractor
│           ├── numerical_pipeline.py          <- Leakage-free fit-on-train transformer
│           └── telemetry_parsers.py           <- Isolated parsers for DNS, Red Team, EVTX, STIX
├── models/                                    <- Frozen, certified model artifacts & encoders
│   ├── role3_retrain_v2/                      <- Primary certified model artifacts (V2)
│   │   ├── supervised/                        <- LightGBM, XGBoost, Random Forest, HistGBT models
│   │   └── anomaly/                           <- Deep Autoencoder PyTorch & Isolation Forest models
│   ├── role3_corrected/                       <- Model correction round artifacts
│   └── role3_real_data/                       <- Baseline model artifacts
├── tests/                                     <- Comprehensive automated test suite (41 tests)
│   ├── test_role6_backend.py                  <- Role 6 backend, health, predict, stream, regression (17 tests)
│   ├── test_role5_xai.py                      <- Role 5 SHAP, LIME, MITRE STIX, priority contract (11 tests)
│   ├── test_e2e_pipeline.py                   <- Role 5/6 end-to-end integration & concurrency (4 tests)
│   └── test_preprocessing.py                  <- Role 2 data pipeline & extraction tests (9 tests)
├── reports/                                   <- Engineering deliverables & audit documentation
│   ├── ROLE5_IMPLEMENTATION_REPORT.md         <- Comprehensive Role 5 deliverable report
│   ├── ROLE6_INTEGRATION_REPORT.md            <- Comprehensive Role 6 deliverable report
│   ├── final_acceptance/                      <- Final multi-role acceptance audit & release gate
│   ├── model_evaluation/                      <- Role 4 red-team evaluation reports
│   ├── model_training/                        <- Role 3 training summaries and model cards
│   ├── data_preprocessing/                    <- Role 2 preprocessor & QA audit deliverables
│   └── dataset_audit/                         <- Phase 1 raw collection audits
└── data/                                      <- Reference metadata & documentation
    ├── documentation/                         <- Data taxonomy, licensing, and legal specs
    ├── manifests/                             <- Cryptographic SHA-256 inventories
    └── reference/MITRE-ATT-CK/                <- STIX 2.1 documentation & setup guide
```

---

## 3. Verified Dataset Inventory

| Dataset | Format | Extracted / Verified Scope | Records / Packets | Key Attack Categories |
| :--- | :--- | :--- | :---: | :--- |
| **CSE-CIC-IDS2018** | Parquet / CSV | 10 Daily Captures (CICFlowMeter) | **16,232,943 flows** | DDoS (HOIC, LOIC), DoS (Hulk, SlowHTTPTest, GoldenEye), BruteForce (SSH, FTP), Botnet, Infiltration |
| **UNSW-NB15** | Parquet / CSV | Benchmark Train & Test Partitions | **257,673 flows** | Synthetic and real modern attacks (Generic, Exploits, Fuzzers, Reconnaissance, DoS) |
| **CTU-13 Scenario 1**| Parquet / PCAP| Raw Capture & Bidirectional Flows | **323,154 packets / 14,521 flows**| Active Neris Botnet C&C, IRC, and HTTP communication |
| **LANL Cyber1** | Parquet / GZ | Red Team Adversary Timeline | **749 events** | Internal lateral movement, credential abuse, and host compromise events |
| **LANL Cyber1** | GZIP CSV | Enterprise DNS Lookups | 100k sampled | Internal enterprise DNS resolution query patterns |
| **Windows EVTX** | ZIP Archive | 432 Host Event Log Files | 2.1 GB uncompressed | Binary XML security event logs from AWS testbed endpoints |
| **MITRE ATT&CK** | STIX 2.1 JSON | Enterprise, Mobile, ICS Matrices | 31,940 objects | Comprehensive adversarial TTPs and mitigation mapping |

---

## 4. Quick Start & Operational Runbook

### 4.1. Installation & Environment
```bash
# Clone the repository
git clone https://github.com/priyanshu200dpsafs-pixel/AIML_NEURAL_BREACH.git
cd AIML_NEURAL_BREACH

# Install dependencies (Python 3.10+ required)
pip install -r requirements.txt

# (Optional) Download upstream MITRE STIX 2.1 bundle (in-code catalog operates independently)
python scripts/setup_mitre_data.py

# (Optional) Synchronize benchmark processed datasets from Google Drive for simulation
python scripts/sync_data_drive.py
```

### 4.2. Launching the Real-Time Detection Backend
The development server defaults strictly to `127.0.0.1` (localhost) with explicit dashboard CORS allowlists:

```bash
# Launch server via CLI module
python3 -m src.backend.run_server

# Or direct uvicorn launch
uvicorn src.backend.app:app --host 127.0.0.1 --port 8000
```

### 4.3. Dispatched Prediction (77-Feature Contract)
A pre-validated, label-free 77-feature sample flow is provided in `scripts/sample_valid_flow.json`:

```bash
# Dispatched inference with Tree-SHAP explanation & MITRE threat enrichment
curl -X POST http://127.0.0.1:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d @scripts/sample_valid_flow.json | jq .
```

### 4.4. Streaming Traffic Simulation
```bash
# Stream 25 authentic flows from CSE-CIC-IDS2018 test split to live WebSockets
curl -X POST http://127.0.0.1:8000/api/v1/alerts/simulate \
  -H "Content-Type: application/json" \
  -d '{
    "sample_size": 25,
    "attack_ratio": 0.5,
    "stream_delay_seconds": 0.05,
    "broadcast_websocket": true
  }' | jq .
```

---

## 5. Automated Verification & Testing

Execute the complete master automated test suite:

```bash
pytest -v
```

**Master Test Suite Status**: `41 passed in 6.43s (100% Pass Rate)`

| Test Suite | File | Tests | Coverage Scope | Status |
| :--- | :--- | :---: | :--- | :---: |
| **Role 6 Backend** | `tests/test_role6_backend.py` | **17** | Health check, SHAP/LIME prediction, missing feature rejection, deduplication bursts, alert query/filter, stats, WebSocket handshake, simulation stream, observe-only invariant enforcement, runbook validation, missing data 503 handling, batch size limits (HTTP 413), CORS origins. | **PASS** |
| **Role 5 XAI & Threat Intel** | `tests/test_role5_xai.py` | **11** | STIX 2.1 verification, 15-class MITRE mapping, anomaly mapping, semantic accuracy ratings, SHAP attribution, LIME surrogate, Autoencoder reconstruction error, prioritization tiers, corroboration boost, enrichment contract. | **PASS** |
| **E2E Pipeline Integration** | `tests/test_e2e_pipeline.py` | **4** | End-to-end alert delivery, live WebSocket push broadcast, batch processing throughput (25 flows), concurrent async stress test (30 clients). | **PASS** |
| **Role 2 Preprocessing** | `tests/test_preprocessing.py` | **9** | Repeated header detection, schema comparison, numeric sanitization, label typo correction, fit-on-train leak prevention, inverse label encoding, Scapy PCAP extraction, CTU-13 labeling, feature policy separation. | **PASS** |
| **Total** | **All 4 Suites** | **41** | **Complete platform coverage** | **100% PASS** |

---

## 6. Comprehensive Deliverable Reports

For deep architectural analyses, methodology breakdowns, and benchmark scorecards:
* **Role 5 Report:** [`ROLE5_IMPLEMENTATION_REPORT.md`](file:///Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/ROLE5_IMPLEMENTATION_REPORT.md)
* **Role 6 Report:** [`ROLE6_INTEGRATION_REPORT.md`](file:///Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/ROLE6_INTEGRATION_REPORT.md)
* **Final Acceptance Audit:** [`reports/final_acceptance/ROLE3_ROLE4_FINAL_ACCEPTANCE_AUDIT.md`](file:///Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/reports/final_acceptance/ROLE3_ROLE4_FINAL_ACCEPTANCE_AUDIT.md)
* **Red-Team Evaluation:** [`reports/model_evaluation/role4/ROLE4_EVALUATION_REPORT.md`](file:///Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/reports/model_evaluation/role4/ROLE4_EVALUATION_REPORT.md)
* **Data Engineering QA Sign-Off:** [`reports/data_preprocessing/ROLE2_FINAL_SIGNOFF_REPORT.md`](file:///Users/priyanshu/.gemini/antigravity-ide/scratch/aiml_project_team_neural_breach/reports/data_preprocessing/ROLE2_FINAL_SIGNOFF_REPORT.md)

---

## 7. Operating Invariants & Governance

1. **Observe-Only Mode:**
   The backend enforces an immutable invariant: `OBSERVE_ONLY_MODE = True` and `ACTION_ENFORCED = "NONE_OBSERVE_ONLY"`. The system operates exclusively for diagnostic detection and triage; automated inline packet drops are disallowed.
2. **Research Prototype Boundary:**
   The service is engineered as an unauthenticated research prototype. Prior to exposing endpoints beyond `127.0.0.1`, operators must deploy behind an authenticating reverse proxy terminating TLS with rate limiting.
3. **Telemetry Boundary:**
   Attributions rely on 77 statistical flow features. Payload-dependent MITRE techniques (SQLi, XSS) are classified as `UNCONFIRMED_FLOW_SURROGATE` requiring external WAF/EDR corroboration.
