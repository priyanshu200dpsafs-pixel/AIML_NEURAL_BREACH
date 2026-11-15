# CHAPTER: BACKEND ARCHITECTURE, IMPLEMENTATION AND PLATFORM INTEGRATION

---

## 1. Introduction and Repository Inspection Baseline

This chapter provides an exhaustive architectural, algorithmic, and engineering specification of the backend services powering **Team Neural Breach: An AI/ML-Based Network Intrusion Detection & Real-Time Threat Intelligence Platform**. The platform was developed across multiple specialized engineering phases to ingest high-dimensional network telemetry, execute low-latency multi-model machine learning inference, compute real-time Shapley Explainable AI (XAI) attributions, semantically correlate detections with the MITRE ATT&CK framework, and deliver prioritized alert streams to Security Operations Center (SOC) analysts via asynchronous WebSockets and an enterprise multi-tenant dashboard.

### 1.1 Source Code Baseline & Branch Lineage

The backend implementation described herein reflects the verified source tree of the official GitHub repository at `https://github.com/priyanshu200dpsafs-pixel/AIML_NEURAL_BREACH`, specifically targeting the active development and integration branch:

- **Active Integration Branch:** `integration/role7-remediation` (HEAD: `0c9a8b1`)
- **Official Baseline Branch:** `main` (Baseline Commit: `f8d172d4b81ca3f125a32f035dee5996e6ac2045`)

A rigorous structural comparison between the `main` baseline and the `integration/role7-remediation` branch reveals a carefully controlled, non-destructive architectural progression:
- **Baseline Inherited Architecture (Role 6 Backend & Role 5 XAI):** Core real-time detection, feature preprocessing, multi-model CPU inference (`LightGBM`, `Isolation Forest`, PyTorch `DeepAutoencoder`), Tree-SHAP attribution, STIX 2.1 MITRE ATT&CK mapping, and in-memory cryptographic alert deduplication residing in `src/backend/` and `src/xai/` (established in commits `e27102a` and `2dbf7ef`).
- **Remediated Platform Extension (Role 7):** Enterprise multi-tenancy, Argon2id credential hashing, PyJWT session rotation, device telemetry ingestion, background worker queueing (`SELECT ... FOR UPDATE SKIP LOCKED`), Ed25519 cryptographic release signing, and 18 relational domain tables managed via explicit Alembic migrations residing in `src/backend/platform_ext/` and `alembic/` (remediated in commits `a31bbd2`, `4e28a36`, `31d6f4e`, and `34eec6c`).
- **Unified Product Delivery:** Integration of a production React 19 SOC Single-Page Application (`frontend/dist/`), zero-setup local launch automation (`scripts/start_local_demo.sh`), and unified multi-stage containerization (`Dockerfile.platform`, `docker-compose.yml`) established in commits `46c5c45`, `2097be6`, and `0c9a8b1`.

---

## 2. Backend Architecture

### 2.1 Backend Overview
The Team Neural Breach backend is an asynchronous, high-throughput Python service constructed on top of the **FastAPI** web framework and **Starlette** ASGI core. It is engineered specifically for defensive cybersecurity monitoring, bridging the gap between raw statistical network flows and actionable SOC triage. The platform operates under a strictly enforced, mathematically guaranteed **Observe-Only** invariant, ensuring the system analyzes, explains, and prioritizes threats without executing automated inline packet drops, firewall blacklisting, or interface shutdowns.

### 2.2 Backend Responsibilities
The backend encapsulates seven core operational mandates:
1. **Defensive Ingress Validation:** Validates incoming network flow batches against an immutable 77-feature contract, rejecting truncated, poisoned, or malformed feature payloads.
2. **Synchronous Multi-Model Threat Inference:** Executes parallel supervised classification and unsupervised anomaly detection on pre-trained, frozen ML artifacts within a sub-50ms operational latency budget.
3. **Real-Time Explainability (XAI):** Generates local feature attribution vectors using a pre-computed `SHAP TreeExplainer` baseline, deriving exact Shapley values that indicate which statistical flow metrics pushed the classifier toward an attack label.
4. **Threat Intelligence Enrichment:** Dynamically queries an authentic STIX 2.1 Enterprise Matrix catalog to map classifications to MITRE ATT&CK tactics, techniques, and observational mitigations.
5. **Deduplication & Flood Suppression:** Mitigates alert fatigue via SHA-256 cryptographic flow fingerprinting, collapsing burst attacks within a sliding 60-second window while aggregating repeat counts.
6. **Multi-Tenant Enterprise Isolation:** Enforces logical database and memory boundary separation across organizations, client devices, and user access levels using Role-Based Access Control (RBAC).
7. **Real-Time Event Broadcast:** Pushes alerts asynchronously to connected analyst consoles via high-throughput WebSocket hubs.

### 2.3 Architecture & Technology Stack

| Layer | Component | Implementation Technology | Operational Rationale |
| :--- | :--- | :--- | :--- |
| **Runtime & Language** | Core Interpreter | Python 3.12 / 3.13 (CPython 3.13.7) | Native support for modern typing, Starlette concurrency, and numeric libraries |
| **Web & API Framework** | HTTP / ASGI Engine | FastAPI 0.115+, Starlette, Uvicorn | Asynchronous route handling, Pydantic v2 validation, native OpenAPI generation |
| **Supervised Inference** | Primary Classifier | LightGBM 4.5.0 (`joblib`) | High inference throughput (<15ms), native handling of tabular flow statistics |
| **Unsupervised Anomaly** | Outlier Detection | Isolation Forest + PyTorch 2.5 Autoencoder | Dual-engine capture of out-of-distribution traffic and stealthy statistical drifts |
| **Explainable AI (XAI)** | Local Attribution | SHAP 0.46 (`TreeExplainer`), LIME 0.2 | Rigorous cooperative game-theoretic feature explanations for security analysts |
| **Threat Intelligence** | Semantic Taxonomy | STIX 2.1 JSON (MITRE ATT&CK v14) | Industry-standard classification of adversarial tactics, techniques, and procedures |
| **Database & ORM** | Relational Persistence | SQLAlchemy 2.0+, Alembic, `psycopg` | Type-safe query building, multi-tenant schemas, explicit reversible DDL migrations |
| **Worker Queue** | Async Job Broker | PostgreSQL `FOR UPDATE SKIP LOCKED` | Eliminates external Redis dependency; transactionally atomic job claiming |
| **Cryptography & Auth** | Security Primitives | Argon2id (`argon2-cffi`), PyJWT, Ed25519 | Memory-hard password hashing, cryptographically signed agent updates and JWTs |
| **Frontend Serving** | SPA Delivery | Starlette `StaticFiles` + `FileResponse` | Eliminates CORS during local evaluation; serves React 19 SPA directly from `/ui` |

### 2.4 FastAPI Application Structure
The backend codebase avoids monolithic design by segregating functionality into cohesive, testable Python packages:

```
src/backend/
├── app.py                      <- Role 6 FastAPI instantiation, lifecycle, REST routes, SPA mounting
├── config.py                   <- BackendSettings with frozen observe-only security validators
├── schemas.py                  <- Pydantic request/response models and contract schemas
├── pipeline.py                 <- RealTimeDetectionPipeline integrating inference, XAI, and storage
├── alert_manager.py            <- In-memory LRU alert repository with SHA-256 sliding-window dedup
├── websocket_manager.py        <- Unauthenticated WebSocket broadcast hub (/ws/alerts)
├── run_server.py               <- CLI launcher for standalone evaluation (127.0.0.1:8000)
├── platform_main.py            <- Platform extension entry point mounting multi-tenant routes
└── platform_ext/               <- Role 7 Enterprise Platform Extension
    ├── api/                    <- Routers: auth, agents, alerts, releases, ws, install
    ├── db/                     <- Base, engine session factory, and 18 SQLAlchemy 2.0 ORM models
    ├── security/               <- Argon2id hashing, PyJWT tokens, token-bucket rate limiting, RBAC
    ├── services/               <- Alert upsert, auth service, event broadcaster, worker loop
    └── adapters/               <- Role6DetectionAdapter bridging worker jobs to frozen ML engine
```

### 2.5 Application Initialization & Startup Lifecycle
The FastAPI application lifecycle is managed using modern asynchronous context managers via `@asynccontextmanager def lifespan(app: FastAPI)` in `src/backend/app.py`:

```
                 [System Startup Event]
                           │
                           ▼
          Load Settings from Environment (NEURAL_BREACH_*)
                           │
                           ▼
         Instantiate CyberDefenseInferenceEngine
         ├── Load feature_columns.json (77 Features Contract)
         ├── Load label_mapping.json (15 Attack Classes)
         ├── Load StandardScaler (scaler_anomaly.joblib)
         ├── Load Supervised Classifier (supervised_lightgbm_primary.joblib)
         ├── Load Isolation Forest (anomaly_isolation_forest.joblib)
         └── Load PyTorch DeepAutoencoder (anomaly_deep_autoencoder.pt)
                           │
                           ▼
          Instantiate ThreatIntelService (Role 5)
         ├── Load STIX 2.1 MITRE ATT&CK Catalog (enterprise-attack.json)
         ├── Compile SHAP TreeExplainer against Classifier
         └── Precompute Expected Value E[f(x)] Baseline
                           │
                           ▼
       Instantiate AlertManager (In-Memory Ring Buffer: 10,000)
                           │
                           ▼
          Mount React 19 Frontend SPA Assets (/assets, /ui)
                           │
                           ▼
         [Server Ready - Accept HTTP & WebSocket Traffic]
```

This eager-loading architecture guarantees that computationally heavy artifacts (such as model deserialization and SHAP TreeExplainer compilation) are executed exactly once during startup, eliminating first-request latency spikes for incoming security telemetry.

### 2.6 Modular Code Organization & Boundaries
The backend architecture strictly separates concerns:
- **`src/models/`**: Dedicated strictly to model definition, artifact deserialization, input matrix imputation, and numeric inference. It has zero knowledge of HTTP or database schemas.
- **`src/xai/`**: Encapsulates game-theoretic Shapley attributions, surrogate approximations, semantic MITRE STIX lookups, and the 0–100 threat prioritization algorithm.
- **`src/backend/` (Role 6)**: Implements the unauthenticated detection engine, in-memory alert ring buffer, and direct WebSocket broadcasting required for local lab evaluation and zero-dependency demonstration.
- **`src/backend/platform_ext/` (Role 7)**: Provides the multi-tenant relational persistence, device lifecycle, and cryptographic auth layers required for enterprise fleet deployments.

### 2.7 Interaction Between Backend, Models, Database, and Frontend
Telemetry follows two distinct execution topologies depending on the client interface:
1. **Synchronous Evaluation Flow (SOC Interactive Dashboard / Demo):** The React frontend sends an HTTP POST request to `/api/v1/predict` containing 77 flow metrics. FastAPI delegates to `RealTimeDetectionPipeline.process_flows()`, which runs the ML engine, computes SHAP attributions, attaches MITRE mappings, updates the in-memory `AlertManager`, broadcasts to `/ws/alerts`, and returns a synchronous JSON response in <25 ms.
2. **Asynchronous Telemetry Ingestion Flow (Enterprise Agent Fleet):** A distributed network sensor sends an encrypted batch to `/api/v1/agents/{id}/telemetry/batches`. The API records the batch in `telemetry_batches`, stores raw statistical rows in `network_flows`, and enqueues an `infer_batch` task in `jobs`. A background worker claims the job via `SELECT ... FOR UPDATE SKIP LOCKED`, calls `Role6DetectionAdapter.process()`, upserts deduplicated alerts into `alerts`, and dispatches real-time notifications through `broadcaster.publish_alert()`.

### 2.8 Coexistence of Role 6 Backend and Role 7 Platform Extension
The platform extension is attached dynamically via `install_platform(app)` in `src/backend/platform_ext/api/install.py`:
- **Preservation of Existing Endpoints:** Role 6 endpoints (`/api/v1/predict`, `/api/v1/alerts/simulate`, `/ws/alerts`, `/api/v1/health`, `/api/v1/stats`) remain completely unauthenticated and structurally identical to their baseline specifications.
- **Additive Namespacing:** Role 7 introduces namespaced routers for `/api/v1/auth`, `/api/v1/agents`, `/api/v1/releases`, `/api/v2/alerts`, and `/ws/v2/alerts`.
- **Selective Hardening Middleware:** Role 7 attaches HTTP security headers (`nosniff`, `DENY`, `HSTS`) and request-size bounds (2 MB) without imposing JWT requirements on public diagnostic routes.
- **Two Distinct Server Entry Points:**
  - `python3 -m src.backend.run_server`: Launches the standalone Role 6 detection backend and React SOC dashboard using in-memory storage.
  - `uvicorn src.backend.platform_main:app`: Launches the full enterprise container platform, automatically detecting `NB_JWT_SECRET` and mounting relational persistence.

---

## 3. FastAPI and REST API Implementation

### 3.1 Exhaustive API Endpoint Reference Table

| HTTP Method | Route Path | Component / Layer | Authentication Policy | Request Body / Schema | Response Contract | Purpose & Status Codes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `GET` | `/` | Web Serving | None (Public) | None | JSON status or HTML SPA | Root probe; serves React SPA if `Accept: text/html` is requested |
| `GET` | `/ui`, `/dashboard`, `/alerts`, `/investigate`, `/analytics`, `/health`, `/demo` | Web Serving | None (Public) | None | HTML (`index.html`) | Deep-link React SPA client-side routes; returns HTTP 200 or 404 if unbuilt |
| `GET` | `/api/v1/health` | Role 6 Diagnostic | None (Public) | None | `HealthResponse` | Service health, model loaded states, uptime, observe-only confirmation |
| `GET` | `/api/v1/ready` | Role 7 Infrastructure | None (Public) | None | `{"status": "ready"}` | Database connectivity readiness probe; returns HTTP 503 if DB is unreachable |
| `GET` | `/api/v1/stats` | Role 6 Analytics | None (Public) | None | `StatsResponse` | Ingested threat counts, severity breakdown, top MITRE techniques |
| `GET` | `/api/v1/alerts` | Role 6 In-Memory | None (Public) | Query Params: `threat_level`, `attack_category`, `min_score`, `limit`, `offset` | Paginated Alerts JSON | Retrieves paginated historical alerts from in-memory ring buffer |
| `GET` | `/api/v1/alerts/{alert_id}` | Role 6 In-Memory | None (Public) | Path Param: `alert_id` | `AlertResponse` | Retrieves single alert details; returns HTTP 404 if not found |
| `POST` | `/api/v1/predict` | Role 6 Core Detection | None (Public) | `PredictRequest` (77 flow features) | `PredictBatchResponse` | Synchronous inference, SHAP waterfall, MITRE mapping (<25 ms) |
| `POST` | `/api/v1/alerts/simulate` | Role 6 Benchmark | None (Public) | `SimulationRequest` (`sample_size`, `attack_ratio`, `stream_delay`) | Simulation Summary JSON | Streams CSE-CIC-IDS2018 flows to WebSockets; HTTP 503 if parquet is missing |
| `WS` | `/ws/alerts` | Role 6 Streaming | None (Public) | Optional JSON ping commands | JSON Event Stream | Unauthenticated WebSocket broadcast hub for live dashboard streaming |
| `POST` | `/api/v1/auth/register` | Role 7 Auth | None (Public) | `RegisterRequest` (email, password, org_name) | `TokenResponse` | Creates user, organization, owner membership; issues access & refresh tokens |
| `POST` | `/api/v1/auth/login` | Role 7 Auth | None (Public) | `LoginRequest` (email, password) | `TokenResponse` | Argon2id verification, lockout check; issues access & refresh tokens |
| `POST` | `/api/v1/auth/refresh` | Role 7 Auth | Refresh Token | `RefreshRequest` (refresh_token) | `TokenResponse` | Opaque token rotation; detects token reuse and revokes entire family |
| `POST` | `/api/v1/auth/logout` | Role 7 Auth | Bearer JWT | None | `{"status": "logged_out"}` | Revokes current user auth session and refresh token family |
| `GET` | `/api/v1/auth/me` | Role 7 Auth | Bearer JWT | None | User Profile JSON | Returns authenticated user details, organization ID, and assigned RBAC role |
| `POST` | `/api/v1/ws/ticket` | Role 7 Auth | Bearer JWT | None | `{"ticket": "..."}` | Mints single-use, 60s time-to-live ticket for WebSocket authentication |
| `POST` | `/api/v1/agents/enroll` | Role 7 Device | Enrollment Token | `EnrollRequest` (token, hostname, os, arch) | `EnrollResponse` | Enrolls sensor; returns unique `device_id` and raw secret (hashed at rest) |
| `POST` | `/api/v1/agents/heartbeat` | Role 7 Device | Device Bearer | `HeartbeatRequest` (client_version, status) | `{"status": "ok"}` | Updates `last_seen_at`; records device status metrics |
| `POST` | `/api/v1/agents/{id}/telemetry/batches` | Role 7 Ingestion | Device Bearer | `BatchTelemetryRequest` (flows array) | `{"batch_id": "...", "status": "accepted"}` | Idempotent telemetry batch ingestion; enqueues worker inference job |
| `GET` | `/api/v2/alerts` | Role 7 Persistence | Bearer JWT (`alerts:read`) | Query Params: severity, status, timestamps | Paginated DB Alerts | Retrieves persistent alerts isolated strictly to caller's organization |
| `PATCH` | `/api/v2/alerts/{id}` | Role 7 Triage | Bearer JWT (`alerts:write`) | `AlertUpdateRequest` (status, note) | Updated Alert JSON | Updates investigation status (`investigating`, `resolved`) and logs notes |
| `WS` | `/ws/v2/alerts` | Role 7 Streaming | Ticket Query Param | Query: `?ticket=...&device_id=...` | JSON Alert Stream | Authenticated, tenant-isolated WebSocket feed with 15s session revalidation |

### 3.2 Request Validation & Defensive Schema Contracts
All request payloads pass through Pydantic v2 schemas:
- **Batch Size Limits (HTTP 413):** `PredictRequest` enforces `len(flows) <= settings.MAX_BATCH_SIZE` (500 flows). Excessively large batches are rejected immediately with `HTTP 413 Content Too Large`.
- **Strict 77-Feature Contract (HTTP 422):** The inference engine verifies that all 77 port-agnostic statistical features are present. If any feature is missing, the backend returns `HTTP 422 Unprocessable Content` with a detailed error listing the missing feature names.
- **Empty Batch Rejection (HTTP 400):** Submitting an empty flows array is rejected with `HTTP 400 Bad Request`.
- **Defensive Error Serialization:** Internal stack traces are caught by global exception handlers (`http_exc` and `val_exc` in `install.py`). Responses are serialized into structured JSON with an associated tracking `X-Request-ID`.

---

## 4. Machine Learning Backend Integration

### 4.1 The 77-Feature Input Contract & Validation
The machine learning inference engine requires a pre-defined feature space of **77 bidirectional statistical flow metrics** derived from the Canadian Institute for Cybersecurity (CIC) flow taxonomy. Port numbers (`Dst Port`, `Src Port`) and host IP addresses are deliberately excluded from the classifier's feature space to ensure the model learns true behavioral network patterns rather than memorizing static network topology.

Feature validation is executed in `CyberDefenseInferenceEngine.validate_and_preprocess()` in `src/models/inference_engine.py`:
1. **Schema Check:** The DataFrame columns are compared against `self.expected_features`. If missing > 0, a `ModelInferenceError` is raised.
2. **Column Alignment:** Columns are reindexed to guarantee exact mathematical matrix alignment: `X_df = df[self.expected_features]`.
3. **Numeric Sanitization & Imputation:** Flow captures frequently contain infinite rates or missing sensor values. The engine sanitizes values defensibly:
   `X_clean = X_df.replace([inf, -inf], NaN).fillna(0.0).values.astype(float32)`
4. **Standardized Scaling:** Feature values are transformed using a frozen `StandardScaler` fitted exclusively on benign baseline training traffic:
   `X_scaled = self.scaler.transform(X_clean)`

### 4.2 Loading Frozen Model Artifacts
All production model artifacts reside in `models/role3_retrain_v2/` and are strictly frozen:
- **Supervised Primary Classifier (`supervised_lightgbm_primary.joblib`):** LightGBM ensemble trained across 15 distinct classes.
- **Unsupervised Isolation Forest (`anomaly_isolation_forest.joblib`):** Scikit-learn Isolation Forest trained with a calibrated contamination factor of 0.01.
- **Deep Autoencoder (`anomaly_deep_autoencoder.pt`):** A 5-layer PyTorch reconstruction neural network (77 -> 48 -> 24 -> 12 -> 24 -> 48 -> 77) with LeakyReLU activations and batch normalization.

### 4.3 Multi-Model Inference & Threshold Decision Logic
Inference executes across all three models in parallel:
1. **Supervised Probability Computation:** The predicted label is the class with maximum softmax probability. An operational classification decision threshold of 0.7303 is enforced to operate within a 1% FPR budget.
2. **Isolation Forest Outlier Scoring:** Outliers are flagged when decision function score is <= -0.08063 (calibrated for 1% FPR).
3. **Deep Autoencoder Reconstruction Error:** Mean Squared Error (MSE) reconstruction loss triggers an anomaly alert when MSE >= 1.29126 (calibrated for 1% FPR).
4. **Threat Level & Prioritization Synthesis:**
   - Attack with confidence >= 0.80 -> `HIGH`
   - Attack with confidence < 0.80 -> `MEDIUM`
   - Benign with Isolation Forest alert or Autoencoder alert -> `SUSPICIOUS_ANOMALY`
   - Otherwise -> `BENIGN`

---

## 5. Detection Adapter and Role 7 Integration

The `Role6DetectionAdapter` class in `src/backend/platform_ext/adapters/detection_adapter.py` acts as an architectural bridge, allowing the Role 7 asynchronous background worker to invoke the frozen Role 3/5/6 detection engine without code duplication or model retraining.

### 5.1 Architecture of the Detection Adapter Bridge
- **Protocol Adherence:** Implements `process(flows: List[Dict[str, float]]) -> List[Dict[str, Any]]`.
- **Zero Retraining Invariant:** Loads identical frozen artifacts from `models/role3_retrain_v2/`.
- **Filtering Pure Benign Flows:** Prunes non-anomalous benign traffic from the returned alert list to conserve relational storage while ensuring 100% of attacks and anomalies are captured.
- **Fail-Safe Observational Guarantees:** Injects `observe_only_mode: True` and `action_enforced: "NONE_OBSERVE_ONLY"` into every generated alert record.

---

## 6. Database Architecture and Implementation

### 6.1 SQLAlchemy 2.0 ORM Architecture & Portable Typings
The database architecture resides in `src/backend/platform_ext/db/` and is built using SQLAlchemy 2.0 declarative mappings:
- Primary keys are 36-character UUID strings (`String(36)`), ensuring compatibility across SQLite (for local evaluation) and PostgreSQL (for production).
- Auto-incrementing telemetry tables utilize `BigInteger().with_variant(Integer, "sqlite")`.
- Unstructured metrics, SHAP waterfall vectors, and raw telemetry are stored in standard `JSON` column types.

### 6.2 The 18 Relational Domain Tables
The schema manages 18 distinct domain tables:
1. `organizations`: Tenant root records.
2. `users`: User profiles with password hashes and account lockout counters.
3. `memberships`: Multi-tenant user-to-organization bindings with roles (`owner`, `admin`, `analyst`, `viewer`).
4. `auth_sessions`: Active refresh-token sessions with family tracking for reuse detection.
5. `enrollment_tokens`: Single-use tokens for sensor registration.
6. `devices`: Enrolled telemetry sensors with host metadata and status.
7. `device_credentials`: Hashed secrets for sensor authentication.
8. `device_heartbeats`: Telemetry logs of sensor health and uptime.
9. `device_configs`: Dynamic sensor configuration payloads.
10. `telemetry_batches`: Ingested batch records with idempotency tracking.
11. `network_flows`: Statistical flow records (the 77-feature contract).
12. `jobs`: Background worker task queue (`status in ('queued','running','done','failed')`).
13. `alerts`: Multi-tenant persistent security alerts with repeat counters and investigation statuses.
14. `alert_notes`: Analyst triage comments and investigation findings.
15. `audit_log`: Append-only security and operational audit trail.
16. `model_versions`: Registry of deployed model artifacts and feature contract hashes.
17. `releases`: Ed25519-signed agent binary update catalog.
18. `release_policies`: Channel-based minimum version enforcement policies.

### 6.3 Relational Deduplication & Row-Level Locking
In `src/backend/platform_ext/services/alert_service.py`, `upsert_alert()` enforces deduplication at the database tier:
- Derives signature: `SHA-256(device_id | label | attack_category)`.
- Selects active alerts within the 60-second sliding cutoff targeting `(org_id, device_id, signature)` with `with_for_update()`.
- If an existing record exists, increments `repeat_count` and updates `last_seen` without inserting duplicate rows.

### 6.4 Explicit Alembic Migrations
- Schema migrations are managed via explicit Alembic DDL (`alembic/versions/0001_initial.py`).
- Implements complete, reversible `upgrade()` and `downgrade()` routines in strict foreign-key order.
- The migration environment (`alembic/env.py`) verifies target dialect safety.

---

## 7. Authentication and Security

### 7.1 Argon2id Password Hashing
User credentials in `src/backend/platform_ext/security/passwords.py` are protected using **Argon2id** (via `argon2-cffi`), with an internal `scrypt` fallback. To neutralize timing side-channel attacks for account enumeration, non-existent accounts compute against a pre-compiled `DUMMY_HASH`.

### 7.2 JWT Lifecycle, Sessions & Refresh Rotation
- **Access Tokens:** Signed with HMAC-SHA256 (`HS256`), containing claims `sub`, `org`, `role`, `jti`, with a short 15-minute TTL.
- **Opaque Refresh Tokens:** 48-byte cryptographically secure random tokens. Only their SHA-256 hash is stored in `auth_sessions`.
- **Token Family Reuse Detection:** Refresh tokens belong to a `family_id`. If an already-rotated token is submitted again, the backend revokes the entire family immediately.
- **Account Lockout:** Five consecutive failed login attempts trigger a 15-minute account lock.

### 7.3 Role-Based Access Control (RBAC) Matrix

| RBAC Permission | Viewer | Analyst | Admin | Owner |
| :--- | :---: | :---: | :---: | :---: |
| `alerts:read` | **YES** | **YES** | **YES** | **YES** |
| `devices:read` | **YES** | **YES** | **YES** | **YES** |
| `alerts:write` (Acknowledge, Triage Notes, Status) | No | **YES** | **YES** | **YES** |
| `devices:manage` (Enroll Tokens, Config, Revoke) | No | No | **YES** | **YES** |
| `members:manage` (Invite Users, Assign Roles) | No | No | **YES** | **YES** |
| `audit:read` (Inspect Immutable System Logs) | No | No | **YES** | **YES** |
| `org:manage` (Rename Organization, Transfer Ownership) | No | No | No | **YES** |

### 7.4 Agent Authentication & Ed25519 Signed Releases
- Sensors authenticate using compound tokens `<device_id>.<secret>`, where only `SHA-256(secret)` is stored on the server.
- Sensor software releases are signed with **Ed25519** elliptic-curve cryptography (`src/backend/platform_ext/releases/signing.py`), verifying artifact digests before distribution.

---

## 8. Background Workers and Job Processing

The Role 7 platform uses a database-backed task queue (`src/backend/platform_ext/services/worker.py`):
1. **Atomic Job Claiming:** Workers claim tasks via `SELECT ... FROM jobs WHERE status='queued' ORDER BY run_after LIMIT 1 FOR UPDATE SKIP LOCKED`.
2. **Crash Recovery:** A periodic sweeper (`reclaim_stale`) resets jobs where `locked_at` is older than 300 seconds back to `queued`.
3. **Exponential Backoff:** Failed jobs retry with exponential backoff (`base * 2^(attempts-1)`). After 5 attempts, the job is moved to `status = 'failed'` (Dead-Letter state).

---

## 9. WebSocket Real-Time Alert System

Real-time streaming is supported via two channels:
1. **Role 6 Channel (`/ws/alerts`):** Public connection for lab demonstration; broadcasts JSON alerts directly to connected browsers.
2. **Role 7 Channel (`/ws/v2/alerts`):** Managed by `AlertBroadcaster` (`src/backend/platform_ext/services/broadcaster.py`); enforces tenant isolation via short-lived query tickets.
- **Bounded Queue Protection:** Each client queue is capped at 500 messages. If a slow consumer fills its queue, the broadcaster drops the oldest alert to prevent server out-of-memory errors.

---

## 10. Explainable AI and Threat Intelligence Integration

### 10.1 SHAP TreeExplainer & Mathematical Feature Attribution
The backend integrates **SHAP (SHapley Additive exPlanations)** in `src/xai/explainer.py`:
- Tree-SHAP computes exact Shapley attributions relative to the base value `E[f(x)]`.
- Top contributing features are returned with directional contribution scores and raw feature values.
- `LimeTabularExplainer` is maintained as a fallback.

### 10.2 MITRE ATT&CK STIX 2.1 Mapping & Semantic Accuracy Ratings
The `MitreMapper` class (`src/xai/mitre_mapper.py`) parses the official **MITRE ATT&CK Enterprise Matrix v14** catalog (`enterprise-attack.json`):
- All 15 attack classes are mapped to primary tactics, technique IDs (e.g., `T1498`, `T1059`), descriptions, and mitigations.
- Explicit semantic accuracy ratings distinguish direct flow signatures (`CONFIRMED_FLOW_SIGNATURE`) from statistical surrogates (`UNCONFIRMED_FLOW_SURROGATE`) and generic anomalies (`UNCONFIRMED_GENERIC_ANOMALY`).

---

## 11. Observe-Only Governance and Safety

The platform operates strictly in **Observe-Only Mode**:
1. **Pydantic Validation:** `OBSERVE_ONLY_MODE = Field(default=True, frozen=True)` in `src/backend/config.py` rejects any attempt to override the setting via environment variables.
2. **Static Alert Injection:** Every alert payload hardcodes `observe_only_mode: True` and `action_enforced: "NONE_OBSERVE_ONLY"`.
3. **Prohibition of Automated Blocking:** The codebase contains no firewall rule injectors, routing table manipulators, or process killers.

---

## 12. Backend Testing and Validation

The backend implementation was verified through an automated test suite executed via `pytest`, achieving **124 passing tests out of 124 collected items (100% pass rate) in 26.43 seconds**:

| Test Suite File | Tests | Core Architectural Capabilities Verified | Status |
| :--- | :---: | :--- | :---: |
| `tests/test_role6_backend.py` | **17** | Health probes, SHAP/LIME inference, missing feature rejection, SHA-256 deduplication, alert query/filtering, stats, WebSocket handshake, simulation stream, observe-only invariant enforcement, batch size limits (HTTP 413), explicit CORS allowlists. | **PASS** |
| `tests/test_role5_xai.py` | **11** | STIX 2.1 taxonomy validation, 15-class MITRE mapping, anomaly mapping, semantic accuracy ratings, SHAP attribution structure, LIME surrogates, Autoencoder reconstruction error, prioritization tiers, corroboration boost. | **PASS** |
| `tests/test_preprocessing.py` | **9** | Repeated header detection, schema comparison, numeric sanitization, label typo correction (`Infilteration` -> `Infiltration`), fit-on-train leak prevention, inverse label encoding, Scapy PCAP extraction, CTU-13 labeling. | **PASS** |
| `tests/test_frontend_serving.py` | **4** | Root endpoint content negotiation (JSON for API clients, HTML for web browsers), React SPA deep-link routing (`/ui`, `/dashboard`, `/alerts`, `/investigate`), static asset bundle serving. | **PASS** |
| `tests/test_e2e_pipeline.py` | **4** | End-to-end alert delivery, live WebSocket broadcast, batch processing throughput (25 flows), concurrent async stress test (30 clients). | **PASS** |
| `tests/test_role7_integration.py` | **10** | Non-regression validation: confirms Role 7 additions do not mutate Role 6 routes, unauthenticated predictions, alert queries, or WebSocket feeds. | **PASS** |
| `tests_r7/test_core_primitives.py` | **29** | Argon2id hashing, timing equalization, JWT life-cycle, RBAC matrix, token-bucket rate limiting, 77-feature contract validation, Ed25519 cryptographic release signing. | **PASS** |
| `tests_r7/test_detection_adapter_real.py` | **4** | Real adapter initialization, missing feature rejection, real multi-model inference execution, and background worker persistence. | **PASS** |
| `tests_r7/test_platform_api.py` | **31** | Multi-tenant auth, lockout protection, refresh rotation, cross-tenant device and alert isolation, agent enrollment, telemetry batching, Alembic migration. | **PASS** |
| `tests_r7/test_websocket_broadcaster.py` | **5** | Multi-subscriber broadcasting, cross-tenant isolation, device-specific filters, graceful disconnects, and bounded queue overflow protections. | **PASS** |
| **Total Automated Tests** | **124** | **Complete platform regression, security, and integration coverage** | **100% PASS** |

---

## 13. Backend Deployment and Operations

- **Local Evaluation:** Unified launcher script `bash scripts/start_local_demo.sh` verifies models, checks frontend build, and starts FastAPI on port 8000.
- **Containerized Multi-Tier:** Docker Compose orchestrates PostgreSQL 16 (`db`), Alembic migrations (`migrate`), Uvicorn API (`api`), and background worker (`worker`) with healthchecks.

---

## 14. Backend Limitations and Future Improvements

1. **Synthetic Telemetry Ingestion vs. Hardware Packet Capture:** The backend processes pre-extracted statistical flow records rather than raw network packets from an active NIC tap.
2. **Benchmark Replay vs. Live Intrusion:** Simulated alerts replay historical benchmark flows from the CSE-CIC-IDS2018 dataset.
3. **Pending PostgreSQL 16 Staging Gate:** Verification of relational schemas was conducted on SQLite and local PostgreSQL 14.24; formal cloud staging on PostgreSQL 16 is pending infrastructure provisioning.
4. **Single-Process WebSocket Scaling:** In-memory `AlertBroadcaster` fan-out requires an external broker (Redis Pub/Sub or PostgreSQL `NOTIFY`) for multi-node deployments.
5. **Observational Governance Scope:** Automated remediation actions are permanently prohibited under project governance (`observe_only_mode: True`, `action_enforced: NONE_OBSERVE_ONLY`).

---

# SECTION B: INDIVIDUAL BACKEND CONTRIBUTIONS

### Contribution: Role 6 — Backend & Real-Time Detection Engine
- **Assigned Engineer:** `[Student Name Placeholder]`, University Roll No: `[Roll Number Placeholder]`
- **Primary Source Modules:** `src/backend/app.py`, `src/backend/config.py`, `src/backend/pipeline.py`, `src/backend/alert_manager.py`, `src/backend/websocket_manager.py`, `src/backend/schemas.py`, `src/models/inference_engine.py`
- **Key Engineering Deliverables:**
  - Architected the sub-50ms real-time detection pipeline combining LightGBM, Isolation Forest, and PyTorch Autoencoder.
  - Implemented the 60-second sliding-window cryptographic deduplication engine preventing SOC alert floods.
  - Created the authentic benchmark traffic simulator streaming CSE-CIC-IDS2018 parquet flows to WebSockets.
  - Developed the automated test suite in `tests/test_role6_backend.py` (17 tests) and `tests/test_e2e_pipeline.py` (4 tests).

---

### Contribution: Role 7 — Platform Extension & Security Architecture
- **Assigned Engineer:** `[Student Name Placeholder]`, University Roll No: `[Roll Number Placeholder]`
- **Primary Source Modules:** `src/backend/platform_ext/api/install.py`, `src/backend/platform_ext/db/models.py`, `src/backend/platform_ext/services/worker.py`, `src/backend/platform_ext/services/alert_service.py`, `src/backend/platform_ext/services/broadcaster.py`, `src/backend/platform_ext/adapters/detection_adapter.py`, `src/backend/platform_ext/security/`, `alembic/versions/0001_initial.py`
- **Key Engineering Deliverables:**
  - Developed the enterprise multi-tenant platform extension without breaking existing Role 6 interfaces.
  - Implemented Argon2id password hashing with dummy timing equalization and token family reuse detection.
  - Created the PostgreSQL-backed worker queue eliminating external Redis dependencies.
  - Engineered the 69 automated platform tests across `tests_r7/` and the 10 integration non-regression tests in `tests/test_role7_integration.py`.

---

# SECTION C: TECHNICAL EVIDENCE TABLE

| Architectural Feature | Primary Implementation File | Core Operational Mechanism | Automated Verification Method | Verified Implementation Status |
| :--- | :--- | :--- | :--- | :---: |
| **77-Feature Schema Guard** | `src/models/inference_engine.py` | Reindexes columns; rejects missing features with `ModelInferenceError` | `tests/test_role6_backend.py::test_predict_missing_features_rejected` | **VERIFIED (PASS)** |
| **Supervised Inference** | `src/models/inference_engine.py` | Deserializes frozen LightGBM model; computes probabilities against 15 classes | `tests/test_role6_backend.py::test_predict_single_flow_shap` | **VERIFIED (PASS)** |
| **Dual Anomaly Detection** | `src/models/inference_engine.py` | Parallel evaluation of Isolation Forest ($s_{\text{iso}} \le -0.08063$) and Autoencoder MSE | `tests/test_role5_xai.py::test_autoencoder_anomaly_attribution` | **VERIFIED (PASS)** |
| **SHAP XAI Waterfall** | `src/xai/explainer.py` | Evaluates local Shapley feature contributions relative to $E[f(x)]$ base value | `tests/test_role5_xai.py::test_shap_explanation_structure` | **VERIFIED (PASS)** |
| **MITRE ATT&CK Mapping** | `src/xai/mitre_mapper.py` | Correlates classes to STIX 2.1 JSON catalog; assigns semantic accuracy ratings | `tests/test_role5_xai.py::test_all_15_classes_mapped` | **VERIFIED (PASS)** |
| **In-Memory Dedup Ring** | `src/backend/alert_manager.py` | Sliding-window SHA-256 fingerprinting collapses bursts within 60 seconds | `tests/test_role6_backend.py::test_deduplication_repeat_count` | **VERIFIED (PASS)** |
| **Live WebSocket Fan-Out** | `src/backend/websocket_manager.py` | Asynchronous broadcast of enriched alerts to connected dashboard sessions | `tests/test_role6_backend.py::test_websocket_connection_and_ping` | **VERIFIED (PASS)** |
| **Argon2id Credential Hash** | `src/backend/platform_ext/security/passwords.py` | Memory-hard password hashing with timing equalization via `DUMMY_HASH` | `tests_r7/test_core_primitives.py::PasswordTests::test_hash_and_verify` | **VERIFIED (PASS)** |
| **JWT Family Rotation** | `src/backend/platform_ext/security/tokens.py` | HS256 access tokens + opaque refresh tokens with reuse family revocation | `tests_r7/test_core_primitives.py::TokenTests::test_roundtrip` | **VERIFIED (PASS)** |
| **Tenant Relational DB** | `src/backend/platform_ext/db/models.py` | 18 SQLAlchemy 2.0 domain models with portable UUID and JSON typings | `tests_r7/test_platform_api.py::test_alembic_upgrade_downgrade` | **VERIFIED (PASS)** |
| **Worker Concurrency Lock** | `src/backend/platform_ext/services/worker.py` | Atomic task claiming via `SELECT ... FOR UPDATE SKIP LOCKED` | `tests_r7/test_platform_api.py::test_worker_processes_and_dedups` | **VERIFIED (PASS)** |
| **Detection Bridge Adapter** | `src/backend/platform_ext/adapters/detection_adapter.py` | Protocol bridge invoking frozen Role 3/5/6 pipeline from worker threads | `tests_r7/test_detection_adapter_real.py::test_real_adapter_executes_real_inference_and_xai` | **VERIFIED (PASS)** |
| **Ed25519 Release Signing** | `src/backend/platform_ext/releases/signing.py` | Asymmetric elliptic-curve signature verification of sensor update binaries | `tests_r7/test_core_primitives.py::SigningTests::test_valid` | **VERIFIED (PASS)** |
| **Observe-Only Mode** | `src/backend/config.py` | Frozen Pydantic field validators prevent overriding `OBSERVE_ONLY_MODE` | `tests/test_role6_backend.py::test_observe_only_mode_invariant_override_rejection` | **VERIFIED (PASS)** |

---

# SECTION D: OUTSTANDING BACKEND LIMITATIONS

1. **Synthetic Telemetry Ingestion vs. Hardware Packet Capture:** The backend functions at the flow telemetry level (accepting 77 pre-computed statistical flow attributes) and does not contain a live kernel packet sniffing daemon (e.g., raw socket capture, eBPF, or DPDK driver).
2. **Benchmark Traffic Simulation Scope:** The traffic stream generated via `/api/v1/alerts/simulate` replays extracted partitions from the CSE-CIC-IDS2018 evaluation dataset; it does not represent live, adversarial attack injection against physical infrastructure.
3. **PostgreSQL 16 Staging Verification Environment:** Verification of the complete relational schema was conducted on SQLite (during automated unit/platform test runs) and on an isolated local PostgreSQL 14.24 instance during audit stress-testing. Formal staging verification on a dedicated PostgreSQL 16 cloud instance remains gated pending staging infrastructure provisioning.
4. **Single-Process WebSocket Scaling:** The current `AlertBroadcaster` delivers real-time notifications via in-memory Python `asyncio.Queue` primitives. Multi-node cluster deployments will require external pub/sub infrastructure (Redis Pub/Sub or PostgreSQL `NOTIFY`) to synchronize events across separate API processes.
5. **Observational Governance Scope:** Automated remediation actions (inline firewall rule injection, host network isolation, active packet dropping) are permanently prohibited under project governance (`observe_only_mode: True`, `action_enforced: NONE_OBSERVE_ONLY`).

---

# SECTION E: FIGURES AND SCREENSHOTS CHECKLIST

- [ ] **Figure 1: Master Backend Architecture Diagram:** Render the complete architecture diagram showing client layers, FastAPI routing, ML inference, and platform persistence.
- [ ] **Figure 2: End-to-End ML Inference Flowchart:** Render the step-by-step decision flowchart illustrating 77-feature validation, parallel model execution, and threat synthesis.
- [ ] **Figure 3: Relational Database Entity-Relationship (ER) Diagram:** Render the 18-table ER diagram detailing primary keys, foreign keys, and organization relationships.
- [ ] **Figure 4: WebSocket Alert Broadcast Event Flow:** Render the sequence and queue fan-out diagrams.
- [ ] **Screenshot 1: Interactive Swagger API Documentation (`/docs`):** Browser screenshot showing the OpenAPI interface listing both Role 6 diagnostic routes and Role 7 enterprise routes.
- [ ] **Screenshot 2: Real-Time Flow Prediction REST Response:** Terminal screenshot executing `curl -X POST http://127.0.0.1:8000/api/v1/predict -d @scripts/sample_valid_flow.json | jq .` showing prediction, confidence, SHAP attributions, and MITRE mapping.
- [ ] **Screenshot 3: Defensive Schema Contract Violation (HTTP 422):** Terminal screenshot showing the server rejecting a truncated flow payload with `HTTP 422 Unprocessable Content` and listing missing features.
- [ ] **Screenshot 4: Master Test Suite Execution Output:** Terminal screenshot executing `pytest tests/ tests_r7/ -v` displaying `124 passed in 26.43s (100%)`.
- [ ] **Screenshot 5: Frozen ML Artifact Integrity Verification:** Terminal screenshot executing the SHA-256 integrity verification script confirming all 32 model artifacts in `models/`.
- [ ] **Screenshot 6: React SOC Command Console Overview:** Browser screenshot of `http://127.0.0.1:8000/ui` showing active KPI cards, severity breakdown, and live WebSocket connection indicator.
- [ ] **Screenshot 7: Deep Alert Investigation & SHAP Waterfall Visualizer:** Browser screenshot of `http://127.0.0.1:8000/investigate` displaying horizontal red/cyan Shapley contribution bars alongside raw flow feature values.

---

# SECTION F: SOURCE CODE VERIFICATION INDEX

1. **FastAPI Lifespan & Application Instantiation:** `src/backend/app.py#L53-L79` — `lifespan()`, `app = FastAPI(...)`
2. **Frozen Observe-Only Invariant Enforcement:** `src/backend/config.py#L28-L51` — `OBSERVE_ONLY_MODE = Field(default=True, frozen=True)`, `enforce_observe_only_mode()`
3. **77-Feature Contract Validation & Imputation:** `src/models/inference_engine.py#L156-L180` — `validate_and_preprocess()`, missing column verification, numeric sanitization
4. **Multi-Model Inference & Operational Decision Thresholds:** `src/models/inference_engine.py#L113-L123` and `#L181-L244` — `predict_flows()`, Isolation Forest threshold (-0.08063), Autoencoder threshold (1.29126)
5. **Detection Adapter Bridge Implementation:** `src/backend/platform_ext/adapters/detection_adapter.py#L19-L164` — `Role6DetectionAdapter.process()`, benign pruning, observe-only injection
6. **In-Memory Cryptographic Alert Deduplication Engine:** `src/backend/alert_manager.py#L42-L100` — `_compute_signature()`, `add_alert()`, LRU ring buffer eviction
7. **Relational Database Models (18 Domain Tables):** `src/backend/platform_ext/db/models.py#L25-L273` — `User`, `Organization`, `Membership`, `AuthSession`, `Device`, `Alert`, `Job`, `Release`, etc.
8. **Worker Queue Concurrency & Row-Level Locking:** `src/backend/platform_ext/services/worker.py#L35-L100` — `claim_job()` with `with_for_update(skip_locked=True)`, `reclaim_stale()`, exponential backoff
9. **Relational Alert Deduplication with Row Locking:** `src/backend/platform_ext/services/alert_service.py#L29-L55` — `upsert_alert()` using `with_for_update()` and 60-second window cutoff
10. **Argon2id Password Security & Timing Equalization:** `src/backend/platform_ext/security/passwords.py#L16-L46` — `hash_password()`, `verify_password()`, `DUMMY_HASH`
11. **JWT Session Lifecycle & Token Family Reuse Revocation:** `src/backend/platform_ext/security/tokens.py#L26-L48` and `src/backend/platform_ext/services/auth_service.py#L55-L95` — `encode_jwt()`, `refresh_session()` family revocation
12. **In-Memory WebSocket Broadcaster & Bounded Queue Protection:** `src/backend/platform_ext/services/broadcaster.py#L19-L87` — `AlertBroadcaster.publish_alert()`, `asyncio.Queue(maxsize=500)`, drop-oldest overflow logic
13. **Ed25519 Cryptographic Release Signature Verification:** `src/backend/platform_ext/releases/signing.py#L40-L60` — `verify_signed_metadata()`, `Ed25519PublicKey.verify()`
14. **Explicit Reversible Schema Migrations:** `alembic/versions/0001_initial.py#L16-L321` — Explicit `upgrade()` and `downgrade()` for all 18 tables and constraints
15. **Non-Destructive Platform Extension Mounting:** `src/backend/platform_ext/api/install.py#L38-L134` — `install_platform(app)`, CORS allowlists, defense-in-depth headers, non-destructive router inclusion
