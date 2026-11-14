# Team Neural Breach — Professor & Evaluator Walkthrough Guide

**Project:** Autonomous AI/ML-Based Network Intrusion Detection & Threat Intelligence Platform  
**Operational Governance:** Strictly Enforced **Observe-Only Mode** (`action_enforced: NONE_OBSERVE_ONLY`)  
**Release Target:** Research Prototype v2.0  
**Target Audience:** Evaluating Professors, Capstone Reviewers, Senior Security Auditors  

---

## 1. Executive Summary & Architecture Overview

Team Neural Breach is an enterprise-grade cyber defense and Security Operations Center (SOC) platform that fuses:
1. **Role 3 Ensembles:** Supervised multi-class classification (`LightGBM` primary with `1%` FPR budget) + Unsupervised dual-engine anomaly detection (`Isolation Forest` + PyTorch 5-layer `Deep Autoencoder`).
2. **Role 5 Explainable AI (XAI) & Threat Intel:** Real-time Shapley additive explanations (`SHAP TreeExplainer`) and semantic mappings to the **MITRE ATT&CK Enterprise Matrix v14** (STIX 2.1 taxonomy).
3. **Role 6 Real-Time Detection Backend:** Asynchronous FastAPI service supporting sub-50ms inference, WebSocket streaming (`/ws/alerts`), in-memory priority deduplication, and benchmark simulation.
4. **Role 7 Platform Extension:** Multi-tenant enterprise RBAC, JWT session management, device telemetry ingestion, and Ed25519-signed release policies.
5. **Interactive SOC Command Console:** A responsive, modern React SPA interface providing live streaming, deep alert investigation with interactive SHAP waterfall contribution charts, threat analytics, system health monitors, and a 1-click evaluation demonstration suite.

---

## 2. Quick-Start Access Instructions (Zero Setup Friction)

### Option A: 1-Step Unified Local Launcher (Recommended)
From the repository root directory, run:

```bash
bash scripts/start_local_demo.sh
```

**What this script does:**
1. Verifies that all 32 frozen model artifacts and MITRE STIX reference data exist.
2. Checks that the production React bundle exists at `frontend/dist/` (builds it automatically if missing).
3. Launches the Python FastAPI service on `http://127.0.0.1:8000`.

### Option B: Manual Startup
If you prefer running commands manually:

```bash
# 1. (Optional) Compile frontend SPA
cd frontend && npm run build && cd ..

# 2. Launch FastAPI backend service
python3 -m src.backend.run_server --host 127.0.0.1 --port 8000
```

### Accessing the Dashboard
Open your web browser (Chrome, Firefox, Safari, or Edge) and navigate to:
```
http://127.0.0.1:8000/ui
```
*(Or navigate to [http://127.0.0.1:8000/](http://127.0.0.1:8000/) directly in a web browser; the server automatically serves the SOC interface).*

---

## 3. Evaluator Authentication & Session Setup

To eliminate password setup friction and protect security credentials:
1. On the login screen, select the **1-Click Evaluator** tab.
2. Click **"Launch SOC Analyst Console"**.
3. You are immediately granted an active observer session as:
   - **User:** `evaluator.soc@neuralbreach.local`
   - **Role:** `Senior SOC Analyst (Observer)`
   - **Permissions:** Full read, live stream monitoring, interactive inference execution, and diagnostic note entry.
   - **Governance Boundary:** All write and remediation actions remain strictly observe-only.

*(Optional)* If you wish to test enterprise multi-tenant authentication, switch to the **Platform Sign In** or **Register Org** tabs to test JWT registration and token refresh against `/api/v1/auth/login`.

---

## 4. Step-by-Step Feature Walkthrough & Verification Procedure

### Test Phase 1 — Security Operations Command Center (SOC Overview)
1. **Navigate to:** Click **"SOC Overview"** in the top navigation bar (or visit [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)).
2. **Observe KPI Cards:**
   - **Total Alerts:** Live count of alerts ingested or simulated.
   - **Critical / High / Medium / Low:** Breakdown based on composite priority score.
   - **Anomaly Detections:** Real-time count of unsupervised outliers flagged by Isolation Forest or Autoencoder.
   - **Service Health:** Displays `HEALTHY` with real-time uptime in seconds.
3. **Inspect Severity Distribution:** Dynamic stacked bar visualizes threat severity percentages.
4. **Inspect Pipeline Specs:** Confirms `LightGBM` supervised classifier, `1%` FPR budget, and `77` expected features contract.

---

### Test Phase 2 — Interactive Demo & Benchmark Simulation Suite
1. **Navigate to:** Click **"Demo Scenarios"** in the top navigation bar.
2. **Execute Scenario 2 (Single-Flow Real-Time Inference + SHAP XAI):**
   - Click **"Execute Real-Time Flow Inference"**.
   - **Observed Result:**
     - The backend executes real-time multi-model inference against a genuine 77-feature network flow record.
     - Latency is recorded live (typically `< 25ms`).
     - Classification displays target attack type (or benign baseline) with confidence percentage.
     - Composite priority score is calculated.
     - Action enforced verifies: `NONE_OBSERVE_ONLY`.
   - Click **"Open Deep Investigation →"** to jump directly into the deep diagnostic screen for this flow.

3. **Execute Scenario 3 (Security Schema Contract Enforcement):**
   - Click **"Test Schema Enforcement Guard"**.
   - **Observed Result:**
     - A deliberately truncated payload missing required flow features is transmitted.
     - The server rejects the malformed input with `HTTP 422 Unprocessable Content`.
     - Confirms defensive boundary enforcement: the model refuses to proceed with poisoned zero-fill assumptions.

4. **Execute Scenario 1 (Live Benchmark Traffic Stream):**
   - If CSE-CIC-IDS2018 benchmark parquet splits are synced locally:
     - Select **10 Flows**, Attack Ratio **40%**, and click **"Launch Benchmark Traffic Stream"**.
     - Live alerts immediately stream via WebSockets (`/ws/alerts`) to all connected dashboard tabs.
   - If offline benchmark splits are not present locally:
     - The system safely reports `TestDatasetUnavailable` with clear instructions, directing evaluators to Scenario 2 for zero-dependency inference.

---

### Test Phase 3 — Real-Time Alert Feed & Triage
1. **Navigate to:** Click **"Alert Feed"** in the navigation bar.
2. **Verify Streaming & Filters:**
   - Observe incoming real-time alerts arriving via WebSocket with live blinking status dot.
   - **Threat Level Filter:** Filter by `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
   - **Category Filter:** Filter by `Infiltration`, `Brute Force`, `DoS`, etc.
   - **Priority Slider:** Slide the minimum score to `60` to view only elevated threats.
   - **Search Bar:** Type an IP address (e.g., `192.168`) or attack keyword to verify instant text filtering.
   - **Stream Controls:** Click **"Pause Stream"** to freeze live incoming events for analyst triage; click **"Resume Stream"** to resume.
3. **Select an Alert:** Click the **"Investigate"** button on any alert row.

---

### Test Phase 4 — Deep Alert Investigation with SHAP & MITRE ATT&CK
1. **Navigate to:** Click **"Investigation"** in the navigation bar.
2. **Inspect the 4 Core Diagnostic Panels:**
   - **A. Explainable AI (SHAP) Waterfall Chart:**
     - Horizontal bar chart shows exact Shapley feature attributions.
     - **Red/Rose Bars:** Features pushing the model toward the attack classification (e.g., `Flow Duration`, `Tot Fwd Pkts`, `Bwd IAT Mean`).
     - **Cyan/Blue Bars:** Features pulling toward the normal benign baseline.
     - Displays raw feature values alongside model expected value $E[f(x)]$.
   - **B. Unsupervised Anomaly Telemetry:**
     - Isolation Forest anomaly score vs. decision threshold.
     - Deep Autoencoder reconstruction MSE error vs. residual threshold.
   - **C. MITRE ATT&CK Enterprise Mapping:**
     - Displays correlated STIX 2.1 technique ID (e.g., `T1059`, `T1498`), technique name, and tactical description.
     - Click **"MITRE ATT&CK Spec"** to open the official Mitre Attack documentation page.
     - Review recommended observational mitigations.
   - **D. Analyst Triage Log:**
     - Type a note in the observation text box (e.g., *"Confirmed infiltration flow signature matches host 192.168.10.50"*).
     - Click **"Save Observation Note"** to log the finding with timestamp and observer verification badge.

---

### Test Phase 5 — System Health & Frozen Artifact Provenance
1. **Navigate to:** Click **"System Health"** in the navigation bar.
2. **Verify Provenance Status:**
   - All 6 model components report **`LOADED & ACTIVE`**:
     1. Supervised Classifier (`LightGBM`, Role 3 Retrain v2)
     2. Isolation Forest (Unsupervised outlier estimator)
     3. Deep Autoencoder (PyTorch 5-layer reconstruction engine)
     4. Feature Scaler (Quantile / Robust normalization)
     5. SHAP Explainer (`TreeExplainer`)
     6. MITRE ATT&CK Catalog (`enterprise-attack.json`, STIX 2.1)
3. **Verify Governance Invariants:**
   - `observe_only_mode`: **`TRUE`** (Frozen, immutable)
   - `action_enforced`: **`NONE_OBSERVE_ONLY`** (Frozen, immutable)
   - `automated_packet_dropping`: **`FALSE`** (Permanently prohibited)

---

## 5. Differentiating Genuine Detections vs. Simulated Benchmarks

| Feature | Genuine Flow Inference (Scenario 2) | Benchmark Stream (Scenario 1) |
|---|---|---|
| **Input Source** | 77-feature flow record passed via `/api/v1/predict` | Benchmark test split (`CSE-CIC-IDS2018`) via `/api/v1/alerts/simulate` |
| **Inference Path** | Live LightGBM + Isolation Forest + PyTorch Autoencoder | Live LightGBM + Isolation Forest + PyTorch Autoencoder |
| **XAI Engine** | Exact SHAP TreeExplainer calculation per flow | Fast attribution per stream item |
| **Delivery Channel** | Synchronous REST JSON response | Asynchronous WebSocket push (`/ws/alerts`) |
| **Offline Feasibility** | 100% offline self-contained (bundled with repo) | Requires external CSE-CIC-IDS2018 test parquet split |

---

## 6. Professor Evaluation Evidence Checklist

Use this checklist to record screenshots and verification milestones for the capstone report:

- [ ] **Screenshot 1: SOC Overview Console** (`/ui` or `/dashboard`) showing active KPI cards, severity distribution bar, and live WebSocket connection dot.
- [ ] **Screenshot 2: Real-Time Alert Feed** (`/alerts`) showing filtered alert table with confidence percentages, anomaly flags, and 5-tuple context.
- [ ] **Screenshot 3: Deep Investigation & SHAP Waterfall** (`/investigate`) displaying the red/cyan feature contribution bars for top contributing features.
- [ ] **Screenshot 4: MITRE ATT&CK Framework Mapping** (`/investigate`) displaying correlated technique ID, description, and observational mitigations.
- [ ] **Screenshot 5: System Health & Provenance Table** (`/health`) confirming all 6 model components loaded and `OBSERVE_ONLY_MODE = TRUE`.
- [ ] **Screenshot 6: Demo Scenario Execution** (`/demo`) showing sub-50ms inference latency and schema boundary rejection test results.

---

## 7. Known Limitations & Troubleshooting

1. **Port 8000 in Use:**
   - If port 8000 is occupied by another local service, specify a custom port:
     ```bash
     NEURAL_BREACH_PORT=8080 bash scripts/start_local_demo.sh
     ```
2. **Offline Parquet Notice on Scenario 1:**
   - The CSE-CIC-IDS2018 dataset test split is a large external parquet file (multi-gigabyte). If it has not been synced locally via Google Drive sync, Scenario 1 reports `TestDatasetUnavailable`.
   - **Resolution:** Use Scenario 2, which runs identical live model inference using the bundled 77-feature flow record without requiring external downloads.
3. **PostgreSQL 16 Staging Verification:**
   - In accordance with strict release governance, the PostgreSQL 16 staging concurrency smoke test is formally documented and isolated in `reports/role7/POSTGRESQL16_STAGING_RUNBOOK.md`. Local SOC dashboard evaluation runs independently without requiring live PostgreSQL 16 staging credentials.
