# TEAM NEURAL BREACH — ROLE 4 HANDOFF TO ROLE 6
## Architectural Certification, Deployment Guidelines & Integration Contract

**Project:** AI/ML-Based Cyber Defense Platform  
**Team:** Neural Breach  
**Author:** Cybersecurity Validation Engineer & Red-Team Specialist (Role 4)  
**Recipient:** Senior Backend Engineer & API Developer (Role 6)  
**Branch:** `role4-redteam-validation`  
**Date:** October 25, 2026  
**Status:** CERTIFIED FOR BACKEND INTEGRATION WITH TIERED DEPLOYMENT  

---

### Executive Handoff Statement

Role 4 has completed the independent red-team testing and validation of the frozen Role 3 machine learning models. We certify that the models, preprocessors, and inference engine are stable, verified, and reproducible.

However, based on our empirical findings across 541,345 test flows and red-team evasion tests, **Role 6 must not deploy a naive single-model pipeline**. We provide Role 6 with an engineered **Tiered Defense-in-Depth Architecture** that satisfies both low false-alarm operational constraints and high-sensitivity threat hunting requirements.

---

### 1. Strongest Candidates by Detection Scenario

Based on comprehensive empirical benchmarking, Role 4 designates the following authoritative candidate selections:

| Detection Scenario | Certified Model Artifact | Justification & Measured Evidence | Known Limitation |
| :--- | :--- | :--- | :--- |
| **Tier 1: High-Speed Inline Dropping (Firewall/IPS)** | `supervised_xgboost_benchmark.joblib` | **1.02% Benign FPR** (only 3,058 FP / 300k); **1.78 µs/flow** throughput (561,291 fps); 100% DoS/DDoS/SSH recall | Misses 73% of Infiltration; must not be sole sensor for APTs |
| **Tier 2: SOC Alerting & Threat Hunting** | `supervised_lightgbm_primary.joblib` | **86.74% Infiltration Recall**; **94.91% Attack Recall**; detects low-and-slow reconnaissance and brute force | 35.87% Benign FPR (107k FP); alerts must be aggregated into incidents |
| **Tier 3: Zero-Day & Unseen Anomaly Detection** | `anomaly_deep_autoencoder.pt` | Captures structural telemetry distortions; recall doubles (7.2% -> 16.5%) under dilated APT exfiltration | Requires scaled inputs via `scaler_anomaly.joblib` |
| **Tier 3 (Alternative): Statistical Outlier Filter** | `anomaly_isolation_forest.joblib` | Fast tree-based outlier scoring; calibrated at $\le -0.08063$ for 1% FPR budget | 111-flow tie plateau at -0.1332; must use `<=` operator |
| **Cross-Dataset Benchmark** | `supervised_unsw_nb15.joblib` | **90.06% Accuracy**, **0.9220 F1**, 98.86% Precision across 175,341 UNSW test flows | Separate 42-feature schema (used for cross-telemetry validation) |
| **BANNED FROM DEPLOYMENT** | `supervised_lightgbm_with_port.joblib` | **99.997% Evasion Drop** under adversarial port hopping; overfits to standard ports | **DO NOT LOAD IN PRODUCTION** |

---

### 2. Certified Model Checksums & Repository Paths

Role 6 must verify these exact SHA-256 digests upon container initialization:

```
[Certified Model Registry]
1. XGBoost Inline Classifier:
   Path:   models/role3_retrain_v2/supervised/supervised_xgboost_benchmark.joblib
   SHA256: b1e6281a2a60376a4ed69de0c77ea8f8a87a82fc99d236f17e36bb50a751dfd9

2. LightGBM SOC Threat Hunter:
   Path:   models/role3_retrain_v2/supervised/supervised_lightgbm_primary.joblib
   SHA256: 8953755188a02f37e9d51f067466d9c465aebc73bd43ad765450ef90657d5fb5

3. PyTorch Deep Autoencoder:
   Path:   models/role3_retrain_v2/anomaly/anomaly_deep_autoencoder.pt
   SHA256: 944f68f819d2a92c024c1cd7a5b384c3d43930d753d2e8a850eb831ad21dd965

4. Isolation Forest:
   Path:   models/role3_retrain_v2/anomaly/anomaly_isolation_forest.joblib
   SHA256: f5ba15a1beae24252a8c8d3b4835150dab5990c936fff7b56ee4843a3fd07f7b

5. Anomaly StandardScaler:
   Path:   models/role3_retrain_v2/anomaly/scaler_anomaly.joblib
   SHA256: 566f0a6ca0878c25f9789b6ecae14855bae72225da18c3581ef497bc19d8f201

6. Feature Schema Contract (77 Features):
   Path:   models/role3_retrain_v2/supervised/feature_columns.json
   SHA256: e8db3ce0a3693fb107dc6d0c406852bb2d9f4d2f8fa49c3ce136fe2670e9a591

7. Label Mapping Contract (15 Classes):
   Path:   models/role3_retrain_v2/supervised/label_mapping.json
   SHA256: 62234559bb0ff62858b73f848c4cf3c43ea5d8d0111a43ff6e77174dbfa3e2ef
```

---

### 3. Role 6 Integration Architecture: The Hybrid Tiered Pipeline

Role 6 should implement the following decision workflow in the FastAPI backend:

```
 Incoming Raw Network Flow (77 features)
                    |
                    v
    [ Schema Validation & NaN Imputation ]
                    |
                    v
    [ Tier 1: XGBoost High-Speed Classifier ]
         |                         |
    Is Attack?                Is Benign?
     (Conf >= 0.85)                |
         |                         v
         v             [ Tier 2: LightGBM Primary Triage ]
 [ IMMEDIATE ACTION ]              |
 Drop Packet / Block IP       Is Infiltration /
                              Stealth Attack?
                                   |
                         +---------+---------+
                         |                   |
                        Yes                  No
                         |                   |
                         v                   v
                [ SOC Threat Alert ]   [ Tier 3: Dual Anomaly Check ]
                Priority: HIGH          Autoencoder MSE >= 1.29126
                Investigation Queue     OR IsoForest Score <= -0.08063
                                             |
                                   +---------+---------+
                                   |                   |
                                  Yes                  No
                                   |                   |
                                   v                   v
                          [ Suspicious Anomaly ]   [ Normal Traffic ]
                          Zero-Day / Outlier Log   Pass Through
```

#### Operational Policy:
1. **Automated Blocking (Inline):** Allowed **only** if Tier 1 (XGBoost) predicts an attack with confidence $\ge 0.85$. This guarantees $< 1.02\%$ false disruptions.
2. **SOC Investigation Alerting (Out-of-Band):** Triggered if Tier 2 (LightGBM) predicts `Infiltration`, `Brute Force -Web`, or `Brute Force -XSS`, or if Tier 3 (Autoencoder) flags a structural anomaly.
3. **Correlation Rule:** If both LightGBM and Autoencoder trigger concurrently on a flow classified as Benign by XGBoost, escalate to **Tier-2 Priority Alert** (Stealth Infiltration Signature).

---

### 4. FastAPI Code Contract

Role 6 should instantiate the verified `CyberDefenseInferenceEngine` from `src.models.inference_engine`.

#### Example Production Backend Service:

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any
import pandas as pd
from src.models.inference_engine import CyberDefenseInferenceEngine, ModelInferenceError

app = FastAPI(
    title="Neural Breach Cyber Defense Inference API",
    version="2.0.0",
    description="Role 6 Production Fast-Inference & Threat Triage Engine"
)

# Initialize engines at startup
# Engine 1: Inline blocking engine (low FPR, high throughput)
inline_engine = CyberDefenseInferenceEngine(
    classifier_type="xgboost",
    fpr_budget="1pct"
)

# Engine 2: Deep threat hunting engine (high infiltration recall)
hunting_engine = CyberDefenseInferenceEngine(
    classifier_type="lightgbm",
    fpr_budget="1pct"
)

@app.post("/api/v1/triage/batch")
async def triage_flows(flows: List[Dict[str, Any]]):
    """
    Batched SOC triage endpoint. Accepts list of flow dicts matching 77-feature contract.
    Returns synthesized multi-tier verdict, probabilities, and anomaly alerts.
    """
    try:
        df = pd.DataFrame(flows)
        
        # 1. Execute Tier-1 Inline Inspection (XGBoost)
        triage_inline = inline_engine.predict_flows(df)
        
        # 2. For flows marked Benign by Tier 1, run Tier-2 Threat Hunting (LightGBM)
        benign_indices = [i for i, r in enumerate(triage_inline) if r["predicted_label"] == "Benign"]
        
        if benign_indices:
            df_benign = df.iloc[benign_indices].copy()
            triage_hunting = hunting_engine.predict_flows(df_benign)
            
            for sub_idx, orig_idx in enumerate(benign_indices):
                hunt_result = triage_hunting[sub_idx]
                # If LightGBM spots Infiltration or Stealth Attack, flag for SOC review
                if hunt_result["predicted_label"] != "Benign":
                    triage_inline[orig_idx]["soc_escalation"] = True
                    triage_inline[orig_idx]["hunting_detected_label"] = hunt_result["predicted_label"]
                    triage_inline[orig_idx]["hunting_confidence"] = hunt_result["confidence"]
                    triage_inline[orig_idx]["threat_level"] = "ELEVATED_THREAT_HUNTING"
        
        return {"status": "SUCCESS", "results": triage_inline}
    except ModelInferenceError as mie:
        raise HTTPException(status_code=422, detail=str(mie))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference failure: {str(e)}")
```

---

### 5. Verified Anomaly Detection Threshold Semantics

Role 6 must enforce the calibrated threshold semantics verified by Role 4:

```python
# Isolation Forest Alert Condition (Lower score = more anomalous)
# At 1% FPR Budget:
is_iso_anomaly = (iso_forest_score <= -0.08063)
# At 5% FPR Budget:
is_iso_anomaly = (iso_forest_score <= -0.01779)

# Deep Autoencoder Alert Condition (Higher MSE = more anomalous)
# At 1% FPR Budget:
is_ae_anomaly = (autoencoder_mse >= 1.29126)
# At 5% FPR Budget:
is_ae_anomaly = (autoencoder_mse >= 0.24448)
```
*Note:* The `<=` operator on Isolation Forest is mandatory to prevent boundary flipping on the $-0.13326530$ tie plateau.

---

### 6. Recommended API Endpoints for Role 6

1. `POST /api/v1/triage/single` — Real-time single-flow triage (amortized latency: 227 µs).
2. `POST /api/v1/triage/batch` — High-throughput streaming batch inspection (supports up to 4,096 flows/batch at 1.78 µs/flow).
3. `GET /api/v1/models/health` — Returns SHA-256 digests, active thresholds, and memory footprint.
4. `GET /api/v1/metrics/runtime` — Exposes inference throughput (fps), buffer queue depth, and anomaly alert counts for Prometheus/Grafana.

---

### 7. Explicit Prohibitions & Operational Constraints

1. **NEVER load `supervised_lightgbm_with_port.joblib`:** Doing so creates an immediate 99.99% bypass vulnerability against port-hopping adversaries.
2. **NEVER use flow ML as the sole Web WAF:** Flow-level models miss $> 70\%$ of SQL Injection and XSS attacks. Layer 7 payload inspect must sit upstream.
3. **NEVER enable automated IP blocking on LightGBM alone:** With a 35.87% benign false positive rate, raw LightGBM predictions will take down enterprise internet connectivity within minutes. Automated blocking must require XGBoost verification or human SOC analyst confirmation.

---

### Deliverable Sign-Off

All test evidence, logs, and benchmark figures have been independently produced and archived under:
`reports/model_evaluation/role4/`

**Certified by:** Role 4 Cybersecurity Validation Engineer  
**Handoff to:** Role 6 Backend Engineer  
**Status:** READY FOR API INTEGRATION  
