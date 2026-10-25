# MODEL CARD: NEURAL BREACH HYBRID CYBER DETECTION ENGINE (V2)
## Team Neural Breach — AI/ML Cyber Defense Platform
**Version:** 3.2.0-retrain-v2  
**Date:** 2026-10-25  
**Authors:** Team Neural Breach — Role 3 (Machine Learning & Anomaly Detection Specialist)  
**Target Environments:** SOC Tier-1 Automated Triage, SOC Tier-2 Threat Hunting, FastAPI Inference Microservice  

---

## 1. Model Overview & Dual Detection Architecture

The Neural Breach Detection Engine V2 combines supervised gradient-boosted decision trees with deep unsupervised reconstruction representation learning:

```
                      INCOMING NETWORK FLOW
                                │
                                ▼
            ┌────────────────────────────────────────┐
            │   Schema Validation & Preprocessing    │
            │   (77 Canonical Features, float32)     │
            └───────────────────┬────────────────────┘
                                │
                 ┌──────────────┴──────────────┐
                 ▼                             ▼
    ┌───────────────────────────┐ ┌──────────────────────────┐
    │  Tier-1 Supervised Tree   │ │  Tier-2 Deep Autoencoder │
    │  XGBoost / LightGBM       │ │  PyTorch 7-Layer Bottled │
    │  (15 Canonical Classes)   │ │  (Reconstruction MSE)    │
    └────────────┬──────────────┘ └────────────┬─────────────┘
                 │                             │
                 ▼                             ▼
       [Predicted Threat Class]      [Reconstruction Error]
       [Confidence Probability]      [Outlier Alert Score]
                 │                             │
                 └──────────────┬──────────────┘
                                │
                                ▼
            ┌────────────────────────────────────────┐
            │   Hybrid SOC Action & Playbook Engine  │
            │   - P(Attack) >= 0.85 -> Auto-Quarantine│
            │   - Anomaly Alert     -> Tier-2 Triage │
            └────────────────────────────────────────┘
```

### Component Details
1. **Primary Supervised Classifier (`supervised_lightgbm_primary.joblib`)**:
   - **Algorithm**: LightGBM 4.7.0 with balanced class weighting.
   - **Hyperparameters**: `n_estimators=100`, `max_depth=8`, `num_leaves=63`, `learning_rate=0.1`, `subsample=0.8`, `colsample_bytree=0.8`.
   - **Target**: Maximum threat interception (**94.91% attack recall**; 86.74% on Infiltration).
2. **Benchmark Supervised Candidate (`supervised_xgboost_benchmark.joblib`)**:
   - **Algorithm**: XGBoost 1.7.6 with L2 regularization (`reg_lambda=2.0`).
   - **Target**: Ultra-low false alarms (**1.02% Benign FPR**; 98.98% specificity; 290,072 flows/s).
3. **Unsupervised Anomaly Detector (`anomaly_deep_autoencoder.pt`)**:
   - **Architecture**: 7-layer Symmetric PyTorch Autoencoder ($77 \to 48 \to 24 \to 12 \to 24 \to 48 \to 77$).
   - **Training Set**: 800,000 pure Benign flows (zero attack contamination).
   - **Throughput**: **2,465,114 flows/sec** (@ Batch 1024).
4. **Independent Benchmark (`supervised_unsw_nb15.joblib`)**:
   - **Algorithm**: LightGBM binary classifier on UNSW-NB15 (42 features, 90.06% accuracy).

---

## 2. Intended Use & Deployment Scope

### In-Scope Operational Scenarios
- **High-Throughput Perimeter Ingestion**: Multi-class classification of preprocessed bidirectional network flows captured at core routers and firewalls.
- **Zero-Day & Out-of-Distribution Alerting**: Catching abnormal packet geometries (e.g. UDP reflection floods, slow TCP exhaustion) that deviate from the normal enterprise manifold.
- **Port-Agnostic Defense**: Evaluating flows without relying on standard destination ports, preventing adversary bypass via port hopping.

### Prohibited & Out-of-Scope Uses
- **Direct PCAP Byte Ingestion**: The models require tabular flow metrics extracted via CICFlowMeter or Zeek; raw packet bytes cannot be ingested directly.
- **Unconstrained Autonomous Mitigation**: The models must not be granted unmediated root permissions to alter core BGP routing or execute destructive firewall rules without SOC human oversight.
- **Cross-Domain Feature Mixing**: Do not feed UNSW-NB15 features into CSE-CIC-IDS2018 models, or vice versa.

---

## 3. Training Data Provenance & Feature Schema

- **Primary Source**: 16,232,943 authentic flow records from CSE-CIC-IDS2018 across 10 daily captures.
- **Partitioning**: 2,182,090 flows processed (1,327,476 train / 313,269 val / 541,345 test).
- **Rare Attacks**: 100% of all rare threat vectors preserved across partitions.
- **Canonical Feature Set (77)**: Flow duration, forward/backward packet counts, packet lengths, inter-arrival times, flag counts (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR), down/up ratios, window sizes, and subflow metrics.
- **Excluded Columns (7)**: `Timestamp`, `Src IP`, `Dst IP`, `Src Port`, `Flow ID`, `_Source_File`, `_Clean_Label`.

---

## 4. Evaluation Summary (Untouched Test Partition: 541,345 Flows)

| Metric | LightGBM Primary | XGBoost Benchmark | Deep Autoencoder (1% FPR) | UNSW-NB15 Model |
| :--- | :---: | :---: | :---: | :---: |
| **Accuracy** | **75.62%** | **84.57%** | N/A (Anomaly) | **90.06%** |
| **Macro-F1 Score** | **0.8057** | **0.8168** | N/A | **0.9220** |
| **Benign FPR** | 35.87% (107,598 FP) | **1.02%** (3,058 FP) | **0.42%** (1,269 FP) | **2.12%** |
| **Overall Attack Recall** | **94.91%** | **71.67%** | **13.54%** (Zero-Day) | **86.38%** |
| **Infiltration Recall** | **86.74%** | **26.52%** | **7.20%** | N/A |
| **High-Volume Flood Recall**| **100.00%** | **>99.9%** | 100% (LOIC-UDP) | N/A |
| **Inference Latency** | 14.84 µs (@b1024) | **1.97 µs** (@b1024) | **0.22 µs** (@b1024) | 4.10 µs |
| **Sustained Throughput** | 67,379 flows/s | **508,089 flows/s** | **4,597,939 flows/s** | 243,900 flows/s |

---

## 5. Known Limitations & Operating Guidance

1. **The Infiltration Trade-Off**:
   - LightGBM achieves 86.74% Infiltration recall at the cost of elevated false alarms (35.87%).
   - XGBoost achieves 1.02% false alarms at the cost of lower Infiltration recall (26.52%).
   - *Operational Policy*: For production firewalls, deploy **XGBoost with Tier-2 Deep Autoencoder alerting**. Correlate suspicious events with host-level EDR telemetry.
2. **Rare Web Exploit Sample Size**:
   - SQL Injection ($N=15$, CI $[3.7\%, 37.9\%]$) and XSS ($N=37$, CI $[28.7\%, 59.1\%]$) are sample-constrained in the benchmark. A Web Application Firewall (WAF) is required for deep HTTP body inspection.
