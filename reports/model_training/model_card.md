# Model Card: Neural Breach Cyber Defense Detection Engine

**Version**: 3.0.0-real-data  
**Date**: 2026-10-24  
**Authors**: Team Neural Breach — Role 3 (Machine Learning & Detection Specialist)  
**Target Environments**: SOC Tier-1 Automated Triage, SOC Tier-2 Threat Hunting, FastAPI Inference Microservice  

---

## 1. Model Overview & Architecture

The Neural Breach Detection Engine employs an authentic hybrid multi-tier detection architecture combining regularized supervised gradient boosting with deep unsupervised representation learning.

```
Incoming Network Flow (77 Canonical Features)
                   │
                   ▼
     ┌───────────────────────────┐
     │  Schema Validation & Sanitization  │
     └─────────────┬─────────────┘
                   │
         ┌─────────┴─────────┐
         │                   │
         ▼                   ▼
┌──────────────────┐ ┌──────────────────────────┐
│  Tier-1 Supervised│ │ Tier-2 Anomaly Detector  │
│  XGBoost Classifier│ │ PyTorch Deep Autoencoder │
│  (15 Classes)    │ │ (77->48->24->12 Bottleneck)│
└────────┬─────────┘ └────────────┬─────────────┘
         │                        │
         ▼                        ▼
[Predicted Category]      [Reconstruction Error]
[Confidence Probability]  [Outlier Alert Score]
         │                        │
         └─────────┬──────────────┘
                   │
                   ▼
┌───────────────────────────────────────────────┐
│     Hybrid Correlation & SOC Action Engine    │
│  - High Conf Attack -> Automated Quarantine   │
│  - Low Conf / Anomaly -> Tier-2 Analyst Review │
└───────────────────────────────────────────────┘
```

### Components Summary

1. **Supervised Multi-Class Classifier (`supervised_xgboost_candidate.joblib`)**:
   - **Algorithm**: Extreme Gradient Boosting (XGBoost 1.7.6) with exact greedy tree splitting.
   - **Hyperparameters**: `n_estimators=100`, `max_depth=8`, `learning_rate=0.1`, `reg_lambda=2.0`, `subsample=0.8`, `colsample_bytree=0.8`.
   - **Feature Dimensionality**: 77 canonical numerical network-flow features (no IP, MAC, timestamp, or port identifiers).
   - **Classes Supported**: 15 classes (Benign + 14 attack families across DoS, DDoS, Brute Force, Web, Botnet, and Infiltration).
   - **Inference Latency**: **3.52 µs per flow** (Apple Silicon M-series single thread).
   - **Throughput**: **290,072 flows/second**.

2. **Unsupervised Anomaly Detector (`anomaly_deep_autoencoder.pt`)**:
   - **Architecture**: 7-layer Symmetric Fully-Connected Deep Autoencoder ($77 \to 48 \to 24 \to 12 \to 24 \to 48 \to 77$).
   - **Activation**: LeakyReLU ($\alpha = 0.05$) with LayerNorm on intermediate layers; Linear output layer.
   - **Objective**: Mean Squared Reconstruction Error (MSE).
   - **Training Provenance**: Trained strictly on 800,000 pure Benign network flows scaled via `StandardScaler`. Zero attack contamination.
   - **Inference Latency**: **0.14 µs per flow** (Batch size 1,024).

3. **Fallback Anomaly Baseline (`anomaly_isolation_forest.joblib`)**:
   - **Algorithm**: Scikit-Learn IsolationForest (`n_estimators=100`, `contamination=0.01`).
   - **Inference Latency**: **3.05 µs per flow**.

4. **Secondary Independent Benchmark (`supervised_unsw_nb15.joblib`)**:
   - **Algorithm**: HistGradientBoostingClassifier evaluated on UNSW-NB15 (42 features, binary classification).

---

## 2. Intended Use & Scope

### Primary Intended Use Cases
- **High-Throughput In-Line Flow Triage**: Real-time multi-class classification of preprocessed bidirectional network flows captured at perimeter firewalls and core switches.
- **Novel Threat & Zero-Day Hunting**: Identification of structurally anomalous flows (high MSE reconstruction error) that deviate from established normal baseline traffic, alerting SOC analysts even if signatures or supervised classifiers fail.
- **Port-Agnostic Defense**: Evaluation without reliance on standard destination ports, preventing evasion by attackers employing non-standard service ports.

### Out-of-Scope & Prohibited Uses
- **Direct Raw Packet Ingestion**: The models require tabular flow summaries (e.g., CICFlowMeter / Zeek extracted bidirectional metrics); raw PCAP bytes cannot be ingested directly.
- **Fully Autonomous Perimeter Severing Without Guardrails**: The models must not be granted unconstrained firewall-rule execution privileges. High-impact mitigations (e.g., BGP route blackholing) must require human confirmation or SOC playbooks.
- **Cross-Domain Feature Mixing**: Do not feed UNSW-NB15 features into the CSE-CIC-IDS2018 model, or vice versa.

---

## 3. Data Provenance & Training Pipeline

### Datasets Utilized
- **CSE-CIC-IDS2018_v2**: 16,232,943 authentic flow records collected by the Canadian Institute for Cybersecurity across 10 distinct days (Feb 14 to Mar 02, 2018).
  - Schema reconciliation resolved an 87-column vs. 83-column discrepancy on the February 20 capture by excluding 4 identifiers (`Src IP`, `Dst IP`, `Src Port`, `Flow ID`).
  - Master dataset partitioned into:
    - Train: 1,327,476 flows
    - Validation: 313,269 flows
    - Test: 541,345 flows (100% rare attack coverage preserved).
- **UNSW-NB15**: 257,673 flows (82,332 train / 175,341 test) with official canonical splits and 42 predictive features.
- **CTU-13 Scenario 1**: 14,521 flows capturing Neris botnet command-and-control behavior.

### Feature Handling & Integrity
- **Predictive Features (77)**: Flow duration, forward/backward packet counts, packet lengths (mean, max, min, std), inter-arrival times (IAT), flag counts (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR), down/up ratios, window sizes, and subflow statistics.
- **Explicitly Excluded Columns (7)**: `Timestamp`, `Src IP`, `Dst IP`, `Src Port`, `Flow ID`, `_Source_File`, `_Split`.
- **Destination Port (`Dst Port`)**: Excluded from baseline (77 features) to prevent port-shortcut overfitting; studied in ablation.

---

## 4. Evaluation Summary & Performance Metrics

### Touchstone Benchmark Results (Untouched Test Partition: 541,345 Flows)

| Metric | XGBoost Candidate | HistGBT Baseline | Deep Autoencoder (1% FPR) | UNSW-NB15 Model |
| :--- | :---: | :---: | :---: | :---: |
| **Accuracy** | **84.57%** | 73.66% | N/A (Binary Anomaly) | **90.00%** |
| **Macro F1** | **0.8168** | 0.7189 | N/A | **0.8988** |
| **Benign FPR** | **1.02%** (3,058 / 300,000) | 39.75% (119,259 / 300k) | **1.14%** | **2.06%** |
| **Attack Detection Rate** | **71.67%** (172,969 / 241k) | 95.64% (230,829 / 241k) | **4.52%** (Pure Zero-Day) | **86.27%** |
| **DDoS/DoS Recall** | **>99.9%** | >99.9% | Variable by profile | N/A |
| **Brute Force Recall** | **94.0%** | 94.2% | Up to 66% (Slowloris) | N/A |
| **Inference Latency** | **3.52 µs** | 5.01 µs | **0.14 µs** | 4.12 µs |

---

## 5. Known Limitations & Failure Modes

1. **Infiltration Recall Trade-Off**:
   - Infiltration traffic consists of Nmap TCP port sweeps and Dropbox exfiltration that mimics normal enterprise web interactions.
   - Forcing high Infiltration recall resulted in a 39.75% to 58.58% false-alarm rate on normal enterprise traffic.
   - The calibrated XGBoost candidate suppresses false alarms to 1.02% by requiring stronger signal, which reduces Infiltration recall to 26.52%.
   - *Mitigation*: Infiltration should be correlated with host endpoint detection (EDR) rather than solely relying on flow headers.

2. **Extremely Rare Web Attacks**:
   - `SQL Injection` (15 test flows) and `Brute Force - XSS` (37 test flows) represent less than 0.001% of benchmark traffic.
   - While precision is high (100% on XSS and SQL Injection), recall is 43.2% and 13.3% due to low sample diversity.
   - *Mitigation*: Deploy a Web Application Firewall (WAF) for deep application-layer inspection.

3. **Adversarial Flow Manipulation**:
   - Attackers injecting dummy packets or pacing packet inter-arrival times (traffic morphing) could push features closer to benign distributions.
   - Role 4 must validate adversarial robustness under timing jitter and packet-splitting perturbations.

---

## 6. Safe Operation & SOC Deployment Guidance

### SOC Alert Thresholds & Calibration
- **Tier-1 Automatic Block**:
  - Supervised probability $P(\text{Attack}) \ge 0.85$ AND Category $\in \{\text{DDoS, DoS, SSH-Bruteforce, Bot}\}$.
- **Tier-2 Analyst Triage Queue**:
  - Supervised probability $0.50 \le P(\text{Attack}) < 0.85$, OR Category $\in \{\text{Infiltration, Web Attacks}\}$.
- **Zero-Day Anomaly Hunt**:
  - Supervised output $=$ `Benign` BUT Deep Autoencoder $\text{MSE} \ge 0.3384$ (the calibrated 1% FPR operational threshold).

### Maintenance & Continuous Monitoring
- Re-estimate background feature statistics weekly to detect enterprise network drift.
- Audit benign false positive rates continuously; if FPR exceeds 2.5%, retrain the background scaler and autoencoder baseline.
