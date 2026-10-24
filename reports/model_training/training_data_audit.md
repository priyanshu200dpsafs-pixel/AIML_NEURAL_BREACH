# Training Data Audit: Real-Data Ingestion & Schema Reconciliation

**Project:** AI/ML-Based Cyber Defense Platform  
**Team:** Neural Breach  
**Role:** Role 3 (Machine Learning & Anomaly Detection)  
**Execution Date:** October 24, 2026  
**Status:** **AUDITED & VERIFIED AGAINST ROLE 2 HANDOFF**  

---

## 1. Primary Data Source: CSE-CIC-IDS2018_v2 Audit

All 10 daily captures located in `data/processed/CSE-CIC-IDS2018_v2/` were independently inspected, audited for column consistency, row counts, and label distributions.

### Ingestion Table (All 10 Captures)

| Daily Capture File | Clean Rows | Columns | Attack Classes Present | File Size |
| :--- | :---: | :---: | :--- | :---: |
| `Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet` | 1,048,575 | 83 | Benign (762,384), Bot (286,191) | 114 MB |
| `Friday-16-02-2018_TrafficForML_CICFlowMeter.parquet` | 1,048,574 | 83 | Benign (446,772), DoS Hulk (461,912), DoS SlowHTTPTest (139,890) | 106 MB |
| `Friday-23-02-2018_TrafficForML_CICFlowMeter.parquet` | 1,048,575 | 83 | Benign (1,048,009), Brute Force Web (362), XSS (151), SQLi (53) | 139 MB |
| `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet` | 7,948,748 | 87 | Benign (7,372,557), DDoS attacks-LOIC-HTTP (576,191) | 1.10 GB |
| `Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet` | 331,100 | 83 | Benign (238,037), Infiltration (93,063) | 37 MB |
| `Thursday-15-02-2018_TrafficForML_CICFlowMeter.parquet` | 1,048,575 | 83 | Benign (996,077), DoS GoldenEye (41,508), DoS Slowloris (10,990) | 134 MB |
| `Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet` | 1,048,575 | 83 | Benign (1,048,213), Brute Force Web (249), XSS (79), SQLi (34) | 139 MB |
| `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.parquet` | 1,048,575 | 83 | Benign (667,626), FTP-BruteForce (193,360), SSH-Bruteforce (187,589) | 103 MB |
| `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet` | 1,048,575 | 83 | Benign (360,833), DDOS attack-HOIC (686,012), DDOS attack-LOIC-UDP (1,730) | 69 MB |
| `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.parquet` | 613,071 | 83 | Benign (544,200), Infiltration (68,871) | 73 MB |
| **TOTAL** | **16,232,943** | — | **15 Classes (1 Benign + 14 Distinct Cyber Attacks)** | **2.04 GB** |

---

## 2. Feature Schema Reconciliation

### Schema Discrepancy Resolution
- **83-Column Files (9 Captures)**: Standard 80 CICFlowMeter columns + `_Raw_Label`, `_Clean_Label`, `_Source_File`.
- **87-Column File (`Thuesday-20-02-2018`)**: Contains 4 additional columns:
  `{'Src IP', 'Dst IP', 'Src Port', 'Flow ID'}`.
- **Defensible Treatment**:
  As specified in Role 2's `feature_policy.py`, `Src IP`, `Dst IP`, and `Flow ID` are network topology identifiers that cause overfitting to lab IP addresses. `Src Port` is an ephemeral client port.
  Excluding these 4 columns harmonizes the schema across all 10 daily captures without fabricating or imputing missing data.
- **Predictive Feature Counts**:
  - **77 Baseline Features**: Canonical CICFlowMeter flow attributes, strictly excluding `Dst Port` and identifiers.
  - **78 Features With Port**: Includes `Dst Port` for destination-port memorization ablation testing.

---

## 3. Label Taxonomy & Harmonization

| Canonical Clean Label | Category | Total Records Across All 10 Captures | % of Full Dataset | Partition Policy |
| :--- | :--- | :---: | :---: | :--- |
| **Benign** | Normal Baseline | 13,484,708 | 83.07% | Stratified sample across all 10 days |
| **DDOS attack-HOIC** | Volumetric DDoS | 686,012 | 4.23% | Stratified chronological |
| **DDoS attacks-LOIC-HTTP** | Application DDoS | 576,191 | 3.55% | Stratified chronological |
| **DoS attacks-Hulk** | Web Application DoS | 461,912 | 2.85% | Stratified chronological |
| **Bot** | Ares Botnet C&C | 286,191 | 1.76% | Stratified chronological |
| **FTP-BruteForce** | Authentication Brute Force | 193,360 | 1.19% | Stratified chronological |
| **SSH-Bruteforce** | Authentication Brute Force | 187,589 | 1.16% | Stratified chronological |
| **Infiltration** | Lateral Movement | 161,934 | 1.00% | Feb 28 $\to$ Train, Mar 01 $\to$ Held-Out Test |
| **DoS attacks-SlowHTTPTest** | Slow Connection Exhaustion | 139,890 | 0.86% | Stratified chronological |
| **DoS attacks-GoldenEye** | HTTP DoS | 41,508 | 0.26% | 100% Retained across splits |
| **DoS attacks-Slowloris** | Connection Header Exhaustion | 10,990 | 0.07% | 100% Retained across splits |
| **DDOS attack-LOIC-UDP** | UDP Flood | 1,730 | 0.01% | 100% Retained across splits |
| **Brute Force -Web** | Web Form Authentication | 611 | 0.004% | 100% Retained across splits |
| **Brute Force -XSS** | Cross-Site Scripting Injection | 230 | 0.001% | 100% Retained across splits |
| **SQL Injection** | Database Query Injection | 87 | 0.0005% | 100% Retained across splits |

---

## 4. Multi-Dataset Benchmarks Audited

### A. UNSW-NB15 Benchmark
- **File Provenance**: `data/processed/UNSW-NB15/UNSW_NB15_training-set.parquet` (82,332 rows) & `UNSW_NB15_testing-set.parquet` (175,341 rows).
- **Features**: 42 numeric predictive features (including `dur`, `spkts`, `dpkts`, `sbytes`, `rate`, `sttl`, `dload`, and encoded `xProt`, `xServ`, `xState`).
- **Segregation Mandate**: Maintained strictly separate from CSE-CIC-IDS2018 to prevent structural null explosion and feature distribution collapse.
- **Trained Model**: Dedicated binary classifier `supervised_unsw_nb15.joblib`.

### B. CTU-13 Scenario 1 Benchmark
- **File Provenance**: `data/processed/CTU-13/ctu13_scenario1_flows.parquet` (14,521 flows).
- **Labeling Limitation**: All 14,521 flows were labeled as `Botnet-Neris` based on an infected IP heuristic (`147.32.84.165`). Does not represent a balanced benign/malicious distribution. Used exclusively as an out-of-distribution evaluation benchmark for anomaly detectors.
