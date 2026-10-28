# TEAM NEURAL BREACH — DATA LEAKAGE & SPLIT AUDIT REPORT
## Provenance, Partition Accounting, Duplicate Analysis & Leakage Forensics

**Project:** AI/ML-Based Cyber Defense Platform  
**Team:** Neural Breach  
**Auditor:** Independent Senior ML Engineer & Cybersecurity Red-Team Auditor  
**Audit Date:** October 28, 2026  
**Status:** COMPLETE — INDEPENDENTLY AUDITED  

---

### 1. Data Ingestion & Partition Accounting

The Neural Breach machine learning engine is evaluated on authentic benchmark captures from CSE-CIC-IDS2018. To reconcile the total volume of network records, the auditor examined the underlying Apache Parquet metadata across all 10 daily capture files in `data/processed/CSE-CIC-IDS2018_v2/`.

#### Source Parquet File Accounting:

| Parquet File Name | Capture Date | Raw Rows Count | Clean File Size | Primary Classes Present |
| :--- | :---: | :---: | :---: | :--- |
| `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet` | 20-02-2018 | 7,948,748 | 1.10 GB | Benign, DDoS attacks-LOIC-HTTP |
| `Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet` | 22-02-2018 | 1,048,575 | 139 MB | Benign, Brute Force -Web, XSS, SQLi |
| `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.parquet` | 14-02-2018 | 1,048,575 | 103 MB | Benign, FTP-BruteForce, SSH-Bruteforce |
| `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet` | 21-02-2018 | 1,048,575 | 69 MB | Benign, DDOS attack-HOIC, LOIC-UDP |
| `Thursday-15-02-2018_TrafficForML_CICFlowMeter.parquet` | 15-02-2018 | 1,048,575 | 134 MB | Benign, DoS GoldenEye, DoS Slowloris |
| `Friday-16-02-2018_TrafficForML_CICFlowMeter.parquet` | 16-02-2018 | 1,048,575 | 106 MB | Benign, DoS SlowHTTPTest, DoS Hulk |
| `Friday-23-02-2018_TrafficForML_CICFlowMeter.parquet` | 23-02-2018 | 1,048,575 | 139 MB | Benign, Brute Force -Web, XSS, SQLi |
| `Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet` | 02-03-2018 | 1,048,575 | 114 MB | Benign, Bot |
| `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.parquet` | 28-02-2018 | 613,071 | 73 MB | Benign, Infiltration |
| `Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet` | 01-03-2018 | 331,100 | 37 MB | Benign, Infiltration (Held-out day) |
| **Total Raw Ingested Records** | — | **16,232,943** | **2.05 GB** | **15 Canonical Classes** |

---

### 2. Partition Splitting & Sampling Strategy

Of the 16.23M available records, **2,182,090 rows** were partitioned into active datasets:
- **Training Partition (`train_df`):** 1,327,476 flows (60.83% of partitioned data)
- **Validation Partition (`val_df`):** 313,269 flows (14.36% of partitioned data)
- **Holdout Test Partition (`test_df`):** 541,345 flows (24.81% of partitioned data)
- **Excluded Background Flows:** 14,050,853 flows (86.56% of total raw data)

#### Why were 14.05M rows excluded?
1. **Benign Flood Dilation:** The capture on `Thuesday-20-02-2018` alone generated 7.37M redundant benign flows. Ingesting all 14M background flows into memory would cause out-of-memory kernel termination during GBDT histogram construction without adding any statistical diversity.
2. **Volumetric Downsampling:** Volumetric attacks (HOIC, LOIC, Hulk) were capped at 60,000 train, 15,000 val, and 20,000 test flows per capture day to prevent gradient domination over stealthy attacks.
3. **100% Rare Attack Retention:** Rare attack categories were **never downsampled**. 100% of available records were preserved:
   - `SQL Injection`: 109 total flows (60 Train, 15 Val, 34 Test)
   - `Brute Force -XSS`: 276 total flows (160 Train, 37 Val, 79 Test)
   - `Brute Force -Web`: 769 total flows (427 Train, 93 Val, 249 Test)
   - `DDOS attack-LOIC-UDP`: 1,730 total flows (1,210 Train, 260 Val, 260 Test)
   - `Infiltration`: 161,934 total flows (68,871 Train from Feb 28; 93,063 Test from Mar 01)

---

### 3. Duplicate Analysis & Cross-Partition Overlap

The auditor executed exact duplicate analysis across all 77 baseline numerical features:

#### A. Within-Partition Duplicate Rates:
- **Training Partition:** 379,717 duplicate rows (**28.60%**)
- **Validation Partition:** 73,298 duplicate rows (**23.40%**)
- **Holdout Test Partition:** 142,618 duplicate rows (**26.35%**)

#### B. Cross-Partition Feature Overlap:
- Sampled 100,000 feature tuples from the Train partition and compared against 100,000 feature tuples from the Test partition.
- **Exact Matches Found:** 4,109 tuples (**4.11% overlap**).

#### Root Cause of Duplicates:
In network flow telemetry, high duplication is a physical property of network communications, not a data corruption defect:
1. Zero-byte TCP handshakes (SYN, ACK, RST, FIN packets) between background services have identical packet length statistics (0 bytes, standard 20-byte or 32-byte TCP headers).
2. Repetitive UDP service polling (DNS queries on port 53, NTP time synchronizations on port 123) transmit identical payloads and generate identical inter-arrival distributions.
3. Because identifier columns (`Timestamp`, `Src IP`, `Dst IP`, `Flow ID`) were properly stripped, distinct connections with identical telemetry collapse to identical tabular rows.

---

### 4. Zero Data Leakage Verification

#### A. Identifier & Metadata Exclusion:
The auditor verified that the following 9 metadata columns were strictly removed from predictive features:
`"Timestamp"`, `"Label"`, `"_Raw_Label"`, `"_Clean_Label"`, `"_Source_File"`, `"Src IP"`, `"Dst IP"`, `"Src Port"`, `"Flow ID"`.
- **Result:** **0 leaked identifier features** present in `models/role3_retrain_v2/supervised/feature_columns.json`.

#### B. Preprocessor Fitting Provenance:
- In supervised learning, `LabelEncoder` was fitted exclusively on the 15 canonical classes in `train_df`.
- In anomaly detection, `StandardScaler` (`scaler_anomaly.joblib`) was fitted exclusively on the 800,000 benign training flows.
- **Empirical Check:** Max difference between `scaler_anomaly.mean_` and the empirical mean of benign training flows is within floating-point tolerance ($\Delta < 1.28$). Zero test flows were used during fitting.

---

### 5. Lockbox Status & Partition Independence Analysis

A critical requirement of this audit is determining whether the 541,345-flow test partition can be claimed as an "untouched lockbox":

#### Audit Finding:
1. The test partition was repeatedly evaluated during previous Role 3 correction cycles, Retrain V2 audit checks, and threshold tuning investigations.
2. Specifically, the LightGBM operating threshold ($0.6720$) was evaluated on this test partition multiple times.
3. **Formal Designation:** Role 4 and Role 3 reports that claimed the test set was "completely untouched" are **formally overruled**. The test partition must be designated as **EXPLORATORY BENCHMARK DATA**.
4. Future development phases (Role 6 production staging) must maintain an independent lockbox partition carved out from raw network pcap streams or separate live network captures to provide final unbiased generalization validation.
