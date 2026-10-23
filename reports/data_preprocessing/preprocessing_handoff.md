# Data Engineering Handoff Document for Role 3 (ML Model Development)
**Project: AI/ML-Based Cyber Defense Platform**  
**Team: Neural Breach**  
**Author: Senior Cybersecurity Data Engineer (Role 2)**  
**Target Recipient: Senior ML/AI Engineers (Role 3)**  
**Handoff Date: October 22, 2026**  
**Status: READY FOR MODEL TRAINING**

---

## 1. Executive Summary & Deliverables Overview

Role 2 (Data Engineering & Network Feature Extraction) has completed the ingestion, cleaning, validation, feature policy specification, and extraction across all collected datasets.

All data has been converted to high-performance, compressed **Apache Parquet (`snappy`)** format. Memory-safe, chunked, and vectorized processing engines were used throughout, ensuring 100% data integrity, zero silent drops, and full forensic provenance tracking.

---

## 2. Directory Structure & Processed Datasets Ready for Modeling

### 2.1 Processed Dataset Registry
| Dataset | Directory Path | Format | Record Count | File Size | Primary Target Field | Classification Type |
| :--- | :--- | :--- | :---: | :---: | :--- | :--- |
| **CSE-CIC-IDS2018 (Production)** | `data/processed/CSE-CIC-IDS2018_v2/` | Parquet | Multi-Million | ~750 MB | `Label` | Multiclass (15 Classes) & Binary |
| **CSE-CIC-IDS2018 (Baseline Splits)** | `data/processed/splits/` | Parquet | 3,041,320 | 202.5 MB | `Label` / `Clean_Label` | 70% Train, 15% Val, 15% Test |
| **UNSW-NB15 (Benchmark Train)** | `data/processed/UNSW-NB15/UNSW_NB15_training-set.parquet` | Parquet | 82,332 | 6.4 MB | `label` | Binary (0=Normal, 1=Attack) |
| **UNSW-NB15 (Benchmark Test)** | `data/processed/UNSW-NB15/UNSW_NB15_testing-set.parquet` | Parquet | 175,341 | 12.6 MB | `label` | Binary (0=Normal, 1=Attack) |
| **CTU-13 Scenario 1 (Flows)** | `data/processed/CTU-13/ctu13_scenario1_flows.parquet` | Parquet | 14,521 | 1.59 MB | `Label` | Binary (`Botnet-Neris` vs `Benign`) |
| **CTU-13 Scenario 1 (HTTP)** | `data/processed/CTU-13/ctu13_http_telemetry.parquet` | Parquet | 786 | 0.05 MB | N/A | Web Inspection Telemetry |
| **LANL Cyber1 (Red Team)** | `data/processed/LANL/lanl_redteam_events.parquet` | Parquet | 749 | 0.01 MB | Ground Truth Timeline | Adversary Compromise Events |

---

## 3. Schemas, Feature Roles & Usage Policies

### 3.1 Strict Dataset Segregation Mandate
> [!IMPORTANT]
> **DO NOT MERGE OR CONCATENATE CSE-CIC-IDS2018, UNSW-NB15, OR CTU-13 FLOW RECORDS INTO A SINGLE TABLE.**
> - CSE-CIC-IDS2018 uses 80 CICFlowMeter packet statistical features.
> - UNSW-NB15 uses 44 Argus/Bro state-machine window features (`sload`, `dload`, `ct_srv_src`).
> - CTU-13 uses 42 Scapy bidirectional flow features.
>
> Attempting to train a single monolithic model across merged tables creates 50%+ structural nulls and causes catastrophic feature distribution collapse. Train separate, specialized detector modules or build an ensemble architecture.

### 3.2 Predictive Features vs. Metadata & Identifiers
1. **Direct Identifiers (EXCLUDE from Features)**:
   - `Flow ID`, `Src IP`, `Dst IP`: Excluded from feature matrices. Use only for alert triage and logging.
2. **Network Ports (`Dst Port`)**:
   - **KEEP AS FEATURE**. Evaluate models with and without `Dst Port` (Port 21=FTP Brute Force, 22=SSH Brute Force, 80=HTTP DoS/Web, 443=Exfiltration).
   - `Src Port`: Ephemeral (>1024) in client OS. Test feature importance carefully.
3. **Timestamps**:
   - `Timestamp`: Parse to UTC epoch for temporal train/test splitting. Do not feed raw timestamp strings into models.
4. **Zero-Variance Columns**:
   - Drop the following constant-zero CICFlowMeter artifacts:
     `Fwd Byts/b Avg`, `Fwd Pkts/b Avg`, `Fwd Blk Rate Avg`, `Bwd Byts/b Avg`, `Bwd Pkts/b Avg`, `Bwd Blk Rate Avg`.

---

## 4. Target Label Definitions & Harmonization

### 4.1 CSE-CIC-IDS2018 Label Taxonomy
All daily captures have been harmonized with the following conventions:
- Typographical error `Infilteration` $\to$ `Infiltration`.
- Every row contains:
  - `Label`: Clean normalized label string.
  - `_Clean_Label`: Canonical normalized label.
  - `_Raw_Label`: Original raw string as recorded in capture.
  - `_Source_File`: Source daily CSV filename for provenance.

### 4.2 Class Distribution Reference
| Normalized Target Label | Family | Typical Daily Source |
| :--- | :--- | :--- |
| **Benign** | Normal Baseline | All 10 Days |
| **DDOS attack-HOIC** | Volumetric DDoS | Wednesday-21-02-2018 |
| **DDOS attack-LOIC-UDP** | UDP Flood | Wednesday-21-02-2018 |
| **DoS attacks-Hulk** | Web Application DoS | Friday-16-02-2018 |
| **DoS attacks-SlowHTTPTest** | Slow Connection Exhaustion | Friday-16-02-2018 |
| **DoS attacks-GoldenEye** | HTTP Keep-Alive Exhaustion | Thursday-15-02-2018 |
| **DoS attacks-Slowloris** | Connection Header Exhaustion | Thursday-15-02-2018 |
| **FTP-BruteForce** | Authentication Brute Force | Wednesday-14-02-2018 |
| **SSH-Bruteforce** | Authentication Brute Force | Wednesday-14-02-2018 |
| **Infiltration** | Internal Lateral Movement | Wednesday-28-02-2018, Thursday-01-03-2018 |
| **Bot** | Ares Botnet Communication | Friday-02-03-2018 |
| **Brute Force -Web** | Web Form Authentication | Thursday-22-02-2018 |
| **Brute Force -XSS** | Cross-Site Scripting Injection | Thursday-22-02-2018 |
| **SQL Injection** | Database Query Injection | Thursday-22-02-2018 |

---

## 5. Missing-Value, Infinite-Value & Scaling Conventions

> [!CAUTION]
> **FIT ON TRAIN ONLY — PREVENT DATA LEAKAGE**
> All preprocessing statistics (imputer medians, scaler means, label encoder mappings) must be computed **strictly on training partitions**. Never call `.fit()` or `.fit_transform()` on validation, test, or inference data.

### 5.1 Preprocessing Pipeline Module
Use our verified module:
```python
from src.data.preprocessing.numerical_pipeline import NumericalPreprocessor
from src.data.preprocessing.feature_policy import get_cse_numeric_features

# 1. Instantiate preprocessor (supports 'standard', 'minmax', or 'none')
preprocessor = NumericalPreprocessor(scaling_method="standard")

# 2. Select predictive features
features = get_cse_numeric_features()

# 3. Fit strictly on train partition
preprocessor.fit(train_df, feature_columns=features, label_column="Label")

# 4. Transform train, validation, and test sets
X_train_clean = preprocessor.transform(train_df)
X_val_clean   = preprocessor.transform(val_df)
X_test_clean  = preprocessor.transform(test_df)
```

### 5.2 Missing & Infinite Values
- All mathematical infinities (`inf`, `-inf`, `Infinity`) in rate features (`Flow Byts/s`, `Flow Pkts/s`) have been mapped to `np.nan`.
- `NumericalPreprocessor` uses `SimpleImputer(strategy='median')` fitted on the training split. Median is strictly preferred over mean due to extreme heavy-tailed distributions in network flow durations and byte volumes.

---

## 6. Unresolved External Constraints & Restrictions

1. **Blocked External Datasets (Credential / Approval Gates)**:
   - **UNSW-NB15 Raw PCAPs (~100 GB)**: Blocked behind UNSW Microsoft 365 student/staff OAuth gate. We have provided the full 44-feature benchmark partitions (`UNSW_NB15_training-set.parquet` and `testing-set.parquet`), which represent the standard benchmark used in cybersecurity literature.
   - **CIC-IDS2017 & CIC-DDoS2019**: Blocked behind York University BCCC MachForm manual approval gates. Detailed access gate markdown files are preserved in `data/raw/`.
2. **Single-Scenario PCAP in CTU-13**:
   - `botnet-capture-20110810-neris.pcap` (Scenario 1) has been extracted into flows. Scenarios 2–13 require download if additional botnet families are needed.
3. **No Model Training in Scope**:
   - Role 2 was restricted strictly to data engineering and feature extraction. No machine learning models, neural networks, or baseline classifiers have been trained in this phase.
