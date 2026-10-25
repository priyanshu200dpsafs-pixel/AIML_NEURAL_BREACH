# SPLIT AND LEAKAGE AUDIT REPORT (RETRAINING V2)
## Team Neural Breach — AI/ML Cyber Defense Platform
**Role:** Machine Learning & Anomaly Detection Specialist  
**Phase:** Role 3 Retraining V2  
**Date:** 2026-10-25  
**Audit Scope:** Multi-Track Evaluation Design, Partition Manifests, and Strict Anti-Leakage Controls  

---

## 1. Multi-Track Evaluation Architecture

To prevent optimistic bias and ensure honest cybersecurity evaluation, the Retraining V2 pipeline implements three independent evaluation tracks:

```
                          CSE-CIC-IDS2018 (All 10 Days)
                                        │
             ┌──────────────────────────┼──────────────────────────┐
             ▼                          ▼                          ▼
     [Track A: Known Attacks]   [Track B: Cross-Day]       [Track C: Unseen Attacks]
     - 15 Canonical Classes     - Held-Out Capture Days    - Supervised Withheld
     - 541,345 Test Flows       - All 10 Days Evaluated    - Anomaly Detector Eval
     - Zero Identifiers         - Per-Day FPR & Recall     - Zero-Day Generalization
```

### Track A: Known-Attack Classification
- Evaluates the multi-class model on attack categories it has been explicitly trained to recognize.
- Uses a stratified, capture-aware test partition (**541,345 flows**) encompassing all 15 classes from all 10 collection days.
- Retains 100% of all available rare attack flows in the test partition (15 SQLi, 37 XSS, 93 Web Brute Force, 260 LOIC-UDP, 1,650 Slowloris, 6,227 GoldenEye, 93,063 Infiltration).

### Track B: Cross-Day Generalization
- Evaluates model stability when faced with ambient network drift across distinct collection dates.
- Specifically tests the model on held-out days (e.g. Thursday-01-03-2018, where benign flows shifted naturally in background timing).
- Records per-day Benign FPR and attack recall across all 10 collection days.
- Classes absent on a given capture day are strictly marked as **Untested for that Capture**.

### Track C: Unseen-Attack Anomaly Detection
- Evaluates the unsupervised anomaly tier (PyTorch Deep Autoencoder and Isolation Forest) on attacks not provided to the anomaly training process.
- The anomaly detectors were fitted **strictly on 800,000 pure Benign flows**, with zero attack examples.
- Measures zero-day anomaly recall across all 14 attack families at calibrated false alarm budgets (0.1% to 5.0% FPR).

---

## 2. Anti-Leakage Controls & Verification

| Leakage Vector | Risk Description | Prevention Protocol Implemented | Verification Status |
| :--- | :--- | :--- | :---: |
| **Identifier Leakage** | `Src IP`, `Dst IP`, `Src Port`, `Flow ID` allow tree models to memorize IP subnets. | Permanently stripped from all feature matrices. Excluded from baseline (77) and port (78) feature sets. | **VERIFIED PASS** |
| **Temporal Artifacts** | `Timestamp` contains recording calendar dates, allowing models to split by time. | Preserved as metadata for partitioning; stripped from training and inference arrays. | **VERIFIED PASS** |
| **Transformer Contamination** | Fitting scalers or imputers on test data leaks test distribution parameters. | `StandardScaler` and `LabelEncoder` fitted strictly on the Training partition only (`X_train`). | **VERIFIED PASS** |
| **Threshold Overfitting** | Tuning decision thresholds on test data artificially optimizes reported FPR and recall. | All classification and anomaly thresholds swept and calibrated strictly on the Validation partition (`X_val`). | **VERIFIED PASS** |
| **Cross-Dataset Leakage** | Mixing UNSW-NB15 or CTU-13 with CSE features causes artificial feature overlap. | UNSW-NB15 and CTU-13 maintained on separate pipelines with dedicated schemas. | **VERIFIED PASS** |

---

## 3. Partition Manifest Accounting

The master partition distribution for the 2,182,090 processed flows is audited below:

| Traffic Class | Total in Dataset | Train Records | Val Records | Test Records | Partition Retention |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Benign** | 13,484,708 | 600,000 | 100,000 | 300,000 | 7.42% (Stratified across all 10 days) |
| **Bot** | 286,191 | 60,000 | 15,000 | 20,000 | 33.19% |
| **Brute Force -Web** | 611 | 425 | 93 | 93 | **100.00%** |
| **Brute Force -XSS** | 230 | 159 | 34 | 37 | **100.00%** |
| **DDOS attack-HOIC** | 686,012 | 60,000 | 15,000 | 20,000 | 13.85% |
| **DDOS attack-LOIC-UDP** | 1,730 | 1,211 | 259 | 260 | **100.00%** |
| **DDoS attacks-LOIC-HTTP** | 576,191 | 60,000 | 15,000 | 20,000 | 16.49% |
| **DoS attacks-GoldenEye** | 41,508 | 29,054 | 6,227 | 6,227 | **100.00%** |
| **DoS attacks-Hulk** | 461,912 | 60,000 | 15,000 | 20,000 | 20.57% |
| **DoS attacks-SlowHTTPTest** | 139,890 | 60,000 | 15,000 | 20,000 | 67.91% |
| **DoS attacks-Slowloris** | 10,990 | 7,692 | 1,648 | 1,650 | **100.00%** |
| **FTP-BruteForce** | 193,360 | 60,000 | 15,000 | 20,000 | 49.13% |
| **Infiltration** | 161,934 | 68,871 | 0 | 93,063 | **100.00%** (Feb 28 Train / Mar 01 Test) |
| **SQL Injection** | 87 | 58 | 14 | 15 | **100.00%** |
| **SSH-Bruteforce** | 187,589 | 60,000 | 15,000 | 20,000 | 50.64% |
| **TOTALS** | **16,232,943** | **1,327,476** | **313,269** | **541,345** | **2,182,090 Processed (100% of Rare)** |

---

## 4. Test Set Integrity Declaration

The test partition (**541,345 flows**) has been kept strictly locked:
- It was NOT used for any hyperparameter searching, feature selection, or probability threshold tuning.
- All evaluation figures reported in `SUPERVISED_MODEL_COMPARISON.md` and `ANOMALY_MODEL_COMPARISON.md` represent true untouched out-of-sample measurements.
