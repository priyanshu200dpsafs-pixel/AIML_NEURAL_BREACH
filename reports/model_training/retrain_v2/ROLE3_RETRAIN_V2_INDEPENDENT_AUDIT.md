# INDEPENDENT AUDIT REPORT: ROLE 3 RETRAIN V2
## AI/ML Cyber Defense Platform — Team Neural Breach
**Audit Role:** Independent Machine Learning Quality Assurance & Cybersecurity Auditor  
**Branch Audited:** `role3-retrain-v2`  
**Git Commit:** `6de452cae5af13cd642fad650b4752aad84b6db1`  
**Date of Audit:** 2026-10-25  
**Final Audit Verdict:** **`VERIFIED WITH CAVEATS`**

---

## 1. Executive Summary & Audit Checklist

An independent, rigorous technical audit was conducted on the Role 3 Retrain V2 pipeline, trained model binaries, data partitions, and evaluation reports. **No models were deleted, overwritten, or retrained.** All metrics, confusion matrices, and inference latencies were independently recomputed from the saved model artifacts and raw Parquet partitions.

### Audit Summary Matrix

| Audit Check | Scope & Requirement | Verification Method | Result | Status |
| :--- | :--- | :--- | :---: | :---: |
| **Check 1: Training Execution** | Verify git commit, hardware, package versions, artifact timestamps, and execution logs. | Inspect environment, git log, file metadata, and script timers. | Models generated Oct 25, 18:48–18:50 UTC; no external log file saved. | **VERIFIED WITH CAVEATS** |
| **Check 2: Data Provenance** | Reconcile 2.18M partitioned flows with 16.23M available CSE-CIC-IDS2018 records. | Parquet file scan of all 10 captures vs. split manifest accounting. | 16,232,943 raw flows verified; 100% of rare attacks preserved. | **PASS** |
| **Check 3: Leakage Controls** | Ensure encoders, scalers, and imputers fitted strictly on training data; verify pure benign anomaly training. | Inspect `dataset_manager.py` and inspect training partition labels. | LabelEncoder & Scaler fit on Train only; Anomaly train set 100% Benign. | **PASS** |
| **Check 4: Supervised Metrics** | Independently recompute Accuracy, Benign FPR, Missed Attacks, and per-class metrics. | Run predictions with saved models on untouched 541,345-flow test partition. | **Exact zero-difference match across all 5 models (Diff: 0.00e+00).** | **PASS** |
| **Check 5: Infiltration Reconcil.** | Distinguish one-vs-rest FN from attacks misclassified as Benign. | Recompute confusion matrix row for Infiltration (index 11). | Reconciled 12,249 Benign FN vs. 92 attack misclassifications for LightGBM. | **PASS** |
| **Check 6: Anomaly Detection** | Verify benign-only fitting, score direction, and threshold calibration across FPR budgets. | Evaluate PyTorch Autoencoder and Isolation Forest on test partition. | Deep Autoencoder detects 100% LOIC-UDP flood flows at 0.1%–5.0% FPR. | **PASS** |
| **Check 7: Latency Benchmark** | Reproduce high-resolution inference benchmarks across batch sizes (1, 64, 1024). | Benchmark with monotonic timer (`perf_counter_ns`), warmup, and median/p95. | Latencies verified: AE = 0.22 µs, XGB = 1.97 µs, LGB = 14.84 µs (@ b1024). | **PASS** |
| **Check 8: Security Contract** | Test schema validation, NaN/Inf imputation, and input rejection in clean process. | Execute defensive interface tests in `src/models/inference_engine.py`. | 100% contract tests passed; structured `ModelInferenceError` raised. | **PASS** |

---

## 2. Check 1: Training Execution & Runtime Verification

### Hardware & Software Environment
- **Workstation:** Apple M4 (10 cores: 4 performance + 6 efficiency cores)
- **Physical Memory:** 16.0 GB RAM (17,179,869,184 bytes), ~5.8 GB free at execution
- **Operating System:** macOS Darwin 27.0 (arm64)
- **Python Version:** 3.13.7
- **Core Library Versions:**
  - `lightgbm`: 4.7.0 (Native arm64 OpenMP build)
  - `xgboost`: 1.7.6
  - `scikit-learn`: 1.7.2
  - `torch`: 2.13.0
  - `joblib`: 1.5.3
  - `pandas`: 2.3.3
  - `numpy`: 2.3.3

### Artifact File Timestamps & SHA-256 Checksums
All model artifacts in [`models/role3_retrain_v2/`](file:///Users/priyanshu/Desktop/aiml%20project%20team%20neural%20breach/models/role3_retrain_v2/) were verified on disk:

| Artifact Path | Size (Bytes) | Last Modified (Local Time) | SHA-256 Checksum |
| :--- | :---: | :---: | :--- |
| `supervised/supervised_lightgbm_primary.joblib` | 10,718,908 | 2026-10-25 18:49:27 | `8953755188a02f37e9d51f067466d9c465aebc73bd43ad765450ef90657d5fb5` |
| `supervised/supervised_lightgbm_with_port.joblib` | 10,749,148 | 2026-10-25 18:50:11 | `7ec2193f3f517dae365c4564b17956f4ad4182a2d8f312364a18df9995b8850d` |
| `supervised/supervised_xgboost_benchmark.joblib` | 2,502,818 | 2026-10-25 18:50:18 | `b1e6281a2a60376a4ed69de0c77ea8f8a87a82fc99d236f17e36bb50a751dfd9` |
| `supervised/supervised_random_forest.joblib` | 10,911,457 | 2026-10-25 18:50:16 | `f34e6b609c3c4676505d6a094085c62f3fc2f57979e3c5e16a384416b7870a2c` |
| `supervised/supervised_histgbt_benchmark.joblib` | 3,678,880 | 2026-10-25 18:50:18 | `604004bde3117fce6d9f46ccdb99df10eaff88bd2850bb2bc748f3e387688fcc` |
| `supervised/supervised_unsw_nb15.joblib` | 356,116 | 2026-10-25 18:50:59 | `f34353b52a23fdceebd09f44e38bb60ece58dbda0465700e90ac9553605aeace` |
| `anomaly/anomaly_deep_autoencoder.pt` | 55,177 | 2026-10-25 18:50:59 | `944f68f819d2a92c024c1cd7a5b384c3d43930d753d2e8a850eb831ad21dd965` |
| `anomaly/anomaly_isolation_forest.joblib` | 23,697,689 | 2026-10-25 18:50:53 | `f5ba15a1beae24252a8c8d3b4835150dab5990c936fff7b56ee4843a3fd07f7b` |
| `anomaly/scaler_anomaly.joblib` | 2,447 | 2026-10-25 18:50:52 | `566f0a6ca0878c25f9789b6ecae14855bae72225da18c3581ef497bc19d8f201` |

### Runtime Log Finding
> [!IMPORTANT]
> **Runtime Log Audit Finding:** No external terminal stdout/stderr log file (`*.log` or `*train*.txt`) was persisted in the repository. While internal timer metadata recorded `training_time_seconds: 34.68s` for LightGBM and `35.80s` for LightGBM with Port in [`supervised_metrics.json`](file:///Users/priyanshu/Desktop/aiml%20project%20team%20neural%20breach/reports/model_training/retrain_v2/supervised_metrics.json), the exact end-to-end execution duration of the original training run cannot be independently verified from runtime logs alone.

---

## 3. Check 2: Data Usage, Provenance & Sampling Audit

An independent scan of all 10 raw Parquet captures in `data/processed/CSE-CIC-IDS2018_v2/` confirmed the exact dataset reconciliation:

### Complete Collection Accounting
- **Total Ingested Flows:** 16,233,002 rows
- **Repeated CSV Headers Removed:** 59 rows
- **Clean Parquet Records:** **16,232,943 clean flows**
- **Typo Normalization:** 161,934 `Infilteration` $\to$ `Infiltration` (100% clean)
- **Active Partition Allocation:** 2,182,090 flows (13.44% of available)
  - `TRAIN`: 1,327,476 flows
  - `VALIDATION`: 313,269 flows
  - `TEST` + `TEST_HELD_OUT`: 541,345 flows (448,282 standard test + 93,063 held-out Infiltration)
- **Unused Flows:** 14,050,853 flows (86.56% of available)
  - 12,484,708 repetitive benign flows (keep-alives, idle connections)
  - 1,566,145 automated volumetric flood flows (HOIC, LOIC-HTTP, Hulk)

### Verification of Rare Threat Vector Preservation
Our audit confirmed that **sampling did NOT disproportionately remove rare attacks**. 100% of rare threat instances across the entire 16.23M-flow dataset were retained:

| Attack Category | Raw Collection Count | Partitioned Manifest Count | Retention Rate | Partition Allocation (Train / Val / Test) |
| :--- | :---: | :---: | :---: | :--- |
| **SQL Injection** | 87 | 87 | **100.00%** | 60 Train / 12 Val / 15 Test |
| **Brute Force - XSS** | 230 | 230 | **100.00%** | 160 Train / 33 Val / 37 Test |
| **Brute Force - Web** | 611 | 611 | **100.00%** | 427 Train / 91 Val / 93 Test |
| **DDOS LOIC-UDP** | 1,730 | 1,730 | **100.00%** | 1,211 Train / 259 Val / 260 Test |
| **DoS Slowloris** | 10,990 | 10,990 | **100.00%** | 7,692 Train / 1,648 Val / 1,650 Test |
| **DoS GoldenEye** | 41,508 | 41,508 | **100.00%** | 29,055 Train / 6,226 Val / 6,227 Test |
| **Infiltration** | 161,934 | 161,934 | **100.00%** | 68,871 Train (Feb 28) / 93,063 Test Held-Out (Mar 01) |

### Memory Boundary Justification
The workstation has 16.0 GB physical RAM. Loading 16.23M rows $\times$ 78 double-precision floats requires 10.1 GB raw memory. Allocating training structures, gradient histograms, and cross-validation buffers requires >28 GB RAM, which would trigger an immediate macOS kernel Out-Of-Memory (OOM) termination. Sampling 2,182,090 flows was technically necessary and statistically sound.

---

## 4. Check 3: Schema Reconciliation & Leakage Prevention

1. **Resolution of 80 vs. 84 Features:**  
   The February 20 capture contained 4 extra columns: `Src IP`, `Dst IP`, `Src Port`, and `Flow ID`. Excluding these identifier columns eliminated dangerous data leakage (preventing models from memorizing specific victim/attacker subnets) and produced a canonical **77-feature numerical schema** across all 10 captures.
2. **Preprocessing Isolation:**  
   `LabelEncoder` and `StandardScaler` objects were fitted exclusively on the `TRAIN` partition (`train_df`). No test statistics, feature means, or variances leaked into validation or test pipelines.
3. **Pure Benign Anomaly Fitting:**  
   The anomaly detection training set ($N = 800,000$) contains 100% Benign flows (0 attack instances). Labels were verified prior to model fitting.

---

## 5. Check 4: Recomputed vs. Reported Metric Verification

Predictions were independently generated on the exact, untouched test partition ($N = 541,345$ flows) using the loaded model artifacts. All metrics were recomputed from scratch using an independent confusion matrix evaluation script.

### Recomputed Metric Verification Table

| Candidate Model | Metric Name | Reported Value | Independently Recomputed Value | Exact Difference | Audit Status |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **LightGBM Primary** | **Multiclass Accuracy** | 75.6178% | **75.6178%** | **0.00e+00** | **EXACT PASS** |
| (77 Features) | **Benign FPR (False Alarms)** | 35.8660% | **35.8660%** | **0.00e+00** | **EXACT PASS** |
| | **Total Attack Recall** | 94.9056% | **94.9056%** | **0.00e+00** | **EXACT PASS** |
| | **Missed Attacks Count (FN)** | 12,295 | **12,295** | **0 flows** | **EXACT PASS** |
| | **Benign False Positives (FP)** | 107,598 | **107,598** | **0 flows** | **EXACT PASS** |
| | **Infiltration Recall** | 86.7391% | **86.7391%** | **0.00e+00** | **EXACT PASS** |
| **LightGBM + Port** | **Multiclass Accuracy** | 76.2647% | **76.2647%** | **0.00e+00** | **EXACT PASS** |
| (78 Features) | **Benign FPR (False Alarms)** | 34.4797% | **34.4797%** | **0.00e+00** | **EXACT PASS** |
| | **Total Attack Recall** | 94.5717% | **94.5717%** | **0.00e+00** | **EXACT PASS** |
| | **Missed Attacks Count (FN)** | 13,101 | **13,101** | **0 flows** | **EXACT PASS** |
| | **Benign False Positives (FP)** | 103,439 | **103,439** | **0 flows** | **EXACT PASS** |
| **XGBoost Benchmark** | **Multiclass Accuracy** | 84.5690% | **84.5690%** | **0.00e+00** | **EXACT PASS** |
| (77 Features) | **Benign FPR (False Alarms)** | 1.0193% | **1.0193%** | **0.00e+00** | **EXACT PASS** |
| | **Total Attack Recall** | 71.6688% | **71.6688%** | **0.00e+00** | **EXACT PASS** |
| | **Missed Attacks Count (FN)** | 68,376 | **68,376** | **0 flows** | **EXACT PASS** |
| | **Benign False Positives (FP)** | 3,058 | **3,058** | **0 flows** | **EXACT PASS** |
| | **Infiltration Recall** | 26.5186% | **26.5186%** | **0.00e+00** | **EXACT PASS** |
| **Random Forest** | **Multiclass Accuracy** | 82.0190% | **82.0190%** | **0.00e+00** | **EXACT PASS** |
| (77 Features) | **Benign FPR (False Alarms)** | 0.7810% | **0.7810%** | **0.00e+00** | **EXACT PASS** |
| | **Total Attack Recall** | 65.7221% | **65.7221%** | **0.00e+00** | **EXACT PASS** |
| | **Missed Attacks Count (FN)** | 82,728 | **82,728** | **0 flows** | **EXACT PASS** |
| | **Benign False Positives (FP)** | 2,343 | **2,343** | **0 flows** | **EXACT PASS** |
| **HistGradientBoost** | **Multiclass Accuracy** | 73.6595% | **73.6595%** | **0.00e+00** | **EXACT PASS** |
| (77 Features) | **Benign FPR (False Alarms)** | 39.7530% | **39.7530%** | **0.00e+00** | **EXACT PASS** |
| | **Total Attack Recall** | 95.6428% | **95.6428%** | **0.00e+00** | **EXACT PASS** |
| | **Missed Attacks Count (FN)** | 10,516 | **10,516** | **0 flows** | **EXACT PASS** |
| | **Benign False Positives (FP)** | 119,259 | **119,259** | **0 flows** | **EXACT PASS** |

> [!NOTE]
> Every single reported metric in [`supervised_metrics.json`](file:///Users/priyanshu/Desktop/aiml%20project%20team%20neural%20breach/reports/model_training/retrain_v2/supervised_metrics.json) matches the independent recomputation **to the exact integer and float decimal precision**. There are zero fabricated, approximate, or inconsistent figures.

---

## 6. Check 5: Infiltration & False-Negative Reconciliation

The audit investigated whether the reported counts of missed attacks, accuracy, and infiltration false negatives are mathematically consistent:

### Mathematical Reconciliation of LightGBM Missed Attacks ($N = 12,295$)
- Total Attack flows in test partition: $N = 241,345$
- Infiltration flows in test partition: $N = 93,063$
- True Infiltration Detections (True Positives): **80,722 flows (86.74%)**
- Infiltration predicted as Benign (Security False Negatives): **12,249 flows**
- Infiltration predicted as another Attack class: **92 flows** (71 Bot, 11 SSH-Bruteforce, 7 FTP, 3 DoS)
- Missed Attacks from other classes (classified as Benign):
  - `DDOS LOIC-UDP`: 19 flows
  - `Brute Force - Web`: 11 flows
  - `Bot`: 7 flows
  - `SQL Injection`: 6 flows
  - `Brute Force - XSS`: 3 flows
  - Other classes (HOIC, LOIC-HTTP, GoldenEye, Hulk, SlowHTTPTest, Slowloris, FTP, SSH): 0 missed
- **Reconciliation Sum:**
  $$12,249 \text{ (Infil)} + 19 \text{ (LOIC-UDP)} + 11 \text{ (Web)} + 7 \text{ (Bot)} + 6 \text{ (SQLi)} + 3 \text{ (XSS)} = \mathbf{12,295 \text{ missed attacks}}$$
The missed attack count matches the confusion matrix reconciliation with 100% precision.

---

## 7. Check 6: Unsupervised Anomaly Detection Audit

The anomaly detection models were audited using the saved PyTorch weights [`anomaly_deep_autoencoder.pt`](file:///Users/priyanshu/Desktop/aiml%20project%20team%20neural%20breach/models/role3_retrain_v2/anomaly/anomaly_deep_autoencoder.pt) and [`anomaly_isolation_forest.joblib`](file:///Users/priyanshu/Desktop/aiml%20project%20team%20neural%20breach/models/role3_retrain_v2/anomaly/anomaly_isolation_forest.joblib):

1. **Validation Calibrated Thresholds Verified:**
   - Deep Autoencoder at 1.0% FPR budget: MSE threshold = `1.29126`
   - Isolation Forest at 1.0% FPR budget: Score threshold = `-0.08063`
2. **Zero-Day Volumetric Flood Interception:**
   - Both models confirmed genuine unsupervised learning on pure Benign flows.
   - At the 1.0% FPR budget, the PyTorch Deep Autoencoder flags **100% of LOIC-UDP flood attacks (260/260)**, **78.2% of FTP-BruteForce**, **65.9% of Slowloris**, and **44.9% of SlowHTTPTest**, confirming that extreme packet-timing distortions trigger massive reconstruction errors.

---

## 8. Check 7: Latency & Throughput Benchmark Reproduction

Inference latencies were reproduced on the Apple M4 processor using monotonic timing (`time.perf_counter_ns()`), 10-iteration warmups, and 50–200 iterations across batch sizes 1, 64, and 1024:

| Pipeline Stage / Model | Batch Size | Median Batch Latency | P95 Batch Latency | Per-Flow Latency | Verified Throughput |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Isolated Feature Preprocessing** | 1 | 66.77 µs | 70.88 µs | 66.771 µs | 14,976 flows/s |
| (Imputation + Scaling) | 64 | 85.54 µs | 96.84 µs | 1.337 µs | 747,943 flows/s |
| | 1024 | 251.06 µs | 256.93 µs | **0.245 µs** | **4,081,632 flows/s** |
| **PyTorch Deep Autoencoder** | 1 | 34.62 µs | 35.30 µs | 34.625 µs | 28,881 flows/s |
| (CPU Tensor Operations) | 64 | 96.10 µs | 106.61 µs | 1.502 µs | 665,945 flows/s |
| | 1024 | 222.71 µs | 231.67 µs | **0.217 µs** | **4,597,939 flows/s** |
| **XGBoost Benchmark** | 1 | 128.60 µs | 350.43 µs | 128.605 µs | 7,776 flows/s |
| (Native Tree Traversal) | 64 | 475.10 µs | 1,401.65 µs | 7.423 µs | 134,707 flows/s |
| | 1024 | 2,015.40 µs | 2,483.03 µs | **1.968 µs** | **508,089 flows/s** |
| **LightGBM Primary Candidate** | 1 | 195.23 µs | 205.96 µs | 195.229 µs | 5,122 flows/s |
| (OpenMP Tree Traversal) | 64 | 1,016.02 µs | 1,129.12 µs | 15.875 µs | 62,991 flows/s |
| | 1024 | 15,197.54 µs | 15,824.17 µs | **14.841 µs** | **67,379 flows/s** |
| **Isolation Forest** | 1 | 1,200.42 µs | 1,421.10 µs | 1,200.417 µs | 833 flows/s |
| (Scikit-Learn Cython) | 64 | 1,375.75 µs | 1,544.00 µs | 21.496 µs | 46,520 flows/s |
| | 1024 | 5,047.92 µs | 5,326.46 µs | **4.930 µs** | **202,856 flows/s** |
| **Full Deployed Inference Path** | 1 | 1,683.38 µs | 1,844.25 µs | 1,683.375 µs | 594 flows/s |
| (Prep + XGBoost + Autoencoder + Triage) | 64 | 2,385.65 µs | 2,999.52 µs | 37.276 µs | 26,827 flows/s |
| | 1024 | 10,576.62 µs | 12,066.36 µs | **10.329 µs** | **96,817 flows/s** |

All timing units are strictly distinguished: microseconds (µs), milliseconds (ms), batch time vs amortized per-flow time. Latency measurements are reproducible and align with theoretical expectations.

---

## 9. Check 8: Usability & Security Contract Verification

The production inference contract in [`src/models/inference_engine.py`](file:///Users/priyanshu/Desktop/aiml%20project%20team%20neural%20breach/src/models/inference_engine.py) was tested in a clean Python subprocess:
- **LightGBM Loading:** Passed (Loads `supervised_lightgbm_primary.joblib`).
- **XGBoost Loading:** Passed (Loads `supervised_xgboost_benchmark.joblib`).
- **Random Forest Loading:** Passed (Loads `supervised_random_forest.joblib`).
- **Schema Validation:** Strict 77-feature order enforced.
- **Corrupt Input Resilience:** DataFrames containing `NaN`, `+Inf`, and `-Inf` are sanitized to `0.0` without throwing uncaught exceptions.
- **Contract Rejection:** DataFrames missing required features or non-DataFrame inputs raise structured `ModelInferenceError` exceptions.

---

## 10. Audit Verdict & Minimum Corrective Actions

### Formal Verdict: **`VERIFIED WITH CAVEATS`**

The Retrain V2 models, partitions, leakage controls, and reported metrics are completely authentic, reproducible, and mathematically verified.

### Operational Caveats for Red-Teaming (Role 4) & Integration (Role 6):
1. **LightGBM False-Alarm Caveat:**  
   While LightGBM catches 86.74% of Infiltration and 94.91% of all attacks, its raw Benign FPR is 35.87% (107,598 false alarms). Deploying raw LightGBM predictions to human SOC analysts will flood the queue. Role 6 must apply the validation-calibrated probability threshold ($P(\text{Attack}) \ge 0.6720$) when using LightGBM.
2. **XGBoost Infiltration Blindspot:**  
   XGBoost has production-grade false alarm control (1.02% FPR), but its Infiltration recall is only 26.52% (misses 68,384 flows). It must be paired with the PyTorch Deep Autoencoder for defense-in-depth.
3. **Absence of Persisted Console Log:**  
   Future training pipelines must pipe stdout/stderr to a timestamped file (`reports/model_training/retrain_v2/train_execution.log`) to record exact end-to-end wall-clock duration.
