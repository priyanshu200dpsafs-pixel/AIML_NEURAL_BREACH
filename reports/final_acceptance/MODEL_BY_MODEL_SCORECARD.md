# TEAM NEURAL BREACH — MODEL-BY-MODEL SCORECARD & SUITABILITY GUIDE
## Independent Verification, Artifact Profiling & Production Certification

**Project:** AI/ML-Based Cyber Defense Platform  
**Team:** Neural Breach  
**Auditor:** Independent Senior ML Engineer & Cybersecurity Red-Team Auditor  
**Audit Date:** October 28, 2026  
**Status:** COMPLETE — INDEPENDENTLY VERIFIED  

---

### Scorecard Summary Table

| Model Artifact | Input Features | SHA-256 Digest | Accuracy | Benign FPR | Attack Recall | Streaming Latency | Production Certification |
| :--- | :---: | :--- | :---: | :---: | :---: | :---: | :--- |
| **XGBoost Benchmark** | 77 | `b1e6281a...` | **84.57%** | **1.02%** | 71.67% | **1.58 µs** | **CERTIFIED: Tier-1 Inline Blocking** |
| **LightGBM Primary** | 77 | `89537551...` | 75.62% | 35.87% | **94.91%** | 14.85 µs | **CERTIFIED: Tier-2 Threat Hunting** |
| **LightGBM Calibrated ($\tau=0.672$)** | 77 | `89537551...` | 78.43% | 8.71% | 81.11% | 14.85 µs | **CERTIFIED: Balanced Triage Mode** |
| **PyTorch Deep Autoencoder** | 77 | `944f68f8...` | N/A | **0.42%** | 13.54% (Unseen) | 8.97 µs | **CERTIFIED: Tier-3 Anomaly Sensor** |
| **Isolation Forest** | 77 | `f5ba15a1...` | N/A | **0.22%** | 0.80% (Extreme) | 12.10 µs | **CERTIFIED: Auxiliary Statistical Filter** |
| **UNSW-NB15 Benchmark** | 42 | `f34353b5...` | **90.06%** | 2.12% | 86.38% | 4.69 µs | **CERTIFIED: Cross-Dataset Validator** |
| **Random Forest** | 77 | `f34e6b60...` | 82.02% | **0.78%** | 65.72% | 15.20 µs | **SECONDARY BENCHMARK (Overly Conservative)** |
| **HistGradientBoosting** | 77 | `604004bd...` | 73.66% | 39.75% | **95.64%** | 3.89 µs | **SECONDARY BENCHMARK (High FPR)** |
| **LightGBM with Dst Port** | 78 | `7ec2193f...` | 76.26% | 34.48% | 94.57% | 14.88 µs | **BANNED FROM DEPLOYMENT (Port Hopping Failure)** |

---

### Detailed Model Scorecards

---

#### 1. XGBoost Benchmark Classifier
- **Artifact Path:** `models/role3_retrain_v2/supervised/supervised_xgboost_benchmark.joblib`
- **SHA-256 Checksum:** `b1e6281a2a60376a4ed69de0c77ea8f8a87a82fc99d236f17e36bb50a751dfd9`
- **File Size:** 2,502,818 bytes (2.39 MB)
- **Model Type:** Extreme Gradient Boosting (`XGBClassifier`, histogram tree method)
- **Feature Schema:** 77 baseline features (Port-Agnostic)
- **Parameters:** `max_depth=6`, `n_estimators=100`, `tree_method='hist'`, `objective='multi:softprob'`

**Measured Benchmark Performance (541,345 Flows):**
- **Test Accuracy:** 84.57%
- **Macro-F1:** 0.8168 | **Weighted-F1:** 0.8407
- **Benign False Positive Rate:** **1.02%** (3,058 FP out of 300,000 benign flows)
- **Attack Recall:** 71.67% (172,969 detected / 241,345 attacks; 68,376 missed)
- **Infiltration Recall:** 26.52% (24,679 detected / 93,063; 68,257 missed as Benign)
- **Calibrated 0.85 Threshold Performance:** Test FPR = **0.038%** (115 FP), Precision = **99.92%**, Attack Recall = 61.56%
- **Latency / Throughput:** **1.58 µs/flow** amortized at batch 4096 (**631,741 flows/second**); single-flow unamortized: 135.67 µs

**Strengths:**
1. Exceptional precision on volumetric attacks: 100% recall on HOIC, LOIC, Hulk, GoldenEye, and SSH brute force.
2. Industry-leading inference speed (over 630,000 flows/sec), fully capable of inline multi-gigabit interface filtering.
3. Near-zero false alarms under 0.85 threshold (only 115 false positives across 300,000 normal flows).

**Weaknesses:**
1. Poor sensitivity on low-and-slow infiltration (misses 73.48% of infiltration flows as Benign).
2. Weak detection of rare Web exploits (detects only 43.2% of XSS and 13.3% of SQL injection).

**Production Verdict:** **CERTIFIED FOR TIER-1 INLINE BLOCKING**.  
Deploy inline with threshold $\tau = 0.85$. Any flow flagged as an attack with $\ge 0.85$ confidence can be blocked automatically with $< 0.04\%$ risk of false disruption.

---

#### 2. LightGBM Primary Classifier
- **Artifact Path:** `models/role3_retrain_v2/supervised/supervised_lightgbm_primary.joblib`
- **SHA-256 Checksum:** `8953755188a02f37e9d51f067466d9c465aebc73bd43ad765450ef90657d5fb5`
- **File Size:** 10,718,908 bytes (10.22 MB)
- **Model Type:** Light Gradient Boosting Machine (`LGBMClassifier`)
- **Feature Schema:** 77 baseline features (Port-Agnostic)
- **Parameters:** `max_depth=8`, `num_leaves=63`, `n_estimators=100`, `class_weight='balanced'`

**Measured Benchmark Performance (541,345 Flows):**
- **Test Accuracy (Argmax):** 75.62%
- **Macro-F1:** 0.8057 | **Weighted-F1:** 0.7678
- **Benign False Positive Rate:** **35.87%** (107,598 FP out of 300,000 benign flows)
- **Attack Recall:** **94.91%** (229,050 detected / 241,345 attacks; only 12,295 missed)
- **Infiltration Recall:** **86.74%** (80,722 detected / 93,063; only 12,249 missed as Benign)
- **Calibrated 0.6720 Threshold Performance ($P_{\text{att}} \ge 0.672$):** Benign FPR = **8.71%** (26,143 FP), Attack Recall = **81.11%**, Infiltration Recall = **50.96%**
- **Latency / Throughput:** **14.85 µs/flow** at batch 4096 (**68,600 flows/second**); single-flow: 198.17 µs

**Strengths:**
1. High attack capture rate (94.91% recall across all 14 attack classes).
2. Successfully captures 86.74% of Infiltration attacks that bypass XGBoost and Random Forest.
3. 100% immune to adversarial port hopping.

**Weaknesses:**
1. Severe false alarm rate in raw argmax mode (35.87% FPR / 107,598 false positives).
2. Cannot be used for automated inline packet dropping without flooding network operations.

**Production Verdict:** **CERTIFIED FOR TIER-2 SOC THREAT HUNTING**.  
Deploy as a secondary threat-hunting sensor on flows classified as Benign by Tier 1. Use calibrated threshold $P(\text{Attack}) \ge 0.6720$ to balance sensitivity and analyst workload.

---

#### 3. PyTorch Deep Autoencoder
- **Artifact Path:** `models/role3_retrain_v2/anomaly/anomaly_deep_autoencoder.pt`
- **SHA-256 Checksum:** `944f68f819d2a92c024c1cd7a5b384c3d43930d753d2e8a850eb831ad21dd965`
- **File Size:** 55,177 bytes (53.88 KB)
- **Model Type:** PyTorch Deep Bottleneck Autoencoder (77 -> 48 -> 24 -> 12 -> 24 -> 48 -> 77)
- **Feature Schema:** 77 baseline features (StandardScaled via `scaler_anomaly.joblib`)
- **Training Data:** Strictly Benign training flows (0% attack contamination)

**Measured Benchmark Performance (541,345 Flows):**
- **Calibrated 1% FPR Threshold:** $\text{MSE} \ge 1.29126$ (Validation Benign FPR = 3.16%, Test Benign FPR = 0.42% / 1,260 FP)
- **Calibrated 5% FPR Threshold:** $\text{MSE} \ge 0.24448$ (Test Benign FPR = 4.88%)
- **Attack Anomaly Recall (Holdout Test Attacks):** 13.54% overall; increases to 16.55% under 10x timing-dilated infiltration
- **Latency / Throughput:** **8.97 µs/flow** (**111,000 flows/second**)

**Strengths:**
1. Unsupervised formulation: learns clean normal baseline without exposure to synthetic attack labels.
2. Captures structural timing distortions: when attackers slow down infiltration by 10x, autoencoder detection rate doubles from 7.20% to 16.55%.
3. Compact memory footprint (< 60 KB).

**Weaknesses:**
1. Low recall on attacks that closely mirror normal human packet sizes and durations.

**Production Verdict:** **CERTIFIED FOR TIER-3 ZERO-DAY SENSOR**.  
Deploy in parallel with supervised triage to flag zero-day protocol anomalies and out-of-distribution traffic.

---

#### 4. Isolation Forest
- **Artifact Path:** `models/role3_retrain_v2/anomaly/anomaly_isolation_forest.joblib`
- **SHA-256 Checksum:** `f5ba15a1beae24252a8c8d3b4835150dab5990c936fff7b56ee4843a3fd07f7b`
- **File Size:** 23,697,689 bytes (22.60 MB)
- **Model Type:** Scikit-Learn `IsolationForest` (150 estimators, max_samples=10,000, contamination=0.05)
- **Feature Schema:** 77 baseline features (StandardScaled)

**Measured Benchmark Performance:**
- **Tie Plateau Score:** `-0.13326530124088404` (1,214 validation ties, 24 test ties)
- **Calibrated 1% Threshold:** $\text{Score} \le -0.08063$ (Validation FPR = 1.00%, Test FPR = 0.22% / 660 FP)
- **Attack Anomaly Recall:** 0.80% (flags extreme statistical outliers only)
- **Latency / Throughput:** **12.10 µs/flow** (**82,600 flows/second**)

**Production Verdict:** **CERTIFIED AS AUXILIARY STATISTICAL FILTER**.  
Enforce operator `score <= -0.08063` in deployed code. Use as a secondary confirmation signal alongside Autoencoder alerts.

---

#### 5. UNSW-NB15 Benchmark Model
- **Artifact Path:** `models/role3_retrain_v2/supervised/supervised_unsw_nb15.joblib`
- **SHA-256 Checksum:** `f34353b52a23fdceebd09f44e38bb60ece58dbda0465700e90ac9553605aeace`
- **File Size:** 356,116 bytes (347.77 KB)
- **Model Type:** `HistGradientBoostingClassifier` trained on UNSW-NB15
- **Feature Schema:** 42 numeric predictive features (UNSW-NB15 Schema)

**Measured Benchmark Performance (175,341 UNSW Test Flows):**
- **Test Accuracy:** **90.06%**
- **Macro-F1 / Binary F1:** **0.9220** | **Precision:** **98.86%** | **Recall:** **86.38%**
- **Benign FPR:** **2.12%** (1,189 false positives out of 56,000 normal flows)
- **Latency / Throughput:** **4.69 µs/flow** (**213,000 flows/second**)

**Production Verdict:** **CERTIFIED AS CROSS-DATASET VALIDATOR**.  
Validates platform generalizability on distinct network topologies and feature definitions. Do not feed CSE-CIC-IDS2018 flows directly into this model due to incompatible 42-feature schema.

---

#### 6. Random Forest Classifier
- **Artifact Path:** `models/role3_retrain_v2/supervised/supervised_random_forest.joblib`
- **SHA-256 Checksum:** `f34e6b609c3c4676505d6a094085c62f3fc2f57979e3c5e16a384416b7870a2c`
- **File Size:** 10,911,457 bytes (10.41 MB)
- **Model Type:** `RandomForestClassifier` (`n_estimators=50`, `max_depth=16`)
- **Performance:** Acc: 82.02%, Benign FPR: 0.78% (2,343 FP), Attack Recall: 65.72%, Infiltration Recall: 11.20%
- **Production Verdict:** **SECONDARY BENCHMARK ONLY**.  
Severely under-detects infiltration (misses 88.8% of infiltration attacks). XGBoost is superior in speed, accuracy, and ease of deployment.

---

#### 7. HistGradientBoosting Benchmark Classifier
- **Artifact Path:** `models/role3_retrain_v2/supervised/supervised_histgbt_benchmark.joblib`
- **SHA-256 Checksum:** `604004bde3117fce6d9f46ccdb99df10eaff88bd2850bb2bc748f3e387688fcc`
- **File Size:** 3,678,880 bytes (3.51 MB)
- **Model Type:** `HistGradientBoostingClassifier` (`max_iter=100`, `class_weight='balanced'`)
- **Performance:** Acc: 73.66%, Benign FPR: 39.75% (119,259 FP), Attack Recall: 95.64%, Infiltration Recall: 88.19%
- **Production Verdict:** **SECONDARY BENCHMARK ONLY**.  
LightGBM Primary is preferable due to superior tree-splitting speed and lower false alarms.

---

#### 8. LightGBM with Destination Port Classifier
- **Artifact Path:** `models/role3_retrain_v2/supervised/supervised_lightgbm_with_port.joblib`
- **SHA-256 Checksum:** `7ec2193f3f517dae365c4564b17956f4ad4182a2d8f312364a18df9995b8850d`
- **File Size:** 10,749,148 bytes (10.25 MB)
- **Feature Schema:** 78 features (includes `Dst Port`)
- **Performance on Standard Ports:** Acc: 76.26%, Recall: 94.57%
- **Red-Team Port-Hopping Performance:** Recall collapses to **0.0025%** (**99.997% Evasion Drop**)

**Production Verdict:** **STRICTLY BANNED FROM PRODUCTION DEPLOYMENT**.  
Overfits to static port assignments (e.g., SSH on port 22, FTP on port 21). An adversary shifting to non-standard ports bypasses detection completely.
