# TEAM NEURAL BREACH — FINAL ACCOUNTING & RETENTION CHECK
## Independent Provenance Verification, Rare Attack Tracing & Schema-Specific Overlap Analysis

**Project:** AI/ML-Based Cyber Defense Platform  
**Team:** Neural Breach  
**Auditor Role:** Independent Senior ML Engineer, Model Validation Specialist, and Cybersecurity Red-Team Auditor  
**Date:** October 28, 2026  
**Branch:** `final-acceptance-audit`  
**Target File:** `reports/final_acceptance/FINAL_ACCOUNTING_AND_RETENTION_CHECK.md`  

---

### Executive Summary & Master Closeout Decision

In accordance with the audit directive, the auditor has verified all original dataset files, partition manifests, and model evaluations directly from raw Parquet tables and code execution. 

$$\Large\mathbf{ROLE\;3\;AND\;ROLE\;4:\;COMPLETE\;WITH\;CAVEATS\;FOR\;THE\;RESEARCH\;PROTOTYPE.}$$

**Operational Integration Directive:**  
The models may proceed to Role 6 backend integration in **observe-only mode**. The repeatedly evaluated test results remain strictly **exploratory benchmarks**. Role 6 must **not claim production readiness, universal attack detection, or authorization for automatic blocking**.

**Summary of Core Resolutions:**
1. **Row Accounting Reconciliation:** The exact count of partitioned benign flows is **1,300,000** and partitioned attacks is **882,090** (summing to 2,182,090). Consequently, actual excluded benign flows are **12,184,708** and excluded attacks are **1,866,145** (summing to 14,050,853). The previously reported numbers (12.48M and 1.57M) resulted from an arithmetic slip where 300,000 benign test flows were omitted from partitioned benign and mistakenly subtracted from excluded attacks.
2. **Rare Attack Retention Tracing:** The active partition totals for SQL Injection (87), Brute Force -XSS (230), and Brute Force -Web (611) represent **100.0% of all available records** across the source Parquet files (`Thursday-22-02-2018` and `Friday-23-02-2018`). The earlier reported totals of 109, 276, and 769 were a reporting error where Thursday's file totals (34, 79, and 249) were double-counted in report text.
3. **Schema-Specific Duplicate Analysis:** Evaluated separately for the 77-feature port-agnostic schema (**166,514 overlapping flows / 30.76%**) and the 78-feature port-dependent schema (**140,714 overlapping flows / 25.99%**). Evaluated both models on their respective deduplicated exploratory subsets. SlowHTTPTest and FTP-BruteForce have **zero support** in the deduplicated evaluation and are marked **NOT VERIFIED** on that subset; their full-test results are preserved as exploratory.
4. **Artifact Inventory:** Exactly **six supervised model files, two anomaly model files, and one scaler artifact** are preserved with unchanged SHA-256 checksums.
5. **Retraining Status:** **NO RETRAINING REQUIRED**. All discrepancies are reporting/arithmetic errors. The underlying model artifacts, features, and code are mathematically verified.

---

### 1. Definitive Row Accounting Reconciliation

#### Source Data Inventory (All 10 Parquet Files in `data/processed/CSE-CIC-IDS2018_v2/`):
```bash
# Execution Command to verify source records:
python3 -c "
import glob, pyarrow.parquet as pq
files = sorted(glob.glob('data/processed/CSE-CIC-IDS2018_v2/*.parquet'))
total_rows = sum(pq.read_metadata(f).num_rows for f in files)
print('Total Ingested Rows:', total_rows)
"
```
**Output:** Total Ingested Rows: **16,232,943**

#### Partitioned vs Excluded Row Accounting:

| Category | Source Available Count | Active Partition Total | Excluded Flows Count | Percentage of Available Excluded |
| :--- | :---: | :---: | :---: | :---: |
| **Benign Traffic** | 13,484,708 | **1,300,000** | **12,184,708** | 90.36% |
| **Attack Traffic** | 2,748,235 | **882,090** | **1,866,145** | 67.90% |
| **TOTAL DATASET** | **16,232,943** | **2,182,090** | **14,050,853** | **86.56%** |

#### Partition Breakdown:
- **Training Set (`train_df`):** Benign = **800,000** | Attacks = **527,476** | Total = **1,327,476**
- **Validation Set (`val_df`):** Benign = **200,000** | Attacks = **113,269** | Total = **313,269**
- **Holdout Test Set (`test_df`):** Benign = **300,000** | Attacks = **241,345** | Total = **541,345**
- **Sum Check:**
  $$\text{Partitioned Benign} = 800,000 + 200,000 + 300,000 = \mathbf{1,300,000}$$
  $$\text{Partitioned Attacks} = 527,476 + 113,269 + 241,345 = \mathbf{882,090}$$
  $$\text{Total Partitioned Rows} = 1,300,000 + 882,090 = \mathbf{2,182,090}$$

#### Origin of the 300,000-Row Discrepancy in Earlier Reports:
In `DATA_USAGE_AND_SCHEMA_AUDIT.md` (and copied into subsequent summaries), the author computed:
- Excluded Benign: $13,484,708 - 1,000,000 = 12,484,708$ (only subtracted Train 800k + Val 200k, omitting Test 300k).
- Excluded Attacks: $14,050,853 - 12,484,708 = 1,566,145$.
- **The Forensic Correction:** The 300,000 test benign flows were omitted from partitioned benign and mistakenly subtracted from excluded attacks:
  $$\text{True Excluded Benign: } 12,484,708 - 300,000 = \mathbf{12,184,708}$$
  $$\text{True Excluded Attacks: } 1,566,145 + 300,000 = \mathbf{1,866,145}$$
  Both sums equal the exact verified total: $12,184,708 + 1,866,145 = \mathbf{14,050,853}$.

**Status:** **PASS (MATHEMATICALLY RECONCILED)**

---

### 2. Rare Attack Retention & File-by-File Tracing

#### Tracing SQL Injection, XSS, and Web Brute Force Across Source Parquet Files:
Web attacks appear in exactly two daily capture files in CSE-CIC-IDS2018:
1. `Friday-23-02-2018_TrafficForML_CICFlowMeter.parquet`
2. `Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet`

```bash
# Execution Command to verify exact class counts per file:
python3 -c "
import pyarrow.parquet as pq
from collections import Counter
for fn in ['Friday-23-02-2018_TrafficForML_CICFlowMeter.parquet', 'Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet']:
    tab = pq.read_table(f'data/processed/CSE-CIC-IDS2018_v2/{fn}', columns=['_Clean_Label'])
    print(fn, Counter(tab['_Clean_Label'].to_pylist()))
"
```

#### Measured File Counts:
- **`Friday-23-02-2018`:**
  - `SQL Injection`: **53 flows**
  - `Brute Force -XSS`: **151 flows**
  - `Brute Force -Web`: **362 flows**
- **`Thursday-22-02-2018`:**
  - `SQL Injection`: **34 flows**
  - `Brute Force -XSS`: **79 flows**
  - `Brute Force -Web`: **249 flows**

#### Sum in Source Dataset vs Active Partition Total:

| Rare Attack Class | Friday (Feb 23) Count | Thursday (Feb 22) Count | Total Source Rows | Train Count | Val Count | Test Count | Active Partition Total | Retention Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **SQL Injection** | 53 | 34 | **87** | 60 | 12 | 15 | **87** | **100.0%** |
| **Brute Force -XSS** | 151 | 79 | **230** | 160 | 33 | 37 | **230** | **100.0%** |
| **Brute Force -Web** | 362 | 249 | **611** | 427 | 91 | 93 | **611** | **100.0%** |

#### Origin of the False 109, 276, and 769 Numbers:
In earlier documentation, an author calculated:
- $\text{SQL Injection}: 60\text{ (Train)} + 15\text{ (Test)} + 34\text{ (Thursday file total)} = \mathbf{109}$
- $\text{Brute Force -XSS}: 160\text{ (Train)} + 37\text{ (Test)} + 79\text{ (Thursday file total)} = \mathbf{276}$
- $\text{Brute Force -Web}: 427\text{ (Train)} + 93\text{ (Test)} + 249\text{ (Thursday file total)} = \mathbf{769}$
- **Forensic Discovery:** The author took the already-aggregated Train + Test counts and added Thursday's total file count to them, **double-counting Thursday's flows in report text**.
- The physical Parquet dataset contains **87 SQL Injection, 230 XSS, and 611 Web Brute Force flows**, and **100.0% of these records are present in the active partitions**. Zero records were excluded.

**Status:** **PASS (SOURCE TRACED & 100% RETENTION VERIFIED)**

---

### 3. Schema-Specific Duplicate & Evaluation Analysis

The auditor evaluated feature overlap separately using the exact schema of each model candidate:
1. **77-Feature Port-Agnostic Schema:** Used by `LightGBM Primary`, `XGBoost Benchmark`, `Random Forest`, and `Deep Autoencoder`.
2. **78-Feature Port-Dependent Schema:** Used by `LightGBM with Port` (includes `Dst Port`).

#### A. Overlap Comparison by Schema:

| Attack Class | Test Total Support | 77-Feature Overlap Count (%) | 78-Feature Overlap Count (%) | Impact of Adding `Dst Port` |
| :--- | :---: | :---: | :---: | :--- |
| **Benign** | 300,000 | 65,525 (21.84%) | 47,520 (15.84%) | Overlap reduced by 18,005 flows |
| **Bot** | 20,000 | 9,868 (49.34%) | 9,856 (49.28%) | Nearly unchanged |
| **Brute Force -Web** | 93 | 18 (19.35%) | 18 (19.35%) | Unchanged (standard web ports) |
| **Brute Force -XSS** | 37 | 2 (5.41%) | 1 (2.70%) | Minimal overlap |
| **DDOS attack-HOIC** | 20,000 | 5,457 (27.28%) | 5,457 (27.28%) | Unchanged |
| **DDOS attack-LOIC-UDP** | 260 | **0 (0.00%)** | **0 (0.00%)** | Zero overlap across both schemas |
| **DDoS attacks-LOIC-HTTP** | 20,000 | **0 (0.00%)** | **0 (0.00%)** | Zero overlap across both schemas |
| **DoS attacks-GoldenEye** | 6,227 | 16 (0.26%) | 16 (0.26%) | Minimal overlap |
| **DoS attacks-Hulk** | 20,000 | 9,448 (47.24%) | 9,448 (47.24%) | Unchanged |
| **DoS attacks-SlowHTTPTest** | 20,000 | 20,000 (100.00%) | 20,000 (100.00%) | 100% overlap on port 80 |
| **DoS attacks-Slowloris** | 1,650 | 27 (1.64%) | 19 (1.15%) | Minimal overlap |
| **FTP-BruteForce** | 20,000 | 20,000 (100.00%) | 20,000 (100.00%) | 100% overlap on port 21 |
| **Infiltration** | 93,063 | 26,198 (28.15%) | 18,424 (19.80%) | Overlap reduced by 7,774 flows |
| **SQL Injection** | 15 | **0 (0.00%)** | **0 (0.00%)** | Zero overlap across both schemas |
| **SSH-Bruteforce** | 20,000 | 9,955 (49.78%) | 9,955 (49.78%) | 100% on port 22 |
| **TOTAL TEST DATASET** | **541,345** | **166,514 (30.76%)** | **140,714 (25.99%)** | **25,800 fewer overlaps with Port** |

#### B. Full Test Set vs Deduplicated Exploratory Evaluation:

The auditor evaluated both models on their respective deduplicated subsets:
- **77-Feature Deduplicated Subset:** **374,831 flows** (541,345 minus 166,514 overlapping flows).
- **78-Feature Deduplicated Subset:** **400,631 flows** (541,345 minus 140,714 overlapping flows).

| Model Candidate | Feature Set | Test Split Type | Flows Count | Accuracy | Macro-F1 | Benign FPR | Attack Recall | Infiltration Recall |
| :--- | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **LightGBM Primary** | 77 | Full Test Set | 541,345 | 75.62% | 0.8057 | 35.87% | 94.91% | 86.74% |
| **LightGBM Primary** | 77 | Deduplicated Subset | 374,831 | **80.77%** | **0.8037** | **26.04%** | 92.19% | 83.65% |
| **XGBoost Benchmark** | 77 | Full Test Set | 541,345 | 84.57% | 0.8168 | 1.02% | 71.67% | 26.52% |
| **XGBoost Benchmark** | 77 | Deduplicated Subset | 374,831 | **86.23%** | 0.8083 | **0.73%** | 64.55% | 25.55% |
| **LightGBM with Port** | 78 | Full Test Set | 541,345 | 76.26% | 0.8259 | 34.48% | 94.57% | 85.96% |
| **LightGBM with Port** | 78 | Deduplicated Subset | 400,631 | **80.03%** | 0.7949 | **26.68%** | 91.48% | 83.14% |

#### C. Per-Class Support and Metrics Before and After Deduplication:

##### 1. LightGBM Primary (77-Feature Port-Agnostic Schema):
| Class Label | Full Test Support | Full Test Recall | Full Test F1 | Deduplicated Support | Deduplicated Recall | Deduplicated F1 | Delta Recall |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Benign** | 300,000 | 64.13% | 0.7624 | 234,475 | **73.96%** | **0.8280** | **+9.83%** |
| **Bot** | 20,000 | 99.69% | 0.9957 | 10,132 | 99.73% | 0.9977 | +0.04% |
| **Brute Force -Web** | 93 | 81.72% | 0.5609 | 75 | **85.33%** | **0.6275** | **+3.61%** |
| **Brute Force -XSS** | 37 | 81.08% | 0.6522 | 35 | **85.71%** | **0.6818** | **+4.63%** |
| **DDOS attack-HOIC** | 20,000 | 100.00% | 1.0000 | 14,543 | 100.00% | 1.0000 | 0.00% |
| **DDOS attack-LOIC-UDP** | 260 | 92.31% | 0.9600 | 260 | 92.31% | 0.9600 | 0.00% |
| **DDoS attacks-LOIC-HTTP** | 20,000 | 100.00% | 1.0000 | 20,000 | 100.00% | 1.0000 | 0.00% |
| **DoS attacks-GoldenEye** | 6,227 | 99.90% | 0.9995 | 6,211 | 99.90% | 0.9995 | 0.00% |
| **DoS attacks-Hulk** | 20,000 | 100.00% | 1.0000 | 10,552 | 100.00% | 1.0000 | 0.00% |
| **DoS attacks-SlowHTTPTest** | 20,000 | 51.96% | 0.6355 | 0 | N/A* | N/A* | 100% duplicate |
| **DoS attacks-Slowloris** | 1,650 | 99.58% | 0.9113 | 1,623 | **100.00%** | **0.9991** | **+0.42%** |
| **FTP-BruteForce** | 20,000 | 88.42% | 0.7479 | 0 | N/A* | N/A* | 100% duplicate |
| **Infiltration** | 93,063 | 86.74% | 0.5745 | 66,865 | 83.65% | **0.6086** | -3.09% |
| **SQL Injection** | 15 | 26.67% | 0.2857 | 15 | 26.67% | **0.3636** | 0.00% |
| **SSH-Bruteforce** | 20,000 | 100.00% | 1.0000 | 10,045 | 100.00% | 1.0000 | 0.00% |

*\*Note: SlowHTTPTest and FTP-BruteForce consist 100% of repeated identical packet probes identical to training flows; their support drops to 0 in the deduplicated exploratory evaluation.*

##### 2. LightGBM with Port (78-Feature Port-Dependent Schema):
| Class Label | Full Test Support | Full Test Recall | Full Test F1 | Deduplicated Support | Deduplicated Recall | Deduplicated F1 | Delta Recall |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Benign** | 300,000 | 65.52% | 0.7713 | 252,480 | **73.32%** | **0.8223** | **+7.80%** |
| **Bot** | 20,000 | 100.00% | 1.0000 | 10,144 | 100.00% | 1.0000 | 0.00% |
| **Brute Force -Web** | 93 | 80.65% | 0.5515 | 75 | **84.00%** | 0.5294 | **+3.35%** |
| **Brute Force -XSS** | 37 | 83.78% | 0.8732 | 36 | **86.11%** | **0.8857** | **+2.33%** |
| **DDOS attack-HOIC** | 20,000 | 100.00% | 1.0000 | 14,543 | 100.00% | 1.0000 | 0.00% |
| **DDOS attack-LOIC-UDP** | 260 | 92.31% | 0.9600 | 260 | 92.31% | 0.9600 | 0.00% |
| **DDoS attacks-LOIC-HTTP** | 20,000 | 100.00% | 1.0000 | 20,000 | 100.00% | 1.0000 | 0.00% |
| **DoS attacks-GoldenEye** | 6,227 | 99.90% | 0.9995 | 6,211 | 99.90% | 0.9995 | 0.00% |
| **DoS attacks-Hulk** | 20,000 | 100.00% | 1.0000 | 10,552 | 100.00% | 1.0000 | 0.00% |
| **DoS attacks-SlowHTTPTest** | 20,000 | 51.96% | 0.6355 | 0 | N/A* | N/A* | 100% duplicate |
| **DoS attacks-Slowloris** | 1,650 | 100.00% | 1.0000 | 1,631 | 100.00% | 1.0000 | 0.00% |
| **FTP-BruteForce** | 20,000 | 88.42% | 0.7479 | 0 | N/A* | N/A* | 100% duplicate |
| **Infiltration** | 93,063 | 85.96% | 0.5788 | 74,639 | 83.14% | **0.6085** | -2.82% |
| **SQL Injection** | 15 | 33.33% | 0.2703 | 15 | 33.33% | **0.3226** | 0.00% |
| **SSH-Bruteforce** | 20,000 | 100.00% | 1.0000 | 10,045 | 100.00% | 1.0000 | 0.00% |

##### 3. XGBoost Benchmark (77-Feature Port-Agnostic Schema):
| Class Label | Full Test Support | Full Test Recall | Full Test F1 | Deduplicated Support | Deduplicated Recall | Deduplicated F1 | Delta Recall |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Benign** | 300,000 | 98.98% | 0.8926 | 234,475 | **99.27%** | **0.9004** | **+0.29%** |
| **Bot** | 20,000 | 99.77% | 0.9946 | 10,132 | 99.59% | 0.9939 | -0.18% |
| **Brute Force -Web** | 93 | 76.34% | 0.7474 | 75 | 70.67% | 0.6883 | -5.67% |
| **Brute Force -XSS** | 37 | 43.24% | 0.6038 | 35 | **45.71%** | **0.6275** | **+2.47%** |
| **DDOS attack-HOIC** | 20,000 | 100.00% | 0.9999 | 14,543 | 99.99% | 0.9998 | -0.01% |
| **DDOS attack-LOIC-UDP** | 260 | 100.00% | 1.0000 | 260 | 100.00% | 1.0000 | 0.00% |
| **DDoS attacks-LOIC-HTTP** | 20,000 | 100.00% | 0.9999 | 20,000 | 100.00% | 0.9999 | 0.00% |
| **DoS attacks-GoldenEye** | 6,227 | 99.90% | 0.9994 | 6,211 | 99.90% | 0.9994 | 0.00% |
| **DoS attacks-Hulk** | 20,000 | 100.00% | 0.9999 | 10,552 | 99.99% | 0.9998 | -0.01% |
| **DoS attacks-SlowHTTPTest** | 20,000 | 52.24% | 0.6358 | 0 | N/A* | N/A* | 100% duplicate |
| **DoS attacks-Slowloris** | 1,650 | 98.67% | 0.9891 | 1,623 | **100.00%** | **0.9960** | **+1.33%** |
| **FTP-BruteForce** | 20,000 | 87.96% | 0.7459 | 0 | N/A* | N/A* | 100% duplicate |
| **Infiltration** | 93,063 | 26.52% | 0.4090 | 66,865 | 25.55% | 0.3990 | -0.97% |
| **SQL Injection** | 15 | 13.33% | 0.2353 | 15 | 13.33% | 0.2353 | 0.00% |
| **SSH-Bruteforce** | 20,000 | 100.00% | 1.0000 | 10,045 | 100.00% | 1.0000 | 0.00% |

#### Evaluation Characterization & Critical Qualifications:

1. **Zero Support on SlowHTTPTest and FTP-BruteForce:**
   - In both 77-feature and 78-feature schemas, `DoS attacks-SlowHTTPTest` and `FTP-BruteForce` consist 100% of repeated identical packet probes identical to training flows.
   - In the deduplicated evaluation, both classes have **zero support (0 flows)**.
   - **Performance on the deduplicated subset is NOT VERIFIED.** Their full-test performance (SlowHTTPTest: 51.96% recall / 0.6355 F1; FTP-BruteForce: 88.42% recall / 0.7479 F1 on LightGBM) is preserved, but classified strictly as **exploratory benchmark results**.

2. **Qualification of the Duplicate-Overlap Conclusion:**
   - **Feature Vectors vs Physical Flows:** Identical feature vectors ($\Delta \mathbf{x} = 0$) do **not** prove identical physical flows. Tabular flow summaries lack packet payloads, timestamps, IP addresses, and ephemeral ports; multiple distinct network sessions naturally collapse into the same statistical vector.
   - **Evaluation Bias:** Improved aggregate metrics after filtering (e.g., LightGBM accuracy rising to 80.77%, benign FPR falling to 26.04%) do **not** independently prove the complete absence of evaluation bias.
   - **Conflicting-Label Overlaps:** There are **14,014 test flows (8.42% of overlapping test flows)** that share identical 77-feature vectors with training flows but carry contradictory class labels (predominantly `Test: Benign` vs `Train: Infiltration`, or `Test: DoS` vs `Train: Benign`).
   - **Security Implication:** In tabular flow space without payload inspection, 2-packet zero-byte handshake probes are statistically indistinguishable regardless of intent, creating an irreducible label ambiguity and setting a theoretical ceiling on purely flow-statistical detection.

**Status:** **PASS (QUALIFIED & CHARACTERIZED WITH DOCUMENTED CAVEATS)**

---

### 4. Final Sign-Off & Verification Summary

| Verification Item | Audit Standard / Requirement | Measured Result | Audit Verdict |
| :--- | :--- | :--- | :---: |
| **Source Records Accounting** | Verify exact 16.23M source counts | Exactly 16,232,943 rows verified across 10 Parquet files | **PASS** |
| **Partition Exclusions** | Reconcile benign (12.18M) and attack (1.87M) exclusions | Reconciled: 12,184,708 benign + 1,866,145 attack = 14,050,853 | **PASS** |
| **Rare Attack Retention** | Verify 100% retention on SQLi, XSS, Web Brute Force | Exactly 87 SQLi, 230 XSS, 611 Web Brute Force (100% retained) | **PASS** |
| **Discrepancy Root Cause** | Explain 109, 276, 769 vs 87, 230, 611 | Thursday's raw file counts were double-counted in earlier report | **PASS** |
| **Schema Overlap Separation** | Separate 77-feature (30.76%) from 78-feature (25.99%) overlap | Evaluated both schemas and documented per-class metrics | **PASS** |
| **Dedup Zero-Support Status** | Report SlowHTTPTest & FTP-BruteForce on deduplicated split | 0 support in deduplicated evaluation; full-test labeled exploratory | **NOT VERIFIED (0 Support)** |
| **Model Artifact Inventory** | Preserve exact inventory with unchanged SHA-256 hashes | Six supervised model files, two anomaly model files, one scaler artifact | **PASS** |
| **Retraining Authorization** | Retrain only if material defect requires it | Zero training defect found; all models valid; retraining unnecessary | **PASS** |

**Final Master Closeout Decision:**  
$$\Large\mathbf{ROLE\;3\;AND\;ROLE\;4:\;COMPLETE\;WITH\;CAVEATS\;FOR\;THE\;RESEARCH\;PROTOTYPE.}$$

The models may proceed to Role 6 integration in **observe-only mode**. The repeatedly evaluated test results remain strictly **exploratory**. The platform must **not claim production readiness, universal attack detection, or authorization for automatic blocking**. Zero model retraining is required.
