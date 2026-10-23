# AI/ML Cyber Defense Platform: Prioritized Next Engineering Steps

**Baseline**: Evidence-based roadmap derived directly from our actual physical dataset audit.

---

## 1. What Can Be Done Immediately WITHOUT Downloading More Data

We already have **3,041,379 verified network flows in CSE-CIC-IDS2018** and **257,673 verified network flows in UNSW-NB15**, plus **323,154 verified botnet packets** in CTU-13. Model development can begin immediately on the following tracks:

### Action 1.1: Build Clean Tabular Preprocessing Pipeline for CSE-CIC-IDS2018 (3.04M Flows)
1. **Header Artifact Stripping**: Write an automated cleaner that drops rows where `Label == 'Label'` (59 total artifact rows across our 4 files).
2. **Label Normalization**: Standardize labels:
   - `Infilteration` -> `Infiltration`
   - `DDOS attack-HOIC` -> `DDoS-HOIC`
   - `DDOS attack-LOIC-UDP` -> `DDoS-LOIC-UDP`
   - `DoS attacks-Hulk` -> `DoS-Hulk`
   - `DoS attacks-SlowHTTPTest` -> `DoS-SlowHTTPTest`
3. **Identifier Leakage Elimination**: Drop `Dst Port` and `Timestamp` to prevent the model from memorizing port numbers and attack execution times rather than behavioral flow distributions.
4. **Handling Infinite / Missing Values**: Replace `Infinity`, `NaN`, and negative flow durations (`Flow Duration < 0`) with domain-appropriate bounds.

### Action 1.2: Train Baseline Supervised Classifiers & Evaluate Class Imbalance
- **Available Multi-Class Target**: 6 verified classes:
  - `Benign`: 1,589,842 flows (52.27%)
  - `DDOS attack-HOIC`: 686,012 flows (22.56%)
  - `DoS attacks-Hulk`: 461,912 flows (15.19%)
  - `Infiltration`: 161,934 flows (5.32%)
  - `DoS attacks-SlowHTTPTest`: 139,890 flows (4.60%)
  - `DDOS attack-LOIC-UDP`: 1,730 flows (0.06% — severe minority class)
- **Recommended Algorithms**: LightGBM / XGBoost with `class_weight='balanced'` and Focal Loss to address the 0.06% LOIC-UDP minority.

### Action 1.3: Train Unsupervised Anomaly Detectors on Benign Baseline
- Extract the **1,589,842 verified Benign flows** from CSE-CIC-IDS2018 and **93,000 normal flows** from UNSW-NB15.
- Train a Deep Autoencoder and Isolation Forest on benign traffic only.
- Test anomaly detection thresholding against the held-out attack flows (HOIC, Hulk, Infiltration).

### Action 1.4: Train Packet-Level Sequence Model on CTU-13 Neris Botnet PCAP
- Ingest the **323,154 raw packets** from `botnet-capture-20110810-neris.pcap`.
- Extract packet payload lengths and inter-arrival timing sequences to train an LSTM / 1D-CNN botnet detector without relying on tabular aggregations.

---

## 2. What Data Is Still Required for Full Platform Objectives

1. **SSH / FTP Brute-Force**: Download `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` (358 MB) from S3.
2. **Web Attacks (SQLi, XSS)**: Download `Thursday-22-02-2018` (382 MB) and `Friday-23-02-2018` (382 MB) from S3.
3. **Zero-Day Generalization**: Use UNSW-NB15 as an external benchmark to test if models trained on CSE-CIC-IDS2018 can detect previously unseen attack signatures.
4. **Lateral Movement Authentication Traces**: Resume LANL `dns.txt.gz` (185 MB) and evaluate downloading LANL `auth.txt.gz` (7.2 GB) into Google Drive.

---

## 3. The Three Most Critical Next Actions

1. **Action 1 (Data Engineering)**: Implement the automated cleaning script for our 3.04M CSE-CIC-IDS2018 flow records (strip 59 repeated header lines, fix `Infilteration` spelling, remove leakage features `Dst Port` and `Timestamp`).
2. **Action 2 (Modeling)**: Train our first supervised LightGBM baseline on the 6 verified classes in CSE-CIC-IDS2018 using a chronological train/test split.
3. **Action 3 (Collection)**: Download the remaining two missing attack classes (Brute-Force from `Wednesday-14-02` and Web Attacks from `Thursday-22-02`) totaling ~740 MB directly into Google Drive to complete our 7 platform capabilities.
