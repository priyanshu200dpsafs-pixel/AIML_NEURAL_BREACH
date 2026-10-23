# Team Neural Breach — Phase 2 Engineering Handoff Specification

**Project**: AI/ML-Based Cyber Defense Platform  
**Engineering Team**: Neural Breach  
**From**: Senior Cybersecurity Data Acquisition Engineer  
**To**: ML Preprocessing & Baseline Modeling Engineers  
**Handoff Timestamp**: 2026-10-22 08:05:00 UTC  
**Document Version**: 4.0 (Phase 1C Final Handoff)  

---

## 1. Executive Summary & Inventory Ready for Modeling

The data acquisition phase has achieved critical mass. The repository contains **8,541,868 clean, trainable network flow records** across 13 distinct cyber attack families, plus **6,205,151 pure benign flows** for false-positive calibration, **40,821,591 DNS lookup records**, **323,154 raw captured packets**, and **432 Windows endpoint host event logs**.

All files have been verified, checksummed, and mirrored to Google Drive. Raw data in `data/raw/` remains untouched.

### Primary ML Telemetry Telemetry Summary
1. **CSE-CIC-IDS2018 (9 Verified Daily CSVs — 90% Complete)**:
   - Total clean flows: **8,284,195 clean records** across 80 CICFlowMeter features.
   - Attack categories verified:
     - Volumetric DDoS: `DDOS attack-HOIC` (686,012 flows), `DDOS attack-LOIC-UDP` (1,730 flows)
     - Application DoS: `DoS attacks-Hulk` (461,912 flows), `DoS attacks-SlowHTTPTest` (139,890 flows), `DoS attacks-GoldenEye` (41,508 flows), `DoS attacks-Slowloris` (10,990 flows)
     - Credential Brute Force: `FTP-BruteForce` (193,360 flows), `SSH-Bruteforce` (187,589 flows)
     - Network Infiltration: `Infiltration` (161,934 flows across multi-day breach)
     - Botnet: `Bot` Ares C2 (286,191 flows)
     - Web Attacks: `Brute Force -Web` (611 flows), `Brute Force -XSS` (230 flows), `SQL Injection` (87 flows)
     - Benign Perimeter Baseline: `Benign` (6,112,151 flows)
2. **UNSW-NB15 (2 Benchmark Partitions)**:
   - Total clean flows: **257,673 records** (82,332 training, 175,341 testing) across 42 features.
   - Ground truth labels: Binary `label` (93,000 Normal vs. 164,673 Attack flows).
3. **Endpoint Host Forensic Evidence**:
   - `Friday-23-02-2018_logs.zip` (209.5 MB) containing **432 Windows Event Log (`.evtx`) files** from the victim machines during the Web Attack campaign.

---

## 2. Essential Data Cleaning Instructions for Phase 2

The preprocessing team must incorporate these exact cleaning directives during ingestion into `data/processed/`:

### A. Filter Out the 59 Repeated Header Lines
Across the 9 CSE CSVs, exactly 59 lines contain repeated CSV headers (`Label == 'Label'`).
- `Friday-16-02-2018`: 1 repeated header
- `Wednesday-28-02-2018`: 33 repeated headers
- `Thursday-01-03-2018`: 25 repeated headers
- All other days (`14-02`, `15-02`, `21-02`, `22-02`, `23-02`, `02-03`): 0 repeated headers.
- **Python Directive**:
  ```python
  # Drop string header artifacts before casting features
  df = df[df["Label"] != "Label"]
  ```

### B. Standardize Typo in Infiltration Label
- Exactly 161,934 records spell Infiltration with an extra 'e' (`Infilteration`).
- **Python Directive**:
  ```python
  df["Label"] = df["Label"].replace({"Infilteration": "Infiltration"})
  ```

### C. Separate Benchmarks Horizontally
- Do NOT merge CSE-CIC-IDS2018 (80 features) and UNSW-NB15 (42 features) into a single dataframe. They represent distinct network sensors and feature schemas. Maintain independent evaluation tracks.

### D. Avoid Random Cross-Validation Data Leakage
- Do NOT use standard randomized k-fold splits on network flow telemetry. Consecutive packets in TCP sessions share identical statistical fingerprints.
- Use **Chronological / Day-Based Splitting**:
  - **Train Set**: `Wednesday-14-02`, `Thursday-15-02`, `Friday-16-02`, `Wednesday-21-02`, `Thursday-22-02`, `Wednesday-28-02` (~6.1M flows).
  - **Held-Out Test Set**: `Friday-23-02` (Web Attacks Day 2), `Thursday-01-03` (Infiltration Day 2), `Friday-02-03` (Botnet Ares) (~2.4M flows).

---

## 3. Recommended Baseline Model Architecture

1. **Supervised GBDT Baseline**:
   - Model: `HistGradientBoostingClassifier` or `LightGBM`.
   - Loss: `class_weight='balanced'` to prevent minority attack classes (SQL Injection, XSS) from being swamped by benign traffic.
2. **Unsupervised Anomaly Detection Baseline**:
   - Model: `IsolationForest` or `OneClassSVM`.
   - Training Data: Exclusively fit on the **6,205,151 pure benign flows**.
   - Evaluation: Measure ROC-AUC and False Positive Rate (FPR) on held-out attack days.
