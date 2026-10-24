# Model Robustness & Reliability Findings

**Project:** AI/ML-Based Cyber Defense Platform  
**Team:** Neural Breach  
**Role:** Role 3 (Machine Learning & Anomaly Detection)  
**Execution Date:** October 24, 2026  

---

## 1. Cross-Day Temporal Generalization & Infiltration Shift

### The Problem
In the previous audit, when the model was trained on Wednesday Feb 28 and evaluated on Thursday Mar 01, it misclassified **210,402 of 359,180 benign flows as Infiltration**, producing a catastrophic **58.58% False Alarm Rate**.

### Root Cause Analysis
1. **Semantic Ambiguity of Infiltration Traffic**: Infiltration attacks emulate normal enterprise user activity (Dropbox syncing, benign binary downloads, Nmap host sweeps). In feature space, their medians (`Tot Fwd Pkts` = 2, `Tot Bwd Pkts` = 1, `Flow Duration` ~1,500 $\mu s$) are virtually indistinguishable from normal browsing sessions.
2. **Environmental Baseline Shift**: On Thursday Mar 01, normal background traffic had longer median flow durations (19,653 $\mu s$ vs. 2,067 $\mu s$ on Feb 28).
3. **Model Regularization Difference**:
   - In unregularized `HistGradientBoostingClassifier`, balanced sample weighting caused tree splits to heavily favor the rare Infiltration class upon encountering unseen background timing variations.
   - In `XGBoost`, depth constraints (`max_depth=6`), L2 regularization, and multi-day background training prevented tree over-branching on temporal noise.
   - **Result:** XGBoost slashed benign false alarms from **58.58% down to 1.02%** (only 3,058 false positives out of 300,000 benign flows).

---

## 2. Rare Cyber Attack Detection Performance

Cybersecurity telemetry is characterized by extreme class imbalance. The table below assesses model performance on the rarest attack families in the test set:

| Attack Category | Test Support | Class % in Test | Baseline HistGBT Recall | XGBoost Recall | XGBoost Precision | XGBoost F1-Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **SQL Injection** | 15 | 0.003% | 40.00% | 13.33% | 100.00% | 0.2353 |
| **Brute Force -XSS** | 37 | 0.007% | 78.38% | 43.24% | 100.00% | 0.6038 |
| **Brute Force -Web** | 93 | 0.017% | 88.17% | 76.34% | 73.20% | 0.7474 |
| **DDOS attack-LOIC-UDP** | 260 | 0.048% | 53.85% | **100.00%** | 100.00% | **1.0000** |
| **DoS attacks-Slowloris** | 1,650 | 0.305% | 99.52% | **98.67%** | 99.15% | **0.9891** |
| **DoS attacks-GoldenEye** | 6,227 | 1.150% | 99.90% | **99.90%** | 99.97% | **0.9994** |

### Key Observations
* **High Volumetric Robustness**: DDOS LOIC-UDP, DoS Slowloris, and DoS GoldenEye achieved $98.6\%$ to $100.0\%$ detection recall with $\ge 99\%$ precision.
* **Web Exploits Limitation**: Rare application-layer exploits (SQL Injection with 15 test flows, XSS with 37 test flows) have high precision ($100\%$) but lower recall ($13.3\%$ and $43.2\%$). In production, web attacks should be supplemented by Web Application Firewall (WAF) payload inspection (Role 2 HTTP telemetry parser).

---

## 3. Destination Port Dependency & Ablation Analysis

| Metric | Baseline Model (Without Dst Port) | Ablation Model (With Dst Port) | Delta ($\Delta$) | Interpretation |
| :--- | :---: | :---: | :---: | :--- |
| **Accuracy** | 73.66% | 74.86% | +1.20% | Marginal improvement |
| **Macro-F1** | 0.7189 | 0.7983 | +0.0794 | Moderate boost on rare port-specific attacks |
| **Weighted-F1** | 0.7538 | 0.7649 | +0.0111 | Slight overall boost |
| **Benign FPR** | 39.75% | 37.46% | -2.29% | Slight reduction in false alarms |

### Assessment
Including `Dst Port` improves macro-F1 on port-specific services (Port 21 for FTP, Port 22 for SSH). However, the baseline model without `Dst Port` still achieves high attack detection (100% on SSH, 88% on FTP, 100% on DoS Hulk), confirming that the decision tree boundaries are anchored primarily on packet dynamics, window sizes, and inter-arrival timers rather than static port memorization.

---

## 4. Anomaly Detection on Out-of-Distribution Traffic (CTU-13 Neris Botnet)

When the 14,521 flows from CTU-13 Scenario 1 (`Botnet-Neris`) were evaluated on the CSE-trained anomaly detectors:
* **Overlapping Flow Attributes**: 36 common attributes (packet counts, byte lengths, duration, flag counts).
* **Deep Autoencoder Response**: Generated elevated reconstruction errors on Neris botnet C&C beaconing flows, recognizing abnormal periodic timing and packet size distributions.
* **Isolation Forest Response**: Volumetric flooding phases were recognized, but low-rate IRC beaconing flows blended into the benign profile.

---

## 5. Security & Evasion Considerations for Role 4

1. **Adversarial Timing Perturbations**: An attacker introducing random delays during DoS flooding can alter `Flow IAT Mean` and `Flow IAT Std`. Role 4 should evaluate adversarial jitter attacks against the classifier.
2. **Payload Splitting (Small TCP Packets)**: Web brute force and SQL injection attacks that fragment payloads across small packets test the model's reliance on `Pkt Len Mean` and `Fwd Act Data Pkts`.
3. **Threshold Calibration Strategy**: For production deployment, the platform should operate the XGBoost classifier for high-confidence signatures and the PyTorch Autoencoder at $\text{FPR} \le 1.0\%$ for zero-day/outlier alerting.
