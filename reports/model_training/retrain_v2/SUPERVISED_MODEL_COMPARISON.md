# SUPERVISED MODEL COMPREHENSIVE COMPARISON (RETRAINING V2)
## Team Neural Breach — AI/ML Cyber Defense Platform
**Role:** Machine Learning & Anomaly Detection Specialist  
**Phase:** Role 3 Retraining V2  
**Date:** 2026-10-25  
**Evaluated Models:** LightGBM Primary Candidate vs. Port Ablation vs. XGBoost vs. HistGBT vs. Random Forest  
**Test Partition:** Untouched Master Test Set (541,345 Flows Across All 15 Classes)  

---

## 1. Candidate Comparison Matrix

All five models were evaluated on the **exact same 541,345 authentic network flows**:

| Model Architecture | Feature Set | Accuracy | Macro-F1 | Weighted-F1 | Benign FPR | Attack FNR (Missed) | Latency (µs/flow) | Throughput (flows/sec) | Training Time |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **LightGBM (Primary Candidate)** | 77 Feat | **75.62%** | **0.8057** | **0.7719** | **35.87%** | **5.09%** (12,295) | 14.92 | 67,002 | **34.7 s** |
| **LightGBM Port Ablation** | 78 (+Dst Port) | **76.26%** | **0.8259** | **0.7788** | **34.48%** | **5.43%** (13,101) | 15.10 | 66,225 | **35.8 s** |
| **XGBoost Benchmark** | 77 Feat | **84.57%** | **0.8168** | **0.8157** | **1.02%** | **28.33%** (68,376) | **3.52** | **290,072** | 2,610 s (~43m) |
| **HistGBT Benchmark** | 77 Feat | **73.66%** | **0.7189** | **0.7538** | **39.75%** | **4.36%** (10,516) | 5.01 | 278,734 | 1,512 s (~25m) |
| **Random Forest Baseline** | 77 Feat | **82.02%** | **0.7861** | **0.7932** | **0.78%** | **34.28%** (82,728) | 22.45 | 44,543 | 48.2 s |

---

## 2. Per-Class Performance Breakdown Across All 15 Classes

Below is the side-by-side per-class performance comparing **LightGBM Primary** against **XGBoost**:

| Traffic Class | Test Support | LightGBM Precision | LightGBM Recall | LightGBM F1 | XGBoost Precision | XGBoost Recall | XGBoost F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Benign** | 300,000 | **93.99%** | **64.13%** | **0.7624** | 81.28% | 98.98% | **0.8926** |
| **Bot** | 20,000 | **99.45%** | **99.69%** | **0.9957** | 99.16% | 99.77% | **0.9946** |
| **Brute Force -Web** | 93 | **42.70%** | **81.72%** | **0.5609** | 73.20% | 76.34% | **0.7474** |
| **Brute Force -XSS** | 37 | **54.55%** | **81.08%** | **0.6522** | 100.00% | 43.24% | **0.6038** |
| **DDOS attack-HOIC** | 20,000 | **100.00%** | **100.00%** | **1.0000** | 99.98% | 100.00% | **0.9999** |
| **DDOS attack-LOIC-UDP** | 260 | **100.00%** | **92.31%** | **0.9600** | 100.00% | 100.00% | **1.0000** |
| **DDoS attacks-LOIC-HTTP** | 20,000 | **100.00%** | **100.00%** | **1.0000** | 99.99% | 100.00% | **0.9999** |
| **DoS attacks-GoldenEye** | 6,227 | **100.00%** | **99.90%** | **0.9995** | 99.97% | 99.90% | **0.9994** |
| **DoS attacks-Hulk** | 20,000 | **100.00%** | **100.00%** | **1.0000** | 99.98% | 100.00% | **0.9999** |
| **DoS attacks-SlowHTTPTest**| 20,000 | **81.77%** | **51.96%** | **0.6355** | 81.20% | 52.24% | **0.6358** |
| **DoS attacks-Slowloris** | 1,650 | **84.00%** | **99.58%** | **0.9113** | 99.15% | 98.67% | **0.9891** |
| **FTP-BruteForce** | 20,000 | **64.80%** | **88.42%** | **0.7479** | 64.75% | 87.96% | **0.7459** |
| **Infiltration** | 93,063 | **42.95%** | **86.74%** | **0.5745** | 89.36% | 26.52% | **0.4090** |
| **SQL Injection** | 15 | **30.77%** | **26.67%** | **0.2857** | 100.00% | 13.33% | **0.2353** |
| **SSH-Bruteforce** | 20,000 | **100.00%** | **100.00%** | **1.0000** | 100.00% | 100.00% | **1.0000** |

---

## 3. Analysis of the Central Cybersecurity Trade-Off

The comparison between **LightGBM** and **XGBoost** exposes the fundamental operating dilemma in network intrusion detection:

```
                      THE SOC OPERATING TRADEOFF
    LightGBM (Balanced Weights)        XGBoost (L2 Regularized)
    ┌─────────────────────────┐        ┌─────────────────────────┐
    │ Attack Recall:  94.91%  │        │ Attack Recall:  71.67%  │
    │ Missed Attacks: 12,295  │        │ Missed Attacks: 68,376  │
    │ Infil Recall:   86.74%  │        │ Infil Recall:   26.52%  │
    │ XSS Recall:     81.08%  │        │ XSS Recall:     43.24%  │
    │ Benign FPR:     35.87%  │        │ Benign FPR:      1.02%  │
    │ (High Recall, High FPs) │        │ (Low FPs, Lower Recall) │
    └─────────────────────────┘        └─────────────────────────┘
```

1. **LightGBM Priority (Maximum Threat Interception)**:
   - Catches **94.91% of all cyber attacks** (misses only 12,295 flows out of 241,345).
   - Achieves **86.74% recall on Infiltration**, **81.08% on XSS**, and **81.72% on Web Brute Force**.
   - *Cost*: Generates a 35.87% raw Benign False Positive Rate because balanced class weights amplify minority attack gradients.
2. **XGBoost Priority (Analyst Alert Fatigue Suppression)**:
   - Slashes benign false alarms down to **1.02%** (only 3,058 false alarms out of 300,000).
   - *Cost*: Drops Infiltration recall to **26.52%**, accounting for 68,257 missed flows.
3. **Random Forest Priority (Extreme Conservatism)**:
   - Slashes false alarms even further to **0.78% FPR**, but misses **82,728 attacks (34.28% FNR)**.
4. **Strategic Architecture Decision**:
   - For an automated inline blocking firewall, **XGBoost is the recommended candidate** because a 35% false alarm rate would disrupt normal business operations.
   - For high-security threat-hunting environments where missing an infiltration is intolerable, **LightGBM with validation threshold calibration** provides superior attack sensitivity.

---

## 4. Destination Port Ablation Findings

Evaluating LightGBM with and without `Dst Port`:
- **Port-Agnostic Model (77 Feat)**: Accuracy = **75.62%**, Macro-F1 = **0.8057**
- **Port-Aware Model (78 Feat)**: Accuracy = **76.26%**, Macro-F1 = **0.8259** (+0.0202 Macro-F1 boost)

### Engineering Assessment:
Including `Dst Port` provides modest gains on port-specific brute-force attacks (FTP on 21, SSH on 22). However, relying on standard destination ports creates an adversary bypass vulnerability if an attacker migrates C2 or brute-force traffic to non-standard ports (e.g., SSH over 443). Therefore, the **77-feature port-agnostic schema is retained as our primary production standard**.

---

## 5. Validation-Calibrated Operating Point Analysis (LightGBM)

Calibrating decision thresholds strictly on the Validation partition across target false-positive budgets:

| Target FPR Budget | Calibrated Threshold | Actual Test FPR | Attack Recall | Binary Precision | Binary F1 | False Alarms | Missed Attacks |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **FPR $\le$ 0.1%** | 0.8476 | **0.04%** | **61.57%** | **99.91%** | **0.7619** | 134 | 92,755 |
| **FPR $\le$ 0.5%** | 0.7350 | **0.12%** | **62.50%** | **99.76%** | **0.7685** | 358 | 90,504 |
| **FPR $\le$ 1.0%** | 0.6720 | **0.46%** | **65.37%** | **99.13%** | **0.7879** | 1,385 | 83,572 |
| **FPR $\le$ 5.0%** | 0.2420 | **3.52%** | **76.14%** | **94.57%** | **0.8436** | 10,551 | 57,595 |

This confirms that by applying a validation threshold of **0.6720**, LightGBM's false positive rate can be tuned down to **0.46% on test data** while capturing **65.37% of all attacks** with **99.13% precision**.
