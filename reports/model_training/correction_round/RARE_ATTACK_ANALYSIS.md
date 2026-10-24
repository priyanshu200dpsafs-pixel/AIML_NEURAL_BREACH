# RARE ATTACK STATISTICAL ANALYSIS & UNCERTAINTY REPORT
## Team Neural Breach — AI/ML Cyber Defense Platform
**Role:** Senior Machine Learning Engineer and Cybersecurity Detection Specialist  
**Phase:** Role 3 Correction, Retraining & Validation  
**Date:** 2026-10-24  
**Audit Scope:** Rare-Class Support Limitations, Wilson Score Confidence Intervals, and Defense Guidance  

---

## 1. Executive Summary & Problem Formulation

In CSE-CIC-IDS2018, several critical cyber threat families are represented by extremely small numbers of flows:
- `SQL Injection`: Only **87 total flows in the entire 16,232,943-record collection** (0.0005% of the dataset).
- `Brute Force - XSS`: Only **230 total flows** (0.0014%).
- `Brute Force - Web`: Only **611 total flows** (0.0038%).
- `DDOS attack-LOIC-UDP`: Only **1,730 total flows** (0.0107%).

When evaluating an untouched test partition, the test support for these classes is necessarily constrained:
- SQL Injection: **15 flows**
- Brute Force - XSS: **37 flows**
- Brute Force - Web: **93 flows**
- DDOS attack-LOIC-UDP: **260 flows**

A single misclassified flow causes observed recall to swing by **6.67% on SQL Injection** and **2.70% on XSS**. Therefore, point estimates of recall without uncertainty bounds are statistically meaningless and scientifically deceptive.

---

## 2. Statistical Uncertainty Matrix (Wilson 95% Confidence Intervals)

To quantify the true uncertainty of these measurements, we computed **Wilson Score Confidence Intervals (95% confidence level)** for binomial proportions:

| Attack Category | Total in Dataset | Test Support ($N$) | True Positives ($TP$) | False Negatives ($FN$) | Point Recall | Wilson 95% Confidence Interval | Precision | F1-Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **SQL Injection** | 87 | **15** | 2 | 13 | **13.33%** | **[ 3.74%, 37.88%]** | **100.00%** | **0.2353** |
| **Brute Force -XSS** | 230 | **37** | 16 | 21 | **43.24%** | **[28.67%, 59.09%]** | **100.00%** | **0.6038** |
| **Brute Force -Web** | 611 | **93** | 71 | 22 | **76.34%** | **[66.77%, 83.83%]** | **73.20%** | **0.7474** |
| **DDOS attack-LOIC-UDP** | 1,730 | **260** | 260 | 0 | **100.00%** | **[98.54%, 100.00%]** | **100.00%** | **1.0000** |

```
Observed Recall and 95% Confidence Intervals:
SQL Injection:        [---●---------] 13.3% CI=[3.7%, 37.9%]
Brute Force -XSS:           [---●---] 43.2% CI=[28.7%, 59.1%]
Brute Force -Web:             [--●--] 76.3% CI=[66.8%, 83.8%]
DDOS attack-LOIC-UDP:               [●] 100.0% CI=[98.5%, 100.0%]
0%                   25%                  50%                  75%                 100%
```

---

## 3. Analysis of Rare Class Behavior

### 1. SQL Injection ($N=15$, CI: $[3.74\%, 37.88\%]$)
- **Observed Behavior**: The model achieved **100.00% Precision** (zero false positive SQLi alerts), but detected only 2 of 15 test flows.
- **Root Cause**:
  - SQL injection payloads (`UNION SELECT`, `' OR 1=1--`) exist inside HTTP URI query parameters or POST bodies.
  - Flow summary features capture bidirectional statistical aggregates (packet sizes, inter-arrival times, flag counts), NOT raw application-layer ASCII text.
  - Unless an SQL injection query produces anomalous packet sizes or unusual transmission delays, its flow statistics closely mimic ordinary HTTP GET / POST transactions.
- **Statistical Truth**: With only 15 test records, we can only state with 95% confidence that true recall lies between 3.7% and 37.9%. It is impossible to claim strong or weak generalizability from 15 samples alone.

### 2. Brute Force - XSS ($N=37$, CI: $[28.67\%, 59.09\%]$)
- **Observed Behavior**: Detected 16 of 37 flows (**43.24% recall**), with **100.00% Precision** (zero false alarms).
- **Root Cause**: XSS attacks in this dataset generated repeated script injections. The flows that were detected exhibited slightly larger forward packet bursts (`Fwd Pkt Len Max`), allowing the model to trigger an alert with high confidence.

### 3. Brute Force - Web ($N=93$, CI: $[66.77\%, 83.83\%]$)
- **Observed Behavior**: Detected 71 of 93 flows (**76.34% recall**) with **73.20% Precision** and **0.7474 F1-score**.
- **Significant Improvement**: This represents a dramatic advance over the teammate's baseline (which achieved an F1 of only 0.2803 due to massive false alarms). The tighter confidence interval $[66.8\%, 83.8\%]$ indicates reliable detection of automated web login brute-forcing.

### 4. DDOS attack-LOIC-UDP ($N=260$, CI: $[98.54\%, 100.00\%]$)
- **Observed Behavior**: Detected 260 of 260 flows (**100.00% recall**) with **100.00% Precision**.
- **Root Cause**: UDP reflection flood attacks produce distinctive packet volume, zero TCP handshake flags, and short inter-arrival times, creating an unmistakable tabular footprint.

---

## 4. Rejection of Synthetic Oversampling (SMOTE)

We explicitly evaluated and **rejected** synthetic oversampling (e.g., SMOTE, ADASYN) for rare attack training:
1. **Mathematical Fallacy of Feature Interpolation**:
   - SMOTE creates synthetic points by linearly interpolating between existing samples in feature space.
   - For an attack like SQL Injection, interpolating between two flow records creates synthetic vectors that do not correspond to any valid TCP/IP state machine transition or authentic HTTP protocol behavior.
2. **False Confidence**:
   - Training on synthetic examples artificially inflates internal cross-validation scores without improving detection on authentic network wire traffic.
3. **Class Weighting Strategy Adopted**:
   - Instead of inventing fake data, we preserved **100% of authentic rare attack flows** and employed inverse class-frequency loss weighting during training.

---

## 5. SOC Defense-in-Depth Recommendations

For Role 4 evaluation and Role 6 backend integration:
- **Do NOT rely exclusively on tabular flow classifiers for Layer-7 web attacks (SQLi and XSS)**.
- **Deploy Web Application Firewalls (WAF)**: Deep packet inspection (DPI) engines with regex / AST parsing are mathematically necessary to inspect HTTP request payloads.
- **Tier-2 Anomaly Correlation**: When an unusual web flow bypasses the supervised tree classifier, the Deep Autoencoder reconstruction error ($\text{MSE}$) flags structural anomalies for analyst review.
