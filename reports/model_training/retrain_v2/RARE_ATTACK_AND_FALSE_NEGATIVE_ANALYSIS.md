# RARE ATTACK AND FALSE NEGATIVE ANALYSIS (RETRAINING V2)
## Team Neural Breach — AI/ML Cyber Defense Platform
**Role:** Machine Learning & Anomaly Detection Specialist  
**Phase:** Role 3 Retraining V2  
**Date:** 2026-10-25  
**Audit Scope:** Rare-Class Support Limitations, Wilson Score Confidence Intervals, and False Negative Trajectories  

---

## 1. Executive Summary & Problem Formulation

In cybersecurity detection, statistical rarity is a defining reality:
- Threat actors execute targeted exploits (such as SQL injection or XSS) with surgical precision (tens of packets), while automated DDoS tools generate millions of packets.
- In CSE-CIC-IDS2018:
  - `SQL Injection`: Only **87 flows in the entire 16,232,943-record collection** (0.0005% of traffic).
  - `Brute Force - XSS`: Only **230 flows** (0.0014%).
  - `Brute Force - Web`: Only **611 flows** (0.0038%).
  - `DDOS attack-LOIC-UDP`: Only **1,730 flows** (0.0107%).

When evaluating an untouched test partition, test support for these classes is necessarily limited ($N=15$ for SQLi, $N=37$ for XSS). Reporting point estimates of accuracy or recall without statistical confidence bounds is deceptive.

---

## 2. Statistical Uncertainty Matrix (Wilson 95% Confidence Intervals)

To provide honest evaluation, we computed **Wilson Score Confidence Intervals (95% confidence level)** for binomial proportions:

| Attack Category | Total in Dataset | Test Support ($N$) | Model Evaluated | True Positives | False Negatives | Point Recall | Wilson 95% Confidence Interval | Precision | F1-Score |
| :--- | :---: | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **SQL Injection** | 87 | **15** | **LightGBM** | 4 | 11 | **26.67%** | **[10.90%, 51.95%]** | 30.77% | **0.2857** |
| | | | **XGBoost** | 2 | 13 | **13.33%** | **[ 3.74%, 37.88%]** | 100.00% | **0.2353** |
| **Brute Force -XSS** | 230 | **37** | **LightGBM** | 30 | 7 | **81.08%** | **[65.84%, 90.52%]** | 54.55% | **0.6522** |
| | | | **XGBoost** | 16 | 21 | **43.24%** | **[28.67%, 59.09%]** | 100.00% | **0.6038** |
| **Brute Force -Web** | 611 | **93** | **LightGBM** | 76 | 17 | **81.72%** | **[72.67%, 88.26%]** | 42.70% | **0.5609** |
| | | | **XGBoost** | 71 | 22 | **76.34%** | **[66.77%, 83.83%]** | 73.20% | **0.7474** |
| **DDOS LOIC-UDP** | 1,730 | **260** | **LightGBM** | 240 | 20 | **92.31%** | **[88.38%, 95.03%]** | 100.00% | **0.9600** |
| | | | **XGBoost** | 260 | 0 | **100.00%** | **[98.54%, 100.00%]** | 100.00% | **1.0000** |

---

## 3. False Negative Trajectory Analysis

In cybersecurity, understanding **where missed attacks go** is critical:

```
                          TRUE ATTACK FLOWS
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
[Alerted as Another Attack]                       [Predicted as Benign]
- e.g. SlowHTTPTest -> FTP-BruteForce             - CRITICAL FALSE NEGATIVE
- SOC Analyst STILL gets an alert                 - Intrusion completely missed
- Security perimeter NOT breached                 - Threat enters unalerted
```

### Empirical Trajectory Findings:
1. **SlowHTTPTest and FTP-BruteForce Mutual Confusion**:
   - Out of 20,000 true `SlowHTTPTest` test flows, 10,449 were predicted as `SlowHTTPTest` and 9,551 were predicted as `FTP-BruteForce`. **Zero flows were predicted as Benign**.
   - Out of 20,000 true `FTP-BruteForce` test flows, 17,591 were predicted as `FTP-BruteForce` and 2,409 were predicted as `SlowHTTPTest`. **Zero flows were predicted as Benign**.
   - *Conclusion*: In the 77-feature port-agnostic model, both attacks use small, repetitive TCP packets with slow inter-arrival times. While the model confuses the specific application protocol, **100% of the traffic triggers high-severity security alerts**!
2. **Infiltration False Negative Trajectory**:
   - In XGBoost, **68,257 Infiltration flows** were predicted as Benign (representing 99.83% of all missed attacks).
   - In LightGBM, Infiltration recall jumped to **86.74%**, reducing missed Infiltration flows down to **12,343**, but at the cost of higher benign false alarms.

---

## 4. Rejection of Synthetic Oversampling (SMOTE)

We evaluated and explicitly **rejected** synthetic oversampling (SMOTE, ADASYN) for rare threat training:
1. **Mathematical Illegitimacy of Interpolated Flows**:
   - SMOTE creates artificial points by linearly interpolating between existing samples in feature space.
   - For an SQL Injection or XSS flow, interpolating between two feature vectors produces synthetic values (such as fractional window sizes or impossible TCP flag combinations) that violate RFC specifications and cannot exist on wire traffic.
2. **False Generalization**:
   - Models trained on synthetic artifacts achieve inflated cross-validation scores while failing to generalize to authentic wire data.
3. **Adopted Protocol**:
   - We preserved **100% of authentic rare attack flows** and utilized inverse class-frequency loss weighting during training.

---

## 5. SOC Defense-in-Depth Recommendations

- **Tabular Flow Classifiers Cannot Replace Web Application Firewalls (WAF)**:
  - SQL injection payloads (`' OR 1=1--`) exist in HTTP URI query strings and POST bodies.
  - Tabular flow features capture packet length and timing statistics, not ASCII payload semantics. A WAF with regex/AST inspection is mathematically necessary.
- **Deep Autoencoder Backstop**:
  - Unseen exploits that bypass the supervised tree model generate elevated reconstruction error in the PyTorch Deep Autoencoder (e.g. 43.2% of XSS flows flagged at 1% FPR budget), providing an independent secondary safety net.
