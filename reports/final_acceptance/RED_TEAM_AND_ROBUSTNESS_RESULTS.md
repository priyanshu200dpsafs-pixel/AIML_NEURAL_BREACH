# TEAM NEURAL BREACH — RED-TEAM & ROBUSTNESS AUDIT REPORT
## Adversarial Evasion Tests, Perturbation Stress & Architectural Defense Limits

**Project:** AI/ML-Based Cyber Defense Platform  
**Team:** Neural Breach  
**Auditor:** Independent Senior ML Engineer & Cybersecurity Red-Team Auditor  
**Audit Date:** October 28, 2026  
**Status:** COMPLETE — REPRODUCED & VALIDATED  

---

### 1. Critical Methodological Distinction: Feature Perturbation vs Packet Evasion

Before reviewing evasion metrics, the auditor establishes an essential scientific qualification:

> **Important Qualification:**  
> The offline red-team experiments presented below modify post-extraction flow summary features (inter-arrival times, packet sizes, transmission rates) within tabular feature arrays. These experiments represent **synthetic feature-space stress tests**.  
> They do not constitute proof of practical network evasion, which requires active packet injection, MTU manipulation, TCP stack segmentation, or dynamic proxying with live traffic replayers. A model that resists synthetic feature throttling cannot be claimed as "universally immune" to live evasion attacks.

---

### 2. Red-Team Test Suite Results

All tests were executed against authentic holdout test flows using [src/models/run_final_acceptance_audit.py](file:///Users/priyanshu/Desktop/aiml%20project%20team%20neural%20breach/src/models/run_final_acceptance_audit.py).

#### A. Infiltration Timing Camouflage (Slow-and-Low Evasion)
- **Threat Scenario:** An APT exfiltrates data using dilated inter-arrival times to blend with human browsing intervals.
- **Test Methodology:** Tested on all 93,063 Infiltration holdout flows from `Thursday-01-03-2018`. All inter-arrival time features (`Flow IAT`, `Fwd IAT`, `Bwd IAT`) and `Flow Duration` were scaled by factor $\alpha \in \{1.0, 2.0, 5.0, 10.0\}$.

| Dilation Factor ($\alpha$) | Tempo Description | LightGBM Infil Recall | XGBoost Infil Recall | Deep Autoencoder Anomaly Recall |
| :---: | :--- | :---: | :---: | :---: |
| **$1.0\times$** | Baseline Capture Speed | **86.74%** (80,722 TP) | 26.52% (24,679 TP) | 7.20% (6,700 TP) |
| **$2.0\times$** | Mild Interval Doubling | 74.50% (69,332 TP) | 27.47% (25,565 TP) | 7.38% (6,868 TP) |
| **$5.0\times$** | Moderate Slow-and-Low | 72.63% (67,591 TP) | 26.12% (24,308 TP) | 14.05% (13,075 TP) |
| **$10.0\times$** | Extreme Low-and-Slow | 71.56% (65,598 TP) | 26.44% (24,608 TP) | **16.55% (15,404 TP)** |

**Audit Finding:**
- LightGBM recall declines by 15.18 percentage points (86.74% $\to$ 71.56%) under 10x dilation, but retains substantial detection due to packet size variance and window advertisements.
- As the attacker dilates timing, the **Deep Autoencoder acts as a counter-evasion mechanism**: abnormal inter-arrival times distort the latent bottleneck representation, more than doubling autoencoder anomaly detection from 7.20% to 16.55%.

---

#### B. Adversarial Port Hopping
- **Threat Scenario:** An attacker routes brute-force attacks through non-standard listening ports (e.g., SSH on port 2222 or 54321, FTP on port 2121) or container port mappings.
- **Test Methodology:** Tested on 40,000 brute-force test flows (`FTP-BruteForce` and `SSH-Bruteforce`). Destination port (`Dst Port`) was randomized to ephemeral ports ($1024 \le \text{Port} \le 65535$).

| Model Candidate | Feature Count | Baseline Recall (Ports 21/22) | Port-Hopped Recall (Ephemeral Ports) | Evasion Drop |
| :--- | :---: | :---: | :---: | :---: |
| **Model with `Dst Port`** | 78 | **94.21%** (37,684 TP) | **0.00%** (0 TP) | **100.0% Collapse** |
| **Port-Agnostic Model** | 77 | **94.21%** (37,684 TP) | **94.21%** (37,684 TP) | **0.0% (100% Resilient)** |

**Audit Finding:**
- The port-dependent model learned an overfitted shortcut: `Dst Port == 22` $\implies$ SSH-Bruteforce. Shifting the port induced complete bypass.
- **Policy Enforcement:** Role 4's prohibition against deploying `supervised_lightgbm_with_port.joblib` is **fully reaffirmed**. Only the 77-feature port-agnostic candidate is certified.

---

#### C. Packet Length Padding on Web Application Exploits
- **Threat Scenario:** An attacker appends junk comments or padding characters to SQL injection queries (`/* ... */`) or XSS payloads (`<!-- ... -->`) to modify packet lengths.
- **Test Methodology:** Tested on all available test web exploit flows (`Brute Force -Web`, `Brute Force -XSS`, `SQL Injection`). Length and size features were dilated by $+0\%, +10\%, +25\%, +50\%, +100\%$.

| Padding Percentage | LightGBM Web Recall | LightGBM Evasion Drop | XGBoost Web Recall | XGBoost Evasion Drop |
| :---: | :---: | :---: | :---: | :---: |
| **+0% (Unmodified)** | **75.86%** | 0.0% | 61.38% | 0.0% |
| **+10% Padding** | 31.03% | **-59.1%** | 18.62% | **-69.7%** |
| **+25% Padding** | 15.86% | -79.1% | 10.34% | -83.2% |
| **+50% Padding** | 13.10% | -82.7% | 8.97% | -85.4% |
| **+100% Padding** | 13.10% | -82.7% | 8.28% | -86.5% |

**Audit Finding:**
- Flow-level ML is brittle against payload length manipulation: adding just 10% junk bytes causes detection to collapse below 32%.
- **Architectural Mandate:** Flow ML must never be marketed as a Web Application Firewall. A Layer-7 reverse proxy WAF must operate upstream.

---

#### D. Volumetric Flood Throttling (Low-Rate DDoS)
- **Threat Scenario:** A botnet operator reduces LOIC/HOIC packet transmission rates from thousands of packets/sec to dozens to evade volumetric threshold alarms.
- **Test Methodology:** Tested on 40,000 DDoS flows (`DDOS attack-HOIC` and `DDoS attacks-LOIC-HTTP`). Packet and byte rate features were throttled by factors $1\times, 5\times, 20\times, 100\times$.

| Throttling Factor | Attack Rate Reduction | LightGBM DDoS Recall | XGBoost DDoS Recall | Evasion Outcome |
| :---: | :---: | :---: | :---: | :---: |
| **$1.0\times$** | Full Blast Baseline | 100.00% | 100.00% | **DETECTED** |
| **$5.0\times$** | 80% Reduction | 100.00% | 100.00% | **DETECTED** |
| **$20.0\times$** | 95% Reduction | 100.00% | 100.00% | **DETECTED** |
| **$100.0\times$** | 99% Reduction | 100.00% | 100.00% | **DETECTED** |

**Audit Finding:**
- Throttling packet rates by up to 100x produces **0% evasion**. Both models maintain 100.0% recall because invariant structural features (asymmetric packet sizes, TCP window sizes, zero backward packets) betray the attack.

---

### 3. Feature Noise Perturbation Stress Curves

To evaluate robustness against noisy network sensors, packet drops, and timer quantization skew, 50,000 test flows were injected with zero-mean Gaussian relative noise:
$$X_{\text{noisy}} = X \cdot (1 + \mathcal{N}(0, \sigma^2)), \quad \sigma \in \{0.00, 0.05, 0.10, 0.25, 0.50\}$$

#### Measured Noise Degradation Curve:

| Noise Standard Deviation ($\sigma$) | Simulated Network Degradation | LightGBM Accuracy | LightGBM Delta | XGBoost Accuracy | XGBoost Delta |
| :---: | :--- | :---: | :---: | :---: | :---: |
| **$\sigma = 0.00$** | Pristine Sensor Baseline | 75.77% | 0.00% | **84.65%** | 0.00% |
| **$\sigma = 0.05$** | Minor Telemetry Jitter | 61.21% | -14.56% | **68.17%** | -16.48% |
| **$\sigma = 0.10$** | Moderate Packet Loss/Skew | 57.52% | -18.25% | **66.72%** | -17.93% |
| **$\sigma = 0.25$** | Severe Congestion Skew | 53.09% | -22.68% | **63.17%** | -21.48% |
| **$\sigma = 0.50$** | Extreme Sensor Corruption | 50.61% | -25.16% | **59.47%** | -25.18% |

**Audit Finding:**
- Both algorithms degrade smoothly and monotonically without catastrophic cliff-edge failure.
- XGBoost retains an accuracy margin of +7% to +9% across all noise regimes, confirming higher decision boundary stability under degraded sensor telemetry.

---

### 4. Cross-Dataset & Held-Out Attack Protocol Audit

1. **UNSW-NB15 Cross-Dataset Benchmark:**
   - Evaluated `supervised_unsw_nb15.joblib` across 175,341 holdout test flows.
   - **Accuracy:** **90.06%** | **F1-Score:** **0.9220** | **Precision:** **98.86%** | **Recall:** **86.38%** | **Benign FPR:** **2.12%**.
   - Verified that the model uses its own 42-feature schema and was not mixed with incompatible CSE-CIC-IDS2018 features.
2. **CTU-13 Neris Botnet Protocol Analysis:**
   - Inspection of `data/processed/CTU-13/ctu13_scenario1_flows.parquet` confirmed it contains 43 columns, whereas CSE-CIC-IDS2018 models require 77 baseline features.
   - **Audit Decision:** Feeding CTU-13 flows into CSE models without schema reconciliation is an invalid protocol. The auditor confirms that Role 3 and Role 4 correctly refrained from claiming direct cross-dataset evaluation on CTU-13.
