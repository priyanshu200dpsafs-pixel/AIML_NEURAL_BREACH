# TEAM NEURAL BREACH — ROLE 4: RED-TEAM TEST RESULTS
## Adversarial Evasion, Perturbation Stress & Edge-Case Probing Suite

**Project:** AI/ML-Based Cyber Defense Platform  
**Team:** Neural Breach  
**Role:** Cybersecurity Validation Engineer & Red-Team Specialist (Role 4)  
**Branch:** `role4-redteam-validation`  
**Execution Date:** October 25, 2026  
**Target Candidates:** Role 3 Retrain V2 Frozen Models  
**Test Suite Script:** `src/models/role4_redteam_eval.py`  

---

### Executive Red-Team Summary

To determine how our detection architecture behaves under deliberate adversarial pressure, Role 4 executed five controlled offline red-team evasion experiments and two system stress tests. Adversaries do not send static attack templates; they dynamically evade detection via **timing dilation, port hopping, packet padding, volumetric throttling, and sensor noise**.

**Key Red-Team Takeaways:**
1. **Port Hopping Destroys Port-Dependent Models:** A model relying on `Dst Port` suffers a **99.997% evasion drop** when an attacker moves SSH/FTP brute force to non-standard ports. The 77-feature port-agnostic model is **100% resilient**.
2. **Timing Camouflage Degrades Tree Recall:** Dilating inter-arrival times by 10x drops LightGBM Infiltration recall from 86.74% down to 71.56% (26,195 missed flows). However, the Deep Autoencoder anomaly recall increases from 7.20% to 16.55% as abnormal timing distorts the reconstruction profile.
3. **Payload Padding Bypasses Web Exploit Classifiers:** Adding just 10% packet length padding degrades LightGBM Web exploit recall from 65.38% down to 38.46%. Web attacks in network flow data are fragile and easily camouflaged.
4. **Volumetric DDoS Throttling Fails to Evade:** Throttling DDoS packet rates by up to 100x fails to evade both LightGBM and XGBoost (100.0% recall maintained) because flow directionality, flag patterns, and window statistics remain distinct.
5. **High-Throughput Streaming Stress:** Under multi-threaded stress on Apple Silicon, XGBoost sustains **561,291 flows/second** (1.78 µs/flow at batch 4096), while LightGBM achieves **50,941 flows/second** (19.63 µs/flow).

---

### Red-Team Scenario 1: Infiltration Timing Dilation (Low-and-Slow Attack)

#### Threat Model:
An Advanced Persistent Threat (APT) actor compromises an internal endpoint and performs reconnaissance and data exfiltration. Aware of flow-based anomaly detection, the attacker artificially dilates packet inter-arrival times (IAT) and flow durations by 2x, 5x, and 10x to blend into normal human browsing intervals.

#### Test Execution:
Tested on 93,063 authentic Infiltration test flows from `Thursday-01-03-2018` and `Wednesday-28-02-2018`. All IAT features (`Flow IAT Mean/Max/Min/Std`, `Fwd IAT`, `Bwd IAT`) and `Flow Duration` were scaled by factor $\alpha \in \{1.0, 2.0, 5.0, 10.0\}$.

#### Empirical Results:

| Dilation Factor | Attack Tempo | LightGBM Infil Recall | LightGBM Missed as Benign | XGBoost Infil Recall | XGBoost Missed as Benign | Autoencoder Anomaly Recall |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1.0x** | Baseline (Standard) | **86.74%** | 12,249 | 26.52% | 68,257 | 7.20% |
| **2.0x** | Mild Dilation | 74.50% | 23,551 | 27.47% | 67,306 | 7.38% |
| **5.0x** | Moderate Low-and-Slow | 72.63% | 25,147 | 26.12% | 68,126 | 14.05% |
| **10.0x** | Extreme Low-and-Slow | 71.56% | 26,195 | 26.44% | 67,761 | **16.55%** |

#### Red-Team Finding:
- LightGBM suffers an initial 12.2 percentage point drop when IATs double (86.74% -> 74.50%), but stabilizes above 71% even under 10x dilation. It remains sensitive to non-temporal features (packet length variance, TCP header flags, sub-flow volume).
- XGBoost is unaffected by timing dilation only because its baseline recall is already abysmal (26.52%), misclassifying over 67,000 flows as Benign regardless of timing.
- The **Deep Autoencoder** acts as a counter-evasion mechanism: as the attacker elongates IATs beyond typical benign norms, autoencoder reconstruction error rises, doubling anomaly detection from 7.20% to 16.55%.

---

### Red-Team Scenario 2: Port-Hopping Adversarial Evasion

#### Threat Model:
An attacker conducts distributed brute-force attacks against SSH and FTP services. Rather than targeting default ports 22 and 21, the attacker targets services bound to non-standard or ephemeral ports (e.g., SSH on port 2222 or 54321, FTP on port 2121) or uses network address translation (NAT) port forwarding.

#### Test Execution:
Tested on 40,000 authentic brute force flows (`FTP-BruteForce` and `SSH-Bruteforce`). The destination port `Dst Port` was randomized to ephemeral port ranges ($1024 \le \text{Port} \le 65535$).

#### Empirical Results:

| Model Architecture | Baseline Recall (Port 21 / 22) | Port-Hopped Recall (Ephemeral Ports) | Evasion Success Rate | Resilience Status |
| :--- | :---: | :---: | :---: | :---: |
| **Port-Dependent Model** (78 feats with `Dst Port`) | 94.21% | **0.0025% (1 flow)** | **99.997%** | **CATASTROPHIC FAILURE** |
| **Port-Agnostic Model** (77 features without `Dst Port`) | **94.21%** | **94.21% (37,684 flows)** | **0.000%** | **100% IMMUNE** |

#### Red-Team Finding:
- The port-dependent model learned an overfitted shortcut: `Dst Port == 21` $\implies$ FTP-BruteForce, and `Dst Port == 22` $\implies$ SSH-Bruteforce. When the attacker shifted ports, the model misclassified virtually 100% of brute-force attacks as Benign.
- The port-agnostic model relies on behavioral signatures (consecutive small packet exchanges, zero-byte ACKs, rapid session terminations), rendering it completely immune to port hopping.
- **Architectural Policy:** Role 4 strictly mandates that `supervised_lightgbm_with_port.joblib` must NOT be deployed in production. Only the 77-feature port-agnostic model is certified.

---

### Red-Team Scenario 3: Packet Length Padding on Web Exploits

#### Threat Model:
A web attacker attempts Cross-Site Scripting (XSS) and SQL Injection against internal web APIs. Aware that ML flow meters compute packet length statistics, the attacker injects junk comments (`/* ... */` in SQL, HTML comments `<!-- ... -->` in XSS) to alter packet sizes and flow byte averages.

#### Test Execution:
Tested on authentic test web attacks (`Brute Force -Web`, `Brute Force -XSS`, `SQL Injection`). All packet length and byte rate features (`Pkt Len Max/Mean/Std`, `Flow Byts/s`, `Bwd Seg Size Avg`) were dilated by $+0\%, +10\%, +25\%, +50\%, +100\%$.

#### Empirical Results:

| Packet Padding Percentage | LightGBM Web Recall | LightGBM Evasion Drop | XGBoost Web Recall | XGBoost Evasion Drop |
| :---: | :---: | :---: | :---: | :---: |
| **+0% (Unmodified)** | **65.38%** | 0.0% | 34.62% | 0.0% |
| **+10% Padding** | 38.46% | **-41.2%** | 34.62% | 0.0% |
| **+25% Padding** | 34.62% | -47.1% | 28.85% | -16.7% |
| **+50% Padding** | 32.69% | -50.0% | 25.00% | -27.8% |
| **+100% Padding** | 32.69% | -50.0% | 23.08% | -33.3% |

#### Red-Team Finding:
- LightGBM is highly vulnerable to small packet padding: adding just 10% payload causes recall to collapse by 26.9 percentage points (from 65.38% down to 38.46%).
- XGBoost has weak initial detection (34.62%), but degrades more gradually under heavy padding.
- **Defensive Requirement:** Flow-based ML must never be the sole defense against application-layer exploits. Web application firewalls (WAF) performing HTTP URI and body inspection must operate in front of the ML triage pipeline.

---

### Red-Team Scenario 4: Volumetric Flood Throttling (Low-Rate DDoS)

#### Threat Model:
A botnet operator seeks to evade volumetric rate limiters and threshold detectors by pacing LOIC (Low Orbit Ion Cannon) and HOIC (High Orbit Ion Cannon) flood packets, reducing packet transmission rates from thousands of packets/sec to dozens.

#### Test Execution:
Tested on 40,000 DDoS flows (`DDOS attack-HOIC` and `DDoS attacks-LOIC-HTTP`). Packet and byte rate features (`Flow Pkts/s`, `Flow Byts/s`, `Bwd Pkts/s`) were throttled by $1\times, 5\times, 20\times, 100\times$.

#### Empirical Results:

| Throttle Factor | Attack Rate Reduction | LightGBM DDoS Recall | XGBoost DDoS Recall | Evasion Outcome |
| :---: | :---: | :---: | :---: | :---: |
| **1.0x** | Full Volumetric Blast | 100.00% | 99.9975% | DETECTED |
| **5.0x** | 80% Reduction | 100.00% | 99.9975% | DETECTED |
| **20.0x** | 95% Reduction | 100.00% | 99.9975% | DETECTED |
| **100.0x** | 99% Reduction | 100.00% | 99.9975% | DETECTED |

#### Red-Team Finding:
- **Total Evasion Failure:** Throttling packet rates by up to 100x produces **0% evasion**. Both LightGBM and XGBoost maintain $\ge 99.9975\%$ recall.
- **Why?** The models do not rely solely on raw packet rates. They recognize structural signatures: identical TCP window advertisements, invariant packet header lengths, lack of bidirectional handshakes, and abnormal push flag distributions. Throttling frequency does not mask structural asymmetry.

---

### Red-Team Scenario 5: Anomaly Plateau Probing (Isolation Forest Ties)

#### Test Execution:
Role 3 identified that 1,196 validation benign flows share the exact decision function score $-0.13326530124088404$. Role 4 tested whether subtle adversarial noise or natural network jitter shifts flows across this threshold boundary.
- Tested on 20,000 sampled benign validation flows.
- Baseline: 111 flows (0.56%) sit precisely at $-0.13326530$.
- Injected micro-noise: Gaussian perturbation with $\sigma = 10^{-4}$ added to all features.

#### Empirical Results:
- Original flows on tie plateau: **111 flows (0.56%)**
- Perturbed flows on tie plateau: **111 flows (0.56%)**
- Decision Score Delta: $\Delta \le 1.4 \times 10^{-6}$.
- **Finding:** The plateau is an intrinsic mathematical consequence of tree-based axis-aligned splits on discrete packet/byte counters. The fix implemented in Role 3 (`iso_scores <= threshold`) ensures that flows on this plateau are handled deterministically without operator flipping.

---

### Robustness Test 1: Feature Noise Degradation Stress

#### Methodology:
Network telemetry captured by hardware taps and routers frequently suffers from packet drops, timer quantization errors, and counter jitter. To measure degradation stability, 50,000 holdout test flows were stressed with zero-mean Gaussian relative noise:
$$X_{\text{noisy}} = X \cdot (1 + \mathcal{N}(0, \sigma^2)), \quad \sigma \in \{0.00, 0.05, 0.10, 0.25\}$$

#### Results:

| Noise Level ($\sigma$) | Simulated Network Degradation | LightGBM Accuracy | LightGBM Degradation | XGBoost Accuracy | XGBoost Degradation |
| :---: | :--- | :---: | :---: | :---: | :---: |
| **0%** | Pristine Sensor Baseline | 75.77% | 0.0% | **84.65%** | 0.0% |
| **5%** | Minor Telemetry Jitter | 61.22% | -14.55% | **68.21%** | -16.44% |
| **10%** | Moderate Packet Loss/Skew | 57.31% | -18.46% | **66.62%** | -18.03% |
| **25%** | Severe Network Congestion | 53.23% | -22.54% | **62.93%** | -21.72% |

#### Robustness Finding:
- Both models degrade smoothly and monotonically without catastrophic cliff-edge collapses.
- XGBoost consistently retains a +7.0% to +9.7% accuracy advantage under severe noise, indicating higher decision-boundary stability against noisy network features.

---

### Robustness Test 2: High-Load Inference Latency & Throughput Scaling

#### Methodology:
To measure inference latency and throughput under production SOC conditions, benchmarks were executed on Apple Silicon (M4, multi-threaded) across batch sizes from $b=1$ (single-flow real-time packet inspection) up to $b=4096$ (streaming telemetry pipeline).

#### Measured Performance:

| Batch Size ($b$) | LightGBM Latency | LightGBM Throughput | XGBoost Latency | XGBoost Throughput | Throughput Ratio (XGB / LGB) |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **1 flow** | 411.90 µs/flow | 2,428 flows/sec | **227.03 µs/flow** | **4,405 flows/sec** | 1.81x faster |
| **16 flows** | 98.89 µs/flow | 10,113 flows/sec | **23.10 µs/flow** | **43,290 flows/sec** | 4.28x faster |
| **64 flows** | 57.84 µs/flow | 17,290 flows/sec | **12.49 µs/flow** | **80,067 flows/sec** | 4.63x faster |
| **256 flows** | 31.02 µs/flow | 32,240 flows/sec | **4.47 µs/flow** | **223,812 flows/sec** | 6.94x faster |
| **1,024 flows** | 23.87 µs/flow | 41,900 flows/sec | **2.24 µs/flow** | **446,751 flows/sec** | **10.66x faster** |
| **4,096 flows** | 19.63 µs/flow | 50,941 flows/sec | **1.78 µs/flow** | **561,291 flows/sec** | **11.02x faster** |

#### Latency Analysis:
- For single-flow unamortized calls ($b=1$), XGBoost requires 227 µs and LightGBM requires 412 µs.
- When batched ($b \ge 256$), XGBoost's histogram-based C++ execution achieves massive multi-core parallelism, dropping amortized latency to **1.78 microseconds per flow** (exceeding half a million flows/second).
- This establishes XGBoost as the only candidate capable of sustaining 10Gbps+ backbone interface streaming without dropping flow buffers.

---

### Summary of Red-Team Attack Resilience

| Attack Vector | Simulated Evasion Method | Model Tested | Vulnerability Level | Operational Countermeasure |
| :--- | :--- | :--- | :---: | :--- |
| **Timing Dilation** | Low-and-slow IAT dilation (10x) | LightGBM | **MEDIUM** (Recall 86.7% -> 71.6%) | Complement with Autoencoder anomaly detection |
| **Port Hopping** | Shift services to ephemeral ports | LightGBM (with Port) | **CRITICAL** (99.997% Evasion) | **BAN** port features; use 77-feature port-agnostic model |
| **Packet Padding** | +10% to +100% junk payload padding | LightGBM & XGBoost | **HIGH** (Recall drops to 32.7%) | Mandatory Layer 7 WAF payload inspection |
| **Volumetric Throttling** | 100x packet rate reduction | LightGBM & XGBoost | **NEGLIGIBLE** (100% Recall retained) | Invariant flow asymmetry signatures defeat throttling |
| **Telemetry Noise** | Up to 25% Gaussian noise injection | LightGBM & XGBoost | **LOW** (Smooth monotonic drop) | Robustness verified; XGBoost exhibits +9.7% advantage |
