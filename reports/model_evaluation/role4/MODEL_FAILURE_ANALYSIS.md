# TEAM NEURAL BREACH — ROLE 4: MODEL FAILURE ANALYSIS
## Root-Cause Taxonomy, Feature Limitations & Dataset Pathology Forensics

**Project:** AI/ML-Based Cyber Defense Platform  
**Team:** Neural Breach  
**Role:** Cybersecurity Validation Engineer & Red-Team Specialist (Role 4)  
**Branch:** `role4-redteam-validation`  
**Execution Date:** October 25, 2026  
**Status:** COMPLETE — HONEST & EVIDENCE-BASED  

---

### Executive Failure Summary

A key directive for Role 4 is **strict honesty**: separate genuine model limitations from implementation bugs, data issues, and evaluation errors. We do not claim universal production readiness without empirical justification.

Our forensic investigation reveals that model failures in the Neural Breach platform fall into four distinct categories:
1. **Statistical Indistinguishability (Genuine Model Boundary):** Low-and-slow infiltration and stealth attacks occupy the exact same statistical distribution in 77 flow summary dimensions as legitimate enterprise background traffic.
2. **Extreme Class Scarcity (Dataset Pathology):** Certain attack categories (SQL Injection: 15 test flows; Brute Force -XSS: 37 test flows) lack the mathematical support necessary for tree-based estimators to learn generalized boundaries.
3. **Information Loss in Flow Extraction (Representation Deficit):** Summarizing bidirectional network flows into aggregate statistical moments (mean, std, min, max) completely strips packet payloads, HTTP verb semantics, query strings, and TLS handshake ciphers.
4. **Operating Point Polarization (Decision Threshold Conflict):** Adjusting thresholds to suppress false alarms to tolerable enterprise levels ($< 2\%$) mechanically suppresses sensitivity to low-amplitude attack signatures.

---

### Failure Category 1: The Infiltration Dilemma

#### Forensic Data:
- Total Infiltration Test Flows: **93,063**
- LightGBM: 80,722 Detected (86.74%), **12,249 Missed as Benign**, 92 Misclassified as other attacks. Benign False Positives: **107,598 (35.87% FPR)**.
- XGBoost: 24,679 Detected (26.52%), **68,257 Missed as Benign (73.35%)**. Benign False Positives: **3,058 (1.02% FPR)**.
- Random Forest: 10,419 Detected (11.20%), **82,373 Missed as Benign (88.51%)**. Benign False Positives: **2,343 (0.78% FPR)**.

```
+-----------------------------------------------------------------------------------+
|                        THE INFILTRATION DETECTION TRADEOFF                        |
+-----------------------------------------------------------------------------------+
| Model       | Infiltration Recall | Benign False Positives | Benign FPR | Verdict |
| :---        | :---:               | :---:                  | :---:      | :---    |
| LightGBM    | 86.74% (80,722/93k) | 107,598 FP             | 35.87%     | Too Noisy for Inline |
| XGBoost     | 26.52% (24,679/93k) |   3,058 FP             |  1.02%     | Misses 73% of Infil  |
| Random F.   | 11.20% (10,419/93k) |   2,343 FP             |  0.78%     | Misses 88% of Infil  |
+-----------------------------------------------------------------------------------+
```

#### Root-Cause Analysis:
1. **Loss Function Objective Differences:**
   - XGBoost minimizes multi-class log-loss across all samples uniformly. Because Benign flows represent the overwhelming majority, the optimizer penalizes false positives heavily, setting conservative decision boundaries that classify ambiguous flows into the majority class (Benign).
   - LightGBM was trained with `class_weight="balanced"`. This artificially amplifies the gradient penalty for minority classes, forcing trees to partition ambiguous regions in favor of Infiltration. The inevitable byproduct is massive false-positive inflation on Benign traffic.
2. **Feature Overlap:**
   - Infiltration traffic in CSE-CIC-IDS2018 consists of an attacker executing Nmap discovery, Metasploit payloads, and Dropbox file exfiltration.
   - Once a foothold is established, C2 communication and exfiltration mimic normal HTTPS sessions (port 443, TLS encrypted, standard TCP window sizes, periodic beaconing indistinguishable from keep-alive polling).
   - In the absence of payload inspection, no tabular feature in the 77-dimensional vector cleanly separates a Dropbox exfiltration flow from an employee uploading files to Google Drive.

---

### Failure Category 2: Web Application Exploit Collapse

#### Forensic Data:
- `Brute Force -Web`: 93 test flows. LightGBM Recall: 81.72% (76/93). XGBoost Recall: 76.34% (71/93).
- `Brute Force -XSS`: 37 test flows. LightGBM Recall: 81.08% (30/37). XGBoost Recall: 43.24% (16/37).
- `SQL Injection`: 15 test flows. LightGBM Recall: 26.67% (4/15). XGBoost Recall: **13.33% (2/15)**.

#### Root-Cause Analysis:
1. **Critical Sample Scarcity:**
   - In the entire 1.32M training partition, there were only 427 Web Brute Force, 160 XSS, and 60 SQL Injection flows.
   - In 77-dimensional continuous feature space, 60 training samples cannot span the variance of HTTP traffic. Decision tree splits on `Init Fwd Win Byts` or `Flow Duration` overfit to the exact workstation IP and server configurations used during the benchmark generation day (`Thursday-22-02-2018`).
2. **Payload Blindness:**
   - A SQL injection attack (`' UNION SELECT password FROM users--`) differs from a benign web query by only 30-50 bytes inside the HTTP request body.
   - The flow statistics (`Flow Pkts/s`, `Tot Fwd Pkts`, `Pkt Len Mean`) of a 1-packet GET or POST request containing a SQL payload are mathematically identical to a user submitting an address form or search query.
   - **Verdict:** Flow-level network ML is fundamentally the wrong layer of abstraction for SQL injection and XSS defense. Deploying flow ML without an upstream WAF (Layer 7 reverse proxy) is an architectural failure.

---

### Failure Category 3: The DoS SlowHTTPTest ~52% Plateau

#### Forensic Data:
- Support: 20,000 flows.
- LightGBM: 10,392 Detected (51.96% Recall), 9,608 Missed as Benign.
- XGBoost: 10,448 Detected (52.24% Recall), 9,552 Missed as Benign.
- Random Forest: 10,452 Detected (52.26% Recall), 9,548 Missed as Benign.

#### Root-Cause Analysis:
- Notice that all three distinct algorithms (LightGBM, XGBoost, and Random Forest) plateau at an almost identical ~52% recall ceiling.
- **Why?** SlowHTTPTest functions by sending HTTP requests incomplete (e.g., sending header fields one by one every 10-15 seconds) to keep server sockets occupied until exhaustion.
- Flows captured by CICFlowMeter during this attack fall into two distinct operational regimes:
  1. **Active Sockets with Multiple Heartbeat Chunks:** These flows accumulate dozens of packets, resulting in abnormally high `Flow Duration` with low `Bwd Pkts/s`. All models detect 100% of these flows.
  2. **Prematurely Terminated or Idle Sockets:** Sockets closed early by the web server timeout (e.g. Apache `Timeout 20`) contain only 2-3 packets with normal TCP teardown flags (FIN/ACK). In aggregate tabular space, these flows are 100% indistinguishable from normal aborted user connections.
- The 48% missed flows are not a model error; they are a physical property of network socket timeouts.

---

### Failure Category 4: The Destination Port Shortcut

#### Forensic Data:
- Model with `Dst Port`: 76.26% Accuracy, 85.96% Infil Recall, 94.21% FTP/SSH Recall.
- Red-Team Port Hopping: Attacker randomizes `Dst Port` to ephemeral ports ($1024 - 65535$).
- Result: **Recall drops to 0.0025% (99.997% evasion)**.

#### Root-Cause Analysis:
- GBDT models greedily select features with the highest information gain during early splits.
- In synthetic or semi-synthetic benchmark datasets like CSE-CIC-IDS2018, attackers always target default server ports (Port 21 for FTP, Port 22 for SSH, Port 80 for HTTP).
- The model exploits this shortcut: if `Dst Port == 21`, predict `FTP-BruteForce`.
- In a real-world enterprise, modern adversaries route brute-force attacks through non-standard listening ports, Docker container port mappings, and SSH jump hosts.
- **Verdict:** Training on destination port creates a brittle, trivial-to-evade signature system masquerading as machine learning.

---

### Failure Category 5: Isolation Forest Score Tie Plateau

#### Forensic Data:
- 1,196 validation flows cluster at the exact score: $-0.13326530124088404$.
- 111 flows in our 20,000 holdout benign sample sit precisely on this score.
- Micro-jitter ($10^{-4}$) shifts individual flow paths across adjacent tree leaves.

#### Root-Cause Analysis:
- Isolation Forest computes anomaly scores as:
  $$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
  where $E(h(x))$ is the average path length across $T$ random trees.
- In network flow telemetry, thousands of benign flows are identical: e.g., zero-byte DNS queries, NTP time syncs, or standard TCP RST packets with zero bytes and standard header lengths.
- When identical feature vectors traverse the same ensemble of trees, every tree traverses the exact same branch, resulting in identical path lengths and discrete score clustering.
- **Implementation Impact:** Prior to Role 3's fix, using a strict inequality `<` caused borderline flows on this tie plateau to flip inconsistently. The updated operator `<=` ensures deterministic alerting across continuous score plateaus.

---

### Failure Taxonomy Matrix

| Failure Symptom | Observed Impact | Root Cause Category | Fix / Mitigation |
| :--- | :--- | :--- | :--- |
| **High Infiltration FPR (35.8%)** | 107,598 false alarms in LightGBM | Feature Overlap / Balanced Weight | Shift LightGBM to Tier-2 Threat Hunting; use XGBoost inline |
| **Infiltration Under-Detection (26.5%)** | 68,257 missed intrusions in XGBoost | Objective Function Optimization | Route unclassified suspicious flows to Deep Autoencoder |
| **Web Exploit Blindness (< 30% Recall)** | SQLi and XSS frequently missed | Extreme Data Scarcity & Payload Blindness | Enforce Layer 7 WAF; do not rely on flow ML for Web |
| **Port-Hopping Bypass (99.99% Evasion)** | Complete evasion on non-standard ports | Spurious Correlation / Shortcut Learning | **Permanently exclude** `Dst Port`; enforce 77-feature schema |
| **SlowHTTPTest 52% Plateau** | 9,600 flows missed across all models | Socket Timeout Distribution Ambiguity | Augment with web server access logs (HTTP status 408) |
| **Discrete Anomaly Tie Plateau** | 1,196 flows share identical score | Tree Path Quantization on Duplicate Flows | Verified `<=` operator parity in production engine |

---

### Final Honesty Statement for Role 6 and SOC Leadership

1. **Do not deploy a single monolithic model.** There is no configuration of LightGBM or XGBoost that achieves zero false positives while capturing stealthy infiltration attacks.
2. **Do not claim Web Application defense.** Our platform cannot reliably stop SQL injection or XSS from network flow headers alone.
3. **Do not deploy port-dependent models.** Models utilizing `Dst Port` are dangerous and will fail against basic adversarial port shifting.
4. **Deploy Defense-in-Depth:** Use **XGBoost for Tier-1 Inline Dropping** (1.02% FPR, 1.78 µs latency) and **LightGBM Primary + PyTorch Autoencoder for Tier-2 SOC Alerting & Threat Hunting** (86.74% Infiltration Recall).
