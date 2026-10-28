# TEAM NEURAL BREACH — THRESHOLD & INFERENCE AUDIT REPORT
## Mathematical Reconciliation, Operating Point Calibration & 100% Full-Dataset Parity

**Project:** AI/ML-Based Cyber Defense Platform  
**Team:** Neural Breach  
**Auditor:** Independent Senior ML Engineer & Cybersecurity Red-Team Auditor  
**Audit Date:** October 28, 2026  
**Status:** COMPLETE — INDEPENDENTLY RECONCILED  

---

### 1. LightGBM Threshold (0.6720) Conflict Reconciliation

A primary focus of this audit was investigating the substantial conflict between prior reports regarding the LightGBM `0.6720` probability operating point:
- **Prior Report 1 (Role 3 Release Gate):** Benign FPR = **8.71%** (26,143 FP), Attack Recall = **81.11%**.
- **Prior Report 2 (Role 4 Evaluation Report):** Benign FPR = **45.17%** (135,496 FP), Attack Recall = **97.77%**.

#### Mathematical Investigation & Root-Cause Discovery:
The auditor inspected both evaluation scripts and recomputed predictions directly on the full 541,345 holdout test flows under both mathematical implementations:

```
[Formulation 1: P(Attack) >= 0.6720 — The Intended Conservative Policy]
Implementation:
  p_attack = 1.0 - probs[:, benign_idx]
  predict_attack = (p_attack >= 0.6720)
Result:
  Benign FPR:         8.71% (26,143 False Positives out of 300,000)
  Total Attack Recall: 81.11% (195,744 / 241,345 detected; 45,601 missed)
  Infiltration Recall: 50.96% (47,427 / 93,063 detected)

[Formulation 2: P(Benign) >= 0.6720 — The Inverted Semantic in Role 4 Evaluation]
Implementation (from src/models/role4_redteam_eval.py, Line 172):
  is_benign_pred = (probs[:, benign_idx] >= 0.6720)
  predict_attack = (~is_benign_pred)
Result:
  Benign FPR:         45.17% (135,496 False Positives out of 300,000)
  Total Attack Recall: 97.77% (235,956 / 241,345 detected; 5,389 missed)
  Infiltration Recall: 94.14% (87,607 / 93,063 detected)
```

#### Forensic Explanation:
- In Formulation 2, checking whether $P(\text{Benign}) \ge 0.6720$ to predict Benign is mathematically identical to declaring an attack whenever $P(\text{Attack}) > 1.0 - 0.6720 = 0.3280$.
- A threshold of $0.3280$ is an **extremely sensitive attack detector**. It partitions ambiguous flow regions into attacks, inflating false alarms by 109,353 flows (from 8.71% to 45.17%).
- **Audit Verdict:** The discrepancy is **100% resolved**. Formulation 1 is the intended threshold design. Role 6 must implement Formulation 1 ($P(\text{Attack}) \ge 0.6720$) when deploying LightGBM.

---

### 2. XGBoost Automated Blocking Threshold (0.85) Audit

To verify whether XGBoost can be safely deployed for automated inline packet dropping, the auditor measured its operating characteristics across both the validation set (313,269 flows) and the holdout test set (541,345 flows):

```
Decision Rule: If P(Attack) >= 0.85, Block Inline; Else Pass Through
```

#### Measured Operating Characteristics:

| Metric | Validation Set (313,269 flows) | Holdout Test Set (541,345 flows) | Verdict |
| :--- | :---: | :---: | :---: |
| **Benign Support** | 200,000 flows | 300,000 flows | Authentic Partition |
| **Benign False Positives** | **196 false alarms** | **115 false alarms** | **< 0.04% Error Rate** |
| **Benign FPR** | **0.098%** | **0.038%** | **PASS** |
| **Inline Precision** | **99.79%** | **99.92%** | **PASS** |
| **Attack Recall** | 60.84% | 61.56% | 148,575 Attacks Blocked |
| **Missed Attacks (Passed)** | 44,357 flows | 92,770 flows | Handled by Tier 2 |

#### Per-Class Attack Breakdown at Threshold 0.85:
- **100% Blocked Attacks:** `DDOS attack-HOIC` (20,000/20,000), `DDoS attacks-LOIC-HTTP` (20,000/20,000), `DoS attacks-Hulk` (20,000/20,000), `SSH-Bruteforce` (19,997/20,000), `Bot` (19,890/20,000).
- **Partially Blocked Attacks:** `FTP-BruteForce` (17,490/20,000; 87.45%), `DoS attacks-GoldenEye` (6,218/6,227; 99.85%), `DoS attacks-Slowloris` (1,624/1,650; 98.42%).
- **Bypassed Stealth Attacks:** `Infiltration` (only 13,010/93,063 blocked; 86.02% passed to Tier 2), `DoS attacks-SlowHTTPTest` (10,332/20,000 blocked).

**Finding:** The claim that XGBoost threshold 0.85 operates with $< 1.02\%$ false alarms is **conservative and verified**: the actual false alarm rate on holdout test traffic is **0.038%** (115 false alarms out of 300,000 benign operations), operating with **99.92% precision**.

---

### 3. Isolation Forest Threshold & Tie Plateau Audit

#### A. Score Direction & Operator Parity:
In scikit-learn's `IsolationForest.decision_function(X)`, lower scores represent more anomalous flows.
- Prior to Role 3 Retrain V2, the codebase contained an operator discrepancy where calibration used `<=` but deployed inference used `<`.
- In `src/models/inference_engine.py` line 198, the operator was corrected to:
  $$\text{iso\_alerts} = (\text{iso\_scores} \le \text{self.iso\_threshold})$$

#### B. Discrete Tie Plateau Forensics:
- Exactly **1,214 flows** in the validation set and **24 flows** in the test set share the exact decision score $-0.13326530124088404$.
- Because multiple zero-byte and standard TCP SYN flows have identical feature values, they traverse identical paths through all 150 random trees, accumulating identical average path lengths.
- The `<=` operator ensures that flows sitting on this tie plateau are evaluated deterministically without operator boundary flipping.

#### C. Operational Calibration Budgets:
- **1% FPR Budget ($\tau = -0.08063$):** Validation Benign FPR = 1.00% (2,000 FP / 200k), Test Benign FPR = 0.22% (660 FP / 300k).
- **5% FPR Budget ($\tau = -0.01779$):** Validation Benign FPR = 5.00%, Test Benign FPR = 1.84%.

---

### 4. Deep Autoencoder Reconstruction Threshold Audit

#### A. Architecture & Training Provenance:
- **Architecture:** PyTorch Linear bottleneck network ($77 \to 48 \to 24 \to 12 \to 24 \to 48 \to 77$), Batch Normalization, LeakyReLU ($0.1$).
- **Training Provenance:** Fitted exclusively on the 800,000 benign training flows for 10 epochs using Adam optimizer and MSE reconstruction loss.

#### B. Threshold Calibration on Validation Benign Flows:
Reconstruction error for a flow $x$ is defined as the mean squared error (MSE):
$$\text{MSE}(x) = \frac{1}{D} \sum_{j=1}^{D} (x_j - \hat{x}_j)^2$$
- **1% FPR Budget ($\tau = 1.29126$):** Validation Benign FPR = 3.16%, Test Benign FPR = 0.42% (1,260 FP / 300,000 flows).
- **5% FPR Budget ($\tau = 0.24448$):** Test Benign FPR = 4.88%.

---

### 5. 100% Full-Dataset Inference Parity Verification

To verify that the deployed `CyberDefenseInferenceEngine` exhibits bit-for-bit equivalence with raw scikit-learn and PyTorch model predictions, the auditor streamed **all 541,345 holdout test flows** through the production engine in 28 batches of 20,000 flows.

#### Empirical Parity Audit Results:

| Component Verified | Comparison Standard | Flows Evaluated | Mismatches Detected | Parity Verdict |
| :--- | :--- | :---: | :---: | :---: |
| **LightGBM Classifier** | Raw `lgb_primary.predict_proba()` | 541,345 | **0** | **100.0% PARITY** |
| **XGBoost Classifier** | Raw `xgb_bench.predict_proba()` | 541,345 | **0** | **100.0% PARITY** |
| **Isolation Forest Alert** | Raw `decision_function() <= -0.08063` | 541,345 | **0** | **100.0% PARITY** |
| **Autoencoder Alert** | Raw PyTorch `MSE >= 1.29126` | 541,345 | **0** | **100.0% PARITY** |
| **Empty DataFrame Input** | Rejection or safe empty return | 0 rows | **0 (Returns `[]`)** | **PASS** |

**Parity Duration:** Streaming and evaluating all 541,345 test flows through the dual-classifier, dual-anomaly inference pipeline completed in **26.94 seconds** on Apple Silicon (M-Series).
