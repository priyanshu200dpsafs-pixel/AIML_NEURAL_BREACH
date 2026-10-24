# Role 3 to Role 4 Model Handoff Package

**Document**: Role 3 Master Implementation Handoff to Role 4 (QA, Evaluation & Validation Specialist)  
**Project**: AI/ML-Based Cyber Defense Platform  
**Team**: Neural Breach  
**Date**: 2026-10-24  
**Author**: Role 3 (Senior ML Engineer & Detection Specialist)  
**Status**: COMPLETE — READY WITH CAVEATS  

---

## 1. Handoff Objectives & Scope

This package formally transitions all verified, retrained machine learning detection models, scalers, encoders, and evaluation harnesses from **Role 3 (Model Engineering)** to **Role 4 (Model Evaluation, Red Teaming, and Quality Assurance)**.

All models in this handoff have been fitted exclusively on authentic collected benchmark datasets (`CSE-CIC-IDS2018_v2`, `UNSW-NB15`, and `CTU-13 Scenario 1`). Zero synthetic training records were permitted. All identified historical defects—including the 58.58% cross-day false positive rate, unscaled anomaly detection, and lack of port ablation evidence—have been systematically investigated, re-engineered, and empirically validated.

---

## 2. Model Artifacts Catalog & Integrity Manifest

All production artifacts reside in:
`models/role3_real_data/`

| Artifact Filename | Type | Size | SHA-256 Checksum | Purpose / Description |
| :--- | :---: | :---: | :---: | :--- |
| `supervised_xgboost_candidate.joblib` | Model | 2.50 MB | `b1e6281a2a60376a4ed69de0c77ea8f8a87a82fc99d236f17e36bb50a751dfd9` | **Recommended Supervised Candidate**: XGBoost 15-class classifier (77 features, 1.02% FPR). |
| `supervised_histgbt_baseline.joblib` | Model | 3.68 MB | `fd5eb25c53210468a217cfed654bd0cc35ecc9c01302ed6d38cfff909413371a` | **Supervised Baseline**: HistGradientBoosting (77 features, raw argmax & calibrated). |
| `supervised_histgbt_with_port.joblib` | Model | 4.11 MB | `537726e5671fce590d05348d52a385826feac6e7ae43d8424f8d975dbab5acd3` | **Port Ablation Model**: HistGradientBoosting with `Dst Port` (78 features). |
| `supervised_unsw_nb15.joblib` | Model | 417 KB | `8a4032a4040e9ba67f40d6f5a5df10bc0f923ad183e38c4ac8b5d69fec2820f8` | **Independent Benchmark**: Binary model on UNSW-NB15 (42 features, 90.0% accuracy). |
| `anomaly_deep_autoencoder.pt` | Model | 55 KB | `9da1b5fe0cdc0c9960a2846bfbf447e52539e4f3f20bf13a482237c1341c8b59` | **Deep Autoencoder**: PyTorch symmetric network ($77 \to 48 \to 24 \to 12 \to 24 \to 48 \to 77$). |
| `anomaly_isolation_forest.joblib` | Model | 2.66 MB | `10244f85f1d18a9e777a290c84a32824ed9aba0377729da7827dd61f6f24428b` | **Isolation Forest Baseline**: Scikit-Learn tree anomaly detector fitted on scaled benign flows. |
| `scaler_anomaly.joblib` | Preproc | 2.45 KB | `f99297e79d02a578aa1780d5185d7ab0a450405ba2f2692acb3f13b139008976` | `StandardScaler` fitted strictly on 800,000 pure Benign training flows. |
| `scaler_baseline.joblib` | Preproc | 2.45 KB | `06be7e35818621251318964d572769e4bfff1ee5230426eb50469f800b7399e9` | `StandardScaler` for the 77-feature supervised feature pipeline. |
| `scaler_with_port.joblib` | Preproc | 2.49 KB | `cedd8d7d9b28a41884cef42ef1a15317e89a31aee8906ec4eac0d0acebe5af61` | `StandardScaler` for the 78-feature port ablation pipeline. |
| `feature_columns_baseline.json` | Schema | 1.45 KB | `b08e4ae48bebb799ea1d6c0397bfb3a151b5f8928979244fdf69a9ffae992308` | Canonical list and exact column order of the 77 baseline features. |
| `feature_columns_with_port.json` | Schema | 1.46 KB | `fe36589ce33a64aa7a4eed643dcd0181469c0dc43e629943a0a6b79195b79046` | Canonical list and order of the 78 features (including `Dst Port`). |
| `label_mapping.json` | Mapping | 406 B | `94d0b01a52fffe623c08d6e725d5929849a55543d29386bf2ddcea6cfd95781f` | JSON dictionary mapping 15 integer class IDs to authentic string labels. |
| `label_encoder.joblib` | Mapping | 1.77 KB | `07b666fa14b6d20ae4b93df2ac142cb2a1a6614971ab049077de272bebf78846` | Scikit-Learn `LabelEncoder` object preserving bidirectional label mapping. |

---

## 3. Verified Benchmark Metrics Summary

### Track A: Supervised Classification (Untouched Test Partition: 541,345 Flows)
- **Primary XGBoost Candidate**:
  - Accuracy: **84.57%**
  - Macro-F1: **0.8168**
  - Weighted-F1: **0.8157**
  - Benign False Positive Rate (FPR): **1.02%** (3,058 / 300,000)
  - Attack False Negative Rate (FNR): **28.33%** (68,376 / 241,345)
  - Per-Flow Latency: **3.52 µs**
  - Throughput: **290,072 flows/sec**
- **HistGBT Baseline Comparison**:
  - Accuracy: 73.66%
  - Macro-F1: 0.7189
  - Benign FPR: 39.75% (119,259 / 300,000)
  - Attack FNR: 4.36% (10,516 / 241,345)

### Track B: Unsupervised Anomaly Detection (800,000 Benign Train / 541,345 Test)
- **PyTorch Deep Autoencoder**:
  - ROC-AUC: **0.7995** | PR-AUC: **0.7561**
  - Operational Threshold (1.0% FPR Budget): **MSE = 0.3384**
  - Actual Test FPR: **1.14%**
  - Overall Zero-Day Attack Recall: **4.52%**
  - High-Volume / Structural Anomaly Recall: **100.0%** on LOIC-UDP, **66.0%** on Slowloris, **43.2%** on Brute Force - XSS, **33.3%** on FTP-BruteForce
  - Inference Latency: **0.14 µs/flow**

### Track C: Independent UNSW-NB15 Benchmark (175,341 Test Flows)
- Accuracy: **90.00%** | Binary F1: **0.9215** | Attack Recall: **86.27%** | Benign FPR: **2.06%**

---

## 4. Key Failure Modes & Vulnerabilities Identified for Role 4

Role 4 is instructed to focus red-teaming and evaluation on the following empirical limitations:

### 1. The Infiltration Evasion Surface
- **Observed Behavior**: The XGBoost candidate achieves 89.36% precision on Infiltration but misses 73.48% of Infiltration flows (recall = 26.52%).
- **Cause**: To eliminate the massive 58.58% false-positive rate caused by background network timing drift between February and March, the model was regularized (`reg_lambda=2.0`). Subtle Nmap sweeps and Dropbox exfiltration flows that resemble benign web interactions are classified conservatively as Benign.
- **Role 4 Test**: Inject multi-stage port scanning and low-rate data transfers to measure exact detection boundaries.

### 2. Rare Web Exploitation Representation Limits
- **Observed Behavior**: In CSE-CIC-IDS2018, SQL Injection has only 15 test flows and XSS has only 37 test flows. Recall is 13.33% and 43.24% respectively.
- **Cause**: Lack of statistical variety in the benchmark dataset. Tree models cannot generalize across diverse SQL syntax or XSS payloads from 80 packet-header summary statistics.
- **Role 4 Test**: Evaluate adversarial web attack vectors and recommend application-layer WAF integration.

### 3. Port Ablation Sensitivity
- **Observed Behavior**: Including `Dst Port` yields +0.079 Macro-F1 improvement on standard services, but risks complete bypass if an adversary shifts traffic to non-standard ports (e.g., SSH over 443).
- **Role 4 Test**: Execute port-mutation red teaming (evaluating `supervised_histgbt_with_port.joblib` vs. `supervised_xgboost_candidate.joblib` when attack flows have their `Dst Port` modified to 8080, 8443, or ephemeral ports).

---

## 5. Recommended Red-Teaming & Stress Test Suite for Role 4

Role 4 should execute the following test battery against the inference engine:

1. **Adversarial Timing Jitter**:
   - Perturb `Flow IAT Mean`, `Flow IAT Std`, and `Flow Duration` by $\pm 15\%$, $\pm 30\%$, and $\pm 50\%$ using random uniform noise to determine if DoS/DDoS detection degrades.
2. **Packet Splitting & Padding**:
   - Artificially inflate `Fwd Pkt Len Min` and reduce `Fwd Pkt Len Max` to mimic MTU manipulation and fragmentation attacks.
3. **Extreme Imbalance Stress Testing**:
   - Construct an operational test stream where Benign flows represent 99.9% of traffic (1 attack per 1,000 flows) and measure the real-world precision and false alarm fatigue.
4. **Out-of-Distribution CTU-13 Evaluation**:
   - Evaluate `inference_engine.py` on the 14,521 CTU-13 Scenario 1 flows to test cross-dataset transferability on Neris botnet traffic.
5. **Schema Attack & Error Handling**:
   - Feed corrupted DataFrames (missing features, unexpected categorical types, infinite values, all zeros) to verify that `ProductionInferenceEngine` throws clean, informative validation exceptions without crashing.

---

## 6. How Role 4 Should Run the Code

Role 4 can immediately execute complete inferences using the production engine:

```python
import pandas as pd
from src.models.inference_engine import ProductionInferenceEngine

# Initialize the production engine
engine = ProductionInferenceEngine(
    models_dir="models/role3_real_data",
    supervised_model_type="xgboost", # or "histgbt_baseline", "histgbt_with_port"
    use_anomaly_autoencoder=True
)

# Load test data
df_test = pd.read_parquet("data/processed/CSE-CIC-IDS2018_v2/Friday-02-03-2018.parquet").head(1000)

# Run batch inference
results = engine.predict(df_test)
print(results.head())
# Columns returned:
# ['predicted_class', 'predicted_label', 'confidence_probability', 
#  'is_attack_predicted', 'anomaly_score_mse', 'is_anomaly_alert']
```

---

## 7. Role 3 Formal Sign-off Verdict

**Verdict: READY WITH CAVEATS**

**Justification**:
- Core data, schema reconciliation, and anti-leakage splitting are verified across all 16.23M CSE flows.
- Benign false positive rate was successfully reduced from 58.58% down to 1.02% with high throughput (290k flows/s).
- Anomaly detection feature scaling and deep autoencoder implementation are verified.
- Documented caveats (Infiltration recall trade-off, small-sample web exploit coverage) require independent red-teaming by Role 4.
