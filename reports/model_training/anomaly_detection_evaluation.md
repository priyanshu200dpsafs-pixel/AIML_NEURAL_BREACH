# Anomaly Detection Training & Evaluation Report

**Execution Timestamp**: 2026-10-24 14:03:27 UTC  
**Models Evaluated**: Scikit-Learn Isolation Forest vs. PyTorch Deep Autoencoder  
**Benign Training Flows**: 800,000 flows  
**Scaling**: StandardScaler fitted strictly on pure benign training flows  

---

## 1. Operating Point Comparison (Operational False Alarm Budgets)

### A. PyTorch Deep Autoencoder

| Target FPR | Threshold (MSE) | Actual Test FPR | Overall Attack Recall | Binary Precision | Binary F1 |
| :---: | :---: | :---: | :---: | :---: | :---: |
| FPR≤0.1% | 1.4763 | **0.09%** | **0.60%** | 83.74% | **0.0120** |
| FPR≤0.5% | 0.6462 | **0.74%** | **1.08%** | 54.23% | **0.0213** |
| FPR≤1.0% | 0.3384 | **1.14%** | **4.52%** | 76.14% | **0.0854** |
| FPR≤2.0% | 0.1880 | **1.83%** | **9.77%** | 81.11% | **0.1744** |
| FPR≤5.0% | 0.0891 | **4.36%** | **27.28%** | 83.44% | **0.4111** |

### B. Isolation Forest

| Target FPR | Threshold (Score) | Actual Test FPR | Overall Attack Recall | Binary Precision | Binary F1 |
| :---: | :---: | :---: | :---: | :---: | :---: |
| FPR≤0.1% | -0.0797 | **0.11%** | **0.06%** | 29.89% | **0.0011** |
| FPR≤0.5% | -0.0175 | **0.52%** | **0.72%** | 52.56% | **0.0143** |
| FPR≤1.0% | -0.0035 | **0.68%** | **0.88%** | 51.19% | **0.0174** |
| FPR≤2.0% | 0.0349 | **1.35%** | **1.40%** | 45.44% | **0.0272** |
| FPR≤5.0% | 0.0954 | **4.93%** | **2.92%** | 32.31% | **0.0536** |

---

## 2. Per-Attack Detection Breakdown at 1.0% False Positive Budget (Deep Autoencoder)

| Attack Category | Total Test Flows | Detected Flows | Recall at 1% FPR |
| :--- | :---: | :---: | :---: |
| **Bot** | 20,000 | 56 | **0.28%** |
| **Brute Force -Web** | 93 | 20 | **21.51%** |
| **Brute Force -XSS** | 37 | 16 | **43.24%** |
| **DDOS attack-HOIC** | 20,000 | 0 | **0.00%** |
| **DDOS attack-LOIC-UDP** | 260 | 260 | **100.00%** |
| **DDoS attacks-LOIC-HTTP** | 20,000 | 0 | **0.00%** |
| **DoS attacks-GoldenEye** | 6,227 | 191 | **3.07%** |
| **DoS attacks-Hulk** | 20,000 | 455 | **2.27%** |
| **DoS attacks-SlowHTTPTest** | 20,000 | 151 | **0.76%** |
| **DoS attacks-Slowloris** | 1,650 | 1,089 | **66.00%** |
| **FTP-BruteForce** | 20,000 | 6,661 | **33.30%** |
| **Infiltration** | 93,063 | 2,015 | **2.17%** |
| **SQL Injection** | 15 | 1 | **6.67%** |
| **SSH-Bruteforce** | 20,000 | 4 | **0.02%** |

---

## 3. Computational Benchmark & Latency

- **Deep Autoencoder Inference Latency**: **0.14 µs/sample**
- **Isolation Forest Inference Latency**: **3.05 µs/sample**
- **Deep Autoencoder ROC-AUC**: **0.7995** | **PR-AUC**: **0.7561**
- **Isolation Forest ROC-AUC**: **0.5682** | **PR-AUC**: **0.4969**
