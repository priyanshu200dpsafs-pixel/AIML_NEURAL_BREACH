# INFERENCE LATENCY & THROUGHPUT BENCHMARK (RETRAINING V2)
## Team Neural Breach — AI/ML Cyber Defense Platform
**Role:** Machine Learning & Anomaly Detection Specialist  
**Phase:** Role 3 Retraining V2  
**Date:** 2026-10-25  
**Hardware Platform:** Apple Silicon M-Series (10-Core CPU, 16.0 GB RAM, arm64 Architecture)  
**Operating System:** macOS Darwin 24.x  

---

## 1. Executive Summary & Benchmark Protocol

A high-performance intrusion detection system must process streaming flow summaries at line rate without introducing packet buffer bloat or latency bottlenecks.

We conducted a comprehensive empirical latency benchmark distinguishing:
1. **Feature Preprocessing Time**: Imputing NaNs/infs, type casting to `float32`, and applying StandardScaler transformations.
2. **Model Inference Time**: Pure mathematical execution of tree ensemble traversals and neural network matrix multiplications across batch sizes $B \in \{1, 64, 256, 1024, 10000\}$.
3. **End-to-End Pipeline Latency**: Total elapsed time from raw flow ingestion to security alert generation.

---

## 2. Empirical Model Inference Benchmark Results

| Model Architecture | Batch Size ($B$) | Per-Sample Latency (µs) | Sustained Throughput (flows/sec) | Hardware Resource Utilization |
| :--- | :---: | :---: | :---: | :--- |
| **PyTorch Deep Autoencoder** | **1** | **36.22 µs** | 27,607 flows/s | Single-core PyTorch tensor overhead |
| | **64** | **2.44 µs** | 410,524 flows/s | Multi-threaded BLAS SIMD acceleration |
| | **256** | **0.71 µs** | 1,409,499 flows/s | High vector register occupancy |
| | **1024** | **0.41 µs** | **2,465,114 flows/s** | Optimal streaming batch efficiency |
| | **10000** | **0.16 µs** | **6,425,098 flows/s** | Peak throughput (Vectorized float32) |
| **XGBoost Classifier** | **1** | **139.93 µs** | 7,146 flows/s | Per-call C++ API boundary overhead |
| | **64** | **7.82 µs** | 127,892 flows/s | Parallel tree traversal across 4 cores |
| | **256** | **4.31 µs** | 232,240 flows/s | OpenMP thread pool saturation |
| | **1024** | **2.64 µs** | **378,141 flows/s** | Efficient L2/L3 CPU cache residency |
| | **10000** | **1.46 µs** | **682,869 flows/s** | Maximum sustained multi-core rate |
| **LightGBM Classifier** | **1** | **273.14 µs** | 3,661 flows/s | Python-to-C wrapper boundary overhead |
| | **64** | **19.52 µs** | 51,220 flows/s | Parallel histogram bin traversal |
| | **256** | **27.66 µs** | 36,153 flows/s | Thread pool synchronization |
| | **1024** | **20.68 µs** | 48,364 flows/s | Cache-optimized decision paths |
| | **10000** | **14.80 µs** | **67,579 flows/s** | Maximum sustained streaming rate |

---

## 3. End-to-End Latency Decomposition (Per-Flow)

Decomposing total wall-clock time for a streaming batch of 1,024 flows:

```
[Raw Flow Ingestion]
        │
        ▼ (0.296 µs) - Feature Sanitization & StandardScaler
[Preprocessed Matrix]
        │
        ├───────────────────────────┬───────────────────────────┐
        ▼ (2.645 µs)                ▼ (0.406 µs)                │
[XGBoost Supervised]        [PyTorch Autoencoder]              │
        │                           │                           │
        ▼                           ▼                           ▼
[Class: DoS-Hulk (99.9%)]   [Recon Error: MSE 0.124]    [Threshold Evaluator]
        │                           │                           │
        └───────────────────────────┴───────────────────────────┘
                                    │
                                    ▼ (0.120 µs) - Correlation & Threat Level
                       [Generated Security Alert]
                       Total End-to-End Latency: ~3.47 µs per flow
```

| Pipeline Processing Stage | Mean Latency per Flow (µs) | % of Total Processing Budget |
| :--- | :---: | :---: |
| **1. Feature Sanitization & Preprocessing** | **0.296 µs** | 8.5% |
| **2. Supervised Inference (XGBoost @ Batch 1024)** | **2.645 µs** | 76.2% |
| **3. Anomaly Inference (Deep Autoencoder @ Batch 1024)** | **0.406 µs** | 11.7% |
| **4. Hybrid Threshold Correlation & Alert JSON Formatting**| **0.120 µs** | 3.6% |
| **TOTAL END-TO-END LATENCY PER FLOW** | **3.467 µs** | **100.0%** |

---

## 4. Network Line-Rate Capacity Analysis

In high-throughput enterprise networks:
- **1 Gbps Ethernet Line**: Generates approximately **15,000 to 50,000 bidirectional flows per second**.
- **10 Gbps Core Switch**: Generates approximately **150,000 to 400,000 bidirectional flows per second** (assuming average flow duration of 10–25 packets).

### Performance Verdict:
1. **XGBoost Throughput (378,141 flows/s @ Batch 1024)**:
   - Capable of sustaining line-rate flow inspection on a **10 Gbps enterprise core network link** on a single workstation CPU without hardware accelerators (GPUs/TPUs).
2. **Deep Autoencoder Throughput (2,465,114 flows/s @ Batch 1024)**:
   - Capable of sustaining line-rate anomaly scoring on a **40 Gbps to 100 Gbps backbone network**.
3. **LightGBM Throughput (48,364 flows/s @ Batch 1024)**:
   - Sufficient for a **1 Gbps perimeter gateway**, but requires multi-threaded scaling or larger batch buffering for 10 Gbps lines.
