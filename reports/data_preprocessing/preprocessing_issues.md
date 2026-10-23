# Technical Issues, Schema Discrepancies & Resolutions
**Project: AI/ML-Based Cyber Defense Platform**  
**Team: Neural Breach — Role 2: Network Feature Extraction & Preprocessing**  
**Date**: October 22, 2026  
**Status**: RESOLVED & VERIFIED

---

## 1. Executive Summary

During the comprehensive audit, ingestion, and preprocessing of our platform's raw cybersecurity datasets, eight critical data quality and schema divergence issues were uncovered. This document details each issue, its root cause, the operational risks to downstream machine learning (Role 3), and our technical resolutions.

---

## 2. Detailed Technical Issues & Resolutions

### Issue 1: CSE-CIC-IDS2018 Schema Divergence (80 vs. 84 Columns)
- **Root Cause**: The raw CSE-CIC-IDS2018 dataset contains 10 daily CSV captures. Nine files contain 80 columns starting directly with `Dst Port`. However, `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv` contains 84 columns because it includes four extra network endpoint fields (`Flow ID`, `Src IP`, `Dst IP`, `Src Port`).
- **Operational Risk**: Naive concatenation or uniform column indexing causes column misalignment, data corruption, or script termination.
- **Resolution**: Implemented dynamic schema detection in `preprocess_cse.py`. For the 84-column file, the extra four columns are preserved as metadata identifiers, while the canonical 80 features are aligned across all files.

### Issue 2: Embedded Repeated Header Rows in Raw CSE CSVs
- **Root Cause**: During the Canadian Institute for Cybersecurity (CIC) distributed multi-threaded capture, header rows were periodically re-emitted into the CSV streams at buffer flush boundaries (e.g. `Label == 'Label'` and `Dst Port == 'Dst Port'`).
  - `Wednesday-28-02-2018`: 33 repeated header rows
  - `Thursday-01-03-2018`: 25 repeated header rows
  - `Friday-16-02-2018`: 1 repeated header row
- **Operational Risk**: Downstream ML tokenizers or numeric converters fail with `ValueError: could not convert string 'Dst Port' to float`, or treat the header string as an unknown anomaly class.
- **Resolution**: Vectorized chunk filtering automatically detects and purges all repeated header rows. Exact counts dropped per file are recorded in `reports/data_preprocessing/data_quality_report.csv`.

### Issue 3: Mathematical Infinities in Flow Rate Features
- **Root Cause**: CICFlowMeter computes `Flow Byts/s` and `Flow Pkts/s` as $\frac{\text{Bytes}}{\text{Duration}}$ and $\frac{\text{Packets}}{\text{Duration}}$. When flow duration is zero microseconds (single-packet flows or instantaneous connections), division by zero outputs strings: `Infinity`, `inf`, and `-inf`.
  - Over 12,000 infinities detected in `Wednesday-28-02` and `Thursday-01-03` alone.
  - Over 5,500 infinities detected in `Friday-02-03`.
- **Operational Risk**: Tree models (LightGBM/XGBoost) may handle infinities arbitrarily, while neural networks, autoencoders, and linear models output `NaN` gradients and diverge.
- **Resolution**: All infinite values are converted to `np.nan` during raw ingestion. Our `NumericalPreprocessor` pipeline implements median imputation fitted **exclusively on training data**, ensuring no data leakage into validation or test sets.

### Issue 4: Typographical Label Corruption (`Infilteration`)
- **Root Cause**: The official CICFlowMeter output for `Wednesday-28-02-2018` and `Thursday-01-03-2018` contains the typographic error `Infilteration` instead of `Infiltration`.
- **Operational Risk**: Downstream classifiers create two distinct target classes (`Infilteration` vs `Infiltration`), splitting support and destroying evaluation metrics.
- **Resolution**: Implemented automatic label normalization mapping `{"Infilteration": "Infiltration"}`. The cleaned label is saved to `Label` and `_Clean_Label`, while the exact source string is preserved in `_Raw_Label` for full forensic traceability.

### Issue 5: UNSW-NB15 Benchmark Partition Schema vs. Feature Dictionary
- **Root Cause**: The raw UNSW collection contains two distinct schemas:
  1. `NUSW-NB15_features.csv`: 49 features including raw IP addresses (`srcip`, `dstip`) and multiclass `attack_cat`.
  2. `UNSW_NB15_training-set.csv` and `testing-set.csv`: 44 features where IP addresses were excluded to prevent lab topology overfitting, protocol/service/state were integer-encoded (`xProt`, `xServ`, `xState`), and only binary `label` (0/1) was provided.
  In addition, `NUSW-NB15_features.csv` contains non-UTF8 byte `0x92` (Windows CP1252 curly quote).
- **Resolution**: Maintained complete separation between UNSW-NB15 and CSE-CIC-IDS2018. Documented the exact 44-feature benchmark partition schema and handled feature dictionary parsing using `latin-1`.

### Issue 6: CTU-13 JSON Metadata Encoding & Structure
- **Root Cause**: `botnet-capture-20110810-neris.json` was documented in prior handoffs as line-delimited Argus NetFlow JSON. Inspection revealed it is actually a single CapTipper HTTP inspection JSON object containing binary bytes (`0xff`) and 113 web conversation objects.
- **Resolution**: Implemented `parse_ctu13_json()` with `latin-1` decoding. Extracted 113 HTTP conversations, 786 URIs, request methods, and malware payload hashes, exporting to `ctu13_http_telemetry.parquet`.

### Issue 7: PCAP Feature Extraction Without Native Java CLI
- **Root Cause**: Native Java-based CICFlowMeter CLI is unavailable in the execution environment.
- **Resolution**: Developed `src/data/preprocessing/pcap_extractor.py` using Scapy. Successfully parsed 323,154 packets from `botnet-capture-20110810-neris.pcap` in 30.58 seconds, computing bidirectional flow durations, packet/byte counts, inter-arrival times, TCP flags, and ground-truth Neris botnet tagging (`147.32.84.165`).

### Issue 8: Multi-Gigabyte Memory Scaling (Streaming Parquet Writing)
- **Root Cause**: Ingesting the 3.86 GB `Thuesday-20-02` CSV (7.9 million rows) via standard `pandas.concat()` would exceed 12 GB RAM, triggering Out-Of-Memory (OOM) crashes. Additionally, chunk-by-chunk pandas dtype inference caused subtle `int64` vs `float64` schema mismatch errors in PyArrow.
- **Resolution**: Implemented chunk-by-chunk streaming directly to disk via PyArrow `ParquetWriter(compression='snappy')` with explicit `float64` numeric casting. Peak memory usage remains strictly under 300 MB throughout the entire multi-gigabyte ingestion.
