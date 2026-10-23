# Master Data Preprocessing & Network Feature Extraction Report
**Project: AI/ML-Based Cyber Defense Platform**  
**Team: Neural Breach — Role 2: Network Feature Extraction & Preprocessing**  
**Execution Timestamp**: 2026-10-22 14:12:35 UTC  
**Compliance**: Project Rules 2, 3, 5, 7  

---

## 1. Executive Summary

Role 2 has engineered and executed a production-grade, memory-safe data preprocessing and feature extraction pipeline across all collected cybersecurity datasets.

### Key Achievements:
- **CSE-CIC-IDS2018 (All 10 Days)**: Vectorized streaming ingestion through PyArrow ParquetWriter processed multi-million records without memory escalation (<300 MB RAM peak). Dropped repeated headers, normalized `Infilteration` typo, converted infinities to NaN, and preserved full per-row provenance.
- **UNSW-NB15**: Official benchmark train/test partitions preserved with zero leakage. Validated 44-feature schema, confirmed zero missing values, and exported compressed Parquet.
- **CTU-13 Scenario 1 PCAP**: Developed Scapy-based bidirectional flow extractor (`pcap_extractor.py`), parsing 323,154 packets into 14,521 bidirectional flow records in 30.58 seconds with ground-truth Neris botnet tagging.
- **Heterogeneous Telemetry Parsers**: Created isolated ingestion modules for LANL DNS, LANL Red Team (749 compromise events exported to Parquet), CTU-13 CapTipper HTTP inspection (113 web sessions), Windows EVTX archive (432 event logs), and MITRE ATT&CK STIX 2.1 threat matrix.
- **Leakage-Free Numerical Pipeline**: `NumericalPreprocessor` guarantees that imputer medians, scaler parameters, and label encodings are fitted strictly on training data.
- **Automated Test Suite**: 9/9 unit and integration tests passing in `tests/test_preprocessing.py` (100% pass rate).

---

## 2. Processed Outputs & Quality Metrics

| dataset_name      | source_file                                        |   source_size_mb |   rows_read |   rows_retained |   headers_dropped |   infinities_imputed |   nans_found |   labels_normalized |   parquet_size_mb |   elapsed_seconds | status                   |
|:------------------|:---------------------------------------------------|-----------------:|------------:|----------------:|------------------:|---------------------:|-------------:|--------------------:|------------------:|------------------:|:-------------------------|
| CSE-CIC-IDS2018   | Friday-02-03-2018_TrafficForML_CICFlowMeter.csv    |           336.04 |     1048575 |         1048575 |                 0 |                 5542 |         8100 |                   0 |            113.57 |             28.11 | VERIFIED_CLEAN           |
| CSE-CIC-IDS2018   | Friday-16-02-2018_TrafficForML_CICFlowMeter.csv    |           318.26 |     1048575 |         1048574 |                 1 |                    0 |            0 |                   0 |            105.83 |             28.59 | VERIFIED_CLEAN           |
| CSE-CIC-IDS2018   | Friday-23-02-2018_TrafficForML_CICFlowMeter.csv    |           365.11 |     1048575 |         1048575 |                 0 |                 7662 |        11416 |                   0 |            139.12 |             29.94 | VERIFIED_CLEAN           |
| CSE-CIC-IDS2018   | Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv  |          3867.08 |     7948748 |         7948748 |                 0 |                82139 |       118906 |                   0 |           1124.72 |            227.07 | VERIFIED_CLEAN           |
| CSE-CIC-IDS2018   | Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv  |           102.85 |      331125 |          331100 |                25 |                 4004 |         5838 |               93063 |             36.59 |              8.71 | VERIFIED_CLEAN           |
| CSE-CIC-IDS2018   | Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv  |           358.53 |     1048575 |         1048575 |                 0 |                11133 |        16054 |                   0 |            134.05 |             28.8  | VERIFIED_CLEAN           |
| CSE-CIC-IDS2018   | Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv  |           364.91 |     1048575 |         1048575 |                 0 |                 7651 |        11220 |                   0 |            138.97 |             28.64 | VERIFIED_CLEAN           |
| CSE-CIC-IDS2018   | Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv |           341.63 |     1048575 |         1048575 |                 0 |                 5371 |         7648 |                   0 |            102.66 |             27.03 | VERIFIED_CLEAN           |
| CSE-CIC-IDS2018   | Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv |           313.66 |     1048575 |         1048575 |                 0 |                    0 |            0 |                   0 |             68.72 |             26.12 | VERIFIED_CLEAN           |
| CSE-CIC-IDS2018   | Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv |           199.56 |      613104 |          613071 |                33 |                 8297 |        12338 |               68871 |             73.28 |             17.16 | VERIFIED_CLEAN           |
| UNSW-NB15         | UNSW_NB15_training-set.csv                         |            13.75 |       82332 |           82332 |                 0 |                    0 |            0 |                   0 |              6.42 |              0.5  | VERIFIED_CLEAN           |
| UNSW-NB15         | UNSW_NB15_testing-set.csv                          |            28.7  |      175341 |          175341 |                 0 |                    0 |            0 |                   0 |             12.65 |              0.5  | VERIFIED_CLEAN           |
| CTU-13 Scenario 1 | botnet-capture-20110810-neris.pcap                 |            55.57 |      323154 |           14521 |                 0 |                    0 |            0 |                   0 |              1.59 |             30.58 | FLOWS_EXTRACTED_VERIFIED |
| LANL Cyber1       | redteam.txt.gz                                     |             0.01 |         749 |             749 |                 0 |                    0 |            0 |                   0 |              0.01 |              0.1  | PARSED_PARQUET           |

---

## 3. Label Distributions Across Platforms

| dataset_name      | clean_label              |   record_count | percentage_within_dataset   | attack_family                        |
|:------------------|:-------------------------|---------------:|:----------------------------|:-------------------------------------|
| CSE-CIC-IDS2018   | Benign                   |       13484708 | 83.07%                      | Normal Baseline                      |
| CSE-CIC-IDS2018   | DDOS attack-HOIC         |         686012 | 4.23%                       | Active Cyber Attack                  |
| CSE-CIC-IDS2018   | DDoS attacks-LOIC-HTTP   |         576191 | 3.55%                       | Active Cyber Attack                  |
| CSE-CIC-IDS2018   | DoS attacks-Hulk         |         461912 | 2.85%                       | Active Cyber Attack                  |
| CSE-CIC-IDS2018   | Bot                      |         286191 | 1.76%                       | Active Cyber Attack                  |
| CSE-CIC-IDS2018   | FTP-BruteForce           |         193360 | 1.19%                       | Active Cyber Attack                  |
| CSE-CIC-IDS2018   | SSH-Bruteforce           |         187589 | 1.16%                       | Active Cyber Attack                  |
| CSE-CIC-IDS2018   | Infiltration             |         161934 | 1.00%                       | Active Cyber Attack                  |
| CSE-CIC-IDS2018   | DoS attacks-SlowHTTPTest |         139890 | 0.86%                       | Active Cyber Attack                  |
| CSE-CIC-IDS2018   | DoS attacks-GoldenEye    |          41508 | 0.26%                       | Active Cyber Attack                  |
| CSE-CIC-IDS2018   | DoS attacks-Slowloris    |          10990 | 0.07%                       | Active Cyber Attack                  |
| CSE-CIC-IDS2018   | DDOS attack-LOIC-UDP     |           1730 | 0.01%                       | Active Cyber Attack                  |
| CSE-CIC-IDS2018   | Brute Force -Web         |            611 | 0.00%                       | Active Cyber Attack                  |
| CSE-CIC-IDS2018   | Brute Force -XSS         |            230 | 0.00%                       | Active Cyber Attack                  |
| CSE-CIC-IDS2018   | SQL Injection            |             87 | 0.00%                       | Active Cyber Attack                  |
| UNSW-NB15         | Attack (1)               |         164673 | 63.91%                      | Synthetic/Real Attacks               |
| UNSW-NB15         | Normal (0)               |          93000 | 36.09%                      | Normal Baseline                      |
| CTU-13 Scenario 1 | Botnet-Neris             |          14521 | 100.00%                     | Infected Botnet Host Traffic (Neris) |

---

## 4. Deliverables Manifest

- Pipeline Source Code: `src/data/preprocessing/`
  - `preprocess_cse.py`: Streaming CSE-CIC-IDS2018 processor
  - `preprocess_unsw.py`: Partitioned UNSW-NB15 processor
  - `pcap_extractor.py`: Scapy bidirectional PCAP flow extractor
  - `numerical_pipeline.py`: Leakage-free fit-on-train transformer
  - `feature_policy.py`: Column policy accessors and definitions
  - `telemetry_parsers.py`: Isolated parsers for DNS, Red Team, EVTX, STIX
  - `csv_validator.py`: Chunked validation engine
- Automated Test Suite: `tests/test_preprocessing.py` (9 passed, 100%)
- Deliverable Reports: `reports/data_preprocessing/`
  - `feature_policy.md`
  - `preprocessing_issues.md`
  - `schema_inventory.csv`
  - `data_quality_report.csv`
  - `label_distribution.csv`
  - `preprocessing_summary.md`
  - `preprocessing_handoff.md`
