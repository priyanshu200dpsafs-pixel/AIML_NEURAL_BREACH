# AI/ML-Based Cyber Defense Platform: Data Engineering & Feature Pipeline
**Team**: Neural Breach  
**Project**: AI/ML-Based Network Intrusion Detection & Threat Defense Platform  
**Target Environment**: Python 3.10+ | Apache Parquet (Snappy) | Scapy | PyArrow | Scikit-learn  
**Cloud Storage**: Google Drive Shared Repository ([Shared Link](https://drive.google.com/drive/folders/1UHwqXR3qM-OHZc5nHNgkAVJ_Ewl_9Rha?usp=sharing))

---

## 1. Executive Summary

This repository houses the complete, reproducible data engineering, network feature extraction, and preprocessing pipeline for the **AI/ML-Based Cyber Defense Platform**, engineered by **Team Neural Breach**.

The project establishes a verified data foundation across real-world cybersecurity datasets:
1. **Real Original Network Traffic**: Ingested directly from official university, government, and threat research repositories—never fabricated, synthetic placeholders, or arbitrary subsamples.
2. **Exhaustive Schema Harmonization & Quality Control**: Processed multi-million flow records across CSE-CIC-IDS2018, UNSW-NB15, and CTU-13. Validated schemas, purged repeated header artifacts, replaced mathematical infinities, normalized typographical errors, and enforced strict data leakage controls.
3. **Reproducible Extraction & Cloud Synchronization**: Bidirectional flow extraction from raw PCAPs via Scapy, isolated telemetry parsers for host and DNS logs, and automated Google Drive synchronization for team accessibility.

---

## 2. Repository Structure

```
aiml project team neural breach/
├── README.md                                  <- Executive project presentation & evaluation guide
├── TEAM_DATASET_ACCESS_GUIDE.md               <- Data access, schema reference, and team onboarding
├── scripts/                                   <- Automation & synchronization utilities
│   └── sync_data_drive.py                     <- Google Drive dataset resolver and synchronization
├── src/                                       <- Production source code
│   ├── data/
│   │   └── preprocessing/                     <- Data engineering and extraction modules
│   │       ├── csv_validator.py               <- Chunked CSV ingestion & schema validation
│   │       ├── feature_policy.py              <- Feature role policy & column governance
│   │       ├── preprocess_cse.py              <- Streaming CSE-CIC-IDS2018 processor
│   │       ├── preprocess_unsw.py             <- Partitioned UNSW-NB15 processor
│   │       ├── pcap_extractor.py              <- Scapy bidirectional PCAP flow extractor
│   │       ├── numerical_pipeline.py          <- Leakage-free fit-on-train transformer
│   │       ├── telemetry_parsers.py           <- Isolated parsers for DNS, Red Team, EVTX, STIX
│   │       └── generate_final_reports.py      <- Automated deliverable report compiler
│   ├── features/                              <- Feature engineering utilities
│   └── models/                                <- Baseline model interfaces
├── tests/                                     <- Automated test suite
│   └── test_preprocessing.py                  <- Unit and integration tests (100% pass rate)
├── reports/                                   <- Comprehensive engineering audit reports
│   ├── data_preprocessing/                    <- Role 2 preprocessor & QA audit deliverables
│   │   ├── ROLE2_FINAL_SIGNOFF_REPORT.md      <- Final QA sign-off and audit certification
│   │   ├── preprocessing_handoff.md           <- Role 3 ML engineer handoff specification
│   │   ├── feature_policy.md                  <- Full feature treatment policy & port guidelines
│   │   ├── preprocessing_issues.md            <- Detailed documentation of 8 resolved issues
│   │   ├── schema_inventory.csv               <- Tabular inventory of all 10 dataset schemas
│   │   ├── data_quality_report.csv            <- Reconciled row counts, infinities, headers dropped
│   │   └── label_distribution.csv             <- Ground-truth class distributions (18 classes)
│   ├── dataset_audit/                         <- Phase 1 raw collection audits
│   └── model_baseline/                        <- Baseline split manifests and distributions
└── data/
    ├── documentation/                         <- Data taxonomy, licensing, and legal specs
    └── manifests/                             <- Cryptographic SHA-256 inventories
```

---

## 3. Verified Dataset Inventory

| Dataset | Format | Extracted / Verified Scope | Records / Packets | Key Attack Categories |
| :--- | :--- | :--- | :---: | :--- |
| **CSE-CIC-IDS2018** | Parquet / CSV | 10 Daily Captures (CICFlowMeter) | **16,232,943 flows** | DDoS (HOIC, LOIC), DoS (Hulk, SlowHTTPTest, GoldenEye), BruteForce (SSH, FTP), Botnet, Infiltration |
| **UNSW-NB15** | Parquet / CSV | Benchmark Train & Test Partitions | **257,673 flows** | Synthetic and real modern attacks (Generic, Exploits, Fuzzers, Reconnaissance, DoS) |
| **CTU-13 Scenario 1**| Parquet / PCAP| Raw Capture & Bidirectional Flows | **323,154 packets / 14,521 flows**| Active Neris Botnet C&C, IRC, and HTTP communication |
| **LANL Cyber1** | Parquet / GZ | Red Team Adversary Timeline | **749 events** | Internal lateral movement, credential abuse, and host compromise events |
| **LANL Cyber1** | GZIP CSV | Enterprise DNS Lookups | 100k sampled | Internal enterprise DNS resolution query patterns |
| **Windows EVTX** | ZIP Archive | 432 Host Event Log Files | 2.1 GB uncompressed | Binary XML security event logs from AWS testbed endpoints |
| **MITRE ATT&CK** | STIX 2.1 JSON | Enterprise, Mobile, ICS Matrices | 31,940 objects | Comprehensive adversarial TTPs and mitigation mapping |

*Note on Raw PCAPs*: The upstream CSE-CIC-IDS2018 collection contains ~400 GB of raw packet captures hosted in the public AWS Open Data S3 bucket (`s3://cse-cic-ids2018/`). In accordance with standard machine-learning data engineering practices, the canonical, pre-extracted 80-feature CICFlowMeter flow datasets (16.23M records across all 10 days, ~7.0 GB) were ingested and processed into compressed Parquet, avoiding redundant multi-hundred-gigabyte raw packet transfers.

---

## 4. Google Drive Data Integration

All raw and processed datasets (~9.4 GB total) are centrally hosted in the team's shared Google Drive repository. Large data files are tracked outside of Git to maintain a clean, lightweight repository.

To synchronize datasets into your local workspace:

```bash
# Clone the repository
git clone https://github.com/priyanshu200dpsafs-pixel/AIML_NEURAL_BREACH.git
cd AIML_NEURAL_BREACH

# Sync datasets from Google Drive
python scripts/sync_data_drive.py
```

* Google Drive Shared Folder: [Team Neural Breach Dataset Hub](https://drive.google.com/drive/folders/1UHwqXR3qM-OHZc5nHNgkAVJ_Ewl_9Rha?usp=sharing)
* Folder ID: `1UHwqXR3qM-OHZc5nHNgkAVJ_Ewl_9Rha`

---

## 5. Automated Verification & Testing

Run the full automated test suite:

```bash
pytest tests/test_preprocessing.py -v
```

**Status**: 9 passed in 1.21s (100% pass rate).

For detailed data engineering validation, refer to:
* [`reports/data_preprocessing/ROLE2_FINAL_SIGNOFF_REPORT.md`](file:///Users/priyanshu/Desktop/aiml%20project%20team%20neural%20breach/reports/data_preprocessing/ROLE2_FINAL_SIGNOFF_REPORT.md)
* [`reports/data_preprocessing/preprocessing_handoff.md`](file:///Users/priyanshu/Desktop/aiml%20project%20team%20neural%20breach/reports/data_preprocessing/preprocessing_handoff.md)
