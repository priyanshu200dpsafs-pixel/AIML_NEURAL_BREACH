# Team Neural Breach — Unified Project & Data Repository
**AI/ML-Based Cyber Defense Platform**  
**Central Team Hub:** Google Drive (`aiml_project_team_neural_breach/`)  
**Maintained by:** Senior Data Acquisition & Engineering Team  
**Data Integrity Policy:** Strict Zero Data Loss | Bit-Level Verification | Cryptographic Immutability  

---

## 1. Quick Navigation & Folder Organization

Everything needed for data access, exploratory analysis, preprocessing, and machine learning model training is unified in this single, organized directory structure:

```
aiml_project_team_neural_breach/
├── TEAM_DATASET_ACCESS_GUIDE.md    <- (THIS FILE) Master onboarding and data access guide for the team
├── README.md                       <- Executive platform overview & evaluation summary
│
├── data/                           <- All project datasets (Raw, Processed, Reference, Manifests)
│   ├── raw/                        <- 100% Authentic, unmodified ground-truth datasets
│   │   ├── CSE-CIC-IDS2018/        <- Full suite of CICFlowMeter daily CSVs + Windows EVTX host logs
│   │   ├── UNSW-NB15/              <- Modern synthetic & realistic network attacks (Train/Test CSVs)
│   │   ├── LANL/                   <- Los Alamos National Lab Cyber1 (40.8M DNS queries + Red Team log)
│   │   ├── CTU-13/                 <- Verified botnet packet captures (Neris PCAP + Argus JSON flows)
│   │   ├── CIC-IDS2017/            <- Access gate specifications & schema definitions
│   │   └── CIC-DDoS2019/           <- Access gate specifications & DDoS taxonomy
│   │
│   ├── processed/                  <- High-speed, compressed, production-ready ML datasets
│   │   ├── splits/                 <- Stratified, leakage-free partitions ready for model training
│   │   │   ├── train.parquet       <- Model training partition (139.2 MB)
│   │   │   ├── val.parquet         <- Hyperparameter tuning & early stopping partition (16.4 MB)
│   │   │   └── test.parquet        <- Final holdout evaluation partition (46.9 MB)
│   │   └── CSE-CIC-IDS2018/        <- Snappy-compressed Parquet versions of daily flow tables
│   │
│   ├── reference/                  <- Threat Intelligence & Framework taxonomies
│   │   └── MITRE-ATT-CK/           <- Enterprise, ICS, and Mobile ATT&CK STIX 2.1 matrices
│   │
│   ├── manifests/                  <- Full dataset inventory & cryptographic logs
│   │   ├── dataset_inventory.csv   <- 15-field tabular inventory of every file
│   │   ├── dataset_inventory.json  <- Structured JSON inventory
│   │   └── verification_report.md  <- Packet-level and row-level verification reports
│   │
│   └── documentation/              <- Legal, licensing, and schema documentation
│       ├── sources_and_licenses.md <- BibTeX citations and open-source licenses
│       ├── dataset_summary.md      <- Attack coverage matrix and feature descriptions
│       └── download_issues.md      <- Network constraints & cloud storage audit
│
├── reports/                        <- Audit trails and model baseline results
│   ├── dataset_audit/              <- 11 comprehensive data collection & verification audits
│   │   ├── MASTER_DATA_COLLECTION_SUMMARY.md <- Executive data handoff summary
│   │   ├── FINAL_DATA_COLLECTION_REPORT.md   <- Final verified collection report
│   │   ├── DATA_HANDOFF_FOR_NEXT_TEAM.md     <- Specifications for ML & modeling engineers
│   │   ├── actual_file_inventory.csv         <- File-by-file sizes, paths, and status
│   │   ├── dataset_completeness.csv          <- Category-by-category audit
│   │   ├── attack_coverage_matrix.csv        <- MITRE & attack vector coverage
│   │   └── dataset_label_distribution.csv    <- Ground-truth label counts
│   └── model_baseline/             <- Baseline ML model metrics & split manifests
│       ├── preprocessing_summary.md          <- Data cleaning & harmonization specifications
│       ├── preprocessing_summary.json        <- Numeric records and memory statistics
│       ├── split_manifest.csv                <- Exact row distributions across train/val/test
│       └── class_distribution.csv            <- Class balance ratios across partitions
│
├── src/                            <- Core Python source code for modeling & preprocessing
│   ├── data/
│   │   └── preprocess_cse.py       <- Robust stream cleaner for CSVs (drops inf/nan, duplicate headers)
│   ├── features/
│   │   └── build_features.py       <- Feature selection, normalization, and label encoding
│   └── models/
│       ├── train_supervised.py     <- Supervised multi-class & binary classifiers (LightGBM/RF)
│       └── train_anomaly.py        <- Unsupervised anomaly detectors (Isolation Forest/Autoencoder)
│
└── scripts/                        <- Automated operational & data pipeline scripts
    ├── config.py                   <- Project configurations and paths
    ├── download_tuesday_20_02.py   <- 24-worker parallel range downloader with state checkpointing
    ├── resumable_downloader.py     <- General resilient chunk downloader
    ├── verify_datasets.py          <- SHA-256 and deep format validation tool
    └── run_pipeline.py             <- Master idempotent pipeline runner
```

---

## 2. How Team Members Can Access the Data

### Option A: From Google Colab (Recommended for GPU Training)
```python
from google.colab import drive
import pandas as pd

# 1. Mount Google Drive
drive.mount('/content/drive')
BASE_DIR = '/content/drive/My Drive/aiml_project_team_neural_breach'

# 2. Load pre-split, clean training data instantly:
train_df = pd.read_parquet(f'{BASE_DIR}/data/processed/splits/train.parquet')
val_df   = pd.read_parquet(f'{BASE_DIR}/data/processed/splits/val.parquet')
test_df  = pd.read_parquet(f'{BASE_DIR}/data/processed/splits/test.parquet')

print(f'Training flows: {len(train_df):,}, Features: {train_df.shape[1]}')
```

### Option B: From Local Python / Jupyter
```python
import os
import pandas as pd

# Set base directory to your local project clone or Google Drive mount:
BASE_DIR = os.environ.get("NEURAL_BREACH_DATA", os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Load raw CSE-CIC-IDS2018 flow table:
df = pd.read_csv(f'{BASE_DIR}/data/raw/CSE-CIC-IDS2018/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv')
print(df['Label'].value_counts())
```

---

## 3. Ground-Truth Data Assets Summary

| Dataset Category | Exact Disk Location | Content Description | Verified Volume |
|---|---|---|---|
| **CSE-CIC-IDS2018 Daily Flows** | `data/raw/CSE-CIC-IDS2018/` | CICFlowMeter 80-feature CSVs (DDoS, DoS, BruteForce, Botnet, Infiltration) | ~7.5+ Million clean network flows |
| **CSE-CIC-IDS2018 Host Logs** | `data/raw/CSE-CIC-IDS2018/` | Windows Event Viewer EVTX logs (`Friday-23-02-2018_logs.zip`) | 432 verified `.evtx` event logs |
| **UNSW-NB15 Attack Benchmarks** | `data/raw/UNSW-NB15/` | Train & Test CSVs with 44 features and 9 distinct cyber attack categories | 254,004 verified records |
| **LANL Cyber1 DNS & Red Team** | `data/raw/LANL/` | Enterprise DNS lookups (`dns.txt.gz`) and adversary compromise log | 40,821,591 DNS rows + 749 redteam events |
| **CTU-13 Real Botnet PCAP** | `data/raw/CTU-13/` | Raw PCAP capture (`botnet-capture-20110810-neris.pcap`) + Argus JSON flows | 323,154 raw packets / 58.3 MB |
| **MITRE ATT&CK STIX 2.1** | `data/reference/MITRE-ATT-CK/` | Enterprise, Mobile, and ICS threat framework JSON matrices | 31,940 STIX threat objects |
| **ML-Ready Parquet Splits** | `data/processed/splits/` | Deduplicated, cleaned, stratified 80/10/10 train/val/test splits | 202.5 MB high-speed Parquet |

---

## 4. Engineering Standards & Rules for Team Members

1. **Never Overwrite or Modify Raw Data**: All files in `data/raw/` must remain immutable.
2. **Schema Separation**: Do NOT concatenate CSE-CIC-IDS2018 (80 columns) with UNSW-NB15 (44 columns) horizontally. Model them independently or use schema alignment functions in `src/features/build_features.py`.
3. **Handle Inf/NaN Values**: Always sanitize infinite values before passing features to ML algorithms (`np.isinf()` replacement is automated in `src/data/preprocess_cse.py`).
4. **Data Integrity**: All original files have verified SHA-256 hashes listed in `data/manifests/dataset_inventory.csv`.
