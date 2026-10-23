# CSE-CIC-IDS2018 Preprocessing Pipeline Report

**Execution Date**: 2026-10-21 15:53:29 UTC  
**Framework**: Python Pandas & PyArrow Streaming (Chunksize = 100,000)  
**Target Format**: Apache Parquet (`snappy` compressed)  

---

## 1. Audit Table: Rows Read, Retained, Rejected and Written

| File Name | Rows Read | Clean Retained | Repeated Headers Rejected | Infinities Imputed | NaNs Imputed | Parquet Size | Input SHA-256 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 1,048,574 | 1 | 0 | 0 | 85.54 MB | `1a4919faa0c4...` |
| `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 1,048,575 | 0 | 0 | 0 | 58.93 MB | `a5f4a1c2689e...` |
| `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv` | 613,104 | 613,071 | 33 | 8,297 | 12,338 | 61.49 MB | `f15e2a123044...` |
| `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | 331,125 | 331,100 | 25 | 4,004 | 5,838 | 30.42 MB | `b0534c5d7d8b...` |
| **TOTAL** | **3,041,379** | **3,041,320** | **59** | **12,301** | **18,176** | **236.38 MB** | |

## 2. Label Harmonization & Class Distributions

| Clean Class Label | Original Raw String | Total Records | % of Dataset | Attack Family |
| :--- | :--- | :---: | :---: | :--- |
| **Benign** | `Benign` | 1,589,842 | 52.27% | Normal Baseline |
| **DDOS attack-HOIC** | `DDOS attack-HOIC` | 686,012 | 22.56% | Active Cyber Attack |
| **DoS attacks-Hulk** | `DoS attacks-Hulk` | 461,912 | 15.19% | Active Cyber Attack |
| **Infiltration** | `Infilteration` | 161,934 | 5.32% | Active Cyber Attack |
| **DoS attacks-SlowHTTPTest** | `DoS attacks-SlowHTTPTest` | 139,890 | 4.60% | Active Cyber Attack |
| **DDOS attack-LOIC-UDP** | `DDOS attack-LOIC-UDP` | 1,730 | 0.06% | Active Cyber Attack |

---

## 3. Discrepancy Resolution

- **Raw Rows Read Across 4 Files**: **3,041,379**
- **Repeated Header Rows Dropped**: **59** (`Label == 'Label'`)
- **Clean Retained CSE Rows**: **3,041,320**
- **Adding Clean UNSW-NB15 Records**: **3,041,320 + 257,673 = 3,298,993 clean rows**.
- **Resolution**: The previously reported 3,299,052 count was calculated from raw lines (3,041,379 + 257,673). Deducting the exact 59 header artifacts yields precisely **3,298,993 verified clean rows**.
