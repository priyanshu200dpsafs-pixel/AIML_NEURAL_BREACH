# Role 2 Final Sign-Off Audit: Network Feature Extraction & Preprocessing
**Project**: AI/ML-Based Cyber Defense Platform  
**Team**: Neural Breach  
**Auditor**: Senior Data Engineering Quality Assurance Engineer  
**Audit Date**: October 22, 2026, 19:50:00 UTC  
**Target Repository**: `/Users/priyanshu/Desktop/aiml project team neural breach`  
**Mirror Repository**: Google Drive (`.../aiml_project_team_neural_breach/`)  
**Scope**: Independent verification of data engineering pipelines, Parquet outputs, numerical quality, schema segregation, and handoff documentation.

---

## 1. Executive QA Audit Summary

| Audit Dimension | Target / Claim | Verified Result | Compliance Status |
| :--- | :--- | :--- | :---: |
| **Automated Test Suite** | 9 Unit & Integration Tests | 9 Passed, 0 Failed, 0 Skipped (1.21s) | **VERIFIED PASS** |
| **CSE Total Rows Read** | 16,233,002 rows | 16,233,002 rows across 10 files | **EXACT MATCH (100%)** |
| **CSE Headers Dropped** | 59 repeated header rows | 59 repeated header rows dropped | **EXACT MATCH (100%)** |
| **CSE Clean Retained** | 16,232,943 rows | 16,232,943 rows in Parquet outputs | **EXACT MATCH (100%)** |
| **CSE Typo Normalization**| 161,934 `Infilteration` $\to$ `Infiltration` | 161,934 instances normalized | **EXACT MATCH (100%)** |
| **CSE Infinities Replaced**| 131,799 infinite values | 131,799 converted to `np.nan` (0 infs left) | **EXACT MATCH (100%)** |
| **UNSW-NB15 Partitioning** | 257,673 records | 82,332 (train) / 175,341 (test) in Parquet | **VERIFIED (With Caveat)** |
| **CTU-13 PCAP Extractor** | 14,521 bidirectional flows | 14,521 flows in Parquet (323,154 packets) | **VERIFIED PASS** |
| **Leakage Prevention** | Fit-on-train-only transformers | Verified in code and test suite | **VERIFIED PASS** |
| **FINAL QA VERDICT** | **PASS WITH CAVEATS** | All critical checks verified; 5 caveats noted | **APPROVED FOR ROLE 3** |

---

## 2. Test Suite Execution & Verification

The test suite was independently executed using `pytest 9.1.1` under Python 3.13.7:
```bash
pytest tests/test_preprocessing.py -v
```

### Execution Output:
```
============================= test session starts ==============================
platform darwin -- Python 3.13.7, pytest-9.1.1, pluggy-1.6.0
rootdir: /Users/priyanshu/Desktop/aiml project team neural breach
collected 9 items

tests/test_preprocessing.py::TestCSVValidation::test_repeated_header_detection PASSED [ 11%]
tests/test_preprocessing.py::TestCSVValidation::test_schema_comparison PASSED [ 22%]
tests/test_preprocessing.py::TestCSVValidation::test_numeric_issue_detection PASSED [ 33%]
tests/test_preprocessing.py::TestLabelNormalization::test_infilteration_typo_correction PASSED [ 44%]
tests/test_preprocessing.py::TestNumericalPreprocessorPipeline::test_fit_on_train_only_no_leakage PASSED [ 55%]
tests/test_preprocessing.py::TestNumericalPreprocessorPipeline::test_label_encoding_inverse_mapping PASSED [ 66%]
tests/test_preprocessing.py::TestPCAPFlowExtraction::test_flow_record_bidirectional_aggregation PASSED [ 77%]
tests/test_preprocessing.py::TestPCAPFlowExtraction::test_ctu13_botnet_labeling PASSED [ 88%]
tests/test_preprocessing.py::TestFeaturePolicy::test_feature_and_metadata_separation PASSED [100%]

============================== 9 passed in 1.21s ===============================
```
- **Passed**: 9
- **Failed**: 0
- **Skipped**: 0
- **Execution Time**: 1.21 seconds

---

## 3. Real Output Validation & CSE-CIC-IDS2018 Reconciliation

Every raw CSV file was audited against its corresponding output Parquet file in `data/processed/CSE-CIC-IDS2018_v2/`.

### Source-by-Source Verification Table:
| Source CSV Filename | Reported Rows Read | Actual CSV Data Rows | Parquet Rows Retained | Headers Dropped | Infinities Replaced | Labels Normalized | Parquet Size | Checksum / Integrity |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 1,048,575 | 1,048,575 | 0 | 5,542 | 0 | 113.57 MB | MATCH (83 cols) |
| `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 1,048,575 | 1,048,574 | 1 | 0 | 0 | 105.83 MB | MATCH (83 cols) |
| `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 1,048,575 | 1,048,575 | 0 | 7,662 | 0 | 139.12 MB | MATCH (83 cols) |
| `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`| 7,948,748 | 7,948,748 | 7,948,748 | 0 | 82,139 | 0 | 1124.72 MB | MATCH (87 cols) |
| `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | 331,125 | 331,125 | 331,100 | 25 | 4,004 | 93,063 | 36.59 MB | MATCH (83 cols) |
| `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 1,048,575 | 1,048,575 | 0 | 11,133 | 0 | 134.05 MB | MATCH (83 cols) |
| `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | 1,048,575 | 1,048,575 | 1,048,575 | 0 | 7,651 | 0 | 138.97 MB | MATCH (83 cols) |
| `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv`| 1,048,575 | 1,048,575 | 1,048,575 | 0 | 5,371 | 0 | 102.66 MB | MATCH (83 cols) |
| `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv`| 1,048,575 | 1,048,575 | 1,048,575 | 0 | 0 | 0 | 68.72 MB | MATCH (83 cols) |
| `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv`| 613,104 | 613,104 | 613,071 | 33 | 8,297 | 68,871 | 73.28 MB | MATCH (83 cols) |
| **TOTALS** | **16,233,002** | **16,233,002** | **16,232,943** | **59** | **131,799** | **161,934** | **2,037.51 MB** | **100% RECONCILED** |

### Findings:
- Zero unreadable, missing, or corrupt Parquet files.
- The 4-column difference in `Thuesday-20-02` (87 columns vs 83 columns) reflects the 4 extra network identifiers (`Flow ID`, `Src IP`, `Dst IP`, `Src Port`) preserved as metadata without disrupting the canonical 80 features.
- All 10 output Parquet files successfully open and read across partitions.

---

## 4. Numerical Data Quality & Missing Value Audit

### 4.1 Infinite Values
- **Encountered in Raw**: 131,799 instances across `Flow Byts/s` and `Flow Pkts/s`.
- **Remaining in Processed Parquet**: **0** (Verified across all 16,232,943 records).
- **Treatment**: Converted to `np.nan` during raw ingestion.

### 4.2 NaN Counts in Processed Parquet Files
A comprehensive scan of all numeric columns in `data/processed/CSE-CIC-IDS2018_v2/` revealed **191,520 remaining NaNs**:
- `Friday-02-03`: 8,100 NaNs
- `Friday-16-02`: 0 NaNs
- `Friday-23-02`: 11,416 NaNs
- `Thuesday-20-02`: 118,906 NaNs
- `Thursday-01-03`: 5,838 NaNs
- `Thursday-15-02`: 16,054 NaNs
- `Thursday-22-02`: 11,220 NaNs
- `Wednesday-14-02`: 7,648 NaNs
- `Wednesday-21-02`: 0 NaNs
- `Wednesday-28-02`: 12,338 NaNs
- **Total Remaining NaNs**: **191,520**

> [!IMPORTANT]
> **QA Clarification on Imputation**:
> Infinities were **replaced with NaN**, not globally imputed prior to Parquet export. This is **correct data engineering practice**: global imputation before splitting causes data leakage from test/validation distributions into training features. The Role 3 ML developer must fit `NumericalPreprocessor` (median strategy) **exclusively on the training partition**.

---

## 5. Investigation of UNSW-NB15 Partition Mapping

### 5.1 Physical File Inspection
- `UNSW_NB15_training-set.csv`: 82,332 records (IDs `1` to `82,332` sequential).
- `UNSW_NB15_testing-set.csv`: 175,341 records (IDs `1` to `99,999` and wrapping).
- `data/processed/UNSW-NB15/UNSW_NB15_training-set.parquet`: 82,332 records, 46 cols.
- `data/processed/UNSW-NB15/UNSW_NB15_testing-set.parquet`: 175,341 records, 46 cols.

### 5.2 Critical Literature & Mirror Discrepancy (Caveat 1)
In the original seminal publication (*Moustafa & Slay, 2015, "UNSW-NB15: a comprehensive data set for network intrusion detection systems"*, Military Communications and Information Systems Conference):
- The authors defined the **training set as 175,341 records (68%)** and the **testing set as 82,332 records (32%)**.
- However, public distribution mirrors (including Kaggle and IEEE DataPort mirrors) inadvertently inverted the filenames:
  - `UNSW_NB15_training-set.csv` contains the 82,332 records.
  - `UNSW_NB15_testing-set.csv` contains the 175,341 records.
- **QA Action**: Per QA protocol, filenames have **not been altered** to prevent broken paths. The Parquet outputs strictly preserve partition provenance via `_Source_File` and `_Split`. The Role 3 ML developer is explicitly informed in this report to decide whether to follow the physical file naming or the original academic paper protocol.

---

## 6. Preprocessing & Leakage Control Audit

### 6.1 `numerical_pipeline.py`
- Implements `NumericalPreprocessor` with explicit `fit()` and `transform()` methods.
- Verified that `transform()` checks `if not self.is_fitted: raise RuntimeError()`.
- Imputation medians, scaler means/standard deviations, and label encodings are computed only inside `fit()`.
- Verified in `test_fit_on_train_only_no_leakage`: test data with NaNs and infinities is transformed using training statistics without updating `fit_stats`.

### 6.2 `feature_policy.py` & Direct Identifiers
- Direct identifiers (`Flow ID`, `Src IP`, `Dst IP`) are marked as `role: "identifier"` and are strictly excluded by `get_cse_feature_columns()` and `get_cse_numeric_features()`.
- `Timestamp` is categorized as `role: "metadata"` and excluded from feature matrices.
- `Dst Port` is categorized as `role: "feature_assess"` and retained for service targeting evaluation.

### 6.3 Existing Baseline Splits Audit
- Existing files in `data/processed/splits/` (`train.parquet` [2,081,074 rows], `val.parquet` [314,568 rows], `test.parquet` [645,678 rows]) represent a total of **3,041,320 rows**.
- Provenance audit confirms these splits were produced from **only 4 of the 10 days** (Friday-16, Wednesday-21, Wednesday-28, Thursday-01) during Role 1 baseline modeling.
- The full 10-day dataset (16,232,943 rows) is stored in `data/processed/CSE-CIC-IDS2018_v2/`.

---

## 7. PCAP Extraction Validation (CTU-13 Scenario 1)

### 7.1 Verification Metrics
- **Input PCAP**: `botnet-capture-20110810-neris.pcap` (55.57 MB, 323,154 packets).
- **Execution Time**: 30.58 seconds via Scapy bidirectional flow engine (`pcap_extractor.py`).
- **Output File**: `data/processed/CTU-13/ctu13_scenario1_flows.parquet` (1.59 MB).
- **Extracted Flows**: **14,521 bidirectional flows** (43 columns).
- **Schema**: Validated 5-tuple, start/end timestamps, duration, packet/byte volumes, IAT statistics, and TCP flag counts (`FIN`, `SYN`, `RST`, `PSH`, `ACK`, `URG`).

### 7.2 Labeling Method & Environment Limitations (Caveat 2)
- Ground-truth labeling tags any flow communicating with the Neris botnet client `147.32.84.165` as `Botnet-Neris`.
- **Limitation**: In this specific Scenario 1 capture filter, all 14,521 extracted flows communicated with the infected host `147.32.84.165`. Therefore, the extracted dataset contains 100% `Botnet-Neris` flows and 0 benign background flows.
- **Scope Restriction**: The Scapy extractor has been validated on this CTU-13 capture only; no claims are made regarding other network environments or protocols.

---

## 8. Heterogeneous Telemetry Claims Audit

The extent of processing across heterogeneous non-flow telemetry was audited:
1. **LANL Cyber1 Red Team (`redteam.txt.gz`)**:
   - **Status**: **FULLY PARSED & EXPORTED TO PARQUET**.
   - Output: `data/processed/LANL/lanl_redteam_events.parquet` (749 events, 4 columns: `time`, `user_domain`, `src_computer`, `dst_computer`).
2. **CTU-13 CapTipper Web Telemetry (`botnet-capture-20110810-neris.json`)**:
   - **Status**: **FULLY PARSED & EXPORTED TO PARQUET**.
   - Output: `data/processed/CTU-13/ctu13_http_telemetry.parquet` (786 HTTP URI requests across 113 web sessions with SHA-256 hashes and methods).
3. **LANL Cyber1 DNS (`dns.txt.gz`)**:
   - **Status**: **INSPECTED & SAMPLED (100k Rows)**. Scanned time span `[2 - 150127]` and top host lookups; not converted into full Parquet.
4. **Windows EVTX Security Event Logs (`Friday-23-02-2018_logs.zip`)**:
   - **Status**: **ARCHIVE-VALIDATED & AUDITED**. 432 binary EVTX files (2,134.8 MB uncompressed) verified intact; individual XML events were not parsed into tabular features.
5. **MITRE ATT&CK STIX 2.1 Bundles**:
   - **Status**: **VERIFIED AS ISOLATED KNOWLEDGE REFERENCE**. Enterprise, Mobile, and ICS bundles audited for tactic and technique counts; strictly kept separate from flow records.

---

## 9. QA Caveats, Uncertainties & Recommendations

The following five caveats must be factored into Role 3 ML engineering:

1. **UNSW-NB15 Partition Name Inversion**: `UNSW_NB15_training-set.parquet` contains 82,332 records and `UNSW_NB15_testing-set.parquet` contains 175,341 records due to a historical upstream repository mirror swap. The Role 3 team must consciously decide whether to train on the 82k file or the 175k file.
2. **Remaining NaNs in Parquet**: 191,520 NaNs remain in `data/processed/CSE-CIC-IDS2018_v2/`. These are un-imputed by design to avoid global data leakage. Role 3 must fit `NumericalPreprocessor`'s median imputer strictly on the training partition.
3. **Existing Splits vs. Full 10-Day Dataset**: `data/processed/splits/` covers 4 days (3,041,320 rows). The complete 10-day dataset (16,232,943 rows) is in `data/processed/CSE-CIC-IDS2018_v2/`.
4. **CTU-13 Scenario 1 Class Homogeneity**: All 14,521 extracted flows in `ctu13_scenario1_flows.parquet` are labeled `Botnet-Neris`. For anomaly detection, these should be evaluated against benign flows from other days or combined with CSE benign traffic with domain adaptation.
5. **Windows EVTX & Full DNS Not Converted to Tabular Flows**: Windows host logs and full LANL DNS remain in their native formats and were not forced into network flow schemas (per project rules).

---

## 10. Final Sign-Off Recommendation

### Status: **PASS WITH CAVEATS**

**Justification**:
- All 16,233,002 CSE-CIC-IDS2018 records, 59 dropped headers, 131,799 replaced infinities, and 161,934 normalized labels are **100% mathematically reconciled**.
- All 9 automated unit and integration tests pass with zero failures.
- Zero memory leaks or crashes occurred during multi-gigabyte ingestion.
- Data leakage controls, feature policies, and schema separations are rigorously enforced.
- The 5 caveats are fully documented and do not impede modeling.

**Sign-off Granted**: October 22, 2026  
**Quality Assurance Lead**: Senior Data Engineering QA Engineer, Team Neural Breach
