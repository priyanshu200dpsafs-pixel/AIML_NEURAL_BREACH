# Cybersecurity Data Collection: Verification Issues & Gaps Log

**Project**: AI/ML-Based Cyber Defense Platform  
**Engineering Team**: Neural Breach  
**Audit Execution Timestamp**: 2026-10-21 16:28:51 UTC  

---

## 1. File Integrity & Corrupted Downloads

### Issue 1.1: LANL `dns.txt.gz` Truncated Download
- **File Path**: `Google Drive/data/raw/LANL/dns.txt.gz`
- **Current Size**: 29,129,566 bytes (~27.78 MB)
- **Expected Official Size**: 185,104,940 bytes (~185.10 MB)
- **Verification Result**: `gzip -t` failed with `unexpected end of file: uncompress failed`.
- **Root Cause**: Download was interrupted prematurely during historical collection.
- **Resolution Action**: The official tokenized endpoint (`https://csr.lanl.gov/data-fence/token`) is verified and functional, but server transfer speeds are throttled to ~70 KB/s (~44 min required). The partial file is marked CORRUPT_CHECKSUM_FAILED and excluded from training counts.

### Issue 1.2: CSE-CIC-IDS2018 `Friday-02-03-2018` Partial Download
- **File Path**: `Google Drive/data/raw/CSE-CIC-IDS2018/Friday-02-03-2018_TrafficForML_CICFlowMeter.csv.part`
- **Current Size**: 3,145,728 bytes (3.0 MB)
- **Expected Size**: 352,368,373 bytes (~352.37 MB)
- **Verification Result**: Unfinished temporary fragment (`.part`). Excluded from dataset totals.
- **Root Cause**: Previous ingestion script was stopped mid-transfer.

## 2. Upstream Access Gates & Decommissioned Endpoints

### Issue 2.1: CIC-IDS2017 & CIC-DDoS2019 UNB Server Decommissioning
- **Dataset**: CIC-IDS2017 & CIC-DDoS2019
- **Official Publisher**: Canadian Institute for Cybersecurity (UNB)
- **Observed Failure**: Direct download links pointing to `http://cicresearch.ca/` (IP: 205.174.165.80) are dead/offline.
- **Current Official Gate**: Downloads have migrated to York University Behaviour-Centric Cybersecurity Center (BCCC) MachForm.
- **Action Required**: Institutional request form submission with university/organization email and supervisor approval. Both datasets are marked `BLOCKED (Institutional Approval Required)`.

### Issue 2.2: UNSW-NB15 Raw PCAP SharePoint Authentication Gate
- **Dataset**: UNSW-NB15 Raw Packet Captures (~100 GB)
- **Official Publisher**: UNSW Canberra Cyber
- **Observed Gate**: The official PCAP link (`unsw-my.sharepoint.com`) enforces Microsoft SharePoint OAuth Single Sign-On.
- **Status**: While raw PCAPs are gated, the official partitioned benchmark CSV files (257,673 flows) and 49-feature dictionary are fully collected and verified.

## 3. Storage & Bandwidth Transfer Bottlenecks

### Issue 3.1: CSE-CIC-IDS2018 Raw PCAPs Upstream Storage Rationale
- **Upstream Archive**: ~400 GB raw PCAPs maintained in AWS Open Data S3 (`s3://cse-cic-ids2018/`)
- **Ingestion Strategy**: The raw packet captures remain upstream in S3. The collection is focused on the canonical pre-extracted 80-feature CICFlowMeter flow datasets (~7.0 GB, 16.23M rows), which provide the exact statistical features required for machine learning intrusion detection.

## 4. Raw Data Quality & Schema Anomalies for Downstream Team

### Issue 4.1: CSE-CIC-IDS2018 Repeated Header Artifact (59 Rows)
- **Discrepancy Reconciled**: 3,041,379 raw CSV lines - 59 repeated header lines = 3,041,320 clean flow records.
- **Affected Files**:
  - `Friday-16-02-2018`: 1 repeated header line
  - `Thursday-01-03-2018`: 25 repeated header lines
  - `Wednesday-28-02-2018`: 33 repeated header lines
- **Action for Next Team**: Data cleaning pipeline must filter rows where `Label == 'Label'` before numeric conversion.

### Issue 4.2: Label Typo Normalization ('Infilteration')
- **Occurrences**: Exactly 161,934 records across `Thursday-01-03-2018` (93,063) and `Wednesday-28-02-2018` (68,871) have label spelled `Infilteration`.
- **Action for Next Team**: Normalize string to `Infiltration`.

### Issue 4.3: Timestamp Formatting Inconsistencies
- **Occurrences**: `Friday-16-02-2018` and `Wednesday-28-02-2018` use `dd/MM/yyyy HH:mm:ss`, while `Wednesday-21-02-2018` uses `dd/MM/yyyy hh:mm:ss a` (12-hour AM/PM format).
- **Action for Next Team**: Use mixed-format datetime parsing or explicit format try/except.
