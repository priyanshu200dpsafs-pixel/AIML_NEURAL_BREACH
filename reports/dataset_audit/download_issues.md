# Cybersecurity Data Collection: Download Issues & Technical Hurdles Log

**Project**: AI/ML-Based Cyber Defense Platform  
**Engineering Team**: Neural Breach  
**Auditor**: Senior Cybersecurity Data Acquisition Engineer  
**Last Updated**: 2026-10-22 08:05:00 UTC  

---

## 1. Upstream Mirror Bandwidth, Storage & Throttling Analysis

### Issue 1.1: AWS S3 Open Data (CSE-CIC-IDS2018)
- **Endpoint**: `https://cse-cic-ids2018.s3.amazonaws.com/`
- **S3 Bucket Path (CSVs)**: `Processed Traffic Data for ML Algorithms/`
- **S3 Bucket Path (PCAPs & Logs)**: `Original Network Traffic and Log data/`
- **Current Collection Status**:
  - **9 of 10 daily CSVs successfully acquired and verified**: Totaling **2.83 GB** (2,831,724,157 bytes) and **8,284,195 clean flow records** (14-02, 15-02, 16-02, 21-02, 22-02, 23-02, 28-02, 01-03, 02-03).
  - **1 daily Host Log Archive acquired**: `Friday-23-02-2018_logs.zip` (209,495,495 bytes) containing 432 Windows Event Log (`.evtx`) files from compromised endpoints.
- **Remaining CSV**:
  - Only 1 file remains on AWS S3: `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv` (4,054,925,350 bytes / ~4.05 GB). Publisher spelled Tuesday as "Thuesday". Requires ~2.5–3.5 hours transfer time.
- **Raw PCAP Footprint & Feasibility Assessment**:
  - Total official raw PCAP archive size: **477,321,665,202 bytes (444.54 GiB)** across 10 daily `.zip` / `.rar` archives.
  - **Architecture Decision**: Upstream raw PCAP archives (~444.5 GiB) remain in the AWS Open Data public repository (`s3://cse-cic-ids2018/`). The project ingests the official 80-feature CICFlowMeter flow datasets (16.23M records across all 10 days) which contain the standardized statistical network features for machine learning.
- **Host Logs Footprint**:
  - Total official host log archives: **1,932,428,474 bytes (1.80 GiB / 1.93 GB)** across 10 daily `logs.zip` archives (~133 MB to ~236 MB each). Manageable downloads can be performed incrementally.

### Issue 1.2: LANL Cyber1 Data-Fence Server Unresponsiveness
- **Endpoint**: `https://csr.lanl.gov/data-fence/<token>/cyber1/`
- **Current Server State**: Inactive / Connection Dropped.
  - Empirical probes to `csr.lanl.gov:443` (204.121.60.93) consistently fail with `[Errno 60] Operation timed out`.
  - The token generation endpoint `https://csr.lanl.gov/data-fence/token` is currently unreachable from external IP addresses.
- **Acquired & Verified**:
  - `dns.txt.gz` (185,104,940 bytes): 100% complete, passed `gzip -t` decompression, contains 40,821,591 DNS records.
  - `redteam.txt.gz` (4,846 bytes): 100% complete, contains 749 lateral movement compromise events across 104 users and 305 hosts.
- **Outstanding Files**:
  - `auth.txt.gz` (7.2 GB), `proc.txt.gz` (2.2 GB), and `flows.txt.gz` (1.1 GB) are currently unobtainable due to upstream server connection timeouts.

### Issue 1.3: Czech Technical University Mirror (CTU-13)
- **Endpoint**: `https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/`
- **Measured Transfer Speed**: ~230–360 KB/s
- **Complete 13-Scenario Archive**: `CTU-13-Dataset.tar.bz2` (1,997,547,391 bytes, ~1.86 GiB) confirmed available with HTTP 200 OK and resumable byte-range support.
- **Transfer Requirement**: Requires ~2.4 hours continuous download.
- **Preserved Baseline**: Scenario 1 Neris Botnet capture is 100% verified (323,154 packets, 55.57 MB PCAP, 14.04 MB JSON profile, 80.9 KB Argus filter).

---

## 2. Institutional Access Gates & Offline Mirrors

### Issue 2.1: UNB Primary Mirror Decommissioning (CIC-IDS2017 & CIC-DDoS2019)
- **Status**: `BLOCKED (Institutional Approval Required)`
- **Decommissioned URL**: `http://cicresearch.ca/` (205.174.165.80) is permanently offline.
- **Official Migration Path**: York University Behaviour-Centric Cybersecurity Center (BCCC) MachForm:
  `https://www.yorku.ca/research/bccc/ucs-technical/cybersecurity-datasets-cds/dataset-request/`
- **Required Information for Unlock**:
  1. Full Name & Academic/Organizational Affiliation
  2. Academic Supervisor / Lab Director Name
  3. Supervisor Institutional Email (`.edu`, `.ca`, `.ac.uk`)
  4. Non-commercial Research Purpose Statement

### Issue 2.2: UNSW-NB15 Raw Packet Captures OAuth Gate
- **Status**: `BLOCKED (OAuth Login Required)`
- **Gate URL**: `https://unsw-my.sharepoint.com/:f:/g/personal/z5025758_ad_unsw_edu_au/...`
- **Required Credentials**: Microsoft 365 Azure AD Single Sign-On (SSO) with authorized UNSW student/staff credentials.
- **Mitigation**: Official benchmark ML partitions (`training-set.csv` [82,332 rows], `testing-set.csv` [175,341 rows], 49-feature dictionary) are 100% verified and mirrored.

---

## 3. Discrepancy Reconciliation & Data Quality Log

### Issue 3.1: The 59 Repeated Header Lines in CSE-CIC-IDS2018
- **Finding**: Across the 9 verified CSVs (8,284,254 total data lines), exactly 59 lines contain repeated CSV headers (`Label == 'Label'`):
  - `Friday-16-02-2018`: 1 repeated header
  - `Wednesday-28-02-2018`: 33 repeated headers
  - `Thursday-01-03-2018`: 25 repeated headers
  - `14-02`, `15-02`, `21-02`, `22-02`, `23-02`, `02-03`: 0 repeated headers
- **Reconciliation Formula**:
  $$\text{Raw Lines (8,284,254)} - \text{Header Artifacts (59)} = \mathbf{8,284,195\text{ clean flow records}}$$

### Issue 3.2: Label Typographical Errors
- **Finding**: Exactly 161,934 records in `01-03-2018` and `28-02-2018` spell Infiltration as `Infilteration`.
- **Handling**: Raw files remain unaltered; normalization is mapped to `Infiltration` during Phase 2 ingestion.

### Issue 3.3: UNSW-NB15 Schema Realities
- **Finding**: Benchmark CSVs contain 44 columns with binary `label` (0 = Normal, 1 = Attack) rather than multi-class strings. Must be ingested as a binary intrusion classification benchmark.
