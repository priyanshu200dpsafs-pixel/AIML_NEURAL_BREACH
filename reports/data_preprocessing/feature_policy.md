# Network Feature Policy & Treatment Specification
**Project: AI/ML-Based Cyber Defense Platform**  
**Team: Neural Breach — Role 2: Network Feature Extraction & Preprocessing**  
**Date**: October 22, 2026  
**Status**: APPROVED & FROZEN FOR ROLE 3 (ML MODEL DEVELOPMENT)

---

## 1. Executive Policy Overview

This document specifies the exact role, mathematical type, expected units, and usage policies for every feature extracted across our platform's network traffic datasets:
1. **CSE-CIC-IDS2018** (80-column standard CICFlowMeter flows + 84-column extended schema)
2. **UNSW-NB15** (44-column partitioned benchmark set)
3. **CTU-13 Scenario 1** (Bidirectional flow records extracted via Scapy)

The primary goal of this policy is to prevent **data leakage**, prevent **overfitting to synthetic lab network topologies**, and provide **interpretable, high-signal security features** to downstream machine-learning models.

---

## 2. Core Treatment Guidelines

### 2.1 Direct Identifiers (IP Addresses & Flow IDs)
- **Policy**: `EXCLUDE FROM MODEL TRAINING`
- **Rationale**: IP addresses (e.g. `192.168.1.x`, `172.31.x.x`, `147.32.84.165`) reflect the specific private IP addressing of the testbed infrastructure. If models train on IP addresses, they learn to classify IP strings rather than malicious behavioral patterns, resulting in 100% false positives when deployed in new networks.
- **Handling**: Preserved strictly as metadata (`_Source_File`, `Src IP`, `Dst IP`, `Flow ID`) in Parquet files for SOC analyst triage and forensic event tracing.

### 2.2 Network Ports (`Dst Port` and `Src Port`)
- **Policy**: `ASSESS AND STRATIFY`
- **Destination Port (`Dst Port`)**: **RETAIN AS HIGH-VALUE SECURITY FEATURE**. Cyber attacks inherently target specific well-known service ports:
  - SSH Brute Force → Port 22
  - FTP Brute Force → Port 21
  - HTTP / Web Attacks → Port 80
  - HTTPS / TLS Exfiltration → Port 443
  - DNS Tunneling / Amplification → Port 53
- **Source Port (`Src Port`)**: Typically ephemeral ports (>1024) randomized by client operating systems. Preserved in raw/metadata, but downstream ML models should test feature importance with and without source ports to avoid spurious correlations.

### 2.3 Timestamps
- **Policy**: `PRESERVE AS METADATA / TEMPORAL PARTITIONING`
- **Handling**: Preserved in raw format (`DD/MM/YYYY HH:MM:SS`) and converted to UTC epoch integers. Excluded from predictive feature vectors to prevent chronological memorization. Used strictly for chronological train/validation/test split partitioning.

### 2.4 Infinite & Non-Numeric Values
- **Policy**: `MANDATORY REPLACEMENT & IMPUTATION`
- Zero-duration flows produce mathematical infinities in `Flow Byts/s` and `Flow Pkts/s` ($\frac{\text{bytes}}{0}$).
- **Standard**: All representations of infinity (`inf`, `-inf`, `Infinity`) are replaced with `np.nan` during initial ingestion.
- Imputation statistics (median strategy) must be **fitted on the training set only** and applied to validation/test sets without refitting.

---

## 3. CSE-CIC-IDS2018 Feature Policy Table

| Column Name | Category | Role | Data Type | Units / Encoding | Missing / Inf Handling | Usage Notes & Security Value |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `Dst Port` | Network Address | **Feature (Assess)** | Float64 / Int | TCP/UDP Port (0–65535) | Zero-filled if missing | Primary service indicator (21, 22, 80, 443, 8080). |
| `Protocol` | Protocol Layer | **Feature** | Float64 (Categorical) | IP Proto (0, 6=TCP, 17=UDP) | Strict integer | Protocol identification; one-hot or label encoded. |
| `Timestamp` | Metadata | **Metadata Only** | String | `DD/MM/YYYY HH:MM:SS` | Unchanged | For chronological ordering; excluded from feature vector. |
| `Flow Duration` | Flow Metric | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Total duration of flow. DoS often exhibits extreme duration. |
| `Tot Fwd Pkts` | Packet Counts | **Predictive Feature** | Float64 | Packet Count | Imputed (median) | Forward packet volume. High in volumetric DDoS. |
| `Tot Bwd Pkts` | Packet Counts | **Predictive Feature** | Float64 | Packet Count | Imputed (median) | Backward packet volume. Low in unidirectional SYN floods. |
| `TotLen Fwd Pkts` | Byte Volume | **Predictive Feature** | Float64 | Total Bytes | Imputed (median) | Forward volume payload. |
| `TotLen Bwd Pkts` | Byte Volume | **Predictive Feature** | Float64 | Total Bytes | Imputed (median) | Backward volume payload. Exfiltration vs download signature. |
| `Fwd Pkt Len Max` | Packet Length | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Max packet size in forward direction. |
| `Fwd Pkt Len Min` | Packet Length | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Min packet size in forward direction. |
| `Fwd Pkt Len Mean`| Packet Length | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Average forward packet payload size. |
| `Fwd Pkt Len Std` | Packet Length | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Packet size variance. Automated bots have uniform sizes. |
| `Bwd Pkt Len Max` | Packet Length | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Max response packet size. |
| `Bwd Pkt Len Min` | Packet Length | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Min response packet size. |
| `Bwd Pkt Len Mean`| Packet Length | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Mean response packet size. |
| `Bwd Pkt Len Std` | Packet Length | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Response packet length variance. |
| `Flow Byts/s` | Flow Rate | **Predictive Feature** | Float64 | Bytes / Second | **Inf $\to$ NaN $\to$ Median** | High in exfiltration and flooding. Frequently contains `inf`. |
| `Flow Pkts/s` | Flow Rate | **Predictive Feature** | Float64 | Packets / Second | **Inf $\to$ NaN $\to$ Median** | High in packet storms and SYN floods. Frequently `inf`. |
| `Flow IAT Mean` | Timing / IAT | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Mean inter-arrival time. Beacons exhibit regular IAT. |
| `Flow IAT Std` | Timing / IAT | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | IAT jitter/variance. Low variance signals C&C heartbeat. |
| `Flow IAT Max` | Timing / IAT | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Max pause between packets. |
| `Flow IAT Min` | Timing / IAT | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Minimum interval between packets. |
| `Fwd IAT Tot` | Timing / IAT | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Total forward inter-arrival time. |
| `Fwd IAT Mean` | Timing / IAT | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Mean forward inter-arrival time. |
| `Fwd IAT Std` | Timing / IAT | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Standard deviation of forward IAT. |
| `Fwd IAT Max` | Timing / IAT | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Max forward IAT. |
| `Fwd IAT Min` | Timing / IAT | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Min forward IAT. |
| `Bwd IAT Tot` | Timing / IAT | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Total backward inter-arrival time. |
| `Bwd IAT Mean` | Timing / IAT | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Mean backward inter-arrival time. |
| `Bwd IAT Std` | Timing / IAT | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Backward IAT standard deviation. |
| `Bwd IAT Max` | Timing / IAT | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Max backward IAT. |
| `Bwd IAT Min` | Timing / IAT | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Min backward IAT. |
| `Fwd PSH Flags` | TCP Control | **Predictive Feature** | Float64 | Binary Count | Strict 0 or 1 | Push flag forward. |
| `Bwd PSH Flags` | TCP Control | **Predictive Feature** | Float64 | Binary Count | Strict 0 or 1 | Push flag backward. |
| `Fwd URG Flags` | TCP Control | **Predictive Feature** | Float64 | Binary Count | Strict 0 or 1 | Urgent flag forward. |
| `Bwd URG Flags` | TCP Control | **Predictive Feature** | Float64 | Binary Count | Strict 0 or 1 | Urgent flag backward. |
| `Fwd Header Len`| TCP Control | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Total forward header size. |
| `Bwd Header Len`| TCP Control | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Total backward header size. |
| `Fwd Pkts/s` | Rate Metric | **Predictive Feature** | Float64 | Packets / Second | Imputed (median) | Forward packet transmission rate. |
| `Bwd Pkts/s` | Rate Metric | **Predictive Feature** | Float64 | Packets / Second | Imputed (median) | Backward packet transmission rate. |
| `Pkt Len Min` | Packet Length | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Overall flow minimum packet length. |
| `Pkt Len Max` | Packet Length | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Overall flow maximum packet length. |
| `Pkt Len Mean`| Packet Length | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Overall flow mean packet length. |
| `Pkt Len Std` | Packet Length | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Overall flow packet length standard deviation. |
| `Pkt Len Var` | Packet Length | **Predictive Feature** | Float64 | Bytes squared | Imputed (median) | Packet length variance. |
| `FIN Flag Cnt` | TCP Control | **Predictive Feature** | Float64 | Count | Strict integer count | Connection teardown frequency. Abnormal in port scans. |
| `SYN Flag Cnt` | TCP Control | **Predictive Feature** | Float64 | Count | Strict integer count | Connection initiation. Spikes in SYN floods and scans. |
| `RST Flag Cnt` | TCP Control | **Predictive Feature** | Float64 | Count | Strict integer count | Connection rejection. High in port scanners hitting closed ports. |
| `PSH Flag Cnt` | TCP Control | **Predictive Feature** | Float64 | Count | Strict integer count | Immediate application data push. |
| `ACK Flag Cnt` | TCP Control | **Predictive Feature** | Float64 | Count | Strict integer count | Acknowledgment count. |
| `URG Flag Cnt` | TCP Control | **Predictive Feature** | Float64 | Count | Strict integer count | Urgent flag count. |
| `CWE Flag Count`| TCP Control | **Predictive Feature** | Float64 | Count | Strict integer count | Congestion window reduced flags. |
| `ECE Flag Cnt` | TCP Control | **Predictive Feature** | Float64 | Count | Strict integer count | Explicit congestion notification echo. |
| `Down/Up Ratio` | Ratio Metric | **Predictive Feature** | Float64 | Unitless ratio | Imputed (median) | Ratio of download to upload packets. |
| `Pkt Size Avg` | Packet Length | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Average packet size across entire flow. |
| `Fwd Seg Size Avg`| Packet Length | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Average forward segment size. |
| `Bwd Seg Size Avg`| Packet Length | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Average backward segment size. |
| `Fwd Byts/b Avg`| Subflow Metric | **Zero Variance** | Float64 | Bytes / block | Constant 0 (Drop) | CICFlowMeter artifact; constant zero. |
| `Fwd Pkts/b Avg`| Subflow Metric | **Zero Variance** | Float64 | Packets / block | Constant 0 (Drop) | CICFlowMeter artifact; constant zero. |
| `Fwd Blk Rate Avg`| Subflow Metric | **Zero Variance** | Float64 | Blocks / sec | Constant 0 (Drop) | CICFlowMeter artifact; constant zero. |
| `Bwd Byts/b Avg`| Subflow Metric | **Zero Variance** | Float64 | Bytes / block | Constant 0 (Drop) | CICFlowMeter artifact; constant zero. |
| `Bwd Pkts/b Avg`| Subflow Metric | **Zero Variance** | Float64 | Packets / block | Constant 0 (Drop) | CICFlowMeter artifact; constant zero. |
| `Bwd Blk Rate Avg`| Subflow Metric | **Zero Variance** | Float64 | Blocks / sec | Constant 0 (Drop) | CICFlowMeter artifact; constant zero. |
| `Subflow Fwd Pkts`| Subflow Metric | **Predictive Feature** | Float64 | Packet Count | Imputed (median) | Subflow forward packets. |
| `Subflow Fwd Byts`| Subflow Metric | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Subflow forward bytes. |
| `Subflow Bwd Pkts`| Subflow Metric | **Predictive Feature** | Float64 | Packet Count | Imputed (median) | Subflow backward packets. |
| `Subflow Bwd Byts`| Subflow Metric | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Subflow backward bytes. |
| `Init Fwd Win Byts`| Window Size | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Initial forward TCP window size. High fingerprinting value. |
| `Init Bwd Win Byts`| Window Size | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Initial backward TCP window size. OS stack fingerprinting. |
| `Fwd Act Data Pkts`| Packet Counts | **Predictive Feature** | Float64 | Packet Count | Imputed (median) | Forward packets containing at least 1 byte of payload. |
| `Fwd Seg Size Min`| Packet Length | **Predictive Feature** | Float64 | Bytes | Imputed (median) | Minimum segment size observed forward. |
| `Active Mean` | State Metric | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Mean time flow was active before becoming idle. |
| `Active Std` | State Metric | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Standard deviation of active time. |
| `Active Max` | State Metric | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Max duration flow was active. |
| `Active Min` | State Metric | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Min duration flow was active. |
| `Idle Mean` | State Metric | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Mean duration flow was idle between bursts. |
| `Idle Std` | State Metric | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Standard deviation of idle time. |
| `Idle Max` | State Metric | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Max idle duration. |
| `Idle Min` | State Metric | **Predictive Feature** | Float64 | Microseconds ($\mu s$) | Imputed (median) | Min idle duration. |
| `Label` | Ground Truth | **Target Label** | String | Standard Class Name | N/A | Target variable for supervised classification. |
| `_Raw_Label` | Provenance | **Audit Provenance** | String | Original string | N/A | Preserves raw CSV string (e.g. `Infilteration`). |
| `_Clean_Label` | Provenance | **Audit Provenance** | String | Normalized string | N/A | Normalized class label (`Infiltration`). |
| `_Source_File` | Provenance | **Audit Provenance** | String | Filename | N/A | Identifies which daily capture produced the record. |

---

## 4. UNSW-NB15 Feature Policy & Separation Rule

### 4.1 Strict Segregation Mandate
- **Rule**: `UNSW-NB15 MUST NEVER BE CONCATENATED WITH CSE-CIC-IDS2018`.
- **Reason**: UNSW-NB15 features (e.g., `sload`, `dload`, `ct_srv_src`, `ct_state_ttl`) are synthesized connection-window state metrics computed by Argus and Bro-IDS. They do not map 1:1 onto CICFlowMeter features. Merging them produces an invalid hybrid dataset with 50%+ structural nulls and corrupted feature distributions.
- **Official Partitions**:
  - `UNSW_NB15_training-set.parquet`: 82,332 records
  - `UNSW_NB15_testing-set.parquet`: 175,341 records

### 4.2 UNSW-NB15 Column Treatments
- **Direct Identifiers**: Excluded in benchmark release (no IP addresses present in `UNSW_NB15_*.csv`). `id` is an integer row index and must be excluded from feature vectors.
- **Categoricals**: `xProt` (Protocol), `xServ` (Service), `xState` (State). In the official CSVs, these are integer-encoded indices. They should be treated as categorical factors.
- **Window Aggregations**: Features prefixed with `ct_` (e.g. `ct_srv_src`, `ct_dst_ltm`, `ct_src_dport_ltm`) represent connection counts within 100-connection windows. Retain as high-signal features for reconnaissance and scanning detection.
- **Target Variable**: `label` (Binary: 0=Normal, 1=Attack).
