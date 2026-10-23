# Dataset Collection Technical Specifications & Access Audit

**AI/ML Cyber Defense Platform | Data Engineering Audit**  
**Team**: Neural Breach  
**Central Repository**: Google Drive Shared Dataset Hub  

---

## 1. Storage Architecture & Ingestion Strategy

To ensure reproducible, high-throughput machine learning without requiring team members to download multi-hundred-gigabyte raw packet captures locally, the data engineering pipeline adopts a tiered architecture:

1. **Central Cloud Hub**: All ingested raw CSVs, extracted flow Parquet files, benchmarks, and manifests are centrally archived in the team's shared Google Drive repository (~9.4 GB total).
2. **Local Repository Decoupling**: Git tracks only source code, manifests, tests, and documentation. Large datasets are synchronized on demand via `scripts/sync_data_drive.py`.
3. **Upstream Raw PCAP Retention**: For CSE-CIC-IDS2018, the raw packet captures (~400 GB) are maintained upstream in the AWS Open Data S3 bucket (`s3://cse-cic-ids2018/`). The official pre-extracted 80-feature CICFlowMeter flow datasets (16.23M records across all 10 days, ~7.0 GB) were collected and processed, providing the exact statistical flow features required for intrusion detection modeling.

---

## 2. Ingested Dataset Summary vs. Upstream Repositories

| Dataset | Ingested Format | Ingested Volume | Ingested Record / Packet Count | Upstream Source / Access Status |
| :--- | :--- | :---: | :---: | :--- |
| **CSE-CIC-IDS2018 (Flows)**| CSV / Parquet | ~7.0 GB / 2.04 GB | **16,232,943 flows** (10 Days) | Ingested from AWS Open Data bucket |
| **CSE-CIC-IDS2018 (Raw PCAP)**| Upstream S3 | ~400 GB | 10 Days Raw PCAP | Maintained in public AWS S3 bucket (`s3://cse-cic-ids2018/`) |
| **UNSW-NB15 (Partitions)** | CSV / Parquet | ~42 MB | **257,673 flows** (Train/Test) | Ingested official benchmark partitions |
| **UNSW-NB15 (Raw PCAP)** | Raw IXIA PCAP | ~100 GB | Multi-day raw captures | Blocked behind UNSW Microsoft 365 OAuth |
| **CTU-13 (Scenario 1)** | PCAP & JSON | ~70 MB | **323,154 packets / 14,521 flows**| Ingested; bidirectional flows extracted via Scapy |
| **LANL Cyber1 (Red Team)** | Parquet / GZ | ~5 KB | **749 compromise events** | Ingested ground-truth compromise timeline |
| **LANL Cyber1 (DNS)** | GZIP CSV | ~176 MB | 100k sample audited | Ingested enterprise DNS queries |
| **Windows EVTX (Host Logs)**| ZIP Archive | ~200 MB (2.1 GB uncompressed)| 432 host event log files | Ingested endpoint event logs |
| **MITRE ATT&CK** | STIX 2.1 JSON | ~63.5 MB | 31,940 objects | Ingested Enterprise, Mobile, and ICS matrices |
| **CIC-IDS2017** | PCAP + Flow CSV | Upstream Archive | Full capture archive | Institutional approval gate (York BCCC MachForm) |
| **CIC-DDoS2019** | PCAP + Flow CSV | Upstream Archive | Full capture archive | Institutional approval gate (York BCCC MachForm) |

---

## 3. Institutional Access Gates & Upstream Restrictions

### Issue A: CIC-IDS2017 & CIC-DDoS2019 Approval Gate
- **Authoring Body**: Canadian Institute for Cybersecurity (UNB) & York University BCCC
- **Historical URL**: `http://205.174.165.80/CICDataset/` (Permanently decommissioned).
- **Current Access Gate**: Hosting was migrated to York University's Behaviour-Centric Cybersecurity Center (BCCC) under Prof. Arash Habibi Lashkari.
- **Requirement**: Institutional request form via York BCCC MachForm (`//laps.apps01.yorku.ca/machform/embed.php?id=2189259`). Requires institutional email and academic non-redistribution agreement.
- **Status**: Request submitted; awaiting token distribution. Detailed gate specifications preserved in `data/raw/CIC-IDS2017/README_ACCESS_GATE.md` and `data/raw/CIC-DDoS2019/README_ACCESS_GATE.md`.

### Issue B: UNSW-NB15 Raw PCAPs OAuth Gate
- **Authoring Body**: Australian Centre for Cyber Security (ACCS), UNSW Canberra
- **Historical Mirror**: `https://cloudstor.aarnet.edu.au/` (Decommissioned nationwide).
- **Current Access Gate**: Hosted on UNSW SharePoint requiring institutional Microsoft 365 OAuth authentication.
- **Status**: Raw ~100 GB PCAPs remain gated. The verified official 44-feature benchmark training and testing partitions (257,673 records) were collected and processed into Parquet.
