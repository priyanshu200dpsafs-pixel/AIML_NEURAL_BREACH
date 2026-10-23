# Team Neural Breach — Phase 1 Final Data Collection & Handoff Report
**AI/ML-Based Cyber Defense Platform**  
**Engineering Team:** Neural Breach  
**Status:** 100% COMPLETE & VERIFIED  
**Timestamp:** 2026-10-22 18:50 UTC  
**Primary Central Hub:** Google Drive Central Repository (`aiml_project_team_neural_breach/`)  
**Project Workspace:** Local Repository Clone  

---

## Executive Summary

Phase 1 (Public Cybersecurity Data Collection & Verification) is **100% complete**. All accessible public cybersecurity benchmark datasets, threat intelligence matrices, and raw captures have been acquired, cryptographically verified via SHA-256, structurally validated, and synchronized across Google Drive and local project storage with **zero data loss**.

### Highlights:
* **CSE-CIC-IDS2018 Complete Suite:** All 10 daily CICFlowMeter CSV files and Windows Event logs (`Friday-23-02-2018_logs.zip`) are fully downloaded, verified, and mirrored.
* **Network Flow Scale:** **16,232,943 verified clean CSE-CIC-IDS2018 flows** + **254,004 UNSW-NB15 flows** = **16,486,947 total network flow records**.
* **Benign Traffic Baseline:** **13,484,708 clean benign flows** (83.07%), providing exceptional statistical stability for anomaly detection and baseline model training.
* **Adversarial Diversity:** 14 distinct attack classes spanning volumetric DDoS (HOIC, LOIC-HTTP, LOIC-UDP), DoS (Hulk, SlowHTTPTest, GoldenEye, Slowloris), Web Application Attacks (BruteForce-Web, BruteForce-XSS, SQL Injection), Protocol Attacks (FTP-BruteForce, SSH-Bruteforce), Infiltration, and Botnets.
* **Host & Telemetry Depth:** 432 Windows Event Logs (`.evtx`), 40,821,591 enterprise DNS queries, 749 Los Alamos National Lab red team compromise events, 323,154 raw botnet packets (Neris PCAP), and 31,940 MITRE ATT&CK STIX 2.1 threat objects.

---

## Final Dataset Inventory & Metrics

| Dataset | Files | Storage Size | Clean Verified Records | Key Attack Classes / Content |
|---|---|---|---|---|
| **CSE-CIC-IDS2018 Flow CSVs** | 10 | 7.125 GB | **16,232,943 clean flows** | DDoS (HOIC/LOIC), DoS (Hulk/Slowloris/GoldenEye), BruteForce (FTP/SSH/Web/XSS), SQLi, Bot, Infiltration |
| **CSE-CIC-IDS2018 Host Logs** | 1 (.zip) | 209.5 MB | **432 `.evtx` event logs** | Full Windows host event logs for attack day Friday-23-02-2018 |
| **UNSW-NB15 Benchmark** | 3 (.csv) | 44.5 MB | **254,004 flow records** | 9 modern attack families (Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Recon, Security, Worms) |
| **LANL Cyber1 Enterprise** | 2 (.gz) | 185.1 MB | **40,822,340 events** | 40,821,591 DNS lookups + 749 ground-truth Red Team compromise events |
| **CTU-13 Neris Botnet** | 2 | 73.0 MB | **323,154 packets / Argus** | Ground-truth Neris IRC Botnet PCAP + bidirectional Argus JSON flows |
| **MITRE ATT&CK STIX 2.1** | 3 (.json) | 66.6 MB | **31,940 objects** | Enterprise (23,298), ICS (3,788), and Mobile (4,854) threat matrices |
| **Total Verified Data** | **21 primary** | **7.704 GB** | **57.9M+ total events** | **Zero missing bytes; 100% cryptographic verification** |

---

## Detailed CSE-CIC-IDS2018 Breakdown

| Date File | Uncompressed Size | Verified Rows | Repeated Headers | Clean Flows | Dominant Labels |
|---|---|---|---|---|---|
| `Wednesday-14-02-2018` | 341.6 MB | 1,048,575 | 0 | 1,048,575 | Benign (667,626), FTP-BruteForce (193,360), SSH-Bruteforce (187,589) |
| `Thursday-15-02-2018` | 358.5 MB | 1,048,575 | 0 | 1,048,575 | Benign (996,077), DoS-GoldenEye (41,508), DoS-Slowloris (10,990) |
| `Friday-16-02-2018` | 318.3 MB | 1,048,575 | 1 | 1,048,574 | DoS-Hulk (461,912), Benign (446,772), DoS-SlowHTTPTest (139,890) |
| `Thuesday-20-02-2018` | 3,867.1 MB | 7,948,748 | 0 | 7,948,748 | Benign (7,372,557), DDoS attacks-LOIC-HTTP (576,191) |
| `Wednesday-21-02-2018` | 313.7 MB | 1,048,575 | 0 | 1,048,575 | DDOS-HOIC (686,012), Benign (360,833), DDOS-LOIC-UDP (1,730) |
| `Thursday-22-02-2018` | 364.9 MB | 1,048,575 | 0 | 1,048,575 | Benign (1,048,213), Brute Force -Web (249), Brute Force -XSS (79), SQLi (34) |
| `Friday-23-02-2018` | 365.1 MB | 1,048,575 | 0 | 1,048,575 | Benign (1,048,009), Brute Force -Web (362), Brute Force -XSS (151), SQLi (53) |
| `Wednesday-28-02-2018` | 199.6 MB | 613,104 | 33 | 613,071 | Benign (544,200), Infilteration (68,871) |
| `Thursday-01-03-2018` | 102.8 MB | 331,125 | 25 | 331,100 | Benign (238,037), Infilteration (93,063) |
| `Friday-02-03-2018` | 336.0 MB | 1,048,575 | 0 | 1,048,575 | Benign (762,384), Bot (286,191) |
| **Total CSE-CIC-IDS2018** | **7.125 GB** | **16,233,002** | **59** | **16,232,943** | **83.07% Benign, 16.93% Attack** |

---

## Ready for Phase 2: Preprocessing & Modeling Handoff
1. **Clean Training Splits:** Available in `data/processed/splits/` (`train.parquet`, `val.parquet`, `test.parquet`).
2. **Team Onboarding:** Detailed in `TEAM_DATASET_ACCESS_GUIDE.md`.
3. **Data Integrity:** 100% verified with SHA-256 checksums recorded in `actual_file_inventory.csv`.
