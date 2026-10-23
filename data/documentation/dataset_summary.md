# Dataset Summary & Attack Taxonomy Analysis

**Project**: AI/ML-Based Cyber Defense Platform  
**Team**: Neural Breach  
**Scope**: Intrusion Detection, Anomaly Detection, and Threat Intelligence Mapping  

---

## 1. High-Level Dataset Profiles

| Dataset | Primary Focus | Traffic Type | Key Protocols | Ground Truth Granularity | Format |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **MITRE ATT&CK** | Adversary Tactics & Techniques | Threat Intel Matrix | Enterprise, Mobile, ICS | Technique IDs (T1xxx), Mitigations | STIX 2.1 JSON |
| **CTU-13** | Botnet C&C & Malicious Flows | Mixed Real & Attack | TCP, UDP, ICMP, DNS, HTTP, IRC | Bidirectional NetFlows + Scenario PCAPs | Binetflow, PCAP, JSON |
| **LANL (cyber1)** | Enterprise Internal Movement | Host & NetFlow Events | Kerberos, NTLM, RPC, DNS, IP Flows | Event-level Red Team Timestamp Timelines | GZIP-compressed CSV |
| **UNSW-NB15** | Comprehensive Modern Attacks | Synthetic & Real Flows | TCP, UDP, OSPF, SCTP, IGMP, ARP | 45 Extracted Flow/Packet Features + 9 Classes | CSV & IXIA Raw PCAP |
| **CSE-CIC-IDS2018** | Large-Scale Enterprise Infrastructure | AWS Cloud Infrastructure | HTTP, HTTPS, FTP, SSH, SMTP, POP3 | 80 Extracted Flow Features (CICFlowMeter-V3) | CSV (10 days) & Raw PCAP |
| **CIC-IDS2017** | Baseline Modern IDS Benchmark | Multi-tier Testbed | HTTP, HTTPS, FTP, SSH, Email | 80 Extracted Flow Features + Raw Packets | CSV (Generated Flows) & PCAP |
| **CIC-DDoS2019** | Distributed Denial of Service | Volumetric & Application DDoS | UDP, TCP, NTP, DNS, LDAP, MSSQL, SNMP | 80+ Flow Features + Raw PCAPs | CSV & Raw PCAP |

---

## 2. Attack Category Coverage & Taxonomy Matrix

This matrix maps each attack category across all seven evaluated cybersecurity datasets:

| Attack Category | MITRE ATT&CK | CTU-13 | LANL cyber1 | UNSW-NB15 | CSE-CIC-IDS2018 | CIC-IDS2017 | CIC-DDoS2019 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Port Scanning & Reconnaissance** | ✅ (T1046) | ✅ (Murlo) | ⚠️ (In flows) | ✅ (Reconnaissance) | ✅ (PortScan) | ✅ (PortScan) | ⚠️ (Probing) |
| **Brute Force (SSH / FTP / Auth)** | ✅ (T1110) | ❌ | ✅ (Auth logs) | ✅ (Generic) | ✅ (SSH/FTP Brute) | ✅ (Brute Force) | ❌ |
| **Denial of Service (DoS)** | ✅ (T1498) | ⚠️ (Sogou) | ❌ | ✅ (DoS) | ✅ (GoldenEye, Hulk) | ✅ (Slowloris, Hulk) | ❌ |
| **Distributed DoS (DDoS)** | ✅ (T1498) | ✅ (Rbot DoS) | ❌ | ⚠️ (Volumetric) | ✅ (LOIC, HOIC) | ✅ (LOIC DDoS) | ✅ (12 Protocols) |
| **Botnets & C&C Communication** | ✅ (T1071) | ✅ (13 Botnets) | ⚠️ (In flows) | ⚠️ (Backdoors) | ✅ (Ares Botnet) | ✅ (Ares Botnet) | ❌ |
| **Web Application Attacks (SQLi, XSS)** | ✅ (T1190) | ❌ | ❌ | ✅ (Exploits) | ✅ (SQLi, XSS) | ✅ (SQLi, XSS) | ❌ |
| **Infiltration & Lateral Movement** | ✅ (T1021) | ⚠️ (P2P Botnet) | ✅ (Red Team) | ✅ (Worms) | ✅ (Dropbox Infiltration) | ✅ (Infiltration) | ❌ |
| **Zero-Day & Fuzzing Exploits** | ✅ (T1203) | ❌ | ❌ | ✅ (Fuzzers, Analysis) | ❌ | ❌ | ❌ |
| **Account Compromise & Privilege Escalation** | ✅ (T1078) | ❌ | ✅ (Red Team) | ⚠️ (Shellcode) | ❌ | ❌ | ❌ |
| **DNS Tunneling & Abuse** | ✅ (T1071.004) | ✅ (Fast Flux) | ✅ (dns.txt.gz) | ⚠️ (In DNS flows) | ❌ | ❌ | ✅ (DNS DDoS) |

*(Legend: ✅ Fully Covered with Ground Truth; ⚠️ Partially Present / Implicit; ❌ Not Included)*

---

## 3. Dataset Overlaps and Cross-Validation Strengths

1. **Botnet C&C Traffic (CTU-13 vs. CSE-CIC-IDS2018 / CIC-IDS2017)**:
   - **CTU-13** provides long-duration, live malware executions across 7 distinct botnet families (Neris, Rbot, Virut, Menti, Sogou, Murlo, NSIS.ay) capturing IRC, P2P, and HTTP command channels.
   - **CIC-IDS2017 / 2018** simulate the Ares Python-based botnet within controlled victim subnets.
   - *Cross-Validation Value*: Models trained on CTU-13 generalized flow behaviors can be tested against Ares botnet traffic in CIC datasets to verify detection generalizability.

2. **DDoS Attack Vectors (CIC-DDoS2019 vs. CSE-CIC-IDS2018 / CIC-IDS2017)**:
   - **CIC-DDoS2019** provides unmatched reflection and amplification depth (NTP, DNS, LDAP, MSSQL, TFTP, SNMP, SSDP, NetBIOS).
   - **CSE-CIC-IDS2018** focuses on volumetric application flooding (HOIC, LOIC-UDP, LOIC-HTTP).
   - *Cross-Validation Value*: Combining these datasets prevents ML overfitting to standard SYN floods by training models on complex UDP reflection dynamics.

3. **Multi-Stage Lateral Movement (LANL cyber1 vs. UNSW-NB15 / MITRE ATT&CK)**:
   - While network flow datasets focus on packet headers, **LANL cyber1** provides raw authentication timelines (`auth.txt.gz`) and ground-truth red team intrusions (`redteam.txt.gz`).
   - *Integration Value*: Allows the platform to correlate perimeter IDS alerts from UNSW-NB15 with internal authentication anomalies in LANL, cross-mapped to MITRE ATT&CK techniques (e.g., T1078 Valid Accounts, T1021 Remote Services).

---

## 4. Coverage Gaps & Engineering Recommendations

1. **Modern Encrypted Protocol Attacks (TLS 1.3 / QUIC / DoH)**:
   - Legacy benchmarks (CIC-IDS2017, UNSW-NB15) predominantly contain plaintext HTTP and unencrypted payloads. Modern threats employ Encrypted SNI (ESNI), TLS 1.3, and DNS over HTTPS (DoH).
   - *Recommendation*: Complement current models with flow statistical feature analysis (inter-arrival times, burst lengths) rather than deep packet inspection (DPI).
2. **Cloud-Native & Container Exploits**:
   - The evaluated datasets primarily represent traditional virtualized Windows/Linux subnets. Kubernetes API abuse, container escapes, and IAM credential abuse are unrepresented.
   - *Recommendation*: Use MITRE ATT&CK Cloud Matrix mappings as reference ground truth for future runtime security sensor development.
