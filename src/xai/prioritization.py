#!/usr/bin/env python3
"""
Threat Prioritization & SOC Analyst Recommendation Engine
Team Neural Breach — Role 5: XAI & Threat Intelligence

Computes transparent, explainable alert priority levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
and generates tailored investigation playbooks and SIEM/hunting queries for SOC analysts.
"""

from typing import Dict, Any, List, Optional


# Base severity weightings calibrated for enterprise threat triage (0 - 100 scale)
ATTACK_BASE_SEVERITY: Dict[str, float] = {
    "Infiltration": 95.0,
    "SQL Injection": 90.0,
    "Bot": 90.0,
    "DDOS attack-HOIC": 85.0,
    "DDOS attack-LOIC-UDP": 85.0,
    "DDoS attacks-LOIC-HTTP": 80.0,
    "DoS attacks-GoldenEye": 75.0,
    "DoS attacks-Hulk": 75.0,
    "DoS attacks-SlowHTTPTest": 70.0,
    "DoS attacks-Slowloris": 70.0,
    "SSH-Bruteforce": 65.0,
    "FTP-BruteForce": 60.0,
    "Brute Force -Web": 60.0,
    "Brute Force -XSS": 60.0,
    "SUSPICIOUS_ANOMALY": 65.0,
    "Benign": 0.0
}

# Tailored SOC investigation playbooks by attack type
SOC_PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "Infiltration": {
        "investigation_steps": [
            "Verify source IP host identity and check for recent vulnerability scan activity against the target endpoint.",
            "Inspect target host endpoint logs (Windows EVTX Event ID 4688 / Sysmon Event ID 1) for abnormal child process spawning.",
            "Cross-reference LANL/internal telemetry to identify unauthorized lateral SMB, RDP, or SSH connections originating from the target host.",
            "Check for newly created user accounts or privilege escalation events (Event ID 4720, 4672)."
        ],
        "containment_playbook": [
            "OBSERVE-ONLY NOTICE: Automated inline blocking is disabled.",
            "Alert SOC Tier 2 Lead immediately of suspected initial access / infiltration vector.",
            "Prepare endpoint network isolation order (EDR host quarantine) pending human authorization.",
            "Snapshot memory and running processes on the destination workstation for forensic analysis."
        ],
        "telemetry_queries": [
            "SELECT timestamp, src_ip, dst_ip, process_name, command_line FROM endpoint_telemetry WHERE dst_ip = '{dst_ip}' AND timestamp >= '{ts_window_start}' ORDER BY timestamp ASC;",
            "Sysmon | where EventID == 1 and Computer == '{target_host}' | project TimeGenerated, Image, CommandLine, ParentImage"
        ]
    },
    "Bot": {
        "investigation_steps": [
            "Review DNS query logs for anomalous domain generation algorithm (DGA) lookups or unusual fast-flux domains.",
            "Check flow beaconing frequency: analyze periodic inter-arrival times (Flow IAT Mean) consistent with automated heartbeats.",
            "Identify the internal host IP initiating the outbound session and verify active processes holding open socket handles.",
            "Correlate destination IP with public threat intelligence feeds (AlienVault OTX, VirusTotal, AbuseIPDB)."
        ],
        "containment_playbook": [
            "OBSERVE-ONLY NOTICE: Maintain continuous telemetry recording.",
            "Formulate firewall egress sinkhole rule for destination C2 IP/domain for operator sign-off.",
            "Instruct host administrators to perform malware scan on affected internal host endpoint."
        ],
        "telemetry_queries": [
            "SELECT query_name, count(*) as query_count FROM dns_logs WHERE client_ip = '{src_ip}' GROUP BY query_name ORDER BY query_count DESC LIMIT 25;",
            "NetworkFlows | where SourceIP == '{src_ip}' | summarize Count=count(), DistinctDstPorts=dcount(DestinationPort) by DestinationIP, bin(TimeGenerated, 5m)"
        ]
    },
    "SQL Injection": {
        "investigation_steps": [
            "Inspect web application gateway / reverse proxy access logs for HTTP GET/POST parameters containing SQL meta-characters (' OR 1=1, UNION SELECT, --, /*).",
            "Examine backend database query logs for syntax errors, unexpected schema dumps (information_schema), or high-volume data retrieval.",
            "Check whether the destination web application returned HTTP 500 Internal Server Error (indicative of error-based SQLi) or HTTP 200 with anomalous payload size."
        ],
        "containment_playbook": [
            "OBSERVE-ONLY NOTICE: Automated packet dropping is disengaged.",
            "Escalate to Application Security team for urgent code review and database statement parameterization.",
            "Draft targeted WAF virtual patch / regex rule blocking specific payload signature for operational review."
        ],
        "telemetry_queries": [
            "SELECT c_ip, cs_method, cs_uri_stem, cs_uri_query, sc_status, sc_bytes FROM w3c_web_logs WHERE cs_uri_query LIKE '%UNION%' OR cs_uri_query LIKE '%SELECT%' LIMIT 50;",
            "W3CIISLog | where csUriQuery matches regex '(?i)(union.*select|exec.*xp_cmdshell|1=1)' | project TimeGenerated, cIP, csMethod, csUriStem, csUriQuery"
        ]
    },
    "DDOS attack-HOIC": {
        "investigation_steps": [
            "Monitor destination edge router interface bandwidth and packet drop counters to gauge saturation levels.",
            "Verify whether source IP addresses are distributed across multiple autonomous systems (ASNs) indicating botnet participation.",
            "Inspect HTTP User-Agent headers in packet telemetry for known HOIC default strings or random 8-character booster scripts."
        ],
        "containment_playbook": [
            "OBSERVE-ONLY NOTICE: Automated inline blocking is disabled.",
            "Notify Upstream ISP / Tier-1 Transit provider of active incoming volumetric DDoS flood.",
            "Prepare BGP Flowspec or Cloudflare/AWS Shield scrubbing center diversion route if flood threatens link saturation."
        ],
        "telemetry_queries": [
            "SELECT dst_port, count(distinct src_ip) as distinct_sources, sum(flow_bytes) as total_bytes FROM flow_records WHERE dst_ip = '{dst_ip}' GROUP BY dst_port;",
            "NetFlow | where DestinationIP == '{dst_ip}' | summarize Bps = sum(Bytes)*8/300 by bin(TimeGenerated, 5m), Protocol"
        ]
    },
    "DDOS attack-LOIC-UDP": {
        "investigation_steps": [
            "Check destination port distribution to identify whether attack is targeting specific UDP services (e.g., DNS port 53, NTP 123) or sweeping random high ports.",
            "Inspect border router NetFlow telemetry for sudden spikes in UDP packet velocity and negligible return traffic.",
            "Verify if internal firewall state tables are reaching maximum concurrent session limits."
        ],
        "containment_playbook": [
            "OBSERVE-ONLY NOTICE: Observe-only mode active.",
            "Formulate border router rate-limiting ACL for incoming UDP traffic destined to the targeted subnet.",
            "Alert network operations center (NOC) of incoming UDP datagram flood."
        ],
        "telemetry_queries": [
            "SELECT protocol, sum(flow_pkts) as total_packets, sum(flow_bytes) as total_bytes FROM flows WHERE protocol = 17 AND dst_ip = '{dst_ip}' GROUP BY protocol;"
        ]
    },
    "DDoS attacks-LOIC-HTTP": {
        "investigation_steps": [
            "Inspect web server worker thread pool utilization (Apache mod_status / NGINX stub_status).",
            "Examine HTTP request frequency per source IP: check for clients generating > 50 requests/second with identical static headers.",
            "Verify whether responses are returning HTTP 503 Service Unavailable or connection timeouts."
        ],
        "containment_playbook": [
            "OBSERVE-ONLY NOTICE: Automated packet dropping is disengaged.",
            "Enable reverse proxy aggressive client connection throttling and JavaScript challenge mode (Cloudflare/WAF Under-Attack Mode).",
            "Coordinate with web engineering to scale backend autoscaling group capacity."
        ],
        "telemetry_queries": [
            "SELECT client_ip, count(*) as req_count FROM http_access_logs WHERE target_url = '{target_url}' GROUP BY client_ip ORDER BY req_count DESC LIMIT 20;"
        ]
    },
    "DoS attacks-GoldenEye": {
        "investigation_steps": [
            "Review web server active Keep-Alive connection count and established TCP socket duration.",
            "Inspect HTTP header telemetry for repeated 'Keep-Alive: 300' and 'Cache-Control: no-cache' combinations.",
            "Monitor memory usage on application tier to ensure JVM/PHP-FPM worker pools are not exhausted."
        ],
        "containment_playbook": [
            "OBSERVE-ONLY NOTICE: Automated inline blocking is disabled.",
            "Recommend lowering web server keepalive_timeout from default (65s) to 5s on reverse proxies.",
            "Tune maximum simultaneous connections permitted per unique client IP address."
        ],
        "telemetry_queries": [
            "SELECT count(*) as active_conns, client_ip FROM active_connections WHERE status = 'ESTABLISHED' GROUP BY client_ip HAVING count(*) > 20;"
        ]
    },
    "DoS attacks-Hulk": {
        "investigation_steps": [
            "Inspect request URI paths for randomized cache-busting query parameters (e.g., ?q=random_string).",
            "Verify User-Agent header distribution to confirm randomized browser strings.",
            "Check cache hit ratio degradation on edge CDN or varnish cache tier."
        ],
        "containment_playbook": [
            "OBSERVE-ONLY NOTICE: Automated inline blocking is disabled.",
            "Draft edge CDN caching rule ignoring randomized query arguments for static landing pages.",
            "Enable progressive CAPTCHA challenges on endpoints exhibiting sustained cache misses."
        ],
        "telemetry_queries": [
            "SELECT uri_query, count(*) FROM cdn_logs WHERE timestamp >= NOW() - INTERVAL 10 MINUTE GROUP BY uri_query HAVING count(*) = 1 LIMIT 50;"
        ]
    },
    "DoS attacks-SlowHTTPTest": {
        "investigation_steps": [
            "Check server thread dump for threads stuck in READ state waiting for partial client headers/bodies.",
            "Verify client connection throughput: flows exhibiting byte transfer rates < 500 bytes/minute over extended flow duration.",
            "Inspect proxy error logs for 'client connection timed out during header read'."
        ],
        "containment_playbook": [
            "OBSERVE-ONLY NOTICE: Observe-only mode active.",
            "Recommend deploying mod_reqtimeout (Apache) or client_header_timeout / client_body_timeout (NGINX set to 10s).",
            "Set minimum data transfer rate requirements (e.g. 500 bytes/sec) before terminating slow client sockets."
        ],
        "telemetry_queries": [
            "SELECT flow_duration, flow_byts_s, client_ip FROM flow_logs WHERE flow_duration > 30000 AND flow_byts_s < 100;"
        ]
    },
    "DoS attacks-Slowloris": {
        "investigation_steps": [
            "Verify count of half-open / lingering TCP connections on port 80/443 with minimal data transmission.",
            "Inspect packet captures for intermittent HTTP newline characters (\\r\\n) sent every 10-15 seconds to keep sockets alive.",
            "Evaluate server connection limit headroom (MaxRequestWorkers / worker_connections)."
        ],
        "containment_playbook": [
            "OBSERVE-ONLY NOTICE: Automated inline blocking is disabled.",
            "Verify reverse proxy buffer settings: ensure buffering proxies (NGINX/HAProxy) absorb slow clients before reaching application workers.",
            "Restrict concurrent connections per source IP address at the firewall or load balancer layer."
        ],
        "telemetry_queries": [
            "netstat -an | grep :80 | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -n 20"
        ]
    },
    "SSH-Bruteforce": {
        "investigation_steps": [
            "Inspect `/var/log/auth.log` or `/var/log/secure` on destination host for repeated 'Failed password for invalid user' messages.",
            "Identify targeted usernames: check if root or default service accounts are being targeted.",
            "Verify if any subsequent 'Accepted password' or 'Accepted publickey' entries occurred from the same source IP."
        ],
        "containment_playbook": [
            "OBSERVE-ONLY NOTICE: Maintain continuous telemetry recording.",
            "Verify Fail2Ban or host-based firewall status on the target host.",
            "Recommend disabling SSH password authentication in favor of ed25519 public keys only, and moving SSH behind VPN/Bastion."
        ],
        "telemetry_queries": [
            "grep 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -n 20",
            "SecurityEvent | where EventID == 4625 and LogonType == 3 | summarize FailedLogons=count() by IpAddress, TargetUserName"
        ]
    },
    "FTP-BruteForce": {
        "investigation_steps": [
            "Review FTP daemon logs (vsftpd.log / proftpd.log) for rapid 530 Login incorrect error bursts.",
            "Determine whether attack attempted standard default credentials (anonymous, ftp, admin).",
            "Check whether destination FTP server transmits in cleartext without TLS."
        ],
        "containment_playbook": [
            "OBSERVE-ONLY NOTICE: Observe-only mode active.",
            "Enforce host-based rate limiting on TCP port 21.",
            "Recommend sunsetting legacy unencrypted FTP in favor of SFTP (SSH File Transfer Protocol)."
        ],
        "telemetry_queries": [
            "SELECT count(*) as failed_attempts, src_ip FROM ftp_audit WHERE status_code = 530 GROUP BY src_ip HAVING count(*) > 10;"
        ]
    },
    "Brute Force -Web": {
        "investigation_steps": [
            "Review web application authentication endpoint POST requests (e.g. /login, /api/auth).",
            "Determine if attack is Single Account Password Guessing (high attempts on one user) or Password Spraying (few attempts on many users).",
            "Verify whether any login attempt returned HTTP 302 Redirect / 200 OK with session cookie issuance."
        ],
        "containment_playbook": [
            "OBSERVE-ONLY NOTICE: Observe-only mode active.",
            "Trigger temporary account lockout or CAPTCHA requirement on affected target accounts.",
            "Notify Identity and Access Management (IAM) team if high-privilege credentials were targeted."
        ],
        "telemetry_queries": [
            "SELECT cs_uri_stem, c_ip, count(*) as post_count FROM web_logs WHERE cs_method = 'POST' AND cs_uri_stem LIKE '%login%' GROUP BY cs_uri_stem, c_ip ORDER BY post_count DESC LIMIT 20;"
        ]
    },
    "Brute Force -XSS": {
        "investigation_steps": [
            "Inspect incoming HTTP request URI parameters and body payloads for `<script>`, `javascript:`, or event handler injection tokens (`onload=`, `onerror=`).",
            "Verify whether destination web server reflects the untrusted input in the response payload without sanitization/encoding.",
            "Check browser logs and Content Security Policy (CSP) violation reports for unauthorized script execution."
        ],
        "containment_playbook": [
            "OBSERVE-ONLY NOTICE: Observe-only mode active.",
            "Notify front-end development team to implement context-aware output encoding (OWASP standard).",
            "Draft WAF policy enforcing strict Content Security Policy headers."
        ],
        "telemetry_queries": [
            "SELECT client_ip, request_uri FROM access_logs WHERE request_uri LIKE '%<script%' OR request_uri LIKE '%onerror=%' LIMIT 25;"
        ]
    },
    "SUSPICIOUS_ANOMALY": {
        "investigation_steps": [
            "Perform deep statistical feature analysis: compare anomalous flow parameters against the benign training baseline distribution.",
            "Inspect raw packet captures (PCAP) corresponding to this flow timestamp and socket tuple for non-standard protocol implementations.",
            "Examine whether destination host has established novel outbound connections to unrecognized external subnets."
        ],
        "containment_playbook": [
            "OBSERVE-ONLY NOTICE: Maintain continuous telemetry recording.",
            "Tag flow as high-interest candidate for proactive threat hunting and model retraining feedback.",
            "Monitor the source and destination IP addresses for progressive threat escalation."
        ],
        "telemetry_queries": [
            "SELECT * FROM flow_telemetry WHERE (src_ip = '{src_ip}' OR dst_ip = '{dst_ip}') AND timestamp BETWEEN '{start_time}' AND '{end_time}';"
        ]
    },
    "Benign": {
        "investigation_steps": [
            "Baseline traffic verification: traffic parameters conform to standard operational profile.",
            "No active investigation required unless correlated with external threat alerts."
        ],
        "containment_playbook": [
            "No containment action required. Observe-only baseline logging active."
        ],
        "telemetry_queries": [
            "SELECT count(*) FROM benign_traffic_sample WHERE timestamp >= NOW() - INTERVAL 1 HOUR;"
        ]
    }
}


class ThreatPrioritizer:
    """
    Transparent alert prioritization engine for the Neural Breach platform.
    Computes explainable composite priority scores (0 - 100) and priority tiers.
    """
    def __init__(self):
        pass

    def calculate_priority(
        self,
        predicted_label: str,
        confidence: float,
        is_anomaly: bool,
        iso_alert: bool = False,
        ae_alert: bool = False,
        flow_features: Optional[Dict[str, float]] = None
    ) -> Dict[str, Any]:
        """
        Calculates transparent composite priority score and level.
        Formula:
          BaseScore * 0.50 + (Confidence * 100) * 0.25 + AnomalyBonus * 0.15 + VolumeImpact * 0.10
        """
        label = predicted_label.strip()
        base_score = ATTACK_BASE_SEVERITY.get(label, 50.0)

        # 1. Base Severity component (weight 0.50)
        base_component = base_score * 0.50

        # 2. Confidence component (weight 0.25)
        # For Benign predictions, high confidence actually REDUCES threat urgency
        if label == "Benign" and not is_anomaly:
            conf_component = 0.0
        else:
            conf_component = min(1.0, max(0.0, float(confidence))) * 100.0 * 0.25

        # 3. Anomaly Corroboration component (weight 0.15, max 15.0 pts)
        # Dual alert bonus: if both Isolation Forest and Autoencoder flag it
        if iso_alert and ae_alert:
            anomaly_pts = 15.0
        elif iso_alert or ae_alert or is_anomaly:
            anomaly_pts = 8.0
        else:
            anomaly_pts = 0.0

        # 4. Volumetric Impact component (weight 0.10, max 10.0 pts)
        volume_pts = 0.0
        if flow_features:
            duration = flow_features.get("Flow Duration", 0.0)
            byts_s = flow_features.get("Flow Byts/s", 0.0)
            pkts_s = flow_features.get("Flow Pkts/s", 0.0)
            tot_fwd = flow_features.get("Tot Fwd Pkts", 0.0)

            # Volumetric indicators
            if byts_s > 1000000.0 or pkts_s > 10000.0:
                volume_pts += 5.0
            elif byts_s > 100000.0 or pkts_s > 1000.0:
                volume_pts += 3.0
            
            if duration > 60000000.0:  # > 60 seconds
                volume_pts += 3.0
            elif duration > 10000000.0:
                volume_pts += 1.5

            if tot_fwd > 1000:
                volume_pts += 2.0

        volume_pts = min(10.0, volume_pts)

        # Calculate final composite score
        if label == "Benign" and not is_anomaly:
            composite_score = 0.0
        elif label == "Benign" and is_anomaly:
            # Unsupervised anomaly with benign classification
            composite_score = 50.0 * 0.50 + 15.0 + anomaly_pts + volume_pts
        else:
            composite_score = base_component + conf_component + anomaly_pts + volume_pts

        composite_score = round(min(100.0, max(0.0, composite_score)), 1)

        # Determine Priority Tier & Urgency
        if composite_score >= 80.0:
            level = "CRITICAL"
            urgency = "IMMEDIATE"
        elif composite_score >= 65.0:
            level = "HIGH"
            urgency = "HIGH"
        elif composite_score >= 45.0:
            level = "MEDIUM"
            urgency = "ELEVATED"
        elif composite_score >= 20.0:
            level = "LOW"
            urgency = "ROUTINE"
        else:
            level = "INFO"
            urgency = "INFORMATIONAL"

        # Lookup tailored SOC recommendations
        playbook = SOC_PLAYBOOKS.get(label, SOC_PLAYBOOKS.get("SUSPICIOUS_ANOMALY" if is_anomaly else "Benign", {}))

        return {
            "level": level,
            "score": composite_score,
            "urgency": urgency,
            "scoring_factors": {
                "base_severity": round(base_component, 2),
                "confidence_contribution": round(conf_component, 2),
                "anomaly_corroboration": round(anomaly_pts, 2),
                "volume_impact": round(volume_pts, 2)
            },
            "recommendations": {
                "investigation_steps": playbook.get("investigation_steps", []),
                "containment_playbook": playbook.get("containment_playbook", []),
                "telemetry_queries": playbook.get("telemetry_queries", [])
            }
        }
