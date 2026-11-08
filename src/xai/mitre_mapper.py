#!/usr/bin/env python3
"""
MITRE ATT&CK Threat Intelligence Mapping Module
Team Neural Breach — Role 5: XAI & Threat Intelligence

Maps all 15 supported attack categories + unsupervised anomalies to verified
MITRE ATT&CK Enterprise Matrix tactics, techniques, sub-techniques, and descriptions.
Cross-referenced and verified against the authentic STIX 2.1 repository:
`data/reference/MITRE-ATT-CK/enterprise-attack.json`.

Semantic Accuracy Review:
  - CONFIRMED_FLOW_SIGNATURE: Directly observable in flow metadata (volumetric floods, connection starvation, high-rate credential guessing).
  - UNCONFIRMED_FLOW_SURROGATE: Flow characteristics are indicative, but true technique execution (e.g. SQL injection payload, XSS execution, host infiltration) requires Layer-7 payload inspection or endpoint telemetry.
  - UNCONFIRMED_GENERIC_ANOMALY: Unsupervised statistical deviations (Autoencoder/Isolation Forest); mapping is an exploratory heuristic candidate, explicitly unconfirmed.
  - BASELINE: Normal authorized traffic meeting baseline operational profile.
"""

import os
import json
from typing import Dict, Any, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_STIX_PATH = os.path.join(
    PROJECT_ROOT, "data", "reference", "MITRE-ATT-CK", "enterprise-attack.json"
)

# Verified MITRE ATT&CK Enterprise Matrix mappings with semantic accuracy annotations
VERIFIED_MITRE_CATALOG: Dict[str, Dict[str, Any]] = {
    "Benign": {
        "mapping_status": "BASELINE",
        "semantic_accuracy_note": "Normal operational baseline; no adversarial technique attributed.",
        "tactics": [],
        "primary_technique": {
            "id": "BASELINE",
            "name": "Authorized Normal Operations",
            "url": "https://attack.mitre.org/",
            "description": "Standard business operations and legitimate network traffic meeting baseline behavioral profiles."
        },
        "secondary_techniques": [],
        "mitigations": [
            "Maintain baseline continuous network monitoring",
            "Review periodic asset configuration drifts"
        ]
    },
    "Bot": {
        "mapping_status": "CONFIRMED_FLOW_SIGNATURE",
        "semantic_accuracy_note": "Periodic flow inter-arrival times (beaconing) and non-standard protocol ratios match C2 communication behavior.",
        "tactics": [
            {"id": "TA0011", "name": "Command and Control"},
            {"id": "TA0002", "name": "Execution"}
        ],
        "primary_technique": {
            "id": "T1071",
            "name": "Application Layer Protocol",
            "url": "https://attack.mitre.org/techniques/T1071",
            "description": "Adversaries may communicate using application layer protocols (e.g., HTTP, IRC, DNS) to avoid detection/network filtering and maintain command and control channels."
        },
        "secondary_techniques": [
            {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "url": "https://attack.mitre.org/techniques/T1059"
            },
            {
                "id": "T1571",
                "name": "Non-Standard Port",
                "url": "https://attack.mitre.org/techniques/T1571"
            }
        ],
        "mitigations": [
            "M1031: Network Intrusion Prevention",
            "M1020: SSL/TLS Inspection",
            "M1037: Filter Network Traffic"
        ]
    },
    "Brute Force -Web": {
        "mapping_status": "CONFIRMED_FLOW_SIGNATURE",
        "semantic_accuracy_note": "Repetitive burst HTTP POST requests with brief durations and constant response sizes reflect automated credential guessing.",
        "tactics": [
            {"id": "TA0006", "name": "Credential Access"}
        ],
        "primary_technique": {
            "id": "T1110.001",
            "name": "Password Guessing",
            "url": "https://attack.mitre.org/techniques/T1110/001",
            "description": "Adversaries may systematically guess passwords to authenticate to web application accounts without prior knowledge of system passwords."
        },
        "secondary_techniques": [
            {
                "id": "T1110.003",
                "name": "Password Spraying",
                "url": "https://attack.mitre.org/techniques/T1110/003"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "url": "https://attack.mitre.org/techniques/T1110"
            }
        ],
        "mitigations": [
            "M1036: Account Use Policies (Account Lockout)",
            "M1032: Multi-factor Authentication",
            "M1037: Filter Network Traffic (Rate Limiting / CAPTCHA)"
        ]
    },
    "Brute Force -XSS": {
        "mapping_status": "UNCONFIRMED_FLOW_SURROGATE",
        "semantic_accuracy_note": "CAVEAT: Flow records show automated web parameter fuzzing, but client-side JavaScript execution (T1059.007) cannot be confirmed without Layer-7 payload and browser DOM telemetry.",
        "tactics": [
            {"id": "TA0002", "name": "Execution"},
            {"id": "TA0001", "name": "Initial Access"}
        ],
        "primary_technique": {
            "id": "T1059.007",
            "name": "JavaScript",
            "url": "https://attack.mitre.org/techniques/T1059/007",
            "description": "Adversaries may execute malicious JavaScript within a victim's browser context via cross-site scripting (XSS) payload injection."
        },
        "secondary_techniques": [
            {
                "id": "T1189",
                "name": "Drive-by Compromise",
                "url": "https://attack.mitre.org/techniques/T1189"
            },
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "url": "https://attack.mitre.org/techniques/T1190"
            }
        ],
        "mitigations": [
            "M1050: Exploit Protection (Content Security Policy)",
            "M1021: Restrict Web-Based Content",
            "M1016: Vulnerability Scanning"
        ]
    },
    "DDOS attack-HOIC": {
        "mapping_status": "CONFIRMED_FLOW_SIGNATURE",
        "semantic_accuracy_note": "High-velocity multi-threaded forward packet floods causing extreme Flow Byts/s directly confirm network denial of service.",
        "tactics": [
            {"id": "TA0040", "name": "Impact"}
        ],
        "primary_technique": {
            "id": "T1498.001",
            "name": "Direct Network Flood",
            "url": "https://attack.mitre.org/techniques/T1498/001",
            "description": "High Orbit Ion Cannon (HOIC) utilizes distributed multi-threaded HTTP POST/GET floods designed to overwhelm target network bandwidth and application layer processing."
        },
        "secondary_techniques": [
            {
                "id": "T1499.002",
                "name": "Service Exhaustion Flood",
                "url": "https://attack.mitre.org/techniques/T1499/002"
            },
            {
                "id": "T1498",
                "name": "Network Denial of Service",
                "url": "https://attack.mitre.org/techniques/T1498"
            }
        ],
        "mitigations": [
            "M1037: Filter Network Traffic (Upstream Anycast Scrubbing)",
            "M1031: Network Intrusion Prevention (Volumetric Rate Limiting)"
        ]
    },
    "DDOS attack-LOIC-UDP": {
        "mapping_status": "CONFIRMED_FLOW_SIGNATURE",
        "semantic_accuracy_note": "Continuous connectionless UDP datagram transmission with zero backward return packets directly confirms bandwidth saturation flood.",
        "tactics": [
            {"id": "TA0040", "name": "Impact"}
        ],
        "primary_technique": {
            "id": "T1498.001",
            "name": "Direct Network Flood",
            "url": "https://attack.mitre.org/techniques/T1498/001",
            "description": "Low Orbit Ion Cannon (LOIC) UDP mode transmits continuous streams of connectionless UDP datagrams targeting random ports to saturate inbound network pipes."
        },
        "secondary_techniques": [
            {
                "id": "T1498",
                "name": "Network Denial of Service",
                "url": "https://attack.mitre.org/techniques/T1498"
            }
        ],
        "mitigations": [
            "M1037: Filter Network Traffic (Border Router UDP Rate Limiting)",
            "M1031: Network Intrusion Prevention"
        ]
    },
    "DDoS attacks-LOIC-HTTP": {
        "mapping_status": "CONFIRMED_FLOW_SIGNATURE",
        "semantic_accuracy_note": "High-frequency HTTP GET/POST flow bursts with abnormal push flag counts confirm endpoint application exhaustion.",
        "tactics": [
            {"id": "TA0040", "name": "Impact"}
        ],
        "primary_technique": {
            "id": "T1499.003",
            "name": "Application Exhaustion Flood",
            "url": "https://attack.mitre.org/techniques/T1499/003",
            "description": "Adversaries flood the target web application with repetitive high-volume HTTP GET/POST requests to deplete web server worker threads and memory."
        },
        "secondary_techniques": [
            {
                "id": "T1499",
                "name": "Endpoint Denial of Service",
                "url": "https://attack.mitre.org/techniques/T1499"
            }
        ],
        "mitigations": [
            "M1037: Filter Network Traffic (WAF HTTP Request Throttling)",
            "M1031: Network Intrusion Prevention"
        ]
    },
    "DoS attacks-GoldenEye": {
        "mapping_status": "CONFIRMED_FLOW_SIGNATURE",
        "semantic_accuracy_note": "Prolonged flow duration combined with persistent TCP Keep-Alive flags confirm socket connection exhaustion.",
        "tactics": [
            {"id": "TA0040", "name": "Impact"}
        ],
        "primary_technique": {
            "id": "T1499.003",
            "name": "Application Exhaustion Flood",
            "url": "https://attack.mitre.org/techniques/T1499/003",
            "description": "GoldenEye executes HTTP Keep-Alive and No-Cache header abuse to hold open server connections and force constant backend page re-rendering until exhaustion."
        },
        "secondary_techniques": [
            {
                "id": "T1499.001",
                "name": "OS Exhaustion Flood",
                "url": "https://attack.mitre.org/techniques/T1499/001"
            }
        ],
        "mitigations": [
            "M1037: Filter Network Traffic (Enforce strict Keep-Alive timeouts)",
            "M1031: Network Intrusion Prevention (Reverse proxy connection limits)"
        ]
    },
    "DoS attacks-Hulk": {
        "mapping_status": "CONFIRMED_FLOW_SIGNATURE",
        "semantic_accuracy_note": "Distinct high-rate HTTP request flows bypassing CDN cache confirmed through packet frequency and unique flow counts.",
        "tactics": [
            {"id": "TA0040", "name": "Impact"}
        ],
        "primary_technique": {
            "id": "T1499.003",
            "name": "Application Exhaustion Flood",
            "url": "https://attack.mitre.org/techniques/T1499/003",
            "description": "HULK (HTTP Unbearable Load King) bypasses caching engines by generating unique randomized query parameters and user-agents, exhausting web server concurrency limits."
        },
        "secondary_techniques": [
            {
                "id": "T1499",
                "name": "Endpoint Denial of Service",
                "url": "https://attack.mitre.org/techniques/T1499"
            }
        ],
        "mitigations": [
            "M1037: Filter Network Traffic (Adaptive Rate Limiting & CAPTCHA)",
            "M1050: Exploit Protection"
        ]
    },
    "DoS attacks-SlowHTTPTest": {
        "mapping_status": "CONFIRMED_FLOW_SIGNATURE",
        "semantic_accuracy_note": "Extreme Flow Duration with ultra-low Flow Byts/s directly confirms slow-read/slow-header connection starvation.",
        "tactics": [
            {"id": "TA0040", "name": "Impact"}
        ],
        "primary_technique": {
            "id": "T1499.001",
            "name": "OS Exhaustion Flood",
            "url": "https://attack.mitre.org/techniques/T1499/001",
            "description": "SlowHTTPTest transmits incomplete HTTP requests or slow message bodies, tying up concurrent sockets and kernel resources with minimal attacker bandwidth."
        },
        "secondary_techniques": [
            {
                "id": "T1499",
                "name": "Endpoint Denial of Service",
                "url": "https://attack.mitre.org/techniques/T1499"
            }
        ],
        "mitigations": [
            "M1037: Filter Network Traffic (Configure minimum data transfer rates)",
            "M1031: Network Intrusion Prevention (Enforce aggressive client header timeouts)"
        ]
    },
    "DoS attacks-Slowloris": {
        "mapping_status": "CONFIRMED_FLOW_SIGNATURE",
        "semantic_accuracy_note": "Low-and-slow socket occupation with periodic newline cadence confirmed via inter-arrival intervals and duration metrics.",
        "tactics": [
            {"id": "TA0040", "name": "Impact"}
        ],
        "primary_technique": {
            "id": "T1499.001",
            "name": "OS Exhaustion Flood",
            "url": "https://attack.mitre.org/techniques/T1499/001",
            "description": "Slowloris opens numerous connections and holds them open indefinitely by periodically sending partial HTTP headers, starving legitimate incoming connections."
        },
        "secondary_techniques": [
            {
                "id": "T1499.003",
                "name": "Application Exhaustion Flood",
                "url": "https://attack.mitre.org/techniques/T1499/003"
            }
        ],
        "mitigations": [
            "M1037: Filter Network Traffic (Limit simultaneous connections per IP)",
            "M1031: Network Intrusion Prevention"
        ]
    },
    "FTP-BruteForce": {
        "mapping_status": "CONFIRMED_FLOW_SIGNATURE",
        "semantic_accuracy_note": "Repeated rapid TCP connections with standard banner exchanges and immediate disconnection confirms automated password guessing.",
        "tactics": [
            {"id": "TA0006", "name": "Credential Access"}
        ],
        "primary_technique": {
            "id": "T1110.001",
            "name": "Password Guessing",
            "url": "https://attack.mitre.org/techniques/T1110/001",
            "description": "Adversaries conduct automated dictionary attacks and password guessing against FTP service (Port 21) to obtain cleartext credentials."
        },
        "secondary_techniques": [
            {
                "id": "T1110",
                "name": "Brute Force",
                "url": "https://attack.mitre.org/techniques/T1110"
            }
        ],
        "mitigations": [
            "M1036: Account Use Policies (Fail2Ban lockout on failed login bursts)",
            "M1042: Disable or Remove Feature or Program (Decommission unencrypted FTP)"
        ]
    },
    "Infiltration": {
        "mapping_status": "UNCONFIRMED_FLOW_SURROGATE",
        "semantic_accuracy_note": "CAVEAT: Network flow features reflect abnormal data transfer volumes and timing shifts, but initial exploitation (T1190) and privilege escalation (T1068) require endpoint EVTX/Sysmon process telemetry for confirmation.",
        "tactics": [
            {"id": "TA0001", "name": "Initial Access"},
            {"id": "TA0008", "name": "Lateral Movement"},
            {"id": "TA0004", "name": "Privilege Escalation"}
        ],
        "primary_technique": {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "url": "https://attack.mitre.org/techniques/T1190",
            "description": "Adversaries exploit vulnerabilities in internet-facing services, establishing initial access before executing privilege escalation and internal lateral movement."
        },
        "secondary_techniques": [
            {
                "id": "T1068",
                "name": "Exploitation for Privilege Escalation",
                "url": "https://attack.mitre.org/techniques/T1068"
            },
            {
                "id": "T1021",
                "name": "Remote Services",
                "url": "https://attack.mitre.org/techniques/T1021"
            }
        ],
        "mitigations": [
            "M1051: Update Software & Security Patching",
            "M1030: Network Segmentation (Demilitarized Zone isolation)",
            "M1026: Privileged Account Management"
        ]
    },
    "SQL Injection": {
        "mapping_status": "UNCONFIRMED_FLOW_SURROGATE",
        "semantic_accuracy_note": "CAVEAT: Flow metadata indicates anomalous forward-to-backward byte ratios and response delays, but SQL syntax injection requires Layer-7 payload/WAF inspection for confirmation.",
        "tactics": [
            {"id": "TA0001", "name": "Initial Access"},
            {"id": "TA0002", "name": "Execution"}
        ],
        "primary_technique": {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "url": "https://attack.mitre.org/techniques/T1190",
            "description": "Adversaries submit malicious SQL control sequences into unvalidated web inputs to execute unauthorized database queries and dump tables."
        },
        "secondary_techniques": [
            {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "url": "https://attack.mitre.org/techniques/T1059"
            }
        ],
        "mitigations": [
            "M1050: Exploit Protection (Parameterized Prepared Statements)",
            "M1037: Filter Network Traffic (Web Application Firewall SQLi Signatures)"
        ]
    },
    "SSH-Bruteforce": {
        "mapping_status": "CONFIRMED_FLOW_SIGNATURE",
        "semantic_accuracy_note": "Repeated encrypted TCP connection handshakes with rapid client-initiated teardowns directly confirm SSH dictionary brute-force.",
        "tactics": [
            {"id": "TA0006", "name": "Credential Access"}
        ],
        "primary_technique": {
            "id": "T1110.001",
            "name": "Password Guessing",
            "url": "https://attack.mitre.org/techniques/T1110/001",
            "description": "Adversaries attempt rapid credential guessing against SSH daemon (Port 22) to gain interactive shell access on remote Linux/Unix servers."
        },
        "secondary_techniques": [
            {
                "id": "T1021.004",
                "name": "SSH",
                "url": "https://attack.mitre.org/techniques/T1021/004"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "url": "https://attack.mitre.org/techniques/T1110"
            }
        ],
        "mitigations": [
            "M1032: Multi-factor Authentication / SSH Key-based Auth Only",
            "M1036: Account Use Policies (SSH MaxAuthTries & rate limiting)",
            "M1037: Filter Network Traffic (Restrict SSH to internal Bastion/VPN)"
        ]
    },
    "SUSPICIOUS_ANOMALY": {
        "mapping_status": "UNCONFIRMED_GENERIC_ANOMALY",
        "semantic_accuracy_note": "UNCONFIRMED: Dual unsupervised anomaly detection flagged multi-dimensional statistical deviations from the benign baseline. Mapping to C2/Exfiltration is a speculative hypothesis requiring manual SOC investigation.",
        "tactics": [
            {"id": "TA0007", "name": "Discovery"},
            {"id": "TA0011", "name": "Command and Control"},
            {"id": "TA0010", "name": "Exfiltration"}
        ],
        "primary_technique": {
            "id": "T1071",
            "name": "Application Layer Protocol",
            "url": "https://attack.mitre.org/techniques/T1071",
            "description": "Unsupervised dual-model anomaly detection flagged statistically deviant network flow dynamics inconsistent with normal operational baselines (potential zero-day or novel C2)."
        },
        "secondary_techniques": [
            {
                "id": "T1005",
                "name": "Data from Local System",
                "url": "https://attack.mitre.org/techniques/T1005"
            },
            {
                "id": "T1020",
                "name": "Automated Exfiltration",
                "url": "https://attack.mitre.org/techniques/T1020"
            },
            {
                "id": "T1046",
                "name": "Network Service Discovery",
                "url": "https://attack.mitre.org/techniques/T1046"
            }
        ],
        "mitigations": [
            "M1031: Network Intrusion Prevention (Deep packet flow inspection)",
            "M1029: Remote Data Storage (Host & flow telemetry retention for hunting)"
        ]
    }
}


class MitreThreatIntelligence:
    """
    Threat Intelligence mapping service linking model predictions
    to verified MITRE ATT&CK Enterprise Matrix entities.
    """
    def __init__(self, stix_path: str = DEFAULT_STIX_PATH):
        self.stix_path = stix_path
        self._stix_cache: Optional[Dict[str, Any]] = None

    def get_mapping(self, label: str) -> Dict[str, Any]:
        """
        Retrieves verified MITRE ATT&CK mapping for a given label.
        Defaults to SUSPICIOUS_ANOMALY or Generic Baseline if unrecognized.
        """
        # Exact match
        if label in VERIFIED_MITRE_CATALOG:
            return VERIFIED_MITRE_CATALOG[label]
        
        # Case-insensitive or normalized lookup
        norm_label = label.strip().lower()
        for k, v in VERIFIED_MITRE_CATALOG.items():
            if k.lower() == norm_label:
                return v

        # Fallback for generic anomalies
        if "anomaly" in norm_label:
            return VERIFIED_MITRE_CATALOG["SUSPICIOUS_ANOMALY"]

        # Default fallback for unrecognized predictions
        return {
            "mapping_status": "UNCONFIRMED_UNKNOWN",
            "semantic_accuracy_note": f"UNCONFIRMED: Label '{label}' is unrecognized in the verified catalog; mapped to generic exploitation candidate.",
            "tactics": [{"id": "TA0001", "name": "Initial Access"}],
            "primary_technique": {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "url": "https://attack.mitre.org/techniques/T1190",
                "description": f"Uncategorized threat '{label}' flagged for manual SOC analyst review."
            },
            "secondary_techniques": [],
            "mitigations": ["M1037: Filter Network Traffic", "M1031: Network Intrusion Prevention"]
        }

    def validate_against_stix(self, stix_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Validates all catalog technique IDs against the official STIX 2.1 JSON file.
        Returns validation statistics and verified technique records.
        """
        path = stix_path or self.stix_path
        if not os.path.exists(path):
            return {
                "status": "SKIPPED",
                "reason": f"STIX file not found at {path}",
                "verified_techniques": 0,
                "total_checked": 0
            }

        with open(path, "r", encoding="utf-8") as f:
            bundle = json.load(f)

        stix_techniques = {}
        for obj in bundle.get("objects", []):
            if obj.get("type") == "attack-pattern":
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        tid = ref.get("external_id")
                        if tid:
                            stix_techniques[tid] = {
                                "name": obj.get("name"),
                                "url": ref.get("url"),
                                "description": obj.get("description", "")
                            }

        checked_tids = set()
        verified_tids = set()
        missing_tids = set()

        for cat, details in VERIFIED_MITRE_CATALOG.items():
            primary = details.get("primary_technique", {})
            pid = primary.get("id")
            if pid and pid != "BASELINE":
                checked_tids.add(pid)
                if pid in stix_techniques:
                    verified_tids.add(pid)
                else:
                    missing_tids.add(pid)

            for sec in details.get("secondary_techniques", []):
                sid = sec.get("id")
                if sid:
                    checked_tids.add(sid)
                    if sid in stix_techniques:
                        verified_tids.add(sid)
                    else:
                        missing_tids.add(sid)

        return {
            "status": "PASS" if len(missing_tids) == 0 else "PARTIAL",
            "total_techniques_checked": len(checked_tids),
            "verified_in_stix": len(verified_tids),
            "missing_from_stix": list(missing_tids),
            "all_verified": len(missing_tids) == 0
        }
