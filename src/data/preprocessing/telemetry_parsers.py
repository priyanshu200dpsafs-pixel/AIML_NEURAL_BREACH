"""
Telemetry Parsers — LANL DNS, LANL Red Team, CTU-13 JSON, Windows EVTX, MITRE STIX
Team Neural Breach — Role 2: Network Feature Extraction & Preprocessing

Each telemetry type has its own isolated parser interface.
Heterogeneous records are NEVER merged with CICFlowMeter or UNSW flow data.
"""

import os
import csv
import gzip
import json
import zipfile
from collections import Counter
from datetime import datetime, timezone
import pandas as pd

PROJECT_ROOT = "/Users/priyanshu/Desktop/aiml project team neural breach"
RAW_DIR = os.path.join(PROJECT_ROOT, "data", "raw")
OUT_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports", "data_preprocessing")

os.makedirs(os.path.join(OUT_DIR, "LANL"), exist_ok=True)
os.makedirs(os.path.join(OUT_DIR, "CTU-13"), exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)


def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


# ═══════════════════════════════════════════════════════════════════════
# LANL DNS Parser
# ═══════════════════════════════════════════════════════════════════════

def parse_lanl_dns(max_rows: int = 500_000) -> dict:
    """
    Parse LANL Cyber1 dns.txt.gz.
    Schema: time,src_computer,resolved_computer
    """
    dns_path = os.path.join(RAW_DIR, "LANL", "dns.txt.gz")
    log(f"Parsing LANL DNS: {dns_path}")

    report = {
        "source_file": dns_path,
        "format": "GZIP CSV (headerless)",
        "schema": ["time", "src_computer", "resolved_computer"],
        "schema_notes": "time=integer epoch offset, src_computer=client hostname, resolved_computer=lookup target",
        "rows_scanned": 0,
        "time_range": {"min": None, "max": None},
        "sample_rows": [],
        "top_src_computers": {},
        "top_resolved_computers": {},
    }

    if not os.path.exists(dns_path):
        report["error"] = "File not found"
        return report

    src_counts = Counter()
    res_counts = Counter()

    with gzip.open(dns_path, "rt", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader):
            if max_rows and i >= max_rows:
                break
            report["rows_scanned"] += 1
            if len(row) >= 3:
                t = int(row[0]) if row[0].isdigit() else None
                if t is not None:
                    if report["time_range"]["min"] is None or t < report["time_range"]["min"]:
                        report["time_range"]["min"] = t
                    if report["time_range"]["max"] is None or t > report["time_range"]["max"]:
                        report["time_range"]["max"] = t
                if i < 5:
                    report["sample_rows"].append(row)
                src_counts[row[1]] += 1
                res_counts[row[2]] += 1

    report["top_src_computers"] = dict(src_counts.most_common(10))
    report["top_resolved_computers"] = dict(res_counts.most_common(10))
    report["unique_src_computers_sampled"] = len(src_counts)
    report["unique_resolved_computers_sampled"] = len(res_counts)

    log(f"  ✓ LANL DNS: {report['rows_scanned']:,} rows scanned, time span [{report['time_range']['min']} - {report['time_range']['max']}]")
    return report


# ═══════════════════════════════════════════════════════════════════════
# LANL Red Team Parser
# ═══════════════════════════════════════════════════════════════════════

def parse_lanl_redteam() -> dict:
    """
    Parse LANL Cyber1 redteam.txt.gz into structured records & Parquet.
    Schema: time,user@domain,src_computer,dst_computer
    """
    rt_path = os.path.join(RAW_DIR, "LANL", "redteam.txt.gz")
    log(f"Parsing LANL Red Team: {rt_path}")

    report = {
        "source_file": rt_path,
        "format": "GZIP CSV (headerless)",
        "schema": ["time", "user_domain", "src_computer", "dst_computer"],
        "schema_notes": "Adversary compromise events with ground-truth epoch offsets",
        "total_events": 0,
        "sample_rows": [],
        "time_range": {"min": None, "max": None},
        "output_file": None,
    }

    if not os.path.exists(rt_path):
        report["error"] = "File not found"
        return report

    records = []
    with gzip.open(rt_path, "rt", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 4:
                report["total_events"] += 1
                t = int(row[0]) if row[0].isdigit() else 0
                if report["time_range"]["min"] is None or t < report["time_range"]["min"]:
                    report["time_range"]["min"] = t
                if report["time_range"]["max"] is None or t > report["time_range"]["max"]:
                    report["time_range"]["max"] = t
                records.append({
                    "time": t,
                    "user_domain": row[1],
                    "src_computer": row[2],
                    "dst_computer": row[3],
                })
                if report["total_events"] <= 5:
                    report["sample_rows"].append(row)

    df = pd.DataFrame(records)
    out_path = os.path.join(OUT_DIR, "LANL", "lanl_redteam_events.parquet")
    df.to_parquet(out_path, engine="pyarrow", compression="snappy", index=False)
    report["output_file"] = out_path
    report["unique_users"] = int(df["user_domain"].nunique())
    report["unique_src_hosts"] = int(df["src_computer"].nunique())
    report["unique_dst_hosts"] = int(df["dst_computer"].nunique())

    log(f"  ✓ LANL Red Team: {report['total_events']} events saved to {os.path.basename(out_path)}")
    return report


# ═══════════════════════════════════════════════════════════════════════
# CTU-13 JSON Metadata Parser (CapTipper HTTP Telemetry)
# ═══════════════════════════════════════════════════════════════════════

def parse_ctu13_json() -> dict:
    """
    Parse CTU-13 Neris botnet CapTipper HTTP inspection JSON metadata.
    """
    json_path = os.path.join(RAW_DIR, "CTU-13", "botnet-capture-20110810-neris.json")
    log(f"Parsing CTU-13 JSON: {json_path}")

    report = {
        "source_file": json_path,
        "format": "CapTipper Web Telemetry JSON",
        "captipper_version": None,
        "traffic_time": None,
        "total_conversations": 0,
        "total_uris": 0,
        "sample_uris": [],
        "methods": {},
        "target_hosts": {},
        "output_file": None,
    }

    if not os.path.exists(json_path):
        report["error"] = "File not found"
        return report

    with open(json_path, "r", encoding="latin-1") as f:
        data = json.load(f)

    info = data.get("info", {})
    report["captipper_version"] = info.get("captipper_version")
    report["traffic_time"] = info.get("traffic_time")

    conversations = data.get("conversations", [])
    report["total_conversations"] = len(conversations)

    extracted_uris = []
    methods_counter = Counter()
    hosts_counter = Counter()

    for conv in conversations:
        host = conv.get("name")
        ip = conv.get("ip")
        for u in conv.get("uris", []):
            method = u.get("method", "UNKNOWN")
            uri = u.get("uri", "")
            methods_counter[method] += 1
            if host:
                hosts_counter[host] += 1
            extracted_uris.append({
                "host": host,
                "server_ip": ip or u.get("server_ip"),
                "method": method,
                "uri": uri,
                "res_type": u.get("res_type"),
                "md5": u.get("md5"),
                "sha256": u.get("sha256"),
            })

    report["total_uris"] = len(extracted_uris)
    report["methods"] = dict(methods_counter)
    report["target_hosts"] = dict(hosts_counter.most_common(10))
    report["sample_uris"] = extracted_uris[:5]

    # Save extracted HTTP telemetry to Parquet
    if extracted_uris:
        df = pd.DataFrame(extracted_uris)
        out_path = os.path.join(OUT_DIR, "CTU-13", "ctu13_http_telemetry.parquet")
        df.to_parquet(out_path, engine="pyarrow", compression="snappy", index=False)
        report["output_file"] = out_path

    log(f"  ✓ CTU-13 JSON: {report['total_conversations']} conversations, {report['total_uris']} URIs extracted")
    return report


# ═══════════════════════════════════════════════════════════════════════
# Windows EVTX Host Logs Archive Audit
# ═══════════════════════════════════════════════════════════════════════

def audit_evtx_archive() -> dict:
    """
    Audit Windows EVTX security host logs archive in CSE-CIC-IDS2018.
    """
    zip_path = os.path.join(RAW_DIR, "CSE-CIC-IDS2018", "Friday-23-02-2018_logs.zip")
    log(f"Auditing Windows EVTX Archive: {zip_path}")

    report = {
        "source_archive": zip_path,
        "format": "ZIP of Windows EVTX Binary XML Event Logs",
        "total_files": 0,
        "total_uncompressed_bytes": 0,
        "sample_hosts": [],
        "status": "AUDITED_VERIFIED",
    }

    if not os.path.exists(zip_path):
        report["error"] = "Archive not found"
        return report

    with zipfile.ZipFile(zip_path, "r") as z:
        infolist = z.infolist()
        report["total_files"] = len(infolist)
        report["total_uncompressed_bytes"] = sum(info.file_size for info in infolist)
        for info in infolist:
            if info.filename.endswith(".evtx") and len(report["sample_hosts"]) < 10:
                report["sample_hosts"].append({
                    "filename": info.filename,
                    "uncompressed_size_bytes": info.file_size,
                })

    log(f"  ✓ Windows EVTX: {report['total_files']} files, {report['total_uncompressed_bytes'] / (1024**2):.1f} MB uncompressed")
    return report


# ═══════════════════════════════════════════════════════════════════════
# MITRE ATT&CK STIX 2.1 Threat Intel Audit
# ═══════════════════════════════════════════════════════════════════════

def audit_mitre_stix() -> dict:
    """
    Audit MITRE ATT&CK STIX 2.1 bundles kept as reference knowledge.
    """
    stix_dir = os.path.join(PROJECT_ROOT, "data", "reference", "MITRE-ATT-CK")
    log(f"Auditing MITRE ATT&CK STIX bundles in: {stix_dir}")

    report = {
        "status": "REFERENCE_KNOWLEDGE_ISOLATED",
        "bundles": {},
    }

    if not os.path.exists(stix_dir):
        report["error"] = "Directory not found"
        return report

    for f in ["enterprise-attack.json", "mobile-attack.json", "ics-attack.json"]:
        fp = os.path.join(stix_dir, f)
        if os.path.exists(fp):
            with open(fp, "r", encoding="utf-8") as s_in:
                data = json.load(s_in)
            objects = data.get("objects", [])
            types = Counter(obj.get("type") for obj in objects)
            report["bundles"][f] = {
                "size_mb": round(os.path.getsize(fp) / (1024**2), 2),
                "total_stix_objects": len(objects),
                "attack_patterns": types.get("attack-pattern", 0),
                "malware": types.get("malware", 0),
                "tools": types.get("tool", 0),
                "intrusion_sets": types.get("intrusion-set", 0),
            }

    log(f"  ✓ MITRE ATT&CK STIX: {len(report['bundles'])} bundles verified as isolated reference knowledge")
    return report


def run_all_telemetry_audits() -> dict:
    """Run all telemetry parsers and audits, saving master report."""
    log("=" * 70)
    log("HETEROGENEOUS TELEMETRY INGESTION & AUDIT")
    log("=" * 70)

    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "lanl_dns": parse_lanl_dns(max_rows=100_000),
        "lanl_redteam": parse_lanl_redteam(),
        "ctu13_json": parse_ctu13_json(),
        "windows_evtx": audit_evtx_archive(),
        "mitre_stix": audit_mitre_stix(),
    }

    report_path = os.path.join(REPORTS_DIR, "telemetry_audit_report.json")
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    log(f"\nSaved telemetry report: {report_path}")
    return results


if __name__ == "__main__":
    run_all_telemetry_audits()
