"""
Raw PCAP Network Flow Feature Extraction Engine
Team Neural Breach — Role 2: Network Feature Extraction & Preprocessing

Extracts bidirectional network flows from raw PCAP files using Scapy:
  - Groups packets into 5-tuple bidirectional flows: (IP1, IP2, Port1, Port2, Proto)
  - Computes flow duration, packet/byte counts, packet length statistics
  - Computes inter-arrival time (IAT) statistics (forward, backward, flow-level)
  - Aggregates TCP flags (FIN, SYN, RST, PSH, ACK, URG)
  - Preserves timestamps and flow endpoints
  - Applies CTU-13 Scenario 1 ground-truth labelling (Neris botnet host 147.32.84.165)
  - Streams extracted flow records to compressed Apache Parquet
"""

import os
import sys
import time
import json
import hashlib
import numpy as np
import pandas as pd
from collections import defaultdict, Counter
from datetime import datetime, timezone

import scapy
from scapy.all import PcapReader, IP, TCP, UDP, ICMP

PROJECT_ROOT = "/Users/priyanshu/Desktop/aiml project team neural breach"
RAW_CTU_DIR = os.path.join(PROJECT_ROOT, "data", "raw", "CTU-13")
OUT_CTU_DIR = os.path.join(PROJECT_ROOT, "data", "processed", "CTU-13")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports", "data_preprocessing")

os.makedirs(OUT_CTU_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# CTU-13 Scenario 1 Ground-Truth Botnet IP
CTU13_BOTNET_HOST = "147.32.84.165"


def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(4 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


class FlowRecord:
    """Internal accumulator for a bidirectional network flow."""

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int, start_time: float):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = proto
        self.start_time = start_time
        self.last_time = start_time
        self.last_fwd_time = start_time
        self.last_bwd_time = None

        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0

        self.fwd_pkt_lens = []
        self.bwd_pkt_lens = []

        self.flow_iats = []
        self.fwd_iats = []
        self.bwd_iats = []

        # TCP flags
        self.fin_cnt = 0
        self.syn_cnt = 0
        self.rst_cnt = 0
        self.psh_cnt = 0
        self.ack_cnt = 0
        self.urg_cnt = 0

    def add_packet(self, pkt_len: int, pkt_time: float, is_forward: bool, tcp_layer=None):
        flow_iat = pkt_time - self.last_time
        if flow_iat >= 0:
            self.flow_iats.append(flow_iat)
        self.last_time = pkt_time

        if is_forward:
            self.fwd_pkts += 1
            self.fwd_bytes += pkt_len
            self.fwd_pkt_lens.append(pkt_len)
            fwd_iat = pkt_time - self.last_fwd_time
            if self.fwd_pkts > 1 and fwd_iat >= 0:
                self.fwd_iats.append(fwd_iat)
            self.last_fwd_time = pkt_time
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += pkt_len
            self.bwd_pkt_lens.append(pkt_len)
            if self.last_bwd_time is not None:
                bwd_iat = pkt_time - self.last_bwd_time
                if bwd_iat >= 0:
                    self.bwd_iats.append(bwd_iat)
            self.last_bwd_time = pkt_time

        if tcp_layer is not None:
            flags = int(tcp_layer.flags)
            if flags & 0x01: self.fin_cnt += 1
            if flags & 0x02: self.syn_cnt += 1
            if flags & 0x04: self.rst_cnt += 1
            if flags & 0x08: self.psh_cnt += 1
            if flags & 0x10: self.ack_cnt += 1
            if flags & 0x20: self.urg_cnt += 1

    def to_feature_dict(self) -> dict:
        duration_s = max(0.0, self.last_time - self.start_time)
        duration_us = duration_s * 1e6
        tot_pkts = self.fwd_pkts + self.bwd_pkts
        tot_bytes = self.fwd_bytes + self.bwd_bytes

        fwd_lens = np.array(self.fwd_pkt_lens, dtype=float) if self.fwd_pkt_lens else np.array([0.0])
        bwd_lens = np.array(self.bwd_pkt_lens, dtype=float) if self.bwd_pkt_lens else np.array([0.0])
        flow_iats = np.array(self.flow_iats, dtype=float) if self.flow_iats else np.array([0.0])
        fwd_iats = np.array(self.fwd_iats, dtype=float) if self.fwd_iats else np.array([0.0])
        bwd_iats = np.array(self.bwd_iats, dtype=float) if self.bwd_iats else np.array([0.0])

        flow_byts_s = (tot_bytes / duration_s) if duration_s > 0 else 0.0
        flow_pkts_s = (tot_pkts / duration_s) if duration_s > 0 else 0.0

        # CTU-13 Label ground truth
        is_botnet = (self.src_ip == CTU13_BOTNET_HOST or self.dst_ip == CTU13_BOTNET_HOST)
        label = "Botnet-Neris" if is_botnet else "Benign"

        return {
            "Src IP": self.src_ip,
            "Dst IP": self.dst_ip,
            "Src Port": int(self.src_port),
            "Dst Port": int(self.dst_port),
            "Protocol": int(self.protocol),
            "Timestamp": datetime.fromtimestamp(self.start_time, tz=timezone.utc).strftime("%d/%m/%Y %H:%M:%S"),
            "Flow Duration": float(duration_us),
            "Tot Fwd Pkts": int(self.fwd_pkts),
            "Tot Bwd Pkts": int(self.bwd_pkts),
            "TotLen Fwd Pkts": float(self.fwd_bytes),
            "TotLen Bwd Pkts": float(self.bwd_bytes),
            "Fwd Pkt Len Max": float(fwd_lens.max()),
            "Fwd Pkt Len Min": float(fwd_lens.min()),
            "Fwd Pkt Len Mean": float(fwd_lens.mean()),
            "Fwd Pkt Len Std": float(fwd_lens.std()),
            "Bwd Pkt Len Max": float(bwd_lens.max()),
            "Bwd Pkt Len Min": float(bwd_lens.min()),
            "Bwd Pkt Len Mean": float(bwd_lens.mean()),
            "Bwd Pkt Len Std": float(bwd_lens.std()),
            "Flow Byts/s": float(flow_byts_s),
            "Flow Pkts/s": float(flow_pkts_s),
            "Flow IAT Mean": float(flow_iats.mean() * 1e6),
            "Flow IAT Std": float(flow_iats.std() * 1e6),
            "Flow IAT Max": float(flow_iats.max() * 1e6),
            "Flow IAT Min": float(flow_iats.min() * 1e6),
            "Fwd IAT Tot": float(fwd_iats.sum() * 1e6),
            "Fwd IAT Mean": float(fwd_iats.mean() * 1e6),
            "Fwd IAT Std": float(fwd_iats.std() * 1e6),
            "Fwd IAT Max": float(fwd_iats.max() * 1e6),
            "Fwd IAT Min": float(fwd_iats.min() * 1e6),
            "Bwd IAT Tot": float(bwd_iats.sum() * 1e6),
            "Bwd IAT Mean": float(bwd_iats.mean() * 1e6),
            "Bwd IAT Std": float(bwd_iats.std() * 1e6),
            "Bwd IAT Max": float(bwd_iats.max() * 1e6),
            "Bwd IAT Min": float(bwd_iats.min() * 1e6),
            "FIN Flag Cnt": int(self.fin_cnt),
            "SYN Flag Cnt": int(self.syn_cnt),
            "RST Flag Cnt": int(self.rst_cnt),
            "PSH Flag Cnt": int(self.psh_cnt),
            "ACK Flag Cnt": int(self.ack_cnt),
            "URG Flag Cnt": int(self.urg_cnt),
            "Label": label,
            "_Source_File": "botnet-capture-20110810-neris.pcap"
        }


def extract_pcap_flows(pcap_path: str, max_packets: int = None, output_parquet: str = None) -> dict:
    """
    Extract bidirectional flow records from a PCAP file using Scapy.
    """
    fname = os.path.basename(pcap_path)
    fsize = os.path.getsize(pcap_path)
    t0 = time.time()
    log(f"Starting PCAP flow extraction: {fname} ({fsize / (1024**2):.2f} MB)")

    if output_parquet is None:
        output_parquet = os.path.join(OUT_CTU_DIR, "ctu13_scenario1_flows.parquet")

    flows = {}  # canonical 5-tuple -> FlowRecord
    total_packets = 0
    ip_packets = 0
    non_ip_packets = 0
    errors = 0

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            total_packets += 1
            if max_packets and total_packets >= max_packets:
                break

            if total_packets % 50_000 == 0:
                log(f"  Processed {total_packets:,} packets... ({len(flows):,} active flows)")

            try:
                if not pkt.haslayer(IP):
                    non_ip_packets += 1
                    continue

                ip_packets += 1
                ip_layer = pkt[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                proto = int(ip_layer.proto)
                pkt_len = len(pkt)
                pkt_time = float(pkt.time)

                sport, dport = 0, 0
                tcp_layer = None

                if pkt.haslayer(TCP):
                    tcp_layer = pkt[TCP]
                    sport = int(tcp_layer.sport)
                    dport = int(tcp_layer.dport)
                elif pkt.haslayer(UDP):
                    udp_layer = pkt[UDP]
                    sport = int(udp_layer.sport)
                    dport = int(udp_layer.dport)

                # Canonical bidirectional flow key
                # Forward if (src_ip, sport) <= (dst_ip, dport)
                if (src_ip, sport) <= (dst_ip, dport):
                    flow_key = (src_ip, dst_ip, sport, dport, proto)
                    is_forward = True
                else:
                    flow_key = (dst_ip, src_ip, dport, sport, proto)
                    is_forward = False

                if flow_key not in flows:
                    # Initiator determines forward direction
                    flows[flow_key] = FlowRecord(src_ip, dst_ip, sport, dport, proto, pkt_time)
                    flows[flow_key].add_packet(pkt_len, pkt_time, is_forward=True, tcp_layer=tcp_layer)
                else:
                    flows[flow_key].add_packet(pkt_len, pkt_time, is_forward=is_forward, tcp_layer=tcp_layer)

            except Exception:
                errors += 1

    log(f"Finalizing {len(flows):,} flows into DataFrame...")
    flow_dicts = [f.to_feature_dict() for f in flows.values()]
    df = pd.DataFrame(flow_dicts)

    # Save to Parquet
    df.to_parquet(output_parquet, engine="pyarrow", compression="snappy", index=False)

    t1 = time.time()
    elapsed = round(t1 - t0, 2)
    label_dist = dict(df["Label"].value_counts().items())

    report = {
        "pipeline": "PCAP Feature Extraction (Scapy)",
        "extractor_engine": "Scapy Bidirectional Flow Extractor v1.0",
        "scapy_version": scapy.__version__,
        "source_pcap": pcap_path,
        "source_pcap_size_bytes": fsize,
        "source_sha256": compute_sha256(pcap_path),
        "total_packets_read": total_packets,
        "ip_packets_processed": ip_packets,
        "non_ip_packets_skipped": non_ip_packets,
        "packet_errors": errors,
        "flows_extracted": len(df),
        "feature_count": len(df.columns),
        "feature_names": list(df.columns),
        "label_distribution": {str(k): int(v) for k, v in label_dist.items()},
        "output_file": output_parquet,
        "output_size_bytes": os.path.getsize(output_parquet),
        "output_sha256": compute_sha256(output_parquet),
        "elapsed_seconds": elapsed,
        "extraction_rate_pkts_per_sec": round(total_packets / max(elapsed, 0.001), 1)
    }

    report_path = os.path.join(REPORTS_DIR, "ctu13_pcap_extraction_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    log(f"  ✓ Extracted {len(df):,} flows from {total_packets:,} packets in {elapsed}s")
    log(f"    Labels: {label_dist}")
    log(f"    Saved Parquet: {output_parquet} ({os.path.getsize(output_parquet) / (1024**2):.2f} MB)")
    log(f"    Saved report: {report_path}")

    return report


if __name__ == "__main__":
    pcap_file = os.path.join(RAW_CTU_DIR, "botnet-capture-20110810-neris.pcap")
    if os.path.exists(pcap_file):
        extract_pcap_flows(pcap_file)
    else:
        log(f"File not found: {pcap_file}")
