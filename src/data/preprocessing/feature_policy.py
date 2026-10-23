"""
Feature Policy — CSE-CIC-IDS2018 and UNSW-NB15
Team Neural Breach — Role 2: Network Feature Extraction & Preprocessing

Defines the explicit treatment of every column in both dataset schemas:
  - Which columns are predictive features
  - Which columns are metadata (kept but excluded from features)
  - Which columns are identifiers (dropped from features, kept as provenance)
  - Which columns are targets/labels
  - Unit, dtype, and missing-value conventions
"""

# ═══════════════════════════════════════════════════════════════════════
# CSE-CIC-IDS2018 Feature Policy (80-column CICFlowMeter schema)
# ═══════════════════════════════════════════════════════════════════════

CSE_FEATURE_POLICY = {
    # ── Identifiers (NOT features — preserved as metadata) ─────────
    "Timestamp":        {"role": "metadata", "dtype": "string",  "unit": "DD/MM/YYYY HH:MM:SS", "notes": "Flow start time. Parse to epoch for ordering; exclude from feature vectors."},
    "Flow ID":          {"role": "identifier", "dtype": "string", "unit": "N/A",     "notes": "Only in 84-col schema (Thuesday-20-02). Flow identifier; exclude from features."},
    "Src IP":           {"role": "identifier", "dtype": "string", "unit": "N/A",     "notes": "Only in 84-col schema. Source IP address; exclude to prevent overfitting to lab topology."},
    "Dst IP":           {"role": "identifier", "dtype": "string", "unit": "N/A",     "notes": "Only in 84-col schema. Destination IP; exclude to prevent overfitting."},

    # ── Port Features (ASSESS: potentially useful) ─────────────────
    "Dst Port":         {"role": "feature_assess", "dtype": "int",    "unit": "TCP/UDP port",  "notes": "Destination port. KEEP as feature — certain attacks target specific services (80, 443, 22, 21). ML team should evaluate with/without."},
    "Src Port":         {"role": "feature_assess", "dtype": "int",    "unit": "TCP/UDP port",  "notes": "Only in 84-col schema. Source port. Typically ephemeral (>1024) so less informative, but may reveal patterns."},

    # ── Protocol ───────────────────────────────────────────────────
    "Protocol":         {"role": "feature", "dtype": "int_categorical", "unit": "IP protocol number", "notes": "0=HOPOPT, 6=TCP, 17=UDP. Treat as categorical."},

    # ── Flow Duration ──────────────────────────────────────────────
    "Flow Duration":    {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Total duration of the flow. Core feature for anomaly detection."},

    # ── Packet Counts ──────────────────────────────────────────────
    "Tot Fwd Pkts":     {"role": "feature", "dtype": "int64",   "unit": "count",  "notes": "Total forward packets."},
    "Tot Bwd Pkts":     {"role": "feature", "dtype": "int64",   "unit": "count",  "notes": "Total backward packets."},

    # ── Byte Lengths ───────────────────────────────────────────────
    "TotLen Fwd Pkts":  {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Total bytes in forward direction."},
    "TotLen Bwd Pkts":  {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Total bytes in backward direction."},

    # ── Packet Length Statistics ────────────────────────────────────
    "Fwd Pkt Len Max":  {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Max forward packet length."},
    "Fwd Pkt Len Min":  {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Min forward packet length."},
    "Fwd Pkt Len Mean": {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Mean forward packet length."},
    "Fwd Pkt Len Std":  {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Std dev forward packet length."},
    "Bwd Pkt Len Max":  {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Max backward packet length."},
    "Bwd Pkt Len Min":  {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Min backward packet length."},
    "Bwd Pkt Len Mean": {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Mean backward packet length."},
    "Bwd Pkt Len Std":  {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Std dev backward packet length."},

    # ── Flow Rate ──────────────────────────────────────────────────
    "Flow Byts/s":      {"role": "feature", "dtype": "float64", "unit": "bytes/second", "notes": "Flow byte rate. May contain inf when duration=0; replace inf→NaN."},
    "Flow Pkts/s":      {"role": "feature", "dtype": "float64", "unit": "packets/second", "notes": "Flow packet rate. May contain inf; replace inf→NaN."},

    # ── Inter-Arrival Time (IAT) ───────────────────────────────────
    "Flow IAT Mean":    {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Mean inter-arrival time of flow packets."},
    "Flow IAT Std":     {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Std dev of inter-arrival time."},
    "Flow IAT Max":     {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Max inter-arrival time."},
    "Flow IAT Min":     {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Min inter-arrival time."},
    "Fwd IAT Tot":      {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Total forward inter-arrival time."},
    "Fwd IAT Mean":     {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Mean forward inter-arrival time."},
    "Fwd IAT Std":      {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Std dev forward inter-arrival time."},
    "Fwd IAT Max":      {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Max forward inter-arrival time."},
    "Fwd IAT Min":      {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Min forward inter-arrival time."},
    "Bwd IAT Tot":      {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Total backward inter-arrival time."},
    "Bwd IAT Mean":     {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Mean backward inter-arrival time."},
    "Bwd IAT Std":      {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Std dev backward inter-arrival time."},
    "Bwd IAT Max":      {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Max backward inter-arrival time."},
    "Bwd IAT Min":      {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Min backward inter-arrival time."},

    # ── TCP Flags ──────────────────────────────────────────────────
    "Fwd PSH Flags":    {"role": "feature", "dtype": "int64",   "unit": "count",  "notes": "Forward PSH flag count."},
    "Bwd PSH Flags":    {"role": "feature", "dtype": "int64",   "unit": "count",  "notes": "Backward PSH flag count."},
    "Fwd URG Flags":    {"role": "feature", "dtype": "int64",   "unit": "count",  "notes": "Forward URG flag count."},
    "Bwd URG Flags":    {"role": "feature", "dtype": "int64",   "unit": "count",  "notes": "Backward URG flag count."},
    "FIN Flag Cnt":     {"role": "feature", "dtype": "int64",   "unit": "count",  "notes": "FIN flag count."},
    "SYN Flag Cnt":     {"role": "feature", "dtype": "int64",   "unit": "count",  "notes": "SYN flag count."},
    "RST Flag Cnt":     {"role": "feature", "dtype": "int64",   "unit": "count",  "notes": "RST flag count."},
    "PSH Flag Cnt":     {"role": "feature", "dtype": "int64",   "unit": "count",  "notes": "PSH flag count."},
    "ACK Flag Cnt":     {"role": "feature", "dtype": "int64",   "unit": "count",  "notes": "ACK flag count."},
    "URG Flag Cnt":     {"role": "feature", "dtype": "int64",   "unit": "count",  "notes": "URG flag count."},
    "CWE Flag Count":   {"role": "feature", "dtype": "int64",   "unit": "count",  "notes": "CWR (Congestion Window Reduced) flag count."},
    "ECE Flag Cnt":     {"role": "feature", "dtype": "int64",   "unit": "count",  "notes": "ECE (ECN-Echo) flag count."},

    # ── Header Lengths ─────────────────────────────────────────────
    "Fwd Header Len":   {"role": "feature", "dtype": "int64",   "unit": "bytes",  "notes": "Forward header length."},
    "Bwd Header Len":   {"role": "feature", "dtype": "int64",   "unit": "bytes",  "notes": "Backward header length."},

    # ── Packets/s Direction ────────────────────────────────────────
    "Fwd Pkts/s":       {"role": "feature", "dtype": "float64", "unit": "packets/second", "notes": "Forward packet rate."},
    "Bwd Pkts/s":       {"role": "feature", "dtype": "float64", "unit": "packets/second", "notes": "Backward packet rate."},

    # ── Packet Length Aggregates ───────────────────────────────────
    "Pkt Len Min":      {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Min packet length (both directions)."},
    "Pkt Len Max":      {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Max packet length."},
    "Pkt Len Mean":     {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Mean packet length."},
    "Pkt Len Std":      {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Std dev packet length."},
    "Pkt Len Var":      {"role": "feature", "dtype": "float64", "unit": "bytes²", "notes": "Variance of packet length."},
    "Pkt Size Avg":     {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Average packet size."},
    "Fwd Seg Size Avg": {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Average forward segment size."},
    "Bwd Seg Size Avg": {"role": "feature", "dtype": "float64", "unit": "bytes",  "notes": "Average backward segment size."},

    # ── Bulk Rate (typically zero) ─────────────────────────────────
    "Fwd Byts/b Avg":   {"role": "feature", "dtype": "float64", "unit": "bytes/bulk", "notes": "Forward bytes per bulk. Usually 0."},
    "Fwd Pkts/b Avg":   {"role": "feature", "dtype": "float64", "unit": "pkts/bulk",  "notes": "Forward packets per bulk. Usually 0."},
    "Fwd Blk Rate Avg": {"role": "feature", "dtype": "float64", "unit": "rate",       "notes": "Forward bulk rate avg. Usually 0."},
    "Bwd Byts/b Avg":   {"role": "feature", "dtype": "float64", "unit": "bytes/bulk", "notes": "Backward bytes per bulk. Usually 0."},
    "Bwd Pkts/b Avg":   {"role": "feature", "dtype": "float64", "unit": "pkts/bulk",  "notes": "Backward packets per bulk. Usually 0."},
    "Bwd Blk Rate Avg": {"role": "feature", "dtype": "float64", "unit": "rate",       "notes": "Backward bulk rate avg. Usually 0."},

    # ── Subflow ────────────────────────────────────────────────────
    "Subflow Fwd Pkts":  {"role": "feature", "dtype": "int64",   "unit": "count", "notes": "Subflow forward packet count."},
    "Subflow Fwd Byts":  {"role": "feature", "dtype": "float64", "unit": "bytes", "notes": "Subflow forward byte count."},
    "Subflow Bwd Pkts":  {"role": "feature", "dtype": "int64",   "unit": "count", "notes": "Subflow backward packet count."},
    "Subflow Bwd Byts":  {"role": "feature", "dtype": "float64", "unit": "bytes", "notes": "Subflow backward byte count."},

    # ── Window Sizes ───────────────────────────────────────────────
    "Init Fwd Win Byts": {"role": "feature", "dtype": "int64",   "unit": "bytes", "notes": "Initial forward TCP window size. -1 means not TCP."},
    "Init Bwd Win Byts": {"role": "feature", "dtype": "int64",   "unit": "bytes", "notes": "Initial backward TCP window size."},

    # ── Active Data ────────────────────────────────────────────────
    "Fwd Act Data Pkts": {"role": "feature", "dtype": "int64",   "unit": "count", "notes": "Forward packets with at least 1 byte of payload."},
    "Fwd Seg Size Min":  {"role": "feature", "dtype": "int64",   "unit": "bytes", "notes": "Minimum forward segment size."},

    # ── Down/Up Ratio ──────────────────────────────────────────────
    "Down/Up Ratio":     {"role": "feature", "dtype": "float64", "unit": "ratio", "notes": "Download-to-upload ratio."},

    # ── Active/Idle Time Statistics ────────────────────────────────
    "Active Mean":       {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Mean active time before going idle."},
    "Active Std":        {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Std dev active time."},
    "Active Max":        {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Max active time."},
    "Active Min":        {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Min active time."},
    "Idle Mean":         {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Mean idle time."},
    "Idle Std":          {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Std dev idle time."},
    "Idle Max":          {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Max idle time."},
    "Idle Min":          {"role": "feature", "dtype": "float64", "unit": "microseconds", "notes": "Min idle time."},

    # ── Target Label ───────────────────────────────────────────────
    "Label":             {"role": "target", "dtype": "string", "unit": "N/A", "notes": "Attack class label. 'Benign' or attack name."},
}


def get_cse_feature_columns() -> list:
    """Return the list of columns designated as predictive features."""
    return [k for k, v in CSE_FEATURE_POLICY.items() if v["role"] in ("feature", "feature_assess")]


def get_cse_metadata_columns() -> list:
    """Return columns that are metadata (not features)."""
    return [k for k, v in CSE_FEATURE_POLICY.items() if v["role"] in ("metadata", "identifier")]


def get_cse_numeric_features() -> list:
    """Return numeric-only feature columns."""
    return [
        k for k, v in CSE_FEATURE_POLICY.items()
        if v["role"] in ("feature", "feature_assess") and v["dtype"] in ("float64", "int64")
    ]


def get_cse_categorical_features() -> list:
    """Return categorical feature columns."""
    return [k for k, v in CSE_FEATURE_POLICY.items() if v["dtype"] == "int_categorical"]
