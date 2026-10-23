"""
CSV Ingestion & Validation Engine
Team Neural Breach — Role 2: Network Feature Extraction & Preprocessing

Provides chunked, memory-safe CSV reading with:
  - Schema validation against a reference column list
  - Repeated-header row detection and exclusion
  - Infinite / NaN / non-numeric value identification in numeric columns
  - Per-row exclusion logging with reasons
  - Provenance tracking back to source file and line number
"""

import csv
import os
import json
import hashlib
from collections import Counter
from datetime import datetime, timezone


class CSVValidationReport:
    """Accumulates validation statistics for a single CSV file."""

    def __init__(self, source_file: str):
        self.source_file = source_file
        self.source_basename = os.path.basename(source_file)
        self.source_size_bytes = os.path.getsize(source_file) if os.path.exists(source_file) else 0
        self.header_columns = []
        self.num_columns = 0
        self.rows_read = 0
        self.rows_retained = 0
        self.rows_rejected = 0
        self.repeated_headers = 0
        self.malformed_rows = 0  # wrong column count
        self.inf_values_found = 0
        self.nan_values_found = 0
        self.non_numeric_in_numeric_col = 0
        self.label_dist_before = Counter()
        self.label_dist_after = Counter()
        self.rejection_reasons = Counter()
        self.started_at = None
        self.finished_at = None

    def to_dict(self) -> dict:
        return {
            "source_file": self.source_file,
            "source_basename": self.source_basename,
            "source_size_bytes": self.source_size_bytes,
            "num_columns": self.num_columns,
            "rows_read": self.rows_read,
            "rows_retained": self.rows_retained,
            "rows_rejected": self.rows_rejected,
            "repeated_headers": self.repeated_headers,
            "malformed_rows": self.malformed_rows,
            "inf_values_found": self.inf_values_found,
            "nan_values_found": self.nan_values_found,
            "non_numeric_in_numeric_col": self.non_numeric_in_numeric_col,
            "label_distribution_before": dict(self.label_dist_before.most_common()),
            "label_distribution_after": dict(self.label_dist_after.most_common()),
            "rejection_reasons": dict(self.rejection_reasons.most_common()),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


def compute_sha256(filepath: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(4 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def validate_schema(actual_cols: list, expected_cols: list) -> dict:
    """
    Compare actual columns against expected columns.
    Returns dict with missing, extra, and matching columns.
    """
    actual_set = set(c.strip() for c in actual_cols)
    expected_set = set(c.strip() for c in expected_cols)
    return {
        "matching": sorted(actual_set & expected_set),
        "missing_from_actual": sorted(expected_set - actual_set),
        "extra_in_actual": sorted(actual_set - expected_set),
        "match_count": len(actual_set & expected_set),
        "total_expected": len(expected_set),
        "total_actual": len(actual_set),
        "is_exact_match": actual_set == expected_set,
    }


def is_repeated_header(row: list, header: list) -> bool:
    """Check if a data row is actually a repeated copy of the header."""
    if len(row) != len(header):
        return False
    return all(r.strip() == h.strip() for r, h in zip(row, header))


def detect_numeric_issues(value: str) -> str | None:
    """
    Check a string value for numeric issues.
    Returns reason string if problematic, None if clean.
    """
    v = value.strip()
    if v == "" or v.lower() == "nan":
        return "nan_value"
    if v.lower() in ("inf", "-inf", "infinity", "-infinity"):
        return "inf_value"
    try:
        float(v)
        return None
    except (ValueError, OverflowError):
        return "non_numeric"


def read_csv_chunked(filepath: str, chunk_size: int = 100_000,
                     expected_columns: list = None,
                     numeric_columns: list = None,
                     label_column: str = "Label"):
    """
    Generator that reads a CSV file in chunks, yielding validated rows.

    Yields tuples of:
        (chunk_index, rows_list, chunk_report)

    Where each row in rows_list is a dict with column names as keys.
    The chunk_report contains per-chunk validation statistics.

    Parameters
    ----------
    filepath : str
        Path to the CSV file.
    chunk_size : int
        Number of rows to yield per chunk.
    expected_columns : list, optional
        If provided, validate the header against these columns.
    numeric_columns : list, optional
        Columns that must contain numeric values.
    label_column : str
        Name of the label/target column.
    """
    report = CSVValidationReport(filepath)
    report.started_at = datetime.now(timezone.utc).isoformat()

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        # Read and validate header
        header_line = f.readline().strip()
        header = [c.strip() for c in header_line.split(",")]
        report.header_columns = header
        report.num_columns = len(header)

        if expected_columns:
            schema_result = validate_schema(header, expected_columns)
            if not schema_result["is_exact_match"]:
                report.schema_validation = schema_result

        label_idx = header.index(label_column) if label_column in header else -1

        # Determine which columns to check for numeric issues
        if numeric_columns is None:
            # Auto-detect: all columns except label, timestamp, protocol identifiers
            skip_cols = {label_column, "Timestamp", "Flow ID", "Src IP", "Dst IP"}
            numeric_col_indices = [
                i for i, c in enumerate(header)
                if c not in skip_cols
            ]
        else:
            numeric_col_indices = [
                i for i, c in enumerate(header)
                if c in set(numeric_columns)
            ]

        chunk_rows = []
        chunk_idx = 0

        for line in f:
            report.rows_read += 1
            row = line.strip().split(",")

            # Extract label before any filtering
            raw_label = row[label_idx].strip() if label_idx >= 0 and len(row) > label_idx else "UNKNOWN"
            report.label_dist_before[raw_label] += 1

            # Check for repeated header
            if is_repeated_header(row, header):
                report.repeated_headers += 1
                report.rows_rejected += 1
                report.rejection_reasons["repeated_header"] += 1
                continue

            # Check column count
            if len(row) != len(header):
                report.malformed_rows += 1
                report.rows_rejected += 1
                report.rejection_reasons[f"column_count_mismatch_{len(row)}_vs_{len(header)}"] += 1
                continue

            # Check numeric columns for issues
            row_has_issue = False
            for ci in numeric_col_indices:
                issue = detect_numeric_issues(row[ci])
                if issue == "inf_value":
                    report.inf_values_found += 1
                    # Replace inf with NaN marker for downstream handling
                    row[ci] = ""
                elif issue == "nan_value":
                    report.nan_values_found += 1
                elif issue == "non_numeric":
                    report.non_numeric_in_numeric_col += 1

            # Build row dict
            row_dict = {header[i]: row[i].strip() for i in range(len(header))}
            chunk_rows.append(row_dict)
            report.rows_retained += 1
            report.label_dist_after[raw_label] += 1

            if len(chunk_rows) >= chunk_size:
                yield chunk_idx, chunk_rows, report
                chunk_rows = []
                chunk_idx += 1

        # Yield remaining rows
        if chunk_rows:
            yield chunk_idx, chunk_rows, report

    report.finished_at = datetime.now(timezone.utc).isoformat()
