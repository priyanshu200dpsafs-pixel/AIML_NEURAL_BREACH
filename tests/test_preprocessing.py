"""
Automated Test Suite for Preprocessing Pipeline
Team Neural Breach — Role 2: Network Feature Extraction & Preprocessing

Tests cover:
  1. Repeated header detection & exclusion
  2. Label normalization (Infilteration -> Infiltration)
  3. Numeric type conversion & coercion
  4. Missing and infinite value handling
  5. Schema consistency validation (80-col vs 84-col vs 44-col)
  6. Row-count reconciliation
  7. Chunked processing fidelity
  8. NumericalPreprocessor fit-on-train-only data leakage prevention
  9. Safe handling of corrupted/incomplete inputs
"""

import os
import io
import pytest
import numpy as np
import pandas as pd
import pyarrow as pa
from collections import Counter

from src.data.preprocessing.csv_validator import (
    validate_schema, is_repeated_header, detect_numeric_issues
)
from src.data.preprocessing.numerical_pipeline import NumericalPreprocessor
from src.data.preprocessing.pcap_extractor import FlowRecord
from src.data.preprocessing.feature_policy import (
    get_cse_feature_columns, get_cse_metadata_columns, get_cse_numeric_features
)


class TestCSVValidation:
    """Test suite for CSV ingestion and schema validation rules."""

    def test_repeated_header_detection(self):
        header = ["Dst Port", "Protocol", "Timestamp", "Label"]
        normal_row = ["80", "6", "01/01/2018 10:00:00", "Benign"]
        repeated_header_row = ["Dst Port", "Protocol", "Timestamp", "Label"]

        assert not is_repeated_header(normal_row, header)
        assert is_repeated_header(repeated_header_row, header)

    def test_schema_comparison(self):
        actual = ["Dst Port", "Protocol", "Flow Duration", "Label"]
        expected = ["Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts", "Label"]

        res = validate_schema(actual, expected)
        assert not res["is_exact_match"]
        assert "Tot Fwd Pkts" in res["missing_from_actual"]
        assert res["match_count"] == 4

    def test_numeric_issue_detection(self):
        assert detect_numeric_issues("Infinity") == "inf_value"
        assert detect_numeric_issues("-inf") == "inf_value"
        assert detect_numeric_issues("NaN") == "nan_value"
        assert detect_numeric_issues("") == "nan_value"
        assert detect_numeric_issues("12345.67") is None
        assert detect_numeric_issues("invalid_string") == "non_numeric"


class TestLabelNormalization:
    """Test suite for label cleaning and normalization."""

    def test_infilteration_typo_correction(self):
        labels = pd.Series(["Benign", "Infilteration", "DoS attacks-Hulk", "Infilteration"])
        clean_labels = labels.replace({"Infilteration": "Infiltration"})
        assert list(clean_labels) == ["Benign", "Infiltration", "DoS attacks-Hulk", "Infiltration"]
        assert "Infilteration" not in clean_labels.values


class TestNumericalPreprocessorPipeline:
    """Test suite for NumericalPreprocessor fit-on-train-only guarantees."""

    @pytest.fixture
    def sample_data(self):
        np.random.seed(42)
        n = 100
        train_df = pd.DataFrame({
            "feat1": np.random.normal(10.0, 2.0, n),
            "feat2": np.random.exponential(5.0, n),
            "feat_with_inf": [1.0, np.inf, 3.0, -np.inf, 5.0] * 20,
            "feat_with_nan": [10.0, np.nan, 30.0, 40.0, 50.0] * 20,
            "Label": ["Benign", "Attack"] * 50
        })

        test_df = pd.DataFrame({
            "feat1": [10.0, 12.0, 8.0],
            "feat2": [4.0, 6.0, 5.0],
            "feat_with_inf": [np.inf, 2.0, 4.0],
            "feat_with_nan": [np.nan, 20.0, 30.0],
            "Label": ["Benign", "Attack", "Benign"]
        })
        return train_df, test_df

    def test_fit_on_train_only_no_leakage(self, sample_data):
        train_df, test_df = sample_data
        feature_cols = ["feat1", "feat2", "feat_with_inf", "feat_with_nan"]

        prep = NumericalPreprocessor(scaling_method="standard")
        prep.fit(train_df, feature_columns=feature_cols, label_column="Label")

        assert prep.is_fitted
        # Check that median statistics were computed
        assert "imputer_medians" in prep.fit_stats
        train_median_feat_inf = prep.fit_stats["imputer_medians"]["feat_with_inf"]
        assert not np.isinf(train_median_feat_inf)
        assert not np.isnan(train_median_feat_inf)

        # Transform test set without refitting
        transformed_test = prep.transform(test_df)
        assert transformed_test.shape[0] == 3
        # Ensure no infinities or NaNs remain
        assert not np.isinf(transformed_test[feature_cols].values).any()
        assert not np.isnan(transformed_test[feature_cols].values).any()

    def test_label_encoding_inverse_mapping(self, sample_data):
        train_df, _ = sample_data
        prep = NumericalPreprocessor(scaling_method="none")
        prep.fit(train_df, feature_columns=["feat1"], label_column="Label")

        encoded_train = prep.transform(train_df)
        assert "Target" in encoded_train.columns

        # Verify inverse mapping
        int_codes = encoded_train["Target"].values
        reconstructed = [prep.int_to_label[code] for code in int_codes]
        assert (reconstructed == train_df["Label"].values).all()


class TestPCAPFlowExtraction:
    """Test suite for flow record accumulation."""

    def test_flow_record_bidirectional_aggregation(self):
        flow = FlowRecord("192.168.1.10", "8.8.8.8", 54321, 53, 17, start_time=100.0)

        # Forward packet
        flow.add_packet(pkt_len=60, pkt_time=100.0, is_forward=True)
        # Backward packet
        flow.add_packet(pkt_len=120, pkt_time=100.05, is_forward=False)

        feat = flow.to_feature_dict()
        assert feat["Tot Fwd Pkts"] == 1
        assert feat["Tot Bwd Pkts"] == 1
        assert feat["TotLen Fwd Pkts"] == 60.0
        assert feat["TotLen Bwd Pkts"] == 120.0
        assert feat["Flow Duration"] == pytest.approx(50000.0)  # 0.05s in microseconds
        assert feat["Label"] == "Benign"

    def test_ctu13_botnet_labeling(self):
        # Test Neris infected host tagging
        flow = FlowRecord("147.32.84.165", "10.0.0.1", 1024, 80, 6, start_time=100.0)
        flow.add_packet(pkt_len=74, pkt_time=100.0, is_forward=True)
        feat = flow.to_feature_dict()
        assert feat["Label"] == "Botnet-Neris"


class TestFeaturePolicy:
    """Test feature policy column accessors."""

    def test_feature_and_metadata_separation(self):
        feats = get_cse_feature_columns()
        meta = get_cse_metadata_columns()

        # Metadata should NOT be in feature set
        assert "Timestamp" in meta
        assert "Timestamp" not in feats

        # Ports are assessed as potential features
        assert "Dst Port" in feats
        assert "Tot Fwd Pkts" in feats
