"""
Numerical Preprocessing Pipeline — Reusable Transformations
Team Neural Breach — Role 2: Network Feature Extraction & Preprocessing

Provides configurable, fit-once-apply-many transformations:
  - Missing value imputation (median strategy, fit on train only)
  - Infinite value replacement (pre-imputation)
  - Numeric type coercion
  - Categorical encoding (LabelEncoder, fit on train only)
  - Numerical scaling (StandardScaler / MinMaxScaler, fit on train only)
  - Target label encoding with inverse mapping

CRITICAL: Fit imputation/scaling on training data ONLY.
          Apply fitted transformers to val/test/inference without refitting.
"""

import os
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, MinMaxScaler, LabelEncoder
from sklearn.impute import SimpleImputer
from datetime import datetime, timezone
from typing import Optional


class NumericalPreprocessor:
    """
    Fit-once, apply-many numerical preprocessing pipeline.
    
    All statistics (imputer medians, scaler means/stds, encoder classes)
    are computed from training data only.
    """

    def __init__(self, scaling_method: str = "standard"):
        """
        Parameters
        ----------
        scaling_method : str
            "standard" for StandardScaler (z-score normalization)
            "minmax" for MinMaxScaler (0-1 normalization)
            "none" for no scaling
        """
        self.scaling_method = scaling_method
        self.imputer = SimpleImputer(strategy="median")
        self.scaler = None
        self.label_encoder = LabelEncoder()
        self.feature_columns = None
        self.categorical_columns = None
        self.numeric_columns = None
        self.label_column = None
        self.label_classes = None
        self.label_to_int = None
        self.int_to_label = None
        self.is_fitted = False
        self.fit_stats = {}

        if scaling_method == "standard":
            self.scaler = StandardScaler()
        elif scaling_method == "minmax":
            self.scaler = MinMaxScaler()

    def fit(self, df: pd.DataFrame,
            feature_columns: list,
            label_column: str,
            categorical_columns: list = None):
        """
        Fit all transformers on training data.

        Parameters
        ----------
        df : pd.DataFrame
            Training DataFrame.
        feature_columns : list
            Columns to use as predictive features.
        label_column : str
            Target label column name.
        categorical_columns : list, optional
            Columns to treat as categorical (will be label-encoded).
        """
        self.feature_columns = feature_columns
        self.label_column = label_column
        self.categorical_columns = categorical_columns or []
        self.numeric_columns = [
            c for c in feature_columns if c not in self.categorical_columns
        ]

        # 1. Replace inf with NaN for imputation
        X = df[self.numeric_columns].copy()
        X = X.replace([np.inf, -np.inf], np.nan)

        # 2. Fit imputer (median strategy) on training data
        self.imputer.fit(X)
        self.fit_stats["imputer_medians"] = {
            col: float(med)
            for col, med in zip(self.numeric_columns, self.imputer.statistics_)
        }

        # 3. Apply imputation, then fit scaler
        X_imputed = pd.DataFrame(
            self.imputer.transform(X),
            columns=self.numeric_columns,
            index=X.index
        )

        if self.scaler is not None:
            self.scaler.fit(X_imputed)
            if hasattr(self.scaler, "mean_"):
                self.fit_stats["scaler_means"] = {
                    col: float(m) for col, m in zip(self.numeric_columns, self.scaler.mean_)
                }
            if hasattr(self.scaler, "scale_"):
                self.fit_stats["scaler_scales"] = {
                    col: float(s) for col, s in zip(self.numeric_columns, self.scaler.scale_)
                }

        # 4. Fit label encoder
        labels = df[label_column].astype(str).values
        self.label_encoder.fit(labels)
        self.label_classes = list(self.label_encoder.classes_)
        self.label_to_int = {
            lbl: int(idx) for idx, lbl in enumerate(self.label_classes)
        }
        self.int_to_label = {v: k for k, v in self.label_to_int.items()}
        self.fit_stats["label_mapping"] = self.label_to_int

        self.is_fitted = True
        return self

    def transform(self, df: pd.DataFrame, include_label: bool = True) -> pd.DataFrame:
        """
        Apply fitted transformations to a DataFrame.

        DOES NOT refit any statistics. Uses training-fitted parameters.
        """
        if not self.is_fitted:
            raise RuntimeError("Must call fit() before transform()")

        result = pd.DataFrame(index=df.index)

        # 1. Numeric features: replace inf → NaN → impute → scale
        X = df[self.numeric_columns].copy()
        X = X.replace([np.inf, -np.inf], np.nan)
        X_imputed = pd.DataFrame(
            self.imputer.transform(X),
            columns=self.numeric_columns,
            index=X.index
        )

        if self.scaler is not None:
            X_scaled = pd.DataFrame(
                self.scaler.transform(X_imputed),
                columns=self.numeric_columns,
                index=X.index
            )
        else:
            X_scaled = X_imputed

        for col in self.numeric_columns:
            result[col] = X_scaled[col]

        # 2. Categorical features: label-encode
        for col in self.categorical_columns:
            if col in df.columns:
                result[col] = df[col].astype("category").cat.codes

        # 3. Target label
        if include_label and self.label_column in df.columns:
            labels = df[self.label_column].astype(str).values
            # Handle unseen labels gracefully
            encoded = []
            for lbl in labels:
                if lbl in self.label_to_int:
                    encoded.append(self.label_to_int[lbl])
                else:
                    encoded.append(-1)  # Mark unknown labels
            result["Target"] = encoded
            result["_Original_Label"] = df[self.label_column].values

        return result

    def fit_transform(self, df: pd.DataFrame,
                      feature_columns: list,
                      label_column: str,
                      categorical_columns: list = None) -> pd.DataFrame:
        """Fit on training data and transform it in one step."""
        self.fit(df, feature_columns, label_column, categorical_columns)
        return self.transform(df)

    def save(self, dirpath: str):
        """Save fitted preprocessor state to disk."""
        os.makedirs(dirpath, exist_ok=True)
        state = {
            "scaling_method": self.scaling_method,
            "feature_columns": self.feature_columns,
            "label_column": self.label_column,
            "categorical_columns": self.categorical_columns,
            "numeric_columns": self.numeric_columns,
            "label_classes": self.label_classes,
            "label_to_int": self.label_to_int,
            "int_to_label": {str(k): v for k, v in self.int_to_label.items()},
            "fit_stats": self.fit_stats,
            "is_fitted": self.is_fitted,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(os.path.join(dirpath, "preprocessor_config.json"), "w") as f:
            json.dump(state, f, indent=2)
        with open(os.path.join(dirpath, "preprocessor.pkl"), "wb") as f:
            pickle.dump(self, f)

    @staticmethod
    def load(dirpath: str) -> "NumericalPreprocessor":
        """Load a previously saved preprocessor."""
        with open(os.path.join(dirpath, "preprocessor.pkl"), "rb") as f:
            return pickle.load(f)

    def get_label_mapping(self) -> dict:
        """Return the label-to-integer mapping."""
        return self.label_to_int.copy()

    def inverse_label(self, encoded: int) -> str:
        """Map an integer label back to the original class name."""
        return self.int_to_label.get(encoded, f"UNKNOWN_{encoded}")
