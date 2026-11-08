#!/usr/bin/env python3
"""
Backend Configuration Settings
Team Neural Breach — Role 6: Backend & Real-Time Detection
"""

import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class BackendSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NEURAL_BREACH_", extra="ignore")

    # Service settings
    APP_NAME: str = "Neural Breach Cyber Defense Platform API"
    APP_VERSION: str = "2.0.0-production"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Observe-Only Mode Governance: MUST ALWAYS REMAIN TRUE (No automated packet drops)
    OBSERVE_ONLY_MODE: bool = True
    ACTION_ENFORCED: str = "NONE_OBSERVE_ONLY"

    # Paths
    PROJECT_ROOT: str = PROJECT_ROOT
    MODELS_DIR: str = os.path.join(PROJECT_ROOT, "models", "role3_retrain_v2")
    STIX_PATH: str = os.path.join(PROJECT_ROOT, "data", "reference", "MITRE-ATT-CK", "enterprise-attack.json")
    TEST_SPLIT_PATH: str = os.path.join(PROJECT_ROOT, "data", "processed", "splits", "test.parquet")

    # Model settings
    DEFAULT_CLASSIFIER: str = "lightgbm"
    FPR_BUDGET: str = "1pct"
    
    # Alert Manager & Storage
    MAX_ALERT_BUFFER_SIZE: int = 10000
    DEDUPLICATION_WINDOW_SECONDS: int = 60
    
    # CORS
    CORS_ORIGINS: List[str] = ["*"]


settings = BackendSettings()
