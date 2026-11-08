#!/usr/bin/env python3
"""
Backend Configuration Settings & Security Invariants
Team Neural Breach — Role 6: Backend & Real-Time Detection
"""

import os
from typing import List, Any
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class BackendSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NEURAL_BREACH_", extra="ignore")

    # Service metadata (Certified as Research Prototype, not authorized for production blocking)
    APP_NAME: str = "Neural Breach Cyber Defense Platform API"
    APP_VERSION: str = "2.0.0-research-prototype"
    DEBUG: bool = False
    
    # Network interface: Default to localhost for secure local evaluation
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    
    # Observe-Only Mode Governance: MUST ALWAYS REMAIN TRUE (Immutable Invariant)
    OBSERVE_ONLY_MODE: bool = Field(default=True, frozen=True)
    ACTION_ENFORCED: str = Field(default="NONE_OBSERVE_ONLY", frozen=True)

    @field_validator("OBSERVE_ONLY_MODE", mode="before")
    @classmethod
    def enforce_observe_only_mode(cls, v: Any) -> bool:
        """Enforces that observe-only mode cannot be disabled through environment variables."""
        if v is False or (isinstance(v, str) and v.lower() in ("false", "0", "no", "disabled", "off")):
            raise ValueError(
                "SECURITY INVARIANT VIOLATION: OBSERVE_ONLY_MODE is a fixed invariant that "
                "cannot be disabled. Automated packet blocking is strictly prohibited by project governance."
            )
        return True

    @field_validator("ACTION_ENFORCED", mode="before")
    @classmethod
    def enforce_action_enforced(cls, v: Any) -> str:
        """Enforces that action enforced remains strictly NONE_OBSERVE_ONLY."""
        if v != "NONE_OBSERVE_ONLY":
            raise ValueError(
                "SECURITY INVARIANT VIOLATION: ACTION_ENFORCED must remain 'NONE_OBSERVE_ONLY'."
            )
        return "NONE_OBSERVE_ONLY"

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
    
    # Request limits & batch governance
    MAX_BATCH_SIZE: int = 500
    
    # Explicit CORS: Restrict to explicit local development dashboard origins
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8000",
        "http://127.0.0.1:8000"
    ]


settings = BackendSettings()
