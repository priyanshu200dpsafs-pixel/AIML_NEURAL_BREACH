"""Role 7 platform settings. All secrets come from the environment (NB_ prefix); none have usable defaults."""
from __future__ import annotations
from functools import lru_cache
from typing import List
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class PlatformSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NB_", env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://neural:change-me@localhost:5432/neural_breach"
    jwt_secret: str = Field(min_length=32)          # required: no default on purpose
    jwt_issuer: str = "neural-breach"
    jwt_audience: str = "neural-breach-api"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 60 * 60 * 24 * 14
    ws_ticket_ttl_seconds: int = 60
    download_token_ttl_seconds: int = 300

    enrollment_token_ttl_seconds: int = 60 * 60 * 24
    device_online_window_seconds: int = 180

    feature_columns_path: str = "models/role3_retrain_v2/supervised/feature_columns.json"
    max_batch_flows: int = 500
    max_request_bytes: int = 2_000_000
    max_timestamp_skew_seconds: int = 24 * 3600

    login_rate_per_minute: int = 10
    api_rate_per_minute: int = 600
    ingest_rate_per_minute: int = 120

    cors_origins: List[str] = Field(default_factory=list)   # explicit list only; wildcard rejected
    ws_max_connections_per_org: int = 50
    ws_poll_interval_seconds: float = 1.0

    job_max_attempts: int = 5
    job_backoff_base_seconds: int = 5
    job_lock_timeout_seconds: int = 300
    detection_adapter: str = ""     # dotted path "pkg.module:factory" -> object with process(list[dict]) -> list[dict]

    alert_retention_days: int = 90
    flow_retention_days: int = 14
    heartbeat_retention_days: int = 30
    audit_retention_days: int = 365

    # Public keys only (key_id -> base64 raw Ed25519 public key). Private keys never live here or in git.
    release_trusted_keys: dict = Field(default_factory=dict)


@lru_cache
def get_settings() -> PlatformSettings:
    s = PlatformSettings()  # type: ignore[call-arg]
    if "*" in s.cors_origins:
        raise ValueError("Wildcard CORS origin is not allowed")
    return s
