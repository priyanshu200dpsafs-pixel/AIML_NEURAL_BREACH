"""SQLAlchemy 2.0 models. Portable types (String(36) UUIDs, JSON) so tests can run on SQLite; production is PostgreSQL.
Every tenant-owned table carries org_id and is always queried with it."""
from __future__ import annotations
import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import (JSON, BigInteger, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text,
                        UniqueConstraint, CheckConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base, utcnow


def _id() -> str:
    return str(uuid.uuid4())


def _pk():
    return mapped_column(String(36), primary_key=True, default=_id)


def _ts(**kw):
    return mapped_column(DateTime(timezone=True), default=utcnow, **kw)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = _pk()
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[Optional[str]] = mapped_column(String(120))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_platform_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _ts()


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = _ts()


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("user_id", "org_id"),
                      CheckConstraint("role in ('owner','admin','analyst','viewer')", name="ck_membership_role"))
    id: Mapped[str] = _pk()
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = _ts()


class AuthSession(Base):
    """Refresh-token session. Only a SHA-256 of the opaque refresh token is stored. `family_id` enables reuse detection."""
    __tablename__ = "auth_sessions"
    id: Mapped[str] = _pk()
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    family_id: Mapped[str] = mapped_column(String(36), index=True)
    refresh_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    rotated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _ts()


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"
    id: Mapped[str] = _pk()
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    label: Mapped[Optional[str]] = mapped_column(String(120))
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    used_by_device: Mapped[Optional[str]] = mapped_column(String(36))
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _ts()


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (Index("ix_devices_org_status", "org_id", "status"),
                      CheckConstraint("status in ('active','revoked')", name="ck_device_status"))
    id: Mapped[str] = _pk()
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    os_name: Mapped[str] = mapped_column(String(64))
    os_version: Mapped[Optional[str]] = mapped_column(String(64))
    cpu_arch: Mapped[str] = mapped_column(String(32))
    client_version: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="active")
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[Optional[str]] = mapped_column(String(255))
    created_at: Mapped[datetime] = _ts()


class DeviceCredential(Base):
    __tablename__ = "device_credentials"
    id: Mapped[str] = _pk()
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    secret_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = _ts()
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class DeviceHeartbeat(Base):
    __tablename__ = "device_heartbeats"
    __table_args__ = (Index("ix_hb_device_time", "device_id", "received_at"),)
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    client_version: Mapped[str] = mapped_column(String(32))
    status_info: Mapped[Optional[dict]] = mapped_column(JSON)
    received_at: Mapped[datetime] = _ts()


class DeviceConfig(Base):
    __tablename__ = "device_configs"
    id: Mapped[str] = _pk()
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[Optional[str]] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)  # NULL = org default
    version: Mapped[int] = mapped_column(Integer, default=1)
    config: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[datetime] = _ts()


class TelemetryBatch(Base):
    __tablename__ = "telemetry_batches"
    __table_args__ = (UniqueConstraint("device_id", "idempotency_key", name="uq_batch_idem"),
                      Index("ix_batches_org_time", "org_id", "received_at"),
                      CheckConstraint("status in ('accepted','processing','processed','failed','rejected')", name="ck_batch_status"))
    id: Mapped[str] = _pk()
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(128))
    payload_sha256: Mapped[str] = mapped_column(String(64))
    flow_count: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(16), default="accepted")
    error: Mapped[Optional[str]] = mapped_column(Text)
    received_at: Mapped[datetime] = _ts()


class NetworkFlow(Base):
    """Statistical flow features only (the frozen 77-feature contract). No payloads, no packet capture."""
    __tablename__ = "network_flows"
    __table_args__ = (Index("ix_flows_org_time", "org_id", "observed_at"),)
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(String(36))
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("telemetry_batches.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    features: Mapped[dict] = mapped_column(JSON)


class Job(Base):
    """Postgres-backed work queue (FOR UPDATE SKIP LOCKED). See docs for why Redis is not required."""
    __tablename__ = "jobs"
    __table_args__ = (Index("ix_jobs_claim", "status", "run_after"),
                      UniqueConstraint("kind", "batch_id", name="uq_job_kind_batch"),
                      CheckConstraint("status in ('queued','running','done','failed')", name="ck_job_status"))
    id: Mapped[str] = _pk()
    kind: Mapped[str] = mapped_column(String(32), default="infer_batch")
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("telemetry_batches.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(12), default="queued")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5)
    run_after: Mapped[datetime] = _ts()
    locked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    locked_by: Mapped[Optional[str]] = mapped_column(String(64))
    last_error: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = _ts()
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_org_time", "org_id", "last_seen"),
                      Index("ix_alerts_org_sev", "org_id", "threat_level"),
                      Index("ix_alerts_dedup", "org_id", "device_id", "signature"),
                      CheckConstraint("investigation_status in ('new','acknowledged','investigating','resolved','false_positive')",
                                      name="ck_alert_status"))
    id: Mapped[str] = _pk()
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    batch_id: Mapped[Optional[str]] = mapped_column(ForeignKey("telemetry_batches.id", ondelete="SET NULL"))
    signature: Mapped[str] = mapped_column(String(64))
    label: Mapped[str] = mapped_column(String(100))
    attack_category: Mapped[Optional[str]] = mapped_column(String(100), index=True)
    threat_level: Mapped[str] = mapped_column(String(20))
    priority_score: Mapped[Optional[float]] = mapped_column(Float)
    repeat_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = _ts()
    last_seen: Mapped[datetime] = _ts()
    investigation_status: Mapped[str] = mapped_column(String(20), default="new")
    acknowledged_by: Mapped[Optional[str]] = mapped_column(String(36))
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    # Role 6 alert response schema (prediction, SHAP/LIME, MITRE, priority, playbook) kept verbatim:
    payload: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = _ts()


class AlertNote(Base):
    __tablename__ = "alert_notes"
    id: Mapped[str] = _pk()
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    org_id: Mapped[str] = mapped_column(String(36), index=True)
    author_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = _ts()


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_org_time", "org_id", "created_at"),)
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    org_id: Mapped[Optional[str]] = mapped_column(String(36))
    actor_type: Mapped[str] = mapped_column(String(10))   # user | device | system
    actor_id: Mapped[Optional[str]] = mapped_column(String(36))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[Optional[str]] = mapped_column(String(100))
    outcome: Mapped[str] = mapped_column(String(10), default="success")
    ip: Mapped[Optional[str]] = mapped_column(String(64))
    request_id: Mapped[Optional[str]] = mapped_column(String(64))
    detail: Mapped[Optional[dict]] = mapped_column(JSON)
    created_at: Mapped[datetime] = _ts()


class ModelVersion(Base):
    __tablename__ = "model_versions"
    id: Mapped[str] = _pk()
    name: Mapped[str] = mapped_column(String(100))
    version: Mapped[str] = mapped_column(String(64))
    artifact_sha256: Mapped[Optional[str]] = mapped_column(String(64))
    feature_contract_sha256: Mapped[Optional[str]] = mapped_column(String(64))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = _ts()
    __table_args__ = (UniqueConstraint("name", "version"),)


class Release(Base):
    __tablename__ = "releases"
    __table_args__ = (UniqueConstraint("version", "channel", "os_name", "cpu_arch", name="uq_release_target"),
                      Index("ix_release_lookup", "channel", "os_name", "cpu_arch"),
                      CheckConstraint("channel in ('stable','beta')", name="ck_release_channel"))
    id: Mapped[str] = _pk()
    version: Mapped[str] = mapped_column(String(32))
    channel: Mapped[str] = mapped_column(String(10))
    os_name: Mapped[str] = mapped_column(String(32))
    cpu_arch: Mapped[str] = mapped_column(String(32))
    artifact_name: Mapped[str] = mapped_column(String(255))
    artifact_size: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    key_id: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(Text)
    signed_metadata: Mapped[dict] = mapped_column(JSON)
    artifact_url: Mapped[Optional[str]] = mapped_column(String(1000))
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[Optional[str]] = mapped_column(String(255))
    created_at: Mapped[datetime] = _ts()


class ReleasePolicy(Base):
    __tablename__ = "release_policies"
    channel: Mapped[str] = mapped_column(String(10), primary_key=True)
    min_supported_version: Mapped[str] = mapped_column(String(32))
    updated_at: Mapped[datetime] = _ts()
