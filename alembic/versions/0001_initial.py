"""Initial Role 7 schema.

Explicit, reviewable schema migration defining all multi-tenant tables,
indexes, foreign keys, and constraints.
"""
from __future__ import annotations
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # 1. users
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(120), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_platform_admin", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("failed_logins", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index("ix_users_email", "users", ["email"])

    # 2. organizations
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False)
    )

    # 3. memberships
    op.create_table(
        "memberships",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", "org_id", name="uq_membership_user_org"),
        sa.CheckConstraint("role in ('owner','admin','analyst','viewer')", name="ck_membership_role")
    )
    op.create_index("ix_memberships_user_id", "memberships", ["user_id"])
    op.create_index("ix_memberships_org_id", "memberships", ["org_id"])

    # 4. auth_sessions
    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("family_id", sa.String(36), nullable=False),
        sa.Column("refresh_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])
    op.create_index("ix_auth_sessions_family_id", "auth_sessions", ["family_id"])

    # 5. enrollment_tokens
    op.create_table(
        "enrollment_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("label", sa.String(120), nullable=True),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("used_by_device", sa.String(36), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index("ix_enrollment_tokens_org_id", "enrollment_tokens", ["org_id"])

    # 6. devices
    op.create_table(
        "devices",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("os_name", sa.String(64), nullable=False),
        sa.Column("os_version", sa.String(64), nullable=True),
        sa.Column("cpu_arch", sa.String(32), nullable=False),
        sa.Column("client_version", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status in ('active','revoked')", name="ck_device_status")
    )
    op.create_index("ix_devices_org_id", "devices", ["org_id"])
    op.create_index("ix_devices_last_seen_at", "devices", ["last_seen_at"])
    op.create_index("ix_devices_org_status", "devices", ["org_id", "status"])

    # 7. device_credentials
    op.create_table(
        "device_credentials",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("secret_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_index("ix_device_credentials_device_id", "device_credentials", ["device_id"])

    # 8. device_heartbeats
    op.create_table(
        "device_heartbeats",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("client_version", sa.String(32), nullable=False),
        sa.Column("status_info", sa.JSON(), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index("ix_device_heartbeats_org_id", "device_heartbeats", ["org_id"])
    op.create_index("ix_hb_device_time", "device_heartbeats", ["device_id", "received_at"])

    # 9. device_configs
    op.create_table(
        "device_configs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index("ix_device_configs_org_id", "device_configs", ["org_id"])
    op.create_index("ix_device_configs_device_id", "device_configs", ["device_id"])

    # 10. telemetry_batches
    op.create_table(
        "telemetry_batches",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("flow_count", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="accepted"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("device_id", "idempotency_key", name="uq_batch_idem"),
        sa.CheckConstraint("status in ('accepted','processing','processed','failed','rejected')", name="ck_batch_status")
    )
    op.create_index("ix_telemetry_batches_device_id", "telemetry_batches", ["device_id"])
    op.create_index("ix_batches_org_time", "telemetry_batches", ["org_id", "received_at"])

    # 11. network_flows
    op.create_table(
        "network_flows",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("batch_id", sa.String(36), sa.ForeignKey("telemetry_batches.id", ondelete="CASCADE"), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("features", sa.JSON(), nullable=False)
    )
    op.create_index("ix_network_flows_device_id", "network_flows", ["device_id"])
    op.create_index("ix_network_flows_batch_id", "network_flows", ["batch_id"])
    op.create_index("ix_flows_org_time", "network_flows", ["org_id", "observed_at"])

    # 12. jobs
    op.create_table(
        "jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False, server_default="infer_batch"),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("batch_id", sa.String(36), sa.ForeignKey("telemetry_batches.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(12), nullable=False, server_default="queued"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default=sa.text("5")),
        sa.Column("run_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_by", sa.String(64), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("kind", "batch_id", name="uq_job_kind_batch"),
        sa.CheckConstraint("status in ('queued','running','done','failed')", name="ck_job_status")
    )
    op.create_index("ix_jobs_org_id", "jobs", ["org_id"])
    op.create_index("ix_jobs_claim", "jobs", ["status", "run_after"])

    # 13. alerts
    op.create_table(
        "alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("batch_id", sa.String(36), sa.ForeignKey("telemetry_batches.id", ondelete="SET NULL"), nullable=True),
        sa.Column("signature", sa.String(64), nullable=False),
        sa.Column("label", sa.String(100), nullable=False),
        sa.Column("attack_category", sa.String(100), nullable=True),
        sa.Column("threat_level", sa.String(20), nullable=False),
        sa.Column("priority_score", sa.Float(), nullable=True),
        sa.Column("repeat_count", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("investigation_status", sa.String(20), nullable=False, server_default="new"),
        sa.Column("acknowledged_by", sa.String(36), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("investigation_status in ('new','acknowledged','investigating','resolved','false_positive')", name="ck_alert_status")
    )
    op.create_index("ix_alerts_device_id", "alerts", ["device_id"])
    op.create_index("ix_alerts_attack_category", "alerts", ["attack_category"])
    op.create_index("ix_alerts_org_time", "alerts", ["org_id", "last_seen"])
    op.create_index("ix_alerts_org_sev", "alerts", ["org_id", "threat_level"])
    op.create_index("ix_alerts_dedup", "alerts", ["org_id", "device_id", "signature"])

    # 14. alert_notes
    op.create_table(
        "alert_notes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("alert_id", sa.String(36), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("author_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index("ix_alert_notes_alert_id", "alert_notes", ["alert_id"])
    op.create_index("ix_alert_notes_org_id", "alert_notes", ["org_id"])

    # 15. audit_log
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.String(36), nullable=True),
        sa.Column("actor_type", sa.String(10), nullable=False),
        sa.Column("actor_id", sa.String(36), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target", sa.String(100), nullable=True),
        sa.Column("outcome", sa.String(10), nullable=False, server_default="success"),
        sa.Column("ip", sa.String(64), nullable=True),
        sa.Column("request_id", sa.String(64), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False)
    )
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_org_time", "audit_log", ["org_id", "created_at"])

    # 16. model_versions
    op.create_table(
        "model_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("artifact_sha256", sa.String(64), nullable=True),
        sa.Column("feature_contract_sha256", sa.String(64), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name", "version", name="uq_model_version")
    )

    # 17. releases
    op.create_table(
        "releases",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("channel", sa.String(10), nullable=False),
        sa.Column("os_name", sa.String(32), nullable=False),
        sa.Column("cpu_arch", sa.String(32), nullable=False),
        sa.Column("artifact_name", sa.String(255), nullable=False),
        sa.Column("artifact_size", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("signed_metadata", sa.JSON(), nullable=False),
        sa.Column("artifact_url", sa.String(1000), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("version", "channel", "os_name", "cpu_arch", name="uq_release_target"),
        sa.CheckConstraint("channel in ('stable','beta')", name="ck_release_channel")
    )
    op.create_index("ix_release_lookup", "releases", ["channel", "os_name", "cpu_arch"])

    # 18. release_policies
    op.create_table(
        "release_policies",
        sa.Column("channel", sa.String(10), primary_key=True),
        sa.Column("min_supported_version", sa.String(32), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False)
    )


def downgrade():
    op.drop_table("release_policies")
    op.drop_table("releases")
    op.drop_table("model_versions")
    op.drop_table("audit_log")
    op.drop_table("alert_notes")
    op.drop_table("alerts")
    op.drop_table("jobs")
    op.drop_table("network_flows")
    op.drop_table("telemetry_batches")
    op.drop_table("device_configs")
    op.drop_table("device_heartbeats")
    op.drop_table("device_credentials")
    op.drop_table("devices")
    op.drop_table("enrollment_tokens")
    op.drop_table("auth_sessions")
    op.drop_table("memberships")
    op.drop_table("organizations")
    op.drop_table("users")
