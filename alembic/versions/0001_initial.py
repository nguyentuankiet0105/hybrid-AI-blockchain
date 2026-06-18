"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-18
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # users
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), nullable=False, server_default="soc_analyst"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("mfa_secret", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
    )

    # gateways
    op.create_table(
        "gateways",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("hostname", sa.String(256), nullable=False, unique=True),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("bc_address", sa.String(42), nullable=True),
        sa.Column("x509_cert_hash", postgresql.BYTEA, nullable=True),
        sa.Column("model_version", sa.String(64), nullable=True),
        sa.Column("model_hash", postgresql.BYTEA, nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="ONLINE"),
        sa.Column("cpu_pct", sa.Numeric(5, 2), nullable=True),
        sa.Column("mem_mb", sa.Integer, nullable=True),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=True),
        sa.Column("registered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # devices
    op.create_table(
        "devices",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("mac_address", sa.String(17), nullable=False, unique=True),
        sa.Column("device_hash", postgresql.BYTEA, nullable=False),
        sa.Column("name", sa.String(128), nullable=True),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("location", sa.String(256), nullable=True),
        sa.Column("protocol", sa.String(32), nullable=False, server_default="MQTT"),
        sa.Column("registered_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("registered_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="ACTIVE"),
        sa.Column("quarantine_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_anomaly_score", sa.Numeric(6, 4), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("bc_address", sa.String(42), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_devices_status", "devices", ["status"])
    op.create_index("idx_devices_mac", "devices", ["mac_address"])

    # anomaly_events
    op.create_table(
        "anomaly_events",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("anomaly_score", sa.Numeric(6, 4), nullable=False),
        sa.Column("is_alert", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("feat_packet_count", sa.Numeric(10, 2), nullable=True),
        sa.Column("feat_payload_size", sa.Numeric(10, 2), nullable=True),
        sa.Column("feat_unique_dst_ips", sa.Integer, nullable=True),
        sa.Column("feat_auth_failure_rate", sa.Numeric(6, 4), nullable=True),
        sa.Column("feat_protocol_entropy", sa.Numeric(6, 4), nullable=True),
        sa.Column("feat_interarrival_var", sa.Numeric(10, 4), nullable=True),
        sa.Column("feat_payload_entropy", sa.Numeric(6, 4), nullable=True),
        sa.Column("feature_vector_hash", postgresql.BYTEA, nullable=True),
        sa.Column("bc_tx_hash", sa.String(66), nullable=True),
        sa.Column("bc_block_number", sa.BigInteger, nullable=True),
        sa.Column("inference_ms", sa.Numeric(6, 2), nullable=True),
        sa.Column("gateway_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("gateways.id"), nullable=True),
    )
    op.create_index("idx_ae_device_time", "anomaly_events", ["device_id", "window_start"])
    op.create_index("idx_ae_alerts", "anomaly_events", ["is_alert", "window_start"])

    # security_incidents
    op.create_table(
        "security_incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("anomaly_event_id", sa.BigInteger, sa.ForeignKey("anomaly_events.id"), nullable=True),
        sa.Column("attack_type", sa.String(64), nullable=True),
        sa.Column("severity", sa.String(16), nullable=False, server_default="MEDIUM"),
        sa.Column("status", sa.String(32), nullable=False, server_default="OPEN"),
        sa.Column("bc_quarantine_tx", sa.String(66), nullable=True),
        sa.Column("bc_revoke_tx", sa.String(66), nullable=True),
        sa.Column("bc_reinstate_tx", sa.String(66), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("resolution_notes", sa.Text, nullable=True),
        sa.Column("copilot_report_hash", postgresql.BYTEA, nullable=True),
    )
    op.create_index("idx_si_device", "security_incidents", ["device_id"])
    op.create_index("idx_si_status", "security_incidents", ["status"])
    op.create_index("idx_si_opened", "security_incidents", ["opened_at"])

    # blockchain_events
    op.create_table(
        "blockchain_events",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("device_mac", sa.String(17), nullable=True),
        sa.Column("bc_tx_hash", sa.String(66), nullable=False, unique=True),
        sa.Column("bc_block_number", sa.BigInteger, nullable=False),
        sa.Column("bc_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("anomaly_score", sa.Numeric(6, 4), nullable=True),
        sa.Column("evidence_hash", postgresql.BYTEA, nullable=True),
        sa.Column("gas_used", sa.Integer, nullable=True),
        sa.Column("emitted_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("synced", sa.Boolean, nullable=False, server_default="true"),
    )
    op.create_index("idx_be_device", "blockchain_events", ["device_mac", "bc_timestamp"])
    op.create_index("idx_be_block", "blockchain_events", ["bc_block_number"])

    # copilot_sessions
    op.create_table(
        "copilot_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("security_incidents.id"), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tool_call_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("bc_report_hash", postgresql.BYTEA, nullable=True),
        sa.Column("confidence_level", sa.String(8), nullable=True),
    )

    # copilot_messages
    op.create_table(
        "copilot_messages",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("copilot_sessions.id"), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("tool_name", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("copilot_messages")
    op.drop_table("copilot_sessions")
    op.drop_table("blockchain_events")
    op.drop_table("security_incidents")
    op.drop_table("anomaly_events")
    op.drop_table("devices")
    op.drop_table("gateways")
    op.drop_table("users")
