import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import BYTEA, INET, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


# ── Users ────────────────────────────────────────────────────


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="soc_analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    mfa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    devices_registered: Mapped[list["Device"]] = relationship(back_populates="registered_by_user")
    incidents_resolved: Mapped[list["SecurityIncident"]] = relationship(back_populates="resolved_by_user")
    copilot_sessions: Mapped[list["CopilotSession"]] = relationship(back_populates="user")


# ── Gateways ─────────────────────────────────────────────────


class Gateway(Base):
    __tablename__ = "gateways"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    bc_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    x509_cert_hash: Mapped[bytes | None] = mapped_column(BYTEA, nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model_hash: Mapped[bytes | None] = mapped_column(BYTEA, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ONLINE")
    cpu_pct: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    mem_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    anomaly_events: Mapped[list["AnomalyEvent"]] = relationship(back_populates="gateway")


# ── Devices ──────────────────────────────────────────────────


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        Index("idx_devices_status", "status"),
        Index("idx_devices_mac", "mac_address"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    mac_address: Mapped[str] = mapped_column(String(17), unique=True, nullable=False)
    device_hash: Mapped[bytes] = mapped_column(BYTEA, nullable=False)
    name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    location: Mapped[str | None] = mapped_column(String(256), nullable=True)
    protocol: Mapped[str] = mapped_column(String(32), nullable=False, default="MQTT")
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    registered_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ACTIVE")
    quarantine_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_anomaly_score: Mapped[float | None] = mapped_column(Numeric(6, 4), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    bc_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    registered_by_user: Mapped[User | None] = relationship(back_populates="devices_registered")
    anomaly_events: Mapped[list["AnomalyEvent"]] = relationship(back_populates="device")
    incidents: Mapped[list["SecurityIncident"]] = relationship(back_populates="device")


# ── Anomaly Events ───────────────────────────────────────────


class AnomalyEvent(Base):
    __tablename__ = "anomaly_events"
    __table_args__ = (
        Index("idx_ae_device_time", "device_id", "window_start"),
        Index("idx_ae_alerts", "is_alert", "window_start"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False
    )
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Numeric(6, 4), nullable=False)
    is_alert: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # 7 features
    feat_packet_count: Mapped[float | None] = mapped_column(Numeric(10, 2), nullable=True)
    feat_payload_size: Mapped[float | None] = mapped_column(Numeric(10, 2), nullable=True)
    feat_unique_dst_ips: Mapped[int | None] = mapped_column(Integer, nullable=True)
    feat_auth_failure_rate: Mapped[float | None] = mapped_column(Numeric(6, 4), nullable=True)
    feat_protocol_entropy: Mapped[float | None] = mapped_column(Numeric(6, 4), nullable=True)
    feat_interarrival_var: Mapped[float | None] = mapped_column(Numeric(10, 4), nullable=True)
    feat_payload_entropy: Mapped[float | None] = mapped_column(Numeric(6, 4), nullable=True)
    feature_vector_hash: Mapped[bytes | None] = mapped_column(BYTEA, nullable=True)
    bc_tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    bc_block_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    inference_ms: Mapped[float | None] = mapped_column(Numeric(6, 2), nullable=True)
    gateway_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("gateways.id"), nullable=True
    )

    device: Mapped[Device] = relationship(back_populates="anomaly_events")
    gateway: Mapped[Gateway | None] = relationship(back_populates="anomaly_events")
    incident: Mapped["SecurityIncident | None"] = relationship(back_populates="anomaly_event")


# ── Security Incidents ───────────────────────────────────────


class SecurityIncident(Base):
    __tablename__ = "security_incidents"
    __table_args__ = (
        Index("idx_si_device", "device_id"),
        Index("idx_si_status", "status"),
        Index("idx_si_opened", "opened_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False
    )
    anomaly_event_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("anomaly_events.id"), nullable=True
    )
    attack_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="MEDIUM")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="OPEN")
    bc_quarantine_tx: Mapped[str | None] = mapped_column(String(66), nullable=True)
    bc_revoke_tx: Mapped[str | None] = mapped_column(String(66), nullable=True)
    bc_reinstate_tx: Mapped[str | None] = mapped_column(String(66), nullable=True)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=True
    )
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    copilot_report_hash: Mapped[bytes | None] = mapped_column(BYTEA, nullable=True)

    device: Mapped[Device] = relationship(back_populates="incidents")
    anomaly_event: Mapped[AnomalyEvent | None] = relationship(back_populates="incident")
    resolved_by_user: Mapped[User | None] = relationship(back_populates="incidents_resolved")


# ── Blockchain Events (mirror) ───────────────────────────────


class BlockchainEvent(Base):
    __tablename__ = "blockchain_events"
    __table_args__ = (
        Index("idx_be_device", "device_mac", "bc_timestamp"),
        Index("idx_be_block", "bc_block_number"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    device_mac: Mapped[str | None] = mapped_column(String(17), nullable=True)
    bc_tx_hash: Mapped[str] = mapped_column(String(66), unique=True, nullable=False)
    bc_block_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    bc_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    anomaly_score: Mapped[float | None] = mapped_column(Numeric(6, 4), nullable=True)
    evidence_hash: Mapped[bytes | None] = mapped_column(BYTEA, nullable=True)
    gas_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    emitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    synced: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


# ── Copilot Sessions ─────────────────────────────────────────


class CopilotSession(Base):
    __tablename__ = "copilot_sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("security_incidents.id"), nullable=True
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tool_call_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    bc_report_hash: Mapped[bytes | None] = mapped_column(BYTEA, nullable=True)
    confidence_level: Mapped[str | None] = mapped_column(String(8), nullable=True)

    user: Mapped[User] = relationship(back_populates="copilot_sessions")
    messages: Mapped[list["CopilotMessage"]] = relationship(back_populates="session")


class CopilotMessage(Base):
    __tablename__ = "copilot_messages"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("copilot_sessions.id"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    tool_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    session: Mapped[CopilotSession] = relationship(back_populates="messages")
