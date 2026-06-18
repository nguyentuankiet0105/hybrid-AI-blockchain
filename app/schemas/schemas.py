from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# ── Shared ───────────────────────────────────────────────────

class PaginatedResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[Any]


# ── Auth ─────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int
    role: str


class RefreshRequest(BaseModel):
    refresh_token: str


class AccessTokenResponse(BaseModel):
    access_token: str
    expires_in: int


# ── Users ────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    role: str = "soc_analyst"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v):
        if v not in ("admin", "soc_analyst"):
            raise ValueError("role must be admin or soc_analyst")
        return v


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]

    model_config = {"from_attributes": True}


# ── Gateways ─────────────────────────────────────────────────

class GatewayOut(BaseModel):
    id: uuid.UUID
    hostname: str
    ip_address: str
    bc_address: Optional[str]
    model_version: Optional[str]
    status: str
    cpu_pct: Optional[float]
    mem_mb: Optional[int]
    last_heartbeat: Optional[datetime]
    registered_at: datetime

    model_config = {"from_attributes": True}


class GatewayHeartbeat(BaseModel):
    hostname: str
    ip_address: str
    cpu_pct: float
    mem_mb: int
    model_version: Optional[str] = None
    model_hash: Optional[str] = None


# ── Devices ──────────────────────────────────────────────────

class DeviceCreate(BaseModel):
    mac_address: str = Field(pattern=r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    name: Optional[str] = None
    type: str
    location: Optional[str] = None
    protocol: str = "MQTT"
    device_hash: str  # hex string

    @field_validator("type")
    @classmethod
    def validate_type(cls, v):
        allowed = {"smart_lock", "camera", "motion_sensor", "temp_sensor", "power_meter"}
        if v not in allowed:
            raise ValueError(f"type must be one of {allowed}")
        return v


class DeviceSummary(BaseModel):
    id: uuid.UUID
    mac_address: str
    name: Optional[str]
    type: str
    status: str
    last_anomaly_score: Optional[float]
    last_seen: Optional[datetime]
    quarantine_count: int
    bc_address: Optional[str]

    model_config = {"from_attributes": True}


class FeatureVector(BaseModel):
    packet_count: Optional[float]
    mean_payload_size: Optional[float]
    unique_dst_ips: Optional[int]
    auth_failure_rate: Optional[float]
    protocol_entropy: Optional[float]
    interarrival_variance: Optional[float]
    payload_entropy: Optional[float]


class AnomalyScorePoint(BaseModel):
    window_start: datetime
    anomaly_score: float
    is_alert: bool
    feature_vector: Optional[FeatureVector]
    bc_tx_hash: Optional[str]
    inference_ms: Optional[float]


class DeviceDetail(BaseModel):
    id: uuid.UUID
    mac_address: str
    name: Optional[str]
    type: str
    location: Optional[str]
    protocol: str
    status: str
    quarantine_count: int
    last_anomaly_score: Optional[float]
    bc_address: Optional[str]
    device_hash: Optional[str]
    registered_at: datetime
    gateway: Optional[GatewayOut]
    recent_scores: List[AnomalyScorePoint] = []

    model_config = {"from_attributes": True}


class DeviceAnomalyHistory(BaseModel):
    device_id: uuid.UUID
    scores: List[AnomalyScorePoint]


# ── Incidents ────────────────────────────────────────────────

class IncidentSummary(BaseModel):
    id: uuid.UUID
    device: DeviceSummary
    attack_type: Optional[str]
    severity: str
    status: str
    anomaly_score: Optional[float]
    bc_quarantine_tx: Optional[str]
    opened_at: datetime

    model_config = {"from_attributes": True}


class BlockchainRef(BaseModel):
    quarantine_tx: Optional[str]
    block_number: Optional[int]
    timestamp: Optional[datetime]


class IncidentDetail(BaseModel):
    id: uuid.UUID
    device: DeviceSummary
    attack_type: Optional[str]
    severity: str
    status: str
    anomaly_event: Optional[AnomalyScorePoint]
    blockchain: Optional[BlockchainRef]
    copilot_report: Optional[Dict[str, Any]]
    opened_at: datetime
    resolved_at: Optional[datetime]
    resolution_notes: Optional[str]

    model_config = {"from_attributes": True}


class QuarantineRequest(BaseModel):
    reason: str


class ReinstatementRequest(BaseModel):
    review_notes: str


class RevocationRequest(BaseModel):
    reason: str


class BlockchainActionResponse(BaseModel):
    bc_tx_hash: Optional[str]
    new_status: str


# ── Blockchain ───────────────────────────────────────────────

class BlockchainEventOut(BaseModel):
    id: int
    event_type: str
    device_mac: Optional[str]
    bc_tx_hash: str
    bc_block_number: int
    bc_timestamp: datetime
    anomaly_score: Optional[float]
    evidence_hash: Optional[str]
    gas_used: Optional[int]

    model_config = {"from_attributes": True}


class BlockchainStats(BaseModel):
    current_tps: float
    last_block_number: int
    last_block_hash: str
    last_block_timestamp: datetime
    validator_count: int
    byzantine_nodes: int
    finality_ms_avg: float


class MerkleVerification(BaseModel):
    tx_hash: str
    block_number: int
    merkle_proof_valid: bool
    device_state_post_tx: Optional[str]


# ── Analytics ────────────────────────────────────────────────

class AttackTypeBreakdown(BaseModel):
    brute_force: int = 0
    telemetry_injection: int = 0
    mitm: int = 0
    device_spoofing: int = 0
    ddos: int = 0
    port_scan: int = 0
    unknown: int = 0


class AnalyticsSummary(BaseModel):
    total_alerts: int
    by_attack_type: AttackTypeBreakdown
    false_positive_rate: float
    mean_response_ms: float
    accuracy_pct: float
    auc_roc: float


class ScoreBin(BaseModel):
    range: str
    count: int


class ScoreDistribution(BaseModel):
    bins: List[ScoreBin]


# ── Copilot ──────────────────────────────────────────────────

class CopilotSessionCreate(BaseModel):
    incident_id: Optional[uuid.UUID] = None


class CopilotSessionOut(BaseModel):
    session_id: uuid.UUID

    model_config = {"from_attributes": True}


class CopilotMessageIn(BaseModel):
    message: str = Field(min_length=1, max_length=4000)


class CopilotMessageOut(BaseModel):
    id: int
    session_id: uuid.UUID
    role: str
    content: str
    tool_name: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class CopilotHistoryOut(BaseModel):
    session_id: uuid.UUID
    messages: List[CopilotMessageOut]
