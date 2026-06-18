import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.deps import get_current_admin, get_current_user
from app.db.session import get_db
from app.models.models import AnomalyEvent, Device, SecurityIncident, User
from app.schemas.schemas import (
    BlockchainActionResponse,
    BlockchainRef,
    DeviceSummary,
    IncidentDetail,
    IncidentSummary,
    PaginatedResponse,
    QuarantineRequest,
    ReinstatementRequest,
    RevocationRequest,
    AnomalyScorePoint,
    FeatureVector,
)
from app.services.blockchain import blockchain_service
from app.services.websocket import ws_manager

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _incident_to_summary(inc: SecurityIncident) -> IncidentSummary:
    return IncidentSummary(
        id=inc.id,
        device=DeviceSummary.model_validate(inc.device),
        attack_type=inc.attack_type,
        severity=inc.severity,
        status=inc.status,
        anomaly_score=float(inc.anomaly_event.anomaly_score) if inc.anomaly_event else None,
        bc_quarantine_tx=inc.bc_quarantine_tx,
        opened_at=inc.opened_at,
    )


@router.get("", response_model=PaginatedResponse)
async def list_incidents(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = None,
    device_id: Optional[uuid.UUID] = None,
    from_time: Optional[datetime] = Query(None, alias="from"),
    to_time: Optional[datetime] = Query(None, alias="to"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = (
        select(SecurityIncident)
        .options(
            selectinload(SecurityIncident.device),
            selectinload(SecurityIncident.anomaly_event),
        )
        .order_by(SecurityIncident.opened_at.desc())
    )
    if status_filter:
        q = q.where(SecurityIncident.status == status_filter.upper())
    if severity:
        q = q.where(SecurityIncident.severity == severity.upper())
    if device_id:
        q = q.where(SecurityIncident.device_id == device_id)
    if from_time:
        q = q.where(SecurityIncident.opened_at >= from_time)
    if to_time:
        q = q.where(SecurityIncident.opened_at <= to_time)

    count_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = count_result.scalar_one()

    q = q.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    incidents = result.scalars().all()

    return PaginatedResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[_incident_to_summary(i) for i in incidents],
    )


@router.get("/{incident_id}", response_model=IncidentDetail)
async def get_incident(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(
        select(SecurityIncident)
        .options(
            selectinload(SecurityIncident.device),
            selectinload(SecurityIncident.anomaly_event),
        )
        .where(SecurityIncident.id == incident_id)
    )
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    ae = inc.anomaly_event
    anomaly_point = None
    if ae:
        anomaly_point = AnomalyScorePoint(
            window_start=ae.window_start,
            anomaly_score=float(ae.anomaly_score),
            is_alert=ae.is_alert,
            feature_vector=FeatureVector(
                packet_count=float(ae.feat_packet_count) if ae.feat_packet_count else None,
                mean_payload_size=float(ae.feat_payload_size) if ae.feat_payload_size else None,
                unique_dst_ips=ae.feat_unique_dst_ips,
                auth_failure_rate=float(ae.feat_auth_failure_rate) if ae.feat_auth_failure_rate else None,
                protocol_entropy=float(ae.feat_protocol_entropy) if ae.feat_protocol_entropy else None,
                interarrival_variance=float(ae.feat_interarrival_var) if ae.feat_interarrival_var else None,
                payload_entropy=float(ae.feat_payload_entropy) if ae.feat_payload_entropy else None,
            ),
            bc_tx_hash=ae.bc_tx_hash,
            inference_ms=float(ae.inference_ms) if ae.inference_ms else None,
        )

    return IncidentDetail(
        id=inc.id,
        device=DeviceSummary.model_validate(inc.device),
        attack_type=inc.attack_type,
        severity=inc.severity,
        status=inc.status,
        anomaly_event=anomaly_point,
        blockchain=BlockchainRef(
            quarantine_tx=inc.bc_quarantine_tx,
            block_number=None,
            timestamp=None,
        ) if inc.bc_quarantine_tx else None,
        copilot_report=None,
        opened_at=inc.opened_at,
        resolved_at=inc.resolved_at,
        resolution_notes=inc.resolution_notes,
    )


@router.post("/{incident_id}/quarantine", response_model=BlockchainActionResponse)
async def quarantine_device(
    incident_id: uuid.UUID,
    body: QuarantineRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(
        select(SecurityIncident)
        .options(selectinload(SecurityIncident.device))
        .where(SecurityIncident.id == incident_id)
    )
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if inc.status not in ("OPEN",):
        raise HTTPException(status_code=400, detail=f"Incident is already {inc.status}")

    bc_tx_hash = None
    try:
        tx = await blockchain_service.quarantine_device(inc.device.mac_address, 0.9)
        bc_tx_hash = tx.get("tx_hash")
    except Exception:
        pass

    inc.status = "QUARANTINED"
    inc.bc_quarantine_tx = bc_tx_hash
    inc.device.status = "QUARANTINED"
    inc.device.quarantine_count += 1
    await db.commit()

    await ws_manager.broadcast({
        "type": "DEVICE_QUARANTINED",
        "device_id": str(inc.device_id),
        "mac": inc.device.mac_address,
        "bc_tx_hash": bc_tx_hash,
    })

    return BlockchainActionResponse(bc_tx_hash=bc_tx_hash, new_status="QUARANTINED")


@router.post("/{incident_id}/reinstate", response_model=BlockchainActionResponse)
async def reinstate_device(
    incident_id: uuid.UUID,
    body: ReinstatementRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(
        select(SecurityIncident)
        .options(selectinload(SecurityIncident.device))
        .where(SecurityIncident.id == incident_id)
    )
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if inc.status != "QUARANTINED":
        raise HTTPException(status_code=400, detail="Incident is not in QUARANTINED state")

    bc_tx_hash = None
    try:
        tx = await blockchain_service.reinstate_device(inc.device.mac_address)
        bc_tx_hash = tx.get("tx_hash")
        inc.bc_reinstate_tx = bc_tx_hash
    except Exception:
        pass

    inc.status = "RESOLVED"
    inc.resolved_at = datetime.now(timezone.utc)
    inc.resolved_by = current_user.id
    inc.resolution_notes = body.review_notes
    inc.device.status = "ACTIVE"
    await db.commit()

    await ws_manager.broadcast({
        "type": "DEVICE_REINSTATED",
        "device_id": str(inc.device_id),
        "mac": inc.device.mac_address,
        "bc_tx_hash": bc_tx_hash,
    })

    return BlockchainActionResponse(bc_tx_hash=bc_tx_hash, new_status="ACTIVE")


@router.post("/{incident_id}/revoke", response_model=BlockchainActionResponse)
async def revoke_device(
    incident_id: uuid.UUID,
    body: RevocationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    result = await db.execute(
        select(SecurityIncident)
        .options(selectinload(SecurityIncident.device))
        .where(SecurityIncident.id == incident_id)
    )
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if inc.status == "RESOLVED":
        raise HTTPException(status_code=400, detail="Incident already resolved")

    bc_tx_hash = None
    try:
        tx = await blockchain_service.revoke_device(inc.device.mac_address, body.reason)
        bc_tx_hash = tx.get("tx_hash")
        inc.bc_revoke_tx = bc_tx_hash
    except Exception:
        pass

    inc.status = "RESOLVED"
    inc.resolved_at = datetime.now(timezone.utc)
    inc.resolved_by = current_user.id
    inc.resolution_notes = body.reason
    inc.device.status = "REVOKED"
    await db.commit()

    await ws_manager.broadcast({
        "type": "DEVICE_REVOKED",
        "device_id": str(inc.device_id),
        "mac": inc.device.mac_address,
        "bc_tx_hash": bc_tx_hash,
    })

    return BlockchainActionResponse(bc_tx_hash=bc_tx_hash, new_status="REVOKED")
