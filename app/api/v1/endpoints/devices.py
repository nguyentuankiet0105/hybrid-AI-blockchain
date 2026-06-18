import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.deps import get_current_admin, get_current_user
from app.db.session import get_db
from app.models.models import AnomalyEvent, Device, User
from app.schemas.schemas import (
    AnomalyScorePoint,
    DeviceAnomalyHistory,
    DeviceCreate,
    DeviceDetail,
    DeviceSummary,
    FeatureVector,
    PaginatedResponse,
)
from app.services.blockchain import blockchain_service

router = APIRouter(prefix="/devices", tags=["devices"])


def _anomaly_to_point(ae: AnomalyEvent) -> AnomalyScorePoint:
    fv = FeatureVector(
        packet_count=float(ae.feat_packet_count) if ae.feat_packet_count else None,
        mean_payload_size=float(ae.feat_payload_size) if ae.feat_payload_size else None,
        unique_dst_ips=ae.feat_unique_dst_ips,
        auth_failure_rate=float(ae.feat_auth_failure_rate) if ae.feat_auth_failure_rate else None,
        protocol_entropy=float(ae.feat_protocol_entropy) if ae.feat_protocol_entropy else None,
        interarrival_variance=float(ae.feat_interarrival_var) if ae.feat_interarrival_var else None,
        payload_entropy=float(ae.feat_payload_entropy) if ae.feat_payload_entropy else None,
    )
    return AnomalyScorePoint(
        window_start=ae.window_start,
        anomaly_score=float(ae.anomaly_score),
        is_alert=ae.is_alert,
        feature_vector=fv,
        bc_tx_hash=ae.bc_tx_hash,
        inference_ms=float(ae.inference_ms) if ae.inference_ms else None,
    )


@router.get("", response_model=PaginatedResponse)
async def list_devices(
    status_filter: Optional[str] = Query(None, alias="status"),
    device_type: Optional[str] = Query(None, alias="type"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = select(Device)
    if status_filter:
        q = q.where(Device.status == status_filter.upper())
    if device_type:
        q = q.where(Device.type == device_type)

    count_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = count_result.scalar_one()

    q = q.offset((page - 1) * page_size).limit(page_size).order_by(Device.created_at.desc())
    result = await db.execute(q)
    devices = result.scalars().all()

    return PaginatedResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[DeviceSummary.model_validate(d) for d in devices],
    )


@router.get("/{device_id}", response_model=DeviceDetail)
async def get_device(
    device_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Device)
        .options(selectinload(Device.anomaly_events))
        .where(Device.id == device_id)
    )
    device = result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    recent = sorted(device.anomaly_events, key=lambda e: e.window_start, reverse=True)[:20]
    detail = DeviceDetail(
        id=device.id,
        mac_address=device.mac_address,
        name=device.name,
        type=device.type,
        location=device.location,
        protocol=device.protocol,
        status=device.status,
        quarantine_count=device.quarantine_count,
        last_anomaly_score=float(device.last_anomaly_score) if device.last_anomaly_score else None,
        bc_address=device.bc_address,
        device_hash=device.device_hash.hex() if device.device_hash else None,
        registered_at=device.registered_at,
        gateway=None,
        recent_scores=[_anomaly_to_point(ae) for ae in recent],
    )
    return detail


@router.get("/{device_id}/anomaly-history", response_model=DeviceAnomalyHistory)
async def get_anomaly_history(
    device_id: uuid.UUID,
    from_time: Optional[datetime] = Query(None, alias="from"),
    to_time: Optional[datetime] = Query(None, alias="to"),
    only_alerts: bool = False,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = select(AnomalyEvent).where(AnomalyEvent.device_id == device_id)
    if from_time:
        q = q.where(AnomalyEvent.window_start >= from_time)
    if to_time:
        q = q.where(AnomalyEvent.window_start <= to_time)
    if only_alerts:
        q = q.where(AnomalyEvent.is_alert.is_(True))
    q = q.order_by(AnomalyEvent.window_start.desc()).limit(500)

    result = await db.execute(q)
    events = result.scalars().all()

    return DeviceAnomalyHistory(
        device_id=device_id,
        scores=[_anomaly_to_point(ae) for ae in events],
    )


@router.post("", response_model=dict, status_code=status.HTTP_201_CREATED)
async def register_device(
    body: DeviceCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    # Check duplicate
    existing = await db.execute(select(Device).where(Device.mac_address == body.mac_address))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Device with this MAC address already exists")

    device_hash_bytes = bytes.fromhex(body.device_hash.replace("0x", ""))
    device = Device(
        mac_address=body.mac_address,
        name=body.name,
        type=body.type,
        location=body.location,
        protocol=body.protocol,
        device_hash=device_hash_bytes,
        status="ACTIVE",
        registered_by=current_user.id,
    )
    db.add(device)
    await db.flush()

    # Attempt blockchain registration (non-blocking if unavailable in dev)
    bc_tx_hash = None
    bc_block = None
    try:
        tx = await blockchain_service.register_device(
            str(device.id), body.device_hash
        )
        bc_tx_hash = tx.get("tx_hash")
        bc_block = tx.get("block_number")
        device.bc_address = tx.get("device_bc_address")
    except Exception:
        pass  # Blockchain unavailable in dev — proceed without

    await db.commit()

    return {
        "id": str(device.id),
        "bc_tx_hash": bc_tx_hash,
        "bc_block_number": bc_block,
    }
