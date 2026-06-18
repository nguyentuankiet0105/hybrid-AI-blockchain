from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_user
from app.db.session import get_db
from app.models.models import Gateway, User
from app.schemas.schemas import GatewayHeartbeat, GatewayOut

router = APIRouter(prefix="/gateways", tags=["gateways"])


@router.get("", response_model=list[GatewayOut])
async def list_gateways(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Gateway).order_by(Gateway.registered_at))
    return [GatewayOut.model_validate(g) for g in result.scalars().all()]


@router.post("/heartbeat", status_code=204)
async def gateway_heartbeat(
    body: GatewayHeartbeat,
    db: AsyncSession = Depends(get_db),
):
    """Called by gateway process to update liveness metrics. No auth required (internal network)."""
    result = await db.execute(select(Gateway).where(Gateway.hostname == body.hostname))
    gw = result.scalar_one_or_none()
    if gw is None:
        gw = Gateway(hostname=body.hostname, ip_address=body.ip_address)
        db.add(gw)
    gw.ip_address = body.ip_address
    gw.cpu_pct = body.cpu_pct
    gw.mem_mb = body.mem_mb
    gw.model_version = body.model_version
    gw.status = "ONLINE"
    gw.last_heartbeat = datetime.now(timezone.utc)
    if body.model_hash:
        gw.model_hash = bytes.fromhex(body.model_hash.replace("0x", ""))
    await db.commit()
