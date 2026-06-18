from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_current_user
from app.db.session import get_db
from app.models.models import BlockchainEvent, User
from app.schemas.schemas import (
    BlockchainEventOut,
    BlockchainStats,
    MerkleVerification,
    PaginatedResponse,
)
from app.services.blockchain import blockchain_service

router = APIRouter(prefix="/blockchain", tags=["blockchain"])


@router.get("/events", response_model=PaginatedResponse)
async def list_blockchain_events(
    event_type: Optional[str] = None,
    device_mac: Optional[str] = None,
    from_block: Optional[int] = None,
    to_block: Optional[int] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = select(BlockchainEvent).order_by(BlockchainEvent.bc_timestamp.desc())
    if event_type:
        q = q.where(BlockchainEvent.event_type == event_type)
    if device_mac:
        q = q.where(BlockchainEvent.device_mac == device_mac)
    if from_block:
        q = q.where(BlockchainEvent.bc_block_number >= from_block)
    if to_block:
        q = q.where(BlockchainEvent.bc_block_number <= to_block)

    count_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = count_result.scalar_one()

    q = q.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    events = result.scalars().all()

    return PaginatedResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[BlockchainEventOut.model_validate(e) for e in events],
    )


@router.get("/stats", response_model=BlockchainStats)
async def get_blockchain_stats(
    _: User = Depends(get_current_user),
):
    try:
        stats = await blockchain_service.get_stats()
        return BlockchainStats(**stats)
    except Exception:
        # Return placeholder when blockchain is not running in dev
        from datetime import datetime, timezone
        return BlockchainStats(
            current_tps=0.0,
            last_block_number=0,
            last_block_hash="0x0000000000000000000000000000000000000000000000000000000000000000",
            last_block_timestamp=datetime.now(timezone.utc),
            validator_count=4,
            byzantine_nodes=0,
            finality_ms_avg=0.0,
        )


@router.get("/verify/{tx_hash}", response_model=MerkleVerification)
async def verify_transaction(
    tx_hash: str,
    _: User = Depends(get_current_user),
):
    try:
        result = await blockchain_service.verify_tx(tx_hash)
        return MerkleVerification(**result)
    except Exception:
        return MerkleVerification(
            tx_hash=tx_hash,
            block_number=0,
            merkle_proof_valid=False,
            device_state_post_tx=None,
        )
