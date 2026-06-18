import asyncio
import json
import uuid
from typing import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.deps import get_current_user
from app.db.session import get_db
from app.models.models import CopilotMessage, CopilotSession, SecurityIncident, User
from app.schemas.schemas import (
    CopilotHistoryOut,
    CopilotMessageIn,
    CopilotMessageOut,
    CopilotSessionCreate,
    CopilotSessionOut,
)
from app.services.copilot import CopilotService
from app.core.config import settings

router = APIRouter(prefix="/copilot", tags=["copilot"])


@router.post("/sessions", response_model=CopilotSessionOut, status_code=status.HTTP_201_CREATED)
async def create_session(
    body: CopilotSessionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    session = CopilotSession(
        user_id=current_user.id,
        incident_id=body.incident_id,
    )
    db.add(session)
    await db.commit()
    return CopilotSessionOut(session_id=session.id)


@router.post("/sessions/{session_id}/messages")
async def send_message(
    session_id: uuid.UUID,
    body: CopilotMessageIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(CopilotSession).where(
            CopilotSession.id == session_id,
            CopilotSession.user_id == current_user.id,
        )
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.tool_call_count >= settings.COPILOT_MAX_TOOL_CALLS_PER_SESSION:
        raise HTTPException(status_code=429, detail="Tool call limit reached for this session")

    # Save user message
    user_msg = CopilotMessage(
        session_id=session_id,
        role="user",
        content=body.message,
    )
    db.add(user_msg)
    await db.commit()

    # Load conversation history for context
    history_result = await db.execute(
        select(CopilotMessage)
        .where(CopilotMessage.session_id == session_id)
        .order_by(CopilotMessage.created_at)
        .limit(20)
    )
    history = history_result.scalars().all()

    copilot = CopilotService(db=db, session=session)

    async def event_stream() -> AsyncGenerator[str, None]:
        final_answer = ""
        try:
            async for chunk in copilot.stream_response(body.message, history):
                yield f"event: {chunk['event']}\ndata: {json.dumps(chunk['data'])}\n\n"
                if chunk["event"] == "final":
                    final_answer = chunk["data"].get("answer", "")
                    # Update tool call count
                    session.tool_call_count += chunk["data"].get("tool_calls_used", 0)
        except Exception as e:
            yield f"event: error\ndata: {json.dumps({'message': str(e)})}\n\n"
            final_answer = f"Error during analysis: {e}"

        # Persist assistant response
        async with db.begin():
            assistant_msg = CopilotMessage(
                session_id=session_id,
                role="assistant",
                content=final_answer,
            )
            db.add(assistant_msg)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/sessions/{session_id}/messages", response_model=CopilotHistoryOut)
async def get_session_history(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(CopilotSession).where(
            CopilotSession.id == session_id,
            CopilotSession.user_id == current_user.id,
        )
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    msgs_result = await db.execute(
        select(CopilotMessage)
        .where(CopilotMessage.session_id == session_id)
        .order_by(CopilotMessage.created_at)
    )
    messages = msgs_result.scalars().all()

    return CopilotHistoryOut(
        session_id=session_id,
        messages=[CopilotMessageOut.model_validate(m) for m in messages],
    )
