from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from app.api.v1.deps import get_ws_user
from app.db.session import get_db
from app.services.websocket import ws_manager

router = APIRouter(tags=["websocket"])


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    db=Depends(get_db),
):
    user = await get_ws_user(websocket, db)
    if user is None:
        await websocket.close(code=4001, reason="Unauthorized")
        return

    client_id = str(user.id)
    await ws_manager.connect(client_id, websocket)
    try:
        while True:
            # Keep connection alive; client sends ping, we echo pong
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(client_id)
