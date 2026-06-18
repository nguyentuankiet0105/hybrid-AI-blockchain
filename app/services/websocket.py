import json
from typing import Dict

from fastapi import WebSocket

from app.core.logging import get_logger

logger = get_logger(__name__)


class WebSocketManager:
    def __init__(self):
        self._connections: Dict[str, WebSocket] = {}

    async def connect(self, client_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections[client_id] = websocket
        logger.info("WebSocket connected", client_id=client_id, total=len(self._connections))

    def disconnect(self, client_id: str) -> None:
        self._connections.pop(client_id, None)
        logger.info("WebSocket disconnected", client_id=client_id, total=len(self._connections))

    async def send_to(self, client_id: str, message: dict) -> None:
        ws = self._connections.get(client_id)
        if ws:
            try:
                await ws.send_text(json.dumps(message))
            except Exception as e:
                logger.warning("Failed to send to client", client_id=client_id, error=str(e))
                self.disconnect(client_id)

    async def broadcast(self, message: dict) -> None:
        disconnected = []
        for client_id, ws in self._connections.items():
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                disconnected.append(client_id)
        for cid in disconnected:
            self.disconnect(cid)

    @property
    def connection_count(self) -> int:
        return len(self._connections)


ws_manager = WebSocketManager()
