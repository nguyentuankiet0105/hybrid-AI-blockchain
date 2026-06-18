from fastapi import APIRouter

from app.api.v1.endpoints import (
    analytics,
    auth,
    blockchain,
    copilot,
    devices,
    gateways,
    incidents,
    websocket,
)

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(devices.router)
api_router.include_router(incidents.router)
api_router.include_router(blockchain.router)
api_router.include_router(analytics.router)
api_router.include_router(gateways.router)
api_router.include_router(copilot.router)
api_router.include_router(websocket.router)
