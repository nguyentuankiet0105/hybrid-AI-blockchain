"""
MQTT ingestion service — subscribes to device telemetry topics,
extracts 7-feature vectors, runs the AI engine, and persists results.

Run with: python -m app.services.mqtt_ingestion
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional

import paho.mqtt.client as mqtt
from sqlalchemy import select

from app.core.config import settings
from app.core.logging import get_logger
from app.db.session import AsyncSessionLocal
from app.models.models import AnomalyEvent, BlockchainEvent, Device, SecurityIncident
from app.services.ai_engine import ai_engine
from app.services.blockchain import blockchain_service
from app.services.websocket import ws_manager

logger = get_logger(__name__)

# Sliding window buffer per device: list of raw telemetry dicts
_windows: Dict[str, list] = {}
WINDOW_SECONDS = 60


def _extract_features(window: list) -> Dict[str, float]:
    """Extract 7-feature vector from a 60-second telemetry window."""
    if not window:
        return {k: 0.0 for k in [
            "packet_count", "mean_payload_size", "unique_dst_ips",
            "auth_failure_rate", "protocol_entropy", "interarrival_variance",
            "payload_entropy",
        ]}

    import numpy as np

    packets = len(window)
    payload_sizes = [msg.get("payload_size", 0) for msg in window]
    dst_ips = set(msg.get("dst_ip", "") for msg in window if msg.get("dst_ip"))
    auth_failures = sum(1 for msg in window if msg.get("auth_failed", False))
    protocols = [msg.get("protocol", "MQTT") for msg in window]
    timestamps = sorted(msg.get("ts", 0) for msg in window)

    # Protocol entropy
    proto_counts = {}
    for p in protocols:
        proto_counts[p] = proto_counts.get(p, 0) + 1
    total = len(protocols)
    proto_entropy = -sum((c / total) * np.log2(c / total) for c in proto_counts.values() if c > 0)

    # Inter-arrival variance
    if len(timestamps) > 1:
        diffs = np.diff(timestamps)
        interarrival_var = float(np.var(diffs))
    else:
        interarrival_var = 0.0

    # Payload entropy
    if payload_sizes:
        size_arr = np.array(payload_sizes, dtype=float)
        size_norm = size_arr / (size_arr.max() + 1e-9)
        bins = np.histogram(size_norm, bins=10)[0]
        probs = bins / (bins.sum() + 1e-9)
        payload_entropy = float(-np.sum(probs * np.log2(probs + 1e-9)))
    else:
        payload_entropy = 0.0

    return {
        "packet_count": float(packets),
        "mean_payload_size": float(np.mean(payload_sizes)) if payload_sizes else 0.0,
        "unique_dst_ips": len(dst_ips),
        "auth_failure_rate": auth_failures / packets if packets > 0 else 0.0,
        "protocol_entropy": float(proto_entropy),
        "interarrival_variance": interarrival_var,
        "payload_entropy": payload_entropy,
    }


async def _process_window(device_id: uuid.UUID, mac: str, window: list):
    """Score a window and persist the result."""
    features = _extract_features(window)
    score, ms = ai_engine.score(features)
    is_alert = ai_engine.is_alert(score)

    # Hash the feature vector
    feature_hash = hashlib.sha256(json.dumps(features, sort_keys=True).encode()).digest()

    async with AsyncSessionLocal() as db:
        # Create anomaly event
        event = AnomalyEvent(
            device_id=device_id,
            window_start=datetime.now(timezone.utc),
            anomaly_score=score,
            is_alert=is_alert,
            feat_packet_count=features["packet_count"],
            feat_payload_size=features["mean_payload_size"],
            feat_unique_dst_ips=int(features["unique_dst_ips"]),
            feat_auth_failure_rate=features["auth_failure_rate"],
            feat_protocol_entropy=features["protocol_entropy"],
            feat_interarrival_var=features["interarrival_variance"],
            feat_payload_entropy=features["payload_entropy"],
            feature_vector_hash=feature_hash,
            inference_ms=ms,
        )
        db.add(event)
        await db.flush()

        # Update device last seen / score
        result = await db.execute(select(Device).where(Device.id == device_id))
        device = result.scalar_one_or_none()
        if device:
            device.last_anomaly_score = score
            device.last_seen = datetime.now(timezone.utc)

        if is_alert:
            # Submit to blockchain
            bc_result = await blockchain_service.quarantine_device(mac, score)
            bc_tx_hash = bc_result.get("tx_hash")
            event.bc_tx_hash = bc_tx_hash

            # Create incident
            incident = SecurityIncident(
                device_id=device_id,
                anomaly_event_id=event.id,
                severity="CRITICAL" if score > 0.95 else "HIGH",
                status="QUARANTINED",
                bc_quarantine_tx=bc_tx_hash,
            )
            db.add(incident)

            if device:
                device.status = "QUARANTINED"
                device.quarantine_count += 1

            # Persist blockchain event mirror
            if bc_tx_hash:
                be = BlockchainEvent(
                    event_type="DeviceQuarantined",
                    device_mac=mac,
                    bc_tx_hash=bc_tx_hash,
                    bc_block_number=0,
                    bc_timestamp=datetime.now(timezone.utc),
                    anomaly_score=score,
                    evidence_hash=feature_hash,
                )
                db.add(be)

            await db.commit()

            # Broadcast WS alert
            await ws_manager.broadcast({
                "type": "ANOMALY_ALERT",
                "device_id": str(device_id),
                "mac": mac,
                "score": score,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "incident_id": str(incident.id) if incident else None,
            })
            logger.info("Alert triggered", mac=mac, score=score, tx=bc_tx_hash)
        else:
            await db.commit()
            logger.debug("Normal telemetry", mac=mac, score=score)


class MQTTIngestionService:
    def __init__(self):
        self._client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def start(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        self._client.username_pw_set(settings.MQTT_USERNAME, settings.MQTT_PASSWORD)
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message

        try:
            self._client.connect(settings.MQTT_BROKER_HOST, settings.MQTT_BROKER_PORT, 60)
            self._client.loop_start()
            logger.info("MQTT ingestion started", host=settings.MQTT_BROKER_HOST)
        except Exception as e:
            logger.warning("MQTT connection failed — ingestion disabled", error=str(e))

    def stop(self):
        self._client.loop_stop()
        self._client.disconnect()

    def _on_connect(self, client, userdata, flags, reason_code, properties):
        topic = f"{settings.MQTT_TOPIC_PREFIX}/+/telemetry"
        client.subscribe(topic)
        logger.info("MQTT subscribed", topic=topic)

    def _on_message(self, client, userdata, msg):
        if self._loop is None:
            return
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            device_mac = payload.get("mac") or msg.topic.split("/")[2]
            self._loop.call_soon_threadsafe(
                asyncio.ensure_future,
                self._handle_message(device_mac, payload),
            )
        except Exception as e:
            logger.error("MQTT message parse error", error=str(e))

    async def _handle_message(self, mac: str, payload: dict):
        now = datetime.now(timezone.utc).timestamp()
        if mac not in _windows:
            _windows[mac] = []
        _windows[mac].append({**payload, "ts": now})

        # Evict messages older than window
        cutoff = now - WINDOW_SECONDS
        _windows[mac] = [m for m in _windows[mac] if m.get("ts", 0) >= cutoff]

        # Look up device
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Device).where(Device.mac_address == mac))
            device = result.scalar_one_or_none()
            if not device:
                return
            # Trigger scoring every ~60 messages as a simple cadence
            if len(_windows[mac]) >= 60:
                window_copy = list(_windows[mac])
                _windows[mac] = []
                await _process_window(device.id, mac, window_copy)


mqtt_service = MQTTIngestionService()
