#!/usr/bin/env python3
"""
Seed script — creates admin user, sample devices, and demo anomaly events.
Run: python scripts/seed_db.py
"""
import asyncio
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.security import hash_password
from app.db.session import AsyncSessionLocal
from app.models.models import AnomalyEvent, Device, Gateway, SecurityIncident, User


SAMPLE_DEVICES = [
    {"mac": "AA:BB:CC:DD:EE:01", "name": "Front Door Lock", "type": "smart_lock", "location": "Building A, Entrance"},
    {"mac": "AA:BB:CC:DD:EE:02", "name": "Lobby Camera", "type": "camera", "location": "Building A, Lobby"},
    {"mac": "AA:BB:CC:DD:EE:03", "name": "Motion Sensor 1", "type": "motion_sensor", "location": "Corridor 1"},
    {"mac": "AA:BB:CC:DD:EE:04", "name": "Temp Sensor A", "type": "temp_sensor", "location": "Server Room"},
    {"mac": "AA:BB:CC:DD:EE:05", "name": "Power Meter Main", "type": "power_meter", "location": "Utility Room"},
]


async def seed():
    async with AsyncSessionLocal() as db:
        # ── Admin user ──────────────────────────────────────
        existing_admin = await db.execute(select(User).where(User.email == "admin@sentinel.local"))
        if not existing_admin.scalar_one_or_none():
            admin = User(
                email="admin@sentinel.local",
                password_hash=hash_password("Admin1234!"),
                role="admin",
            )
            db.add(admin)
            print("Created admin user: admin@sentinel.local / Admin1234!")

        # SOC analyst
        existing_soc = await db.execute(select(User).where(User.email == "analyst@sentinel.local"))
        if not existing_soc.scalar_one_or_none():
            soc = User(
                email="analyst@sentinel.local",
                password_hash=hash_password("Analyst1234!"),
                role="soc_analyst",
            )
            db.add(soc)
            print("Created SOC analyst: analyst@sentinel.local / Analyst1234!")

        await db.flush()

        # ── Gateway ──────────────────────────────────────────
        existing_gw = await db.execute(select(Gateway).where(Gateway.hostname == "gw-01"))
        if not existing_gw.scalar_one_or_none():
            gw = Gateway(
                hostname="gw-01",
                ip_address="192.168.1.1",
                model_version="v1.0.0",
                status="ONLINE",
                cpu_pct=8.4,
                mem_mb=162,
            )
            db.add(gw)
            print("Created gateway: gw-01")

        await db.flush()

        # ── Devices ──────────────────────────────────────────
        result = await db.execute(select(User).where(User.email == "admin@sentinel.local"))
        admin_user = result.scalar_one()

        devices = []
        for d in SAMPLE_DEVICES:
            existing = await db.execute(select(Device).where(Device.mac_address == d["mac"]))
            if not existing.scalar_one_or_none():
                device = Device(
                    mac_address=d["mac"],
                    name=d["name"],
                    type=d["type"],
                    location=d["location"],
                    device_hash=hashlib.sha256(d["mac"].encode()).digest(),
                    status="ACTIVE",
                    registered_by=admin_user.id,
                    last_anomaly_score=0.08,
                )
                db.add(device)
                devices.append(device)
                print(f"Created device: {d['name']} ({d['mac']})")

        await db.flush()

        # ── Sample anomaly events ────────────────────────────
        result = await db.execute(select(Device).limit(5))
        all_devices = result.scalars().all()

        if all_devices:
            now = datetime.now(timezone.utc)
            import random
            random.seed(42)

            for device in all_devices[:3]:
                # 48 hours of normal events
                for i in range(48):
                    score = random.uniform(0.05, 0.25)
                    event = AnomalyEvent(
                        device_id=device.id,
                        window_start=now - timedelta(hours=48 - i),
                        anomaly_score=score,
                        is_alert=False,
                        feat_packet_count=random.uniform(30, 80),
                        feat_payload_size=random.uniform(100, 200),
                        feat_unique_dst_ips=random.randint(1, 5),
                        feat_auth_failure_rate=random.uniform(0.0, 0.02),
                        feat_protocol_entropy=random.uniform(0.8, 1.5),
                        feat_interarrival_var=random.uniform(0.01, 0.1),
                        feat_payload_entropy=random.uniform(3.5, 4.5),
                        inference_ms=1.1,
                    )
                    db.add(event)

            # One brute-force attack on device 0
            attack_device = all_devices[0]
            attack_time = now - timedelta(hours=2)
            alert_event = AnomalyEvent(
                device_id=attack_device.id,
                window_start=attack_time,
                anomaly_score=0.982,
                is_alert=True,
                feat_packet_count=420.0,
                feat_payload_size=48.0,
                feat_unique_dst_ips=1,
                feat_auth_failure_rate=0.94,
                feat_protocol_entropy=0.2,
                feat_interarrival_var=0.001,
                feat_payload_entropy=1.1,
                bc_tx_hash="0xdemo" + "a" * 60,
                inference_ms=1.1,
            )
            db.add(alert_event)
            await db.flush()

            incident = SecurityIncident(
                device_id=attack_device.id,
                anomaly_event_id=alert_event.id,
                attack_type="brute_force",
                severity="CRITICAL",
                status="QUARANTINED",
                bc_quarantine_tx="0xdemo" + "a" * 60,
            )
            db.add(incident)
            attack_device.status = "QUARANTINED"
            attack_device.quarantine_count = 1
            attack_device.last_anomaly_score = 0.982
            print(f"Created demo brute-force incident on {attack_device.name}")

        await db.commit()
        print("\nSeed complete.")


if __name__ == "__main__":
    asyncio.run(seed())
