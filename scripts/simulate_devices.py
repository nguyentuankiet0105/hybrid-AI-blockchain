#!/usr/bin/env python3
"""
IoT device telemetry simulator — generates realistic MQTT messages
for 5 device types. Optionally injects attack traffic.

Usage:
  python scripts/simulate_devices.py              # normal traffic
  python scripts/simulate_devices.py --attack brute_force --device AA:BB:CC:DD:EE:01
"""
import argparse
import asyncio
import json
import random
import time

import paho.mqtt.client as mqtt

BROKER_HOST = "localhost"
BROKER_PORT = 1883
TOPIC_PREFIX = "sentinel/devices"

DEVICES = [
    {"mac": "AA:BB:CC:DD:EE:01", "type": "smart_lock"},
    {"mac": "AA:BB:CC:DD:EE:02", "type": "camera"},
    {"mac": "AA:BB:CC:DD:EE:03", "type": "motion_sensor"},
    {"mac": "AA:BB:CC:DD:EE:04", "type": "temp_sensor"},
    {"mac": "AA:BB:CC:DD:EE:05", "type": "power_meter"},
]


def normal_payload(mac: str, device_type: str) -> dict:
    return {
        "mac": mac,
        "device_type": device_type,
        "ts": time.time(),
        "payload_size": random.randint(80, 220),
        "dst_ip": f"192.168.1.{random.randint(1, 10)}",
        "protocol": random.choice(["MQTT", "MQTT", "MQTT", "CoAP"]),
        "auth_failed": random.random() < 0.01,
        "reading": random.uniform(20.0, 30.0),
    }


def brute_force_payload(mac: str) -> dict:
    return {
        "mac": mac,
        "device_type": "smart_lock",
        "ts": time.time(),
        "payload_size": random.randint(40, 60),
        "dst_ip": "192.168.1.1",
        "protocol": "MQTT",
        "auth_failed": True,
        "reading": 0.0,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack", choices=["brute_force", "none"], default="none")
    parser.add_argument("--device", default="AA:BB:CC:DD:EE:01")
    parser.add_argument("--duration", type=int, default=300, help="Seconds to run")
    args = parser.parse_args()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.connect(BROKER_HOST, BROKER_PORT, 60)
    client.loop_start()

    print(f"Simulating {len(DEVICES)} devices for {args.duration}s (attack={args.attack})")
    start = time.time()

    while time.time() - start < args.duration:
        for device in DEVICES:
            if args.attack == "brute_force" and device["mac"] == args.device:
                # Inject 10 rapid brute-force messages
                for _ in range(10):
                    payload = brute_force_payload(device["mac"])
                    topic = f"{TOPIC_PREFIX}/{device['mac'].replace(':', '')}/telemetry"
                    client.publish(topic, json.dumps(payload))
            else:
                payload = normal_payload(device["mac"], device["type"])
                topic = f"{TOPIC_PREFIX}/{device['mac'].replace(':', '')}/telemetry"
                client.publish(topic, json.dumps(payload))

        time.sleep(1)

    client.loop_stop()
    client.disconnect()
    print("Simulation complete.")


if __name__ == "__main__":
    main()
