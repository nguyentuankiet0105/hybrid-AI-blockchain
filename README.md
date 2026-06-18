# Sentient Sentinel — Backend API

Hybrid AI-Blockchain IoT Security Platform — REST API & WebSocket server.

Built with **FastAPI**, **PostgreSQL**, **Redis**, **scikit-learn Isolation Forest**, **LangChain**, and **Web3.py**.

---

## Tech Stack

| Component | Technology |
|---|---|
| API Framework | FastAPI 0.111 + Uvicorn |
| Database | PostgreSQL 16 + TimescaleDB |
| ORM + Migrations | SQLAlchemy 2.0 (async) + Alembic |
| Cache / Sessions | Redis 7 |
| AI Engine | scikit-learn Isolation Forest (7-feature, θ=0.85) |
| AI Copilot | LangChain + GPT-4o + ChromaDB |
| Blockchain | Web3.py → Hyperledger Besu EVM |
| MQTT | Paho MQTT → Mosquitto 2.0 |
| Auth | JWT (HS256) + bcrypt |

---

## Project Structure

```
sentinel-backend/
├── app/
│   ├── api/v1/
│   │   ├── endpoints/       # auth, devices, incidents, blockchain, analytics, copilot, ws
│   │   ├── deps.py          # JWT auth dependencies
│   │   └── router.py        # aggregated router
│   ├── core/
│   │   ├── config.py        # Pydantic settings (reads .env)
│   │   ├── security.py      # JWT + bcrypt helpers
│   │   └── logging.py       # structlog config
│   ├── db/
│   │   ├── session.py       # SQLAlchemy async engine + session
│   │   └── redis.py         # Redis async client
│   ├── models/models.py     # SQLAlchemy ORM models
│   ├── schemas/schemas.py   # Pydantic request/response schemas
│   ├── services/
│   │   ├── ai_engine.py     # Isolation Forest scorer
│   │   ├── blockchain.py    # Web3.py / Besu wrapper
│   │   ├── copilot.py       # LangChain ReAct agent
│   │   ├── mqtt_ingestion.py # MQTT → feature extraction → AI → blockchain
│   │   └── websocket.py     # WebSocket connection manager
│   └── main.py              # FastAPI app + lifespan
├── alembic/                 # DB migration scripts
├── scripts/
│   ├── seed_db.py           # Create admin user + sample data
│   ├── train_model.py       # Train Isolation Forest model
│   └── simulate_devices.py  # IoT telemetry simulator
├── tests/
│   ├── unit/                # AI engine + security tests
│   └── integration/         # API endpoint tests
├── docker/
│   ├── Dockerfile
│   └── mosquitto.conf
├── docker-compose.yml
├── requirements.txt
├── .env.example
└── alembic.ini
```

---

## Prerequisites

- **Python 3.11+**
- **Docker + Docker Compose** (for infrastructure services)
- **Git**

---

## Quick Start — Docker Compose (Recommended)

The simplest way to run everything including PostgreSQL, Redis, MQTT, and ChromaDB.

### 1. Clone and configure

```bash
git clone <repo-url> sentinel-backend
cd sentinel-backend

cp .env.example .env
# Edit .env — at minimum set OPENAI_API_KEY if you want the Copilot to work
```

### 2. Build and start

```bash
docker compose up --build
```

This will automatically:
- Start PostgreSQL, Redis, Mosquitto, ChromaDB
- Run `alembic upgrade head` (applies DB schema)
- Run `scripts/seed_db.py` (creates users + sample data)
- Train the Isolation Forest model
- Start the FastAPI server on **http://localhost:8000**

### 3. Verify

```bash
curl http://localhost:8000/health
# → {"status": "ok", "env": "development"}
```

Open **http://localhost:8000/docs** for the interactive Swagger UI.

---

## Manual Local Setup (without Docker)

Use this if you want to run the API directly on your machine for development.

### Step 1 — Infrastructure services

Start only the infrastructure containers:

```bash
docker compose up postgres redis mosquitto chromadb -d
```

### Step 2 — Python environment

```bash
python3.11 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Step 3 — Configure environment

```bash
cp .env.example .env
```

Open `.env` and verify these values match your local setup:

```env
DATABASE_URL=postgresql+asyncpg://sentinel:sentinel_password@localhost:5432/sentinel
REDIS_URL=redis://localhost:6379/0
MQTT_BROKER_HOST=localhost
CHROMADB_HOST=localhost
OPENAI_API_KEY=sk-your-key-here   # Required for AI Copilot
```

### Step 4 — Database migration

```bash
alembic upgrade head
```

### Step 5 — Train the AI model

```bash
python scripts/train_model.py
```

This creates `models/isolation_forest.pkl`. You'll see the AUC-ROC score printed.

### Step 6 — Seed sample data

```bash
python scripts/seed_db.py
```

Creates:
- **Admin user:** `admin@sentinel.local` / `Admin1234!`
- **SOC Analyst:** `analyst@sentinel.local` / `Analyst1234!`
- 5 sample IoT devices
- 48 hours of normal anomaly events
- 1 demo brute-force incident (device quarantined)

### Step 7 — Run the API

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

API is live at **http://localhost:8000**

---

## API Usage

### Authenticate

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@sentinel.local", "password": "Admin1234!"}'
```

Returns `{ "access_token": "...", ... }`. Use this token in subsequent requests:

```bash
export TOKEN="<access_token>"
```

### List devices

```bash
curl http://localhost:8000/api/v1/devices \
  -H "Authorization: Bearer $TOKEN"
```

### List security incidents

```bash
curl http://localhost:8000/api/v1/incidents \
  -H "Authorization: Bearer $TOKEN"
```

### Blockchain stats

```bash
curl http://localhost:8000/api/v1/blockchain/stats \
  -H "Authorization: Bearer $TOKEN"
```

### Threat analytics

```bash
curl http://localhost:8000/api/v1/analytics/summary \
  -H "Authorization: Bearer $TOKEN"
```

### Start a Copilot session

```bash
# Create session
curl -X POST http://localhost:8000/api/v1/copilot/sessions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

# Send a message (streams SSE)
SESSION_ID="<session_id from above>"
curl -N -X POST "http://localhost:8000/api/v1/copilot/sessions/$SESSION_ID/messages" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "What security incidents happened in the last 24 hours?"}'
```

### WebSocket connection

```bash
# Connect with wscat (npm install -g wscat)
wscat -c "ws://localhost:8000/api/v1/ws?token=$TOKEN"
# Send: ping → receives: pong
# Receives live ANOMALY_ALERT, DEVICE_QUARANTINED events
```

---

## Simulate IoT Attack Traffic

With the API running, open a second terminal:

```bash
# Normal traffic for 60 seconds
python scripts/simulate_devices.py --duration 60

# Inject brute-force attack on the smart lock
python scripts/simulate_devices.py --attack brute_force --device AA:BB:CC:DD:EE:01 --duration 30
```

Watch the `/incidents` endpoint and WebSocket for live alerts.

---

## Running Tests

```bash
# Unit tests only (no DB required)
pytest tests/unit/ -v

# Integration tests (requires PostgreSQL + Redis running)
pytest tests/integration/ -v

# All tests
pytest -v
```

---

## Configuration Reference

All settings are in `.env`. Key variables:

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://...` | PostgreSQL connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `JWT_SECRET_KEY` | `changeme` | **Change in production!** |
| `ANOMALY_THRESHOLD` | `0.85` | Isolation Forest alert threshold |
| `MODEL_PATH` | `./models/isolation_forest.pkl` | Path to trained model |
| `OPENAI_API_KEY` | `sk-placeholder` | Required for AI Copilot |
| `BLOCKCHAIN_RPC_URL` | `http://localhost:8545` | Besu node RPC |
| `MQTT_BROKER_HOST` | `localhost` | Mosquitto host |
| `CORS_ORIGINS` | `["http://localhost:3000"]` | Allowed frontend origins |

---

## API Documentation

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **OpenAPI JSON:** http://localhost:8000/openapi.json

---

## Notes

**Blockchain:** The system runs without a Besu node in development. All blockchain operations gracefully return `null` tx hashes when the node is unreachable. To connect a real Besu node, deploy the `DeviceRegistry.sol` contract and set `DEVICE_REGISTRY_CONTRACT_ADDRESS` and `GATEWAY_PRIVATE_KEY` in `.env`.

**AI Copilot:** Requires a valid `OPENAI_API_KEY`. Without it, the Copilot falls back to a limited no-tool mode. The LangChain ReAct agent, ChromaDB vector store, and tool-calling features require the key.

**MQTT Auth:** The default Mosquitto config requires a password file. For local dev without auth, change `allow_anonymous true` in `docker/mosquitto.conf`.
