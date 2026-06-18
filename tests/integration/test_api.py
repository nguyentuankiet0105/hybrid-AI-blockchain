"""
Integration tests — requires a running PostgreSQL + Redis.
Run: pytest tests/integration/ -v

Set TEST_DATABASE_URL in environment to override default.
"""
import os
import uuid
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.core.security import hash_password
from app.db.session import AsyncSessionLocal, engine, Base
from app.models.models import User


@pytest_asyncio.fixture(scope="session")
async def setup_db():
    """Create all tables for test run."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def test_admin(setup_db):
    """Create a fresh admin user for each test."""
    async with AsyncSessionLocal() as db:
        user = User(
            email=f"test-admin-{uuid.uuid4()}@test.local",
            password_hash=hash_password("TestPass123!"),
            role="admin",
        )
        db.add(user)
        await db.commit()
        yield user


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def auth_headers(client, test_admin):
    resp = await client.post("/api/v1/auth/login", json={
        "email": test_admin.email,
        "password": "TestPass123!",
    })
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestAuthEndpoints:
    @pytest.mark.asyncio
    async def test_login_success(self, client, test_admin):
        resp = await client.post("/api/v1/auth/login", json={
            "email": test_admin.email,
            "password": "TestPass123!",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["role"] == "admin"

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client, test_admin):
        resp = await client.post("/api/v1/auth/login", json={
            "email": test_admin.email,
            "password": "WrongPassword",
        })
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_logout(self, client, auth_headers):
        resp = await client.post("/api/v1/auth/logout", headers=auth_headers)
        assert resp.status_code == 204


class TestDeviceEndpoints:
    @pytest.mark.asyncio
    async def test_list_devices_requires_auth(self, client):
        resp = await client.get("/api/v1/devices")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_list_devices_empty(self, client, auth_headers):
        resp = await client.get("/api/v1/devices", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "items" in data

    @pytest.mark.asyncio
    async def test_create_device(self, client, auth_headers):
        mac = f"AA:BB:CC:DD:{uuid.uuid4().hex[:2].upper()}:{uuid.uuid4().hex[:2].upper()}"
        resp = await client.post("/api/v1/devices", json={
            "mac_address": mac,
            "name": "Test Device",
            "type": "smart_lock",
            "device_hash": "ab" * 32,
        }, headers=auth_headers)
        assert resp.status_code == 201
        assert "id" in resp.json()

    @pytest.mark.asyncio
    async def test_create_duplicate_device(self, client, auth_headers):
        mac = "CC:DD:EE:FF:00:99"
        payload = {"mac_address": mac, "name": "D1", "type": "camera", "device_hash": "ab" * 32}
        r1 = await client.post("/api/v1/devices", json=payload, headers=auth_headers)
        assert r1.status_code == 201
        r2 = await client.post("/api/v1/devices", json=payload, headers=auth_headers)
        assert r2.status_code == 409

    @pytest.mark.asyncio
    async def test_get_device_not_found(self, client, auth_headers):
        resp = await client.get(f"/api/v1/devices/{uuid.uuid4()}", headers=auth_headers)
        assert resp.status_code == 404


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"
