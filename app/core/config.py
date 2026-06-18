from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App
    APP_ENV: str = "development"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    APP_SECRET_KEY: str = "changeme"
    DEBUG: bool = True

    # JWT
    JWT_SECRET_KEY: str = "changeme"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://sentinel:sentinel_password@localhost:5432/sentinel"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "sentinel"
    POSTGRES_USER: str = "sentinel"
    POSTGRES_PASSWORD: str = "sentinel_password"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Blockchain
    BLOCKCHAIN_RPC_URL: str = "http://localhost:8545"
    BLOCKCHAIN_WS_URL: str = "ws://localhost:8546"
    DEVICE_REGISTRY_CONTRACT_ADDRESS: str = "0x0000000000000000000000000000000000000000"
    GATEWAY_PRIVATE_KEY: str = "0x" + "0" * 64
    BLOCKCHAIN_CHAIN_ID: int = 1337

    # AI Model
    MODEL_PATH: str = "./models/isolation_forest.pkl"
    ANOMALY_THRESHOLD: float = 0.85

    # MQTT
    MQTT_BROKER_HOST: str = "localhost"
    MQTT_BROKER_PORT: int = 1883
    MQTT_USERNAME: str = "sentinel"
    MQTT_PASSWORD: str = "sentinel_mqtt_password"
    MQTT_TLS_ENABLED: bool = False
    MQTT_TOPIC_PREFIX: str = "sentinel/devices"

    # OpenAI
    OPENAI_API_KEY: str = "sk-placeholder"
    OPENAI_MODEL: str = "gpt-4o"

    # ChromaDB
    CHROMADB_HOST: str = "localhost"
    CHROMADB_PORT: int = 8001

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Rate limiting
    COPILOT_MAX_TOOL_CALLS_PER_SESSION: int = 50

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors(cls, v):
        if isinstance(v, str):
            import json
            return json.loads(v)
        return v


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
