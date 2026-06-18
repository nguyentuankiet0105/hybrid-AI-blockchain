from typing import Optional

import redis.asyncio as aioredis

from app.core.config import settings

_redis_client: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
    return _redis_client


async def close_redis() -> None:
    global _redis_client
    if _redis_client:
        await _redis_client.aclose()
        _redis_client = None


# ── Helper shortcuts ──────────────────────────────────────────

async def redis_set(key: str, value: str, ex: Optional[int] = None) -> None:
    r = await get_redis()
    await r.set(key, value, ex=ex)


async def redis_get(key: str) -> Optional[str]:
    r = await get_redis()
    return await r.get(key)


async def redis_delete(key: str) -> None:
    r = await get_redis()
    await r.delete(key)


async def redis_exists(key: str) -> bool:
    r = await get_redis()
    return bool(await r.exists(key))
