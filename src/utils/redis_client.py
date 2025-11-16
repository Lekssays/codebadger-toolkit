"""
Redis client wrapper for data storage
"""

import json
import logging
from typing import Any, Dict, List, Optional

import redis.asyncio as redis

from ..models import RedisConfig

logger = logging.getLogger(__name__)


class RedisClient:
    """Async Redis client for session storage"""

    def __init__(self, config: RedisConfig):
        self.config = config
        self.client: Optional[redis.Redis] = None

    async def connect(self):
        """Establish Redis connection"""
        try:
            self.client = redis.from_url(
                f"redis://{self.config.host}:{self.config.port}/{self.config.db}",
                password=self.config.password,
                decode_responses=self.config.decode_responses,
            )
            await self.client.ping()
            logger.info("Connected to Redis successfully")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise

    async def close(self):
        """Close Redis connection"""
        if self.client:
            await self.client.close()
            logger.info("Closed Redis connection")

    # Generic key-value operations
    async def set(self, key: str, value: str, ttl: Optional[int] = None):
        """Set a key-value pair"""
        if ttl:
            await self.client.set(key, value, ex=ttl)
        else:
            await self.client.set(key, value)

    async def get(self, key: str) -> Optional[str]:
        """Get a value by key"""
        return await self.client.get(key)

    async def delete(self, key: str):
        """Delete a key"""
        await self.client.delete(key)

    async def expire(self, key: str, ttl: int):
        """Set TTL on a key"""
        await self.client.expire(key, ttl)

    async def cache_query_result(
        self, codebase_hash: str, query_hash: str, result: Dict[str, Any], ttl: int = 300
    ):
        """Cache query result"""
        key = f"query:{codebase_hash}:{query_hash}"
        data = json.dumps(result)
        await self.client.set(key, data, ex=ttl)

    async def get_cached_query(
        self, codebase_hash: str, query_hash: str
    ) -> Optional[Dict[str, Any]]:
        """Get cached query result"""
        key = f"query:{codebase_hash}:{query_hash}"
        data = await self.client.get(key)
        if data:
            return json.loads(data)
        return None
