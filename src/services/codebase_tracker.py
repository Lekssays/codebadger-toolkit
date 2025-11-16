"""
Codebase tracker for managing CPG codebase information by hash
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..models import CodebaseInfo
from ..utils.redis_client import RedisClient

logger = logging.getLogger(__name__)


class CodebaseTracker:
    """Tracks codebase information by hash"""

    def __init__(self, redis_client: RedisClient):
        self.redis = redis_client
        self._key_prefix = "codebase:"

    def _make_key(self, codebase_hash: str) -> str:
        """Create Redis key for codebase"""
        return f"{self._key_prefix}{codebase_hash}"

    async def save_codebase(
        self,
        codebase_hash: str,
        source_type: str,
        source_path: str,
        language: str,
        cpg_path: Optional[str] = None,
        joern_port: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> CodebaseInfo:
        """Save or update codebase information"""
        try:
            codebase = CodebaseInfo(
                hash=codebase_hash,
                source_type=source_type,
                source_path=source_path,
                language=language,
                cpg_path=cpg_path,
                joern_port=joern_port,
                metadata=metadata or {},
            )

            key = self._make_key(codebase_hash)
            # Filter out None values for Redis
            data = {k: v for k, v in codebase.to_dict().items() if v is not None}
            await self.redis.client.hset(key, mapping=data)
            
            # Set expiry to 7 days
            await self.redis.client.expire(key, 7 * 24 * 3600)

            logger.info(f"Saved codebase info for hash {codebase_hash}")
            return codebase

        except Exception as e:
            logger.error(f"Failed to save codebase {codebase_hash}: {e}")
            raise

    async def get_codebase(self, codebase_hash: str) -> Optional[CodebaseInfo]:
        """Get codebase information by hash"""
        try:
            key = self._make_key(codebase_hash)
            data = await self.redis.client.hgetall(key)
            
            if not data:
                return None

            # Update last accessed time
            data["last_accessed"] = datetime.now(timezone.utc).isoformat()
            await self.redis.client.hset(key, "last_accessed", data["last_accessed"])
            
            return CodebaseInfo.from_dict(data)

        except Exception as e:
            logger.error(f"Failed to get codebase {codebase_hash}: {e}")
            return None

    async def update_codebase(self, codebase_hash: str, **updates) -> None:
        """Update codebase fields"""
        try:
            updates["last_accessed"] = datetime.now(timezone.utc).isoformat()
            # Filter out None values for Redis
            updates = {k: v for k, v in updates.items() if v is not None}
            if updates:  # Only update if there are non-None values
                key = self._make_key(codebase_hash)
                await self.redis.client.hset(key, mapping=updates)
            logger.debug(f"Updated codebase {codebase_hash}")
        except Exception as e:
            logger.error(f"Failed to update codebase {codebase_hash}: {e}")
            raise

    async def delete_codebase(self, codebase_hash: str) -> None:
        """Delete codebase information"""
        try:
            key = self._make_key(codebase_hash)
            await self.redis.client.delete(key)
            logger.info(f"Deleted codebase {codebase_hash}")
        except Exception as e:
            logger.error(f"Failed to delete codebase {codebase_hash}: {e}")
            raise

    async def list_codebases(self) -> list[str]:
        """List all tracked codebase hashes"""
        try:
            keys = []
            async for key in self.redis.client.scan_iter(f"{self._key_prefix}*"):
                # Extract hash from key
                codebase_hash = key.replace(self._key_prefix, "")
                keys.append(codebase_hash)
            return keys
        except Exception as e:
            logger.error(f"Failed to list codebases: {e}")
            return []
