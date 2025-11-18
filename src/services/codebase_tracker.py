"""
Codebase tracker for managing CPG codebase information by hash
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..models import CodebaseInfo
from ..utils.db_manager import DBManager

logger = logging.getLogger(__name__)


class CodebaseTracker:
    """Tracks codebase information by hash"""

    def __init__(self, db_manager: DBManager):
        self.db = db_manager

    def save_codebase(
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
                codebase_hash=codebase_hash,
                source_type=source_type,
                source_path=source_path,
                language=language,
                cpg_path=cpg_path,
                joern_port=joern_port,
                metadata=metadata or {},
            )

            # Convert to dict (which handles metadata JSON serialization)
            data = codebase.to_dict()
            self.db.save_codebase(data)

            logger.info(f"Saved codebase info for hash {codebase_hash}")
            return codebase

        except Exception as e:
            logger.error(f"Failed to save codebase {codebase_hash}: {e}")
            raise

    def get_codebase(self, codebase_hash: str) -> Optional[CodebaseInfo]:
        """Get codebase information by hash"""
        try:
            data = self.db.get_codebase(codebase_hash)
            
            if not data:
                return None
            
            return CodebaseInfo.from_dict(data)

        except Exception as e:
            logger.error(f"Failed to get codebase {codebase_hash}: {e}")
            return None

    def update_codebase(self, codebase_hash: str, **updates) -> None:
        """Update codebase fields"""
        try:
            # Get existing data first
            existing = self.get_codebase(codebase_hash)
            if not existing:
                raise ValueError(f"Codebase {codebase_hash} not found")
            
            data = existing.to_dict()
            
            # Handle metadata updates - merge with existing metadata
            if "metadata" in updates and isinstance(updates["metadata"], dict):
                if existing.metadata:
                    merged_metadata = {**existing.metadata, **updates["metadata"]}
                    updates["metadata"] = merged_metadata
            
            # Update data with new values
            data.update(updates)
            
            # Save back to DB
            self.db.save_codebase(data)
            
            logger.debug(f"Updated codebase {codebase_hash}")
        except Exception as e:
            logger.error(f"Failed to update codebase {codebase_hash}: {e}")
            raise

    def delete_codebase(self, codebase_hash: str) -> None:
        """Delete codebase information"""
        # Not implemented in DBManager yet, but we can add it if needed.
        # For now, we can just log a warning or implement it in DBManager.
        # Let's implement it in DBManager later if needed.
        pass

    def list_codebases(self) -> list[str]:
        """List all tracked codebase hashes"""
        return self.db.list_codebases()
