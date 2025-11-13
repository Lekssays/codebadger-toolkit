"""
Core MCP Tools for Joern MCP Server - Session management and CPG generation
"""

import asyncio
import logging
import os
from typing import Any, Dict, Optional

from ..exceptions import SessionNotFoundError, ValidationError
from ..models import SessionStatus
from ..utils.validators import (
    validate_github_url,
    validate_language,
    validate_local_path,
    validate_session_id,
    validate_source_type,
)

logger = logging.getLogger(__name__)


def register_core_tools(mcp, services: dict):
    """Register core MCP tools with the FastMCP server"""

    @mcp.tool()
    async def create_cpg_session(
        source_type: str,
        source_path: str,
        language: str,
        github_token: Optional[str] = None,
        branch: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Creates a new CPG analysis session and generates the CPG.

        This tool initiates CPG generation for a codebase. For GitHub repositories,
        it clones the repo first. For local paths, it uses the existing directory.
        A dedicated Joern server will be started on a unique port for this session.

        Args:
            source_type: Either "local" or "github"
            source_path: For local: absolute path to source directory
                        For github: full GitHub URL
            language: Programming language (java, c, cpp, javascript, python, go, etc)
            github_token: GitHub Personal Access Token for private repositories
            branch: Specific git branch to checkout

        Returns:
            Dictionary with session info, allocated port, and status
        """
        try:
            validate_source_type(source_type)
            validate_language(language)

            session_manager = services["session_manager"]
            git_manager = services["git_manager"]
            cpg_generator = services["cpg_generator"]

            session = await session_manager.create_session(
                source_type=source_type,
                source_path=source_path,
                language=language,
                options={"github_token": github_token, "branch": branch},
            )

            logger.info(
                f"Created session {session.id} with allocated port {session.joern_port}"
            )

            if source_type == "github":
                validate_github_url(source_path)
                await git_manager.clone_repository(
                    repo_url=source_path,
                    target_path=session.source_path,
                    branch=branch,
                    token=github_token,
                )
                container_source_path = session.source_path
            else:
                validate_local_path(source_path)
                if not source_path.startswith("/"):
                    raise ValidationError("Local path must be absolute")
                container_source_path = source_path

            asyncio.create_task(
                cpg_generator.generate_cpg(
                    session_id=session.id,
                    source_path=container_source_path,
                    language=language,
                )
            )

            return {
                "success": True,
                "session_id": session.id,
                "status": SessionStatus.GENERATING.value,
                "message": "CPG generation started",
                "joern_port": session.joern_port,
                "joern_host": session.joern_host,
                "estimated_time": "2-5 minutes",
            }

        except ValidationError as e:
            logger.error(f"Validation error: {e}")
            return {
                "success": False,
                "error": {"code": "VALIDATION_ERROR", "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Failed to create session: {e}", exc_info=True)
            return {
                "success": False,
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "Failed to create session",
                    "details": str(e),
                },
            }

    @mcp.tool()
    async def get_session_status(session_id: str) -> Dict[str, Any]:
        """
        Gets the current status of a CPG session.

        Use this to check if CPG generation is complete and get Joern server details.

        Args:
            session_id: The session ID to query

        Returns:
            Dictionary with session status, port, CPG path, and metadata
        """
        try:
            validate_session_id(session_id)

            session_manager = services["session_manager"]
            session = await session_manager.get_session(session_id)

            if not session:
                raise SessionNotFoundError(f"Session {session_id} not found")

            cpg_size = None
            if session.cpg_path and os.path.exists(session.cpg_path):
                size_bytes = os.path.getsize(session.cpg_path)
                cpg_size = f"{size_bytes / (1024 * 1024):.2f}MB"

            return {
                "success": True,
                "session_id": session.id,
                "status": session.status,
                "source_type": session.source_type,
                "source_path": session.source_path,
                "language": session.language,
                "joern_port": session.joern_port,
                "joern_host": session.joern_host,
                "cpg_path": session.cpg_path,
                "cpg_size": cpg_size,
                "created_at": session.created_at.isoformat(),
                "last_accessed": session.last_accessed.isoformat(),
                "error_message": session.error_message,
            }

        except SessionNotFoundError as e:
            logger.error(f"Session not found: {e}")
            return {
                "success": False,
                "error": {"code": "SESSION_NOT_FOUND", "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Error getting session status: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    @mcp.tool()
    async def close_session(session_id: str) -> Dict[str, Any]:
        """
        Closes a CPG session and stops the Joern server.

        This stops the Joern server, removes temporary files, and frees up resources.

        Args:
            session_id: The session ID to close

        Returns:
            Success status dictionary
        """
        try:
            validate_session_id(session_id)

            session_manager = services["session_manager"]
            cpg_generator = services["cpg_generator"]

            session = await session_manager.get_session(session_id)
            if not session:
                raise SessionNotFoundError(f"Session {session_id} not found")

            if session.joern_port:
                await cpg_generator.stop_joern_server(session_id)

            await session_manager.cleanup_session(session_id)

            return {
                "success": True,
                "message": "Session closed successfully",
            }

        except SessionNotFoundError as e:
            logger.error(f"Session not found: {e}")
            return {
                "success": False,
                "error": {"code": "SESSION_NOT_FOUND", "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Error closing session: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }
