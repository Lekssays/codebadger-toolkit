"""
Core MCP Tools for CodeBadger Toolkit Server - Simplified hash-based version

Provides core CPG management functionality
"""

import asyncio
import hashlib
import io
import logging
import os
import shutil
import tarfile
from typing import Any, Dict, Optional

from ..exceptions import ValidationError
from ..utils.validators import (
    validate_github_url,
    validate_language,
    validate_local_path,
    validate_source_type,
)

logger = logging.getLogger(__name__)


def get_cpg_cache_key(source_type: str, source_path: str, language: str) -> str:
    """
    Generate a deterministic CPG cache key based on source type, path, and language.
    """
    if source_type == "github":
        # Extract owner/repo from GitHub URL
        if "github.com/" in source_path:
            parts = source_path.split("github.com/")[-1].split("/")
            if len(parts) >= 2:
                owner = parts[0]
                repo = parts[1].replace(".git", "")
                identifier = f"github:{owner}/{repo}:{language}"
            else:
                identifier = f"github:{source_path}:{language}"
        else:
            identifier = f"github:{source_path}:{language}"
    else:
        # For local paths, use absolute path
        source_path = os.path.abspath(source_path)
        identifier = f"local:{source_path}:{language}"

    hash_digest = hashlib.sha256(identifier.encode()).hexdigest()[:16]
    return hash_digest


def register_core_tools(mcp, services: dict):
    """Register core MCP tools with the FastMCP server"""

    @mcp.tool()
    async def generate_cpg(
        source_type: str,
        source_path: str,
        language: str,
        github_token: Optional[str] = None,
        branch: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate a CPG for a codebase.

        This tool generates a Code Property Graph for the specified codebase.
        For GitHub repositories, it clones the repo first. For local paths,
        it copies the source code. The CPG is cached by codebase hash.

        Args:
            source_type: Either "local" or "github"
            source_path: For local: absolute path to source directory
                        For github: full GitHub URL (e.g., https://github.com/user/repo)
            language: Programming language - one of: java, c, cpp, javascript,
                        python, go, kotlin, csharp, ghidra, jimple, php, ruby, swift
            github_token: GitHub Personal Access Token for private repositories (optional)
            branch: Specific git branch to checkout (optional, defaults to default branch)

        Returns:
            {
                "codebase_hash": "hash of the codebase",
                "status": "ready" | "generating" | "cached",
                "message": "Status message",
                "cpg_path": "path to CPG file"
            }

        Examples:
            # GitHub repository
            generate_cpg(
                source_type="github",
                source_path="https://github.com/joernio/sample-repo",
                language="java"
            )

            # Local directory
            generate_cpg(
                source_type="local",
                source_path="/home/user/projects/myapp",
                language="python"
            )
        """
        try:
            # Validate inputs
            validate_source_type(source_type)
            validate_language(language)

            git_manager = services["git_manager"]
            cpg_generator = services["cpg_generator"]
            codebase_tracker = services["codebase_tracker"]

            # Generate CPG cache key
            cpg_cache_key = get_cpg_cache_key(source_type, source_path, language)
            logger.info(f"Processing codebase with hash: {cpg_cache_key}")

            # Get playground path (absolute)
            playground_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "playground")
            )

            # Paths for codebase and CPG storage
            codebase_dir = os.path.join(playground_path, "codebases", cpg_cache_key)
            cpg_dir = os.path.join(playground_path, "cpgs", cpg_cache_key)
            cpg_path = os.path.join(cpg_dir, "cpg.bin")

            # Check if CPG already exists
            if os.path.exists(cpg_path):
                logger.info(f"Found existing CPG: {cpg_path}")
                
                # Update codebase tracker
                await codebase_tracker.save_codebase(
                    codebase_hash=cpg_cache_key,
                    source_type=source_type,
                    source_path=source_path,
                    language=language,
                    cpg_path=cpg_path,
                )

                return {
                    "codebase_hash": cpg_cache_key,
                    "status": "cached",
                    "message": "Using existing CPG from cache",
                    "cpg_path": cpg_path,
                }

            # Prepare source code
            logger.info(f"Preparing source code for {cpg_cache_key}")
            
            if source_type == "github":
                validate_github_url(source_path)
                
                # Clone to playground/codebases/<hash>
                if not os.path.exists(codebase_dir):
                    os.makedirs(codebase_dir, exist_ok=True)
                    await git_manager.clone_repository(
                        repo_url=source_path,
                        target_path=codebase_dir,
                        branch=branch,
                        token=github_token,
                    )
                    logger.info(f"Cloned repository to {codebase_dir}")
                else:
                    logger.info(f"Using existing cloned repository at {codebase_dir}")
            else:
                # Local path
                validate_local_path(source_path)
                
                if not os.path.isabs(source_path):
                    raise ValidationError("Local path must be absolute")
                
                if not os.path.exists(source_path):
                    raise ValidationError(f"Path does not exist: {source_path}")
                if not os.path.isdir(source_path):
                    raise ValidationError(f"Path is not a directory: {source_path}")

                # Copy to playground/codebases/<hash>
                if not os.path.exists(codebase_dir):
                    os.makedirs(codebase_dir, exist_ok=True)
                    logger.info(f"Copying source from {source_path} to {codebase_dir}")
                    
                    for item in os.listdir(source_path):
                        src_item = os.path.join(source_path, item)
                        dst_item = os.path.join(codebase_dir, item)
                        
                        if os.path.isdir(src_item):
                            shutil.copytree(src_item, dst_item, dirs_exist_ok=True)
                        else:
                            shutil.copy2(src_item, dst_item)
                else:
                    logger.info(f"Using existing source at {codebase_dir}")

            # Ensure CPG directory exists (we're running inside the container)
            os.makedirs(cpg_dir, exist_ok=True)
            logger.info(f"CPG directory ready: {cpg_dir}")

            # Paths for CPG generation (already inside container at /app/playground)
            source_path_for_cpg = codebase_dir  # Already the correct path
            cpg_path_for_gen = cpg_path  # Already the correct path

            # Track in codebase tracker
            await codebase_tracker.save_codebase(
                codebase_hash=cpg_cache_key,
                source_type=source_type,
                source_path=source_path,
                language=language,
                cpg_path=None,  # Will be updated after generation
            )

            # Generate CPG asynchronously
            async def generate_cpg_async():
                try:
                    # Generate CPG (already inside container, no copying needed)
                    logger.info(f"Generating CPG for {cpg_cache_key}")
                    await cpg_generator.generate_cpg(
                        source_path=source_path_for_cpg,
                        language=language,
                        cpg_path=cpg_path_for_gen,
                    )
                    
                    logger.info(f"CPG generated successfully: {cpg_path}")
                    
                    # Update codebase tracker with CPG path
                    await codebase_tracker.update_codebase(
                        codebase_hash=cpg_cache_key,
                        cpg_path=cpg_path,
                    )
                    
                except Exception as e:
                    logger.error(f"Failed to generate CPG for {cpg_cache_key}: {e}")
                    raise

            # Start async generation
            asyncio.create_task(generate_cpg_async())

            return {
                "codebase_hash": cpg_cache_key,
                "status": "generating",
                "message": "CPG generation started",
                "estimated_time": "2-5 minutes",
            }

        except ValidationError as e:
            logger.error(f"Validation error: {e}")
            return {
                "success": False,
                "error": {"code": "VALIDATION_ERROR", "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Failed to generate CPG: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    @mcp.tool()
    async def get_cpg_status(codebase_hash: str) -> Dict[str, Any]:
        """
        Get the status of a CPG generation or check if CPG exists.

        Args:
            codebase_hash: The hash identifier of the codebase

        Returns:
            {
                "codebase_hash": "hash",
                "exists": true/false,
                "cpg_path": "path to CPG if exists",
                "source_type": "local/github",
                "language": "programming language"
            }
        """
        try:
            codebase_tracker = services["codebase_tracker"]
            
            # Get codebase info
            codebase_info = await codebase_tracker.get_codebase(codebase_hash)
            
            if not codebase_info:
                # Check if CPG file exists on disk
                playground_path = os.path.abspath(
                    os.path.join(os.path.dirname(__file__), "..", "..", "playground")
                )
                cpg_path = os.path.join(playground_path, "cpgs", codebase_hash, "cpg.bin")
                
                if os.path.exists(cpg_path):
                    return {
                        "codebase_hash": codebase_hash,
                        "exists": True,
                        "cpg_path": cpg_path,
                        "status": "ready",
                    }
                else:
                    return {
                        "codebase_hash": codebase_hash,
                        "exists": False,
                        "status": "not_found",
                        "message": "CPG not found for this codebase hash",
                    }
            
            # Check if CPG file exists
            cpg_exists = codebase_info.cpg_path and os.path.exists(codebase_info.cpg_path)
            
            return {
                "codebase_hash": codebase_hash,
                "exists": cpg_exists,
                "status": "ready" if cpg_exists else "generating",
                "cpg_path": codebase_info.cpg_path if cpg_exists else None,
                "source_type": codebase_info.source_type,
                "source_path": codebase_info.source_path,
                "language": codebase_info.language,
                "created_at": codebase_info.created_at.isoformat(),
                "last_accessed": codebase_info.last_accessed.isoformat(),
            }

        except Exception as e:
            logger.error(f"Failed to get CPG status: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }
