"""
CPG Generator for creating Code Property Graphs using Joern CLI
"""

import asyncio
import logging
import os
import subprocess
from typing import AsyncIterator, Dict, Optional

from ..exceptions import CPGGenerationError
from ..models import CPGConfig, Config

logger = logging.getLogger(__name__)


class CPGGenerator:
    """Generates CPG from source code using Docker containers"""

    # Language-specific Joern commands
    LANGUAGE_COMMANDS = {
        "java": "javasrc2cpg",
        "c": "c2cpg.sh",
        "cpp": "c2cpg.sh",
        "javascript": "jssrc2cpg.sh",
        "python": "pysrc2cpg",
        "go": "gosrc2cpg",
        "kotlin": "kotlin2cpg",
        "csharp": "csharpsrc2cpg",
        "ghidra": "ghidra2cpg",
        "jimple": "jimple2cpg",
        "php": "php2cpg",
        "ruby": "rubysrc2cpg",
        "swift": "swiftsrc2cpg.sh",
    }

    def __init__(
        self, config: Config, docker_orchestrator=None
    ):
        self.config = config
        # docker_orchestrator is ignored - we run Joern CLI directly

    async def initialize(self):
        """Initialize CPG Generator (no-op in container)"""
        logger.info("CPG Generator initialized (running locally)")

    async def generate_cpg(
        self, source_path: str, language: str, cpg_path: str
    ) -> str:
        """Generate CPG from source code using Joern CLI directly
        
        Args:
            source_path: Path to source code (e.g., /app/playground/codebases/<hash>/)
            language: Programming language
            cpg_path: Full path where CPG should be stored (e.g., /app/playground/cpgs/<hash>/cpg.bin)
            
        Returns:
            Path to generated CPG file
        """
        try:
            logger.info(f"Starting CPG generation for {source_path} -> {cpg_path}")

            # Get language-specific command
            if language not in self.LANGUAGE_COMMANDS:
                raise CPGGenerationError(f"Unsupported language: {language}")
            
            base_cmd = self.LANGUAGE_COMMANDS[language]
            
            # Create CPG directory
            cpg_dir = os.path.dirname(cpg_path)
            os.makedirs(cpg_dir, exist_ok=True)
            
            # Get Java opts from config
            java_opts = self.config.joern.java_opts or "-Xmx2G -Xms512M"
            
            # Build command arguments
            cmd_args = [base_cmd, source_path, "-o", cpg_path]
            
            # Add Java opts as environment variables (Joern scripts read JAVA_OPTS)
            env = os.environ.copy()
            if java_opts:
                env["JAVA_OPTS"] = java_opts
                logger.info(f"Using JAVA_OPTS: {java_opts}")
            
            # Apply exclusions for languages that support them
            if (
                language in self.config.cpg.languages_with_exclusions
                and self.config.cpg.exclusion_patterns
            ):
                combined_regex = "|".join(
                    f"({pattern})" for pattern in self.config.cpg.exclusion_patterns
                )
                cmd_args.extend(["--exclude-regex", combined_regex])

            logger.info(f"Executing CPG generation: {' '.join(cmd_args)}")

            # Execute with timeout
            try:
                result = await asyncio.wait_for(
                    self._exec_command_async(cmd_args, env),
                    timeout=self.config.cpg.generation_timeout,
                )

                logger.info(f"CPG generation output:\n{result[:2000]}")

                # Check for fatal errors
                if "ERROR:" in result or "Exception" in result:
                    logger.error(f"CPG generation reported fatal errors:\n{result[:2000]}")
                    error_msg = "Joern reported fatal errors during CPG generation"
                    raise CPGGenerationError(error_msg)

                # Validate CPG was created on disk
                if await self._validate_cpg_async(cpg_path):
                    logger.info(f"CPG generation completed: {cpg_path}")
                    return cpg_path
                else:
                    error_msg = "CPG file was not created"
                    logger.error(f"{error_msg}: {result[:2000]}")
                    raise CPGGenerationError(error_msg)

            except asyncio.TimeoutError:
                error_msg = (
                    f"CPG generation timed out after {self.config.cpg.generation_timeout}s"
                )
                logger.error(error_msg)
                raise CPGGenerationError(error_msg)

        except CPGGenerationError:
            raise
        except Exception as e:
            error_msg = f"CPG generation failed: {str(e)}"
            logger.error(error_msg)
            raise CPGGenerationError(error_msg)

    async def _exec_command_async(self, cmd_args: list, env: dict) -> str:
        """Execute command asynchronously using subprocess"""
        loop = asyncio.get_event_loop()

        def _exec_sync():
            result = subprocess.run(
                cmd_args,
                env=env,
                capture_output=True,
                text=True,
                timeout=self.config.cpg.generation_timeout
            )
            # Combine stdout and stderr
            output = result.stdout + result.stderr
            return output

        return await loop.run_in_executor(None, _exec_sync)

    async def _validate_cpg_async(self, cpg_path: str) -> bool:
        """Validate that CPG file was created successfully and is not empty"""
        try:
            # Check if file exists
            if not os.path.exists(cpg_path):
                logger.error(f"CPG file not found: {cpg_path}")
                return False

            # Check file size
            file_size = os.path.getsize(cpg_path)
            min_cpg_size = 1024  # 1KB minimum

            if file_size < min_cpg_size:
                logger.error(
                    f"CPG file is too small ({file_size} bytes), likely empty or corrupted. "
                    f"Minimum expected size: {min_cpg_size} bytes"
                )
                return False

            logger.info(
                f"CPG file created successfully: {cpg_path} (size: {file_size} bytes)"
            )
            return True

        except Exception as e:
            logger.error(f"CPG validation failed: {e}")
            return False

    async def cleanup(self):
        """Cleanup (no-op in container)"""
        logger.info("CPG Generator cleanup (no-op)")
