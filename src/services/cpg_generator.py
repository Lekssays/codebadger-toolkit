"""
CPG Generator for creating Code Property Graphs using joern-parse
"""

import asyncio
import logging
import os
import subprocess
from typing import Optional, Tuple

from ..constants import CPGS_DIR, CPG_FILENAME
from ..exceptions import CPGGenerationError
from ..models import CPGConfig, SessionStatus, Config
from .session_manager import SessionManager
from ..utils.redis_client import RedisClient

logger = logging.getLogger(__name__)


class CPGGenerator:
    """Generates CPG from source code using joern-parse"""

    def __init__(
        self, config: Config, session_manager: Optional[SessionManager] = None, redis_client: Optional[RedisClient] = None
    ):
        self.config = config
        self.session_manager = session_manager
        self.redis = redis_client
        self.process_map = {}  # Map of session_id -> process for tracking Joern servers

    async def initialize(self):
        """Initialize CPG generator (verify joern-parse is available)"""
        try:
            # Check if joern-parse is available
            result = subprocess.run(
                ["which", "joern-parse"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info(f"joern-parse found at: {result.stdout.strip()}")
            else:
                logger.warning("joern-parse not found in PATH")
            logger.info("CPG Generator initialized")
        except Exception as e:
            logger.error(f"Failed to initialize CPG generator: {e}")
            raise CPGGenerationError(f"Initialization failed: {str(e)}")

    async def generate_cpg(
        self, session_id: str, source_path: str, language: Optional[str] = None
    ) -> Tuple[str, int]:
        """
        Generate CPG from source code using joern-parse and start Joern server on allocated port.

        Args:
            session_id: Unique session identifier
            source_path: Path to source code directory
            language: Optional language hint (joern-parse auto-detects)

        Returns:
            Tuple of (cpg_path, port) - path to generated CPG file and port of Joern server

        Raises:
            CPGGenerationError: If CPG generation fails
        """
        try:
            logger.info(
                f"Starting CPG generation for session {session_id} from {source_path}"
            )

            if self.session_manager:
                await self.session_manager.update_status(
                    session_id, SessionStatus.GENERATING.value
                )

            # Get session to retrieve allocated port
            session = await self.session_manager.get_session(session_id)
            if not session:
                raise CPGGenerationError(f"Session {session_id} not found")
            
            joern_port = session.joern_port
            if not joern_port:
                raise CPGGenerationError(f"No port allocated for session {session_id}")

            # Create output directory for this session's CPG
            cpg_dir = os.path.join(CPGS_DIR, session_id)
            os.makedirs(cpg_dir, exist_ok=True)

            # Output path for CPG
            cpg_output_path = os.path.join(cpg_dir, CPG_FILENAME)

            # Build joern-parse command
            command = ["joern-parse", source_path, "-o", cpg_output_path]

            if language:
                logger.info(f"Using language hint: {language}")

            logger.info(f"Executing: {' '.join(command)}")

            # Execute with timeout
            try:
                result = await asyncio.wait_for(
                    self._exec_command_async(command),
                    timeout=self.config.cpg.generation_timeout,
                )

                stdout, stderr = result

                logger.info(f"CPG generation output:\n{stdout[:1000]}")

                if stderr:
                    logger.warning(f"CPG generation stderr:\n{stderr[:1000]}")

                # Validate CPG was created
                if await self._validate_cpg_async(cpg_output_path):
                    # Start Joern server on the allocated port with the generated CPG
                    await self._start_joern_server(session_id, cpg_output_path, joern_port)
                    
                    # Update session with port and ready status
                    if self.session_manager:
                        await self.session_manager.update_session(
                            session_id,
                            status=SessionStatus.READY.value,
                            cpg_path=cpg_output_path,
                            joern_port=joern_port,
                        )
                    
                    # Store in Redis for easy lookup
                    if self.redis:
                        await self.redis.set(
                            f"session:{session_id}:joern_server",
                            {
                                "cpg_path": cpg_output_path,
                                "port": joern_port,
                                "host": self.config.joern.http_host,
                            },
                            ttl=3600
                        )
                    
                    logger.info(
                        f"CPG generation completed for session {session_id}: {cpg_output_path} "
                        f"with Joern server on port {joern_port}"
                    )
                    return cpg_output_path, joern_port
                else:
                    error_msg = "CPG file was not created or is empty"
                    logger.error(error_msg)
                    if self.session_manager:
                        await self.session_manager.update_status(
                            session_id, SessionStatus.ERROR.value, error_msg
                        )
                    raise CPGGenerationError(error_msg)

            except asyncio.TimeoutError:
                error_msg = (
                    f"CPG generation timed out after {self.config.cpg.generation_timeout}s"
                )
                logger.error(error_msg)
                if self.session_manager:
                    await self.session_manager.update_status(
                        session_id, SessionStatus.ERROR.value, error_msg
                    )
                raise CPGGenerationError(error_msg)

        except CPGGenerationError:
            raise
        except Exception as e:
            error_msg = f"CPG generation failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            if self.session_manager:
                await self.session_manager.update_status(
                    session_id, SessionStatus.ERROR.value, error_msg
                )
            raise CPGGenerationError(error_msg)

    async def _exec_command_async(
        self, command: list
    ) -> tuple[str, str]:
        """Execute command asynchronously"""
        loop = asyncio.get_event_loop()

        def _exec_sync():
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.config.cpg.generation_timeout,
                )
                return result.stdout, result.stderr
            except subprocess.TimeoutExpired as e:
                raise CPGGenerationError(f"Command timed out: {str(e)}")

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

            # Minimum CPG size (1KB)
            min_cpg_size = 1024

            if file_size < min_cpg_size:
                logger.error(
                    f"CPG file is too small ({file_size} bytes), likely empty. "
                    f"Minimum expected size: {min_cpg_size} bytes"
                )
                return False

            logger.info(f"CPG file validated: {cpg_path} (size: {file_size} bytes)")
            return True

        except Exception as e:
            logger.error(f"Failed to validate CPG: {e}")
            return False

    async def _start_joern_server(self, session_id: str, cpg_path: str, port: int) -> None:
        """
        Start a Joern interactive shell server on the specified port with the CPG loaded.
        
        Args:
            session_id: Session identifier
            cpg_path: Path to the CPG file
            port: Port to run the Joern server on
            
        Raises:
            CPGGenerationError: If server fails to start
        """
        try:
            logger.info(f"Starting Joern server on port {port} for session {session_id}")
            
            # Build Joern server command
            # Using joern interactive shell with the CPG
            command = [
                self.config.joern.binary_path,
                cpg_path,
                "--server",
                f"--listen=0.0.0.0:{port}",
            ]
            
            logger.info(f"Executing: {' '.join(command)}")
            
            # Start server process (detached)
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            # Store process reference
            self.process_map[session_id] = process
            
            # Give server a moment to start
            await asyncio.sleep(2)
            
            # Check if process is still running
            if process.returncode is not None:
                _, stderr = await process.communicate()
                logger.error(f"Joern server failed to start: {stderr.decode()}")
                raise CPGGenerationError(
                    f"Joern server on port {port} failed to start"
                )
            
            logger.info(f"Joern server started successfully on port {port}")
            
        except Exception as e:
            logger.error(f"Failed to start Joern server: {e}")
            raise CPGGenerationError(f"Failed to start Joern server: {str(e)}")

    async def stop_joern_server(self, session_id: str) -> None:
        """
        Stop the Joern server for a session.
        
        Args:
            session_id: Session identifier
        """
        try:
            process = self.process_map.get(session_id)
            if process and process.returncode is None:
                logger.info(f"Stopping Joern server for session {session_id}")
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    logger.warning(f"Joern server for session {session_id} did not stop, killing...")
                    process.kill()
                    await process.wait()
                del self.process_map[session_id]
                logger.info(f"Joern server for session {session_id} stopped")
        except Exception as e:
            logger.error(f"Error stopping Joern server for {session_id}: {e}")
