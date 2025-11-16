"""
Simplified Docker orchestrator for container
Now running inside the container, just manages local Joern processes
"""

import asyncio
import logging
import subprocess
from typing import Dict, Optional

from ..models import JoernConfig
from .joern_client import JoernServerClient
from .port_manager import PortManager

logger = logging.getLogger(__name__)


class DockerOrchestrator:
    """Manages Joern server processes running locally inside the container"""

    def __init__(self, joern_config: JoernConfig):
        self.joern_config = joern_config
        self.port_manager = PortManager()
        
        # Track running Joern servers
        self.joern_clients: Dict[str, JoernServerClient] = {}  # codebase_hash -> client
        self.server_processes: Dict[str, subprocess.Popen] = {}  # codebase_hash -> process
        
        logger.info("Docker orchestrator initialized for local execution")

    async def initialize(self):
        """Initialize the orchestrator"""
        logger.info("Docker orchestrator ready (running locally)")

    async def start_joern_server(self, codebase_hash: str, cpg_path: str) -> int:
        """
        Start a Joern server instance for a codebase
        
        Args:
            codebase_hash: Codebase hash identifier
            cpg_path: Path to the CPG file (local container path)
            
        Returns:
            Port number assigned to the server
        """
        try:
            # Check if server already running
            if codebase_hash in self.joern_clients:
                port = await self.port_manager.get_port(codebase_hash)
                logger.info(f"Joern server already running for codebase {codebase_hash} on port {port}")
                return port

            # Allocate port
            port = await self.port_manager.allocate_port(codebase_hash)
            
            # Start joern server process
            logger.info(f"Starting Joern server for codebase {codebase_hash} on port {port}")
            
            # Use subprocess to start Joern server
            cmd = [
                "joern",
                "--server",
                "--server-host", "0.0.0.0",
                "--server-port", str(port)
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd="/playground"
            )
            
            self.server_processes[codebase_hash] = process
            logger.info(f"Joern server started with PID {process.pid} for codebase {codebase_hash}")
            
            # Wait for server to start
            await asyncio.sleep(3)
            
            # Create client and verify server is running
            client = JoernServerClient(host="localhost", port=port)
            await client.initialize()
            
            # Wait for server to be ready
            max_retries = 10
            for i in range(max_retries):
                if await client.health_check():
                    logger.info(f"Joern server is ready on port {port}")
                    break
                logger.debug(f"Waiting for Joern server to be ready... ({i+1}/{max_retries})")
                await asyncio.sleep(1)
            else:
                # Kill the process if health check failed
                process.kill()
                await self.port_manager.release_port(codebase_hash)
                raise RuntimeError(f"Joern server failed to start on port {port}")
            
            self.joern_clients[codebase_hash] = client
            
            # Load CPG if provided
            if cpg_path:
                logger.info(f"Loading CPG {cpg_path} for codebase {codebase_hash}")
                await self._load_cpg_in_server(codebase_hash, cpg_path)
            
            return port
            
        except Exception as e:
            logger.error(f"Failed to start Joern server for codebase {codebase_hash}: {e}")
            if codebase_hash in self.server_processes:
                self.server_processes[codebase_hash].kill()
                del self.server_processes[codebase_hash]
            await self.port_manager.release_port(codebase_hash)
            raise

    async def _load_cpg_in_server(self, codebase_hash: str, cpg_path: str):
        """Load a CPG in the Joern server"""
        client = self.joern_clients.get(codebase_hash)
        if not client:
            raise RuntimeError(f"No Joern client found for codebase {codebase_hash}")
        
        try:
            # Execute importCpg command
            query = f'importCpg("{cpg_path}")'
            result = await client.execute_query(query, timeout=120)
            
            if not result.get("success"):
                stderr = result.get("stderr", "Unknown error")
                logger.error(f"Failed to load CPG: {stderr}")
                raise RuntimeError(f"Failed to load CPG: {stderr}")
            
            logger.info(f"CPG loaded successfully for codebase {codebase_hash}")
            
        except Exception as e:
            logger.error(f"Error loading CPG in server: {e}")
            raise

    async def get_joern_client(self, codebase_hash: str) -> Optional[JoernServerClient]:
        """Get the Joern client for a codebase"""
        return self.joern_clients.get(codebase_hash)

    async def stop_joern_server(self, codebase_hash: str):
        """Stop a Joern server instance"""
        try:
            # Close client
            if codebase_hash in self.joern_clients:
                client = self.joern_clients[codebase_hash]
                await client.close()
                del self.joern_clients[codebase_hash]
            
            # Kill process
            if codebase_hash in self.server_processes:
                process = self.server_processes[codebase_hash]
                process.kill()
                process.wait(timeout=5)
                del self.server_processes[codebase_hash]
                logger.info(f"Stopped Joern server for codebase {codebase_hash}")
            
            # Release port
            await self.port_manager.release_port(codebase_hash)
            
        except Exception as e:
            logger.error(f"Error stopping Joern server for codebase {codebase_hash}: {e}")

    async def cleanup(self):
        """Cleanup all servers"""
        logger.info("Cleaning up all Joern servers")
        codebases = list(self.joern_clients.keys())
        for codebase_hash in codebases:
            await self.stop_joern_server(codebase_hash)
        logger.info("Docker orchestrator cleanup complete")
