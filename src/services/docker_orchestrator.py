"""
Docker orchestration for CodeBadger Toolkit Server
"""

import asyncio
import logging
import os
import time
from typing import Dict, Optional

import docker
import docker.types

from .port_manager import PortManager
from .joern_client import JoernServerClient

logger = logging.getLogger(__name__)


class DockerOrchestrator:
    """Manages a single Docker container with multiple Joern server instances"""

    def __init__(self, playground_path: str = "playground"):
        self.client: Optional[docker.DockerClient] = None
        self.container_id: Optional[str] = None
        # Ensure playground path is absolute from the start
        # Convert to realpath to resolve any symlinks which might cause Docker issues
        self.playground_path = os.path.realpath(os.path.abspath(os.path.expanduser(playground_path)))
        self.port_manager = PortManager()
        self.joern_clients: Dict[str, JoernServerClient] = {}  # codebase_hash -> client
        self.server_processes: Dict[str, str] = {}  # codebase_hash -> process_id/tracking

    async def initialize(self):
        """Initialize Docker client and start the main container"""
        try:
            self.client = docker.from_env()
            self.client.ping()
            logger.info("Docker client initialized successfully")
            
            # Start the main Joern container
            await self._start_main_container()
            
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            raise

    async def _start_main_container(self):
        """Start the main Docker container with Joern"""
        try:
            if not self.client:
                raise RuntimeError("Docker client not initialized")

            # Ensure playground path is absolute
            self.playground_path = os.path.abspath(self.playground_path)
            
            # Ensure playground directories exist
            os.makedirs(os.path.join(self.playground_path, "codebases"), exist_ok=True)
            os.makedirs(os.path.join(self.playground_path, "cpgs"), exist_ok=True)
            logger.info(f"Playground directory (absolute): {self.playground_path}")

            # Container configuration
            container_name = "codebadger-toolkit-server"
            
            # Check if container already exists
            try:
                existing = self.client.containers.get(container_name)
                logger.info(f"Found existing container {container_name}, removing it")
                existing.stop(timeout=5)
                existing.remove()
            except docker.errors.NotFound:
                pass

            # Don't expose ports upfront - we'll use host network mode
            # or expose ports dynamically when starting joern servers
            # This avoids "port already allocated" errors
            logger.info("Creating container without volume mount (will use docker cp)")
            
            host_config = self.client.api.create_host_config(
                network_mode='host'  # Use host network to avoid port conflicts
            )
            
            container_config = self.client.api.create_container(
                image="joern:latest",
                name=container_name,
                command="tail -f /dev/null",
                working_dir="/playground",
                host_config=host_config,
                detach=True
            )
            
            container = self.client.containers.get(container_config['Id'])
            container.start()
            
            # Initialize playground structure in container
            container.exec_run("mkdir -p /playground/codebases /playground/cpgs")

            self.container_id = container.id
            logger.info(f"Started main Joern container {self.container_id}")

        except Exception as e:
            logger.error(f"Failed to start main container: {e}")
            raise

    async def start_joern_server(self, codebase_hash: str, cpg_path: str) -> int:
        """
        Start a Joern server instance for a codebase
        
        Args:
            codebase_hash: Codebase hash identifier
            cpg_path: Path to the CPG file (host filesystem path)
            
        Returns:
            Port number assigned to the server
        """
        try:
            if not self.container_id:
                raise RuntimeError("Main container not started")

            # Check if server already running for this codebase
            if codebase_hash in self.joern_clients:
                port = await self.port_manager.get_port(codebase_hash)
                logger.info(f"Joern server already running for codebase {codebase_hash} on port {port}")
                return port

            # Copy CPG to container if it's a host path
            container = self.client.containers.get(self.container_id)
            if cpg_path and not cpg_path.startswith("/workspace"):
                # It's a host path, need to copy to container
                import os
                container_cpg_dir = f"/workspace/cpgs/{codebase_hash}"
                container_cpg_path = f"{container_cpg_dir}/cpg.bin"
                
                # Create directory in container
                container.exec_run(["mkdir", "-p", container_cpg_dir])
                
                # Copy CPG file to container
                if os.path.exists(cpg_path):
                    logger.info(f"Copying CPG from {cpg_path} to container {container_cpg_path}")
                    import tarfile
                    import io
                    
                    # Create tar archive in memory
                    tar_stream = io.BytesIO()
                    with tarfile.open(fileobj=tar_stream, mode='w') as tar:
                        tar.add(cpg_path, arcname='cpg.bin')
                    tar_stream.seek(0)
                    
                    # Put tar archive into container
                    container.put_archive(container_cpg_dir, tar_stream)
                    logger.info(f"CPG copied to container: {container_cpg_path}")
                    
                    # Use container path for loading
                    cpg_path = container_cpg_path
                else:
                    raise RuntimeError(f"CPG file not found: {cpg_path}")

            # Allocate port
            port = await self.port_manager.allocate_port(codebase_hash)
            
            # Start joern server in background
            container = self.client.containers.get(self.container_id)
            
            # Command to start joern server
            # First load the CPG, then start the server
            start_cmd = f"""
nohup sh -c '
cd /playground && \\
joern --server --server-host 0.0.0.0 --server-port {port} \\
> /tmp/joern_server_{codebase_hash}.log 2>&1
' > /dev/null 2>&1 &
echo $!
"""
            
            logger.info(f"Starting Joern server for codebase {codebase_hash} on port {port}")
            result = container.exec_run(
                ["sh", "-c", start_cmd],
                detach=False
            )
            
            if result.exit_code == 0:
                process_id = result.output.decode('utf-8').strip()
                self.server_processes[codebase_hash] = process_id
                logger.info(f"Joern server started with PID {process_id} for codebase {codebase_hash}")
            else:
                logger.warning(f"Could not get PID for Joern server (codebase {codebase_hash})")
            
            # Wait a bit for server to start
            await asyncio.sleep(2)
            
            # Create client and verify server is running
            client = JoernServerClient(host="localhost", port=port)
            await client.initialize()
            
            # Wait for server to be ready (with timeout)
            max_retries = 10
            for i in range(max_retries):
                if await client.health_check():
                    logger.info(f"Joern server is ready on port {port}")
                    break
                logger.debug(f"Waiting for Joern server to be ready... ({i+1}/{max_retries})")
                await asyncio.sleep(1)
            else:
                raise RuntimeError(f"Joern server failed to start on port {port}")
            
            self.joern_clients[codebase_hash] = client
            
            # Load CPG if provided
            if cpg_path:
                logger.info(f"Loading CPG {cpg_path} for codebase {codebase_hash}")
                await self._load_cpg_in_server(codebase_hash, cpg_path)
            
            return port

        except Exception as e:
            logger.error(f"Failed to start Joern server for codebase {codebase_hash}: {e}")
            # Cleanup on failure
            await self.port_manager.release_port(codebase_hash)
            if codebase_hash in self.joern_clients:
                del self.joern_clients[codebase_hash]
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
            
            # Kill server process
            if codebase_hash in self.server_processes:
                process_id = self.server_processes[codebase_hash]
                container = self.client.containers.get(self.container_id)
                
                # Try to kill the process gracefully
                container.exec_run(["kill", process_id])
                logger.info(f"Killed Joern server process {process_id} for codebase {codebase_hash}")
                
                del self.server_processes[codebase_hash]
            
            # Release port
            await self.port_manager.release_port(codebase_hash)
            
            logger.info(f"Stopped Joern server for codebase {codebase_hash}")

        except Exception as e:
            logger.error(f"Failed to stop Joern server for codebase {codebase_hash}: {e}")

    async def stop_container(self, container_id: str):
        """Stop and remove a Docker container (kept for compatibility, no-op now)"""
        logger.info(f"stop_container called with {container_id} (no-op in new architecture)")

    async def cleanup(self):
        """Cleanup all Joern servers and the main container"""
        try:
            # Stop all Joern servers
            codebases = list(self.joern_clients.keys())
            for codebase_hash in codebases:
                await self.stop_joern_server(codebase_hash)
            
            # Stop main container
            if self.container_id and self.client:
                try:
                    container = self.client.containers.get(self.container_id)
                    container.stop(timeout=10)
                    container.remove()
                    logger.info(f"Stopped and removed main container {self.container_id}")
                except docker.errors.NotFound:
                    logger.warning("Main container not found, may already be removed")
                except Exception as e:
                    logger.error(f"Failed to stop main container: {e}")

        except Exception as e:
            logger.error(f"Error during Docker cleanup: {e}")
