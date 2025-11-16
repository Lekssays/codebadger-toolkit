"""
Joern Server Manager for spawning and managing individual Joern server instances per CPG
"""

import asyncio
import logging
import subprocess
import time
from typing import Dict, Optional

from .port_manager import PortManager

logger = logging.getLogger(__name__)


class JoernServerManager:
    """Manages individual Joern server instances, one per CPG"""

    def __init__(self, joern_binary_path: str = "joern"):
        self.joern_binary = joern_binary_path
        self.port_manager = PortManager()
        self._processes: Dict[str, subprocess.Popen] = {}  # codebase_hash -> process
        self._ports: Dict[str, int] = {}  # codebase_hash -> port

    def spawn_server(self, codebase_hash: str) -> int:
        """
        Spawn a new Joern server instance for the given codebase

        Args:
            codebase_hash: The codebase identifier

        Returns:
            Port number where the server is running
        """
        try:
            # Check if server already exists
            if codebase_hash in self._ports:
                port = self._ports[codebase_hash]
                logger.info(f"Joern server for {codebase_hash} already running on port {port}")
                return port

            # Allocate a port
            port = self.port_manager.allocate_port(codebase_hash)

            # Start Joern server process
            cmd = [
                self.joern_binary,
                "--server",
                "--server-host", "0.0.0.0",
                "--server-port", str(port)
            ]

            logger.info(f"Starting Joern server for {codebase_hash} on port {port}")
            logger.info(f"Command: {' '.join(cmd)}")

            # Start the process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            self._processes[codebase_hash] = process
            self._ports[codebase_hash] = port

            # Wait for server to start
            if self._wait_for_server(port, timeout=30):
                logger.info(f"Joern server for {codebase_hash} started successfully on port {port}")
                return port
            else:
                # Cleanup on failure
                self._cleanup_server(codebase_hash)
                raise RuntimeError(f"Joern server for {codebase_hash} failed to start on port {port}")

        except Exception as e:
            logger.error(f"Failed to spawn Joern server for {codebase_hash}: {e}")
            self._cleanup_server(codebase_hash)
            raise

    def load_cpg(self, codebase_hash: str, cpg_path: str, timeout: int = 120) -> bool:
        """
        Load a CPG into the Joern server for the given codebase

        Args:
            codebase_hash: The codebase identifier
            cpg_path: Path to the CPG file
            timeout: Timeout for loading operation

        Returns:
            True if CPG was loaded successfully
        """
        try:
            if codebase_hash not in self._ports:
                raise RuntimeError(f"No Joern server running for codebase {codebase_hash}")

            port = self._ports[codebase_hash]

            # Use JoernServerClient to load the CPG
            from .joern_client import JoernServerClient
            client = JoernServerClient(host="localhost", port=port)

            logger.info(f"Loading CPG {cpg_path} into Joern server for {codebase_hash} (port {port})")
            success = client.load_cpg(cpg_path, timeout=timeout)

            if success:
                logger.info(f"CPG loaded successfully for {codebase_hash}")
            else:
                logger.error(f"Failed to load CPG for {codebase_hash}")

            return success

        except Exception as e:
            logger.error(f"Error loading CPG for {codebase_hash}: {e}")
            return False

    def get_server_port(self, codebase_hash: str) -> Optional[int]:
        """
        Get the port for the Joern server of the given codebase

        Args:
            codebase_hash: The codebase identifier

        Returns:
            Port number or None if no server is running
        """
        return self._ports.get(codebase_hash)

    def is_server_running(self, codebase_hash: str) -> bool:
        """
        Check if the Joern server for the given codebase is running

        Args:
            codebase_hash: The codebase identifier

        Returns:
            True if server is running
        """
        if codebase_hash not in self._processes:
            return False

        process = self._processes[codebase_hash]
        return process.poll() is None

    def terminate_server(self, codebase_hash: str) -> bool:
        """
        Terminate the Joern server for the given codebase

        Args:
            codebase_hash: The codebase identifier

        Returns:
            True if server was terminated successfully
        """
        try:
            if codebase_hash not in self._processes:
                logger.warning(f"No process found for codebase {codebase_hash}")
                return False

            process = self._processes[codebase_hash]
            port = self._ports.get(codebase_hash)

            logger.info(f"Terminating Joern server for {codebase_hash} on port {port}")

            # Terminate the process
            process.terminate()

            # Wait for process to end
            try:
                process.wait(timeout=10)
                logger.info(f"Joern server for {codebase_hash} terminated")
            except subprocess.TimeoutExpired:
                logger.warning(f"Joern server for {codebase_hash} didn't terminate gracefully, killing")
                process.kill()
                process.wait()

            # Cleanup
            self._cleanup_server(codebase_hash)
            return True

        except Exception as e:
            logger.error(f"Error terminating Joern server for {codebase_hash}: {e}")
            return False

    def terminate_all_servers(self) -> None:
        """Terminate all running Joern servers"""
        logger.info("Terminating all Joern servers")
        codebases = list(self._processes.keys())
        for codebase_hash in codebases:
            self.terminate_server(codebase_hash)
        logger.info("All Joern servers terminated")

    def get_running_servers(self) -> Dict[str, int]:
        """Get information about all running servers"""
        return {
            codebase_hash: port
            for codebase_hash, port in self._ports.items()
            if self.is_server_running(codebase_hash)
        }

    def _wait_for_server(self, port: int, timeout: int = 30) -> bool:
        """Wait for Joern server to be ready on the given port"""
        import socket

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # Try to connect to the port
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('localhost', port))
                sock.close()

                if result == 0:
                    # Also try a simple health check via HTTP
                    try:
                        import requests
                        response = requests.get(f"http://localhost:{port}", timeout=2)
                        if response.status_code == 200:
                            return True
                    except:
                        pass

                    # If basic connection works, assume server is ready
                    return True

            except Exception:
                pass

            time.sleep(1)

        return False

    def _cleanup_server(self, codebase_hash: str) -> None:
        """Clean up server resources"""
        if codebase_hash in self._processes:
            del self._processes[codebase_hash]
        if codebase_hash in self._ports:
            port = self._ports[codebase_hash]
            self.port_manager.release_port(codebase_hash)
            del self._ports[codebase_hash]
            logger.debug(f"Cleaned up resources for {codebase_hash} (port {port})")