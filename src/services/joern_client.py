"""
HTTP client for communicating with Joern server API
"""

import asyncio
import json
import logging
import time
from typing import Dict, Optional, Any

import aiohttp

logger = logging.getLogger(__name__)


class JoernServerClient:
    """Client for Joern server HTTP API"""

    def __init__(self, host: str = "localhost", port: int = 8080):
        """
        Initialize Joern server client
        
        Args:
            host: Server hostname
            port: Server port
        """
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"
        self._session: Optional[aiohttp.ClientSession] = None

    async def initialize(self):
        """Initialize the HTTP client session"""
        if not self._session:
            self._session = aiohttp.ClientSession()
            logger.info(f"Initialized Joern server client for {self.base_url}")

    async def close(self):
        """Close the HTTP client session"""
        if self._session:
            await self._session.close()
            self._session = None
            logger.info("Closed Joern server client")

    async def submit_query(self, query: str) -> str:
        """
        Submit a query to the Joern server
        
        Args:
            query: The CPGQL query to execute
            
        Returns:
            UUID of the query for retrieving results
        """
        if not self._session:
            await self.initialize()

        try:
            url = f"{self.base_url}/query"
            payload = {"query": query}
            
            logger.debug(f"Submitting query to {url}: {query[:100]}...")
            
            async with self._session.post(url, json=payload) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"Query submission failed: {response.status} - {error_text}")
                
                result = await response.json()
                query_uuid = result.get("uuid")
                
                if not query_uuid:
                    raise Exception("Server did not return a query UUID")
                
                logger.info(f"Query submitted successfully, UUID: {query_uuid}")
                return query_uuid
                
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error submitting query: {e}")
            raise Exception(f"Failed to submit query: {str(e)}")
        except Exception as e:
            logger.error(f"Error submitting query: {e}")
            raise

    async def get_result(self, query_uuid: str) -> Dict[str, Any]:
        """
        Get the result of a query by UUID
        
        Args:
            query_uuid: UUID of the query
            
        Returns:
            Dictionary with keys: success (bool), stdout (str), stderr (str)
        """
        if not self._session:
            await self.initialize()

        try:
            url = f"{self.base_url}/result/{query_uuid}"
            
            logger.debug(f"Fetching result for query {query_uuid}")
            
            async with self._session.get(url) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"Result fetch failed: {response.status} - {error_text}")
                
                result = await response.json()
                
                logger.debug(f"Query {query_uuid} result: success={result.get('success')}")
                return result
                
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error fetching result: {e}")
            raise Exception(f"Failed to fetch result: {str(e)}")
        except Exception as e:
            logger.error(f"Error fetching result: {e}")
            raise

    async def execute_query(
        self,
        query: str,
        timeout: int = 60,
        poll_interval: float = 0.5
    ) -> Dict[str, Any]:
        """
        Execute a query and wait for the result
        
        Args:
            query: The CPGQL query to execute
            timeout: Maximum time to wait for result (seconds)
            poll_interval: Time between polling attempts (seconds)
            
        Returns:
            Dictionary with keys: success (bool), stdout (str), stderr (str)
        """
        start_time = time.time()
        
        # Submit query
        query_uuid = await self.submit_query(query)
        
        # Poll for result
        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout:
                raise TimeoutError(f"Query {query_uuid} timed out after {timeout}s")
            
            # Get result
            result = await self.get_result(query_uuid)
            
            # Check if query is complete
            success = result.get("success")
            if success == "true" or success is True:
                logger.info(f"Query {query_uuid} completed successfully")
                return result
            elif success == "false" or success is False:
                # Query completed with error
                logger.error(f"Query {query_uuid} failed: {result.get('stderr', 'Unknown error')}")
                return result
            
            # Result not ready yet, wait and retry
            await asyncio.sleep(poll_interval)

    async def health_check(self) -> bool:
        """
        Check if the Joern server is healthy
        
        Returns:
            True if server is responding, False otherwise
        """
        if not self._session:
            await self.initialize()

        try:
            # Try to query the root endpoint or a simple query
            url = self.base_url
            async with self._session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                return response.status == 200
        except Exception as e:
            logger.warning(f"Joern server health check failed: {e}")
            return False

    def __del__(self):
        """Cleanup on deletion"""
        if self._session and not self._session.closed:
            try:
                # Try to close session gracefully
                asyncio.get_event_loop().create_task(self.close())
            except Exception:
                pass
