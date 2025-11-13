"""
HTTP client for communicating with Joern server using cpgqls-client-python
"""

import logging
from typing import Optional

from cpgqls_client import CPGQLSClient

from ..exceptions import QueryExecutionError
from ..models import QueryResult

logger = logging.getLogger(__name__)


class JoernHTTPClient:
    """HTTP client for Joern server communication using cpgqls-client-python"""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        timeout: int = 30,
        auth_credentials: Optional[tuple] = None,
    ):
        """
        Initialize Joern HTTP client using cpgqls-client-python

        Args:
            host: Joern HTTP server host (default: 127.0.0.1)
            port: Joern HTTP server port (default: 8080)
            timeout: Request timeout in seconds (default: 30)
            auth_credentials: Optional tuple of (username, password) for basic auth
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.auth_credentials = auth_credentials
        self.server_endpoint = f"{host}:{port}"
        self.client: Optional[CPGQLSClient] = None

    async def initialize(self):
        """Initialize cpgqls-client-python client"""
        try:
            self.client = CPGQLSClient(
                self.server_endpoint,
                auth_credentials=self.auth_credentials
            )
            logger.info(f"JoernHTTPClient initialized: {self.server_endpoint}")
        except Exception as e:
            logger.error(f"Failed to initialize cpgqls-client: {e}")
            raise QueryExecutionError(f"Client initialization failed: {str(e)}")

    async def execute_query(
        self, query: str, timeout: Optional[int] = None
    ) -> str:
        """
        Execute a CPGQL query against Joern server

        Args:
            query: CPGQL query string
            timeout: Optional timeout in seconds (not used with cpgqls-client)

        Returns:
            Raw stdout string from Joern server

        Raises:
            QueryExecutionError: If query execution fails
        """
        if not self.client:
            raise QueryExecutionError("Client not initialized")

        try:
            result = self.client.execute(query)
            
            if result is None:
                raise QueryExecutionError("Query returned None")
            
            # Extract stdout from result
            stdout = result.get("stdout", "")
            
            logger.debug(f"Query executed successfully, got output length: {len(stdout)}")
            return stdout

        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            raise QueryExecutionError(f"Query execution failed: {str(e)}")

    async def parse_response(
        self, stdout: str
    ) -> QueryResult:
        """
        Parse Joern query output into QueryResult

        Args:
            stdout: Raw stdout string from Joern

        Returns:
            QueryResult object with plain text output

        Raises:
            QueryExecutionError: If parsing fails
        """
        try:
            # Simply return the raw stdout as data
            # Split by lines for row count
            lines = stdout.strip().split('\n') if stdout.strip() else []
            row_count = len(lines) if lines and lines[0] else 0

            return QueryResult(
                success=True,
                data=[{"output": stdout}],  # Store raw output
                row_count=row_count,
                execution_time=0,
            )
        except Exception as e:
            logger.error(f"Failed to parse query response: {e}")
            raise QueryExecutionError(f"Failed to parse query response: {str(e)}")

    async def cleanup(self):
        """Clean up client resources"""
        if self.client:
            self.client = None
            logger.debug("JoernHTTPClient cleaned up")

    async def __aenter__(self):
        """Async context manager entry"""
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.cleanup()
