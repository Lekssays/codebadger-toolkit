"""
Query executor for running CPGQL queries against Joern server using cpgqls-client-python
"""

import asyncio
import logging
import time
import uuid
from enum import Enum
from typing import Any, Dict, Optional

from ..exceptions import QueryExecutionError
from ..models import JoernConfig, QueryConfig, QueryResult
from ..utils.http_client import JoernHTTPClient
from ..utils.redis_client import RedisClient
from ..utils.validators import hash_query, validate_cpgql_query

logger = logging.getLogger(__name__)


class QueryStatus(str, Enum):
    """Query execution status"""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class QueryExecutor:
    """Executes CPGQL queries using Joern server via cpgqls-client-python"""

    def __init__(
        self,
        config: QueryConfig,
        joern_config: JoernConfig,
        redis_client: Optional[RedisClient] = None,
        cpg_generator=None,
    ):
        self.config = config
        self.joern_config = joern_config
        self.redis = redis_client
        self.cpg_generator = cpg_generator
        self.http_client: Optional[JoernHTTPClient] = None
        self.query_status: Dict[str, Dict[str, Any]] = {}  # query_id -> status info

    async def initialize(self):
        """Initialize HTTP client for Joern communication"""
        try:
            self.http_client = JoernHTTPClient(
                host=self.joern_config.http_host,
                port=self.joern_config.http_port,
                timeout=self.config.timeout,
            )
            await self.http_client.initialize()
            logger.info("QueryExecutor initialized with cpgqls-client")
        except Exception as e:
            logger.error(f"Failed to initialize HTTP client: {e}")
            raise QueryExecutionError(f"HTTP client initialization failed: {str(e)}")

    def set_cpg_generator(self, cpg_generator):
        """Set reference to CPG generator"""
        self.cpg_generator = cpg_generator

    async def execute_query_async(
        self,
        session_id: str,
        query: str,
        timeout: Optional[int] = None,
    ) -> str:
        """Execute a CPGQL query asynchronously and return query UUID"""
        try:
            # Generate unique query ID
            query_id = str(uuid.uuid4())

            # Validate query
            validate_cpgql_query(query)

            # Initialize query status
            self.query_status[query_id] = {
                "status": QueryStatus.PENDING.value,
                "session_id": session_id,
                "query": query,
                "created_at": time.time(),
                "error": None,
            }

            # Start async execution
            asyncio.create_task(
                self._execute_query_background(query_id, session_id, query, timeout)
            )

            logger.info(f"Started async query {query_id} for session {session_id}")
            return query_id

        except Exception as e:
            logger.error(f"Failed to start async query: {e}")
            raise QueryExecutionError(f"Query initialization failed: {str(e)}")

    async def _execute_query_background(
        self,
        query_id: str,
        session_id: str,
        query: str,
        timeout: Optional[int],
    ):
        """Execute query in background"""
        try:
            # Update status to running
            self.query_status[query_id]["status"] = QueryStatus.RUNNING.value
            self.query_status[query_id]["started_at"] = time.time()

            # Check cache if enabled
            if self.config.cache_enabled and self.redis:
                query_hash_val = hash_query(query)
                cached = await self.redis.get_cached_query(session_id, query_hash_val)
                if cached:
                    logger.info(f"Query cache hit for session {session_id}")
                    self.query_status[query_id]["status"] = QueryStatus.COMPLETED.value
                    self.query_status[query_id]["completed_at"] = time.time()
                    self.query_status[query_id]["result"] = cached
                    return

            # Execute query via HTTP
            result = await self._execute_query_via_http(query, timeout)

            if result.success:
                # Update status to completed
                self.query_status[query_id]["status"] = QueryStatus.COMPLETED.value
                self.query_status[query_id]["completed_at"] = time.time()
                self.query_status[query_id]["result"] = result.to_dict()

                # Cache result if enabled
                if self.config.cache_enabled and self.redis:
                    query_hash_val = hash_query(query)
                    await self.redis.cache_query_result(
                        session_id,
                        query_hash_val,
                        result.to_dict(),
                        self.config.cache_ttl,
                    )

                logger.info(f"Query {query_id} completed successfully")
            else:
                # Update status to failed
                self.query_status[query_id]["status"] = QueryStatus.FAILED.value
                self.query_status[query_id]["error"] = result.error
                self.query_status[query_id]["completed_at"] = time.time()
                logger.error(f"Query {query_id} failed: {result.error}")

        except Exception as e:
            self.query_status[query_id]["status"] = QueryStatus.FAILED.value
            self.query_status[query_id]["error"] = str(e)
            self.query_status[query_id]["completed_at"] = time.time()
            logger.error(f"Query {query_id} failed: {e}")

    async def get_query_status(self, query_id: str) -> Dict[str, Any]:
        """Get status of a query"""
        if query_id not in self.query_status:
            raise QueryExecutionError(f"Query {query_id} not found")

        status_info = self.query_status[query_id].copy()

        # Add execution time if completed
        if "completed_at" in status_info and "started_at" in status_info:
            status_info["execution_time"] = (
                status_info["completed_at"] - status_info["started_at"]
            )

        return status_info

    async def get_query_result(self, query_id: str) -> QueryResult:
        """Get result of a completed query"""
        if query_id not in self.query_status:
            raise QueryExecutionError(f"Query {query_id} not found")

        status_info = self.query_status[query_id]

        if status_info["status"] == QueryStatus.FAILED.value:
            return QueryResult(
                success=False,
                error=status_info.get("error", "Query failed"),
                execution_time=status_info.get("execution_time", 0),
            )

        if status_info["status"] != QueryStatus.COMPLETED.value:
            raise QueryExecutionError(
                f"Query {query_id} is not completed yet "
                f"(status: {status_info['status']})"
            )

        # Return the stored result
        if "result" in status_info:
            return QueryResult(**status_info["result"])
        else:
            execution_time = status_info.get("execution_time", 0)
            return QueryResult(
                success=True, data=[], row_count=0, execution_time=execution_time
            )

    async def execute_query(
        self,
        session_id: str,
        cpg_path: str,
        query: str,
        timeout: Optional[int] = None,
    ) -> QueryResult:
        """Execute a CPGQL query synchronously (for backwards compatibility)"""
        start_time = time.time()

        try:
            # Validate query
            validate_cpgql_query(query)

            # Check cache if enabled
            if self.config.cache_enabled and self.redis:
                query_hash_val = hash_query(query)
                cached = await self.redis.get_cached_query(session_id, query_hash_val)
                if cached:
                    logger.info(f"Query cache hit for session {session_id}")
                    cached["execution_time"] = time.time() - start_time
                    return QueryResult(**cached)

            # Execute query via HTTP
            timeout_val = timeout or self.config.timeout
            result = await self._execute_query_via_http(query, timeout_val)
            result.execution_time = time.time() - start_time

            # Cache result if enabled
            if self.config.cache_enabled and self.redis and result.success:
                query_hash_val = hash_query(query)
                await self.redis.cache_query_result(
                    session_id, query_hash_val, result.to_dict(), self.config.cache_ttl
                )

            logger.info(
                f"Query executed for session {session_id}: "
                f"{result.row_count} rows in {result.execution_time:.2f}s"
            )

            return result

        except QueryExecutionError as e:
            logger.error(f"Query execution error: {e}")
            return QueryResult(
                success=False, error=str(e), execution_time=time.time() - start_time
            )
        except Exception as e:
            logger.error(f"Unexpected error executing query: {e}")
            logger.exception(e)
            return QueryResult(
                success=False,
                error=f"Query execution failed: {str(e)}",
                execution_time=time.time() - start_time,
            )

    async def _execute_query_via_http(
        self, query: str, timeout: Optional[int] = None
    ) -> QueryResult:
        """Execute query via Joern server"""
        if not self.http_client:
            raise QueryExecutionError("HTTP client not initialized")

        try:
            start_time = time.time()
            timeout_val = timeout or self.config.timeout

            # Execute query via cpgqls-client
            stdout = await self.http_client.execute_query(query, timeout_val)

            # Parse response into QueryResult
            result = await self.http_client.parse_response(stdout)
            result.execution_time = time.time() - start_time

            logger.debug(
                f"Query executed via HTTP: {result.row_count} rows in {result.execution_time:.2f}s"
            )
            return result

        except QueryExecutionError:
            raise
        except Exception as e:
            logger.error(f"HTTP query execution failed: {e}")
            raise QueryExecutionError(f"Query execution failed: {str(e)}")

    async def list_queries(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """List all queries or queries for a specific session"""
        if session_id:
            return {
                query_id: status_info
                for query_id, status_info in self.query_status.items()
                if status_info["session_id"] == session_id
            }
        else:
            return self.query_status.copy()

    async def cleanup_query(self, query_id: str):
        """Clean up query resources"""
        if query_id in self.query_status:
            del self.query_status[query_id]
            logger.info(f"Cleaned up query {query_id}")

    async def cleanup_old_queries(self, max_age_seconds: int = 3600):
        """Clean up old completed queries"""
        current_time = time.time()
        to_cleanup = []

        for query_id, status_info in self.query_status.items():
            if status_info["status"] in [
                QueryStatus.COMPLETED.value,
                QueryStatus.FAILED.value,
            ]:
                age = current_time - status_info.get(
                    "completed_at", status_info["created_at"]
                )
                if age > max_age_seconds:
                    to_cleanup.append(query_id)

        for query_id in to_cleanup:
            await self.cleanup_query(query_id)

        if to_cleanup:
            logger.info(f"Cleaned up {len(to_cleanup)} old queries")

    async def cleanup(self):
        """Clean up resources"""
        if self.http_client:
            await self.http_client.cleanup()
            self.http_client = None
        logger.info("QueryExecutor cleaned up")
