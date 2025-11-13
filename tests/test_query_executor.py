"""
Tests for HTTP-based query executor
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.exceptions import QueryExecutionError
from src.models import JoernConfig, QueryConfig, QueryResult
from src.services.query_executor import QueryExecutor, QueryStatus
from src.utils.redis_client import RedisClient


class TestQueryExecutor:
    """Test query executor functionality"""

    @pytest.fixture
    def query_config(self):
        """Query configuration fixture"""
        return QueryConfig(timeout=30, cache_enabled=True, cache_ttl=300)

    @pytest.fixture
    def joern_config(self):
        """Joern configuration fixture"""
        return JoernConfig(http_host="127.0.0.1", http_port=8080)

    @pytest.fixture
    def mock_redis_client(self):
        """Mock Redis client fixture"""
        mock_client = AsyncMock(spec=RedisClient)
        mock_client.get_cached_query = AsyncMock(return_value=None)
        return mock_client

    @pytest.fixture
    async def query_executor(self, query_config, joern_config, mock_redis_client):
        """Query executor fixture"""
        executor = QueryExecutor(query_config, joern_config, mock_redis_client)
        
        # Mock the HTTP client
        executor.http_client = AsyncMock()
        executor.http_client.execute_query = AsyncMock(
            return_value=""  # cpgqls-client returns raw stdout as string
        )
        executor.http_client.parse_response = AsyncMock(
            return_value=QueryResult(
                success=True,
                data=[{"output": ""}],
                row_count=0,
                execution_time=0.5
            )
        )
        executor.http_client.cleanup = AsyncMock()
        
        return executor


    @pytest.mark.asyncio
    async def test_execute_query_success(self, query_executor):
        """Test successful query execution via HTTP"""
        result = await query_executor.execute_query(
            session_id="test-session",
            cpg_path="/playground/cpgs/test-session/cpg.bin",
            query="cpg.method",
            timeout=30,
        )

        assert result.success is True
        assert result.data == [{"output": ""}]
        assert result.row_count == 0
        
        # Verify HTTP client was called
        query_executor.http_client.execute_query.assert_called_once()
        query_executor.http_client.parse_response.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_query_async(self, query_executor):
        """Test asynchronous query execution"""
        query_id = await query_executor.execute_query_async(
            session_id="test-session",
            query="cpg.method",
        )

        assert query_id is not None
        assert isinstance(query_id, str)
        
        # Wait a bit for async task to start
        await asyncio.sleep(0.1)
        
        # Verify status tracking
        assert query_id in query_executor.query_status

    @pytest.mark.asyncio
    async def test_get_query_status_pending(self, query_executor):
        """Test getting status of pending query"""
        query_id = await query_executor.execute_query_async(
            session_id="test-session",
            query="cpg.method",
        )

        status = await query_executor.get_query_status(query_id)
        
        assert status["session_id"] == "test-session"
        assert "status" in status
        assert "created_at" in status

    @pytest.mark.asyncio
    async def test_get_query_result_not_found(self, query_executor):
        """Test getting result of non-existent query"""
        with pytest.raises(QueryExecutionError) as exc_info:
            await query_executor.get_query_result("non-existent-query")
        
        assert "not found" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_list_queries(self, query_executor):
        """Test listing queries"""
        query_id_1 = await query_executor.execute_query_async(
            session_id="session-1",
            query="cpg.method",
        )
        query_id_2 = await query_executor.execute_query_async(
            session_id="session-2",
            query="cpg.method",
        )

        # List all queries
        all_queries = await query_executor.list_queries()
        assert len(all_queries) >= 2

        # List queries for specific session
        session_1_queries = await query_executor.list_queries("session-1")
        assert all(q["session_id"] == "session-1" for q in session_1_queries.values())

    @pytest.mark.asyncio
    async def test_cleanup_query(self, query_executor):
        """Test query cleanup"""
        query_id = await query_executor.execute_query_async(
            session_id="test-session",
            query="cpg.method",
        )

        await query_executor.cleanup_query(query_id)
        
        # Query should no longer be in tracking
        assert query_id not in query_executor.query_status

    @pytest.mark.asyncio
    async def test_cleanup_old_queries(self, query_executor):
        """Test cleanup of old queries"""
        # Create a query
        query_id = await query_executor.execute_query_async(
            session_id="test-session",
            query="cpg.method",
        )

        # Manually mark it as completed long ago
        query_executor.query_status[query_id]["status"] = QueryStatus.COMPLETED.value
        query_executor.query_status[query_id]["completed_at"] = 0  # Long ago

        # Clean up old queries (older than 1 hour)
        await query_executor.cleanup_old_queries(max_age_seconds=3600)

        # Query should be removed
        assert query_id not in query_executor.query_status

    @pytest.mark.asyncio
    async def test_cleanup_executor(self, query_executor):
        """Test executor cleanup"""
        # Store reference to the mock before cleanup
        mock_http_client = query_executor.http_client
        await query_executor.cleanup()
        
        # HTTP client cleanup should have been called
        mock_http_client.cleanup.assert_called_once()
        assert query_executor.http_client is None
