"""
Tests for MCP tools
"""

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from src.models import CodebaseInfo, Config, QueryResult
from src.services.codebase_tracker import CodebaseTracker
from src.services.cpg_generator import CPGGenerator
from src.services.git_manager import GitManager
from src.tools.mcp_tools import register_tools


class FakeMCP:
    """Fake MCP class for testing"""

    def __init__(self):
        self.registered = {}

    def tool(self):
        """Decorator to register tool functions"""
        def _decorator(func):
            self.registered[func.__name__] = func
            return func
        return _decorator


@pytest.fixture
def mock_services():
    """Create mock services for testing"""
    # Mock git manager
    git_manager = MagicMock(spec=GitManager)

    # Mock CPG generator
    cpg_generator = MagicMock(spec=CPGGenerator)

    # Mock codebase tracker
    codebase_tracker = MagicMock(spec=CodebaseTracker)
    codebase_tracker.save_codebase.return_value = CodebaseInfo(
        codebase_hash="553642871dd4251d",
        source_type="github",
        source_path="https://github.com/test/repo",
        language="c",
        cpg_path="/tmp/test.cpg"
    )
    codebase_tracker.get_codebase.return_value = CodebaseInfo(
        codebase_hash="553642871dd4251d",
        source_type="github",
        source_path="https://github.com/test/repo",
        language="c",
        cpg_path="/tmp/test.cpg"
    )

    # Mock query executor
    query_executor = MagicMock()
    query_executor.execute_query.return_value = QueryResult(
        success=True,
        data=[{"_1": "main", "_2": "function", "_3": "void main()", "_4": "main.c", "_5": 1}],
        row_count=1
    )

    # Mock config
    config = Config()

    return {
        "git_manager": git_manager,
        "cpg_generator": cpg_generator,
        "codebase_tracker": codebase_tracker,
        "query_executor": query_executor,
        "config": config,
    }


@pytest.fixture
def temp_workspace():
    """Create a temporary workspace directory"""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create playground structure
        playground = os.path.join(temp_dir, "playground")
        os.makedirs(os.path.join(playground, "cpgs", "test1234567890123456"))
        os.makedirs(os.path.join(playground, "codebases", "test1234567890123456"))

        # Create a fake CPG file
        cpg_path = os.path.join(playground, "cpgs", "test1234567890123456", "cpg.bin")
        with open(cpg_path, "w") as f:
            f.write("fake cpg")

        yield temp_dir


class TestMCPTools:
    """Test MCP tools functionality"""

    def test_generate_cpg_github_success(self, mock_services, temp_workspace):
        """Test successful CPG generation from GitHub"""
        with patch("src.tools.core_tools.os.path.abspath", return_value=temp_workspace), \
             patch("src.tools.core_tools.os.path.dirname", return_value=temp_workspace), \
             patch("src.tools.core_tools.os.path.join", side_effect=os.path.join):

            mcp = FakeMCP()
            register_tools(mcp, mock_services)

            func = mcp.registered.get("generate_cpg")
            assert func is not None

            # Mock the git clone and CPG generation
            mock_services["git_manager"].clone_repository.return_value = None
            # Return a valid CPG path and optional joern_port
            mock_services["cpg_generator"].generate_cpg.return_value = ("/tmp/test.cpg", None)

            # Call the tool
            result = func(
                source_type="github",
                source_path="https://github.com/test/repo",
                language="c"
            )

            assert result["codebase_hash"] == "553642871dd4251d"
            assert result["status"] in ["ready", "cached"]
            assert "cpg_path" in result

    def test_generate_cpg_cached(self, mock_services, temp_workspace):
        """Test CPG generation when CPG already exists"""
        with patch("src.tools.core_tools.os.path.abspath", return_value=temp_workspace), \
             patch("src.tools.core_tools.os.path.dirname", return_value=temp_workspace), \
             patch("src.tools.core_tools.os.path.join", side_effect=os.path.join), \
             patch("src.tools.core_tools.os.path.exists", return_value=True):

            mcp = FakeMCP()
            register_tools(mcp, mock_services)

            func = mcp.registered.get("generate_cpg")
            assert func is not None

            # Call the tool
            result = func(
                source_type="github",
                source_path="https://github.com/test/repo",
                language="c"
            )

            assert result["status"] == "cached"
            assert "cpg_path" in result

    def test_get_cpg_status_exists(self, mock_services):
        """Test getting CPG status when CPG exists"""
        mcp = FakeMCP()
        register_tools(mcp, mock_services)

        func = mcp.registered.get("get_cpg_status")
        assert func is not None

        with patch("os.path.exists", return_value=True):
            result = func(codebase_hash="553642871dd4251d")

        assert result["codebase_hash"] == "553642871dd4251d"
        assert result["exists"] is True
        assert "cpg_path" in result

    def test_get_cpg_status_not_found(self, mock_services):
        """Test getting CPG status when CPG doesn't exist"""
        mock_services["codebase_tracker"].get_codebase.return_value = None

        mcp = FakeMCP()
        register_tools(mcp, mock_services)

        func = mcp.registered.get("get_cpg_status")
        assert func is not None

        result = func(codebase_hash="nonexistent")

        assert result["exists"] is False
        assert result["status"] == "not_found"

    def test_list_methods_success(self, mock_services):
        """Test listing methods successfully"""
        mcp = FakeMCP()
        register_tools(mcp, mock_services)

        func = mcp.registered.get("list_methods")
        assert func is not None

        result = func(codebase_hash="553642871dd4251d")

        assert result["success"] is True
        assert "methods" in result
        assert isinstance(result["methods"], list)

    def test_run_cpgql_query_success(self, mock_services):
        """Test running CPGQL query successfully"""
        mcp = FakeMCP()
        register_tools(mcp, mock_services)

        func = mcp.registered.get("run_cpgql_query")
        assert func is not None

        result = func(codebase_hash="553642871dd4251d", query="cpg.method")

        assert result["success"] is True
        assert "data" in result
        assert "row_count" in result

    def test_run_cpgql_query_invalid(self, mock_services):
        """Test running invalid CPGQL query"""
        mock_services["query_executor"].execute_query.return_value = QueryResult(
            success=False,
            error="Invalid query syntax"
        )

        mcp = FakeMCP()
        register_tools(mcp, mock_services)

        func = mcp.registered.get("run_cpgql_query")
        assert func is not None

        result = func(codebase_hash="553642871dd4251d", query="invalid query")

        assert result["success"] is False
        assert "error" in result

    def test_get_codebase_summary_success(self, mock_services):
        """Test getting codebase summary successfully"""
        # Mock the metadata query
        meta_result = QueryResult(
            success=True,
            data=[{"_1": "c", "_2": "1.0"}],
            row_count=1
        )

        # Mock the stats query
        stats_result = QueryResult(
            success=True,
            data=[{"_1": 5, "_2": 10, "_3": 8, "_4": 15, "_5": 20}],
            row_count=1
        )

        # Configure mock to return different results for different queries
        call_count = 0
        def mock_execute(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            query = kwargs.get('query', '')
            if 'm.language' in query:
                return meta_result
            else:
                return stats_result

        mock_services["query_executor"].execute_query.side_effect = mock_execute

        mcp = FakeMCP()
        register_tools(mcp, mock_services)

        func = mcp.registered.get("get_codebase_summary")
        assert func is not None

        result = func(codebase_hash="553642871dd4251d")

        assert result["success"] is True
        assert "summary" in result
        assert result["summary"]["language"] == "c"
        assert result["summary"]["total_files"] == 5
        assert result["summary"]["total_methods"] == 10
