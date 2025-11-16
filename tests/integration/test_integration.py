"""
Integration Tests for CodeBadger Toolkit Server

These tests verify the complete workflow of the CodeBadger Toolkit MCP server
using the core.c test codebase.
"""

import asyncio
import json
import os
import pytest
import re
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from fastmcp import Client
except ImportError:
    pytest.skip("FastMCP not found. Install with: pip install fastmcp", allow_module_level=True)


class TestCodeBadgerIntegration:
    """Integration tests for CodeBadger Toolkit MCP server"""

    @pytest.fixture(scope="class")
    def event_loop(self):
        """Create an instance of the default event loop for the test class"""
        loop = asyncio.get_event_loop_policy().new_event_loop()
        yield loop
        loop.close()

    @pytest.fixture
    async def client(self):
        """FastMCP client fixture"""
        server_url = "http://localhost:4242/mcp"
        try:
            async with Client(server_url) as client_instance:
                # Test connectivity with timeout
                import asyncio
                await asyncio.wait_for(client_instance.ping(), timeout=5.0)
                yield client_instance
        except (asyncio.TimeoutError, Exception) as e:
            pytest.skip(f"Cannot connect to server at {server_url}: {e}")

    @pytest.fixture
    def codebase_path(self):
        """Path to the test codebase - use container path since server runs in Docker"""
        # Host path: playground/codebases/core -> Container path: /app/playground/codebases/core
        return "/app/playground/codebases/core"

    def extract_tool_result(self, result):
        """Extract dictionary data from CallToolResult"""
        if hasattr(result, 'content') and result.content:
            content_text = result.content[0].text
            try:
                parsed = json.loads(content_text)

                # Handle complex results that return Scala output with embedded JSON
                if isinstance(parsed, dict) and 'value' in parsed:
                    value = parsed['value']
                    if isinstance(value, str):
                        # Look for embedded JSON in the Scala output
                        json_match = re.search(r'val res\d+: String = ("\{.*\}")', value)
                        if json_match:
                            try:
                                # Extract the escaped JSON string and unescape it
                                escaped_json = json_match.group(1)
                                # Remove the surrounding quotes and unescape
                                json_str = escaped_json[1:-1]  # Remove quotes
                                json_str = json_str.replace('\\"', '"')  # Unescape quotes
                                json_str = json_str.replace('\\\\', '\\')  # Unescape backslashes
                                return json.loads(json_str)
                            except json.JSONDecodeError:
                                pass
                        # If no embedded JSON found, return the original parsed result
                        return parsed
                    else:
                        return parsed
                else:
                    return parsed
            except json.JSONDecodeError:
                return {"error": content_text}
        return {}

    @pytest.mark.asyncio
    @pytest.mark.timeout(10)
    async def test_server_connectivity(self, client):
        """Test that the server is responding"""
        await client.ping()

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    async def test_cpg_generation(self, client, codebase_path):
        """Test CPG generation for the test codebase"""
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })

        cpg_dict = self.extract_tool_result(result)
        assert "codebase_hash" in cpg_dict, f"No codebase_hash in response: {cpg_dict}"

        codebase_hash = cpg_dict["codebase_hash"]
        assert isinstance(codebase_hash, str), "codebase_hash should be a string"
        assert len(codebase_hash) == 16, "codebase_hash should be 16 characters"

        status = cpg_dict.get("status")
        assert status in ["generating", "cached"], f"Unexpected status: {status}"

        return codebase_hash

    @pytest.mark.asyncio
    @pytest.mark.timeout(60)
    async def test_cpg_status_wait(self, client, codebase_path):
        """Test waiting for CPG to be ready"""
        # First generate CPG
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        # Wait for CPG to be ready
        max_attempts = 30
        cpg_ready = False

        for attempt in range(max_attempts):
            await asyncio.sleep(2)

            status_result = await client.call_tool("get_cpg_status", {
                "codebase_hash": codebase_hash
            })

            status_dict = self.extract_tool_result(status_result)
            status = status_dict.get("status")
            exists = status_dict.get("exists", False)

            if status in ["ready", "cached"] and exists:
                cpg_ready = True
                break

        assert cpg_ready, f"CPG not ready after {max_attempts} attempts"

        # Verify CPG status response structure
        expected_fields = ["codebase_hash", "exists", "status", "cpg_path",
                         "source_type", "language", "created_at", "last_accessed"]
        for field in expected_fields:
            assert field in status_dict, f"Missing field: {field}"

        assert status_dict["source_type"] == "local"
        assert status_dict["language"] == "c"
        assert status_dict["exists"] is True

        return codebase_hash

    @pytest.mark.asyncio
    @pytest.mark.timeout(10)
    async def test_cpg_caching(self, client, codebase_path):
        """Test that CPG generation uses caching for repeated requests"""
        # Generate CPG twice for the same codebase
        result1 = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict1 = self.extract_tool_result(result1)

        result2 = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict2 = self.extract_tool_result(result2)

        # Should get the same hash
        assert cpg_dict1["codebase_hash"] == cpg_dict2["codebase_hash"]

        # Second call should be cached
        assert cpg_dict2["status"] == "cached"

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    async def test_list_methods(self, client, codebase_path):
        """Test listing methods in the codebase"""
        # Generate and wait for CPG
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        # Wait for ready
        for _ in range(30):
            await asyncio.sleep(1)
            status_result = await client.call_tool("get_cpg_status", {"codebase_hash": codebase_hash})
            if self.extract_tool_result(status_result).get("status") in ["ready", "cached"]:
                break

        # List methods
        methods_result = await client.call_tool("list_methods", {
            "codebase_hash": codebase_hash,
            "limit": 20
        })

        methods_dict = self.extract_tool_result(methods_result)
        assert methods_dict.get("success") is True, f"list_methods failed: {methods_dict}"

        methods = methods_dict.get("methods", [])
        total = methods_dict.get("total", 0)

        assert isinstance(methods, list), "methods should be a list"
        assert total >= 0, "total should be non-negative"
        assert len(methods) <= 20, "should not return more than limit"

        # Verify method structure
        if methods:
            method = methods[0]
            required_fields = ["node_id", "name"]
            for field in required_fields:
                assert field in method, f"Method missing field: {field}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    async def test_get_codebase_summary(self, client, codebase_path):
        """Test getting codebase summary"""
        # Generate and wait for CPG
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        # Wait for ready
        for _ in range(30):
            await asyncio.sleep(1)
            status_result = await client.call_tool("get_cpg_status", {"codebase_hash": codebase_hash})
            if self.extract_tool_result(status_result).get("status") in ["ready", "cached"]:
                break

        # Get summary
        summary_result = await client.call_tool("get_codebase_summary", {
            "codebase_hash": codebase_hash
        })

        summary_dict = self.extract_tool_result(summary_result)
        assert summary_dict.get("success") is True, f"Summary failed: {summary_dict}"

        summary = summary_dict.get("summary", {})
        assert isinstance(summary, dict), "summary should be a dict"

        # Check expected fields
        expected_fields = ["language", "total_files", "total_methods", "total_calls"]
        for field in expected_fields:
            assert field in summary, f"Summary missing field: {field}"

        assert summary["language"] in ["c", "unknown"], f"Unexpected language: {summary['language']}"
        assert summary["total_files"] >= 1
        assert summary["total_methods"] >= 0
        assert summary["total_calls"] >= 0

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    async def test_find_taint_sources(self, client, codebase_path):
        """Test finding taint sources"""
        # Generate and wait for CPG
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        # Wait for ready
        for _ in range(30):
            await asyncio.sleep(1)
            status_result = await client.call_tool("get_cpg_status", {"codebase_hash": codebase_hash})
            if self.extract_tool_result(status_result).get("status") in ["ready", "cached"]:
                break

        # Find taint sources
        sources_result = await client.call_tool("find_taint_sources", {
            "codebase_hash": codebase_hash,
            "language": "c"
        })

        sources_dict = self.extract_tool_result(sources_result)
        assert sources_dict.get("success") is True, f"Find sources failed: {sources_dict}"

        sources = sources_dict.get("sources", [])
        total = sources_dict.get("total", 0)

        assert isinstance(sources, list), "sources should be a list"
        assert total >= 0, "total should be non-negative"

        # Verify source structure
        if sources:
            source = sources[0]
            required_fields = ["node_id", "name", "code", "filename", "lineNumber", "method"]
            for field in required_fields:
                assert field in source, f"Source missing field: {field}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    async def test_find_taint_sinks(self, client, codebase_path):
        """Test finding taint sinks"""
        # Generate and wait for CPG
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        # Wait for ready
        for _ in range(30):
            await asyncio.sleep(1)
            status_result = await client.call_tool("get_cpg_status", {"codebase_hash": codebase_hash})
            if self.extract_tool_result(status_result).get("status") in ["ready", "cached"]:
                break

        # Find taint sinks
        sinks_result = await client.call_tool("find_taint_sinks", {
            "codebase_hash": codebase_hash,
            "language": "c"
        })

        sinks_dict = self.extract_tool_result(sinks_result)
        assert sinks_dict.get("success") is True, f"Find sinks failed: {sinks_dict}"

        sinks = sinks_dict.get("sinks", [])
        total = sinks_dict.get("total", 0)

        assert isinstance(sinks, list), "sinks should be a list"
        assert total >= 0, "total should be non-negative"

        # Verify sink structure
        if sinks:
            sink = sinks[0]
            required_fields = ["node_id", "name", "code", "filename", "lineNumber", "method"]
            for field in required_fields:
                assert field in sink, f"Sink missing field: {field}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    async def test_get_code_snippet(self, client, codebase_path):
        """Test getting code snippets"""
        # Generate and wait for CPG
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        # Wait for ready
        for _ in range(30):
            await asyncio.sleep(1)
            status_result = await client.call_tool("get_cpg_status", {"codebase_hash": codebase_hash})
            if self.extract_tool_result(status_result).get("status") in ["ready", "cached"]:
                break

        # Get code snippet
        snippet_result = await client.call_tool("get_code_snippet", {
            "codebase_hash": codebase_hash,
            "filename": "core.c",
            "start_line": 1,
            "end_line": 10
        })

        snippet_dict = self.extract_tool_result(snippet_result)
        assert snippet_dict.get("success") is True, f"Snippet failed: {snippet_dict}"

        assert "code" in snippet_dict, "Snippet should contain code"
        code = snippet_dict["code"]
        assert isinstance(code, str), "code should be a string"
        assert len(code) > 0, "code should not be empty"

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    async def test_list_calls(self, client, codebase_path):
        """Test listing function calls"""
        # Generate and wait for CPG
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        # Wait for ready
        for _ in range(30):
            await asyncio.sleep(1)
            status_result = await client.call_tool("get_cpg_status", {"codebase_hash": codebase_hash})
            if self.extract_tool_result(status_result).get("status") in ["ready", "cached"]:
                break

        # List calls
        calls_result = await client.call_tool("list_calls", {
            "codebase_hash": codebase_hash,
            "limit": 10
        })

        calls_dict = self.extract_tool_result(calls_result)
        assert calls_dict.get("success") is True, f"List calls failed: {calls_dict}"

        calls = calls_dict.get("calls", [])
        total = calls_dict.get("total", 0)

        assert isinstance(calls, list), "calls should be a list"
        assert total >= 0, "total should be non-negative"
        assert len(calls) <= 10, "should not return more than limit"

        # Verify call structure
        if calls:
            call = calls[0]
            required_fields = ["caller", "callee", "code", "filename", "lineNumber"]
            for field in required_fields:
                assert field in call, f"Call missing field: {field}"

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    async def test_run_cpgql_query(self, client, codebase_path):
        """Test executing raw CPGQL queries"""
        # Generate and wait for CPG
        result = await client.call_tool("generate_cpg", {
            "source_type": "local",
            "source_path": codebase_path,
            "language": "c"
        })
        cpg_dict = self.extract_tool_result(result)
        codebase_hash = cpg_dict["codebase_hash"]

        # Wait for ready
        for _ in range(30):
            await asyncio.sleep(1)
            status_result = await client.call_tool("get_cpg_status", {"codebase_hash": codebase_hash})
            if self.extract_tool_result(status_result).get("status") in ["ready", "cached"]:
                break

        # Execute a simple CPGQL query to count methods
        query_result = await client.call_tool("run_cpgql_query", {
            "codebase_hash": codebase_hash,
            "query": "cpg.method.size",
            "timeout": 10
        })

        query_dict = self.extract_tool_result(query_result)
        assert query_dict.get("success") is True, f"CPGQL query failed: {query_dict}"

        # Verify response structure
        assert "data" in query_dict, "Response should contain data"
        assert "row_count" in query_dict, "Response should contain row_count"
        assert "execution_time" in query_dict, "Response should contain execution_time"

        # The result should be a number (count of methods)
        data = query_dict["data"]
        assert isinstance(data, (int, str)), "Data should be a number or string"

        row_count = query_dict["row_count"]
        assert isinstance(row_count, int), "row_count should be an integer"
        assert row_count >= 0, "row_count should be non-negative"

        execution_time = query_dict["execution_time"]
        assert isinstance(execution_time, (int, float)), "execution_time should be a number"
        assert execution_time >= 0, "execution_time should be non-negative"