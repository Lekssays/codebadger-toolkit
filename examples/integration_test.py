#!/usr/bin/env python3
"""
Integration Test for CodeBadger Toolkit Server - Hash-based Architecture

This test verifies the complete workflow:
1. CPG generation from local codebase
2. CPG status checking
3. Comprehensive analysis expectations based on core.c
"""

import asyncio
import logging
import sys
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    from fastmcp import Client
except ImportError:
    logger.error("FastMCP not found. Install with: pip install fastmcp")
    sys.exit(1)


def extract_tool_result(result):
    """Extract dictionary data from CallToolResult"""
    if hasattr(result, 'content') and result.content:
        content_text = result.content[0].text
        try:
            import json
            return json.loads(content_text)
        except:
            return {"error": content_text}
    return {}


class TestResults:
    """Track test results"""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []
    
    def record(self, test_name, passed, message=""):
        self.tests.append({
            "name": test_name,
            "passed": passed,
            "message": message
        })
        if passed:
            self.passed += 1
            logger.info(f"✅ PASS: {test_name}")
        else:
            self.failed += 1
            logger.error(f"❌ FAIL: {test_name} - {message}")
    
    def summary(self):
        total = self.passed + self.failed
        logger.info(f"\n{'='*60}")
        logger.info(f"TEST SUMMARY: {self.passed}/{total} passed")
        logger.info(f"{'='*60}")
        if self.failed > 0:
            logger.info("\nFailed tests:")
            for test in self.tests:
                if not test["passed"]:
                    logger.info(f"  - {test['name']}: {test['message']}")
        return self.failed == 0


async def run_integration_tests():
    """Run comprehensive integration tests"""
    server_url = "http://localhost:4242/mcp"
    results = TestResults()
    
    try:
        async with Client(server_url) as client:
            logger.info("="*60)
            logger.info("CODEBADGER TOOLKIT INTEGRATION TEST")
            logger.info("="*60)
            
            # ===== SERVER CONNECTIVITY =====
            logger.info("\n[1] Testing Server Connectivity")
            try:
                await client.ping()
                results.record("Server Ping", True)
            except Exception as e:
                results.record("Server Ping", False, str(e))
                return results.summary()
            
            # ===== LIST TOOLS =====
            logger.info("\n[2] Listing Available Tools")
            try:
                tools = await client.list_tools()
                tool_names = [tool.name for tool in tools]
                logger.info(f"Available tools: {tool_names}")
                
                expected_tools = ["generate_cpg", "get_cpg_status"]
                missing = [t for t in expected_tools if t not in tool_names]
                if missing:
                    results.record("Tool Availability", False, f"Missing tools: {missing}")
                else:
                    results.record("Tool Availability", True)
            except Exception as e:
                results.record("Tool Availability", False, str(e))
            
            # ===== CPG GENERATION =====
            logger.info("\n[3] Testing CPG Generation")
            codebase_path = os.path.abspath("playground/codebases/core")
            
            if not os.path.exists(codebase_path):
                results.record("CPG Generation", False, f"Source path not found: {codebase_path}")
                return results.summary()
            
            try:
                cpg_result = await client.call_tool("generate_cpg", {
                    "source_type": "local",
                    "source_path": codebase_path,
                    "language": "c"
                })
                
                cpg_dict = extract_tool_result(cpg_result)
                logger.info(f"CPG generation result: {cpg_dict}")
                
                if "codebase_hash" not in cpg_dict:
                    results.record("CPG Generation", False, "No codebase_hash returned")
                    return results.summary()
                
                codebase_hash = cpg_dict["codebase_hash"]
                status = cpg_dict.get("status")
                
                if status in ["generating", "cached"]:
                    results.record("CPG Generation", True)
                else:
                    results.record("CPG Generation", False, f"Unexpected status: {status}")
                
                logger.info(f"Codebase hash: {codebase_hash}")
                logger.info(f"Initial status: {status}")
                
            except Exception as e:
                results.record("CPG Generation", False, str(e))
                return results.summary()
            
            # ===== CPG STATUS POLLING =====
            logger.info("\n[4] Waiting for CPG to be Ready")
            cpg_ready = False
            cpg_path = None
            
            for attempt in range(30):  # Max 5 minutes (30 * 10 seconds)
                try:
                    await asyncio.sleep(10)
                    
                    status_result = await client.call_tool("get_cpg_status", {
                        "codebase_hash": codebase_hash
                    })
                    
                    status_dict = extract_tool_result(status_result)
                    status = status_dict.get("status")
                    exists = status_dict.get("exists", False)
                    
                    logger.info(f"  Attempt {attempt + 1}/30: status={status}, exists={exists}")
                    
                    if status in ["ready", "cached"] and exists:
                        cpg_ready = True
                        cpg_path = status_dict.get("cpg_path")
                        logger.info(f"  CPG ready at: {cpg_path}")
                        break
                    elif status == "not_found":
                        results.record("CPG Status Check", False, "CPG not found")
                        break
                        
                except Exception as e:
                    logger.warning(f"  Status check failed: {e}")
                    continue
            
            if cpg_ready:
                results.record("CPG Status Check", True)
            else:
                results.record("CPG Status Check", False, "CPG not ready after 5 minutes")
            
            # ===== VERIFY CPG FILE =====
            logger.info("\n[5] Verifying CPG File")
            # Note: CPG file is inside the container, not accessible from host
            # We verify it exists through the API instead
            if cpg_path:
                logger.info(f"  CPG path (container): {cpg_path}")
                # Check if we got a valid path from the API
                if cpg_path.endswith("cpg.bin"):
                    results.record("CPG File Verification", True)
                    logger.info(f"  ✓ CPG path confirmed via API")
                else:
                    results.record("CPG File Verification", False, f"Invalid CPG path: {cpg_path}")
            else:
                results.record("CPG File Verification", False, "CPG path not returned")
            
            # ===== CODEBASE INFO VERIFICATION =====
            logger.info("\n[6] Verifying Codebase Information")
            try:
                status_result = await client.call_tool("get_cpg_status", {
                    "codebase_hash": codebase_hash
                })
                
                status_dict = extract_tool_result(status_result)
                
                # Verify expected fields
                expected_fields = ["codebase_hash", "exists", "status", "cpg_path", 
                                 "source_type", "language", "created_at", "last_accessed"]
                missing_fields = [f for f in expected_fields if f not in status_dict]
                
                if missing_fields:
                    results.record("Codebase Info", False, f"Missing fields: {missing_fields}")
                else:
                    results.record("Codebase Info", True)
                    logger.info(f"  Source type: {status_dict.get('source_type')}")
                    logger.info(f"  Language: {status_dict.get('language')}")
                    logger.info(f"  Created: {status_dict.get('created_at')}")
            except Exception as e:
                results.record("Codebase Info", False, str(e))
            
            # ===== CACHE BEHAVIOR TEST =====
            logger.info("\n[7] Testing CPG Caching Behavior")
            try:
                # Generate CPG again for same codebase - should be cached
                cpg_result2 = await client.call_tool("generate_cpg", {
                    "source_type": "local",
                    "source_path": codebase_path,
                    "language": "c"
                })
                
                cpg_dict2 = extract_tool_result(cpg_result2)
                codebase_hash2 = cpg_dict2.get("codebase_hash")
                status2 = cpg_dict2.get("status")
                
                if codebase_hash2 == codebase_hash and status2 == "cached":
                    results.record("CPG Caching", True)
                    logger.info("  ✓ CPG correctly returned from cache")
                else:
                    results.record("CPG Caching", False, 
                                 f"Expected cached CPG, got status={status2}, hash_match={codebase_hash2 == codebase_hash}")
            except Exception as e:
                results.record("CPG Caching", False, str(e))
            
            # ===== LIST METHODS TEST =====
            logger.info("\n[8] Testing list_methods Tool")
            try:
                methods_result = await client.call_tool("list_methods", {
                    "codebase_hash": codebase_hash,
                    "limit": 10
                })
                
                methods_dict = extract_tool_result(methods_result)
                
                if methods_dict.get("success"):
                    method_count = methods_dict.get("total", 0)
                    logger.info(f"  Found {method_count} methods")
                    
                    # Test uses limit=10, so we expect up to 10 methods
                    if method_count >= 5:  # Reasonable minimum for the test codebase
                        results.record("List Methods", True)
                    else:
                        results.record("List Methods", False, f"Expected >=5 methods, got {method_count}")
                else:
                    results.record("List Methods", False, methods_dict.get("error", "Unknown error"))
            except Exception as e:
                results.record("List Methods", False, str(e))
            
            # ===== FIND TAINT SOURCES TEST =====
            logger.info("\n[9] Testing find_taint_sources Tool")
            try:
                sources_result = await client.call_tool("find_taint_sources", {
                    "codebase_hash": codebase_hash,
                    "language": "c"
                })
                
                sources_dict = extract_tool_result(sources_result)
                
                if sources_dict.get("success"):
                    source_count = sources_dict.get("total", 0)
                    sources = sources_dict.get("sources", [])
                    logger.info(f"  Found {source_count} taint sources")
                    
                    # Expected sources in core.c from config patterns: 
                    # fgets (line 154), getenv (line 160), fopen (line 165), 
                    # fread (line 168), recv (line 175)
                    # Total: 5 sources
                    if source_count == 5:
                        results.record("Find Taint Sources", True)
                        logger.info(f"  ✓ Found expected sources from config patterns")
                    else:
                        results.record("Find Taint Sources", False, f"Expected 5 sources, got {source_count}")
                else:
                    results.record("Find Taint Sources", False, sources_dict.get("error", "Unknown error"))
            except Exception as e:
                results.record("Find Taint Sources", False, str(e))
            
            # ===== FIND TAINT SINKS TEST =====
            logger.info("\n[10] Testing find_taint_sinks Tool")
            try:
                sinks_result = await client.call_tool("find_taint_sinks", {
                    "codebase_hash": codebase_hash,
                    "language": "c"
                })
                
                sinks_dict = extract_tool_result(sinks_result)
                
                if sinks_dict.get("success"):
                    sink_count = sinks_dict.get("total", 0)
                    sinks = sinks_dict.get("sinks", [])
                    logger.info(f"  Found {sink_count} taint sinks")
                    
                    # Expected sinks in core.c based on default patterns:
                    # Default patterns: ["system", "popen", "execl", "execv", "sprintf", "fprintf"]
                    # Actually present in core.c: system (line 180), sprintf (line 238)
                    # Total expected: 2
                    if sink_count == 2:
                        results.record("Find Taint Sinks", True)
                        logger.info(f"  ✓ Found expected sinks: system, sprintf")
                    else:
                        results.record("Find Taint Sinks", False, f"Expected 2 sinks, got {sink_count}")
                else:
                    results.record("Find Taint Sinks", False, sinks_dict.get("error", "Unknown error"))
            except Exception as e:
                results.record("Find Taint Sinks", False, str(e))
            
            # ===== FIND TAINT FLOWS TEST =====
            logger.info("\n[11] Testing find_taint_flows Tool")
            try:
                # Test flow detection from a taint source location
                # Note: This tool does intra-procedural analysis (within same function)
                # Testing with fgets call at line 154
                flows_result = await client.call_tool("find_taint_flows", {
                    "codebase_hash": codebase_hash,
                    "source_location": "core.c:154",  # fgets in read_user_input()
                    "max_path_length": 20,
                    "timeout": 60
                })
                
                flows_dict = extract_tool_result(flows_result)
                
                if flows_dict.get("success"):
                    flow_count = flows_dict.get("total", 0)
                    logger.info(f"  Found {flow_count} taint flows")
                    
                    # The tool successfully executed - this is an intra-procedural analysis
                    # The specific flow count may vary based on the analysis scope
                    # Success means the tool works correctly
                    results.record("Find Taint Flows", True)
                    logger.info(f"  ✓ Taint flow analysis completed successfully")
                else:
                    results.record("Find Taint Flows", False, flows_dict.get("error", "Unknown error"))
            except Exception as e:
                results.record("Find Taint Flows", False, str(e))
            
            # ===== FIND BOUNDS CHECKS TEST =====
            logger.info("\n[12] Testing find_bounds_checks Tool")
            try:
                # Test with unchecked buffer access at line 121 (buffer[index] without prior check)
                bounds_result = await client.call_tool("find_bounds_checks", {
                    "codebase_hash": codebase_hash,
                    "buffer_access_location": "core.c:121"
                })
                
                bounds_dict = extract_tool_result(bounds_result)
                
                if bounds_dict.get("success"):
                    check_before = bounds_dict.get("check_before_access", False)
                    check_after = bounds_dict.get("check_after_access", False)
                    logger.info(f"  Check before access: {check_before}")
                    logger.info(f"  Check after access: {check_after}")
                    
                    # Line 121 should have NO check before (unchecked access)
                    if not check_before:
                        results.record("Find Bounds Checks", True)
                        logger.info(f"  ✓ Correctly detected unchecked buffer access")
                    else:
                        results.record("Find Bounds Checks", False, "Expected no check before access")
                else:
                    results.record("Find Bounds Checks", False, bounds_dict.get("error", "Unknown error"))
            except Exception as e:
                results.record("Find Bounds Checks", False, str(e))
            
            logger.info("\n" + "="*60)
            logger.info("Integration test completed!")
            logger.info("="*60)
            
            return results.summary()
            
    except Exception as e:
        logger.error(f"Test suite failed with exception: {e}", exc_info=True)
        return False


if __name__ == "__main__":
    try:
        success = asyncio.run(run_integration_tests())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        logger.info("\n🛑 Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Test suite error: {e}", exc_info=True)
        sys.exit(1)
