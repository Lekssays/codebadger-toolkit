"""
Interactive query executor for running CPGQL queries using Joern server HTTP API
"""

import asyncio
import json
import logging
import re
import subprocess
import time
import uuid
from enum import Enum
from typing import Any, Dict, Optional

import httpx

from ..exceptions import QueryExecutionError
from ..models import JoernConfig, QueryConfig, QueryResult
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
    """Executes CPGQL queries using Joern server HTTP API"""

    def __init__(
        self,
        config: QueryConfig,
        joern_config: JoernConfig,
        redis_client: Optional[RedisClient] = None,
        docker_orchestrator=None,
    ):
        self.config = config
        self.joern_config = joern_config
        self.redis = redis_client
        # docker_orchestrator is ignored - we manage Joern servers directly
        self.codebase_cpgs: Dict[str, str] = {}  # codebase_hash -> cpg_path
        self.query_status: Dict[str, Dict[str, Any]] = {}  # query_id -> status info
        self.joern_servers: Dict[str, subprocess.Popen] = {}  # codebase_hash -> Joern server process
        self.joern_ports: Dict[str, int] = {}  # codebase_hash -> port number
        self.next_port = 2000  # Start port allocation at 2000

    async def initialize(self):
        """Initialize QueryExecutor (no-op in container)"""
        logger.info("QueryExecutor initialized (running locally)")

    async def _start_joern_server(self, codebase_hash: str, cpg_path: str):
        """Start a Joern server process for the given codebase"""
        try:
            # Allocate a port
            port = self.next_port
            self.next_port += 1
            
            # Start Joern server as subprocess
            logger.info(f"Starting Joern server on port {port} for {cpg_path}")
            
            # Command: joern --server --server-port <port> --server-host 0.0.0.0
            process = subprocess.Popen(
                ["joern", "--server", "--server-port", str(port), "--server-host", "0.0.0.0"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Store process and port
            self.joern_servers[codebase_hash] = process
            self.joern_ports[codebase_hash] = port
            
            # Wait for server to be ready
            await self._wait_for_server(port, timeout=30)
            
            # Load CPG into server
            await self._load_cpg(port, cpg_path)
            
            logger.info(f"Joern server started on port {port} for codebase {codebase_hash}")
            
        except Exception as e:
            error_msg = f"Failed to start Joern server: {str(e)}"
            logger.error(error_msg)
            # Cleanup on failure
            if codebase_hash in self.joern_servers:
                process = self.joern_servers[codebase_hash]
                process.terminate()
                del self.joern_servers[codebase_hash]
            if codebase_hash in self.joern_ports:
                del self.joern_ports[codebase_hash]
            raise QueryExecutionError(error_msg)

    async def _wait_for_server(self, port: int, timeout: int = 30):
        """Wait for Joern server to be ready"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                async with httpx.AsyncClient() as client:
                    # Try the /query endpoint with a simple test query
                    response = await client.post(
                        f"http://localhost:{port}/query",
                        json={"query": "cpg"},
                        timeout=5.0
                    )
                    # If we get any response (200, 40x, etc.), server is ready
                    if response.status_code in [200, 400, 404]:
                        logger.info(f"Joern server on port {port} is ready")
                        return
            except Exception as e:
                # Server not ready yet
                logger.debug(f"Waiting for server on port {port}: {e}")
            await asyncio.sleep(1)
        
        raise QueryExecutionError(f"Joern server on port {port} did not start within {timeout}s")

    async def _load_cpg(self, port: int, cpg_path: str):
        """Load CPG into Joern server"""
        try:
            logger.info(f"Loading CPG {cpg_path} into Joern server on port {port}")
            
            # Use Joern HTTP API to load CPG
            # POST /query with importCpg command
            query = f'importCpg("{cpg_path}")'
            
            async with httpx.AsyncClient(timeout=300.0) as client:
                # Submit query
                response = await client.post(
                    f"http://localhost:{port}/query",
                    json={"query": query}
                )
                
                if response.status_code != 200:
                    raise QueryExecutionError(f"Failed to load CPG: HTTP {response.status_code}")
                
                result = response.json()
                query_uuid = result.get("uuid")
                
                if not query_uuid:
                    raise QueryExecutionError("Server did not return query UUID")
                
                # Wait for result
                for _ in range(60):  # Wait up to 60 seconds
                    await asyncio.sleep(1)
                    result_response = await client.get(
                        f"http://localhost:{port}/result/{query_uuid}"
                    )
                    
                    if result_response.status_code == 200:
                        result_data = result_response.json()
                        if result_data.get("success"):
                            logger.info(f"CPG loaded successfully into server on port {port}")
                            return
                        else:
                            error = result_data.get("stderr", "Unknown error")
                            raise QueryExecutionError(f"Failed to load CPG: {error}")
                
                raise QueryExecutionError("CPG loading timed out")
            
        except Exception as e:
            error_msg = f"Failed to load CPG: {str(e)}"
            logger.error(error_msg)
            raise QueryExecutionError(error_msg)

    async def execute_query_async(
        self,
        codebase_hash: str,
        query: str,
        timeout: Optional[int] = None,
        limit: Optional[int] = 150,
        offset: Optional[int] = None,
    ) -> str:
        """Execute a CPGQL query asynchronously and return query UUID"""
        try:
            # Generate unique query ID
            query_id = str(uuid.uuid4())

            # Validate query
            validate_cpgql_query(query)

            # Normalize query to ensure JSON output and pipe to file
            query_normalized = self._normalize_query_for_json(
                query.strip(), limit, offset
            )
            output_file = f"/tmp/query_{query_id}.json"
            query_with_pipe = f'{query_normalized} #> "{output_file}"'

            # Initialize query status
            self.query_status[query_id] = {
                "status": QueryStatus.PENDING.value,
                "codebase_hash": codebase_hash,
                "query": query,
                "output_file": output_file,
                "created_at": time.time(),
                "error": None,
            }

            # Start async execution
            asyncio.create_task(
                self._execute_query_background(
                    query_id, codebase_hash, query_with_pipe, timeout
                )
            )

            logger.info(f"Started async query {query_id} for codebase {codebase_hash}")
            return query_id

        except Exception as e:
            logger.error(f"Failed to start async query: {e}")
            raise QueryExecutionError(f"Query initialization failed: {str(e)}")

    async def _execute_query_background(
        self,
        query_id: str,
        codebase_hash: str,
        query_with_pipe: str,
        timeout: Optional[int],
    ):
        """Execute query in background"""
        try:
            # Update status to running
            self.query_status[query_id]["status"] = QueryStatus.RUNNING.value
            self.query_status[query_id]["started_at"] = time.time()

            # Extract the normalized query (remove the pipe part)
            query_normalized = query_with_pipe.split(" #>")[0]

            # Check cache if enabled
            if self.config.cache_enabled and self.redis:
                query_hash_val = hash_query(query_normalized)
                cached = await self.redis.get_cached_query(codebase_hash, query_hash_val)
                if cached:
                    logger.info(f"Query cache hit for session {codebase_hash}")
                    # Update status to completed with cached result
                    self.query_status[query_id]["status"] = QueryStatus.COMPLETED.value
                    self.query_status[query_id]["completed_at"] = time.time()
                    self.query_status[query_id]["result"] = cached
                    return

            # Execute query using the same approach as sync queries
            result = await self._execute_query_in_shell(
                codebase_hash, query_normalized, timeout or self.config.timeout
            )

            if result.success:
                # Update status to completed
                self.query_status[query_id]["status"] = QueryStatus.COMPLETED.value
                self.query_status[query_id]["completed_at"] = time.time()
                self.query_status[query_id]["result"] = result.to_dict()

                # Cache result if enabled
                if self.config.cache_enabled and self.redis:
                    query_hash_val = hash_query(query_normalized)
                    await self.redis.cache_query_result(
                        codebase_hash,
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
            # Update status to failed
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
            # Fallback for compatibility
            execution_time = status_info.get("execution_time", 0)
            return QueryResult(
                success=True, data=[], row_count=0, execution_time=execution_time
            )



    async def execute_query(
        self,
        codebase_hash: str,
        cpg_path: str,
        query: str,
        timeout: Optional[int] = None,
        limit: Optional[int] = 150,
        offset: Optional[int] = None,
    ) -> QueryResult:
        """Execute a CPGQL query using Joern server HTTP API"""
        start_time = time.time()

        try:
            # Store CPG path for this codebase
            self.codebase_cpgs[codebase_hash] = cpg_path
            
            # Validate query
            validate_cpgql_query(query)

            # Normalize query to ensure JSON output
            query_normalized = self._normalize_query_for_json(
                query.strip(), limit, offset
            )

            # Check cache if enabled
            if self.config.cache_enabled and self.redis:
                query_hash_val = hash_query(query_normalized)
                cached = await self.redis.get_cached_query(codebase_hash, query_hash_val)
                if cached:
                    logger.info(f"Query cache hit for codebase {codebase_hash}")
                    cached["execution_time"] = time.time() - start_time
                    return QueryResult(**cached)

            # Get or start Joern server for this codebase
            if codebase_hash not in self.joern_servers:
                # Start a Joern server for this codebase
                logger.info(f"Starting Joern server for codebase {codebase_hash}")
                await self._start_joern_server(codebase_hash, cpg_path)
            
            # Get port for this codebase
            port = self.joern_ports.get(codebase_hash)
            if not port:
                raise QueryExecutionError(f"No Joern server found for codebase {codebase_hash}")

            # Execute query via HTTP API
            timeout_val = timeout or self.config.timeout
            result = await self._execute_query_via_http(
                port, query_normalized, timeout_val
            )
            result.execution_time = time.time() - start_time

            # Cache result if enabled
            if self.config.cache_enabled and self.redis and result.success:
                query_hash_val = hash_query(query_normalized)
                await self.redis.cache_query_result(
                    codebase_hash, query_hash_val, result.to_dict(), self.config.cache_ttl
                )

            logger.info(
                f"Query executed for session {codebase_hash}: "
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

    async def list_queries(self, codebase_hash: Optional[str] = None) -> Dict[str, Any]:
        """List all queries or queries for a specific session"""
        if codebase_hash:
            return {
                query_id: status_info
                for query_id, status_info in self.query_status.items()
                if status_info["codebase_hash"] == codebase_hash
            }
        else:
            return self.query_status.copy()

    async def cleanup_query(self, query_id: str):
        """Clean up query resources"""
        if query_id in self.query_status:
            status_info = self.query_status[query_id]

            # Clean up output file if it exists
            if "output_file" in status_info:
                try:
                    codebase_hash = status_info["codebase_hash"]
                    output_file = status_info["output_file"]

                    # Execute rm command in container to clean up file
                    container_id = await self._get_container_id(codebase_hash)
                    if container_id:
                        container = self.docker_client.containers.get(container_id)
                        container.exec_run(f"rm -f {output_file}")
                except Exception as e:
                    logger.warning(
                        f"Failed to cleanup output file for query {query_id}: {e}"
                    )

            # Remove from tracking
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

    def _normalize_query_for_json(
        self,
        query: str,
        limit: Optional[int] = None,
        offset: Optional[int] = None
    ) -> str:
        """Normalize query to ensure JSON output"""
        import re

        # Remove any existing output modifiers
        query = query.strip()

        # Check if query already ends with .toJsonPretty (multi-line queries add
        # it manually)
        if query.endswith(".toJsonPretty"):
            return query

        # Check if this is a multi-line query (contains newlines or val statements)
        # Multi-line queries already handle their own JSON output
        if "\n" in query or query.startswith("val ") or "if (" in query:
            # Multi-line queries should have .toJsonPretty at the end already
            # If not, something is wrong, but don't modify them
            return query

        # For single-line queries, normalize to JSON output
        if query.endswith(".l"):
            query = query[:-2]
        elif query.endswith(".toList"):
            query = query[:-7]
        elif query.endswith(".toJson"):
            query = query[:-7]
        elif query.endswith(".toJsonPretty"):
            query = query[:-13]

        # Remove existing .take() and .drop() modifiers using regex
        query = re.sub(r"\.take\(\d+\)", "", query)
        query = re.sub(r"\.drop\(\d+\)", "", query)

        # Add offset if specified
        if offset is not None and offset > 0:
            query = f"{query}.drop({offset})"

        # Add limit if specified
        if limit is not None and limit > 0:
            query = f"{query}.take({limit})"

        # Add .toJsonPretty for proper JSON output
        return query + ".toJsonPretty"

    async def _execute_query_via_http(
        self, port: int, query: str, timeout: int
    ) -> QueryResult:
        """Execute query using Joern server HTTP API"""
        try:
            logger.debug(f"Executing query via HTTP on port {port}: {query[:100]}...")
            
            # Execute query via Joern HTTP API
            async with httpx.AsyncClient(timeout=float(timeout)) as client:
                # Submit query
                response = await client.post(
                    f"http://localhost:{port}/query",
                    json={"query": query}
                )
                
                if response.status_code != 200:
                    error_msg = f"HTTP {response.status_code}"
                    logger.error(f"Query failed: {error_msg}")
                    return QueryResult(success=False, error=error_msg)
                
                result = response.json()
                query_uuid = result.get("uuid")
                
                if not query_uuid:
                    return QueryResult(success=False, error="Server did not return query UUID")
                
                # Poll for result
                start_time = time.time()
                while time.time() - start_time < timeout:
                    await asyncio.sleep(0.5)
                    
                    result_response = await client.get(
                        f"http://localhost:{port}/result/{query_uuid}"
                    )
                    
                    if result_response.status_code == 200:
                        result_data = result_response.json()
                        success = result_data.get("success")
                        stdout = result_data.get("stdout", "")
                        stderr = result_data.get("stderr", "")
                        
                        if success:
                            # Try to parse stdout as JSON
                            data = self._parse_joern_output(stdout)
                            return QueryResult(success=True, data=data, row_count=len(data))
                        else:
                            # Query failed
                            error_msg = stderr if stderr else "Query failed"
                            logger.error(f"Query failed: {error_msg}")
                            return QueryResult(success=False, error=error_msg)
                
                # Timeout
                return QueryResult(success=False, error=f"Query timeout after {timeout}s")
                
        except asyncio.TimeoutError as e:
            logger.error(f"Query timeout: {e}")
            return QueryResult(success=False, error=f"Query timeout: {str(e)}")
        except Exception as e:
            logger.error(f"Error executing query via HTTP: {e}")
            return QueryResult(success=False, error=str(e))

    def _parse_joern_output(self, output: str) -> list:
        """Parse Joern query output, extracting JSON from Scala REPL format"""
        if not output or not output.strip():
            return []
        
        # Remove ANSI color codes
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        output = ansi_escape.sub('', output)
        
        # Try to extract JSON from Scala REPL output
        # Format: val res0: String = """[...]"""
        # or: val res0: List[...] = List(...)
        
        # Look for JSON array or object within triple quotes
        match = re.search(r'"""(\[.*?\]|\{.*?\})"""', output, re.DOTALL)
        if match:
            json_str = match.group(1)
            try:
                data = json.loads(json_str)
                if isinstance(data, dict):
                    return [data]
                elif isinstance(data, list):
                    return data
                else:
                    return [{"value": str(data)}]
            except json.JSONDecodeError as e:
                logger.debug(f"Failed to parse extracted JSON: {e}")
        
        # Try direct JSON parsing (for when output is already clean JSON)
        try:
            data = json.loads(output)
            if isinstance(data, dict):
                return [data]
            elif isinstance(data, list):
                return data
            else:
                return [{"value": str(data)}]
        except json.JSONDecodeError:
            # If not JSON, return as plain text
            logger.debug("Output is not JSON, returning as plain text")
            return [{"value": output.strip()}]

    async def _ensure_cpg_loaded(self, codebase_hash: str, cpg_path: str):
        """Ensure CPG is loaded in the Joern session (DEPRECATED)"""
        # This method is deprecated in the new architecture
        # CPG loading is handled by docker_orchestrator when starting the server
        logger.debug(f"_ensure_cpg_loaded called for session {codebase_hash} (deprecated)")
        pass

    async def _load_cpg_in_container(self, codebase_hash: str, cpg_path: str):
        """Load CPG in the container (DEPRECATED - handled by docker_orchestrator)"""
        logger.debug(f"_load_cpg_in_container called for session {codebase_hash} (deprecated)")
        # This is now handled by docker_orchestrator.start_joern_server
        pass

    async def _execute_query_in_shell(
        self, codebase_hash: str, query: str, timeout: int
    ) -> QueryResult:
        """Execute query (DEPRECATED - use _execute_query_via_http)"""
        logger.warning("_execute_query_in_shell is deprecated")
        # Get client and use HTTP API
        if not self.docker_orchestrator:
            raise QueryExecutionError("Docker orchestrator not initialized")
        
        client = await self.docker_orchestrator.get_joern_client(codebase_hash)
        if not client:
            raise QueryExecutionError(f"No Joern server found for codebase {codebase_hash}")
        
        return await self._execute_query_via_http(client, query, timeout)

    async def _execute_query_via_persistent_shell_DEPRECATED(
        self, codebase_hash: str, query: str, timeout: int
    ) -> QueryResult:
        """Execute query using Joern project (reuses loaded CPG - fast path)"""
        logger.info(f"Executing query via Joern project (session {codebase_hash})")
        
        container_id = await self._get_container_id(codebase_hash)
        container = self.docker_client.containers.get(container_id)
        
        query_id = str(uuid.uuid4())[:8]
        cpg_path = self.codebase_cpgs.get(codebase_hash, "/workspace/cpg.bin")
        
        try:
            # Create query script file
            output_file = f"/tmp/query_result_{query_id}.json"
            
            # Escape query for shell
            query_escaped = query.replace("'", "'\\''")
            query_with_pipe = f'{query_escaped} #> "{output_file}"'
            
            # Use Joern's project system - it caches the loaded CPG with overlays
            # The project name is derived from the CPG path
            # Format: open("<project_name>")
            # After first load via importCpg, subsequent opens are instant
            project_name = f"cpg.bin"  # Joern creates project based on CPG filename
            
            # Create script that opens existing project (fast) or imports fresh (slow on first run)
            query_script = f"""
// Try to open existing project (fast - reuses loaded CPG)
val projectPath = "{cpg_path}"
try {{
  open(projectPath)
}} catch {{
  case e: Exception =>
    // Project doesn't exist, import it (slow - first time only)
    importCpg(projectPath)
}}

// Execute the query
{query_with_pipe}
"""
            
            query_file = f"/tmp/query_{query_id}.sc"
            
            # Write query script
            write_cmd = f"cat > {query_file} << 'QUERY_EOF'\n{query_script}\nQUERY_EOF"
            write_result = container.exec_run(["sh", "-c", write_cmd])
            
            if write_result.exit_code != 0:
                raise QueryExecutionError("Failed to write query file")
            
            # Execute with joern (will reuse project if it exists)
            exec_script = f"""#!/bin/bash
timeout {timeout} joern --script {query_file} 2>&1

EXIT_CODE=$?

# Clean up query file
rm -f {query_file}

exit $EXIT_CODE
"""
            
            loop = asyncio.get_event_loop()
            
            def _exec():
                return container.exec_run(["sh", "-c", exec_script], workdir="/workspace")
            
            start_time = time.time()
            exec_result = await loop.run_in_executor(None, _exec)
            exec_time = time.time() - start_time
            
            logger.info(f"Query execution completed in {exec_time:.2f}s")
            
            if exec_result.exit_code != 0:
                output = exec_result.output.decode("utf-8", errors="ignore") if exec_result.output else ""
                
                # Check if it's just warnings
                non_fatal_patterns = [
                    "FieldAccessLinkerPass",
                    "ReachingDefPass",
                    "The graph has been modified",
                    "Skipping.",
                    "WARN",
                ]
                
                lines = [l.strip() for l in output.splitlines() if l.strip()]
                if lines:
                    fatal_lines = [
                        l for l in lines
                        if not any(tok in l for tok in non_fatal_patterns)
                        and not l.startswith("Creating project")
                        and not l.startswith("Loading base CPG")
                        and not l.startswith("Adding default overlays")
                    ]
                    
                    if fatal_lines:
                        logger.error(f"Query execution failed: {output[:500]}")
                        return QueryResult(success=False, error=f"Query failed: {output[:500]}")
                    else:
                        logger.info("Query completed with warnings only")
            
            # Read result file
            def _read():
                return container.exec_run(f"cat {output_file}")
            
            read_result = await loop.run_in_executor(None, _read)
            
            if read_result.exit_code != 0:
                return QueryResult(success=False, error="Query produced no output")
            
            json_content = read_result.output.decode("utf-8", errors="ignore")
            
            # Clean up
            container.exec_run(f"rm -f {output_file}")
            
            if not json_content.strip():
                return QueryResult(success=True, data=[], row_count=0)
            
            # Parse JSON
            try:
                data = json.loads(json_content)
                if isinstance(data, dict):
                    data = [data]
                elif not isinstance(data, list):
                    data = [{"value": str(data)}]
                
                logger.info(f"Query executed successfully: {len(data)} results in {exec_time:.2f}s")
                return QueryResult(success=True, data=data, row_count=len(data))
            
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON: {e}")
                return QueryResult(
                    success=True,
                    data=[{"value": json_content.strip()}],
                    row_count=1
                )
        
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            return QueryResult(success=False, error=str(e))

    async def _execute_query_oneshot_DEPRECATED(
        self, codebase_hash: str, query: str, timeout: int
    ) -> QueryResult:
        """Execute query using one-shot joern process (slow but reliable fallback)"""
        logger.debug(f"Executing query via one-shot execution in session {codebase_hash}: {query[:100]}...")

        container_id = await self._get_container_id(codebase_hash)
        if not container_id:
            raise QueryExecutionError(f"No container found for session {codebase_hash}")

        try:
            container = self.docker_client.containers.get(container_id)

            # Use the CPG file from workspace
            cpg_path = "/workspace/cpg.bin"

            # Create unique output file for this query
            query_id = str(uuid.uuid4())[:8]
            output_file = f"/tmp/query_result_{query_id}.json"

            # Escape single quotes in query for shell
            query_escaped = query.replace("'", "'\\''")
            
            # Create query with pipe to JSON file
            query_with_pipe = f'{query_escaped} #> "{output_file}"'

            # NOTE: For large CPGs like ImageMagick, loading CPG can take 2-3 minutes
            # The timeout needs to account for: CPG load time + query execution time
            logger.info(f"Executing one-shot query with timeout={timeout}s (includes CPG load time)")

            # Use file-based approach: write query to file, execute with timeout
            exec_script = f"""#!/bin/bash
# Check if CPG exists
if [ ! -f "{cpg_path}" ]; then
    echo "ERROR: CPG file not found at {cpg_path}" >&2
    exit 1
fi

# Write query to temp file
cat > /tmp/query_{query_id}.sc << 'QUERY_EOF'
{query_with_pipe}
QUERY_EOF

# Execute query with timeout (load CPG + execute query)
# For large CPGs, loading alone can take 2-3 minutes
timeout {timeout} joern --script /tmp/query_{query_id}.sc {cpg_path} 2>&1

# Capture exit code
EXIT_CODE=$?

# Clean up query file
rm -f /tmp/query_{query_id}.sc

exit $EXIT_CODE
"""

            # Write and execute script
            loop = asyncio.get_event_loop()

            def _exec_sync():
                result = container.exec_run(
                    ["sh", "-c", exec_script],
                    workdir="/workspace"
                )
                return result

            exec_result = await loop.run_in_executor(None, _exec_sync)

            logger.debug(f"Query execution exit code: {exec_result.exit_code}")

            if exec_result.exit_code != 0:
                output = (
                    exec_result.output.decode("utf-8", errors="ignore")
                    if exec_result.output
                    else ""
                )
                logger.error(
                    f"Query execution failed with exit code {
                        exec_result.exit_code}: {output}"
                )
                return QueryResult(
                    success=False, error=f"Query execution failed: {output}"
                )

            # Read the JSON result file
            try:

                def _read_file():
                    result = container.exec_run(f"cat {output_file}")
                    return result

                file_result = await loop.run_in_executor(None, _read_file)

                if file_result.exit_code != 0:
                    logger.error(
                        "Output file not generated, query failed due to "
                        "syntax error or not found attribute"
                    )
                    return QueryResult(
                        success=False,
                        error="Query failed: syntax error or attribute not found",
                    )

                json_content = file_result.output.decode("utf-8", errors="ignore")

                # Clean up the output file
                container.exec_run(f"rm -f {output_file}")

                if not json_content.strip():
                    return QueryResult(success=True, data=[], row_count=0)

                # Parse JSON content
                try:
                    data = json.loads(json_content)

                    # Normalize data to list
                    if isinstance(data, dict):
                        data = [data]
                    elif not isinstance(data, list):
                        data = [{"value": str(data)}]

                    logger.info(f"Successfully parsed {len(data)} results from query")

                    return QueryResult(success=True, data=data, row_count=len(data))

                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse JSON output: {e}")
                    logger.debug(f"Raw JSON content: {json_content[:500]}...")

                    # Return as string value if JSON parsing fails
                    return QueryResult(
                        success=True,
                        data=[{"value": json_content.strip()}],
                        row_count=1,
                    )

            except Exception as e:
                logger.error(f"Failed to read query result file: {e}")
                return QueryResult(
                    success=False, error=f"Failed to read result: {str(e)}"
                )

        except Exception as e:
            logger.error(f"Error executing query in container: {e}")
            return QueryResult(success=False, error=f"Query execution error: {str(e)}")

    async def close_session(self, codebase_hash: str):
        """Close query executor codebase resources"""
        if codebase_hash in self.codebase_cpgs:
            del self.codebase_cpgs[codebase_hash]

        logger.info(f"Closed query executor resources for codebase {codebase_hash}")

    async def cleanup(self):
        """Cleanup all codebases and queries"""
        # Cleanup all queries
        query_ids = list(self.query_status.keys())
        for query_id in query_ids:
            await self.cleanup_query(query_id)

        # Terminate all Joern server processes
        for codebase_hash, process in self.joern_servers.items():
            try:
                logger.info(f"Terminating Joern server for codebase {codebase_hash}")
                process.terminate()
                process.wait(timeout=5)
            except Exception as e:
                logger.warning(f"Error terminating Joern server: {e}")
                try:
                    process.kill()
                except:
                    pass
        
        self.joern_servers.clear()
        self.joern_ports.clear()

        # Cleanup codebase resources
        codebases = list(self.codebase_cpgs.keys())
        for codebase_hash in codebases:
            await self.close_session(codebase_hash)
