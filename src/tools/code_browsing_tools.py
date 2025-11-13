"""
Code Browsing MCP Tools for Joern MCP Server (SIMPLIFIED)

Tools for exploring and navigating codebase structure using query templates.
Returns plain text output instead of parsing JSON tuples.
"""

import logging
import os
from typing import Any, Dict, Optional

from ..exceptions import (
    SessionNotFoundError,
    SessionNotReadyError,
    ValidationError,
)
from ..models import SessionStatus
from ..utils.validators import validate_session_id

logger = logging.getLogger(__name__)


def _extract_output(result_data: Any) -> str:
    """Extract plain text output from query result"""
    if isinstance(result_data, list) and len(result_data) > 0:
        first_item = result_data[0]
        if isinstance(first_item, dict):
            return first_item.get("output", "")
        else:
            return str(first_item)
    return ""


def register_code_browsing_tools(mcp, services: dict):
    """Register code browsing MCP tools with the FastMCP server"""

    @mcp.tool()
    async def list_methods(
        session_id: str,
        name_pattern: Optional[str] = None,
        file_pattern: Optional[str] = None,
        callee_pattern: Optional[str] = None,
        include_external: bool = False,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        List methods/functions in the codebase.

        Discover all methods and functions defined in the analyzed code. This is
        essential for understanding the codebase structure and finding specific
        functions to analyze.

        Args:
            session_id: The session ID from create_cpg_session
            name_pattern: Optional regex to filter method names (e.g., ".*authenticate.*")
            file_pattern: Optional regex to filter by file path
            callee_pattern: Optional regex to filter for methods that call a specific function
            include_external: Include external/library methods (default: false)
            limit: Maximum number of results to return (default: 100)

        Returns:
            {
                "success": true,
                "methods": [
                    {
                        "node_id": "12345",
                        "name": "main",
                        "fullName": "main",
                        "signature": "int main()",
                        "filename": "main.c",
                        "lineNumber": 10,
                        "isExternal": false
                    }
                ],
                "total": 1
            }
        """
        try:
            validate_session_id(session_id)

            session_manager = services["session_manager"]
            template_executor = services["template_query_executor"]

            session = await session_manager.get_session(session_id)
            if not session:
                raise SessionNotFoundError(f"Session {session_id} not found")

            if session.status != SessionStatus.READY.value:
                raise SessionNotReadyError(f"Session is in '{session.status}' status")

            await session_manager.touch_session(session_id)

            # Execute template query
            result = await template_executor.execute_template_query(
                session_id=session_id,
                category="core",
                template_name="list_methods",
                params={
                    "include_external": include_external,
                    "name_pattern": name_pattern or "",
                    "file_pattern": file_pattern or "",
                    "callee_pattern": callee_pattern or "",
                    "limit": limit,
                },
                timeout=30,
                limit=limit,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            # Return raw output
            output = result.data[0].get("output", "") if result.data and isinstance(result.data[0], dict) else ""

            return {"success": True, "output": output}

        except (SessionNotFoundError, SessionNotReadyError, ValidationError) as e:
            logger.error(f"Error listing methods: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    @mcp.tool()
    async def get_method_source(
        session_id: str, method_name: str, filename: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get the source code of a specific method.

        Retrieve the actual source code for a method to understand its implementation.
        Useful when you need to examine the details of a specific function.

        Args:
            session_id: The session ID from create_cpg_session
            method_name: Name of the method (can be regex pattern)
            filename: Optional filename to disambiguate methods with same name

        Returns:
            {
                "success": true,
                "methods": [
                    {
                        "name": "main",
                        "filename": "main.c",
                        "lineNumber": 10,
                        "lineNumberEnd": 20,
                        "code": "int main() { ... }"
                    }
                ],
                "total": 1
            }
        """
        try:
            validate_session_id(session_id)

            session_manager = services["session_manager"]
            template_executor = services["template_query_executor"]

            session = await session_manager.get_session(session_id)
            if not session:
                raise SessionNotFoundError(f"Session {session_id} not found")

            if session.status != SessionStatus.READY.value:
                raise SessionNotReadyError(f"Session is in '{session.status}' status")

            await session_manager.touch_session(session_id)

            # Execute template query to get method metadata
            result = await template_executor.execute_template_query(
                session_id=session_id,
                category="core",
                template_name="get_method_source",
                params={
                    "method_name": method_name,
                    "filename": filename or "",
                },
                timeout=30,
                limit=10,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            output = _extract_output(result.data)

            return {"success": True, "output": output}

        except (SessionNotFoundError, SessionNotReadyError, ValidationError) as e:
            logger.error(f"Error getting method source: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    @mcp.tool()
    async def list_calls(
        session_id: str,
        caller_pattern: Optional[str] = None,
        callee_pattern: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        List function/method calls in the codebase.

        Discover call relationships between functions. Essential for understanding
        control flow and dependencies in the code.

        Args:
            session_id: The session ID from create_cpg_session
            caller_pattern: Optional regex to filter caller method names
            callee_pattern: Optional regex to filter callee method names
            limit: Maximum number of results (default: 100)

        Returns:
            {
                "success": true,
                "calls": [
                    {
                        "caller": "main",
                        "callee": "helper",
                        "code": "helper(x)",
                        "filename": "main.c",
                        "lineNumber": 15
                    }
                ],
                "total": 1
            }
        """
        try:
            validate_session_id(session_id)

            session_manager = services["session_manager"]
            template_executor = services["template_query_executor"]

            session = await session_manager.get_session(session_id)
            if not session:
                raise SessionNotFoundError(f"Session {session_id} not found")

            if session.status != SessionStatus.READY.value:
                raise SessionNotReadyError(f"Session is in '{session.status}' status")

            await session_manager.touch_session(session_id)

            # Execute template query
            result = await template_executor.execute_template_query(
                session_id=session_id,
                category="core",
                template_name="find_calls",
                params={
                    "caller_pattern": caller_pattern or "",
                    "callee_pattern": callee_pattern or "",
                    "limit": limit,
                },
                timeout=30,
                limit=limit,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            output = _extract_output(result.data)

            return {"success": True, "output": output}

        except (SessionNotFoundError, SessionNotReadyError, ValidationError) as e:
            logger.error(f"Error listing calls: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    @mcp.tool()
    async def get_call_graph(
        session_id: str, method_name: str, depth: int = 5, direction: str = "outgoing"
    ) -> Dict[str, Any]:
        """
        Get the call graph for a specific method.

        Understand what functions a method calls (outgoing) or what functions
        call it (incoming). Essential for impact analysis and understanding
        code dependencies.

        Args:
            session_id: The session ID from create_cpg_session
            method_name: Name of the method to analyze (can be regex)
            depth: How many levels deep to traverse (default: 5, max recommended: 10)
            direction: "outgoing" (callees) or "incoming" (callers)

        Returns:
            {
                "success": true,
                "root_method": "authenticate",
                "direction": "outgoing",
                "calls": [
                    {"from": "authenticate", "to": "validate_password", "depth": 1},
                    {"from": "validate_password", "to": "hash_password", "depth": 2}
                ],
                "total": 2
            }
        """
        try:
            validate_session_id(session_id)

            if depth < 1 or depth > 15:
                raise ValidationError("Depth must be between 1 and 15")

            if direction not in ["outgoing", "incoming"]:
                raise ValidationError("Direction must be 'outgoing' or 'incoming'")

            session_manager = services["session_manager"]
            template_executor = services["template_query_executor"]

            session = await session_manager.get_session(session_id)
            if not session:
                raise SessionNotFoundError(f"Session {session_id} not found")

            if session.status != SessionStatus.READY.value:
                raise SessionNotReadyError(f"Session is in '{session.status}' status")

            await session_manager.touch_session(session_id)

            # Execute template query
            result = await template_executor.execute_template_query(
                session_id=session_id,
                category="core",
                template_name="call_graph",
                params={
                    "method_name": method_name,
                    "depth": depth,
                    "direction": direction,
                    "limit": 500,
                },
                timeout=120,
                limit=500,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            output = _extract_output(result.data)

            return {
                "success": True,
                "root_method": method_name,
                "direction": direction,
                "output": output,
            }

        except (SessionNotFoundError, SessionNotReadyError, ValidationError) as e:
            logger.error(f"Error getting call graph: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    @mcp.tool()
    async def list_parameters(session_id: str, method_name: str) -> Dict[str, Any]:
        """
        List parameters of a specific method.

        Get detailed information about method parameters including their names,
        types, and order. Useful for understanding function signatures.

        Args:
            session_id: The session ID from create_cpg_session
            method_name: Name of the method (can be regex pattern)

        Returns:
            {
                "success": true,
                "methods": [
                    {
                        "method": "authenticate",
                        "parameters": [
                            {"name": "username", "type": "string", "index": 1},
                            {"name": "password", "type": "string", "index": 2}
                        ]
                    }
                ],
                "total": 1
            }
        """
        try:
            validate_session_id(session_id)

            session_manager = services["session_manager"]
            template_executor = services["template_query_executor"]

            session = await session_manager.get_session(session_id)
            if not session:
                raise SessionNotFoundError(f"Session {session_id} not found")

            if session.status != SessionStatus.READY.value:
                raise SessionNotReadyError(f"Session is in '{session.status}' status")

            await session_manager.touch_session(session_id)

            # Execute template query
            result = await template_executor.execute_template_query(
                session_id=session_id,
                category="core",
                template_name="list_parameters",
                params={
                    "method_name": method_name,
                },
                timeout=30,
                limit=10,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            output = _extract_output(result.data)

            return {"success": True, "output": output}

        except (SessionNotFoundError, SessionNotReadyError, ValidationError) as e:
            logger.error(f"Error listing parameters: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    @mcp.tool()
    async def find_literals(
        session_id: str,
        pattern: Optional[str] = None,
        literal_type: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """
        Find literal values in the code (strings, numbers, etc).

        Search for hardcoded values like strings, numbers, or constants.
        Useful for finding configuration values, API keys, URLs, or
        magic numbers in the code.

        Args:
            session_id: The session ID from create_cpg_session
            pattern: Optional regex to filter literal values (e.g., ".*password.*")
            literal_type: Optional type filter (e.g., "string", "int")
            limit: Maximum number of results (default: 50)

        Returns:
            {
                "success": true,
                "literals": [
                    {
                        "value": "admin_password",
                        "type": "string",
                        "filename": "config.c",
                        "lineNumber": 42,
                        "method": "init_config"
                    }
                ],
                "total": 1
            }
        """
        try:
            validate_session_id(session_id)

            session_manager = services["session_manager"]
            template_executor = services["template_query_executor"]

            session = await session_manager.get_session(session_id)
            if not session:
                raise SessionNotFoundError(f"Session {session_id} not found")

            if session.status != SessionStatus.READY.value:
                raise SessionNotReadyError(f"Session is in '{session.status}' status")

            await session_manager.touch_session(session_id)

            # Execute template query
            result = await template_executor.execute_template_query(
                session_id=session_id,
                category="core",
                template_name="find_literals",
                params={
                    "pattern": pattern or "",
                    "literal_type": literal_type or "",
                    "limit": limit,
                },
                timeout=30,
                limit=limit,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            output = _extract_output(result.data)

            return {"success": True, "output": output}

        except (SessionNotFoundError, SessionNotReadyError, ValidationError) as e:
            logger.error(f"Error finding literals: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    @mcp.tool()
    async def get_codebase_summary(session_id: str) -> Dict[str, Any]:
        """
        Get a high-level summary of the codebase structure.

        Provides an overview including file count, method count, language,
        and other metadata. Useful as a first step when exploring a new codebase.

        Args:
            session_id: The session ID from create_cpg_session

        Returns:
            {
                "success": true,
                "summary": {
                    "language": "C",
                    "total_files": 15,
                    "total_methods": 127,
                    "total_calls": 456,
                    "user_defined_methods": 89,
                    "external_methods": 38,
                    "total_literals": 234
                }
            }
        """
        try:
            validate_session_id(session_id)

            session_manager = services["session_manager"]
            template_executor = services["template_query_executor"]

            session = await session_manager.get_session(session_id)
            if not session:
                raise SessionNotFoundError(f"Session {session_id} not found")

            if session.status != SessionStatus.READY.value:
                raise SessionNotReadyError(f"Session is in '{session.status}' status")

            await session_manager.touch_session(session_id)

            # Execute template query
            result = await template_executor.execute_template_query(
                session_id=session_id,
                category="analysis",
                template_name="codebase_summary",
                params={},
                timeout=30,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            output = _extract_output(result.data)

            return {"success": True, "summary": {"output": output}}

        except (SessionNotFoundError, SessionNotReadyError, ValidationError) as e:
            logger.error(f"Error getting codebase summary: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    @mcp.tool()
    async def get_code_snippet(
        session_id: str, filename: str, start_line: int, end_line: int
    ) -> Dict[str, Any]:
        """
        Retrieve a code snippet from a specific file with line range.

        Get the source code from a file between specified start and end line numbers.
        Useful for examining specific parts of the codebase.

        Args:
            session_id: The session ID from create_cpg_session
            filename: Name of the file to retrieve code from (relative to source root)
            start_line: Starting line number (1-indexed)
            end_line: Ending line number (1-indexed, inclusive)

        Returns:
            {
                "success": true,
                "filename": "main.c",
                "start_line": 10,
                "end_line": 20,
                "code": "example code here"
            }
        """
        try:
            validate_session_id(session_id)

            if start_line < 1 or end_line < start_line:
                raise ValidationError(
                    "Invalid line range: start_line must be >= 1 and end_line >= start_line"
                )

            session_manager = services["session_manager"]

            session = await session_manager.get_session(session_id)
            if not session:
                raise SessionNotFoundError(f"Session {session_id} not found")

            if session.status != SessionStatus.READY.value:
                raise SessionNotReadyError(f"Session is in '{session.status}' status")

            await session_manager.touch_session(session_id)

            # Get playground path
            playground_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "playground")
            )

            # Get source directory from session
            if session.source_type == "github":
                from .core_tools import get_cpg_cache_key
                cpg_cache_key = get_cpg_cache_key(
                    session.source_type, session.source_path, session.language
                )
                source_dir = os.path.join(playground_path, "codebases", cpg_cache_key)
            else:
                source_path = session.source_path
                if not os.path.isabs(source_path):
                    source_path = os.path.abspath(source_path)
                source_dir = source_path

            # Construct full file path
            file_path = os.path.join(source_dir, filename)

            # Check if file exists
            if not os.path.exists(file_path):
                raise ValidationError(f"File '{filename}' not found in source directory")

            if not os.path.isfile(file_path):
                raise ValidationError(f"'{filename}' is not a file")

            # Read the file
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            # Validate line numbers
            total_lines = len(lines)
            if start_line > total_lines:
                raise ValidationError(
                    f"start_line {start_line} exceeds file length {total_lines}"
                )

            if end_line > total_lines:
                end_line = total_lines

            # Extract the code snippet (lines are 0-indexed in the list)
            code_lines = lines[start_line - 1 : end_line]
            code = "".join(code_lines)

            return {
                "success": True,
                "filename": filename,
                "start_line": start_line,
                "end_line": end_line,
                "code": code,
            }

        except (SessionNotFoundError, SessionNotReadyError, ValidationError) as e:
            logger.error(f"Error getting code snippet: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }

    @mcp.tool()
    async def find_bounds_checks(
        session_id: str, buffer_access_location: str
    ) -> Dict[str, Any]:
        """
        Find bounds checks near buffer access.

        Verify if buffer accesses have corresponding bounds checks by analyzing
        comparison operations involving the index variable.

        Args:
            session_id: The session ID from create_cpg_session
            buffer_access_location: Location of buffer access in format "filename:line"

        Returns:
            {
                "success": true,
                "buffer_access": {
                    "line": 3393,
                    "code": "buf[len++] = c",
                    "buffer": "buf",
                    "index": "len++"
                },
                "bounds_checks": [...],
                "check_before_access": false,
                "check_after_access": true
            }
        """
        try:
            validate_session_id(session_id)

            # Parse the buffer access location
            if ":" not in buffer_access_location:
                raise ValidationError(
                    "buffer_access_location must be in format 'filename:line'"
                )

            filename, line_str = buffer_access_location.rsplit(":", 1)
            try:
                line_num = int(line_str)
            except ValueError:
                raise ValidationError(f"Invalid line number: {line_str}")

            session_manager = services["session_manager"]
            query_executor = services["query_executor"]

            session = await session_manager.get_session(session_id)
            if not session:
                raise SessionNotFoundError(f"Session {session_id} not found")

            if session.status != SessionStatus.READY.value:
                raise SessionNotReadyError(f"Session is in '{session.status}' status")

            await session_manager.touch_session(session_id)

            # For bounds checks, we need to use inline Scala because of complex JSON escaping
            query_template = r"""{
def escapeJson(s: String): String = {
s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
}
val bufferAccessOpt = cpg.call.name("<operator>.indirectIndexAccess").where(_.file.name(".*FILENAME_PLACEHOLDER")).lineNumber(LINE_NUM_PLACEHOLDER).headOption
bufferAccessOpt match {
case Some(bufferAccess) =>
val accessLine = bufferAccess.lineNumber.getOrElse(0)
val args = bufferAccess.argument.l
val bufferName = if (args.nonEmpty) args.head.code else "unknown"
val indexExpr = if (args.size > 1) args.last.code else "unknown"
val indexVar = indexExpr.replaceAll("[^a-zA-Z0-9_].*", "")
val method = bufferAccess.method
val comparisons = method.call.name("<operator>.(lessThan|greaterThan|lessEqualsThan|greaterEqualsThan)").filter { cmp => val args = cmp.argument.code.l; args.exists(_.contains(indexVar)) }.l
val boundsChecksJson = comparisons.map { cmp =>
val cmpLine = cmp.lineNumber.getOrElse(0)
val position = if (cmpLine < accessLine) "BEFORE_ACCESS" else if (cmpLine > accessLine) "AFTER_ACCESS" else "SAME_LINE"
val args = cmp.argument.l
val leftArg = if (args.nonEmpty) args.head.code else "?"
val rightArg = if (args.size > 1) args.last.code else "?"
val operator = cmp.name match { case "<operator>.lessThan" => "<"; case "<operator>.greaterThan" => ">"; case "<operator>.lessEqualsThan" => "<="; case "<operator>.greaterEqualsThan" => ">="; case _ => "?" }
"{\"line\":" + cmpLine + ",\"code\":\"" + escapeJson(cmp.code) + "\",\"checked_variable\":\"" + escapeJson(leftArg) + "\",\"bound\":\"" + escapeJson(rightArg) + "\",\"operator\":\"" + operator + "\",\"position\":\"" + position + "\"}"
}.mkString(",")
val checkBefore = comparisons.exists { cmp => val cmpLine = cmp.lineNumber.getOrElse(0); cmpLine < accessLine }
val checkAfter = comparisons.exists { cmp => val cmpLine = cmp.lineNumber.getOrElse(0); cmpLine > accessLine }
"{\"success\":true,\"buffer_access\":{\"line\":" + accessLine + ",\"code\":\"" + escapeJson(bufferAccess.code) + "\",\"buffer\":\"" + escapeJson(bufferName) + "\",\"index\":\"" + escapeJson(indexExpr) + "\"},\"bounds_checks\":[" + boundsChecksJson + "],\"check_before_access\":" + checkBefore + ",\"check_after_access\":" + checkAfter + "}"
case None =>
"{\"success\":false,\"error\":{\"code\":\"NOT_FOUND\",\"message\":\"No buffer access found at FILENAME_PLACEHOLDER:LINE_NUM_PLACEHOLDER\"}}"
}
}"""

            query = query_template.replace("FILENAME_PLACEHOLDER", filename).replace("LINE_NUM_PLACEHOLDER", str(line_num))

            result = await query_executor.execute_query(
                session_id=session_id,
                cpg_path="/workspace/cpg.bin",
                query=query,
                timeout=30,
            )

            if not result.success:
                return {
                    "success": False,
                    "error": {"code": "QUERY_ERROR", "message": result.error},
                }

            # Return raw output
            output = _extract_output(result.data)

            return {
                "success": True,
                "output": output,
            }

        except (SessionNotFoundError, SessionNotReadyError, ValidationError) as e:
            logger.error(f"Error finding bounds checks: {e}")
            return {
                "success": False,
                "error": {"code": type(e).__name__.upper(), "message": str(e)},
            }
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            return {
                "success": False,
                "error": {"code": "INTERNAL_ERROR", "message": str(e)},
            }
