"""
MCP Tool Definitions for Joern MCP Server

Main entry point that registers all tools from separate modules
"""

from .core_tools import register_core_tools


def register_tools(mcp, services: dict):
    """Register all MCP tools with the FastMCP server"""

    # Register core tools (session management and CPG generation)
    register_core_tools(mcp, services)
