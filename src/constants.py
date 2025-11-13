"""
Centralized constants for joern-mcp server

This module defines all hardcoded strings, paths, and configuration values
to eliminate magic strings throughout the codebase.
"""

# ============================================================================
# CONTAINER & PLAYGROUND PATHS (all paths inside container/Docker)
# ============================================================================

# Root playground directory - all codebases, CPGs, and temp files go here
PLAYGROUND_ROOT = "/playground"

# Subdirectories within playground
CODEBASES_DIR = f"{PLAYGROUND_ROOT}/codebases"
CPGS_DIR = f"{PLAYGROUND_ROOT}/cpgs"
TEMP_DIR = f"{PLAYGROUND_ROOT}/temp"
QUERIES_DIR = f"{PLAYGROUND_ROOT}/queries"
LOGS_DIR = f"{PLAYGROUND_ROOT}/logs"

# ============================================================================
# JOERN CONFIGURATION
# ============================================================================

# Joern executable and commands
JOERN_BINARY = "joern"
JOERN_PARSE_CMD = "joern-parse"
JOERN_HTTP_SERVER_CMD = "joern"

# HTTP server configuration
JOERN_HTTP_PORT = 8080
JOERN_HTTP_HOST = "127.0.0.1"
JOERN_HTTP_TIMEOUT = 300  # 5 minutes for large CPG loading

# CPG file naming
CPG_FILENAME = "cpg.bin"
CPG_EXTENSION = ".bin"

# Default memory settings (can be overridden in config)
DEFAULT_JAVA_OPTS = "-Xmx4G -Xms2G -XX:+UseG1GC -Dfile.encoding=UTF-8"

# ============================================================================
# FILE EXTENSIONS & PATTERNS
# ============================================================================

SCALA_SCRIPT_EXT = ".sc"
JSON_OUTPUT_EXT = ".json"
QUERY_SCRIPT_PREFIX = "query_"

# File patterns for query execution
QUERY_OUTPUT_PATTERN = f"{QUERY_SCRIPT_PREFIX}{{query_id}}{JSON_OUTPUT_EXT}"

# ============================================================================
# SESSION & QUERY CONFIGURATION
# ============================================================================

# Session status values
SESSION_STATUS_INITIALIZING = "initializing"
SESSION_STATUS_GENERATING = "generating"
SESSION_STATUS_READY = "ready"
SESSION_STATUS_ERROR = "error"

# Query status values
QUERY_STATUS_PENDING = "pending"
QUERY_STATUS_RUNNING = "running"
QUERY_STATUS_COMPLETED = "completed"
QUERY_STATUS_FAILED = "failed"

# Source types
SOURCE_TYPE_LOCAL = "local"
SOURCE_TYPE_GITHUB = "github"

# ============================================================================
# DOCKER CONFIGURATION
# ============================================================================

# Single container name
JOERN_CONTAINER_NAME = "joern-mcp-server"
JOERN_IMAGE_NAME = "joern-mcp:latest"

# Default container settings
DEFAULT_CONTAINER_MEMORY = "4g"
DEFAULT_CONTAINER_CPUS = 4

# ============================================================================
# REDIS CONFIGURATION
# ============================================================================

# Redis defaults (can be overridden in config)
DEFAULT_REDIS_HOST = "localhost"
DEFAULT_REDIS_PORT = 6379
DEFAULT_REDIS_DB = 0

# ============================================================================
# QUERY SCRIPT DIRECTORIES
# ============================================================================

# Query script locations within the image
QUERY_SCRIPTS_BASE = "/app/queries"
QUERY_CORE_SCRIPTS = f"{QUERY_SCRIPTS_BASE}/core"
QUERY_TAINT_SCRIPTS = f"{QUERY_SCRIPTS_BASE}/taint"
QUERY_ANALYSIS_SCRIPTS = f"{QUERY_SCRIPTS_BASE}/analysis"

# ============================================================================
# API ENDPOINTS
# ============================================================================

# Joern HTTP API endpoints
JOERN_QUERY_ENDPOINT = "/query"
JOERN_HEALTH_ENDPOINT = "/health"

# MCP server endpoints
MCP_HEALTH_ENDPOINT = "/health"
MCP_ROOT_ENDPOINT = "/"

# ============================================================================
# TIMEOUTS & LIMITS
# ============================================================================

# Query execution
DEFAULT_QUERY_TIMEOUT = 30  # seconds
DEFAULT_QUERY_LIMIT = 150   # max results

# CPG generation
DEFAULT_CPG_GENERATION_TIMEOUT = 600  # 10 minutes
DEFAULT_CPG_MAX_REPO_SIZE_MB = 500

# Session management
DEFAULT_SESSION_TTL = 3600  # 1 hour
DEFAULT_SESSION_IDLE_TIMEOUT = 1800  # 30 minutes
DEFAULT_MAX_CONCURRENT_SESSIONS = 50

# ============================================================================
# LANGUAGE IDENTIFIERS
# ============================================================================

SUPPORTED_LANGUAGES = [
    "java",
    "c",
    "cpp",
    "javascript",
    "python",
    "go",
    "kotlin",
    "csharp",
    "ghidra",
    "jimple",
    "php",
    "ruby",
    "swift",
]

# Languages that support exclusion patterns during CPG generation
LANGUAGES_WITH_EXCLUSIONS = [
    "c",
    "cpp",
    "java",
    "javascript",
    "python",
    "go",
    "kotlin",
    "csharp",
    "php",
    "ruby",
]

# ============================================================================
# COMMON ERROR MESSAGES
# ============================================================================

ERROR_DOCKER_NOT_INITIALIZED = "Docker client not initialized"
ERROR_CONTAINER_NOT_FOUND = "Container not found"
ERROR_CPG_NOT_FOUND = "CPG not found for session"
ERROR_QUERY_EXECUTION_FAILED = "Query execution failed"
ERROR_CPG_GENERATION_FAILED = "CPG generation failed"
ERROR_SESSION_NOT_FOUND = "Session not found"
ERROR_INVALID_LANGUAGE = "Unsupported language"
ERROR_REPO_TOO_LARGE = "Repository size exceeds maximum limit"

# ============================================================================
# LOGGING
# ============================================================================

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DEFAULT_LOG_LEVEL = "INFO"

# ============================================================================
# VERSION
# ============================================================================

MCP_SERVER_VERSION = "0.3.0-beta"
