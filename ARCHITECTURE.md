# Architecture - Joern-MCP Server

## Overview

Joern-MCP Server is a production-ready MCP (Model Context Protocol) server for static code analysis using Joern's Code Property Graph (CPG) technology. The architecture emphasizes simplicity, reliability, and cross-platform compatibility through a single-container design with HTTP-based query execution.

## System Architecture

### Single Container Design

The entire system runs in one Docker container with three co-located services:

```
┌─────────────────────────────────────┐
│     Single Joern-MCP Container      │
├─────────────────────────────────────┤
│                                     │
│  ┌─────────────────────────────┐   │
│  │    MCP Server (Port 4242)   │   │
│  │  - Tool registration        │   │
│  │  - Tool execution           │   │
│  │  - Session management       │   │
│  └──────────┬────────────────┬─┘   │
│             │                │     │
│  ┌──────────▼──┐  ┌─────────▼────┐ │
│  │ Joern HTTP  │  │    Redis     │ │
│  │   Server    │  │  (Port 6379) │ │
│  │(Port 8080)  │  │              │ │
│  │             │  │  - Sessions  │ │
│  │ - Query     │  │  - Cache     │ │
│  │   execution │  │  - State     │ │
│  │ - CPG       │  │              │ │
│  │   analysis  │  └──────────────┘ │
│  └─────────────┘                    │
│                                     │
│  ┌─────────────────────────────┐   │
│  │   /playground (Volume)      │   │
│  │   - /codebases/{session_id} │   │
│  │   - /cpgs/{session_id}      │   │
│  │   - /temp/{session_id}      │   │
│  │   - /logs                   │   │
│  └─────────────────────────────┘   │
│                                     │
└─────────────────────────────────────┘
```

## Core Components

### 1. MCP Server (`main.py`)

**Responsibility:** FastMCP server initialization and lifecycle management

**Features:**
- Async lifespan management (startup/shutdown)
- Service initialization and cleanup
- HTTP endpoints for health checks
- Tool registration

**Endpoints:**
- `GET /health` - Server health status
- `GET /` - Server information
- `POST /mcp` - MCP protocol endpoint

### 2. Query Executor (`src/services/query_executor.py`)

**Responsibility:** Execute CPGQL queries against Joern via HTTP API

**Key Methods:**
- `execute_query()` - Synchronous query execution
- `execute_query_async()` - Asynchronous query execution  
- `_execute_query_via_http()` - HTTP client integration
- `get_query_status()` - Get query status
- `get_query_result()` - Retrieve query results

**Features:**
- Stateless query execution (no Docker exec)
- Query result caching via Redis
- Query status tracking
- Support for limit/offset pagination
- Automatic JSON output normalization

**Query Normalization:**
```python
# Input:  "cpg.method.name"
# Output: "cpg.method.name.toJsonPretty"
# With pagination: "cpg.method.name.drop(5).take(10).toJsonPretty"
```

### 3. HTTP Client (`src/utils/http_client.py`)

**Responsibility:** Communication with Joern HTTP server

**API Integration:**
- Endpoint: `POST http://127.0.0.1:8080/query`
- Request format: `{"query": "cpg.method.toJsonPretty"}`
- Response format: JSON array of results

**Key Methods:**
- `execute_query()` - Send query to Joern
- `parse_response()` - Parse and validate response
- `_check_health()` - Health check on startup

### 4. CPG Generator (`src/services/cpg_generator.py`)

**Responsibility:** Generate Code Property Graphs from source code

**Implementation:**
- Uses universal `joern-parse` command (not per-language commands)
- Automatic language detection  
- Subprocess-based execution (not Docker-dependent)
- Output to `/playground/cpgs/{session_id}/cpg.bin`

**Command:**
```bash
joern-parse /path/to/source -o /playground/cpgs/{session_id}/cpg.bin
```

**Key Methods:**
- `generate_cpg()` - Generate CPG using joern-parse
- `_validate_cpg_async()` - Validate generated CPG file
- `_exec_command_async()` - Async subprocess execution

### 5. Session Manager (`src/services/session_manager.py`)

**Responsibility:** Session lifecycle and metadata management

**Key Methods:**
- `create_session()` - Create new analysis session
- `get_session()` - Retrieve session metadata
- `update_session()` - Update session state
- `cleanup_session()` - Clean up session resources
- `cleanup_idle_sessions()` - Auto-cleanup old sessions

**Session Model:**
```python
@dataclass
class Session:
    id: str                    # Unique session ID
    source_type: str           # "github" or "local"  
    source_path: str           # Repository URL or local path
    language: str              # Programming language
    status: str                # INITIALIZING, GENERATING, READY, ERROR
    cpg_path: str              # Path to generated CPG
    created_at: datetime       # Creation timestamp
    last_accessed: datetime    # Last access timestamp
    error_message: str         # Error description
    metadata: dict             # Custom metadata
```

### 6. Tools (`src/tools/`)

**Responsibility:** MCP tool implementations

**Tool Categories:**

#### Core Tools (`core_tools.py`)
- `create_cpg_session` - Create analysis session
- `list_sessions` - List all sessions
- `get_session_status` - Get session metadata
- `close_session` - Close and cleanup
- `cleanup_sessions` - Batch cleanup

#### Code Browsing (`code_browsing_tools.py`)
- `list_methods` - List methods in CPG
- `find_calls` - Find function calls
- `get_code_snippet` - Get source code
- `call_graph` - Generate call graphs

#### Taint Analysis (`taint_analysis_tools.py`)
- `find_sources` - Identify data sources
- `find_sinks` - Identify data sinks
- `trace_flow` - Trace data flows

## Data Flow

### Query Execution

```
Client Request
    ↓
Tool Execution
    ↓
Session Manager (get session)
    ↓
Query Executor
    ├─ Check Redis cache
    ├─ Normalize query
    └─ Execute via HTTP
        ↓
    HTTP Client
        ↓
    Joern HTTP Server (Port 8080)
    ├─ Load CPG if needed
    ├─ Execute CPGQL
    └─ Return JSON
        ↓
    Parse Response
        ↓
    Cache in Redis
        ↓
    Return to Client
```

### CPG Generation

```
create_cpg_session Tool
    ↓
Session Manager (create)
    ↓
Git Manager (clone if GitHub)
    ↓
CPG Generator
    ├─ Create playground directory
    ├─ Execute: joern-parse /source -o /cpg
    ├─ Validate CPG file
    ├─ Update session status
    └─ Cache CPG
        ↓
Return session_id to client
```

## Storage Structure

### Playground Directory

```
/playground/
├── codebases/
│   └── {session_id}/
│       ├── main/
│       ├── src/
│       └── ... (cloned repository or local source)
├── cpgs/
│   └── {session_id}/
│       └── cpg.bin (Code Property Graph)
├── temp/
│   └── {session_id}/
│       └── (temporary files, cache)
└── logs/
    ├── joern-server.log
    └── mcp-server.log
```

**Mount:** Docker volume `-v $(pwd)/playground:/playground`

## Configuration

### config.yaml

```yaml
server:
  host: "127.0.0.1"
  port: 4242
  log_level: "INFO"

container:
  name: "joern-mcp-server"
  redis_port: 6379
  joern_http_port: 8080

joern:
  http_host: "127.0.0.1"
  http_port: 8080
  http_timeout: 30

storage:
  playground_root: "/playground"
  codebases_dir: "/playground/codebases"
  cpgs_dir: "/playground/cpgs"
  temp_dir: "/playground/temp"

query:
  timeout: 30
  cache_enabled: true
  cache_ttl: 300

cpg:
  generation_timeout: 600
  max_repo_size_mb: 500

redis:
  host: "127.0.0.1"
  port: 6379

sessions:
  max_concurrent: 10
  ttl: 3600
```

## Key Design Decisions

### 1. Single Container
**Why:** Simplifies deployment, eliminates orchestration
**Benefit:** One service to manage, consistent environment

### 2. HTTP Query Execution  
**Why:** Stateless, leverages Joern's native API
**Benefit:** No Docker exec overhead, better performance

### 3. joern-parse for CPG
**Why:** Universal command, auto language detection
**Benefit:** Simpler code, fewer special cases

### 4. Subprocess instead of Docker
**Why:** Simpler, fewer dependencies
**Benefit:** Lighter, faster CPG generation

### 5. Playground Directory Model
**Why:** Cross-platform compatible paths
**Benefit:** Works on Windows/Mac/Linux

## Performance

### Query Execution
- Cold query (CPG load): 1-5 seconds
- Warm query (cached): 100-500ms
- Cache hit: 10-50ms

### CPG Generation
- Small (< 10K files): 30-60s
- Medium (10-50K): 2-5m
- Large (50K+): 5-30+ minutes

### Memory
- Joern HTTP: 1-4GB
- MCP Server: 100-200MB  
- Redis: 10-100MB
- Total: 2-5GB

## Deployment

### Docker

```bash
# Build
docker build -f Dockerfile.joern -t joern-mcp:latest .

# Run
docker run -d \
  --name joern-mcp \
  -p 4242:4242 \
  -v $(pwd)/playground:/playground \
  joern-mcp:latest

# Verify
curl http://localhost:4242/health
```

### Docker Compose

```yaml
version: "3.9"
services:
  joern-mcp:
    build:
      context: .
      dockerfile: Dockerfile.joern
    ports:
      - "4242:4242"
    volumes:
      - ./playground:/playground
    environment:
      LOG_LEVEL: "INFO"
```

## Error Handling

### Query Errors

| Error | Cause | Fix |
|-------|-------|-----|
| CPG not loaded | Session not ready | Wait for READY status |
| Syntax error | Invalid CPGQL | Fix query syntax |
| Timeout | Complex query | Increase timeout |
| Network error | Connection lost | Retry or restart |

### CPG Errors

| Error | Cause | Fix |
|-------|-------|-----|
| Unsupported | Language not supported | Use different language |
| Out of memory | Large codebase | Increase memory |
| Invalid CPG | Corrupted generation | Retry generation |
| Timeout | Long processing | Increase timeout |

## Monitoring

### Health Check
```bash
curl http://localhost:4242/health
```

### Logs
- MCP: `/playground/logs/mcp-server.log`
- Joern: `/playground/logs/joern-server.log`

### Metrics
- Session count
- Query execution time
- Cache hit rate
- CPG generation time
- Memory usage

## Related Files

- **Entry point:** `main.py`
- **Services:** `src/services/`
- **Tools:** `src/tools/`
- **Config:** `config.yaml`, `src/constants.py`
- **Models:** `src/models.py`
- **Utilities:** `src/utils/`
- **Queries:** `queries/`
- **Docker:** `Dockerfile.joern`, `entrypoint.sh`
