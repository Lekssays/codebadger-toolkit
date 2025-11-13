#!/bin/bash
# Entrypoint script for joern-mcp all-in-one container
# Starts Redis, Joern HTTP server, and MCP server

set -e

echo "Starting joern-mcp all-in-one container..."

# Create necessary directories
mkdir -p /playground/codebases
mkdir -p /playground/cpgs
mkdir -p /playground/temp
mkdir -p /playground/logs

echo "Directories created: /playground/codebases, /playground/cpgs, /playground/temp, /playground/logs"

# Start Redis in the background
echo "Starting Redis..."
redis-server --daemonize yes --port 6379 --bind 127.0.0.1

# Wait for Redis to be ready
sleep 2
redis-cli ping > /dev/null || {
    echo "ERROR: Redis failed to start"
    exit 1
}
echo "Redis started successfully"

# Start Joern HTTP server in the background
echo "Starting Joern HTTP server on port 8080..."
joern --server --server-port 8080 > /playground/logs/joern-server.log 2>&1 &
JOERN_PID=$!

# Wait for Joern HTTP server to be ready (check a few times with delay)
echo "Waiting for Joern HTTP server to be ready..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8080/health > /dev/null 2>&1; then
        echo "Joern HTTP server is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "ERROR: Joern HTTP server failed to start within 30 seconds"
        kill $JOERN_PID 2>/dev/null || true
        exit 1
    fi
    sleep 1
done

# Start MCP server (blocking, runs in foreground)
echo "Starting MCP server on port 4242..."
cd /app
exec python main.py
