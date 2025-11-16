# Dockerfile for CodeBadger Toolkit Server
# Container with Joern, Python MCP server, and Redis

FROM eclipse-temurin:21-jdk-jammy

# Install system dependencies including Python 3.12 and Redis
RUN apt-get update && apt-get install -y \
    curl \
    git \
    wget \
    unzip \
    build-essential \
    software-properties-common \
    redis-server \
    libffi-dev \
    libssl-dev \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update \
    && apt-get install -y \
    python3.12 \
    python3.12-venv \
    python3.12-dev \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Set Python 3.12 as default
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1 \
    && update-alternatives --install /usr/bin/python python /usr/bin/python3.12 1

# Set Joern version
ENV JOERN_VERSION=4.0.429
ENV JOERN_HOME=/opt/joern

# Download and install Joern from joernio/joern GitHub releases
RUN mkdir -p ${JOERN_HOME} && \
    cd /tmp && \
    wget -q https://github.com/joernio/joern/releases/download/v${JOERN_VERSION}/joern-install.sh && \
    chmod +x joern-install.sh && \
    sed -i 's/sudo //g' joern-install.sh && \
    ./joern-install.sh && \
    rm -rf joern-install.sh

# Add Joern CLI tools to PATH
ENV PATH="${JOERN_HOME}/joern-cli:${JOERN_HOME}/joern-cli/bin:${PATH}"

# Create workspace and playground directories
RUN mkdir -p /workspace /playground /app

# Copy MCP server code
COPY . /app
WORKDIR /app

# Install Python dependencies
# Ensure pip/setuptools are available for python3 (pointing to 3.12)
RUN python3 -m ensurepip --upgrade || true && \
    python3 -m pip install --upgrade pip setuptools wheel && \
    python3 -m pip install --no-cache-dir -r requirements.txt && \
    python3 -m pip uninstall -y cryptography && \
    python3 -m pip install --no-cache-dir cffi cryptography

# Configure Redis to run in background
RUN mkdir -p /var/lib/redis && \
    chown redis:redis /var/lib/redis && \
    sed -i 's/^daemonize no/daemonize yes/' /etc/redis/redis.conf && \
    sed -i 's/^bind 127.0.0.1 ::1/bind 0.0.0.0/' /etc/redis/redis.conf

# Verify Joern installation
RUN joern --help

# Expose MCP server port only
EXPOSE 4242

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Start Redis in background\n\
redis-server /etc/redis/redis.conf\n\
\n\
# Wait for Redis to be ready\n\
sleep 2\n\
\n\
# Start MCP server\n\
cd /app\n\
exec python3 main.py\n\
' > /app/entrypoint.sh && chmod +x /app/entrypoint.sh

# Run entrypoint script
CMD ["/app/entrypoint.sh"]