# Dockerfile for Joern Server Container
# Contains Joern CLI and Redis for CPG generation and caching

FROM eclipse-temurin:21-jdk-jammy

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    redis-server \
    && rm -rf /var/lib/apt/lists/*

# Set Joern version
ENV JOERN_VERSION=4.0.444
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

# Create playground directory for CPG storage
RUN mkdir -p /playground

# Configure Redis to run in background and listen on all interfaces
RUN mkdir -p /var/lib/redis && \
    chown redis:redis /var/lib/redis && \
    sed -i 's/^daemonize no/daemonize yes/' /etc/redis/redis.conf && \
    sed -i 's/^bind 127.0.0.1 ::1/bind 0.0.0.0/' /etc/redis/redis.conf

# Verify Joern installation
RUN joern --help

# Expose Redis port
EXPOSE 6379

# Create entrypoint script that starts Redis
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Start Redis in background\n\
redis-server /etc/redis/redis.conf\n\
\n\
# Keep container running\n\
tail -f /dev/null\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh

# Run entrypoint script
CMD ["/entrypoint.sh"]
