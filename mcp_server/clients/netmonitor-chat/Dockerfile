# NetMonitor Chat - Production Dockerfile
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY static/ ./static/

# Create directory for mcp_bridge.py (will be mounted)
RUN mkdir -p /app/mcp

# Environment variables with defaults
ENV OLLAMA_BASE_URL=http://host.docker.internal:11434
ENV MCP_SERVER_URL=https://soc.poort.net/mcp
ENV MCP_AUTH_TOKEN=""

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Expose port
EXPOSE 8000

# Run application
CMD ["python3", "app.py"]
