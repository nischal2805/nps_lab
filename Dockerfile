# Multi-stage build for NetSentinel
# Base image: Python 3.12-slim for smaller footprint

# ============================================================================
# Stage 1: Builder - Install dependencies with uv
# ============================================================================
FROM python:3.12-slim AS builder

# Install uv for fast dependency resolution
RUN pip install --no-cache-dir uv

# Set working directory
WORKDIR /build

# Copy dependency files first (better layer caching)
COPY requirements.txt requirements-dev.txt pyproject.toml setup.py ./

# Create virtual environment and install dependencies
RUN uv venv /opt/venv && \
    . /opt/venv/bin/activate && \
    uv pip install -r requirements.txt

# Copy application code
COPY netsentinel/ ./netsentinel/

# Install NetSentinel package
RUN . /opt/venv/bin/activate && \
    pip install --no-cache-dir -e .


# ============================================================================
# Stage 2: Runtime - Minimal production image
# ============================================================================
FROM python:3.12-slim

# Install runtime dependencies (git for GitHub URL scanning)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        curl \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash netsentinel && \
    mkdir -p /home/netsentinel/.netsentinel/scans && \
    chown -R netsentinel:netsentinel /home/netsentinel

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application code
COPY --from=builder /build/netsentinel /app/netsentinel
COPY --from=builder /build/setup.py /build/pyproject.toml /app/

# Set working directory
WORKDIR /app

# Activate virtual environment
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV NETSENTINEL_DATA_DIR=/home/netsentinel/.netsentinel

# Switch to non-root user
USER netsentinel

# Expose dashboard port
EXPOSE 8080

# Health check for dashboard server
# Checks if the server is responsive on port 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/api/scans || exit 1

# Default entrypoint: netsentinel CLI
ENTRYPOINT ["netsentinel"]

# Default command: show help
CMD ["--help"]
