# Multi-stage Dockerfile for Threat Radar
# Production-ready container with Grype and Syft

# ============================================================================
# Stage 1: Builder - Install dependencies and compile Python packages
# ============================================================================
FROM python:3.11-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    python3-dev \
    build-base \
    curl

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements files
WORKDIR /build
COPY docker/requirements-docker.txt docker/requirements-ai-docker.txt ./
COPY pyproject.toml ./

# Install Python dependencies
# Note: Using requirements-docker.txt which excludes anchore-syft (requires CMake)
# We install Syft CLI instead in the runtime stage
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements-docker.txt && \
    pip install --no-cache-dir -r requirements-ai-docker.txt

# Copy application source
COPY threat_radar/ ./threat_radar/

# Install threat-radar package (without optional syft bindings)
RUN pip install --no-cache-dir --no-deps .

# ============================================================================
# Stage 2: Runtime - Minimal production image
# ============================================================================
FROM python:3.11-alpine

# Metadata
LABEL maintainer="Threat Radar Team <contact@threat-radar.dev>"
LABEL description="Enterprise-grade threat assessment and vulnerability analysis platform"
LABEL version="0.4.0"

# Install runtime dependencies
RUN apk add --no-cache \
    docker-cli \
    git \
    curl \
    bash \
    ca-certificates \
    && rm -rf /var/cache/apk/*

# Install Grype (vulnerability scanner)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Syft (SBOM generator)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Verify installations
RUN grype version && syft version

# Create non-root user for security and add to docker group
# Note: GID 999 is a common docker group ID, but it may vary
RUN addgroup -g 1000 threatradar && \
    adduser -D -u 1000 -G threatradar threatradar && \
    addgroup -g 999 docker 2>/dev/null || addgroup docker && \
    addgroup threatradar docker

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    GRYPE_DB_CACHE_DIR=/app/cache/grype \
    GRYPE_DB_AUTO_UPDATE=true

# Create application directories
RUN mkdir -p /app/storage/cve_storage \
             /app/storage/ai_analysis \
             /app/storage/graph_storage \
             /app/cache/grype \
             /app/logs \
             /app/sbom_storage && \
    chown -R threatradar:threatradar /app

# Set working directory
WORKDIR /app

# Copy entrypoint script with execute permissions
COPY --chmod=755 docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Note: Running as root for Docker socket access
# On macOS/Docker Desktop, the socket requires root access
# USER threatradar

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD threat-radar --help || exit 1

# Expose ports (if running as service in future)
# EXPOSE 8000

# Default entrypoint
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Default command
CMD ["threat-radar", "--help"]
