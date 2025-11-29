#!/bin/bash
set -e

# Docker entrypoint script for Threat Radar
# Handles initialization and environment setup

echo "=========================================="
echo "  Threat Radar - Starting Container"
echo "=========================================="

# Display version information
echo "Threat Radar Version: 0.4.0"
echo "Python Version: $(python --version)"
echo "Grype Version: $(grype version 2>&1 | head -n 1)"
echo "Syft Version: $(syft version 2>&1 | head -n 1)"
echo ""

# Ensure directories exist
mkdir -p /app/storage/cve_storage
mkdir -p /app/storage/ai_analysis
mkdir -p /app/storage/graph_storage
mkdir -p /app/cache/grype
mkdir -p /app/logs
mkdir -p /app/sbom_storage

# Update Grype vulnerability database if AUTO_UPDATE is enabled
if [ "${GRYPE_DB_AUTO_UPDATE:-true}" = "true" ]; then
    echo "Updating Grype vulnerability database..."
    grype db update || echo "Warning: Grype DB update failed (will continue anyway)"
    echo ""
fi

# Display configuration
echo "Configuration:"
echo "  Storage Path: ${STORAGE_PATH:-/app/storage}"
echo "  Cache Path: ${CACHE_PATH:-/app/cache}"
echo "  Log Level: ${LOG_LEVEL:-INFO}"
echo "  AI Provider: ${AI_PROVIDER:-not configured}"
echo "=========================================="
echo ""

# Execute the command passed to docker run
exec "$@"
