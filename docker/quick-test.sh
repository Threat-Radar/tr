#!/bin/bash
# Quick Test Commands for Threat Radar Docker
# Copy and paste these commands one by one in the Docker shell

echo "==========================================="
echo "  Threat Radar - Quick Test Commands"
echo "==========================================="
echo ""
echo "Run these commands inside: make docker-shell"
echo ""

cat << 'EOF'

# ============================================================================
# 1. BASIC TESTS
# ============================================================================

# Check help
threat-radar --help

# Health check
threat-radar health check

# Check Docker access
docker ps

# ============================================================================
# 2. SBOM GENERATION (Quick)
# ============================================================================

# Small image - Alpine
threat-radar sbom docker alpine:3.18 -o /app/sbom_storage/alpine.json

# View SBOM
threat-radar sbom read /app/sbom_storage/alpine.json

# SBOM stats
threat-radar sbom stats /app/sbom_storage/alpine.json

# ============================================================================
# 3. CVE SCANNING (Quick)
# ============================================================================

# Scan Alpine
threat-radar cve scan-image alpine:3.18 -o /tmp/alpine-scan.json

# Scan with severity filter
threat-radar cve scan-image alpine:3.18 --severity HIGH -o /tmp/alpine-high.json

# Scan SBOM
threat-radar cve scan-sbom /app/sbom_storage/alpine.json --auto-save

# ============================================================================
# 4. GRAPH OPERATIONS
# ============================================================================

# Build graph
threat-radar graph build /tmp/alpine-scan.json -o /tmp/alpine-graph.graphml

# Query graph
threat-radar graph query /tmp/alpine-graph.graphml --stats

# ============================================================================
# 5. REPORTS
# ============================================================================

# Generate JSON report
threat-radar report generate /tmp/alpine-scan.json -o /tmp/report.json

# Generate HTML report
threat-radar report generate /tmp/alpine-scan.json -o /tmp/report.html -f html

# Dashboard data
threat-radar report dashboard-export /tmp/alpine-scan.json -o /tmp/dashboard.json

# ============================================================================
# 6. TEST MULTIPLE IMAGES
# ============================================================================

# Python image
threat-radar sbom docker python:3.11-alpine -o /app/sbom_storage/python.json
threat-radar cve scan-sbom /app/sbom_storage/python.json --auto-save

# Nginx
threat-radar sbom docker nginx:alpine -o /app/sbom_storage/nginx.json
threat-radar cve scan-sbom /app/sbom_storage/nginx.json --auto-save

# BusyBox (very small)
threat-radar sbom docker busybox:latest -o /app/sbom_storage/busybox.json

# ============================================================================
# 7. LOCAL PROJECT SCANNING
# ============================================================================

# If you mounted a project with: make docker-shell-project PROJECT=/path
# The project will be at /workspace

# Generate SBOM from local project
threat-radar sbom generate /workspace -o /app/sbom_storage/my-project.json

# Scan the SBOM
threat-radar cve scan-sbom /app/sbom_storage/my-project.json --auto-save

# View results
ls -lh /app/storage/cve_storage/

# ============================================================================
# 8. ADVANCED OPERATIONS
# ============================================================================

# Compare SBOMs
threat-radar sbom compare /app/sbom_storage/alpine.json /app/sbom_storage/python.json

# Search in SBOM
threat-radar sbom search /app/sbom_storage/python.json openssl

# List components
threat-radar sbom components /app/sbom_storage/python.json

# Export to CSV
threat-radar sbom export /app/sbom_storage/alpine.json -o /tmp/packages.csv -f csv

# ============================================================================
# 9. CHECK RESULTS
# ============================================================================

# List all generated SBOMs
ls -lh /app/sbom_storage/

# List all CVE scan results
ls -lh /app/storage/cve_storage/

# List graphs
ls -lh /app/storage/graph_storage/

# View a scan result
cat /tmp/alpine-scan.json | jq '.matches | length'

# ============================================================================
# 10. CLEANUP (Optional)
# ============================================================================

# Clean up test files
rm -f /tmp/*.json /tmp/*.html /tmp/*.graphml

# Exit container
exit

EOF
