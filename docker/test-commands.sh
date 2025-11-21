#!/bin/bash
# Threat Radar Docker Test Suite
# Tests all major commands in the Docker environment

set -e

echo "=========================================="
echo "  Threat Radar Docker Test Suite"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

test_count=0
pass_count=0
fail_count=0

# Function to run a test
run_test() {
    local test_name="$1"
    local command="$2"

    test_count=$((test_count + 1))
    echo -e "${YELLOW}Test $test_count:${NC} $test_name"
    echo "Command: $command"

    if eval "$command" > /tmp/test_output_$test_count.log 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}"
        pass_count=$((pass_count + 1))
    else
        echo -e "${RED}✗ FAIL${NC}"
        echo "Error output:"
        tail -5 /tmp/test_output_$test_count.log
        fail_count=$((fail_count + 1))
    fi
    echo ""
}

echo "Starting tests..."
echo ""

# ============================================================================
# 1. BASIC HEALTH CHECKS
# ============================================================================
echo "=== 1. Basic Health Checks ==="
echo ""

run_test "Show help" \
    "threat-radar --help"

run_test "Show version" \
    "threat-radar --version"

run_test "Health ping" \
    "threat-radar health ping"

run_test "Health check" \
    "threat-radar health check"

run_test "Health check verbose" \
    "threat-radar health check --verbose"

run_test "Health version" \
    "threat-radar health version"

# ============================================================================
# 2. DOCKER ACCESS
# ============================================================================
echo "=== 2. Docker Access Tests ==="
echo ""

run_test "List Docker images" \
    "docker images --format 'table {{.Repository}}:{{.Tag}}' | head -5"

run_test "Docker ps" \
    "docker ps"

run_test "Grype version" \
    "grype version"

run_test "Syft version" \
    "syft version"

# ============================================================================
# 3. SBOM GENERATION
# ============================================================================
echo "=== 3. SBOM Generation Tests ==="
echo ""

run_test "Generate SBOM from alpine:3.18" \
    "threat-radar sbom docker alpine:3.18 -o /app/sbom_storage/test_alpine.json"

run_test "Read SBOM file" \
    "threat-radar sbom read /app/sbom_storage/test_alpine.json"

run_test "SBOM stats" \
    "threat-radar sbom stats /app/sbom_storage/test_alpine.json"

run_test "List SBOM components" \
    "threat-radar sbom components /app/sbom_storage/test_alpine.json"

run_test "Search in SBOM" \
    "threat-radar sbom search /app/sbom_storage/test_alpine.json openssl"

run_test "List stored SBOMs" \
    "threat-radar sbom list"

# ============================================================================
# 4. CVE SCANNING
# ============================================================================
echo "=== 4. CVE Scanning Tests ==="
echo ""

run_test "Scan Docker image (alpine:3.18)" \
    "threat-radar cve scan-image alpine:3.18 -o /tmp/test_scan_alpine.json"

run_test "Scan SBOM file" \
    "threat-radar cve scan-sbom /app/sbom_storage/test_alpine.json -o /tmp/test_scan_sbom.json"

run_test "Scan with severity filter (HIGH)" \
    "threat-radar cve scan-image alpine:3.18 --severity HIGH -o /tmp/test_scan_high.json"

run_test "Scan with auto-save" \
    "threat-radar cve scan-image busybox:latest --auto-save"

run_test "Grype database status" \
    "threat-radar cve db-status"

# ============================================================================
# 5. GRAPH OPERATIONS
# ============================================================================
echo "=== 5. Graph Operations Tests ==="
echo ""

run_test "Build graph from scan" \
    "threat-radar graph build /tmp/test_scan_alpine.json -o /tmp/test_graph.graphml"

run_test "Query graph stats" \
    "threat-radar graph query /tmp/test_graph.graphml --stats"

run_test "List stored graphs" \
    "threat-radar graph list"

run_test "Show graph info" \
    "threat-radar graph info /tmp/test_graph.graphml"

# ============================================================================
# 6. REPORT GENERATION
# ============================================================================
echo "=== 6. Report Generation Tests ==="
echo ""

run_test "Generate JSON report" \
    "threat-radar report generate /tmp/test_scan_alpine.json -o /tmp/test_report.json -f json"

run_test "Generate Markdown report" \
    "threat-radar report generate /tmp/test_scan_alpine.json -o /tmp/test_report.md -f markdown"

run_test "Generate HTML report" \
    "threat-radar report generate /tmp/test_scan_alpine.json -o /tmp/test_report.html -f html"

run_test "Dashboard export" \
    "threat-radar report dashboard-export /tmp/test_scan_alpine.json -o /tmp/test_dashboard.json"

# ============================================================================
# 7. FILE SYSTEM ACCESS
# ============================================================================
echo "=== 7. File System Access Tests ==="
echo ""

run_test "Check storage directory" \
    "ls -la /app/storage/"

run_test "Check sbom_storage directory" \
    "ls -la /app/sbom_storage/"

run_test "Check cache directory" \
    "ls -la /app/cache/"

run_test "Create test file in storage" \
    "echo 'test' > /app/storage/test.txt && cat /app/storage/test.txt"

run_test "Remove test file" \
    "rm /app/storage/test.txt"

# ============================================================================
# 8. ENVIRONMENT VARIABLES
# ============================================================================
echo "=== 8. Environment Variables Tests ==="
echo ""

run_test "Check LOG_LEVEL variable" \
    "echo \"LOG_LEVEL=\${LOG_LEVEL:-INFO}\""

run_test "Check STORAGE_PATH variable" \
    "echo \"STORAGE_PATH=\${STORAGE_PATH:-/app/storage}\""

run_test "Check AI_PROVIDER variable" \
    "echo \"AI_PROVIDER=\${AI_PROVIDER:-not set}\""

# ============================================================================
# 9. MULTIPLE IMAGE FORMATS
# ============================================================================
echo "=== 9. Multiple Image Format Tests ==="
echo ""

run_test "Scan lightweight image (busybox)" \
    "threat-radar cve scan-image busybox:latest -o /tmp/test_busybox.json"

run_test "Generate SBOM for Python image" \
    "threat-radar sbom docker python:3.11-alpine -o /tmp/test_python_sbom.json"

run_test "Scan nginx image" \
    "threat-radar cve scan-image nginx:alpine -o /tmp/test_nginx.json"

# ============================================================================
# 10. ADVANCED OPERATIONS
# ============================================================================
echo "=== 10. Advanced Operations Tests ==="
echo ""

run_test "Generate SBOM with different format" \
    "threat-radar sbom docker redis:alpine -o /tmp/test_redis.json"

run_test "Compare two SBOMs" \
    "threat-radar sbom compare /app/sbom_storage/test_alpine.json /tmp/test_python_sbom.json"

run_test "Export SBOM to CSV" \
    "threat-radar sbom export /app/sbom_storage/test_alpine.json -o /tmp/packages.csv -f csv"

run_test "Build graph with auto-save" \
    "threat-radar graph build /tmp/test_scan_alpine.json --auto-save"

# ============================================================================
# SUMMARY
# ============================================================================
echo ""
echo "=========================================="
echo "  Test Summary"
echo "=========================================="
echo "Total tests: $test_count"
echo -e "Passed: ${GREEN}$pass_count${NC}"
echo -e "Failed: ${RED}$fail_count${NC}"
echo ""

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed. Check logs in /tmp/test_output_*.log${NC}"
    exit 1
fi
