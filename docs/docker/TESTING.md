# Docker Environment Testing Guide

Complete testing reference for Threat Radar Docker deployment.

---

## Quick Start

```bash
# 1. Start interactive shell
make docker-shell

# 2. Run automated tests (inside container)
bash /app/test-commands.sh

# 3. Or run manual tests
cat /app/quick-test.sh
```

---

## Test Categories

### 1. Basic Health Checks

```bash
# Show help
tr --help

# Version info
tr --version

# Health ping (quick)
tr health ping

# Full health check
tr health check

# Verbose health check
tr health check --verbose

# Show version details
tr health version
```

**Expected Results:**
- ✓ All commands should complete without errors
- ✓ Health check should show all components as healthy (except Docker if not mounted)
- ✓ Version numbers should be displayed correctly

---

### 2. Docker Access Tests

```bash
# List Docker images
docker images

# List running containers
docker ps

# Test Grype
grype version

# Test Syft
syft version
```

**Expected Results:**
- ✓ Docker commands should work without permission errors
- ✓ Grype and Syft versions should display
- ✓ Should see your host's Docker images/containers

---

### 3. SBOM Generation

#### Test Small Image (Alpine)
```bash
tr sbom docker alpine:3.18 -o /app/sbom_storage/alpine.json

# Verify output
ls -lh /app/sbom_storage/alpine.json
tr sbom read /app/sbom_storage/alpine.json
```

**Expected Results:**
- ✓ SBOM file created (~50-100KB)
- ✓ Contains Alpine packages (apk ecosystem)
- ✓ JSON format is valid

#### Test Medium Image (Python)
```bash
tr sbom docker python:3.11-alpine -o /app/sbom_storage/python.json

# View stats
tr sbom stats /app/sbom_storage/python.json
```

**Expected Results:**
- ✓ SBOM file created (larger than Alpine)
- ✓ Contains both OS and Python packages
- ✓ Stats show package counts

#### Test Large Image (Full Python)
```bash
tr sbom docker python:3.11 -o /app/sbom_storage/python-full.json

# Compare sizes
ls -lh /app/sbom_storage/python*.json
```

**Expected Results:**
- ✓ Full Python image has many more packages than Alpine version
- ✓ SBOM file is larger

---

### 4. CVE Vulnerability Scanning

#### Scan Docker Image Directly
```bash
# Basic scan
tr cve scan-image alpine:3.18 -o /tmp/scan-alpine.json

# With severity filter
tr cve scan-image alpine:3.18 --severity HIGH -o /tmp/scan-high.json

# With auto-save
tr cve scan-image busybox:latest --auto-save
```

**Expected Results:**
- ✓ Scan completes successfully
- ✓ JSON file contains vulnerability matches
- ✓ Auto-saved files appear in `/app/storage/cve_storage/`
- ✓ Severity filtering works correctly

#### Scan SBOM File
```bash
# Generate SBOM first
tr sbom docker nginx:alpine -o /app/sbom_storage/nginx.json

# Scan the SBOM
tr cve scan-sbom /app/sbom_storage/nginx.json --auto-save

# Check results
ls -lh /app/storage/cve_storage/
```

**Expected Results:**
- ✓ SBOM scan completes
- ✓ Results saved automatically
- ✓ Timestamped filename created

#### Database Operations
```bash
# Check database status
tr cve db-status

# Update database
tr cve db-update
```

**Expected Results:**
- ✓ Database status shows version and update time
- ✓ Database update completes successfully

---

### 5. Graph Operations

#### Build Vulnerability Graph
```bash
# Scan image first
tr cve scan-image alpine:3.18 --auto-save -o /tmp/scan.json

# Build graph
tr graph build /tmp/scan.json -o /tmp/graph.graphml

# Verify
ls -lh /tmp/graph.graphml
```

**Expected Results:**
- ✓ GraphML file created
- ✓ File size > 0
- ✓ Valid GraphML format

#### Query Graph
```bash
# Show statistics
tr graph query /tmp/graph.graphml --stats

# Query specific CVE (if exists)
tr graph query /tmp/graph.graphml --cve CVE-2023-1234

# Top vulnerable packages
tr graph query /tmp/graph.graphml --top-packages 10
```

**Expected Results:**
- ✓ Stats show node and edge counts
- ✓ CVE queries return relevant data
- ✓ Top packages list displayed

#### List Stored Graphs
```bash
# Build with auto-save
tr graph build /tmp/scan.json --auto-save

# List all graphs
tr graph list

# Show graph info
tr graph info /app/storage/graph_storage/*.graphml
```

**Expected Results:**
- ✓ Graphs listed with timestamps
- ✓ Info shows metadata

---

### 6. Report Generation

#### JSON Report
```bash
tr report generate /tmp/scan.json -o /tmp/report.json -f json

# View summary
cat /tmp/report.json | jq '.summary'
```

**Expected Results:**
- ✓ Valid JSON file created
- ✓ Contains summary, findings, and metadata

#### Markdown Report
```bash
tr report generate /tmp/scan.json -o /tmp/report.md -f markdown

# View
head -50 /tmp/report.md
```

**Expected Results:**
- ✓ Markdown file with proper formatting
- ✓ Tables and sections rendered correctly

#### HTML Report
```bash
tr report generate /tmp/scan.json -o /tmp/report.html -f html

# Check size
ls -lh /tmp/report.html
```

**Expected Results:**
- ✓ Standalone HTML file created
- ✓ Contains CSS styling
- ✓ Can be opened in browser

#### Dashboard Export
```bash
tr report dashboard-export /tmp/scan.json -o /tmp/dashboard.json

# View structure
cat /tmp/dashboard.json | jq 'keys'
```

**Expected Results:**
- ✓ Dashboard JSON with visualization data
- ✓ Contains charts and metrics

---

### 7. Local Project Scanning

Start shell with project mounted:
```bash
make docker-shell-project PROJECT=/path/to/your/project
```

Inside container:
```bash
# Check project is mounted
ls -la /workspace

# Generate SBOM from local directory
tr sbom generate /workspace -o /app/sbom_storage/my-project.json

# View stats
tr sbom stats /app/sbom_storage/my-project.json

# Scan for vulnerabilities
tr cve scan-sbom /app/sbom_storage/my-project.json --auto-save

# Check results
ls -lh /app/storage/cve_storage/
```

**Expected Results:**
- ✓ Project directory visible at `/workspace`
- ✓ SBOM generated from local files
- ✓ Scan completes successfully
- ✓ Results saved

---

### 8. File System Access

```bash
# Storage directory
ls -la /app/storage/
ls -la /app/storage/cve_storage/
ls -la /app/storage/ai_analysis/
ls -la /app/storage/graph_storage/

# SBOM storage
ls -la /app/sbom_storage/

# Cache
ls -la /app/cache/

# Test write access
echo "test" > /app/storage/test.txt
cat /app/storage/test.txt
rm /app/storage/test.txt
```

**Expected Results:**
- ✓ All directories exist and are accessible
- ✓ Can read and write files
- ✓ Permissions are correct

---

### 9. Multiple Image Format Tests

```bash
# Lightweight images
tr cve scan-image alpine:3.18 --auto-save
tr cve scan-image busybox:latest --auto-save

# Language runtimes
tr cve scan-image python:3.11-alpine --auto-save
tr cve scan-image node:20-alpine --auto-save
tr cve scan-image golang:1.21-alpine --auto-save

# Application images
tr cve scan-image nginx:alpine --auto-save
tr cve scan-image redis:alpine --auto-save
tr cve scan-image postgres:16-alpine --auto-save

# Check all results
ls -lh /app/storage/cve_storage/
```

**Expected Results:**
- ✓ All scans complete successfully
- ✓ Different vulnerability counts per image
- ✓ All results saved correctly

---

### 10. Advanced Operations

#### Compare SBOMs
```bash
tr sbom docker alpine:3.17 -o /tmp/alpine-3.17.json
tr sbom docker alpine:3.18 -o /tmp/alpine-3.18.json

tr sbom compare /tmp/alpine-3.17.json /tmp/alpine-3.18.json
```

**Expected Results:**
- ✓ Shows added, removed, and updated packages
- ✓ Version differences highlighted

#### Search in SBOM
```bash
tr sbom search /app/sbom_storage/alpine.json openssl
tr sbom search /app/sbom_storage/python.json pip
```

**Expected Results:**
- ✓ Matching packages displayed
- ✓ Version information shown

#### List Components
```bash
tr sbom components /app/sbom_storage/python.json
tr sbom components /app/sbom_storage/python.json --type library
tr sbom components /app/sbom_storage/python.json --language python
```

**Expected Results:**
- ✓ Component list displayed
- ✓ Filtering works correctly

#### Export to CSV
```bash
tr sbom export /app/sbom_storage/alpine.json -o /tmp/packages.csv -f csv

head -10 /tmp/packages.csv
```

**Expected Results:**
- ✓ CSV file created
- ✓ Proper CSV format with headers

---

## Automated Test Suite

Run the full automated test suite:

```bash
# Inside container
bash docker/test-commands.sh
```

This will run all tests and provide a summary:
- Total tests run
- Passed count
- Failed count
- Detailed logs in `/tmp/test_output_*.log`

---

## Environment Variable Tests

```bash
# Check default variables
echo "LOG_LEVEL=${LOG_LEVEL:-INFO}"
echo "STORAGE_PATH=${STORAGE_PATH:-/app/storage}"
echo "AI_PROVIDER=${AI_PROVIDER:-not set}"

# Check cache configuration
echo "GRYPE_DB_CACHE_DIR=${GRYPE_DB_CACHE_DIR}"
```

**Expected Results:**
- ✓ All environment variables set correctly
- ✓ Defaults apply when not set

---

## Troubleshooting Failed Tests

### Docker Access Fails
```bash
# Check Docker socket
ls -l /var/run/docker.sock

# Test Docker directly
docker ps
```

**Fix:** Ensure socket is mounted and container runs as root

### SBOM Generation Fails
```bash
# Check Syft
syft version

# Test Syft directly
syft alpine:3.18 -o json
```

**Fix:** Ensure Syft CLI is installed correctly

### CVE Scanning Fails
```bash
# Check Grype
grype version

# Check database
grype db status

# Update database
grype db update
```

**Fix:** Update Grype database or check network connectivity

### Storage Access Fails
```bash
# Check permissions
ls -la /app/

# Test write access
touch /app/storage/test.txt
rm /app/storage/test.txt
```

**Fix:** Ensure volumes are mounted correctly

---

## Test Results Reference

### Expected File Sizes

| File Type | Typical Size | Location |
|-----------|-------------|----------|
| Alpine SBOM | 50-100 KB | `/app/sbom_storage/` |
| Python SBOM | 200-500 KB | `/app/sbom_storage/` |
| CVE Scan Result | 50-500 KB | `/app/storage/cve_storage/` |
| Graph File | 100-1000 KB | `/app/storage/graph_storage/` |
| HTML Report | 20-100 KB | Custom location |

### Expected Command Times

| Operation | Typical Duration |
|-----------|-----------------|
| Health Check | < 1 second |
| SBOM Generation (Alpine) | 5-10 seconds |
| CVE Scan (Alpine) | 10-20 seconds |
| Graph Build | 2-5 seconds |
| Report Generation | 1-3 seconds |

---

## Success Criteria

A successful test run should show:
- ✅ All health checks pass
- ✅ Docker access works (can run `docker ps`)
- ✅ SBOM generation completes for all image types
- ✅ CVE scanning finds vulnerabilities
- ✅ Graph operations complete successfully
- ✅ Reports generate in all formats
- ✅ File system access works correctly
- ✅ Local project scanning works (if mounted)

---

## Quick Test Checklist

```bash
# Minimal smoke test (5 minutes)
tr health check ✓
tr sbom docker alpine:3.18 -o /tmp/test.json ✓
tr cve scan-sbom /tmp/test.json ✓
docker ps ✓

# If all pass, environment is working correctly!
```
