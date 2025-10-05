# Threat Radar CLI Examples

Complete command-line interface examples for vulnerability management.

## Table of Contents

- [Setup](#setup)
- [CVE Operations](#cve-operations)
- [Docker Analysis](#docker-analysis)
- [Vulnerability Scanning](#vulnerability-scanning)
- [Database Management](#database-management)
- [Workflows](#complete-workflows)

## Setup

### Initial Configuration

```bash
# 1. Install threat-radar
pip install -e .

# 2. Set up environment (optional but recommended)
cp .env.example .env
# Edit .env and add your NVD_API_KEY

# 3. Verify installation
threat-radar --help
tradar --help  # Shorthand alias
```

### First-Time Database Setup

```bash
# Initialize and populate CVE database
threat-radar cve update --days 30

# View database statistics
threat-radar cve stats
```

## CVE Operations

### Retrieve Specific CVEs

```bash
# Get a single CVE
threat-radar cve get CVE-2021-44228

# Get multiple CVEs
threat-radar cve get CVE-2021-44228 CVE-2021-45046

# Save to JSON file
threat-radar cve get CVE-2021-44228 -o log4shell.json

# Bypass cache and fetch fresh data
threat-radar cve get CVE-2021-44228 --no-cache
```

**Example Output:**
```
CVE-2021-44228

Severity    HIGH
CVSS Score  10.0
Published   2021-12-10
Modified    2023-12-10
CWE IDs     CWE-502, CWE-400

Description:
Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases...
```

### Search CVEs

```bash
# Search by keyword
threat-radar cve search --keyword "log4j"

# Search with severity filter
threat-radar cve search --severity CRITICAL --limit 20

# Search by CPE (Common Platform Enumeration)
threat-radar cve search --cpe "cpe:2.3:a:apache:log4j:2.14.1"

# Recent CVEs (last N days)
threat-radar cve search --days 7 --limit 50

# Complex search with output
threat-radar cve search \
  --keyword "remote code execution" \
  --severity HIGH \
  --limit 10 \
  -o rce_vulns.json
```

### Local Database Search (Faster)

```bash
# Search local database
threat-radar cve db-search --keyword "openssl"

# Filter by severity
threat-radar cve db-search --severity CRITICAL

# Filter by minimum CVSS score
threat-radar cve db-search --min-cvss 9.0

# Combined filters
threat-radar cve db-search \
  --severity HIGH \
  --min-cvss 7.5 \
  --keyword "buffer overflow" \
  --limit 20 \
  -o critical_issues.json
```

## Docker Analysis

### Image Analysis

```bash
# Analyze an image
threat-radar docker scan alpine:3.18

# Import and analyze
threat-radar docker import-image ubuntu:22.04 -o analysis.json

# List local images
threat-radar docker list-images

# List packages in image
threat-radar docker packages nginx:alpine --limit 50

# Filter packages
threat-radar docker packages ubuntu:22.04 \
  --filter openssl \
  --limit 10
```

### Python SBOM Generation

```bash
# Generate CycloneDX SBOM
threat-radar docker python-sbom python:3.11 \
  -o sbom.json \
  --format cyclonedx

# Generate CSV format
threat-radar docker python-sbom python:3.11 \
  -o packages.csv \
  --format csv

# Generate requirements.txt format
threat-radar docker python-sbom python:3.11 \
  -o requirements.txt \
  --format txt
```

## Vulnerability Scanning

### Scan Docker Images

```bash
# Basic scan
threat-radar cve scan-image alpine:3.18

# Scan with custom confidence threshold
threat-radar cve scan-image ubuntu:22.04 --confidence 0.8

# Filter by minimum severity
threat-radar cve scan-image nginx:alpine --severity HIGH

# Save detailed report
threat-radar cve scan-image ubuntu:22.04 \
  --confidence 0.7 \
  --severity CRITICAL \
  -o vulnerability_report.json
```

**Example Output:**
```
Found 143 packages

✓ Updated 1234 CVEs in local database
✓ Loaded 5000 CVEs

⚠ Found vulnerabilities in 8 packages:

openssl
  ● CVE-2023-12345 (Confidence: 95%)
    Severity: HIGH | CVSS: 8.1
    exact name match with openssl/openssl (version affected)

curl
  ● CVE-2023-67890 (Confidence: 87%)
    Severity: MEDIUM | CVSS: 5.3
    exact name match with curl/curl (version not confirmed)

Summary:
  Vulnerable packages: 8
  Total vulnerabilities: 15
```

### Batch Scanning

```bash
# Scan multiple images
for image in alpine:3.17 alpine:3.18 alpine:3.19; do
  threat-radar cve scan-image $image -o "report_${image//:/_}.json"
done

# Compare results
ls -lh report_*.json
```

## Database Management

### Update Database

```bash
# Update with recent CVEs (last 7 days)
threat-radar cve update

# Update with custom timeframe
threat-radar cve update --days 30

# Force update (bypass throttling)
threat-radar cve update --days 14 --force
```

### Database Statistics

```bash
# View database stats
threat-radar cve stats
```

**Example Output:**
```
CVE Database Statistics

Total CVEs        25,432
Last Update       2024-01-15 10:30:00

Date Range:
  Earliest CVE    2020-01-01
  Latest CVE      2024-01-15

CVEs by Severity:
  CRITICAL        2,145  (8.4%)
  HIGH            8,234  (32.4%)
  MEDIUM          11,567 (45.5%)
  LOW             3,486  (13.7%)
```

### Cache Management

```bash
# Clear all cache
threat-radar cve clear-cache --yes

# Clear cache older than 7 days
threat-radar cve clear-cache --older-than 7 --yes

# Interactive (prompts for confirmation)
threat-radar cve clear-cache
```

## Complete Workflows

### Workflow 1: Initial Setup & Scan

```bash
#!/bin/bash
# setup_and_scan.sh

# 1. Update CVE database
echo "Updating CVE database..."
threat-radar cve update --days 30

# 2. Scan image
echo "Scanning ubuntu:22.04..."
threat-radar cve scan-image ubuntu:22.04 \
  --confidence 0.7 \
  --severity HIGH \
  -o ubuntu_vulnerabilities.json

# 3. View statistics
threat-radar cve stats
```

### Workflow 2: Continuous Monitoring

```bash
#!/bin/bash
# daily_scan.sh - Run this daily via cron

DATE=$(date +%Y%m%d)
IMAGES=("nginx:alpine" "python:3.11-slim" "node:18-alpine")

# Update CVE database
threat-radar cve update --days 1 --force

# Scan each image
for IMAGE in "${IMAGES[@]}"; do
  SAFE_NAME=${IMAGE//[:\/]/_}
  threat-radar cve scan-image $IMAGE \
    --confidence 0.75 \
    -o "reports/${DATE}_${SAFE_NAME}.json"
done

# Alert on critical findings
# (Add your alerting logic here)
```

### Workflow 3: Image Comparison

```bash
#!/bin/bash
# compare_images.sh

echo "Comparing Alpine versions..."

for VERSION in 3.17 3.18 3.19; do
  echo "Scanning alpine:${VERSION}..."
  threat-radar cve scan-image alpine:${VERSION} \
    -o "alpine_${VERSION}_report.json"
done

echo "Reports generated:"
ls -lh alpine_*_report.json

# Parse and compare (example with jq)
for FILE in alpine_*_report.json; do
  VULNS=$(jq '.vulnerable_packages' $FILE)
  echo "$FILE: $VULNS vulnerable packages"
done
```

### Workflow 4: CI/CD Integration

```bash
#!/bin/bash
# ci_vulnerability_check.sh
# Exit with error if critical vulnerabilities found

IMAGE=$1
THRESHOLD=0.8

# Scan image
threat-radar cve scan-image $IMAGE \
  --confidence $THRESHOLD \
  --severity CRITICAL \
  -o scan_results.json

# Check for critical vulnerabilities
CRITICAL_COUNT=$(jq '.vulnerable_packages' scan_results.json)

if [ "$CRITICAL_COUNT" -gt 0 ]; then
  echo "❌ FAILED: $CRITICAL_COUNT critical vulnerabilities found"
  jq '.matches' scan_results.json
  exit 1
else
  echo "✓ PASSED: No critical vulnerabilities"
  exit 0
fi
```

**GitHub Actions Example:**

```yaml
# .github/workflows/vulnerability-scan.yml
name: Vulnerability Scan

on:
  push:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Threat Radar
        run: pip install threat-radar

      - name: Update CVE Database
        run: threat-radar cve update --days 30
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}

      - name: Scan Docker Image
        run: |
          threat-radar cve scan-image myapp:latest \
            --confidence 0.8 \
            --severity CRITICAL \
            -o vulnerability_report.json

      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: vulnerability-report
          path: vulnerability_report.json

      - name: Check for Critical Issues
        run: |
          CRITICAL=$(jq '.vulnerable_packages' vulnerability_report.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "Critical vulnerabilities found!"
            exit 1
          fi
```

### Workflow 5: Report Generation

```bash
#!/bin/bash
# generate_weekly_report.sh

DATE=$(date +%Y%m%d)
REPORT_DIR="reports/weekly_${DATE}"
mkdir -p $REPORT_DIR

# Update database
threat-radar cve update --days 7 --force

# Scan production images
IMAGES=(
  "prod/webapp:latest"
  "prod/api:latest"
  "prod/worker:latest"
)

echo "# Weekly Vulnerability Report - $(date)" > $REPORT_DIR/summary.md
echo "" >> $REPORT_DIR/summary.md

for IMAGE in "${IMAGES[@]}"; do
  SAFE_NAME=${IMAGE//[:\/]/_}

  # Scan
  threat-radar cve scan-image $IMAGE \
    --confidence 0.7 \
    -o "$REPORT_DIR/${SAFE_NAME}.json"

  # Add to summary
  echo "## $IMAGE" >> $REPORT_DIR/summary.md
  VULNS=$(jq -r '.vulnerable_packages' "$REPORT_DIR/${SAFE_NAME}.json")
  echo "- Vulnerable packages: $VULNS" >> $REPORT_DIR/summary.md
  echo "" >> $REPORT_DIR/summary.md
done

# Email report (example)
# mail -s "Weekly Vulnerability Report" security@company.com < $REPORT_DIR/summary.md
```

## Advanced Usage

### Custom Filtering with jq

```bash
# Get all CRITICAL CVEs for a specific package
threat-radar cve scan-image ubuntu:22.04 -o report.json
jq '.matches.openssl[] | select(.severity == "CRITICAL")' report.json

# List all unique CVE IDs
jq -r '.matches | to_entries | .[].value[].cve_id' report.json | sort -u

# Count vulnerabilities by severity
jq '.matches | to_entries | .[].value[] | .severity' report.json | \
  sort | uniq -c
```

### Programmatic Usage

```bash
# Get CVE as JSON for scripting
threat-radar cve get CVE-2021-44228 -o - | jq '.cves[0].cvss_score'

# Check if specific CVE exists in database
threat-radar cve db-search --keyword "CVE-2021-44228" --limit 1 | \
  jq -e '.count > 0' && echo "Found" || echo "Not found"
```

## Tips & Best Practices

1. **Use API Key:** Set `NVD_API_KEY` for higher rate limits (50 req/30s vs 5 req/30s)

2. **Local Database:** Use `db-search` instead of `search` for faster queries

3. **Confidence Threshold:**
   - 0.9+ : Very strict, fewer false positives
   - 0.7-0.8 : Balanced (recommended)
   - 0.5-0.6 : Permissive, may have false positives

4. **Update Frequency:**
   - Development: Weekly
   - Staging: Daily
   - Production: Real-time or hourly

5. **Cache Management:** Clear cache monthly to save disk space

## Troubleshooting

```bash
# Check CLI is working
threat-radar --help

# Verify Docker access
threat-radar docker list-images

# Test NVD API connection
threat-radar cve get CVE-2021-44228

# Check database status
threat-radar cve stats

# Clear and rebuild database
rm ~/.threat_radar/cve.db
threat-radar cve update --days 30 --force
```

## See Also

- **Examples:** `/examples/` directory for Python examples
- **Documentation:** `threat-radar --help` for all commands
- **NVD API:** https://nvd.nist.gov/developers
- **CPE Search:** https://nvd.nist.gov/products/cpe/search
