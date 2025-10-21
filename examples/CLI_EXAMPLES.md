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

### First-Time Setup

```bash
# Install Grype (required for vulnerability scanning)
# macOS:
brew install grype

# Linux:
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh

# Update Grype vulnerability database
threat-radar cve db-update

# Verify installation
threat-radar cve db-status
```

## CVE Operations

### Vulnerability Scanning

```bash
# Scan a Docker image
threat-radar cve scan-image ghcr.io/christophetd/log4shell-vulnerable-app

# Scan from a pre-generated SBOM file
threat-radar cve scan-sbom path/to/sbom.json

# Scan a local directory
threat-radar cve scan-directory /path/to/project
```

**Example Output:**
```
⚠ Found 432 vulnerabilities in ghcr.io/christophetd/log4shell-vulnerable-app:

Severity Breakdown:
 CRITICAL   28
 HIGH       95
 MEDIUM    183
 LOW       126

Vulnerabilities (showing top 20):

┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━┓
┃ CVE ID              ┃ Severity ┃ Package    ┃ Installed  ┃ Fixed In   ┃ CVSS ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━┩
│ GHSA-jfh8-c2jp-5v3q │ CRITICAL │ log4j-core │ 2.14.1     │ 2.15.0     │ 10.0 │
│ GHSA-36p3-wjmg-h94x │ CRITICAL │ spring-be… │ 5.3.13     │ 5.3.18     │  9.8 │
│ ...                 │          │            │            │            │      │
└─────────────────────┴──────────┴────────────┴────────────┴────────────┴──────┘
```

### Database Management

```bash
# Update Grype vulnerability database
threat-radar cve db-update

# Check database status
threat-radar cve db-status
```

## Docker Analysis

### Image Analysis

```bash
# Scan an image
threat-radar docker scan ghcr.io/christophetd/log4shell-vulnerable-app

# Import and analyze
threat-radar docker import-image ghcr.io/christophetd/log4shell-vulnerable-app -o analysis.json

# List local images
threat-radar docker list-images

# List packages in image
threat-radar docker packages ghcr.io/christophetd/log4shell-vulnerable-app --limit 50

# Filter packages
threat-radar docker packages ghcr.io/christophetd/log4shell-vulnerable-app \
  --filter log4j \
  --limit 10
```

### SBOM Generation (Recommended: Use threat-radar sbom)

```bash
# Generate SBOM from Docker image (using Syft)
threat-radar sbom docker ghcr.io/christophetd/log4shell-vulnerable-app --auto-save

# Generate in different formats
threat-radar sbom docker ghcr.io/christophetd/log4shell-vulnerable-app --format cyclonedx-json -o sbom.json
threat-radar sbom docker ghcr.io/christophetd/log4shell-vulnerable-app --format spdx-json -o sbom-spdx.json

# Export SBOM to CSV
threat-radar sbom export sbom.json -o packages.csv --format csv

# Export Python packages to requirements.txt
threat-radar sbom export sbom.json -o requirements.txt --format requirements
```

### Python SBOM (Legacy - for Python-specific images)

```bash
# Generate Python-specific SBOM
threat-radar docker python-sbom python:3.11 \
  -o python-packages.json \
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
threat-radar cve scan-image ghcr.io/christophetd/log4shell-vulnerable-app

# Scan from SBOM file
threat-radar cve scan-sbom path/to/sbom.json

# Scan local directory
threat-radar cve scan-directory /path/to/project
```

**Example Output:**
```
⚠ Found 432 vulnerabilities in ghcr.io/christophetd/log4shell-vulnerable-app:

Severity Breakdown:
 CRITICAL   28
 HIGH       95
 MEDIUM    183
 LOW       126

Vulnerabilities (showing top 20):

┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━┓
┃ CVE ID              ┃ Severity ┃ Package    ┃ Installed  ┃ Fixed In   ┃ CVSS ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━┩
│ GHSA-jfh8-c2jp-5v3q │ CRITICAL │ log4j-core │ 2.14.1     │ 2.15.0     │ 10.0 │
│ GHSA-36p3-wjmg-h94x │ CRITICAL │ spring-be… │ 5.3.13     │ 5.3.18     │  9.8 │
│ ...                 │          │            │            │            │      │
└─────────────────────┴──────────┴────────────┴────────────┴────────────┴──────┘
```

### Batch Scanning

```bash
# Scan multiple images
for image in ghcr.io/christophetd/log4shell-vulnerable-app node:10 python:2.7; do
  echo "Scanning $image..."
  threat-radar cve scan-image $image > "report_${image//[:\\/]/_}.txt"
done

# Compare results
ls -lh report_*.txt
```

## Database Management

### Grype Database Management

```bash
# Update Grype vulnerability database
threat-radar cve db-update

# Check database status
threat-radar cve db-status
```

**Example Output:**
```
Grype Database Status:

Location: ~/.cache/grype/db/5
Built: 2024-01-15 10:30:00
Schema Version: 5
```

## Complete Workflows

### Workflow 1: Initial Setup & Scan

```bash
#!/bin/bash
# setup_and_scan.sh

# 1. Update Grype database
echo "Updating vulnerability database..."
threat-radar cve db-update

# 2. Generate SBOM for image
echo "Generating SBOM..."
threat-radar sbom docker ghcr.io/christophetd/log4shell-vulnerable-app --auto-save

# 3. Scan image for vulnerabilities
echo "Scanning for vulnerabilities..."
threat-radar cve scan-image ghcr.io/christophetd/log4shell-vulnerable-app > scan_results.txt

# 4. View database status
threat-radar cve db-status
```

### Workflow 2: Continuous Monitoring

```bash
#!/bin/bash
# daily_scan.sh - Run this daily via cron

DATE=$(date +%Y%m%d)
IMAGES=("ghcr.io/christophetd/log4shell-vulnerable-app" "python:3.11-slim" "node:18-alpine")

# Update Grype database
threat-radar cve db-update

# Scan each image
for IMAGE in "${IMAGES[@]}"; do
  SAFE_NAME=${IMAGE//[:\/]/_}
  echo "Scanning $IMAGE..."
  threat-radar cve scan-image $IMAGE > "reports/${DATE}_${SAFE_NAME}.txt"

  # Check for CRITICAL vulnerabilities
  if grep -q "CRITICAL" "reports/${DATE}_${SAFE_NAME}.txt"; then
    echo "⚠️  CRITICAL vulnerabilities found in $IMAGE"
    # Add your alerting logic here
  fi
done
```

### Workflow 3: SBOM Comparison

```bash
#!/bin/bash
# compare_sboms.sh

echo "Comparing different application versions..."

# Generate SBOMs for two versions
threat-radar sbom docker myapp:v1.0 -o sbom_v1.json
threat-radar sbom docker myapp:v2.0 -o sbom_v2.json

# Compare SBOMs to see what changed
threat-radar sbom compare sbom_v1.json sbom_v2.json --versions

# Scan both for vulnerabilities
threat-radar cve scan-sbom sbom_v1.json > vuln_v1.txt
threat-radar cve scan-sbom sbom_v2.json > vuln_v2.txt

# Compare vulnerability counts
echo "V1 Vulnerabilities:"
grep -c "CRITICAL\|HIGH\|MEDIUM\|LOW" vuln_v1.txt || echo "0"
echo "V2 Vulnerabilities:"
grep -c "CRITICAL\|HIGH\|MEDIUM\|LOW" vuln_v2.txt || echo "0"
```

### Workflow 4: CI/CD Integration

```bash
#!/bin/bash
# ci_vulnerability_check.sh
# Exit with error if critical vulnerabilities found

IMAGE=$1

if [ -z "$IMAGE" ]; then
  echo "Usage: $0 <docker-image>"
  exit 1
fi

# Scan image
echo "Scanning $IMAGE for vulnerabilities..."
threat-radar cve scan-image $IMAGE > scan_results.txt

# Check for critical vulnerabilities
CRITICAL_COUNT=$(grep -c "CRITICAL" scan_results.txt || true)

if [ "$CRITICAL_COUNT" -gt 0 ]; then
  echo "❌ FAILED: $CRITICAL_COUNT critical vulnerabilities found"
  grep "CRITICAL" scan_results.txt | head -10
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

      - name: Install Grype
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

      - name: Update Grype Database
        run: threat-radar cve db-update

      - name: Scan Docker Image
        run: |
          threat-radar cve scan-image myapp:latest > vulnerability_report.txt

      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: vulnerability-report
          path: vulnerability_report.txt

      - name: Check for Critical Issues
        run: |
          if grep -q "CRITICAL" vulnerability_report.txt; then
            echo "Critical vulnerabilities found!"
            grep "CRITICAL" vulnerability_report.txt
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

# Update Grype database
threat-radar cve db-update

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

  # Generate SBOM
  echo "Generating SBOM for $IMAGE..."
  threat-radar sbom docker $IMAGE -o "$REPORT_DIR/${SAFE_NAME}_sbom.json"

  # Scan for vulnerabilities
  echo "Scanning $IMAGE..."
  threat-radar cve scan-image $IMAGE > "$REPORT_DIR/${SAFE_NAME}_scan.txt"

  # Count vulnerabilities by severity
  CRITICAL=$(grep -c "CRITICAL" "$REPORT_DIR/${SAFE_NAME}_scan.txt" || echo "0")
  HIGH=$(grep -c "HIGH" "$REPORT_DIR/${SAFE_NAME}_scan.txt" || echo "0")

  # Add to summary
  echo "## $IMAGE" >> $REPORT_DIR/summary.md
  echo "- CRITICAL: $CRITICAL" >> $REPORT_DIR/summary.md
  echo "- HIGH: $HIGH" >> $REPORT_DIR/summary.md
  echo "" >> $REPORT_DIR/summary.md
done

# Email report (example)
# mail -s "Weekly Vulnerability Report" security@company.com < $REPORT_DIR/summary.md
```

## Advanced Usage

### Combining SBOM and Vulnerability Scanning

```bash
# Generate SBOM, export to CSV, and scan for vulnerabilities
IMAGE="ghcr.io/christophetd/log4shell-vulnerable-app"

# Step 1: Generate SBOM
threat-radar sbom docker $IMAGE -o sbom.json

# Step 2: Export package list to CSV
threat-radar sbom export sbom.json -o packages.csv --format csv

# Step 3: Scan for vulnerabilities
threat-radar cve scan-sbom sbom.json > vulnerabilities.txt

# Step 4: View results
echo "Packages:"
wc -l packages.csv
echo ""
echo "Vulnerabilities:"
grep -c "CRITICAL\|HIGH\|MEDIUM\|LOW" vulnerabilities.txt || echo "0"
```

### Filtering Scan Results

```bash
# Scan and filter results
threat-radar cve scan-image ghcr.io/christophetd/log4shell-vulnerable-app > scan.txt

# Show only CRITICAL vulnerabilities
grep "CRITICAL" scan.txt

# Count vulnerabilities by severity
echo "CRITICAL: $(grep -c "CRITICAL" scan.txt || echo 0)"
echo "HIGH: $(grep -c "HIGH" scan.txt || echo 0)"
echo "MEDIUM: $(grep -c "MEDIUM" scan.txt || echo 0)"
echo "LOW: $(grep -c "LOW" scan.txt || echo 0)"
```

## Tips & Best Practices

1. **Install Grype:** The CVE scanning features require Grype to be installed
   ```bash
   # macOS
   brew install grype

   # Linux
   curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh
   ```

2. **Update Database Regularly:** Keep the Grype vulnerability database up to date
   ```bash
   threat-radar cve db-update
   ```

3. **Use SBOM for Faster Scans:** Generate SBOM once, scan multiple times
   ```bash
   threat-radar sbom docker myapp:latest -o sbom.json
   threat-radar cve scan-sbom sbom.json  # Fast repeated scans
   ```

4. **Automate Scanning:** Set up daily/weekly scans in CI/CD

5. **Focus on CRITICAL/HIGH:** Filter scan results to prioritize serious vulnerabilities
   ```bash
   threat-radar cve scan-image myapp:latest | grep -E "CRITICAL|HIGH"
   ```

## Troubleshooting

```bash
# Check CLI is working
threat-radar --help

# Verify Docker access
threat-radar docker list-images

# Check if Grype is installed
grype version
# If not installed:
# macOS: brew install grype
# Linux: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh

# Check Grype database status
threat-radar cve db-status

# Update Grype database
threat-radar cve db-update

# Test SBOM generation
threat-radar sbom docker alpine:latest -o test_sbom.json

# Test vulnerability scanning
threat-radar cve scan-image alpine:latest
```

## See Also

- **Examples:** `/examples/` directory for Python examples
- **Documentation:** `threat-radar --help` for all commands
- **NVD API:** https://nvd.nist.gov/developers
- **CPE Search:** https://nvd.nist.gov/products/cpe/search
