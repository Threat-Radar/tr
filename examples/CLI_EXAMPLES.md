# Threat Radar CLI Examples

Complete command-line interface examples for vulnerability management.

**Powered by Anchore's Syft (SBOM) and Grype (Vulnerability Scanning)**

Threat Radar provides a unified CLI that combines:
- **Syft** - Fast, comprehensive SBOM generation
- **Grype** - Industry-standard vulnerability scanning
- **Integrated Workflow** - Seamless SBOM → Scan → Report pipeline

## Table of Contents

- [Setup](#setup)
- [Why Grype?](#why-grype)
- [CVE Operations](#cve-operations)
- [Docker Analysis](#docker-analysis)
- [Vulnerability Scanning](#vulnerability-scanning)
- [Database Management](#database-management)
- [AI-Powered Analysis](#ai-powered-analysis)
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

## Why Grype?

Threat Radar uses **Grype** from Anchore for vulnerability detection, providing enterprise-grade security scanning with zero configuration.

### Key Benefits

**1. Comprehensive Vulnerability Coverage**
- **Multiple Data Sources** - NVD, GitHub Security Advisories, OS-specific databases
- **200,000+ CVEs** - Complete coverage from 1999 to present
- **Daily Updates** - Fresh vulnerability data every day
- **Cross-Ecosystem** - Python, Java, Go, Node.js, Ruby, .NET, OS packages, and more

**2. High Accuracy & Performance**
```
Test: ghcr.io/christophetd/log4shell-vulnerable-app
Scan Time: 5 seconds
Vulnerabilities: 432 found
├─ CRITICAL: 28 (including Log4Shell CVSS 10.0)
├─ HIGH: 95
├─ MEDIUM: 183
└─ LOW: 126

✓ Log4Shell (GHSA-jfh8-c2jp-5v3q) detected in log4j-core 2.14.1
✓ Spring Framework CVEs in version 5.3.13
✓ All package types scanned (JARs, Alpine packages, etc.)
```

**3. Industry Standard Tool**
- **Trusted by Enterprises** - Used by Fortune 500 companies
- **Open Source** - Transparent, community-driven (Apache 2.0)
- **Active Development** - Regular updates from Anchore
- **SBOM Native** - Built to work with CycloneDX, SPDX, Syft formats

**4. What Threat Radar Adds**
- **Unified CLI** - Single interface for SBOM + CVE scanning
- **Automated Workflows** - Generate SBOM, scan, export results
- **Storage Management** - Organized SBOM storage with timestamps
- **Export Options** - CSV, requirements.txt, JSON reports
- **CI/CD Integration** - Easy pipeline integration

### Complete Workflow Example

```bash
# Step 1: Generate SBOM (Syft)
threat-radar sbom docker myapp:latest --auto-save

# Step 2: Scan for vulnerabilities (Grype)
threat-radar cve scan-image myapp:latest

# Step 3: Export results
threat-radar sbom export sbom.json -o packages.csv --format csv

# Step 4: Track over time
threat-radar cve scan-sbom sbom.json > scan_$(date +%Y%m%d).txt
```

### Why Not Write Our Own Scanner?

**Grype Advantages:**
- ✅ **Proven Accuracy** - Battle-tested by thousands of organizations
- ✅ **Database Maintenance** - Anchore maintains fresh CVE data daily
- ✅ **Performance Optimized** - Years of optimization for speed
- ✅ **Broad Coverage** - Supports 13+ package ecosystems
- ✅ **Active Community** - Bug fixes and updates from large community
- ✅ **Professional Support** - Enterprise support available from Anchore

**Custom Scanner Drawbacks:**
- ❌ **Maintenance Burden** - Daily CVE database updates required
- ❌ **Accuracy Issues** - False positives/negatives take years to tune
- ❌ **Limited Resources** - Can't match Anchore's dedicated team
- ❌ **Ecosystem Coverage** - Supporting all package types is complex
- ❌ **Reinventing the Wheel** - Why rebuild what works?

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

## AI-Powered Analysis

Transform raw vulnerability scan results into actionable intelligence using AI-powered analysis. Threat Radar supports multiple AI providers for exploitability assessment, smart prioritization, and automated remediation planning.

### Supported AI Providers

**1. OpenAI (GPT-4o, GPT-4-Turbo, GPT-3.5-Turbo)**
- Best for: Production analysis, highest accuracy
- Requires: OpenAI API key
- Cost: Pay-per-use (varies by model)

**2. Anthropic (Claude 3.5 Sonnet, Claude 3 Opus)**
- Best for: Detailed vulnerability analysis
- Requires: Anthropic API key
- Cost: Pay-per-use

**3. Ollama (Mistral, Llama2, CodeLlama)**
- Best for: Privacy-focused, offline analysis
- Requires: Local Ollama installation
- Cost: Free (runs locally)

### Setup

```bash
# Option 1: OpenAI (Recommended for production)
export OPENAI_API_KEY="sk-..."
export AI_PROVIDER="openai"
export AI_MODEL="gpt-4o"

# Option 2: Anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
export AI_PROVIDER="anthropic"
export AI_MODEL="claude-3-5-sonnet-20241022"

# Option 3: Ollama (Local, free)
# First install Ollama: https://ollama.ai
brew install ollama  # macOS
ollama pull mistral  # Download model
export AI_PROVIDER="ollama"
export AI_MODEL="mistral"
```

### Three AI Workflows

**1. Vulnerability Analysis** - Assess exploitability and business impact
**2. Prioritization** - Rank vulnerabilities by urgency
**3. Remediation** - Generate actionable fix steps

### 1. Vulnerability Analysis (`ai analyze`)

Analyzes each vulnerability for real-world exploitability and business impact.

```bash
# Basic analysis
threat-radar ai analyze scan.json

# With specific AI provider (GPT-4o)
threat-radar ai analyze scan.json --provider openai --model gpt-4o

# Save and auto-store results
threat-radar ai analyze scan.json --provider openai --model gpt-4o --auto-save

# Using local Ollama model
threat-radar ai analyze scan.json --provider ollama --model mistral --auto-save
```

**Example Output:**
```
╭──────────────────────────────────────────────────────────────────────────────╮
│ AI Vulnerability Analysis                                                    │
│                                                                              │
│ Target: ghcr.io/christophetd/log4shell-vulnerable-app                        │
│ Total Vulnerabilities: 432                                                   │
╰──────────────────────────────────────────────────────────────────────────────╯

Summary:
The vulnerability landscape is dominated by critical remote code execution
vulnerabilities, particularly in widely used libraries like Log4j and Spring
Framework. These vulnerabilities pose significant risks of system compromise,
data breaches, and service disruptions. Immediate patching and mitigation
strategies are essential to protect against potential exploitation.

High Priority Vulnerabilities (6):
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ CVE ID              ┃ Package           ┃ Exploitability ┃ Business Impact ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ GHSA-jfh8-c2jp-5v3q │ log4j-core        │ HIGH           │ HIGH            │
│ GHSA-7rjr-3q55-vv33 │ log4j-core        │ HIGH           │ HIGH            │
│ GHSA-36p3-wjmg-h94x │ spring-beans      │ HIGH           │ HIGH            │
│ GHSA-36p3-wjmg-h94x │ spring-webmvc     │ HIGH           │ HIGH            │
│ GHSA-83qj-6fr2-vhqg │ tomcat-embed-core │ HIGH           │ HIGH            │
│ GHSA-mjmj-j48q-9wg2 │ snakeyaml         │ HIGH           │ HIGH            │
└─────────────────────┴───────────────────┴────────────────┴─────────────────┘

Analysis auto-saved to storage/ai_analysis/...
```

### 2. Vulnerability Prioritization (`ai prioritize`)

Generate intelligent priority rankings based on severity, exploitability, and business impact.

```bash
# Generate priority list
threat-radar ai prioritize scan.json --provider openai --model gpt-4o

# Show top 20 priorities
threat-radar ai prioritize scan.json --provider openai --model gpt-4o --top 20 --auto-save

# Using local model
threat-radar ai prioritize scan.json --provider ollama --model mistral --top 10
```

**Example Output:**
```
╭──────────────────────────────────────────────────────────────────────────────╮
│ Prioritized Vulnerability List                                               │
│                                                                              │
│ Target: ghcr.io/christophetd/log4shell-vulnerable-app                        │
╰──────────────────────────────────────────────────────────────────────────────╯

Overall Strategy:
Prioritize patching critical and high-severity vulnerabilities with available
fixes, focusing on those with high exploitability and business impact. Implement
network-level security controls and conduct thorough security assessments to
mitigate risks. Regularly monitor for updates and educate users on safe practices.

Quick Wins:
1. Upgrade log4j-core to version 2.15.0 or later to address GHSA-jfh8-c2jp-5v3q
2. Upgrade log4j-core to version 2.16.0 or later to address GHSA-7rjr-3q55-vv33
3. Upgrade spring-beans to version 5.3.18 or later to address GHSA-36p3-wjmg-h94x
4. Upgrade spring-webmvc to version 5.3.18 or later to address GHSA-36p3-wjmg-h94x
5. Upgrade tomcat-embed-core to version 9.0.99 or later to address GHSA-83qj-6fr2-vhqg
6. Upgrade snakeyaml to version 2.0 or later to address GHSA-mjmj-j48q-9wg2

Top 20 Priorities:
┏━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ #  ┃ CVE ID              ┃ Package           ┃ Urgency ┃ Reason           ┃
┡━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ 1  │ GHSA-jfh8-c2jp-5v3q │ log4j-core        │ 100     │ Remote code ex...│
│ 2  │ GHSA-7rjr-3q55-vv33 │ log4j-core        │ 95      │ Incomplete fix...│
│ 3  │ GHSA-36p3-wjmg-h94x │ spring-beans      │ 90      │ Highly exploit...│
│ 4  │ GHSA-36p3-wjmg-h94x │ spring-webmvc     │ 90      │ Similar to spr...│
│ 5  │ GHSA-83qj-6fr2-vhqg │ tomcat-embed-core │ 90      │ Highly exploit...│
...
└────┴─────────────────────┴───────────────────┴─────────┴──────────────────┘

Priority Distribution:
  Critical: 2
  High: 5
  Medium: 13
  Low: 0
```

### 3. Remediation Planning (`ai remediate`)

Generate detailed, actionable remediation steps for each vulnerability.

```bash
# Generate remediation plan
threat-radar ai remediate scan.json --provider openai --model gpt-4o --auto-save

# Show commands
threat-radar ai remediate scan.json --provider openai --model gpt-4o --show-commands

# Save to file
threat-radar ai remediate scan.json --provider openai --model gpt-4o -o remediation.json
```

**Example Output:**
```
╭──────────────────────────────────────────────────────────────────────────────╮
│ Remediation Plan                                                             │
│                                                                              │
│ Target: ghcr.io/christophetd/log4shell-vulnerable-app                        │
│ Vulnerabilities: 432                                                         │
│ Packages Affected: 5                                                         │
╰──────────────────────────────────────────────────────────────────────────────╯

Packages Requiring Updates:
  • log4j-core: 3 vulnerabilities → 2.17.0 [✓ Upgrade fixes all]
  • spring-beans: 1 vulnerabilities → 5.3.18 [✓ Upgrade fixes all]
  • tomcat-embed-core: 4 vulnerabilities → 9.0.99 [✓ Upgrade fixes all]
  • freetype: 2 vulnerabilities → No fix available [⚠ Partial fix]
  • zlib: 1 vulnerabilities → No fix available [⚠ Partial fix]

Upgrade Commands:

MAVEN:
  mvn dependency:purge-local-repository -DreResolve=false && mvn clean install -Dlog4j2.version=2.15.0
  mvn dependency:purge-local-repository -DreResolve=false && mvn clean install -Dlog4j2.version=2.16.0
  mvn dependency:purge-local-repository -DreResolve=false && mvn clean install -Dspring.version=5.3.18
  mvn dependency:purge-local-repository -DreResolve=false && mvn clean install -Dtomcat.version=9.0.99

Quick Fixes (1 low-effort remediations):
  • CVE-2020-15999 (freetype): N/A

Remediation plan auto-saved to storage/ai_analysis/...
```

### Complete AI Workflow

**Step-by-step: Scan → Analyze → Prioritize → Remediate**

```bash
#!/bin/bash
# ai_security_analysis.sh

# Set your AI provider (choose one)
export OPENAI_API_KEY="sk-..."  # For GPT-4o
# OR
# export ANTHROPIC_API_KEY="sk-ant-..."  # For Claude
# OR
# ollama pull mistral  # For local Ollama

IMAGE="ghcr.io/christophetd/log4shell-vulnerable-app"

echo "Step 1: Scanning image for vulnerabilities..."
threat-radar cve scan-image $IMAGE --output scan.json

echo "Step 2: AI Analysis - Assessing exploitability and business impact..."
threat-radar ai analyze scan.json --provider openai --model gpt-4o --auto-save

echo "Step 3: AI Prioritization - Ranking vulnerabilities by urgency..."
threat-radar ai prioritize scan.json --provider openai --model gpt-4o --auto-save --top 20

echo "Step 4: AI Remediation - Generating actionable fix steps..."
threat-radar ai remediate scan.json --provider openai --model gpt-4o --auto-save

echo "✓ Complete! All AI analysis results saved to storage/ai_analysis/"
ls -lh storage/ai_analysis/
```

### AI Storage Organization

Results are automatically organized when using `--auto-save`:

```
storage/ai_analysis/
└── ghcr_io_christophetd_log4shell-vulnerable-app/
    ├── analysis_2025-10-21_00-15-50.json
    ├── prioritization_2025-10-21_00-19-28.json
    └── remediation_2025-10-21_00-19-56.json
```

### Comparison: Ollama vs OpenAI

| Feature | Ollama (Local) | OpenAI (GPT-4o) |
|---------|----------------|-----------------|
| **Cost** | Free | ~$0.01-0.10 per scan |
| **Privacy** | Complete (offline) | Data sent to OpenAI |
| **Speed** | Slower (depends on hardware) | Fast (cloud optimized) |
| **Quality** | Good | Excellent |
| **Setup** | Requires local install | API key only |
| **Best For** | Privacy, testing | Production, accuracy |

### Example: Comparing AI Providers

```bash
# Scan once, analyze with different providers
threat-radar cve scan-image ghcr.io/christophetd/log4shell-vulnerable-app --output scan.json

# Analyze with GPT-4o
threat-radar ai analyze scan.json --provider openai --model gpt-4o -o analysis_gpt4o.json

# Analyze with Claude
threat-radar ai analyze scan.json --provider anthropic --model claude-3-5-sonnet-20241022 -o analysis_claude.json

# Analyze with local Mistral
threat-radar ai analyze scan.json --provider ollama --model mistral -o analysis_mistral.json

# Compare results
diff analysis_gpt4o.json analysis_claude.json
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

### Threat Radar Resources
- **Examples:** `/examples/` directory for Python examples
- **Documentation:** `threat-radar --help` for all commands
- **Project Repository:** https://github.com/Threat-Radar/tr-nvd

### Core Tools Documentation
- **Syft (SBOM Generation):** https://github.com/anchore/syft
  - Used by Threat Radar for SBOM generation
  - Supports 13+ package ecosystems
  - Multiple output formats (CycloneDX, SPDX, Syft-JSON)

- **Grype (Vulnerability Scanning):** https://github.com/anchore/grype
  - Used by Threat Radar for CVE detection
  - Multi-source vulnerability database
  - Fast, accurate, enterprise-ready

### Additional Resources
- **NVD (Vulnerability Database):** https://nvd.nist.gov/
- **CycloneDX Specification:** https://cyclonedx.org/
- **SPDX Specification:** https://spdx.dev/

---

## Architecture Overview

```
Threat Radar = Unified CLI + Workflow Automation
    │
    ├─ SBOM Generation ────► Syft (Anchore)
    │                         └─ Scans containers/directories
    │                         └─ Outputs CycloneDX/SPDX/Syft-JSON
    │
    ├─ Vulnerability Scan ──► Grype (Anchore)
    │                         └─ Scans images/SBOMs/directories
    │                         └─ Multi-source CVE database
    │
    └─ Value-Add Features
        ├─ Automated SBOM storage with timestamps
        ├─ Export to CSV/requirements.txt
        ├─ SBOM comparison and analysis
        ├─ CI/CD integration helpers
        └─ Unified command interface
```

**Philosophy:** Leverage best-in-class open source tools (Syft, Grype) and add value through automation, storage, and workflow integration.
