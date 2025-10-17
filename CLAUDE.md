# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Threat Radar (tr) is a threat assessment and analysis platform for security vulnerability management. It provides Docker container analysis, SBOM generation, package extraction, and GitHub integration for security analysis.

## Development Commands

### Installation & Setup
```bash
# Install package in development mode
pip install -e .

# Install with dev dependencies
pip install -e ".[dev]"

# Set up environment variables
cp .env.example .env
# Edit .env and add your GITHUB_ACCESS_TOKEN
```

### Running the CLI
The package provides two CLI entry points:
- `threat-radar` - Main command
- `tradar` - Shortened alias

```bash
# Available commands
threat-radar --help
threat-radar cve --help
threat-radar docker --help
threat-radar sbom --help
```

### Testing
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_docker_integration.py

# Run with coverage
pytest --cov=threat_radar --cov-report=html
```

### Code Quality
```bash
# Format code with Black
black threat_radar/ tests/

# Run type checking
mypy threat_radar/

# Run linting
flake8 threat_radar/
```

## Architecture

### CLI Structure
The CLI is built with Typer and uses a modular command structure in `threat_radar/cli/`:
- `app.py` - Main CLI app that registers all sub-commands
- `cve.py` - CVE vulnerability scanning with Grype (scan-image, scan-sbom, scan-directory, db-update, db-status)
- `docker.py` - Docker container analysis commands
- `sbom.py` - SBOM generation and operations (generate, docker, read, compare, stats, export, search, list, components)
- `ai.py` - AI-powered vulnerability analysis (analyze, prioritize, remediate)
- `report.py` - **NEW**: Comprehensive reporting with AI executive summaries (generate, dashboard-export, compare)
- `hash.py` - File hashing utilities
- `config.py` - Configuration management
- `enrich.py` - Data enrichment operations

### Core Modules

#### Docker Integration (`threat_radar/core/`)
- **`docker_integration.py`** - `DockerClient` class wraps Docker SDK with error handling
  - Handles image pulling, running containers, inspecting images
  - Manages Docker daemon connection lifecycle

- **`container_analyzer.py`** - `ContainerAnalyzer` class for analyzing containers
  - `import_container(image_name, tag)` - Pulls and analyzes images
  - `analyze_container(image_name)` - Analyzes existing local images using native package managers
  - `analyze_container_with_sbom(image_name)` - **NEW**: Analyzes using SBOM (Syft) for comprehensive detection
  - Auto-detects Linux distributions (Alpine, Ubuntu, Debian, RHEL, CentOS, Fedora)
  - Extracts installed packages using distro-specific commands (dpkg, apk, rpm)

- **`package_extractors.py`** - Package manager parsers
  - `APTExtractor` - Debian/Ubuntu (dpkg)
  - `APKExtractor` - Alpine (apk)
  - `YUMExtractor` - RHEL/CentOS/Fedora (rpm)
  - `PackageExtractorFactory` - Factory pattern for getting appropriate extractor

- **`python_sbom.py`** - `PythonPackageExtractor` for Python-specific analysis
  - Extracts pip packages from containers
  - Generates CycloneDX SBOM format
  - Supports JSON and text output formats

#### GitHub Integration (`threat_radar/core/`)
- **`github_integration.py`** - `GitHubIntegration` class using PyGithub
  - Repository analysis and metadata extraction
  - Security issue detection (labels: security, vulnerability, cve)
  - Dependency file extraction (requirements.txt, package.json, etc.)
  - Requires `GITHUB_ACCESS_TOKEN` environment variable

#### CVE Vulnerability Scanning (`threat_radar/core/`)
- **`grype_integration.py`** - `GrypeClient` wrapper for Grype vulnerability scanner
  - Docker image scanning with automatic vulnerability detection
  - SBOM file scanning (CycloneDX, SPDX, Syft JSON)
  - Directory scanning for application dependencies
  - Severity filtering (NEGLIGIBLE, LOW, MEDIUM, HIGH, CRITICAL)
  - Automatic vulnerability database updates
  - No API rate limits - uses locally managed database

- **`syft_integration.py`** - `SyftClient` wrapper for Syft SBOM generator
  - Generates SBOMs from Docker images, directories, and files
  - Multiple output formats (CycloneDX, SPDX, Syft JSON)
  - Comprehensive package detection (OS packages + app dependencies)
  - Works seamlessly with Grype for vulnerability scanning

#### Utilities (`threat_radar/utils/`)
- **`hasher.py`** - File hashing utilities for integrity verification

### Docker Analysis Workflow

1. **Image Import**: `ContainerAnalyzer.import_container()` pulls image from registry
2. **Distribution Detection**: Tries `/etc/os-release`, `/etc/issue`, then image name heuristics
3. **Package Extraction**: Uses appropriate package manager (dpkg/apk/rpm) via container execution
4. **Parsing**: `PackageExtractor` subclasses parse package manager output into `Package` objects
5. **Results**: Returns `ContainerAnalysis` object with metadata and package list

### Data Models

Key dataclasses in `threat_radar/core/`:
- `ContainerAnalysis` - Container metadata and package list
- `Package` - Installed package info (name, version, architecture)
- `PythonPackage` - Python-specific package info with location

## CVE Commands Reference (Powered by Grype)

### Installation Requirements
Grype must be installed on your system:

```bash
# macOS
brew install grype

# Linux
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh

# Verify installation
grype version
```

### Scanning Commands

```bash
# Scan Docker image for CVEs
threat-radar cve scan-image alpine:3.18
threat-radar cve scan-image python:3.11 --severity HIGH
threat-radar cve scan-image ubuntu:22.04 --only-fixed -o results.json

# Scan with automatic cleanup (removes image after scan if newly pulled)
threat-radar cve scan-image nginx:latest --cleanup
threat-radar cve scan-image test-app:v1.0 --cleanup --severity HIGH

# Auto-save results to storage/cve_storage/ directory
threat-radar cve scan-image alpine:3.18 --auto-save
threat-radar cve scan-image myapp:latest --as  # Short form
threat-radar cve scan-image python:3.11 --auto-save --cleanup  # Combined

# Scan pre-generated SBOM file (CI/CD friendly)
threat-radar cve scan-sbom my-app-sbom.json
threat-radar cve scan-sbom docker-sbom.json --severity CRITICAL
threat-radar cve scan-sbom sbom.json --only-fixed -o cve-results.json

# SBOM scanning with cleanup and auto-save
threat-radar cve scan-sbom alpine-sbom.json --cleanup --image alpine:3.18
threat-radar cve scan-sbom app-sbom.json --auto-save  # Auto-save results

# Scan local directory for vulnerabilities
threat-radar cve scan-directory ./my-app
threat-radar cve scan-directory /path/to/project --severity MEDIUM
threat-radar cve scan-directory . --only-fixed -o results.json
threat-radar cve scan-directory ./src --auto-save  # Auto-save

# Vulnerability database management
threat-radar cve db-update                     # Update Grype database
threat-radar cve db-status                     # Show database status
```

### CVE Scanning Workflow

**Grype-based vulnerability scanning (automated, no manual work):**

1. **Docker Image Scanning**: `cve scan-image <image>`
   - Grype automatically detects OS packages + application dependencies
   - No SBOM generation required (Grype handles this internally)
   - Comprehensive coverage across all package ecosystems
   - Zero API rate limits

2. **SBOM Scanning**: `cve scan-sbom <file>`
   - Scans pre-generated SBOM files (CycloneDX, SPDX, Syft JSON)
   - Perfect for CI/CD pipelines
   - Works offline with local vulnerability database
   - No Docker daemon required

3. **Directory Scanning**: `cve scan-directory <path>`
   - Scans local application code for vulnerabilities
   - Auto-detects package manifests (package.json, requirements.txt, go.mod, etc.)
   - Great for development workflows

### Image Cleanup Feature

The `--cleanup` flag automatically removes Docker images after scanning to save disk space:

**How it works:**
- ✅ Checks if image existed before scan
- ✅ If image was **newly pulled** during scan → removes it after scan
- ✅ If image **already existed** → preserves it (never deletes user's images)
- ✅ Only works when `--cleanup` is explicitly set

**Use cases:**
```bash
# CI/CD pipelines - scan and cleanup
threat-radar cve scan-image myapp:latest --cleanup --severity HIGH

# Testing multiple images without storage buildup
threat-radar cve scan-image nginx:alpine --cleanup
threat-radar cve scan-image redis:alpine --cleanup

# SBOM scanning with source image cleanup
threat-radar cve scan-sbom app-sbom.json --cleanup --image myapp:v1.0
```

**Storage management:**
- Without `--cleanup`: Images remain on disk (standard Docker behavior)
- With `--cleanup`: Auto-removes newly pulled images, preserves existing ones
- Manual cleanup: `docker image prune -a` to remove all unused images

### Auto-Save Feature

The `--auto-save` (or `--as`) flag automatically saves CVE scan results to the `storage/cve_storage/` directory with timestamped filenames:

**How it works:**
- ✅ Creates `./storage/cve_storage/` directory automatically if not exists
- ✅ Saves results with format: `<target>_<type>_YYYY-MM-DD_HH-MM-SS.json`
- ✅ Preserves scan history - never overwrites previous scans
- ✅ Works with all scan commands (image, sbom, directory)
- ✅ Can be combined with `--output` to save to both locations

**Use cases:**
```bash
# Keep history of all scans in one place
threat-radar cve scan-image myapp:v1.0 --auto-save
threat-radar cve scan-image myapp:v1.1 --auto-save
threat-radar cve scan-image myapp:v1.2 --auto-save

# CI/CD: Auto-save + cleanup for ephemeral environments
threat-radar cve scan-image $IMAGE --auto-save --cleanup --fail-on HIGH

# Save to both custom location and auto-save
threat-radar cve scan-image alpine:3.18 -o report.json --auto-save
```

**File naming examples:**
- Docker image `alpine:3.18` → `alpine_3_18_image_2025-01-09_14-30-45.json`
- SBOM `my-app.json` → `my-app_sbom_2025-01-09_14-30-45.json`
- Directory `./src` → `src_directory_2025-01-09_14-30-45.json`

**Managing stored reports:**
```bash
# View all stored reports
ls -lh storage/cve_storage/

# Count reports
ls storage/cve_storage/ | wc -l

# Find recent reports
ls -t storage/cve_storage/ | head -5

# Clean up old reports (manual)
find storage/cve_storage/ -name "*.json" -mtime +30 -delete  # Remove >30 days old
```

### Recommended Workflow

```bash
# Generate SBOM with Syft
threat-radar sbom generate docker:alpine:3.18 -o sbom.json

# Scan SBOM with Grype for vulnerabilities
threat-radar cve scan-sbom sbom.json --severity HIGH -o vulns.json

# Or scan Docker image directly (Grype handles SBOM internally)
threat-radar cve scan-image alpine:3.18 --severity HIGH -o vulns.json
```

## AI Commands Reference

### Overview

The AI integration provides intelligent analysis of vulnerability scan results using Large Language Models (LLMs). It supports both cloud-based models (OpenAI GPT) and local models (Ollama, LM Studio).

**Key Features:**
- **Vulnerability Analysis**: Assess exploitability, attack vectors, and business impact
- **Prioritization**: Generate ranked lists based on risk and context
- **Remediation**: Create actionable fix recommendations and upgrade paths
- **Flexible Backend**: Support for OpenAI API and local models

### Installation & Setup

```bash
# Install with AI dependencies
pip install -e .

# For optional AI providers (Ollama, Anthropic)
pip install -e ".[ai]"

# Configure environment variables
cp .env.example .env
# Edit .env and add AI configuration:
# - OPENAI_API_KEY=your_key_here
# - AI_PROVIDER=openai  # or 'ollama' for local
# - AI_MODEL=gpt-4  # or 'llama2' for Ollama
# - LOCAL_MODEL_ENDPOINT=http://localhost:11434  # Ollama default
```

### AI Analysis Commands

#### Analyze Vulnerabilities

Analyze CVE scan results to understand exploitability and business impact:

```bash
# Basic analysis
threat-radar ai analyze cve-results.json

# Specify AI provider and model
threat-radar ai analyze results.json --provider openai --model gpt-4

# Save analysis to file
threat-radar ai analyze scan.json -o analysis.json

# Auto-save to storage/ai_analysis/
threat-radar ai analyze results.json --auto-save

# Use local model (Ollama)
threat-radar ai analyze scan.json --provider ollama --model llama2
```

**Output includes:**
- Exploitability assessment (HIGH/MEDIUM/LOW)
- Attack vector identification (RCE, XSS, SQL injection, etc.)
- Business impact evaluation
- Contextual recommendations per vulnerability
- Overall threat landscape summary

#### Prioritize Remediation

Generate AI-powered prioritized vulnerability lists:

```bash
# Generate priority list
threat-radar ai prioritize cve-results.json

# Show top 20 priorities
threat-radar ai prioritize results.json --top 20

# Save prioritization
threat-radar ai prioritize scan.json -o priorities.json

# Auto-save results
threat-radar ai prioritize results.json --auto-save
```

**Output includes:**
- Critical/High/Medium/Low priority grouping
- Urgency scores (0-100) for each vulnerability
- Rationale for priority assignments
- Quick wins (low effort, high impact fixes)
- Overall remediation strategy

#### Generate Remediation Plan

Create detailed, actionable remediation guidance:

```bash
# Generate remediation plan
threat-radar ai remediate cve-results.json

# Save plan to file
threat-radar ai remediate scan.json -o remediation.json

# Hide upgrade commands
threat-radar ai remediate results.json --no-commands

# Use local model
threat-radar ai remediate scan.json --provider ollama
```

**Output includes:**
- Immediate mitigation actions
- Specific version upgrades and patches
- Package manager upgrade commands
- Workarounds when patches unavailable
- Testing steps to verify fixes
- Reference links to security advisories
- Grouped package remediation (fix multiple CVEs with one upgrade)
- Effort estimates (LOW/MEDIUM/HIGH)

### AI Workflow Examples

#### Complete Analysis Workflow

```bash
# 1. Scan Docker image for vulnerabilities
threat-radar cve scan-image alpine:3.18 --auto-save -o cve-scan.json

# 2. Analyze with AI
threat-radar ai analyze cve-scan.json --auto-save -o ai-analysis.json

# 3. Generate priorities
threat-radar ai prioritize cve-scan.json --auto-save -o priorities.json

# 4. Create remediation plan
threat-radar ai remediate cve-scan.json --auto-save -o remediation.json
```

#### CI/CD Integration

```bash
# Scan, analyze, and prioritize in one pipeline
threat-radar cve scan-image $IMAGE --auto-save --cleanup > scan.json
threat-radar ai analyze scan.json --auto-save
threat-radar ai prioritize scan.json --top 10 --auto-save
```

#### Using Local Models (Privacy-Focused)

```bash
# Start Ollama locally (one-time setup)
# brew install ollama
# ollama pull llama2

# Use local model for all AI operations
export AI_PROVIDER=ollama
export AI_MODEL=llama2

threat-radar ai analyze cve-scan.json
threat-radar ai prioritize cve-scan.json
threat-radar ai remediate cve-scan.json
```

### AI Storage Management

AI analysis results are auto-saved to `./storage/ai_analysis/` with timestamped filenames:

```bash
# View all AI analyses
ls -lh storage/ai_analysis/

# Filename format examples:
# - alpine_3_18_analysis_2025-01-09_14-30-45.json
# - myapp_prioritization_2025-01-09_15-00-00.json
# - scan_remediation_2025-01-09_16-30-00.json

# Clean up old analyses (manual)
find storage/ai_analysis/ -name "*.json" -mtime +30 -delete
```

### AI Architecture

#### Modules (`threat_radar/ai/`)

- **`llm_client.py`** - LLM client abstraction
  - `OpenAIClient` - OpenAI GPT integration
  - `OllamaClient` - Local Ollama model integration
  - `get_llm_client()` - Factory function based on configuration

- **`vulnerability_analyzer.py`** - Vulnerability analysis engine
  - `VulnerabilityAnalyzer` - Analyzes CVE data with AI
  - Generates exploitability and impact assessments
  - Returns structured `VulnerabilityAnalysis` objects
  - Data model: `VulnerabilityAnalysis` with per-CVE assessments

- **`prioritization.py`** - Prioritization engine
  - `PrioritizationEngine` - Creates ranked vulnerability lists
  - Urgency scoring (0-100 scale)
  - Returns `PrioritizedVulnerabilityList` objects
  - Data model: `PrioritizedVulnerability` with urgency scores and rationale

- **`remediation_generator.py`** - Remediation plan generator
  - `RemediationGenerator` - Creates actionable fix plans
  - Package-grouped remediation strategies
  - Returns `RemediationReport` objects
  - Data models: `RemediationPlan`, `PackageRemediationGroup`

- **`prompt_templates.py`** - Prompt engineering
  - Pre-designed prompts for analysis, prioritization, remediation
  - Optimized for security context and accuracy

#### Configuration

AI behavior is controlled via environment variables:

```bash
# Provider selection
AI_PROVIDER=openai  # or 'ollama'

# Model selection
AI_MODEL=gpt-4  # OpenAI: gpt-4, gpt-3.5-turbo
              # Ollama: llama2, mistral, codellama, etc.

# API credentials
OPENAI_API_KEY=sk-...  # Required for OpenAI

# Local model endpoint
LOCAL_MODEL_ENDPOINT=http://localhost:11434  # Ollama default
```

### Supported AI Providers

#### OpenAI (Cloud)
- **Models**: GPT-4, GPT-3.5 Turbo
- **Setup**: Requires API key (`OPENAI_API_KEY`)
- **Pros**: High accuracy, no local resources needed
- **Cons**: API costs, data sent to cloud

#### Ollama (Local)
- **Models**: Llama 2, Mistral, CodeLlama, and more
- **Setup**: Install Ollama, pull models locally
- **Pros**: Privacy, no API costs, works offline
- **Cons**: Requires GPU/CPU resources, lower accuracy

```bash
# Install Ollama (macOS)
brew install ollama

# Pull a model
ollama pull llama2
ollama pull mistral

# Start using local models
export AI_PROVIDER=ollama
export AI_MODEL=llama2
```

## SBOM Commands Reference

### Generation
```bash
# Generate SBOM from local directory
threat-radar sbom generate ./path/to/project -f cyclonedx-json

# Generate SBOM from Docker image
threat-radar sbom docker alpine:3.18 -o sbom.json

# Auto-save to sbom_storage/
threat-radar sbom generate . --auto-save
threat-radar sbom docker python:3.11 --auto-save
```

### Analysis
```bash
# Read and display SBOM
threat-radar sbom read sbom.json
threat-radar sbom read sbom.json --format json

# Get statistics
threat-radar sbom stats sbom.json

# Search for packages
threat-radar sbom search sbom.json openssl

# List components with filtering
threat-radar sbom components sbom.json --type library
threat-radar sbom components sbom.json --language python
threat-radar sbom components sbom.json --group-by type
```

### Comparison
```bash
# Compare two SBOMs (useful for tracking changes)
threat-radar sbom compare alpine-3.17-sbom.json alpine-3.18-sbom.json
threat-radar sbom compare old.json new.json --versions
```

### Export
```bash
# Export to CSV
threat-radar sbom export sbom.json -o packages.csv -f csv

# Export as requirements.txt (Python packages)
threat-radar sbom export sbom.json -o requirements.txt -f requirements
```

### Storage Management
```bash
# List all stored SBOMs
threat-radar sbom list

# List by category
threat-radar sbom list --category docker
threat-radar sbom list --category local
threat-radar sbom list --category comparisons

# Limit results
threat-radar sbom list --limit 10
```

## Comprehensive Reporting Commands

### Overview

The reporting system provides AI-powered vulnerability reports with multiple output formats and detail levels, designed for different audiences (executives, security teams, developers).

**Key Features:**
- **AI-Powered Executive Summaries** - Risk ratings, key findings, and business impact analysis
- **Multiple Output Formats** - JSON, Markdown, HTML for different use cases
- **Report Levels** - Executive, Summary, Detailed, Critical-only
- **Dashboard Data** - Visualization-ready data structures for custom dashboards
- **Trend Analysis** - Compare reports over time to track improvements

### Report Generation

```bash
# Generate comprehensive HTML report with AI executive summary
threat-radar report generate scan-results.json -o report.html -f html

# Executive summary in Markdown (for documentation)
threat-radar report generate scan-results.json -o summary.md -f markdown --level executive

# Detailed JSON report with dashboard data
threat-radar report generate scan-results.json -o detailed.json --level detailed

# Critical-only issues (for immediate action)
threat-radar report generate scan-results.json -o critical.json --level critical-only

# Use custom AI model
threat-radar report generate scan-results.json --ai-provider ollama --ai-model llama2

# Without AI executive summary (faster)
threat-radar report generate scan-results.json -o report.json --no-executive
```

### Report Levels

1. **Executive** - High-level summary for leadership
   - Overall risk rating (CRITICAL, HIGH, MEDIUM, LOW)
   - Key findings (3-5 bullet points)
   - Immediate actions required
   - Business impact and compliance concerns
   - Estimated remediation effort and timeline

2. **Summary** - Overview with key metrics
   - Vulnerability statistics
   - Top vulnerable packages
   - Critical/High severity findings
   - Quick remediation recommendations

3. **Detailed** (default) - Complete report
   - All vulnerabilities with full details
   - Package-level groupings
   - CVSS scores and severity ratings
   - Fix availability and upgrade paths
   - Dashboard visualization data

4. **Critical-Only** - Filtered for urgent issues
   - Only CRITICAL and HIGH severity vulnerabilities
   - Immediate action items
   - Priority remediation guidance

### Output Formats

#### JSON Format
```bash
threat-radar report generate scan.json -o report.json -f json
```
- Machine-readable structured data
- Suitable for API integrations
- Complete data including dashboard structures
- Easy parsing for automation

#### Markdown Format
```bash
threat-radar report generate scan.json -o report.md -f markdown
```
- Human-readable documentation
- Great for GitHub/GitLab issues
- Includes severity icons and charts
- Easy to version control

#### HTML Format
```bash
threat-radar report generate scan.json -o report.html -f html
```
- Beautiful web-based reports
- Styled with modern CSS
- Interactive tables and cards
- Shareable via web browser
- No external dependencies

### Dashboard Data Export

Export visualization-ready data for custom dashboards (Grafana, custom web apps, etc.):

```bash
# Export dashboard data structure
threat-radar report dashboard-export scan-results.json -o dashboard.json
```

**Dashboard data includes:**
- **Summary Cards** - Total vulnerabilities, critical count, average CVSS, fix availability
- **Severity Distribution** - Data for pie/bar charts with colors
- **Top Vulnerable Packages** - Horizontal bar chart data
- **CVSS Score Histogram** - Distribution buckets (0-10)
- **Package Type Breakdown** - Vulnerabilities by ecosystem (npm, pip, alpine, etc.)
- **Critical Items List** - Top 20 critical/high issues with details

Example dashboard.json structure:
```json
{
  "summary_cards": {
    "total_vulnerabilities": 45,
    "critical_vulnerabilities": 5,
    "average_cvss_score": 6.8,
    "fix_available_percentage": 75.5
  },
  "severity_distribution_chart": [
    {"severity": "Critical", "count": 5, "color": "#dc2626"},
    {"severity": "High", "count": 12, "color": "#ea580c"}
  ],
  "top_vulnerable_packages_chart": [
    {"package": "openssl@1.1.1", "vulnerability_count": 8, "severity": "high"}
  ]
}
```

### Report Comparison

Track vulnerability changes over time:

```bash
# Compare two scan results
threat-radar report compare old-scan.json new-scan.json

# Save comparison report
threat-radar report compare baseline.json current.json -o comparison.json
```

**Comparison shows:**
- New vulnerabilities discovered
- Fixed vulnerabilities (improvements)
- Common vulnerabilities (ongoing issues)
- Trend analysis (improving/worsening/stable)
- Severity distribution changes

### Complete Workflow Examples

#### Weekly Security Report

```bash
#!/bin/bash
# weekly-security-scan.sh - Run every Monday

WEEK=$(date +%Y-W%U)
IMAGE="myapp:production"

# 1. Scan production Docker image
threat-radar cve scan-image $IMAGE --auto-save -o scan-${WEEK}.json

# 2. Generate comprehensive HTML report for security team
threat-radar report generate scan-${WEEK}.json \
  -o reports/detailed-${WEEK}.html \
  -f html \
  --level detailed \
  --ai-provider openai

# 3. Generate executive summary for leadership meeting
threat-radar report generate scan-${WEEK}.json \
  -o reports/exec-${WEEK}.md \
  -f markdown \
  --level executive

# 4. Export dashboard data for Grafana monitoring
threat-radar report dashboard-export scan-${WEEK}.json \
  -o dashboards/metrics-${WEEK}.json

# 5. Compare with last week's scan
if [ -f "scan-${LAST_WEEK}.json" ]; then
  threat-radar report compare \
    scan-${LAST_WEEK}.json \
    scan-${WEEK}.json \
    -o reports/trend-${WEEK}.json

  # Alert if situation is worsening
  TREND=$(jq -r '.trend' reports/trend-${WEEK}.json)
  if [ "$TREND" = "worsening" ]; then
    send_slack_alert "⚠️  Security posture worsening! Check reports/exec-${WEEK}.md"
  fi
fi

# 6. Send reports via email/Slack
send_report_email reports/exec-${WEEK}.md "leadership@company.com"
send_slack_report reports/detailed-${WEEK}.html "#security-team"

echo "✅ Weekly security report complete!"
```

#### CI/CD Pipeline Integration

```yaml
# .github/workflows/security-scan.yml
name: Container Security Scan
on:
  push:
    branches: [main, develop]
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Build Docker image
        run: docker build -t app:${{ github.sha }} .

      - name: Install Threat Radar
        run: pip install threat-radar

      - name: Scan for vulnerabilities
        run: |
          threat-radar cve scan-image app:${{ github.sha }} \
            -o scan-results.json \
            --auto-save \
            --cleanup

      - name: Generate critical-only report
        run: |
          threat-radar report generate scan-results.json \
            -o critical-report.json \
            --level critical-only

      - name: Check for blocking vulnerabilities
        run: |
          CRITICAL=$(jq '.summary.critical' critical-report.json)
          HIGH=$(jq '.summary.high' critical-report.json)

          if [ $CRITICAL -gt 0 ]; then
            echo "❌ CRITICAL: $CRITICAL critical vulnerabilities found!"
            jq -r '.findings[] | select(.severity=="critical") | "  - \(.cve_id): \(.package_name)"' critical-report.json
            exit 1
          elif [ $HIGH -gt 10 ]; then
            echo "⚠️  WARNING: $HIGH high-severity vulnerabilities found"
            exit 1
          fi

      - name: Generate PR comment report
        if: github.event_name == 'pull_request'
        run: |
          threat-radar report generate scan-results.json \
            -o pr-report.md \
            -f markdown \
            --level summary

          gh pr comment ${{ github.event.pull_request.number }} \
            --body-file pr-report.md

      - name: Upload reports as artifacts
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-reports
          path: |
            scan-results.json
            critical-report.json
            pr-report.md
```

#### Trend Monitoring & Compliance

```bash
#!/bin/bash
# quarterly-compliance-report.sh

QUARTER=$(date +%Y-Q$(( ($(date +%-m)-1)/3+1 )))
IMAGES=(
  "frontend:production"
  "backend:production"
  "api:production"
  "worker:production"
)

echo "Generating quarterly compliance report for $QUARTER..."

# Scan all production images
for IMAGE in "${IMAGES[@]}"; do
  echo "Scanning $IMAGE..."

  threat-radar cve scan-image $IMAGE \
    -o "compliance/${IMAGE//:/─}-${QUARTER}.json" \
    --auto-save

  # Generate detailed report for each service
  threat-radar report generate \
    "compliance/${IMAGE//:/─}-${QUARTER}.json" \
    -o "compliance/${IMAGE//:/─}-${QUARTER}.html" \
    -f html \
    --level detailed \
    --ai-provider openai
done

# Generate consolidated compliance summary
python3 << 'EOF'
import json
import glob
from pathlib import Path
from datetime import datetime

scans = []
for f in glob.glob('compliance/*-Q*.json'):
    with open(f) as file:
        scans.append(json.load(file))

summary = {
    'quarter': '${QUARTER}',
    'report_date': datetime.now().isoformat(),
    'total_images': len(scans),
    'total_vulnerabilities': sum(s['total_vulnerabilities'] for s in scans),
    'critical_count': sum(s['severity_counts'].get('critical', 0) for s in scans),
    'high_count': sum(s['severity_counts'].get('high', 0) for s in scans),
    'compliance_status': 'PASS' if all(s['severity_counts'].get('critical', 0) == 0 for s in scans) else 'REQUIRES_REMEDIATION',
    'images_scanned': [s['target'] for s in scans],
}

Path('compliance/SUMMARY-${QUARTER}.json').write_text(json.dumps(summary, indent=2))
print(f"✅ Compliance summary: compliance/SUMMARY-${QUARTER}.json")
EOF

# Archive for audit trail
tar -czf "compliance-${QUARTER}.tar.gz" compliance/
echo "📦 Archived to: compliance-${QUARTER}.tar.gz"
```

#### Custom Dashboard Integration

```python
#!/usr/bin/env python3
# dashboard-updater.py - Update custom dashboard with latest scan data

import json
from pathlib import Path
from datetime import datetime
import requests

def update_dashboard(scan_file):
    """Update custom dashboard with scan results."""

    # Generate dashboard data
    from threat_radar.utils import ComprehensiveReportGenerator
    from threat_radar.core.grype_integration import GrypeScanResult

    # Load scan results
    with open(scan_file) as f:
        scan_data = json.load(f)

    # Convert to GrypeScanResult
    # ... (conversion code) ...

    # Generate dashboard data
    generator = ComprehensiveReportGenerator()
    report = generator.generate_report(
        scan_result=scan_result,
        include_dashboard_data=True,
    )

    dashboard_data = report.dashboard_data.to_dict()

    # Update Grafana
    update_grafana_dashboard(dashboard_data)

    # Update custom web dashboard
    update_web_dashboard(dashboard_data)

    # Send metrics to monitoring system
    send_metrics_to_prometheus(dashboard_data)

def update_grafana_dashboard(data):
    """Push metrics to Grafana."""
    grafana_url = "http://grafana:3000/api/dashboards/db"
    headers = {"Authorization": f"Bearer {os.getenv('GRAFANA_TOKEN')}"}

    dashboard = {
        "dashboard": {
            "title": "Vulnerability Metrics",
            "panels": [
                {
                    "title": "Total Vulnerabilities",
                    "type": "stat",
                    "targets": [{
                        "expr": data['summary_cards']['total_vulnerabilities']
                    }]
                },
                # ... more panels ...
            ]
        }
    }

    requests.post(grafana_url, json=dashboard, headers=headers)

def update_web_dashboard(data):
    """Update web-based dashboard."""
    # Save data for React/Vue frontend
    web_data = {
        "lastUpdated": datetime.now().isoformat(),
        "metrics": data['summary_cards'],
        "charts": {
            "severity": data['severity_distribution_chart'],
            "packages": data['top_vulnerable_packages_chart'],
        }
    }

    Path('/var/www/dashboard/data.json').write_text(json.dumps(web_data))

def send_metrics_to_prometheus(data):
    """Send metrics to Prometheus pushgateway."""
    from prometheus_client import CollectorRegistry, Gauge, push_to_gateway

    registry = CollectorRegistry()

    # Define metrics
    total_vulns = Gauge('vulnerability_total', 'Total vulnerabilities', registry=registry)
    critical_vulns = Gauge('vulnerability_critical', 'Critical vulnerabilities', registry=registry)

    # Set values
    total_vulns.set(data['summary_cards']['total_vulnerabilities'])
    critical_vulns.set(data['summary_cards']['critical_vulnerabilities'])

    # Push to gateway
    push_to_gateway('pushgateway:9091', job='vulnerability-scan', registry=registry)

if __name__ == "__main__":
    update_dashboard("latest-scan.json")
```

### Report Architecture

#### Core Components

- **`report_templates.py`** - Data structures and models
  - `ComprehensiveReport` - Main report container
  - `VulnerabilitySummary` - Statistical metrics
  - `VulnerabilityFinding` - Individual CVE details
  - `PackageVulnerabilities` - Package-grouped findings
  - `ExecutiveSummary` - AI-generated executive summary
  - `DashboardData` - Visualization-ready structures

- **`comprehensive_report.py`** - Report generator
  - `ComprehensiveReportGenerator` - Main report generation engine
  - AI-powered executive summary generation
  - Dashboard data construction
  - Remediation recommendations

- **`report_formatters.py`** - Output format handlers
  - `JSONFormatter` - JSON output
  - `MarkdownFormatter` - Markdown documentation
  - `HTMLFormatter` - Styled HTML reports

## Docker Commands Reference

```bash
# Import and analyze an image
threat-radar docker import-image alpine:3.18 -o analysis.json

# Scan existing local image
threat-radar docker scan ubuntu:22.04

# List all local Docker images
threat-radar docker list-images

# List packages in an image
threat-radar docker packages alpine:3.18 --limit 20 --filter openssl

# Generate Python SBOM
threat-radar docker python-sbom python:3.11 -o sbom.json --format cyclonedx
```

## Development Notes

### Module Structure
- `threat_radar/ai/` - **IMPLEMENTED**: AI-powered vulnerability analysis, prioritization, and remediation
  - Supports OpenAI GPT and Ollama (local models)
  - See AI Commands Reference section above for full capabilities
- `threat_radar/ontology/` - Reserved for ontology/schema definitions
- `threat_radar/remediation/` - Reserved for remediation strategies
- `threat_radar/risk/` - Reserved for risk assessment
- `threat_radar/scenarios/` - Reserved for threat scenarios

### Storage Organization

The project uses organized storage directories (git-ignored):

- **`./storage/cve_storage/`** - CVE scan results with timestamped filenames
  - Created automatically with `--auto-save` or `--as` flag
  - Format: `<target>_<type>_YYYY-MM-DD_HH-MM-SS.json`
  - Useful for tracking vulnerability trends over time

- **`./storage/ai_analysis/`** - AI analysis results
  - Analysis, prioritization, and remediation reports
  - Auto-saved with `--auto-save` flag in AI commands
  - Format: `<target>_<analysis_type>_YYYY-MM-DD_HH-MM-SS.json`

- **`./sbom_storage/`** - SBOM files organized by category
  - `docker/` - SBOMs from Docker images
  - `local/` - SBOMs from local directories
  - `comparisons/` - SBOM comparison results
  - `archives/` - Historical SBOMs

### Testing Patterns
- Tests use fixtures in `tests/fixtures/` directory
- Docker tests in `test_docker_integration.py` require Docker daemon running
- Hash tests in `test_hasher.py` test file integrity verification

### Dependencies
Core Python dependencies:
- `PyGithub==2.1.1` - GitHub API integration
- `python-dotenv==1.0.0` - Environment variable management
- `typer>=0.9.0` - CLI framework
- `docker>=7.0.0` - Docker SDK
- `anchore-syft>=1.18.0` - SBOM generation (optional Python bindings)

External tools (must be installed separately):
- **Grype** - Vulnerability scanner (required for CVE scanning)
  - Install: `brew install grype` (macOS) or see https://github.com/anchore/grype
- **Syft** - SBOM generator (required for SBOM operations)
  - Install: `brew install syft` (macOS) or see https://github.com/anchore/syft

Dev dependencies include pytest, black, flake8, mypy for testing and code quality.

## Environment Configuration

Create `.env` file from `.env.example`:
```
GITHUB_ACCESS_TOKEN=your_github_personal_access_token_here
NVD_API_KEY=your_nvd_api_key_here

# AI Configuration
OPENAI_API_KEY=your_openai_api_key_here
AI_PROVIDER=openai
AI_MODEL=gpt-4
LOCAL_MODEL_ENDPOINT=http://localhost:11434
```

- `GITHUB_ACCESS_TOKEN` - Required for GitHub integration features
- `NVD_API_KEY` - Optional, for higher rate limits with NVD API
- `OPENAI_API_KEY` - Required for AI features with OpenAI
- `AI_PROVIDER` - Set to `openai` or `ollama` for AI provider selection
- `AI_MODEL` - Model name (e.g., `gpt-4`, `llama2`)
- `LOCAL_MODEL_ENDPOINT` - Ollama endpoint (default: `http://localhost:11434`)
