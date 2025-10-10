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
- `cve.py` - CVE operations with SBOM integration (includes CVSS scoring data)
- `docker.py` - Docker container analysis commands
- `sbom.py` - SBOM operations
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
- `threat_radar/ai/` - Placeholder for AI/LLM features
- `threat_radar/ontology/` - Placeholder for ontology/schema definitions
- `threat_radar/remediation/` - Placeholder for remediation strategies
- `threat_radar/risk/` - Placeholder for risk assessment
- `threat_radar/scenarios/` - Placeholder for threat scenarios

These modules are currently empty but reserved for future functionality.

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
```

This token is required for GitHub integration features.
