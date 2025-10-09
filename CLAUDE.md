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
- `cve.py` - CVE operations with SBOM integration
- `cvss.py` - CVSS scoring operations
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

#### CVE Integration (`threat_radar/core/`) **NEW**
- **`nvd_client.py`** - `NVDClient` class for interacting with NVD REST API
  - Rate-limited requests (5/30s public, 50/30s with API key)
  - CVE retrieval by ID, search with filters (keyword, CPE, severity, dates)
  - Local caching system (7-day cache)
  - CVSS v3.1/v3.0/v2.0 metric extraction

- **`cve_database.py`** - `CVEDatabase` class for local CVE storage
  - SQLite database at `~/.threat_radar/cve.db`
  - Incremental updates from NVD
  - Fast local search with severity/CVSS filters
  - Statistics and metadata tracking

- **`cve_matcher.py`** - `CVEMatcher` engine for matching packages to CVEs
  - Version comparison with semantic versioning support
  - Fuzzy package name matching with known mappings
  - Confidence scoring (name similarity + version match + CVSS)
  - Configurable filters (age, disputed CVEs, vendor allowlist)

- **`sbom_package_converter.py`** - **NEW**: Converts SBOM to CVE-matchable packages
  - Auto-detects SBOM format (CycloneDX, SPDX, Syft JSON)
  - Converts SBOM components to `Package` objects
  - Package type filtering and statistics
  - Architecture extraction from PURLs

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

## CVE Commands Reference **NEW**

```bash
# Scan Docker image for CVEs (SBOM-based by default)
threat-radar cve scan-image alpine:3.18
threat-radar cve scan-image ubuntu:22.04 --severity HIGH -o results.json

# Use native package manager analysis (legacy mode)
threat-radar cve scan-image alpine:3.18 --no-sbom

# Scan pre-generated SBOM file for CVEs (CI/CD friendly)
threat-radar cve scan-sbom my-app-sbom.json
threat-radar cve scan-sbom docker-sbom.json --severity CRITICAL
threat-radar cve scan-sbom sbom.json --format cyclonedx -o cve-results.json

# CVE database management
threat-radar cve update --days 30              # Update local CVE database
threat-radar cve stats                         # Show database statistics
threat-radar cve db-search --severity HIGH     # Search local database

# Individual CVE operations
threat-radar cve get CVE-2021-44228            # Get specific CVE
threat-radar cve search --keyword log4j        # Search NVD by keyword
threat-radar cve clear-cache                   # Clear CVE cache
```

### CVE Scanning Workflow

**Three methods for CVE scanning:**

1. **SBOM-based (Default, Recommended)**: `cve scan-image --use-sbom`
   - Uses Syft to generate SBOM on-the-fly
   - Detects OS packages + application dependencies (npm, pip, go, etc.)
   - More comprehensive coverage

2. **Native Package Manager**: `cve scan-image --no-sbom`
   - Runs dpkg/apk/rpm inside container
   - Only detects OS packages
   - Faster, no Syft dependency

3. **Pre-Generated SBOM**: `cve scan-sbom <file>`
   - Scans existing SBOM files
   - No Docker or Syft required
   - Perfect for CI/CD pipelines, works offline

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
Core dependencies:
- `PyGithub==2.1.1` - GitHub API integration
- `python-dotenv==1.0.0` - Environment variable management
- `typer>=0.9.0` - CLI framework
- `docker>=7.0.0` - Docker SDK

Dev dependencies include pytest, black, flake8, mypy for testing and code quality.

## Environment Configuration

Create `.env` file from `.env.example`:
```
GITHUB_ACCESS_TOKEN=your_github_personal_access_token_here
```

This token is required for GitHub integration features.
