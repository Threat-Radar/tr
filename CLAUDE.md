# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Threat Radar (tr) is a threat assessment and analysis platform for security vulnerability management. It provides Docker container analysis, SBOM generation, package extraction, and GitHub integration for security analysis.

## Quick Reference

Common development tasks:

```bash
# Setup and verify installation
pip install -e .
threat-radar --help

# Run vulnerability scan
threat-radar cve scan-image alpine:3.18 --auto-save

# Use global options for verbose output and JSON format
threat-radar -vv -f json cve scan-image python:3.11 --auto-save

# Load configuration from custom file
threat-radar --config ./myconfig.json cve scan-image ubuntu:22.04

# Quiet mode for CI/CD (errors only)
threat-radar -q --no-color cve scan-image myapp:latest --fail-on HIGH

# Generate SBOM
threat-radar sbom docker python:3.11 -o sbom.json

# Run AI analysis (requires API key in .env)
threat-radar ai analyze scan-results.json --auto-save

# Generate comprehensive report
threat-radar report generate scan-results.json -o report.html -f html

# Build vulnerability graph for relationship analysis
threat-radar graph build scan-results.json --auto-save
threat-radar graph query graph.graphml --cve CVE-2023-1234
threat-radar graph query graph.graphml --top-packages 10 --stats

# Environment configuration and business context
threat-radar env validate my-environment.json
threat-radar env build-graph production.json --auto-save
threat-radar env analyze-risk production.json scan-results.json --auto-save

# Run tests
pytest                                    # All tests
pytest tests/test_grype_integration.py   # Specific test file
pytest -v -k "scan"                      # Tests matching pattern

# Code quality
black threat_radar/ tests/               # Format code
mypy threat_radar/                       # Type checking
flake8 threat_radar/                     # Linting
```

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

# Run specific test within a file
pytest tests/test_ai_integration.py::TestVulnerabilityAnalyzer::test_analyze_vulnerabilities

# Run with coverage
pytest --cov=threat_radar --cov-report=html

# Run with verbose output
pytest -v

# Run tests matching a pattern
pytest -k "grype"
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

## CLI Global Options & Configuration

### Global Options

All Threat Radar commands support global options that control behavior across the entire CLI:

```bash
threat-radar [OPTIONS] COMMAND [ARGS]

Global Options:
  -c, --config PATH        Path to configuration file (JSON format)
  -v, --verbose            Increase verbosity (can be repeated: -v, -vv, -vvv)
  -q, --quiet              Suppress all output except errors
  -f, --output-format TEXT Default output format (table, json, yaml, csv)
  --no-color               Disable colored output
  --no-progress            Disable progress indicators
  --help                   Show help message
```

### Verbosity Levels

Control the amount of output and logging:

| Level | Flag | Description | Use Case |
|-------|------|-------------|----------|
| 0 | `--quiet` or `-q` | Errors only | Scripts, automation |
| 1 | (default) | Warnings and errors | Normal interactive use |
| 2 | `-v` | Info, warnings, errors | Debugging issues |
| 3 | `-vv` or `-vvv` | Debug - everything | Development, troubleshooting |

**Examples:**
```bash
# Quiet mode for automation
threat-radar -q cve scan-image alpine:3.18

# Verbose debugging
threat-radar -vv cve scan-image python:3.11

# Very verbose with all internal logging
threat-radar -vvv ai analyze scan.json
```

### Configuration File Support

Threat Radar supports persistent configuration through JSON files. Configuration is searched in the following order (first found wins):

1. `./.threat-radar.json` (current directory)
2. `./threat-radar.json` (current directory)
3. `~/.threat-radar/config.json` (user home)
4. `~/.config/threat-radar/config.json` (XDG config)

**Configuration precedence (later overrides earlier):**
1. Default values (built into code)
2. Configuration file (if found)
3. Environment variables (if set)
4. Command-line options (highest priority)

**Example configuration file:**
```json
{
  "scan": {
    "severity": "HIGH",
    "only_fixed": false,
    "auto_save": true,
    "cleanup": false,
    "scope": "squashed",
    "output_format": "json"
  },
  "ai": {
    "provider": "openai",
    "model": "gpt-4o",
    "temperature": 0.3,
    "batch_size": 25,
    "auto_batch_threshold": 30
  },
  "report": {
    "level": "detailed",
    "format": "json",
    "include_executive_summary": true,
    "include_dashboard_data": true
  },
  "output": {
    "format": "table",
    "verbosity": 1,
    "color": true,
    "progress": true
  },
  "paths": {
    "cve_storage": "./storage/cve_storage",
    "ai_storage": "./storage/ai_analysis",
    "sbom_storage": "./sbom_storage",
    "cache_dir": "~/.threat-radar/cache",
    "config_dir": "~/.threat-radar"
  }
}
```

### Configuration Management Commands

```bash
# Initialize new configuration file
threat-radar config init
threat-radar config init --path ./my-config.json
threat-radar config init --force  # Overwrite existing

# Show current configuration
threat-radar config show
threat-radar config show scan.severity
threat-radar config show ai.provider

# Modify configuration
threat-radar config set scan.severity HIGH
threat-radar config set ai.provider ollama
threat-radar config set output.verbosity 2

# Validate configuration file
threat-radar config validate
threat-radar config validate ./my-config.json

# Show configuration file locations
threat-radar config path
```

### Output Formats

Threat Radar supports multiple output formats for different use cases:

- **table** (default) - Human-readable formatted tables for interactive use
- **json** - Machine-readable JSON output for automation and parsing
- **yaml** - YAML format for human-readable structured data
- **csv** - Comma-separated values for spreadsheet compatibility

**Examples:**
```bash
# JSON output for automation
threat-radar -f json cve scan-image alpine:3.18

# CSV output for spreadsheets
threat-radar -f csv sbom components sbom.json -o packages.csv

# Combine with other global options
threat-radar -q -f json --no-color cve scan-image myapp:latest > results.json
```

**For complete CLI features documentation, see [docs/CLI_FEATURES.md](docs/CLI_FEATURES.md)**

## Architecture

### CLI Structure
The CLI is built with Typer and uses a modular command structure in `threat_radar/cli/`:
- `app.py` - Main CLI app with global options callback (--config, --verbose, --quiet, --output-format, --no-color, --no-progress) and sub-command registration
- `__main__.py` - Entry point for `python -m threat_radar.cli` and CLI scripts
- `cve.py` - CVE vulnerability scanning with Grype (scan-image, scan-sbom, scan-directory, db-update, db-status)
- `docker.py` - Docker container analysis commands (import-image, scan, packages, list-images, python-sbom)
- `sbom.py` - SBOM generation and operations (generate, docker, read, compare, stats, export, search, list, components)
- `ai.py` - AI-powered vulnerability analysis (analyze, prioritize, remediate) with batch processing support
- `report.py` - Comprehensive reporting with AI executive summaries (generate, dashboard-export, compare)
- `graph.py` - Graph database operations for vulnerability modeling (build, query, list, info, fixes, cleanup)
- `env.py` - Environment configuration and business context management (validate, build-graph, analyze-risk)
- `hash.py` - File hashing utilities
- `config.py` - Configuration management (show, set, init, path, validate)

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
- **`config_manager.py`** - Configuration management system
  - `ThreatRadarConfig` - Main configuration dataclass with nested defaults for scan, AI, report, output, and paths
  - `ConfigManager` - Manages config loading from JSON files, environment variables, and defaults
  - Supports multiple config file locations with precedence rules
  - Dot-notation key access (e.g., `config.get('scan.severity')`)
  - Save/load config to/from JSON files
- **`cli_context.py`** - Global CLI context management
  - `CLIContext` - Holds global CLI state (config_manager, verbosity, output_format, console, etc.)
  - Integrates with Rich console for colored output and progress bars
  - Sets up logging based on verbosity level (0-3)
  - Global context getter/setter for accessing CLI options across commands

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
# - OPENAI_API_KEY=your_key_here (for OpenAI)
# - ANTHROPIC_API_KEY=sk-ant-your-key-here (for Claude)
# - AI_PROVIDER=openai  # or 'anthropic' or 'ollama'
# - AI_MODEL=gpt-4o  # or 'gpt-4-turbo', 'claude-3-5-sonnet-20241022', 'llama2'
# - LOCAL_MODEL_ENDPOINT=http://localhost:11434  # Ollama default
```

### AI Analysis Commands

#### Analyze Vulnerabilities

Analyze CVE scan results to understand exploitability and business impact:

```bash
# Basic analysis (auto-batches for large scans)
threat-radar ai analyze cve-results.json

# Specify AI provider and model
threat-radar ai analyze results.json --provider openai --model gpt-4o
threat-radar ai analyze results.json --provider anthropic --model claude-3-5-sonnet-20241022

# Save analysis to file
threat-radar ai analyze scan.json -o analysis.json

# Auto-save to storage/ai_analysis/
threat-radar ai analyze results.json --auto-save

# Use local model (Ollama)
threat-radar ai analyze scan.json --provider ollama --model llama2
```

**BATCH PROCESSING FOR LARGE SCANS:**

Automatically handles 100+ CVE scans via intelligent batch processing:

```bash
# Auto-batch mode (default) - automatically batches when >30 CVEs
threat-radar ai analyze large-scan.json

# Force batch processing with custom size
threat-radar ai analyze scan.json --batch-mode enabled --batch-size 30

# Disable batching (use single-pass, may fail for large scans)
threat-radar ai analyze scan.json --batch-mode disabled

# Hide progress bar (useful for CI/CD)
threat-radar ai analyze scan.json --no-progress
```

**How batch processing works:**
- **Auto-detection**: Scans with >30 CVEs automatically use batching
- **Configurable**: Adjust batch size via `--batch-size` (default: 25)
- **Progress tracking**: Real-time progress bar with batch status
- **Failure recovery**: Individual batch failures don't stop analysis
- **Summary consolidation**: AI generates executive summary across all batches
- **Performance**: 100 CVEs analyzed in ~45s (4 batches), 150 CVEs in ~60s (6 batches)

**Batch modes:**
- `auto` (default): Automatically batch when count > 30
- `enabled`: Force batching regardless of count
- `disabled`: Single-pass only (original behavior)

**SEVERITY FILTERING:**

Reduce analysis time and cost by filtering to specific severity levels:

```bash
# Analyze only CRITICAL vulnerabilities
threat-radar ai analyze scan.json --severity critical

# Analyze HIGH and above (critical + high)
threat-radar ai analyze scan.json --severity high

# Analyze MEDIUM and above (critical + high + medium)
threat-radar ai analyze scan.json --severity medium

# Combine with batch processing
threat-radar ai analyze large-scan.json --severity high --batch-size 20
```

**Severity levels** (from highest to lowest):
- `critical` - Only critical severity
- `high` - Critical + High
- `medium` - Critical + High + Medium
- `low` - Critical + High + Medium + Low

**Use cases:**
- Focus on urgent vulnerabilities only
- Reduce API costs for large scans
- Quick triage of critical issues
- CI/CD pipelines that only care about severe issues

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
  - `AnthropicClient` - Anthropic Claude integration
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
AI_PROVIDER=openai  # or 'anthropic' or 'ollama'

# Model selection
AI_MODEL=gpt-4o  # OpenAI: gpt-4o, gpt-4-turbo, gpt-3.5-turbo-1106 (requires JSON mode support)
               # Anthropic: claude-3-5-sonnet-20241022, claude-3-opus-20240229
               # Ollama: llama2, mistral, codellama, etc.

# API credentials
OPENAI_API_KEY=sk-...  # Required for OpenAI
ANTHROPIC_API_KEY=sk-ant-...  # Required for Anthropic

# Local model endpoint
LOCAL_MODEL_ENDPOINT=http://localhost:11434  # Ollama default
```

### Supported AI Providers

#### OpenAI (Cloud)
- **Models**: GPT-4o (recommended), GPT-4 Turbo, GPT-3.5 Turbo
- **Setup**: Requires API key (`OPENAI_API_KEY`)
- **Pros**: High accuracy, no local resources needed
- **Cons**: API costs, data sent to cloud
- **Note**: Use models with JSON mode support (gpt-4o, gpt-4-turbo, gpt-3.5-turbo-1106 or later)

#### Anthropic Claude (Cloud)
- **Models**: Claude 3.5 Sonnet, Claude 3 Opus, Claude 3 Sonnet
- **Setup**: Requires API key (`ANTHROPIC_API_KEY`)
- **Pros**: High accuracy, excellent reasoning, good at structured outputs
- **Cons**: API costs, data sent to cloud

```bash
# Get API key from https://console.anthropic.com/
export ANTHROPIC_API_KEY=sk-ant-your-key-here
export AI_PROVIDER=anthropic
export AI_MODEL=claude-3-5-sonnet-20241022

# Use with any AI command
threat-radar ai analyze scan.json --provider anthropic
threat-radar ai prioritize scan.json --provider anthropic
threat-radar ai remediate scan.json --provider anthropic
```

**Available Claude Models:**
- `claude-3-5-sonnet-20241022` (recommended, best balance)
- `claude-3-opus-20240229` (highest capability)
- `claude-3-sonnet-20240229` (faster, cost-effective)

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

## Graph Commands Reference

### Overview

The graph database integration provides relationship-based vulnerability analysis using NetworkX. It models containers, packages, vulnerabilities, and their relationships as a graph structure for advanced queries.

**Key Features:**
- **Vulnerability Blast Radius**: Find all assets affected by a CVE
- **Package Risk Analysis**: Identify most vulnerable packages
- **Fix Recommendations**: Discover vulnerabilities with available patches
- **Attack Path Discovery**: Trace potential attack vectors through dependencies
- **Persistent Storage**: Save graphs for historical analysis

### Graph Building

```bash
# Build graph from CVE scan results
threat-radar graph build scan-results.json -o vulnerability-graph.graphml

# Auto-save to storage/graph_storage/
threat-radar graph build scan-results.json --auto-save

# Example workflow: Scan and build graph
threat-radar cve scan-image alpine:3.18 --auto-save -o scan.json
threat-radar graph build scan.json --auto-save
```

### Graph Querying

```bash
# Find containers affected by a CVE (blast radius)
threat-radar graph query graph.graphml --cve CVE-2023-1234

# Show top 10 most vulnerable packages
threat-radar graph query graph.graphml --top-packages 10

# Display vulnerability statistics
threat-radar graph query graph.graphml --stats

# Combined query
threat-radar graph query graph.graphml --cve CVE-2023-1234 --stats
```

### Graph Management

```bash
# List all stored graphs
threat-radar graph list
threat-radar graph list --limit 10

# Show detailed graph information
threat-radar graph info graph.graphml

# Find vulnerabilities with available fixes
threat-radar graph fixes graph.graphml
threat-radar graph fixes graph.graphml --severity critical

# Clean up old graphs
threat-radar graph cleanup --days 30
threat-radar graph cleanup --days 30 --force
```

### Graph Architecture

**Node Types:**
- **Container**: Docker images and their metadata
- **Package**: Installed packages (OS and application)
- **Vulnerability**: CVE entries with severity and CVSS scores
- **Service**: Exposed services (ports, protocols)
- **Host**: Infrastructure hosts (future)
- **ScanResult**: Scan metadata and timestamps

**Edge Types:**
- **CONTAINS**: Container → Package (container includes package)
- **HAS_VULNERABILITY**: Package → Vulnerability (package has CVE)
- **FIXED_BY**: Vulnerability → Package (CVE fixed in version)
- **DEPENDS_ON**: Container → Container (dependency chain)
- **EXPOSES**: Container → Service (exposed services)
- **RUNS_ON**: Container → Host (deployment location)
- **SCANNED_BY**: Container → ScanResult (scan history)

### Graph Storage

Graphs are stored in `./storage/graph_storage/` with timestamped filenames:

```bash
# Storage location
./storage/graph_storage/
  ├── alpine_3_18_2025-01-09_14-30-45.graphml
  ├── alpine_3_18_2025-01-09_14-30-45.json  # Metadata
  └── python_3_11_2025-01-09_15-00-00.graphml

# Manage storage
ls -lh storage/graph_storage/
du -sh storage/graph_storage/
```

### Complete Workflow Example

```bash
# 1. Scan multiple images
threat-radar cve scan-image alpine:3.18 --auto-save -o alpine-scan.json
threat-radar cve scan-image python:3.11 --auto-save -o python-scan.json
threat-radar cve scan-image nginx:alpine --auto-save -o nginx-scan.json

# 2. Build graphs
threat-radar graph build alpine-scan.json --auto-save
threat-radar graph build python-scan.json --auto-save
threat-radar graph build nginx-scan.json --auto-save

# 3. Analyze vulnerability landscape
threat-radar graph list
threat-radar graph query latest-graph.graphml --stats

# 4. Find critical CVE impact
threat-radar graph query latest-graph.graphml --cve CVE-2023-XXXX

# 5. Identify fix candidates
threat-radar graph fixes latest-graph.graphml --severity critical

# 6. Export for custom dashboards
# Graphs are in GraphML format, compatible with:
# - Python NetworkX
# - Gephi (visualization)
# - Neo4j (import)
# - Custom analysis tools
```

### Python API Usage

```python
from threat_radar.graph import NetworkXClient, GraphBuilder, GraphAnalyzer
from threat_radar.core import GrypeScanResult
from threat_radar.utils.graph_storage import GraphStorageManager

# Load scan results
with open("scan-results.json") as f:
    scan_data = json.load(f)
    scan_result = GrypeScanResult.from_dict(scan_data)

# Build graph
client = NetworkXClient()
builder = GraphBuilder(client)
builder.build_from_scan(scan_result)

# Query graph
analyzer = GraphAnalyzer(client)
blast_radius = analyzer.blast_radius("CVE-2023-1234")
vulnerable_packages = analyzer.most_vulnerable_packages(top_n=10)
stats = analyzer.vulnerability_statistics()

# Save graph
storage = GraphStorageManager()
storage.save_graph(client, "my-analysis")
```

### Advanced Use Cases

**1. Vulnerability Trend Analysis**
```bash
# Build graphs over time
threat-radar graph build scan-week1.json -o week1.graphml
threat-radar graph build scan-week2.json -o week2.graphml
threat-radar graph build scan-week3.json -o week3.graphml

# Compare graphs programmatically to track improvements
```

**2. Multi-Container Risk Assessment**
```bash
# Scan entire stack
for image in frontend:latest backend:latest api:latest; do
  threat-radar cve scan-image $image --auto-save -o ${image//:/─}-scan.json
  threat-radar graph build ${image//:/─}-scan.json --auto-save
done

# Analyze shared vulnerabilities across containers
```

**3. CI/CD Integration**
```bash
# Pipeline: Fail if critical vulnerabilities found
threat-radar cve scan-image $IMAGE --auto-save -o scan.json
threat-radar graph build scan.json -o graph.graphml
threat-radar graph fixes graph.graphml --severity critical > critical-fixes.txt

if [ -s critical-fixes.txt ]; then
  echo "CRITICAL vulnerabilities found!"
  exit 1
fi
```

### Future Enhancements (Sprint 2+)

- **Neo4j Support**: Migrate to Neo4j for production-scale deployments
- **Container Dependencies**: Auto-detect Docker Compose/orchestration dependencies
- **Network Topology**: Map container communication patterns
- **Graph Visualization**: Built-in graph rendering (matplotlib/graphviz)
- **Attack Path Analysis**: Automated attack vector identification
- **Remediation Impact**: Predict remediation impact before changes

## Environment Configuration Commands

### Overview

The environment configuration system provides technology-agnostic infrastructure modeling with rich business context for AI-driven risk assessment. It bridges the gap between technical vulnerability data and business impact analysis.

**Key Features:**
- **Infrastructure Modeling**: Define assets, dependencies, and network topology
- **Business Context**: Criticality, revenue impact, compliance requirements, SLA tiers
- **Risk Assessment**: Calculate risk scores based on business context
- **AI Integration**: Business context-aware vulnerability analysis
- **Graph Integration**: Merge infrastructure topology with vulnerability data
- **Compliance Tracking**: PCI-DSS, GDPR, SOX, HIPAA compliance scope

### Environment Configuration File

Environment configurations are defined in JSON format with comprehensive metadata:

**Structure:**
```json
{
  "environment": {
    "name": "production-ecommerce",
    "type": "production",
    "cloud_provider": "aws",
    "region": "us-east-1",
    "compliance_requirements": ["pci-dss", "gdpr", "sox"],
    "owner": "platform-team@acme.com"
  },
  "global_business_context": {
    "industry": "ecommerce",
    "company_size": "enterprise",
    "risk_tolerance": "low",
    "incident_cost_estimates": {
      "data_breach_per_record": 150.0,
      "downtime_per_hour": 50000.0,
      "reputation_damage": 1000000.0,
      "regulatory_fine_range": [100000.0, 5000000.0]
    }
  },
  "assets": [
    {
      "id": "asset-payment-api",
      "name": "Payment Processing API",
      "type": "container",
      "host": "10.0.2.100",
      "software": {
        "image": "payment-api:v2.1.0",
        "os": "Alpine Linux 3.18",
        "packages": [
          {"name": "openssl", "version": "1.1.1q", "ecosystem": "apk"}
        ]
      },
      "network": {
        "internal_ip": "10.0.2.100",
        "zone": "dmz",
        "exposed_ports": [
          {
            "port": 8443,
            "protocol": "https",
            "public": false,
            "description": "Internal API"
          }
        ]
      },
      "business_context": {
        "criticality": "critical",
        "criticality_score": 95,
        "function": "payment-processing",
        "data_classification": "pci",
        "revenue_impact": "critical",
        "customer_facing": true,
        "pci_scope": true,
        "sla_tier": "tier-1",
        "mttr_target": 1,
        "owner_team": "payments-team"
      }
    }
  ],
  "dependencies": [
    {
      "from": "asset-frontend-web",
      "to": "asset-payment-api",
      "type": "api-call",
      "protocol": "https",
      "critical": true
    }
  ],
  "network_topology": {
    "zones": [
      {
        "name": "dmz",
        "trust_level": "medium",
        "internet_facing": true,
        "description": "Demilitarized zone for public services"
      },
      {
        "name": "internal",
        "trust_level": "high",
        "internet_facing": false,
        "description": "Internal application zone"
      }
    ],
    "segmentation_rules": [
      {
        "from_zone": "dmz",
        "to_zone": "internal",
        "allowed": true,
        "ports": [8443, 5432],
        "protocols": ["https", "postgresql"]
      }
    ]
  }
}
```

**Configuration Elements:**

1. **Environment Metadata**
   - Name, type (production/staging/dev)
   - Cloud provider and region
   - Compliance requirements
   - Owner and contact information

2. **Global Business Context**
   - Industry and company size
   - Risk tolerance (low/medium/high)
   - Incident cost estimates
   - Compliance frameworks

3. **Assets**
   - Infrastructure components (containers, VMs, load balancers, databases)
   - Software inventory (images, OS, packages)
   - Network configuration (IPs, ports, zones)
   - Business context (criticality, function, data classification)

4. **Dependencies**
   - Inter-asset relationships
   - Communication protocols
   - Criticality flags

5. **Network Topology**
   - Network zones and trust levels
   - Segmentation rules
   - Firewall configurations

### Environment Commands

#### Validate Configuration

Validate environment configuration file syntax and schema:

```bash
# Validate configuration file
threat-radar env validate my-environment.json

# Show detailed validation errors
threat-radar env validate my-environment.json --errors

# Validate and show risk summary
threat-radar env validate production-env.json
```

**Validation checks:**
- JSON/YAML syntax
- Schema compliance (Pydantic models)
- Required fields present
- Valid enum values
- Risk score calculation
- Dependency graph consistency

**Output includes:**
```
✓ Validation successful!

Environment: production-ecommerce
  Type: production
  Assets: 15
  Dependencies: 28

Risk Summary:
  Critical assets: 5
  Internet-facing: 3
  PCI scope: 7
  Risk level: 3.2/4.0
```

#### Build Infrastructure Graph

Build graph database from environment configuration:

```bash
# Build graph from environment config
threat-radar env build-graph my-environment.json -o infrastructure.graphml

# Auto-save to storage/graph_storage/
threat-radar env build-graph production-env.json --auto-save

# Merge with vulnerability scan results
threat-radar env build-graph my-environment.json \
  --merge-scan scan-results-1.json \
  --merge-scan scan-results-2.json \
  --auto-save
```

**How it works:**
1. Parses environment configuration
2. Creates graph nodes for assets, zones, and business context
3. Creates edges for dependencies and network relationships
4. Optionally merges with CVE scan data
5. Saves to GraphML format for analysis

**Graph node types created:**
- **Asset** - Infrastructure components with business context
- **Zone** - Network zones with trust levels
- **BusinessContext** - Criticality and compliance metadata
- **Vulnerability** - CVEs (when merged with scans)
- **Package** - Software packages (when merged with scans)

**Use cases:**
```bash
# Build infrastructure topology graph
threat-radar env build-graph production.json --auto-save

# Merge infrastructure with vulnerability scans
threat-radar cve scan-image payment-api:v2.1.0 -o scan1.json
threat-radar cve scan-image frontend:latest -o scan2.json
threat-radar env build-graph production.json \
  --merge-scan scan1.json \
  --merge-scan scan2.json \
  -o complete-risk-graph.graphml

# Query merged graph for business-context-aware analysis
threat-radar graph query complete-risk-graph.graphml --stats
```

#### Analyze Risk with Business Context

Perform AI-powered risk analysis incorporating business context:

```bash
# Analyze vulnerabilities with business context
threat-radar env analyze-risk my-environment.json scan-results.json

# Use specific AI provider
threat-radar env analyze-risk production.json scan.json \
  --ai-provider anthropic \
  --ai-model claude-3-5-sonnet-20241022

# Save analysis results
threat-radar env analyze-risk env.json scan.json -o risk-analysis.json

# Auto-save to storage/ai_analysis/
threat-radar env analyze-risk production.json scan.json --auto-save
```

**Business context-aware analysis includes:**

1. **Risk Prioritization**
   - Critical assets get higher priority
   - PCI/HIPAA scope increases urgency
   - Customer-facing services prioritized
   - Revenue impact consideration

2. **Impact Assessment**
   - Downtime cost estimates
   - Data breach risk calculations
   - Regulatory fine exposure
   - Reputation damage potential

3. **Compliance Mapping**
   - PCI-DSS requirements affected
   - GDPR data protection implications
   - SOX financial control impact
   - HIPAA PHI exposure risk

4. **Business-Driven Remediation**
   - SLA tier-based timelines
   - MTTR target recommendations
   - Quick wins for critical assets
   - Cost-benefit analysis

**Example output:**
```json
{
  "overall_risk_rating": "HIGH",
  "business_impact_summary": {
    "critical_assets_affected": 3,
    "pci_scope_impact": true,
    "estimated_breach_cost": 2500000,
    "downtime_risk_per_hour": 50000,
    "compliance_violations": ["pci-dss-6.5.1", "gdpr-art-32"]
  },
  "prioritized_findings": [
    {
      "cve_id": "CVE-2023-1234",
      "asset": "asset-payment-api",
      "business_priority": "CRITICAL",
      "reasoning": "Affects PCI-scoped payment API with critical business function. Exploitable RCE vulnerability in internet-facing service processing card data. Tier-1 SLA requires 1-hour MTTR.",
      "impact_estimate": {
        "potential_breach_cost": 500000,
        "compliance_fine_risk": [100000, 500000],
        "reputation_damage": "severe"
      },
      "recommended_action": "Emergency patch within 24 hours. Implement temporary WAF rules. Notify security team and compliance officer."
    }
  ]
}
```

### Environment Workflows

#### Complete Infrastructure Risk Assessment

```bash
#!/bin/bash
# infrastructure-risk-assessment.sh

ENV_FILE="production-environment.json"

# 1. Validate environment configuration
echo "Validating environment configuration..."
threat-radar env validate $ENV_FILE

# 2. Scan all assets for vulnerabilities
echo "Scanning assets..."
SCANS=()
for asset in $(jq -r '.assets[].software.image' $ENV_FILE | grep -v null); do
  echo "  Scanning $asset..."
  scan_file="scan-${asset//[:\/]/_}.json"
  threat-radar cve scan-image $asset --auto-save -o $scan_file
  SCANS+=("--merge-scan $scan_file")
done

# 3. Build infrastructure graph with vulnerabilities
echo "Building infrastructure graph..."
threat-radar env build-graph $ENV_FILE ${SCANS[@]} --auto-save

# 4. Perform business context-aware risk analysis
echo "Analyzing risk with business context..."
for scan in scan-*.json; do
  threat-radar env analyze-risk $ENV_FILE $scan --auto-save
done

# 5. Generate executive report
echo "Generating executive report..."
threat-radar report generate scan-*.json \
  -o executive-risk-report.html \
  -f html \
  --level executive \
  --ai-provider openai

echo "✅ Infrastructure risk assessment complete!"
```

#### CI/CD with Business Context

```yaml
# .github/workflows/security-with-context.yml
name: Security Scan with Business Context
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Tools
        run: |
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh
          pip install threat-radar

      - name: Build Image
        run: docker build -t app:${{ github.sha }} .

      - name: Scan for Vulnerabilities
        run: |
          threat-radar cve scan-image app:${{ github.sha }} \
            --auto-save -o scan.json

      - name: Validate Environment Config
        run: threat-radar env validate .threat-radar/production-env.json

      - name: Analyze with Business Context
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          threat-radar env analyze-risk \
            .threat-radar/production-env.json \
            scan.json \
            -o risk-analysis.json

      - name: Check Critical Business Impact
        run: |
          CRITICAL=$(jq '.prioritized_findings | map(select(.business_priority=="CRITICAL")) | length' risk-analysis.json)

          if [ $CRITICAL -gt 0 ]; then
            echo "❌ Found $CRITICAL critical business-impacting vulnerabilities!"
            jq -r '.prioritized_findings[] | select(.business_priority=="CRITICAL") | "  - \(.cve_id): \(.asset) - \(.reasoning)"' risk-analysis.json
            exit 1
          fi
```

#### Compliance Reporting

```bash
#!/bin/bash
# compliance-risk-report.sh - Generate compliance-focused vulnerability report

ENV_FILE="production-environment.json"
QUARTER=$(date +%Y-Q$(( ($(date +%-m)-1)/3+1 )))

# Scan all PCI-scoped assets
echo "Scanning PCI-scoped assets..."
jq -r '.assets[] | select(.business_context.pci_scope == true) | .software.image' $ENV_FILE | \
while read -r image; do
  if [ -n "$image" ]; then
    echo "  Scanning $image..."
    threat-radar cve scan-image $image --auto-save
  fi
done

# Build infrastructure graph with scans
echo "Building compliance risk graph..."
threat-radar env build-graph $ENV_FILE \
  --merge-scan storage/cve_storage/*.json \
  -o compliance-risk-${QUARTER}.graphml

# Generate compliance report
echo "Generating compliance report..."
threat-radar env analyze-risk $ENV_FILE storage/cve_storage/*.json \
  -o compliance-report-${QUARTER}.json \
  --ai-provider openai

# Extract PCI-DSS specific findings
jq '.prioritized_findings[] | select(.business_context.pci_scope == true)' \
  compliance-report-${QUARTER}.json > pci-findings-${QUARTER}.json

echo "✅ Compliance report ready: compliance-report-${QUARTER}.json"
echo "   PCI findings: pci-findings-${QUARTER}.json"
```

### Environment Architecture

#### Core Components (`threat_radar/environment/`)

- **`models.py`** - Pydantic data models
  - `Environment` - Environment metadata and configuration
  - `Asset` - Infrastructure assets with business context
  - `Dependency` - Inter-asset dependencies
  - `NetworkTopology` - Network zones and segmentation
  - `BusinessContext` - Criticality, compliance, and impact data
  - `GlobalBusinessContext` - Organization-wide risk parameters

- **`parser.py`** - Configuration parser
  - `EnvironmentParser` - Load and validate environment configs
  - Supports JSON and YAML formats
  - Schema validation via Pydantic
  - Risk score calculation

- **`graph_builder.py`** - Graph construction
  - `EnvironmentGraphBuilder` - Build infrastructure graphs
  - Merge with vulnerability data
  - Create business context nodes and edges

#### Data Models

Key data structures:

```python
class Asset:
    id: str
    name: str
    type: AssetType  # container, vm, database, load-balancer, etc.
    host: Optional[str]
    software: Optional[Software]
    network: Optional[Network]
    business_context: BusinessContext
    metadata: Optional[AssetMetadata]

class BusinessContext:
    criticality: Criticality  # critical, high, medium, low
    criticality_score: int  # 0-100
    function: str
    data_classification: DataClassification  # public, internal, confidential, pci, hipaa
    revenue_impact: str
    customer_facing: bool
    pci_scope: bool
    hipaa_scope: bool
    sla_tier: str
    mttr_target: int  # hours
    owner_team: str

class GlobalBusinessContext:
    industry: str
    company_size: str  # startup, small, medium, enterprise
    risk_tolerance: RiskTolerance  # low, medium, high
    incident_cost_estimates: IncidentCostEstimates
```

### Example Environment Configurations

**Minimal Configuration:**
```json
{
  "environment": {
    "name": "dev-environment",
    "type": "development"
  },
  "assets": [
    {
      "id": "dev-api",
      "name": "Development API",
      "type": "container",
      "software": {"image": "api:dev"},
      "business_context": {
        "criticality": "low",
        "function": "development-testing"
      }
    }
  ]
}
```

**Enterprise Production Configuration:**
See `examples/environments/ecommerce-production.json` for a comprehensive example with:
- 15+ assets across multiple zones
- Complete network topology
- PCI-DSS and GDPR compliance scope
- Detailed business context for all assets
- Inter-asset dependencies
- Cost estimates and SLA definitions

### Benefits of Environment Configuration

1. **Business-Driven Prioritization**
   - Vulnerabilities prioritized by business impact
   - Critical assets get immediate attention
   - Compliance requirements drive remediation timelines

2. **Accurate Risk Assessment**
   - Technical severity + business context = true risk
   - Revenue impact calculations
   - Compliance violation exposure

3. **Better Communication**
   - Technical findings translated to business impact
   - Executive summaries with cost estimates
   - Compliance reports for auditors

4. **Efficient Remediation**
   - Focus on highest business risk first
   - SLA-driven timelines
   - Quick wins identified

5. **Compliance Automation**
   - PCI-DSS scope tracking
   - GDPR data classification
   - SOX control mapping
   - HIPAA PHI identification

## Development Notes

### Module Structure
- `threat_radar/graph/` - **IMPLEMENTED**: Graph database integration for vulnerability modeling
  - `models.py` - Graph node and edge data models
  - `graph_client.py` - NetworkX client implementation
  - `builders.py` - Convert scan results to graph structures
  - `queries.py` - Advanced graph analysis and queries
- `threat_radar/environment/` - **IMPLEMENTED**: Environment configuration and business context integration
  - `models.py` - Pydantic models for infrastructure, assets, and business context
  - `parser.py` - Configuration file loading and validation
  - `graph_builder.py` - Build infrastructure topology graphs
  - See Environment Configuration Commands section above for full capabilities
- `threat_radar/ai/` - **IMPLEMENTED**: AI-powered vulnerability analysis, prioritization, and remediation
  - Includes `remediation_generator.py` for creating actionable fix plans
  - Supports OpenAI GPT, Anthropic Claude, and Ollama (local models)
  - Business context-aware risk assessment when used with environment configs
  - See AI Commands Reference section above for full capabilities
- `threat_radar/core/` - Core business logic for scanning, SBOM generation, and container analysis
- `threat_radar/cli/` - CLI commands and user interface
- `threat_radar/utils/` - Utilities for reporting, storage, configuration, and helpers

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

- **`./storage/graph_storage/`** - Graph database files
  - Vulnerability and infrastructure graphs in GraphML format
  - Auto-saved with `--auto-save` flag in graph commands
  - Format: `<target>_YYYY-MM-DD_HH-MM-SS.graphml` with optional `.json` metadata
  - Compatible with NetworkX, Gephi, Neo4j, and custom analysis tools

- **`./sbom_storage/`** - SBOM files organized by category
  - `docker/` - SBOMs from Docker images
  - `local/` - SBOMs from local directories
  - `comparisons/` - SBOM comparison results
  - `archives/` - Historical SBOMs

### Testing Patterns
- Tests use fixtures in `tests/fixtures/` directory
- Docker tests in `test_docker_integration.py` require Docker daemon running
- AI tests in `test_ai_integration.py` require AI provider configuration (or can be mocked)
- Batch processing tests in `test_batch_processing.py` validate large-scale CVE handling
- Comprehensive report tests in `test_comprehensive_report.py` validate all report formats
- Graph integration tests in `test_graph_integration.py` test graph building, querying, and storage
- Hash tests in `test_hasher.py` test file integrity verification
- All tests can run independently without external dependencies (except Docker tests)

### Dependencies

**Core Python dependencies:**
- `PyGithub==2.1.1` - GitHub API integration
- `python-dotenv==1.0.0` - Environment variable management
- `typer>=0.9.0` - CLI framework (argument parsing and commands)
- `docker>=7.0.0` - Docker SDK for Python
- `openai>=1.0.0` - OpenAI API client (for AI features)
- `tenacity>=8.2.0` - Retry logic for API calls

**Optional Python dependencies:**
- `anchore-syft>=1.18.0` - SBOM generation Python bindings (not required, CLI tool is primary)
- `ollama>=0.1.0` - Local Ollama model integration (install via `pip install -e ".[ai]"`)
- `anthropic>=0.7.0` - Anthropic Claude API client (install via `pip install -e ".[ai]"`)

**External tools (REQUIRED, must be installed separately):**
- **Grype** - Anchore vulnerability scanner (required for CVE scanning)
  - Install: `brew install grype` (macOS)
  - Install: `curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh` (Linux)
  - Verify: `grype version`
  - Website: https://github.com/anchore/grype

- **Syft** - Anchore SBOM generator (required for SBOM operations)
  - Install: `brew install syft` (macOS)
  - Install: `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh` (Linux)
  - Verify: `syft version`
  - Website: https://github.com/anchore/syft

**Dev dependencies:**
- `pytest>=7.0.0` - Testing framework
- `pytest-cov>=4.0.0` - Coverage reporting
- `black>=22.0.0` - Code formatting
- `flake8>=4.0.0` - Linting
- `mypy>=0.950` - Type checking

## Environment Configuration

Create `.env` file from `.env.example`:
```
GITHUB_ACCESS_TOKEN=your_github_personal_access_token_here

# AI Configuration
# Option 1: OpenAI
OPENAI_API_KEY=your_openai_api_key_here
AI_PROVIDER=openai
AI_MODEL=gpt-4o  # Recommended: gpt-4o, gpt-4-turbo, or gpt-3.5-turbo-1106 (JSON mode support required)

# Option 2: Anthropic Claude
# ANTHROPIC_API_KEY=sk-ant-your-key-here
# AI_PROVIDER=anthropic
# AI_MODEL=claude-3-5-sonnet-20241022

# Option 3: Ollama (local)
# AI_PROVIDER=ollama
# AI_MODEL=llama2
LOCAL_MODEL_ENDPOINT=http://localhost:11434
```

- `GITHUB_ACCESS_TOKEN` - Required for GitHub integration features
- `OPENAI_API_KEY` - Required for AI features with OpenAI
- `ANTHROPIC_API_KEY` - Required for AI features with Anthropic Claude
- `AI_PROVIDER` - Set to `openai`, `anthropic`, or `ollama` for AI provider selection
- `AI_MODEL` - Model name (e.g., `gpt-4o`, `gpt-4-turbo`, `claude-3-5-sonnet-20241022`, `llama2`)
- `LOCAL_MODEL_ENDPOINT` - Ollama endpoint (default: `http://localhost:11434`)

## Common Issues and Troubleshooting

### Grype/Syft Not Found
```bash
# Error: "grype: command not found" or "syft: command not found"

# Solution: Install the external tools
brew install grype syft  # macOS
# OR
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh

# Verify installation
grype version
syft version
```

### Docker Daemon Not Running
```bash
# Error: "Cannot connect to the Docker daemon"

# Solution: Start Docker Desktop or Docker daemon
# macOS: Open Docker Desktop application
# Linux: sudo systemctl start docker
```

### AI Features Not Working
```bash
# Error: "OpenAI API key not provided" or similar

# Solution: Configure AI provider in .env file
cp .env.example .env
# Edit .env and add your API key:
# - For OpenAI: OPENAI_API_KEY=sk-your-key-here
# - For Anthropic: ANTHROPIC_API_KEY=sk-ant-your-key-here
# - For Ollama: Start ollama service and pull a model

# Verify Ollama is running (for local models)
ollama list  # Should show available models
ollama pull llama2  # If no models available
```

### Import Errors
```bash
# Error: ModuleNotFoundError for threat_radar or dependencies

# Solution: Install in development mode
pip install -e .

# Or install all dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # For development
pip install -e ".[ai]"  # For AI features
```

### Test Failures
```bash
# Docker tests failing: Ensure Docker daemon is running
docker ps  # Should not error

# AI tests failing: Set up AI provider or mock tests
export AI_PROVIDER=ollama  # Or skip AI tests

# Run tests with verbose output for debugging
pytest -v -s tests/test_specific_file.py
```

### Permission Issues with Storage Directories
```bash
# Error: Permission denied when auto-saving

# Solution: Ensure write permissions
chmod -R u+w storage/ sbom_storage/

# Or create directories manually
mkdir -p storage/cve_storage storage/ai_analysis
mkdir -p sbom_storage/docker sbom_storage/local
```

For more troubleshooting help, see `examples/TROUBLESHOOTING.md`

---

## Documentation Resources

### User Documentation
- **[INSTALLATION.md](INSTALLATION.md)** - Complete installation guide for all platforms (macOS, Linux, Windows)
- **[docs/CLI_FEATURES.md](docs/CLI_FEATURES.md)** - Comprehensive CLI features guide (global options, configuration, filtering, output formats)
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and release notes

### Developer Documentation
- **[docs/API.md](docs/API.md)** - Complete Python API reference for programmatic usage
- **[PUBLISHING.md](PUBLISHING.md)** - PyPI publishing and release workflow guide
- **[threat-radar.config.example.json](threat-radar.config.example.json)** - Example configuration file template

### Additional Resources
- **[README.md](README.md)** - Project overview and quick start
- **[examples/TROUBLESHOOTING.md](examples/TROUBLESHOOTING.md)** - Common issues and solutions
- **[.env.example](.env.example)** - Environment variables template
